"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
import zlib
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def compute_hashes(filepath: str | Path) -> dict[str, str]:
    """Compute SHA1, MD5, SHA256, CRC32 for a file."""
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    crc = 0
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha1.update(chunk)
            md5.update(chunk)
            sha256.update(chunk)
            crc = zlib.crc32(chunk, crc)
    return {
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": format(crc & 0xFFFFFFFF, "08x"),
    }


def load_database(db_path: str) -> dict:
    """Load database.json and return parsed dict."""
    with open(db_path) as f:
        return json.load(f)


def md5sum(source: str | Path | object) -> str:
    """Compute MD5 of a file path or file-like object - matches Batocera's md5sum()."""
    h = hashlib.md5()
    if hasattr(source, "read"):
        for chunk in iter(lambda: source.read(65536), b""):
            h.update(chunk)
    else:
        with open(source, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


_md5_composite_cache: dict[str, str] = {}


def md5_composite(filepath: str | Path) -> str:
    """Compute composite MD5 of a ZIP - matches Recalbox's Zip::Md5Composite().

    Sorts filenames alphabetically, reads each file's contents in order,
    feeds everything into a single MD5 hasher. The result is independent
    of ZIP compression level or metadata. Results are cached per path.
    """
    key = str(filepath)
    cached = _md5_composite_cache.get(key)
    if cached is not None:
        return cached
    with zipfile.ZipFile(filepath) as zf:
        names = sorted(n for n in zf.namelist() if not n.endswith("/"))
        h = hashlib.md5()
        for name in names:
            h.update(zf.read(name))
        result = h.hexdigest()
    _md5_composite_cache[key] = result
    return result


def load_platform_config(platform_name: str, platforms_dir: str = "platforms") -> dict:
    """Load a platform config with inheritance and shared group resolution.

    This is the SINGLE implementation used by generate_pack, generate_readme,
    verify, and auto_fetch. No other copy should exist.
    """
    if yaml is None:
        raise ImportError("PyYAML required: pip install pyyaml")

    config_file = os.path.join(platforms_dir, f"{platform_name}.yml")
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Platform config not found: {config_file}")

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    # Resolve inheritance
    if "inherits" in config:
        parent = load_platform_config(config["inherits"], platforms_dir)
        merged = {**parent}
        merged.update({k: v for k, v in config.items() if k not in ("inherits", "overrides")})
        if "overrides" in config and "systems" in config["overrides"]:
            merged.setdefault("systems", {})
            for sys_id, override in config["overrides"]["systems"].items():
                if sys_id in merged["systems"]:
                    merged["systems"][sys_id] = {**merged["systems"][sys_id], **override}
                else:
                    merged["systems"][sys_id] = override
        config = merged

    # Resolve shared group includes (cached to avoid re-parsing per call)
    shared_path = os.path.join(platforms_dir, "_shared.yml")
    if os.path.exists(shared_path):
        if not hasattr(load_platform_config, "_shared_cache"):
            load_platform_config._shared_cache = {}
        cache_key = os.path.realpath(shared_path)
        if cache_key not in load_platform_config._shared_cache:
            with open(shared_path) as f:
                load_platform_config._shared_cache[cache_key] = yaml.safe_load(f) or {}
        shared = load_platform_config._shared_cache[cache_key]
        shared_groups = shared.get("shared_groups", {})
        for system in config.get("systems", {}).values():
            for group_name in system.get("includes", []):
                if group_name in shared_groups:
                    existing = {
                        (f.get("name"), f.get("destination", f.get("name")))
                        for f in system.get("files", [])
                    }
                    existing_lower = {
                        f.get("destination", f.get("name", "")).lower()
                        for f in system.get("files", [])
                    }
                    for gf in shared_groups[group_name]:
                        key = (gf.get("name"), gf.get("destination", gf.get("name")))
                        dest_lower = gf.get("destination", gf.get("name", "")).lower()
                        if key not in existing and dest_lower not in existing_lower:
                            system.setdefault("files", []).append(gf)
                            existing.add(key)

    return config


def load_data_dir_registry(platforms_dir: str = "platforms") -> dict:
    """Load the data directory registry from _data_dirs.yml."""
    registry_path = os.path.join(platforms_dir, "_data_dirs.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        data = yaml.safe_load(f) or {}
    return data.get("data_directories", {})


def resolve_local_file(
    file_entry: dict,
    db: dict,
    zip_contents: dict | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file to its local path using database.json.

    Single source of truth for file resolution, used by both verify.py
    and generate_pack.py. Does NOT handle storage tiers (external/user_provided)
    or release assets - callers handle those.

    Returns (local_path, status) where status is one of:
    exact, zip_exact, hash_mismatch, not_found.
    """
    sha1 = file_entry.get("sha1")
    md5_raw = file_entry.get("md5", "")
    name = file_entry.get("name", "")
    zipped_file = file_entry.get("zipped_file")
    aliases = file_entry.get("aliases", [])
    names_to_try = [name] + [a for a in aliases if a != name]

    md5_list = [m.strip().lower() for m in md5_raw.split(",") if m.strip()] if md5_raw else []
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    # 1. SHA1 exact match
    if sha1 and sha1 in files_db:
        path = files_db[sha1]["path"]
        if os.path.exists(path):
            return path, "exact"

    # 2. MD5 direct lookup (skip for zipped_file: md5 is inner ROM, not container)
    if md5_list and not zipped_file:
        for md5_candidate in md5_list:
            sha1_match = by_md5.get(md5_candidate)
            if sha1_match and sha1_match in files_db:
                path = files_db[sha1_match]["path"]
                if os.path.exists(path):
                    return path, "md5_exact"
            if len(md5_candidate) < 32:
                for db_md5, db_sha1 in by_md5.items():
                    if db_md5.startswith(md5_candidate) and db_sha1 in files_db:
                        path = files_db[db_sha1]["path"]
                        if os.path.exists(path):
                            return path, "md5_exact"

    # 3. No MD5 = any file with that name or alias (existence check)
    if not md5_list:
        candidates = []
        for try_name in names_to_try:
            for match_sha1 in by_name.get(try_name, []):
                if match_sha1 in files_db:
                    path = files_db[match_sha1]["path"]
                    if os.path.exists(path) and path not in candidates:
                        candidates.append(path)
        if candidates:
            if zipped_file:
                candidates = [p for p in candidates if ".zip" in os.path.basename(p)]
            primary = [p for p in candidates if "/.variants/" not in p]
            if primary or candidates:
                return (primary[0] if primary else candidates[0]), "exact"

    # 4. Name + alias fallback with md5_composite + direct MD5 per candidate
    md5_set = set(md5_list)
    candidates = []
    seen_paths = set()
    for try_name in names_to_try:
        for match_sha1 in by_name.get(try_name, []):
            if match_sha1 in files_db:
                entry = files_db[match_sha1]
                path = entry["path"]
                if os.path.exists(path) and path not in seen_paths:
                    seen_paths.add(path)
                    candidates.append((path, entry.get("md5", "")))

    if candidates:
        if zipped_file:
            candidates = [(p, m) for p, m in candidates if ".zip" in os.path.basename(p)]
        if md5_set:
            for path, db_md5 in candidates:
                if ".zip" in os.path.basename(path):
                    try:
                        composite = md5_composite(path).lower()
                        if composite in md5_set:
                            return path, "exact"
                    except (zipfile.BadZipFile, OSError):
                        pass
                if db_md5.lower() in md5_set:
                    return path, "exact"
        primary = [p for p, _ in candidates if "/.variants/" not in p]
        return (primary[0] if primary else candidates[0][0]), "hash_mismatch"

    # 5. zipped_file content match via pre-built index (last resort:
    # matches inner ROM MD5 across ALL ZIPs in the repo, so only use
    # when name-based resolution failed entirely)
    if zipped_file and md5_list and zip_contents:
        for md5_candidate in md5_list:
            if md5_candidate in zip_contents:
                zip_sha1 = zip_contents[md5_candidate]
                if zip_sha1 in files_db:
                    path = files_db[zip_sha1]["path"]
                    if os.path.exists(path):
                        return path, "zip_exact"

    return None, "not_found"


def check_inside_zip(container: str, file_name: str, expected_md5: str) -> str:
    """Check a ROM inside a ZIP — replicates Batocera checkInsideZip().

    Returns "ok", "untested", "not_in_zip", or "error".
    """
    try:
        with zipfile.ZipFile(container) as archive:
            for fname in archive.namelist():
                if fname.casefold() == file_name.casefold():
                    if expected_md5 == "":
                        return "ok"
                    with archive.open(fname) as entry:
                        actual = md5sum(entry)
                    return "ok" if actual == expected_md5 else "untested"
            return "not_in_zip"
    except (zipfile.BadZipFile, OSError, KeyError):
        return "error"


def build_zip_contents_index(db: dict, max_entry_size: int = 512 * 1024 * 1024) -> dict:
    """Build {inner_rom_md5: zip_file_sha1} for ROMs inside ZIP files."""
    index: dict[str, str] = {}
    for sha1, entry in db.get("files", {}).items():
        path = entry["path"]
        if not path.endswith(".zip") or not os.path.exists(path):
            continue
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > max_entry_size:
                        continue
                    h = hashlib.md5()
                    with zf.open(info.filename) as inner:
                        for chunk in iter(lambda: inner.read(65536), b""):
                            h.update(chunk)
                    index[h.hexdigest()] = sha1
        except (zipfile.BadZipFile, OSError):
            continue
    return index


def load_emulator_profiles(
    emulators_dir: str, skip_aliases: bool = True,
) -> dict[str, dict]:
    """Load all emulator YAML profiles from a directory."""
    try:
        import yaml
    except ImportError:
        return {}
    profiles = {}
    emu_path = Path(emulators_dir)
    if not emu_path.exists():
        return profiles
    for f in sorted(emu_path.glob("*.yml")):
        with open(f) as fh:
            profile = yaml.safe_load(fh) or {}
        if "emulator" not in profile:
            continue
        if skip_aliases and profile.get("type") == "alias":
            continue
        profiles[f.stem] = profile
    return profiles


def group_identical_platforms(
    platforms: list[str], platforms_dir: str,
) -> list[tuple[list[str], str]]:
    """Group platforms that produce identical packs (same files + base_destination).

    Returns [(group_of_platform_names, representative), ...].
    """
    fingerprints: dict[str, list[str]] = {}
    representatives: dict[str, str] = {}

    for platform in platforms:
        try:
            config = load_platform_config(platform, platforms_dir)
        except FileNotFoundError:
            fingerprints.setdefault(platform, []).append(platform)
            representatives.setdefault(platform, platform)
            continue

        base_dest = config.get("base_destination", "")
        entries = []
        for sys_id, system in sorted(config.get("systems", {}).items()):
            for fe in system.get("files", []):
                dest = fe.get("destination", fe.get("name", ""))
                full_dest = f"{base_dest}/{dest}" if base_dest else dest
                sha1 = fe.get("sha1", "")
                md5 = fe.get("md5", "")
                entries.append(f"{full_dest}|{sha1}|{md5}")

        fp = hashlib.sha1("|".join(sorted(entries)).encode()).hexdigest()
        fingerprints.setdefault(fp, []).append(platform)
        representatives.setdefault(fp, platform)

    return [(group, representatives[fp]) for fp, group in fingerprints.items()]


def resolve_platform_cores(
    config: dict, profiles: dict[str, dict],
) -> set[str]:
    """Resolve which emulator profiles are relevant for a platform.

    Resolution strategies (by priority):
    1. cores: "all_libretro" — all profiles with libretro in type
    2. cores: [list] — profiles whose dict key matches a core name
    3. cores: absent — fallback to systems intersection

    Alias profiles are always excluded (they point to another profile).
    """
    cores_config = config.get("cores")

    if cores_config == "all_libretro":
        return {
            name for name, p in profiles.items()
            if "libretro" in p.get("type", "")
            and p.get("type") != "alias"
        }

    if isinstance(cores_config, list):
        core_set = set(cores_config)
        return {
            name for name in profiles
            if name in core_set
            and profiles[name].get("type") != "alias"
        }

    # Fallback: system ID intersection
    platform_systems = set(config.get("systems", {}).keys())
    return {
        name for name, p in profiles.items()
        if set(p.get("systems", [])) & platform_systems
        and p.get("type") != "alias"
    }


def safe_extract_zip(zip_path: str, dest_dir: str) -> None:
    """Extract a ZIP file safely, preventing zip-slip path traversal."""
    dest = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(dest, member.filename))
            if not member_path.startswith(dest + os.sep) and member_path != dest:
                raise ValueError(f"Zip slip detected: {member.filename}")
            zf.extract(member, dest)
