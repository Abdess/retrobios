"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def require_yaml():
    """Import and return yaml, exiting if PyYAML is not installed."""
    try:
        import yaml as _yaml
        return _yaml
    except ImportError:
        import sys
        print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
        sys.exit(1)


_ALL_ALGORITHMS = frozenset({"sha1", "md5", "sha256", "crc32", "adler32"})


def compute_hashes(
    filepath: str | Path,
    algorithms: frozenset[str] | None = None,
) -> dict[str, str]:
    """Compute file hashes. Pass *algorithms* to limit which are computed."""
    algos = algorithms or _ALL_ALGORITHMS
    sha1 = hashlib.sha1() if "sha1" in algos else None
    md5 = hashlib.md5() if "md5" in algos else None
    sha256 = hashlib.sha256() if "sha256" in algos else None
    do_crc = "crc32" in algos
    do_adler = "adler32" in algos
    crc = 0
    adler = 1  # zlib.adler32 initial value
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            if sha1:
                sha1.update(chunk)
            if md5:
                md5.update(chunk)
            if sha256:
                sha256.update(chunk)
            if do_crc:
                crc = zlib.crc32(chunk, crc)
            if do_adler:
                adler = zlib.adler32(chunk, adler)
    result: dict[str, str] = {}
    if sha1:
        result["sha1"] = sha1.hexdigest()
    if md5:
        result["md5"] = md5.hexdigest()
    if sha256:
        result["sha256"] = sha256.hexdigest()
    if do_crc:
        result["crc32"] = format(crc & 0xFFFFFFFF, "08x")
    if do_adler:
        result["adler32"] = format(adler & 0xFFFFFFFF, "08x")
    return result


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
            info = zf.getinfo(name)
            if info.file_size > 512 * 1024 * 1024:
                continue  # skip oversized entries
            h.update(zf.read(name))
        result = h.hexdigest()
    _md5_composite_cache[key] = result
    return result


def parse_md5_list(raw: str) -> list[str]:
    """Parse comma-separated MD5 string into normalized lowercase list."""
    return [m.strip().lower() for m in raw.split(",") if m.strip()] if raw else []


_shared_yml_cache: dict[str, dict] = {}
_platform_config_cache: dict[tuple[str, str], dict] = {}


def load_platform_config(platform_name: str, platforms_dir: str = "platforms") -> dict:
    """Load a platform config with inheritance and shared group resolution.

    This is the SINGLE implementation used by generate_pack, generate_readme,
    verify, and auto_fetch. No other copy should exist.
    """
    cache_key = (platform_name, os.path.realpath(platforms_dir))
    if cache_key in _platform_config_cache:
        return _platform_config_cache[cache_key]

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

    # Resolve shared group includes
    shared_path = os.path.join(platforms_dir, "_shared.yml")
    if os.path.exists(shared_path):
        shared_real = os.path.realpath(shared_path)
        if shared_real not in _shared_yml_cache:
            with open(shared_path) as f:
                _shared_yml_cache[shared_real] = yaml.safe_load(f) or {}
        shared = _shared_yml_cache[shared_real]
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

    _platform_config_cache[cache_key] = config
    return config


def load_data_dir_registry(platforms_dir: str = "platforms") -> dict:
    """Load the data directory registry from _data_dirs.yml."""
    registry_path = os.path.join(platforms_dir, "_data_dirs.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        data = yaml.safe_load(f) or {}
    return data.get("data_directories", {})


def list_registered_platforms(
    platforms_dir: str = "platforms",
    include_archived: bool = False,
) -> list[str]:
    """List platforms registered in _registry.yml.

    Only registered platforms generate packs and appear in CI.
    Unregistered YAMLs (e.g., emulatorjs.yml) are base configs for inheritance.
    """
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        return []
    with open(registry_path) as f:
        registry = yaml.safe_load(f) or {}
    platforms = []
    for name, meta in sorted(registry.get("platforms", {}).items()):
        status = meta.get("status", "active")
        if status == "archived" and not include_archived:
            continue
        config_path = os.path.join(platforms_dir, meta.get("config", f"{name}.yml"))
        if os.path.exists(config_path):
            platforms.append(name)
    return platforms


def load_target_config(
    platform_name: str,
    target: str,
    platforms_dir: str = "platforms",
) -> set[str]:
    """Load target config and return the set of core names for the given target.

    Resolves aliases from _overrides.yml, applies add_cores/remove_cores.
    Raises ValueError if target is unknown (with list of available targets).
    Raises FileNotFoundError if no target file exists for the platform.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    target_file = os.path.join(targets_dir, f"{platform_name}.yml")
    if not os.path.exists(target_file):
        raise FileNotFoundError(
            f"No target config for platform '{platform_name}': {target_file}"
        )
    with open(target_file) as f:
        data = yaml.safe_load(f) or {}

    targets = data.get("targets", {})

    overrides_file = os.path.join(targets_dir, "_overrides.yml")
    overrides = {}
    if os.path.exists(overrides_file):
        with open(overrides_file) as f:
            all_overrides = yaml.safe_load(f) or {}
        overrides = all_overrides.get(platform_name, {}).get("targets", {})

    alias_index: dict[str, str] = {}
    for tname in targets:
        alias_index[tname] = tname
        for alias in overrides.get(tname, {}).get("aliases", []):
            alias_index[alias] = tname

    canonical = alias_index.get(target)
    if canonical is None:
        available = sorted(targets.keys())
        aliases = []
        for tname, ovr in overrides.items():
            for a in ovr.get("aliases", []):
                aliases.append(f"{a} -> {tname}")
        msg = f"Unknown target '{target}' for platform '{platform_name}'.\n"
        msg += f"Available targets: {', '.join(available)}"
        if aliases:
            msg += f"\nAliases: {', '.join(sorted(aliases))}"
        raise ValueError(msg)

    cores = set(str(c) for c in targets[canonical].get("cores", []))

    ovr = overrides.get(canonical, {})
    for c in ovr.get("add_cores", []):
        cores.add(str(c))
    for c in ovr.get("remove_cores", []):
        cores.discard(str(c))

    return cores


def list_available_targets(
    platform_name: str,
    platforms_dir: str = "platforms",
) -> list[dict]:
    """List available targets for a platform with their aliases.

    Returns list of dicts with keys: name, architecture, core_count, aliases.
    Returns empty list if no target file exists.
    """
    targets_dir = os.path.join(platforms_dir, "targets")
    target_file = os.path.join(targets_dir, f"{platform_name}.yml")
    if not os.path.exists(target_file):
        return []
    with open(target_file) as f:
        data = yaml.safe_load(f) or {}

    overrides_file = os.path.join(targets_dir, "_overrides.yml")
    overrides = {}
    if os.path.exists(overrides_file):
        with open(overrides_file) as f:
            all_overrides = yaml.safe_load(f) or {}
        overrides = all_overrides.get(platform_name, {}).get("targets", {})

    result = []
    for tname, tdata in sorted(data.get("targets", {}).items()):
        aliases = overrides.get(tname, {}).get("aliases", [])
        result.append({
            "name": tname,
            "architecture": tdata.get("architecture", ""),
            "core_count": len(tdata.get("cores", [])),
            "aliases": aliases,
        })
    return result


def resolve_local_file(
    file_entry: dict,
    db: dict,
    zip_contents: dict | None = None,
    dest_hint: str = "",
    _depth: int = 0,
    data_dir_registry: dict | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file to its local path using database.json.

    Single source of truth for file resolution, used by both verify.py
    and generate_pack.py. Does NOT handle storage tiers (external/user_provided)
    or release assets - callers handle those.

    dest_hint: optional destination path (e.g., "GC/USA/IPL.bin") used to
    disambiguate when multiple files share the same name. Matched against
    the by_path_suffix index built from the repo's directory structure.

    Returns (local_path, status) where status is one of:
    exact, zip_exact, hash_mismatch, not_found.
    """
    sha1 = file_entry.get("sha1")
    md5_raw = file_entry.get("md5", "")
    name = file_entry.get("name", "")
    zipped_file = file_entry.get("zipped_file")
    aliases = file_entry.get("aliases", [])
    names_to_try = [name] + [a for a in aliases if a != name]

    # When name contains a path separator (e.g. "res/tilemap.bin"), also
    # try the basename since by_name indexes filenames without directories
    if "/" in name:
        name_base = name.rsplit("/", 1)[-1]
        if name_base and name_base not in names_to_try:
            names_to_try.append(name_base)

    # When dest_hint contains a path, also try its basename as a name
    # (handles emulator profiles where name: is descriptive and path: is
    # the actual filename, e.g. name: "MDA font ROM", path: "mda.rom")
    if dest_hint:
        hint_base = dest_hint.rsplit("/", 1)[-1] if "/" in dest_hint else dest_hint
        if hint_base and hint_base not in names_to_try:
            names_to_try.append(hint_base)

    md5_list = [m.strip().lower() for m in md5_raw.split(",") if m.strip()] if md5_raw else []
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    # 0. Path suffix exact match (for regional variants with same filename)
    if dest_hint and by_path_suffix:
        for match_sha1 in by_path_suffix.get(dest_hint, []):
            if match_sha1 in files_db:
                path = files_db[match_sha1]["path"]
                if os.path.exists(path):
                    return path, "exact"

    # 1. SHA1 exact match
    if sha1 and sha1 in files_db:
        path = files_db[sha1]["path"]
        if os.path.exists(path):
            return path, "exact"

    # 2. MD5 direct lookup (skip for zipped_file: md5 is inner ROM, not container)
    # Guard: only accept if the found file's name matches the requested name
    # (or is a .variants/ derivative). Prevents cross-contamination when an
    # unrelated file happens to share the same MD5 in the index.
    _name_set = set(names_to_try)

    def _md5_name_ok(candidate_path: str) -> bool:
        bn = os.path.basename(candidate_path)
        if bn in _name_set:
            return True
        # .variants/ pattern: filename like "neogeo.zip.fc398ab4"
        return any(bn.startswith(n + ".") for n in _name_set)

    if md5_list and not zipped_file:
        for md5_candidate in md5_list:
            sha1_match = by_md5.get(md5_candidate)
            if sha1_match and sha1_match in files_db:
                path = files_db[sha1_match]["path"]
                if os.path.exists(path) and _md5_name_ok(path):
                    return path, "md5_exact"
            if len(md5_candidate) < 32:
                for db_md5, db_sha1 in by_md5.items():
                    if db_md5.startswith(md5_candidate) and db_sha1 in files_db:
                        path = files_db[db_sha1]["path"]
                        if os.path.exists(path) and _md5_name_ok(path):
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
        # When zipped_file is set, only accept candidates that contain it
        if zipped_file:
            valid = []
            for path, m in candidates:
                try:
                    with zipfile.ZipFile(path) as zf:
                        inner_names = {n.casefold() for n in zf.namelist()}
                        if zipped_file.casefold() in inner_names:
                            valid.append((path, m))
                except (zipfile.BadZipFile, OSError):
                    pass
            if valid:
                primary = [p for p, _ in valid if "/.variants/" not in p]
                return (primary[0] if primary else valid[0][0]), "hash_mismatch"
            # No candidate contains the zipped_file — fall through to step 5
        else:
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

    # MAME clone fallback: if a file was deduped, resolve via canonical
    if _depth < 3:
        clone_map = _get_mame_clone_map()
        canonical = clone_map.get(name)
        if canonical and canonical != name:
            canonical_entry = {"name": canonical}
            result = resolve_local_file(
                canonical_entry, db, zip_contents, dest_hint, _depth=_depth + 1,
                data_dir_registry=data_dir_registry,
            )
            if result[0]:
                return result[0], "mame_clone"

    # Data directory fallback: scan data/ caches for matching filename
    if data_dir_registry:
        for _dd_key, dd_entry in data_dir_registry.items():
            cache_dir = dd_entry.get("local_cache", "")
            if not cache_dir or not os.path.isdir(cache_dir):
                continue
            for try_name in names_to_try:
                # Exact relative path
                candidate = os.path.join(cache_dir, try_name)
                if os.path.isfile(candidate):
                    return candidate, "data_dir"
            # Basename walk: find file anywhere in cache tree (case-insensitive)
            basename_targets = {
                (n.rsplit("/", 1)[-1] if "/" in n else n).casefold()
                for n in names_to_try
            }
            for root, _dirs, fnames in os.walk(cache_dir):
                for fn in fnames:
                    if fn.casefold() in basename_targets:
                        return os.path.join(root, fn), "data_dir"

    return None, "not_found"


_mame_clone_map_cache: dict[str, str] | None = None


def _get_mame_clone_map() -> dict[str, str]:
    """Load and cache the MAME clone map (clone_name -> canonical_name)."""
    global _mame_clone_map_cache
    if _mame_clone_map_cache is not None:
        return _mame_clone_map_cache
    clone_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "_mame_clones.json",
    )
    if os.path.exists(clone_path):
        with open(clone_path) as f:
            data = json.load(f)
        _mame_clone_map_cache = {}
        for canonical, info in data.items():
            for clone in info.get("clones", []):
                _mame_clone_map_cache[clone] = canonical
    else:
        _mame_clone_map_cache = {}
    return _mame_clone_map_cache


def check_inside_zip(container: str, file_name: str, expected_md5: str) -> str:
    """Check a ROM inside a ZIP — replicates Batocera checkInsideZip().

    Returns "ok", "untested", "not_in_zip", or "error".
    """
    try:
        with zipfile.ZipFile(container) as archive:
            for fname in archive.namelist():
                if fname.casefold() == file_name.casefold():
                    info = archive.getinfo(fname)
                    if info.file_size > 512 * 1024 * 1024:
                        return "error"
                    if expected_md5 == "":
                        return "ok"
                    with archive.open(fname) as entry:
                        actual = md5sum(entry)
                    return "ok" if actual == expected_md5 else "untested"
            return "not_in_zip"
    except (zipfile.BadZipFile, OSError, KeyError):
        return "error"


_zip_contents_cache: tuple[frozenset[tuple[str, float]], dict] | None = None


def build_zip_contents_index(db: dict, max_entry_size: int = 512 * 1024 * 1024) -> dict:
    """Build {inner_rom_md5: zip_file_sha1} for ROMs inside ZIP files.

    Results are cached in-process; repeated calls with unchanged ZIPs return
    the cached index.
    """
    global _zip_contents_cache

    # Build fingerprint from ZIP paths + mtimes for cache invalidation
    zip_entries: list[tuple[str, str]] = []
    for sha1, entry in db.get("files", {}).items():
        path = entry["path"]
        if path.endswith(".zip") and os.path.exists(path):
            zip_entries.append((path, sha1))

    fingerprint = frozenset(
        (path, os.path.getmtime(path)) for path, _ in zip_entries
    )
    if _zip_contents_cache is not None and _zip_contents_cache[0] == fingerprint:
        return _zip_contents_cache[1]

    index: dict[str, str] = {}
    for path, sha1 in zip_entries:
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

    _zip_contents_cache = (fingerprint, index)
    return index


_emulator_profiles_cache: dict[tuple[str, bool], dict[str, dict]] = {}


def load_emulator_profiles(
    emulators_dir: str, skip_aliases: bool = True,
) -> dict[str, dict]:
    """Load all emulator YAML profiles from a directory (cached)."""
    cache_key = (os.path.realpath(emulators_dir), skip_aliases)
    if cache_key in _emulator_profiles_cache:
        return _emulator_profiles_cache[cache_key]
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
    _emulator_profiles_cache[cache_key] = profiles
    return profiles


def group_identical_platforms(
    platforms: list[str], platforms_dir: str,
    target_cores_cache: dict[str, set[str] | None] | None = None,
) -> list[tuple[list[str], str]]:
    """Group platforms that produce identical packs (same files + base_destination).

    Returns [(group_of_platform_names, representative), ...].
    The representative is the root platform (one that does not inherit).
    """
    fingerprints: dict[str, list[str]] = {}
    representatives: dict[str, str] = {}
    inherits: dict[str, bool] = {}

    for platform in platforms:
        try:
            raw_path = os.path.join(platforms_dir, f"{platform}.yml")
            with open(raw_path) as f:
                raw = yaml.safe_load(f) or {}
            inherits[platform] = "inherits" in raw
            config = load_platform_config(platform, platforms_dir)
        except FileNotFoundError:
            fingerprints.setdefault(platform, []).append(platform)
            representatives.setdefault(platform, platform)
            inherits[platform] = False
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
        if target_cores_cache:
            tc = target_cores_cache.get(platform)
            if tc is not None:
                tc_str = "|".join(sorted(tc))
                fp = hashlib.sha1(f"{fp}|{tc_str}".encode()).hexdigest()
        fingerprints.setdefault(fp, []).append(platform)
        # Prefer the root platform (no inherits) as representative
        if fp not in representatives or (not inherits[platform] and inherits.get(representatives[fp], False)):
            representatives[fp] = platform

    result = []
    for fp, group in fingerprints.items():
        rep = representatives[fp]
        ordered = [rep] + [p for p in group if p != rep]
        result.append((ordered, rep))
    return result


def resolve_platform_cores(
    config: dict, profiles: dict[str, dict],
    target_cores: set[str] | None = None,
) -> set[str]:
    """Resolve which emulator profiles are relevant for a platform.

    Resolution strategies (by priority):
    1. cores: "all_libretro" -- all profiles with libretro in type
    2. cores: [list] -- profiles whose dict key matches a core name
    3. cores: absent -- fallback to systems intersection

    Alias profiles are always excluded (they point to another profile).
    If target_cores is provided, result is intersected with it.
    """
    cores_config = config.get("cores")

    if cores_config == "all_libretro":
        result = {
            name for name, p in profiles.items()
            if "libretro" in p.get("type", "")
            and p.get("type") != "alias"
        }
    elif isinstance(cores_config, list):
        core_set = {str(c) for c in cores_config}
        core_to_profile: dict[str, str] = {}
        for name, p in profiles.items():
            if p.get("type") == "alias":
                continue
            core_to_profile[name] = name
            for core_name in p.get("cores", []):
                core_to_profile[str(core_name)] = name
        result = {
            core_to_profile[c]
            for c in core_set
            if c in core_to_profile
        }
    else:
        # Fallback: system ID intersection with normalization
        norm_plat_systems = {_norm_system_id(s) for s in config.get("systems", {})}
        result = {
            name for name, p in profiles.items()
            if {_norm_system_id(s) for s in p.get("systems", [])} & norm_plat_systems
            and p.get("type") != "alias"
        }

    if target_cores is not None:
        # Build reverse index: upstream name -> profile key
        # Upstream sources (buildbot, es_systems) may use different names
        # than our profile keys (e.g., mednafen_psx vs beetle_psx).
        # The profiles' cores: field lists these alternate names.
        upstream_to_profile: dict[str, str] = {}
        for name, p in profiles.items():
            upstream_to_profile[name] = name
            for alias in p.get("cores", []):
                upstream_to_profile[str(alias)] = name
        # Expand target_cores to profile keys
        expanded = {upstream_to_profile.get(c, c) for c in target_cores}
        result = result & expanded
    return result


MANUFACTURER_PREFIXES = (
    "acorn-", "apple-", "microsoft-", "nintendo-", "sony-", "sega-",
    "snk-", "panasonic-", "nec-", "epoch-", "mattel-", "fairchild-",
    "hartung-", "tiger-", "magnavox-", "philips-", "bandai-", "casio-",
    "coleco-", "commodore-", "sharp-", "sinclair-", "atari-", "sammy-",
    "gce-", "texas-instruments-",
)


def derive_manufacturer(system_id: str, system_data: dict) -> str:
    """Derive manufacturer name for a system.

    Priority: explicit manufacturer field > system ID prefix > 'Other'.
    """
    mfr = system_data.get("manufacturer", "")
    if mfr and mfr not in ("Various", "Other"):
        return mfr.split("|")[0].strip()
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            return prefix.rstrip("-").title()
    return "Other"


# Abbreviations that normalization alone cannot resolve.
# Maps platform-specific short names to canonical profile system IDs.
SYSTEM_ALIASES: dict[str, str] = {
    "gmaster": "hartung-game-master",
    "n64dd": "nintendo-64dd",
    "neogeo64": "hyper-neogeo64",
    "psvita": "sony-playstation-vita",
    # Platform IDs missing the manufacturer-prefix hyphen
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarist": "atari-st",
    "sega32x": "sega-32x",
    "segastv": "sega-stv",
}


def _norm_system_id(sid: str) -> str:
    """Normalize system ID for cross-platform matching.

    Resolves known aliases, then strips manufacturer prefixes and separators
    so that platform-specific IDs (e.g., "xbox", "nintendo-wiiu") match
    profile IDs (e.g., "microsoft-xbox", "nintendo-wii-u").
    """
    s = sid.lower().replace("_", "-")
    s = SYSTEM_ALIASES.get(s, s)
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return s.replace("-", "")


def filter_systems_by_target(
    systems: dict[str, dict],
    profiles: dict[str, dict],
    target_cores: set[str] | None,
    platform_cores: set[str] | None = None,
) -> dict[str, dict]:
    """Filter platform systems to only those reachable by target cores.

    A system is reachable if at least one core that emulates it is available
    on the target. Only considers cores relevant to the platform (from
    platform_cores). Systems whose cores are all outside the platform's
    scope are kept (no information to exclude them).

    Returns the filtered systems dict (or all if no target).
    """
    if target_cores is None:
        return systems

    # Build reverse index for target core name resolution
    upstream_to_profile: dict[str, str] = {}
    for name, p in profiles.items():
        upstream_to_profile[name] = name
        for alias in p.get("cores", []):
            upstream_to_profile[str(alias)] = name
    expanded_target = {upstream_to_profile.get(c, c) for c in target_cores}

    _norm_sid = _norm_system_id

    # Build normalized system -> cores from ALL profiles
    norm_system_cores: dict[str, set[str]] = {}
    for name, p in profiles.items():
        if p.get("type") == "alias":
            continue
        for sid in p.get("systems", []):
            norm_key = _norm_sid(sid)
            norm_system_cores.setdefault(norm_key, set()).add(name)

    # Platform-scoped mapping (for distinguishing "no info" from "known but off-target")
    norm_plat_system_cores: dict[str, set[str]] = {}
    if platform_cores is not None:
        for name in platform_cores:
            p = profiles.get(name, {})
            for sid in p.get("systems", []):
                norm_key = _norm_sid(sid)
                norm_plat_system_cores.setdefault(norm_key, set()).add(name)

    filtered = {}
    for sys_id, sys_data in systems.items():
        norm_key = _norm_sid(sys_id)
        all_cores = norm_system_cores.get(norm_key, set())
        plat_cores_here = norm_plat_system_cores.get(norm_key, set())

        if not all_cores and not plat_cores_here:
            # No profile maps to this system — keep it
            filtered[sys_id] = sys_data
        elif all_cores & expanded_target:
            # At least one core is on the target
            filtered[sys_id] = sys_data
        elif not plat_cores_here:
            # Platform resolution didn't find cores for this system — keep it
            filtered[sys_id] = sys_data
        # else: known cores exist but none are on the target — exclude
    return filtered



# Validation and mode filtering — extracted to validation.py for SoC.
# Re-exported below for backward compatibility.


LARGE_FILES_RELEASE = "large-files"
LARGE_FILES_REPO = "Abdess/retrobios"
LARGE_FILES_CACHE = ".cache/large"


def fetch_large_file(name: str, dest_dir: str = LARGE_FILES_CACHE,
                     expected_sha1: str = "", expected_md5: str = "") -> str | None:
    """Download a large file from the 'large-files' GitHub release if not cached."""
    cached = os.path.join(dest_dir, name)
    if os.path.exists(cached):
        if expected_sha1 or expected_md5:
            hashes = compute_hashes(cached)
            if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
                os.unlink(cached)
            elif expected_md5:
                md5_list = [m.strip().lower() for m in expected_md5.split(",") if m.strip()]
                if hashes["md5"].lower() not in md5_list:
                    os.unlink(cached)
                else:
                    return cached
            else:
                return cached
        else:
            return cached

    encoded_name = urllib.parse.quote(name)
    url = f"https://github.com/{LARGE_FILES_REPO}/releases/download/{LARGE_FILES_RELEASE}/{encoded_name}"
    os.makedirs(dest_dir, exist_ok=True)
    tmp_path = cached + ".tmp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios/1.0"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError):
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return None

    if expected_sha1 or expected_md5:
        hashes = compute_hashes(tmp_path)
        if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
            os.unlink(tmp_path)
            return None
        if expected_md5:
            md5_list = [m.strip().lower() for m in expected_md5.split(",") if m.strip()]
            if hashes["md5"].lower() not in md5_list:
                os.unlink(tmp_path)
                return None
    os.replace(tmp_path, cached)
    return cached


def safe_extract_zip(zip_path: str, dest_dir: str) -> None:
    """Extract a ZIP file safely, preventing zip-slip path traversal."""
    dest = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(dest, member.filename))
            if not member_path.startswith(dest + os.sep) and member_path != dest:
                raise ValueError(f"Zip slip detected: {member.filename}")
            zf.extract(member, dest)


def list_emulator_profiles(emulators_dir: str, skip_aliases: bool = True) -> None:
    """Print available emulator profiles."""
    profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    for name in sorted(profiles):
        p = profiles[name]
        if p.get("type") in ("alias", "test"):
            continue
        display = p.get("emulator", name)
        ptype = p.get("type", "libretro")
        systems = ", ".join(p.get("systems", [])[:3])
        more = "..." if len(p.get("systems", [])) > 3 else ""
        print(f"  {name:30s} {display:40s} [{ptype}] {systems}{more}")


def list_system_ids(emulators_dir: str) -> None:
    """Print available system IDs with emulator count."""
    profiles = load_emulator_profiles(emulators_dir)
    system_emus: dict[str, list[str]] = {}
    for name, p in profiles.items():
        if p.get("type") in ("alias", "test", "launcher"):
            continue
        for sys_id in p.get("systems", []):
            system_emus.setdefault(sys_id, []).append(name)
    for sys_id in sorted(system_emus):
        count = len(system_emus[sys_id])
        print(f"  {sys_id:35s} ({count} emulator{'s' if count > 1 else ''})")


def list_platform_system_ids(platform_name: str, platforms_dir: str) -> None:
    """Print system IDs from a platform's YAML config."""
    config = load_platform_config(platform_name, platforms_dir)
    systems = config.get("systems", {})
    for sys_id in sorted(systems):
        file_count = len(systems[sys_id].get("files", []))
        mfr = systems[sys_id].get("manufacturer", "")
        mfr_display = f"  [{mfr.split('|')[0]}]" if mfr else ""
        print(f"  {sys_id:35s} ({file_count} file{'s' if file_count != 1 else ''}){mfr_display}")



def build_target_cores_cache(
    platforms: list[str],
    target: str,
    platforms_dir: str,
    is_all: bool = False,
) -> tuple[dict[str, set[str] | None], list[str]]:
    """Build target cores cache for a list of platforms.

    Returns (cache dict, list of platforms to keep after skipping failures).
    """
    cache: dict[str, set[str] | None] = {}
    skip: list[str] = []
    for p in platforms:
        try:
            cache[p] = load_target_config(p, target, platforms_dir)
        except FileNotFoundError:
            if is_all:
                cache[p] = None
            else:
                raise
        except ValueError as e:
            if is_all:
                print(f"INFO: Skipping {p}: {e}")
                skip.append(p)
            else:
                raise
    kept = [p for p in platforms if p not in skip]
    return cache, kept
