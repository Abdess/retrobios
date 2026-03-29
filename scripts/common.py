"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def compute_hashes(filepath: str | Path) -> dict[str, str]:
    """Compute SHA1, MD5, SHA256, CRC32, Adler32 for a file."""
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    crc = 0
    adler = 1  # zlib.adler32 initial value
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha1.update(chunk)
            md5.update(chunk)
            sha256.update(chunk)
            crc = zlib.crc32(chunk, crc)
            adler = zlib.adler32(chunk, adler)
    return {
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": format(crc & 0xFFFFFFFF, "08x"),
        "adler32": format(adler & 0xFFFFFFFF, "08x"),
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
            # Basename walk: find file anywhere in cache tree
            basename_targets = {
                (n.rsplit("/", 1)[-1] if "/" in n else n)
                for n in names_to_try
            }
            for root, _dirs, fnames in os.walk(cache_dir):
                for fn in fnames:
                    if fn in basename_targets:
                        return os.path.join(root, fn), "data_dir"

    return None, "not_found"


def _get_mame_clone_map() -> dict[str, str]:
    """Load and cache the MAME clone map (clone_name -> canonical_name)."""
    if not hasattr(_get_mame_clone_map, "_cache"):
        clone_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "_mame_clones.json",
        )
        if os.path.exists(clone_path):
            import json as _json
            with open(clone_path) as f:
                data = _json.load(f)
            _get_mame_clone_map._cache = {}
            for canonical, info in data.items():
                for clone in info.get("clones", []):
                    _get_mame_clone_map._cache[clone] = canonical
        else:
            _get_mame_clone_map._cache = {}
    return _get_mame_clone_map._cache


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
    "microsoft-", "nintendo-", "sony-", "sega-", "snk-", "panasonic-",
    "nec-", "epoch-", "mattel-", "fairchild-", "hartung-", "tiger-",
    "magnavox-", "philips-", "bandai-", "casio-", "coleco-",
    "commodore-", "sharp-", "sinclair-", "atari-",
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


def _norm_system_id(sid: str) -> str:
    """Normalize system ID for cross-platform matching.

    Strips manufacturer prefixes and separators so that platform-specific
    IDs (e.g., "xbox", "nintendo-wiiu") match profile IDs
    (e.g., "microsoft-xbox", "nintendo-wii-u").
    """
    s = sid.lower().replace("_", "-")
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


def _parse_validation(validation: list | dict | None) -> list[str]:
    """Extract the validation check list from a file's validation field.

    Handles both simple list and divergent (core/upstream) dict forms.
    For dicts, uses the ``core`` key since RetroArch users run the core.
    """
    if validation is None:
        return []
    if isinstance(validation, list):
        return validation
    if isinstance(validation, dict):
        return validation.get("core", [])
    return []


# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these — size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})

# All reproducible validation types.
_HASH_CHECKS = frozenset({"crc32", "md5", "sha1", "adler32"})


def _build_validation_index(profiles: dict) -> dict[str, dict]:
    """Build per-filename validation rules from emulator profiles.

    Returns {filename: {"checks": [str], "size": int|None, "min_size": int|None,
    "max_size": int|None, "crc32": str|None, "md5": str|None, "sha1": str|None,
    "adler32": str|None, "crypto_only": [str], "per_emulator": {emu: detail}}}.

    ``crypto_only`` lists validation types we cannot reproduce (signature, crypto)
    so callers can report them as non-verifiable rather than silently skipping.

    ``per_emulator`` preserves each core's individual checks, source_ref, and
    expected values before merging, for ground truth reporting.

    When multiple emulators reference the same file, merges checks (union).
    Raises ValueError if two profiles declare conflicting values.
    """
    index: dict[str, dict] = {}
    for emu_name, profile in profiles.items():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname:
                continue
            checks = _parse_validation(f.get("validation"))
            if not checks:
                continue
            if fname not in index:
                index[fname] = {
                    "checks": set(), "sizes": set(),
                    "min_size": None, "max_size": None,
                    "crc32": set(), "md5": set(), "sha1": set(), "sha256": set(),
                    "adler32": set(), "crypto_only": set(),
                    "emulators": set(), "per_emulator": {},
                }
            index[fname]["emulators"].add(emu_name)
            index[fname]["checks"].update(checks)
            # Track non-reproducible crypto checks
            index[fname]["crypto_only"].update(
                c for c in checks if c in _CRYPTO_CHECKS
            )
            # Size checks
            if "size" in checks:
                if f.get("size") is not None:
                    index[fname]["sizes"].add(f["size"])
                if f.get("min_size") is not None:
                    cur = index[fname]["min_size"]
                    index[fname]["min_size"] = min(cur, f["min_size"]) if cur is not None else f["min_size"]
                if f.get("max_size") is not None:
                    cur = index[fname]["max_size"]
                    index[fname]["max_size"] = max(cur, f["max_size"]) if cur is not None else f["max_size"]
            # Hash checks — collect all accepted hashes as sets (multiple valid
            # versions of the same file, e.g. MT-32 ROM versions)
            if "crc32" in checks and f.get("crc32"):
                crc_val = f["crc32"]
                crc_list = crc_val if isinstance(crc_val, list) else [crc_val]
                for cv in crc_list:
                    norm = str(cv).lower()
                    if norm.startswith("0x"):
                        norm = norm[2:]
                    index[fname]["crc32"].add(norm)
            for hash_type in ("md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    val = f[hash_type]
                    if isinstance(val, list):
                        for h in val:
                            index[fname][hash_type].add(str(h).lower())
                    else:
                        index[fname][hash_type].add(str(val).lower())
            # Adler32 — stored as known_hash_adler32 field (not in validation: list
            # for Dolphin, but support it in both forms for future profiles)
            adler_val = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val:
                norm = adler_val.lower()
                if norm.startswith("0x"):
                    norm = norm[2:]
                index[fname]["adler32"].add(norm)
            # Per-emulator ground truth detail
            expected: dict = {}
            if "size" in checks:
                for key in ("size", "min_size", "max_size"):
                    if f.get(key) is not None:
                        expected[key] = f[key]
            for hash_type in ("crc32", "md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    expected[hash_type] = f[hash_type]
            adler_val_pe = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val_pe:
                expected["adler32"] = adler_val_pe
            pe_entry = {
                "checks": sorted(checks),
                "source_ref": f.get("source_ref"),
                "expected": expected,
            }
            pe = index[fname]["per_emulator"]
            if emu_name in pe:
                # Merge checks from multiple file entries for same emulator
                existing = pe[emu_name]
                merged_checks = sorted(set(existing["checks"]) | set(pe_entry["checks"]))
                existing["checks"] = merged_checks
                existing["expected"].update(pe_entry["expected"])
                if pe_entry["source_ref"] and not existing["source_ref"]:
                    existing["source_ref"] = pe_entry["source_ref"]
            else:
                pe[emu_name] = pe_entry
    # Convert sets to sorted tuples/lists for determinism
    for v in index.values():
        v["checks"] = sorted(v["checks"])
        v["crypto_only"] = sorted(v["crypto_only"])
        v["emulators"] = sorted(v["emulators"])
        # Keep hash sets as frozensets for O(1) lookup in check_file_validation
    return index


def build_ground_truth(filename: str, validation_index: dict[str, dict]) -> list[dict]:
    """Format per-emulator ground truth for a file from the validation index.

    Returns a sorted list of {emulator, checks, source_ref, expected} dicts.
    Returns [] if the file has no emulator validation data.
    """
    entry = validation_index.get(filename)
    if not entry or not entry.get("per_emulator"):
        return []
    result = []
    for emu_name in sorted(entry["per_emulator"]):
        detail = entry["per_emulator"][emu_name]
        result.append({
            "emulator": emu_name,
            "checks": detail["checks"],
            "source_ref": detail.get("source_ref"),
            "expected": detail.get("expected", {}),
        })
    return result


def check_file_validation(
    local_path: str, filename: str, validation_index: dict[str, dict],
    bios_dir: str = "bios",
) -> str | None:
    """Check emulator-level validation on a resolved file.

    Supports: size (exact/min/max), crc32, md5, sha1, adler32,
    signature (RSA-2048 PKCS1v15 SHA256), crypto (AES-128-CBC + SHA256).

    Returns None if all checks pass or no validation applies.
    Returns a reason string if a check fails.
    """
    entry = validation_index.get(filename)
    if not entry:
        return None
    checks = entry["checks"]

    # Size checks — sizes is a set of accepted values
    if "size" in checks:
        actual_size = os.path.getsize(local_path)
        if entry["sizes"] and actual_size not in entry["sizes"]:
            expected = ",".join(str(s) for s in sorted(entry["sizes"]))
            return f"size mismatch: got {actual_size}, accepted [{expected}]"
        if entry["min_size"] is not None and actual_size < entry["min_size"]:
            return f"size too small: min {entry['min_size']}, got {actual_size}"
        if entry["max_size"] is not None and actual_size > entry["max_size"]:
            return f"size too large: max {entry['max_size']}, got {actual_size}"

    # Hash checks — compute once, reuse for all hash types.
    # Each hash field is a set of accepted values (multiple valid ROM versions).
    need_hashes = (
        any(h in checks and entry.get(h) for h in ("crc32", "md5", "sha1", "sha256"))
        or entry.get("adler32")
    )
    if need_hashes:
        hashes = compute_hashes(local_path)
        if "crc32" in checks and entry["crc32"]:
            if hashes["crc32"].lower() not in entry["crc32"]:
                expected = ",".join(sorted(entry["crc32"]))
                return f"crc32 mismatch: got {hashes['crc32']}, accepted [{expected}]"
        if "md5" in checks and entry["md5"]:
            if hashes["md5"].lower() not in entry["md5"]:
                expected = ",".join(sorted(entry["md5"]))
                return f"md5 mismatch: got {hashes['md5']}, accepted [{expected}]"
        if "sha1" in checks and entry["sha1"]:
            if hashes["sha1"].lower() not in entry["sha1"]:
                expected = ",".join(sorted(entry["sha1"]))
                return f"sha1 mismatch: got {hashes['sha1']}, accepted [{expected}]"
        if "sha256" in checks and entry["sha256"]:
            if hashes["sha256"].lower() not in entry["sha256"]:
                expected = ",".join(sorted(entry["sha256"]))
                return f"sha256 mismatch: got {hashes['sha256']}, accepted [{expected}]"
        if entry["adler32"]:
            if hashes["adler32"].lower() not in entry["adler32"]:
                expected = ",".join(sorted(entry["adler32"]))
                return f"adler32 mismatch: got 0x{hashes['adler32']}, accepted [{expected}]"

    # Signature/crypto checks (3DS RSA, AES)
    if entry["crypto_only"]:
        from crypto_verify import check_crypto_validation
        crypto_reason = check_crypto_validation(local_path, filename, bios_dir)
        if crypto_reason:
            return crypto_reason

    return None


def validate_cli_modes(args, mode_attrs: list[str]) -> None:
    """Validate mutual exclusion of CLI mode arguments."""
    modes = sum(1 for attr in mode_attrs if getattr(args, attr, None))
    if modes == 0:
        raise SystemExit(f"Specify one of: --{'  --'.join(mode_attrs)}")
    if modes > 1:
        raise SystemExit(f"Options are mutually exclusive: --{'  --'.join(mode_attrs)}")


def filter_files_by_mode(files: list[dict], standalone: bool) -> list[dict]:
    """Filter file entries by libretro/standalone mode."""
    result = []
    for f in files:
        fmode = f.get("mode", "")
        if standalone and fmode == "libretro":
            continue
        if not standalone and fmode == "standalone":
            continue
        result.append(f)
    return result


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

    encoded_name = urllib.request.quote(name)
    url = f"https://github.com/{LARGE_FILES_REPO}/releases/download/{LARGE_FILES_RELEASE}/{encoded_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios/1.0"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            os.makedirs(dest_dir, exist_ok=True)
            with open(cached, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError):
        return None

    if expected_sha1 or expected_md5:
        hashes = compute_hashes(cached)
        if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
            os.unlink(cached)
            return None
        if expected_md5:
            md5_list = [m.strip().lower() for m in expected_md5.split(",") if m.strip()]
            if hashes["md5"].lower() not in md5_list:
                os.unlink(cached)
                return None
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


# ---------------------------------------------------------------
# Truth generation — build ground-truth YAML from emulator profiles
# ---------------------------------------------------------------

def _determine_core_mode(
    emu_name: str, profile: dict,
    cores_config: str | list | None,
    standalone_set: set[str] | None,
) -> str:
    """Determine effective mode (libretro/standalone) for a resolved core."""
    if cores_config == "all_libretro":
        return "libretro"
    if standalone_set is not None:
        profile_names = {emu_name} | {str(c) for c in profile.get("cores", [])}
        if profile_names & standalone_set:
            return "standalone"
        return "libretro"
    ptype = profile.get("type", "libretro")
    if "standalone" in ptype and "libretro" in ptype:
        return "both"
    if "standalone" in ptype:
        return "standalone"
    return "libretro"


def _enrich_hashes(entry: dict, db: dict) -> None:
    """Fill missing hash fields from the database."""
    sha1 = entry.get("sha1", "")
    md5 = entry.get("md5", "")

    record = None
    if sha1 and db.get("files"):
        record = db["files"].get(sha1)
    if record is None and md5:
        by_md5 = db.get("by_md5", {})
        md5_str = md5 if isinstance(md5, str) else md5[0] if md5 else ""
        ref_sha1 = by_md5.get(md5_str.lower()) if md5_str else None
        if ref_sha1 and db.get("files"):
            record = db["files"].get(ref_sha1)
    if record is None:
        return

    for field in ("sha1", "md5", "sha256", "crc32"):
        if not entry.get(field) and record.get(field):
            entry[field] = record[field]


def _merge_file_into_system(
    system: dict, file_entry: dict, emu_name: str, db: dict | None,
) -> None:
    """Merge a file entry into a system's file list, deduplicating by name."""
    files = system.setdefault("files", [])
    name_lower = file_entry["name"].lower()

    existing = None
    for f in files:
        if f["name"].lower() == name_lower:
            existing = f
            break

    if existing is not None:
        existing["_cores"] = existing.get("_cores", set()) | {emu_name}
        sr = file_entry.get("source_ref")
        if sr is not None:
            sr_key = str(sr) if not isinstance(sr, str) else sr
            existing["_source_refs"] = existing.get("_source_refs", set()) | {sr_key}
        else:
            existing.setdefault("_source_refs", set())
        if file_entry.get("required") and not existing.get("required"):
            existing["required"] = True
        for h in ("sha1", "md5", "sha256", "crc32"):
            theirs = file_entry.get(h, "")
            ours = existing.get(h, "")
            if theirs and ours and theirs.lower() != ours.lower():
                import sys as _sys
                print(
                    f"WARNING: hash conflict for {file_entry['name']} "
                    f"({h}: {ours} vs {theirs}, core {emu_name})",
                    file=_sys.stderr,
                )
            elif theirs and not ours:
                existing[h] = theirs
        return

    entry: dict = {"name": file_entry["name"]}
    if file_entry.get("required") is not None:
        entry["required"] = file_entry["required"]
    for field in ("sha1", "md5", "sha256", "crc32", "size", "path",
                  "description", "hle_fallback", "category", "note",
                  "validation", "min_size", "max_size", "aliases"):
        val = file_entry.get(field)
        if val is not None:
            entry[field] = val
    entry["_cores"] = {emu_name}
    sr = file_entry.get("source_ref")
    if sr is not None:
        sr_key = str(sr) if not isinstance(sr, str) else sr
        entry["_source_refs"] = {sr_key}
    else:
        entry["_source_refs"] = set()

    if db:
        _enrich_hashes(entry, db)

    files.append(entry)


def generate_platform_truth(
    platform_name: str,
    config: dict,
    registry_entry: dict,
    profiles: dict[str, dict],
    db: dict | None = None,
    target_cores: set[str] | None = None,
) -> dict:
    """Generate ground-truth system data for a platform from emulator profiles.

    Args:
        platform_name: platform identifier
        config: loaded platform config (via load_platform_config), has cores,
                systems, standalone_cores with inheritance resolved
        registry_entry: registry metadata for hash_type, verification_mode, etc.
        profiles: all loaded emulator profiles
        db: optional database for hash enrichment
        target_cores: optional hardware target core filter

    Returns a dict with platform metadata, systems, and per-file details
    including which cores reference each file.
    """
    cores_config = config.get("cores")

    # Resolve standalone set for mode determination
    standalone_set: set[str] | None = None
    standalone_cores = config.get("standalone_cores")
    if isinstance(standalone_cores, list):
        standalone_set = {str(c) for c in standalone_cores}

    resolved = resolve_platform_cores(config, profiles, target_cores)

    systems: dict[str, dict] = {}
    cores_profiled: set[str] = set()
    cores_unprofiled: set[str] = set()
    # Track which cores contribute to each system
    system_cores: dict[str, dict[str, set[str]]] = {}

    for emu_name in sorted(resolved):
        profile = profiles.get(emu_name)
        if not profile:
            cores_unprofiled.add(emu_name)
            continue
        cores_profiled.add(emu_name)

        mode = _determine_core_mode(emu_name, profile, cores_config, standalone_set)
        raw_files = profile.get("files", [])
        if mode == "both":
            filtered = raw_files
        else:
            filtered = filter_files_by_mode(raw_files, standalone=(mode == "standalone"))

        for fe in filtered:
            sys_id = fe.get("system", "")
            if not sys_id:
                sys_ids = profile.get("systems", [])
                sys_id = sys_ids[0] if sys_ids else "unknown"
            system = systems.setdefault(sys_id, {})
            _merge_file_into_system(system, fe, emu_name, db)
            # Track core contribution per system
            sys_cov = system_cores.setdefault(sys_id, {
                "profiled": set(), "unprofiled": set(),
            })
            sys_cov["profiled"].add(emu_name)

    # Track unprofiled cores per system based on profile system lists
    for emu_name in cores_unprofiled:
        for sys_id in systems:
            sys_cov = system_cores.setdefault(sys_id, {
                "profiled": set(), "unprofiled": set(),
            })
            sys_cov["unprofiled"].add(emu_name)

    # Convert sets to sorted lists for serialization
    for sys_id, sys_data in systems.items():
        for fe in sys_data.get("files", []):
            fe["_cores"] = sorted(fe.get("_cores", set()))
            fe["_source_refs"] = sorted(fe.get("_source_refs", set()))
        # Add per-system coverage
        cov = system_cores.get(sys_id, {})
        sys_data["_coverage"] = {
            "cores_profiled": sorted(cov.get("profiled", set())),
            "cores_unprofiled": sorted(cov.get("unprofiled", set())),
        }

    return {
        "platform": platform_name,
        "generated": True,
        "systems": systems,
        "_coverage": {
            "cores_resolved": len(resolved),
            "cores_profiled": len(cores_profiled),
            "cores_unprofiled": sorted(cores_unprofiled),
        },
    }


# -------------------------------------------------------------------
# Platform truth diffing
# -------------------------------------------------------------------

def _diff_system(truth_sys: dict, scraped_sys: dict) -> dict:
    """Compare files between truth and scraped for a single system."""
    # Build truth index: name.lower() -> entry, alias.lower() -> entry
    truth_index: dict[str, dict] = {}
    for fe in truth_sys.get("files", []):
        truth_index[fe["name"].lower()] = fe
        for alias in fe.get("aliases", []):
            truth_index[alias.lower()] = fe

    # Build scraped index: name.lower() -> entry
    scraped_index: dict[str, dict] = {}
    for fe in scraped_sys.get("files", []):
        scraped_index[fe["name"].lower()] = fe

    missing: list[dict] = []
    hash_mismatch: list[dict] = []
    required_mismatch: list[dict] = []
    extra_phantom: list[dict] = []
    extra_unprofiled: list[dict] = []

    matched_truth_names: set[str] = set()

    # Compare scraped files against truth
    for s_key, s_entry in scraped_index.items():
        t_entry = truth_index.get(s_key)
        if t_entry is None:
            continue
        matched_truth_names.add(t_entry["name"].lower())

        # Hash comparison
        for h in ("sha1", "md5", "crc32"):
            t_hash = t_entry.get(h, "")
            s_hash = s_entry.get(h, "")
            if not t_hash or not s_hash:
                continue
            # Normalize to list for multi-hash support
            t_list = t_hash if isinstance(t_hash, list) else [t_hash]
            s_list = s_hash if isinstance(s_hash, list) else [s_hash]
            t_set = {v.lower() for v in t_list}
            s_set = {v.lower() for v in s_list}
            if not t_set & s_set:
                hash_mismatch.append({
                    "name": s_entry["name"],
                    "hash_type": h,
                    f"truth_{h}": t_hash,
                    f"scraped_{h}": s_hash,
                    "truth_cores": list(t_entry.get("_cores", [])),
                })
                break

        # Required mismatch
        t_req = t_entry.get("required")
        s_req = s_entry.get("required")
        if t_req is not None and s_req is not None and t_req != s_req:
            required_mismatch.append({
                "name": s_entry["name"],
                "truth_required": t_req,
                "scraped_required": s_req,
            })

    # Truth files not matched -> missing
    for fe in truth_sys.get("files", []):
        if fe["name"].lower() not in matched_truth_names:
            missing.append({
                "name": fe["name"],
                "cores": list(fe.get("_cores", [])),
                "source_refs": list(fe.get("_source_refs", [])),
            })

    # Scraped files not in truth -> extra
    coverage = truth_sys.get("_coverage", {})
    has_unprofiled = bool(coverage.get("cores_unprofiled"))
    for s_key, s_entry in scraped_index.items():
        if s_key not in truth_index:
            entry = {"name": s_entry["name"]}
            if has_unprofiled:
                extra_unprofiled.append(entry)
            else:
                extra_phantom.append(entry)

    result: dict = {}
    if missing:
        result["missing"] = missing
    if hash_mismatch:
        result["hash_mismatch"] = hash_mismatch
    if required_mismatch:
        result["required_mismatch"] = required_mismatch
    if extra_phantom:
        result["extra_phantom"] = extra_phantom
    if extra_unprofiled:
        result["extra_unprofiled"] = extra_unprofiled
    return result


def _has_divergences(sys_div: dict) -> bool:
    """Check if a system divergence dict contains any actual divergences."""
    return bool(sys_div)


def _update_summary(summary: dict, sys_div: dict) -> None:
    """Update summary counters from a system divergence dict."""
    summary["total_missing"] += len(sys_div.get("missing", []))
    summary["total_extra_phantom"] += len(sys_div.get("extra_phantom", []))
    summary["total_extra_unprofiled"] += len(sys_div.get("extra_unprofiled", []))
    summary["total_hash_mismatch"] += len(sys_div.get("hash_mismatch", []))
    summary["total_required_mismatch"] += len(sys_div.get("required_mismatch", []))


def diff_platform_truth(truth: dict, scraped: dict) -> dict:
    """Compare truth YAML against scraped YAML, returning divergences.

    System IDs are matched using normalized forms (via _norm_system_id) to
    handle naming differences between emulator profiles and scraped platforms
    (e.g. 'sega-game-gear' vs 'sega-gamegear').
    """
    truth_systems = truth.get("systems", {})
    scraped_systems = scraped.get("systems", {})

    summary = {
        "systems_compared": 0,
        "systems_fully_covered": 0,
        "systems_partially_covered": 0,
        "systems_uncovered": 0,
        "total_missing": 0,
        "total_extra_phantom": 0,
        "total_extra_unprofiled": 0,
        "total_hash_mismatch": 0,
        "total_required_mismatch": 0,
    }

    divergences: dict[str, dict] = {}
    uncovered_systems: list[str] = []

    # Build normalized-ID lookup for truth systems
    norm_to_truth: dict[str, str] = {}
    for sid in truth_systems:
        norm_to_truth[_norm_system_id(sid)] = sid

    # Match scraped systems to truth via normalized IDs
    matched_truth: set[str] = set()

    for s_sid in sorted(scraped_systems):
        norm = _norm_system_id(s_sid)
        t_sid = norm_to_truth.get(norm)

        if t_sid is None:
            # Also try exact match (in case normalization is lossy)
            if s_sid in truth_systems:
                t_sid = s_sid
            else:
                uncovered_systems.append(s_sid)
                summary["systems_uncovered"] += 1
                continue

        matched_truth.add(t_sid)
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], scraped_systems[s_sid])

        if _has_divergences(sys_div):
            divergences[s_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    # Truth systems not matched by any scraped system — all files missing
    for t_sid in sorted(truth_systems):
        if t_sid in matched_truth:
            continue
        summary["systems_compared"] += 1
        sys_div = _diff_system(truth_systems[t_sid], {"files": []})
        if _has_divergences(sys_div):
            divergences[t_sid] = sys_div
            _update_summary(summary, sys_div)
            summary["systems_partially_covered"] += 1
        else:
            summary["systems_fully_covered"] += 1

    result: dict = {"summary": summary}
    if divergences:
        result["divergences"] = divergences
    if uncovered_systems:
        result["uncovered_systems"] = uncovered_systems
    return result
