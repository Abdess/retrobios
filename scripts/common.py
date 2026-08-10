"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
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

_casefold_index_cache: dict[int, dict[str, list[str]]] = {}


def _casefold_name_index(by_name: dict) -> dict[str, list[str]]:
    """Build (and cache) a casefolded view of the by_name index."""
    key = id(by_name)
    cached = _casefold_index_cache.get(key)
    if cached is not None:
        return cached
    folded: dict[str, list[str]] = {}
    for name, sha1s in by_name.items():
        folded.setdefault(name.casefold(), []).extend(sha1s)
    _casefold_index_cache[key] = folded
    return folded


def name_match_size_ok(file_entry: dict, candidate_size: int | None) -> bool:
    """Whether a candidate found by name may be the file the entry describes.

    Generic filenames collide across systems: rom1.bin is a Sony PlayStation 2
    firmware and a Roland SC-55mk2 program ROM. A name carries no evidence on
    its own, so a size the emulator verifies settles it. A size declared
    without ``validation: [size]`` is informative and rejects nothing.
    """
    validation = file_entry.get("validation")
    if isinstance(validation, dict):
        validation = validation.get("core", [])
    if "size" not in (validation or []) or candidate_size is None:
        return True
    declared = file_entry.get("size")
    if declared is not None:
        allowed = declared if isinstance(declared, list) else [declared]
        return candidate_size in allowed
    low = file_entry.get("min_size")
    high = file_entry.get("max_size")
    if low is not None and candidate_size < low:
        return False
    return not (high is not None and candidate_size > high)


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


def parse_md5_list(raw: str | list | None) -> list[str]:
    """Normalize an md5 field into a lowercase list.

    Platform YAMLs carry Recalbox multi-hash as one comma-separated string,
    emulator profiles carry a YAML list. Both reach here.
    """
    if not raw:
        return []
    values = raw if isinstance(raw, list) else str(raw).split(",")
    return [str(m).strip().lower() for m in values if str(m).strip()]


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
        merged.update(
            {k: v for k, v in config.items() if k not in ("inherits", "overrides")}
        )
        if "overrides" in config and "systems" in config["overrides"]:
            merged.setdefault("systems", {})
            for sys_id, override in config["overrides"]["systems"].items():
                if sys_id in merged["systems"]:
                    merged["systems"][sys_id] = {
                        **merged["systems"][sys_id],
                        **override,
                    }
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

    # Merge metadata from _registry.yml. The registry is our curated source;
    # the scraped YAML may be incomplete (missing cores, metadata fields).
    # Registry fields supplement (not replace) the scraped config.
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if os.path.exists(registry_path):
        reg_real = os.path.realpath(registry_path)
        if reg_real not in _shared_yml_cache:
            with open(registry_path) as f:
                _shared_yml_cache[reg_real] = yaml.safe_load(f) or {}
        reg = _shared_yml_cache[reg_real]
        reg_entry = reg.get("platforms", {}).get(platform_name, {})

        # Merge cores (union for lists, override for all_libretro)
        reg_cores = reg_entry.get("cores")
        if reg_cores is not None:
            cfg_cores = config.get("cores")
            if reg_cores == "all_libretro":
                config["cores"] = "all_libretro"
            elif isinstance(reg_cores, list) and isinstance(cfg_cores, list):
                merged_set = {str(c) for c in cfg_cores} | {str(c) for c in reg_cores}
                config["cores"] = sorted(merged_set)
            elif isinstance(reg_cores, list) and cfg_cores is None:
                config["cores"] = reg_cores

        # Merge all registry fields absent from config (except cores,
        # handled above with union logic). No hardcoded list — any field
        # added to the registry is automatically available in the config.
        for key, val in reg_entry.items():
            if key != "cores" and key not in config:
                config[key] = val

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


def load_platform_registry(platforms_dir: str = "platforms") -> dict:
    """Return the `platforms:` mapping from _registry.yml, empty if absent."""
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if not os.path.exists(registry_path):
        return {}
    with open(registry_path) as f:
        return (yaml.safe_load(f) or {}).get("platforms", {})


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
        result.append(
            {
                "name": tname,
                "architecture": tdata.get("architecture", ""),
                "core_count": len(tdata.get("cores", [])),
                "aliases": aliases,
            }
        )
    return result


HASH_EXACT_RESOLUTION_STATUSES = frozenset(
    {
        "sha1_exact",
        "sha256_exact",
        "crc32_exact",
        "md5_exact",
        "md5_composite_exact",
        "zip_exact",
        "data_dir_hash_exact",
    }
)


def resolution_is_hash_exact(status: str) -> bool:
    """Whether *status* proves content identity with a declared hash."""
    return status in HASH_EXACT_RESOLUTION_STATUSES


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

    Returns ``(local_path, status)``.  Statuses describe the evidence used:
    ``sha1_exact``, ``sha256_exact``, ``crc32_exact``, ``md5_exact``,
    ``md5_composite_exact``, ``zip_exact``, ``path_exact``, ``name_exact``,
    ``hash_mismatch`` or ``not_found`` (plus documented fallback statuses).

    A path or filename is never allowed to override a declared strong hash.
    """
    sha1 = file_entry.get("sha1")
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

    md5_list = parse_md5_list(file_entry.get("md5"))
    sha1_candidates = [
        str(value).strip().lower()
        for value in (sha1 if isinstance(sha1, list) else [sha1] if sha1 else [])
        if str(value).strip()
    ]
    sha256_raw = file_entry.get("sha256")
    sha256_values = sha256_raw if isinstance(sha256_raw, list) else [sha256_raw]
    sha256_candidates = [
        candidate.strip().lower()
        for value in sha256_values
        if value
        for candidate in str(value).split(",")
        if len(candidate.strip()) == 64
    ]
    crc_raw = str(file_entry.get("crc32", "") or "").strip().lower()
    declared_size = file_entry.get("size")
    has_strong_hash = bool(
        sha1_candidates or sha256_candidates or md5_list or crc_raw
    )
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    def _record_match_status(match_sha1: str) -> str | None:
        """Return hash evidence when a DB record satisfies every declaration."""
        entry = files_db.get(match_sha1)
        if not entry:
            return None
        statuses: list[str] = []
        if sha1_candidates:
            if match_sha1.lower() not in sha1_candidates:
                return None
            statuses.append("sha1_exact")
        if sha256_candidates:
            if str(entry.get("sha256", "")).lower() not in sha256_candidates:
                return None
            statuses.append("sha256_exact")
        # With zipped_file the MD5 identifies the member, not the container.
        if md5_list and not zipped_file:
            actual_md5 = str(entry.get("md5", "")).lower()
            if not any(actual_md5.startswith(expected) for expected in md5_list):
                return None
            statuses.append("md5_exact")
        if crc_raw:
            if str(entry.get("crc32", "")).lower() != crc_raw:
                return None
            if declared_size is not None:
                allowed_sizes = (
                    declared_size if isinstance(declared_size, list) else [declared_size]
                )
                if entry.get("size") not in allowed_sizes:
                    return None
            statuses.append("crc32_exact")
        return statuses[0] if statuses else None

    # 1. SHA1 exact match (accept list-valued sha1 from profiles)
    for cand in sha1_candidates:
        if cand in files_db:
            path = files_db[cand]["path"]
            status = _record_match_status(cand)
            if status and os.path.exists(path):
                return path, status

    # 1b. SHA256 exact match (profiles hashed from sources that publish
    # sha256, e.g. MesenCE). A full sha256 is a strong identifier.
    if sha256_candidates:
        by_sha256 = db.get("indexes", {}).get("by_sha256", {})
        for cand in sha256_candidates:
            match = by_sha256.get(cand)
            if match and match in files_db:
                path = files_db[match]["path"]
                status = _record_match_status(match)
                if status and os.path.exists(path):
                    return path, status

    # 1c. CRC32 lookup, only when no stronger hash is declared.  A declared
    # size confirms it when available; a handful of emulators validate CRC32
    # alone, so those entries retain the same (weaker) evidence as the core.
    if (
        crc_raw
        and not zipped_file
        and not md5_list
        and not sha1_candidates
        and not sha256_candidates
    ):
        by_crc32 = db.get("indexes", {}).get("by_crc32", {})
        match = by_crc32.get(crc_raw)
        if match and match in files_db:
            entry = files_db[match]
            path = entry["path"]
            status = _record_match_status(match)
            if status and os.path.exists(path):
                return path, status

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
                # Full MD5 (32 chars) is a strong identifier: trust it
                # without name guard. Truncated MD5 still needs name check
                # to avoid cross-contamination.
                status = _record_match_status(sha1_match)
                if status and os.path.exists(path):
                    if len(md5_candidate) >= 32 or _md5_name_ok(path):
                        return path, status
            if len(md5_candidate) < 32:
                for db_md5, db_sha1 in by_md5.items():
                    if db_md5.startswith(md5_candidate) and db_sha1 in files_db:
                        path = files_db[db_sha1]["path"]
                        status = _record_match_status(db_sha1)
                        if status and os.path.exists(path) and _md5_name_ok(path):
                            return path, status

    # 2b. Path suffix lookup is useful for same-named regional files, but it
    # is identity evidence only when no content hash was declared.  A stale
    # or incorrect destination can therefore never mask a hash mismatch.
    if dest_hint and by_path_suffix:
        for match_sha1 in by_path_suffix.get(dest_hint, []):
            if match_sha1 in files_db:
                path = files_db[match_sha1]["path"]
                if os.path.exists(path):
                    if not has_strong_hash:
                        return path, "path_exact"
                    status = _record_match_status(match_sha1)
                    if status:
                        return path, status

    # 3. No MD5 = any file with that name or alias (existence check)
    def _size_ok(match_sha1: str) -> bool:
        return name_match_size_ok(
            file_entry, files_db.get(match_sha1, {}).get("size")
        )

    if not has_strong_hash:
        candidates = []
        for try_name in names_to_try:
            for match_sha1 in by_name.get(try_name, []):
                if match_sha1 in files_db and _size_ok(match_sha1):
                    path = files_db[match_sha1]["path"]
                    if os.path.exists(path) and path not in candidates:
                        candidates.append(path)
        if not candidates:
            # Case-insensitive fallback: upstream platforms disagree on
            # casing (VEC_MineStorm.vec vs VEC_Minestorm.vec). Safe by
            # invariant: dedup keeps a single casing per content, so a
            # casefold match cannot pick a different file.
            folded = _casefold_name_index(by_name)
            for try_name in names_to_try:
                for match_sha1 in folded.get(try_name.casefold(), []):
                    if match_sha1 in files_db and _size_ok(match_sha1):
                        path = files_db[match_sha1]["path"]
                        if os.path.exists(path) and path not in candidates:
                            candidates.append(path)
        if candidates:
            if zipped_file:
                candidates = [p for p in candidates if ".zip" in os.path.basename(p)]
            primary = [p for p in candidates if "/.variants/" not in p]
            if primary or candidates:
                return (primary[0] if primary else candidates[0]), "name_exact"

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
            candidates = [
                (p, m) for p, m in candidates if ".zip" in os.path.basename(p)
            ]
        if md5_set and not (sha1_candidates or sha256_candidates or crc_raw):
            for path, db_md5 in candidates:
                if ".zip" in os.path.basename(path):
                    try:
                        composite = md5_composite(path).lower()
                        if composite in md5_set:
                            return path, "md5_composite_exact"
                    except (zipfile.BadZipFile, OSError):
                        pass
                if db_md5.lower() in md5_set:
                    return path, "md5_exact"
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
            # No candidate contains the zipped_file -fall through to step 5
        else:
            primary = [p for p, _ in candidates if "/.variants/" not in p]
            return (primary[0] if primary else candidates[0][0]), "hash_mismatch"

    # 5. zipped_file content match via pre-built index (last resort:
    # matches inner ROM MD5 across ALL ZIPs in the repo, so only use
    # when name-based resolution failed entirely)
    if (
        zipped_file
        and md5_list
        and zip_contents
        and not (sha1_candidates or sha256_candidates or crc_raw)
    ):
        for md5_candidate in md5_list:
            if md5_candidate in zip_contents:
                zip_sha1 = zip_contents[md5_candidate]
                if zip_sha1 in files_db:
                    path = files_db[zip_sha1]["path"]
                    if os.path.exists(path):
                        return path, "zip_exact"

    # MAME clone fallback: if a file was deduped, resolve via canonical
    if _depth < 3 and not has_strong_hash:
        clone_map = _get_mame_clone_map()
        canonical = clone_map.get(name)
        if canonical and canonical != name:
            canonical_entry = {"name": canonical}
            result = resolve_local_file(
                canonical_entry,
                db,
                zip_contents,
                dest_hint,
                _depth=_depth + 1,
                data_dir_registry=data_dir_registry,
            )
            if result[0]:
                return result[0], "mame_clone"

    # Data directory fallback: scan data/ caches for matching filename
    def _unindexed_path_status(candidate: str) -> str:
        """Validate a data-directory candidate without trusting its filename."""
        if not has_strong_hash:
            return "data_dir"
        algorithms: set[str] = set()
        if sha1_candidates:
            algorithms.add("sha1")
        if sha256_candidates:
            algorithms.add("sha256")
        if md5_list and not zipped_file:
            algorithms.add("md5")
        if crc_raw:
            algorithms.add("crc32")
        actual = compute_hashes(candidate, frozenset(algorithms)) if algorithms else {}
        if sha1_candidates and actual.get("sha1", "").lower() not in sha1_candidates:
            return "hash_mismatch"
        if sha256_candidates and actual.get("sha256", "").lower() not in sha256_candidates:
            return "hash_mismatch"
        if md5_list and not zipped_file and not any(
            actual.get("md5", "").lower().startswith(expected) for expected in md5_list
        ):
            return "hash_mismatch"
        if crc_raw and actual.get("crc32", "").lower() != crc_raw:
            return "hash_mismatch"
        if crc_raw and declared_size is not None:
            allowed_sizes = declared_size if isinstance(declared_size, list) else [declared_size]
            if os.path.getsize(candidate) not in allowed_sizes:
                return "hash_mismatch"
        if zipped_file and md5_list and not any(
            check_inside_zip(candidate, zipped_file, expected) == "ok"
            for expected in md5_list
        ):
            return "hash_mismatch"
        return "data_dir_hash_exact"

    data_dir_mismatch: str | None = None
    if data_dir_registry:
        for _dd_key, dd_entry in data_dir_registry.items():
            cache_dir = dd_entry.get("local_cache", "")
            if not cache_dir or not os.path.isdir(cache_dir):
                continue
            for try_name in names_to_try:
                # Exact relative path
                candidate = os.path.join(cache_dir, try_name)
                if os.path.isfile(candidate):
                    status = _unindexed_path_status(candidate)
                    if status != "hash_mismatch":
                        return candidate, status
                    data_dir_mismatch = data_dir_mismatch or candidate
            # Basename walk: find file anywhere in cache tree (case-insensitive)
            basename_targets = {
                (n.rsplit("/", 1)[-1] if "/" in n else n).casefold()
                for n in names_to_try
            }
            for root, _dirs, fnames in os.walk(cache_dir):
                for fn in fnames:
                    if fn.casefold() in basename_targets:
                        candidate = os.path.join(root, fn)
                        status = _unindexed_path_status(candidate)
                        if status != "hash_mismatch":
                            return candidate, status
                        data_dir_mismatch = data_dir_mismatch or candidate

    if data_dir_mismatch:
        return data_dir_mismatch, "hash_mismatch"

    # Agnostic fallback: for filename-agnostic files, find any DB file
    # matching the system path prefix and size criteria
    if file_entry.get("agnostic") and not has_strong_hash:
        agnostic_prefix = file_entry.get("agnostic_path_prefix", "")
        min_size = file_entry.get("min_size", 0)
        max_size = file_entry.get("max_size", float("inf"))
        exact_size = file_entry.get("size")
        if exact_size and not min_size:
            min_size = exact_size
            max_size = exact_size
        if agnostic_prefix:
            for _sha1, entry in files_db.items():
                path = entry.get("path", "")
                if not path.startswith(agnostic_prefix):
                    continue
                size = entry.get("size", 0)
                if min_size <= size <= max_size and os.path.exists(path):
                    return path, "agnostic_fallback"

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
    """Check a ROM inside a ZIP -replicates Batocera checkInsideZip().

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

    fingerprint = frozenset((path, os.path.getmtime(path)) for path, _ in zip_entries)
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
    emulators_dir: str,
    skip_aliases: bool = True,
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
        if f.name.endswith(".old.yml"):
            continue
        with open(f) as fh:
            profile = yaml.safe_load(fh) or {}
        if "emulator" not in profile:
            continue
        if skip_aliases and profile.get("type") == "alias":
            continue
        _normalize_hash_fields(profile)
        profiles[f.stem] = profile
    _emulator_profiles_cache[cache_key] = profiles
    return profiles


_HASH_FIELDS = ("crc32", "md5", "sha1", "sha256")


def _normalize_hash_fields(node: object) -> None:
    """Coerce hash values to str in place.

    YAML types unquoted digit-only hashes (e.g. crc32: 70295038) as int,
    which breaks string comparisons and formatting downstream.
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if key in _HASH_FIELDS:
                if isinstance(val, int):
                    node[key] = str(val)
                elif isinstance(val, list):
                    node[key] = [str(v) if isinstance(v, int) else v for v in val]
            else:
                _normalize_hash_fields(val)
    elif isinstance(node, list):
        for item in node:
            _normalize_hash_fields(item)


def unique_emulator_profiles(profiles: dict[str, dict]) -> dict[str, dict]:
    """Profiles counting as distinct emulators (aliases and tests excluded)."""
    return {
        k: v for k, v in profiles.items() if v.get("type") not in ("alias", "test")
    }


GAME_DATA_TOPS = ("RPG Maker", "ScummVM")


def compute_composition(db: dict) -> dict:
    """File and byte counts by tree area.

    Three buckets, each re-derivable from paths alone: arcade ROM sets
    (Arcade/), game and engine data (the RPG Maker/ and ScummVM/ trees),
    and console or computer system files (everything else).
    """
    buckets = {
        "systems": {"files": 0, "size_bytes": 0},
        "arcade": {"files": 0, "size_bytes": 0},
        "game_data": {"files": 0, "size_bytes": 0},
    }
    for entry in db.get("files", {}).values():
        parts = entry.get("path", "").split("/")
        top = parts[1] if len(parts) > 1 else ""
        if top == "Arcade":
            bucket = buckets["arcade"]
        elif top in GAME_DATA_TOPS:
            bucket = buckets["game_data"]
        else:
            bucket = buckets["systems"]
        bucket["files"] += 1
        bucket["size_bytes"] += entry.get("size", 0)
    return buckets


def group_identical_platforms(
    platforms: list[str],
    platforms_dir: str,
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

        entries = []
        for sys_id, system in sorted(config.get("systems", {}).items()):
            for fe in system.get("files", []):
                dest = fe.get("destination", fe.get("name", ""))
                sha1 = fe.get("sha1", "")
                md5 = fe.get("md5", "")
                entries.append(f"{dest}|{sha1}|{md5}")

        fp = hashlib.sha1("|".join(sorted(entries)).encode()).hexdigest()
        if target_cores_cache:
            tc = target_cores_cache.get(platform)
            if tc is not None:
                tc_str = "|".join(sorted(tc))
                fp = hashlib.sha1(f"{fp}|{tc_str}".encode()).hexdigest()
        fingerprints.setdefault(fp, []).append(platform)
        # Prefer the root platform (no inherits) as representative
        if fp not in representatives or (
            not inherits[platform] and inherits.get(representatives[fp], False)
        ):
            representatives[fp] = platform

    result = []
    for fp, group in fingerprints.items():
        rep = representatives[fp]
        ordered = [rep] + [p for p in group if p != rep]
        result.append((ordered, rep))
    return result


def resolve_platform_cores(
    config: dict,
    profiles: dict[str, dict],
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
            name
            for name, p in profiles.items()
            if "libretro" in p.get("type", "") and p.get("type") != "alias"
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
        result = {core_to_profile[c] for c in core_set if c in core_to_profile}
        # Support "all_libretro" as a list element: combines all libretro
        # profiles with explicitly listed standalone cores (e.g. RetroDECK
        # ships RetroArch + standalone emulators)
        if "all_libretro" in core_set or "retroarch" in core_set:
            result |= {
                name
                for name, p in profiles.items()
                if "libretro" in p.get("type", "") and p.get("type") != "alias"
            }
    else:
        # Fallback: system ID intersection with normalization
        norm_plat_systems = {_norm_system_id(s) for s in config.get("systems", {})}
        result = {
            name
            for name, p in profiles.items()
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
    "acorn-",
    "apple-",
    "microsoft-",
    "nintendo-",
    "sony-",
    "sega-",
    "snk-",
    "panasonic-",
    "nec-",
    "epoch-",
    "mattel-",
    "fairchild-",
    "hartung-",
    "tiger-",
    "magnavox-",
    "philips-",
    "bandai-",
    "casio-",
    "coleco-",
    "commodore-",
    "sharp-",
    "sinclair-",
    "atari-",
    "sammy-",
    "gce-",
    "interton-",
    "texas-instruments-",
    "videoton-",
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
    "ti994a": "ti99",
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
            s = s[len(prefix) :]
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
            # No profile maps to this system -keep it
            filtered[sys_id] = sys_data
        elif all_cores & expanded_target:
            # At least one core is on the target
            filtered[sys_id] = sys_data
        elif not plat_cores_here:
            # Platform resolution didn't find cores for this system -keep it
            filtered[sys_id] = sys_data
        # else: known cores exist but none are on the target -exclude
    return filtered


def expand_platform_declared_names(config: dict, db: dict) -> set[str]:
    """Build set of file names declared by a platform config.

    Enriches the set with canonical names and aliases from the database
    by resolving each platform file's MD5 through by_md5.  This handles
    cases where a platform declares a file under a different name than
    the emulator profile (e.g. Batocera ROM1 vs gsplus ROM).
    """
    declared: set[str] = set()
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    files_db = db.get("files", {})
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            name = fe.get("name", "")
            if name:
                declared.add(name)
            md5 = fe.get("md5", "")
            if not md5:
                continue
            # Skip multi-hash and zippedFile entries (inner ROM MD5, not file MD5)
            if "," in md5 or fe.get("zippedFile"):
                continue
            sha1 = by_md5.get(md5.lower())
            if not sha1:
                continue
            entry = files_db.get(sha1, {})
            db_name = entry.get("name", "")
            if db_name:
                declared.add(db_name)
            for alias in entry.get("aliases", []):
                declared.add(alias)
    return declared


import re

_TIMESTAMP_PATTERNS = [
    re.compile(r'"generated_at":\s*"[^"]*"'),  # database.json
    re.compile(r'"imported_at":\s*"[^"]*"'),  # provenance snapshots
    re.compile(r"\*Auto-generated on [^*]*\*"),  # README.md
    re.compile(r"\*Generated on [^*]*\*"),  # docs site pages
]


def write_if_changed(path: str, content: str) -> bool:
    """Write content to path only if the non-timestamp content differs.

    Compares new and existing content after stripping timestamp lines.
    Returns True if the file was written, False if skipped (unchanged).
    """
    if os.path.exists(path):
        with open(path) as f:
            existing = f.read()
        if _strip_timestamps(existing) == _strip_timestamps(content):
            return False
    with open(path, "w") as f:
        f.write(content)
    return True


def _strip_timestamps(text: str) -> str:
    """Remove known timestamp patterns for content comparison."""
    result = text
    for pattern in _TIMESTAMP_PATTERNS:
        result = pattern.sub("", result)
    return result


# Validation and mode filtering -extracted to validation.py for SoC.
# Re-exported below for backward compatibility.


LARGE_FILES_RELEASE = "large-files"
LARGE_FILES_REPO = "Abdess/retrobios"
LARGE_FILES_CACHE = ".cache/large"


def fetch_large_file(
    name: str,
    dest_dir: str = LARGE_FILES_CACHE,
    expected_sha1: str = "",
    expected_md5: str = "",
    *,
    offline: bool = False,
) -> str | None:
    """Return a verified cached large file, downloading it only when allowed."""
    cached = os.path.join(dest_dir, name)
    if os.path.exists(cached):
        if expected_sha1 or expected_md5:
            hashes = compute_hashes(cached)
            if expected_sha1 and hashes["sha1"].lower() != expected_sha1.lower():
                os.unlink(cached)
            elif expected_md5:
                md5_list = [
                    m.strip().lower() for m in expected_md5.split(",") if m.strip()
                ]
                if hashes["md5"].lower() not in md5_list:
                    os.unlink(cached)
                else:
                    return cached
            else:
                return cached
        else:
            return cached

    if offline:
        return None

    os.makedirs(dest_dir, exist_ok=True)
    # A per-process scratch name: two runs fetching the same asset into one
    # shared path interleave their writes into a full-size, corrupt file.
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=dest_dir, prefix=os.path.basename(cached) + ".", suffix=".tmp"
    )
    os.close(tmp_fd)
    # GitHub rewrites spaces to dots in release asset names, so a file whose
    # name contains spaces is published under a dotted name.
    candidates = [name]
    if " " in name:
        candidates.append(name.replace(" ", "."))

    downloaded = False
    for candidate in candidates:
        encoded_name = urllib.parse.quote(candidate)
        url = (
            f"https://github.com/{LARGE_FILES_REPO}/releases/download/"
            f"{LARGE_FILES_RELEASE}/{encoded_name}"
        )
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "retrobios/1.0"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                with open(tmp_path, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
            downloaded = True
            break
        except (urllib.error.URLError, urllib.error.HTTPError):
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    if not downloaded:
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


MAX_ZIP_MEMBERS = 100_000
MAX_ZIP_MEMBER_SIZE = 8 * 1024 * 1024 * 1024
# The largest generated pack is already ~5 GB uncompressed and the collection
# only grows; this bounds a malicious archive without capping a real one.
MAX_ZIP_TOTAL_SIZE = 64 * 1024 * 1024 * 1024
# DEFLATE cannot exceed roughly 1,032:1, so this rejects a declared ratio no
# real DEFLATE member can reach. Methods with a higher ceiling (bzip2, LZMA)
# are exempt and bounded by the per-member and per-archive size limits alone.
MAX_ZIP_COMPRESSION_RATIO = 1_100
_BOUNDED_RATIO_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


def safe_extract_zip(
    zip_path: str,
    dest_dir: str,
    *,
    max_members: int = MAX_ZIP_MEMBERS,
    max_member_size: int = MAX_ZIP_MEMBER_SIZE,
    max_total_size: int = MAX_ZIP_TOTAL_SIZE,
    max_compression_ratio: int = MAX_ZIP_COMPRESSION_RATIO,
) -> None:
    """Extract a ZIP with traversal, link and resource-limit protection.

    Files are streamed to a temporary sibling and atomically installed only
    after their declared length and CRC have been checked by ``zipfile``.
    """
    dest = os.path.realpath(dest_dir)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > max_members:
            raise ValueError(
                f"ZIP has {len(members)} members; limit is {max_members}"
            )

        declared_total = 0
        seen: set[str] = set()
        for member in members:
            # Archives written on Windows store a backslash separator. It is a
            # separator, not a filename character, so it is normalized before
            # the component checks rather than rejected.
            name = member.filename.replace("\\", "/")
            if not name or "\x00" in name:
                raise ValueError(f"Unsafe ZIP member name: {member.filename!r}")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise ValueError(f"Absolute ZIP member path: {name}")
            parts = [part for part in name.split("/") if part]
            if any(part in (".", "..") for part in parts):
                raise ValueError(f"ZIP traversal detected: {name}")
            normalized = "/".join(parts)
            if normalized in seen:
                raise ValueError(f"Duplicate ZIP member path: {name}")
            seen.add(normalized)

            mode = (member.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"ZIP link or special file rejected: {name}")
            if member.flag_bits & 0x1:
                raise ValueError(f"Encrypted ZIP member rejected: {name}")
            if member.file_size > max_member_size:
                raise ValueError(
                    f"ZIP member {name} is {member.file_size} bytes; "
                    f"limit is {max_member_size}"
                )
            declared_total += member.file_size
            if declared_total > max_total_size:
                raise ValueError(
                    f"ZIP expands to {declared_total} bytes; limit is {max_total_size}"
                )
            if member.file_size and member.compress_type in _BOUNDED_RATIO_METHODS:
                if member.compress_size == 0:
                    raise ValueError(f"Invalid compression size for ZIP member: {name}")
                if member.file_size / member.compress_size > max_compression_ratio:
                    raise ValueError(f"Suspicious compression ratio for ZIP member: {name}")

            target = os.path.realpath(os.path.join(dest, *parts))
            if not target.startswith(dest + os.sep) and target != dest:
                raise ValueError(f"ZIP traversal detected: {name}")
            if member.is_dir() or name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue

            os.makedirs(os.path.dirname(target), exist_ok=True)
            tmp_path = ""
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=os.path.dirname(target), delete=False
                ) as tmp_file:
                    tmp_path = tmp_file.name
                    actual_size = 0
                    with zf.open(member, "r") as source:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            actual_size += len(chunk)
                            if actual_size > member.file_size or actual_size > max_member_size:
                                raise ValueError(
                                    f"ZIP member exceeded declared or configured size: {name}"
                                )
                            tmp_file.write(chunk)
                if actual_size != member.file_size:
                    raise ValueError(
                        f"ZIP member size mismatch for {name}: "
                        f"{actual_size} != {member.file_size}"
                    )
                os.replace(tmp_path, target)
                tmp_path = ""
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    os.unlink(tmp_path)


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
        print(
            f"  {sys_id:35s} ({file_count} file{'s' if file_count != 1 else ''}){mfr_display}"
        )


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


DEFAULT_PROVENANCE_DIR = "provenance"


def load_provenance_snapshots(provenance_dir: str = DEFAULT_PROVENANCE_DIR) -> dict:
    """Load dump-catalog snapshots from provenance/*.json.

    Returns {source_name: snapshot} where snapshot holds the normalized
    entries written by the redump scraper or the pack importer. Missing
    directory means no snapshots: returns an empty dict.
    """
    snapshots = {}
    prov_path = Path(provenance_dir)
    if not prov_path.is_dir():
        return snapshots
    for path in sorted(prov_path.glob("*.json")):
        with open(path) as f:
            snapshot = json.load(f)
        source = snapshot.get("source")
        if source and snapshot.get("entries"):
            snapshots[source] = snapshot
    return snapshots


def build_provenance_index(snapshots: dict) -> dict:
    """Index snapshot entries by sha1 and by (md5, size) per source.

    First entry wins on hash collisions within a source; entries are
    pre-sorted at snapshot write time so the outcome is deterministic.
    """
    index = {}
    for source, snapshot in snapshots.items():
        by_sha1 = {}
        by_md5_size = {}
        for entry in snapshot["entries"]:
            sha1 = entry.get("sha1", "")
            md5 = entry.get("md5", "")
            if sha1 and sha1 not in by_sha1:
                by_sha1[sha1] = entry
            if md5 and entry.get("size"):
                key = (md5, entry["size"])
                if key not in by_md5_size:
                    by_md5_size[key] = entry
        index[source] = {"by_sha1": by_sha1, "by_md5_size": by_md5_size}
    return index


def annotate_provenance(files: dict, snapshots: dict) -> dict[str, int]:
    """Attach a provenance field to database file entries.

    Matches by SHA1 first, then MD5 + size. Returns per-source match
    counts. Files without any catalog match keep no provenance field.
    """
    index = build_provenance_index(snapshots)
    counts = dict.fromkeys(index, 0)
    for sha1, entry in files.items():
        matches = {}
        for source in sorted(index):
            src_index = index[source]
            hit = src_index["by_sha1"].get(sha1) or src_index["by_md5_size"].get(
                (entry.get("md5", ""), entry.get("size", 0))
            )
            if hit:
                matches[source] = {
                    "dat": hit.get("dat", ""),
                    "name": hit.get("name", ""),
                    "description": hit.get("description", ""),
                }
                counts[source] += 1
        if matches:
            entry["provenance"] = matches
        else:
            entry.pop("provenance", None)
    return counts


def write_provenance_snapshot(
    path: str, source: str, imported_at: str, dats: dict, entries: list[dict]
) -> bool:
    """Write a normalized provenance snapshot, sorted for determinism."""
    snapshot = {
        "source": source,
        "imported_at": imported_at,
        "dats": dict(sorted(dats.items())),
        "entries": sorted(entries, key=lambda e: (e["dat"], e["name"])),
    }
    return write_if_changed(path, json.dumps(snapshot, indent=2) + "\n")


class ArtifactLockBusy(RuntimeError):
    """Raised when another process already holds the artifact directory."""


@contextlib.contextmanager
def artifact_lock(directory: str, exclusive: bool = True):
    """Serialize access to a shared artifact directory across processes.

    Two pipeline runs building the same dist/ leave readers looking at
    half-written ZIPs, which surfaces as BadZipFile far from its cause.
    Writers take the lock exclusively, readers share it. On platforms
    without flock the lock is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    os.makedirs(directory, exist_ok=True)
    lock_path = os.path.join(directory, ".lock")
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    with open(lock_path, "w") as handle:
        try:
            fcntl.flock(handle, mode | fcntl.LOCK_NB)
        except OSError as exc:
            raise ArtifactLockBusy(
                f"{directory} is in use by another run "
                f"(lock: {lock_path}). Wait for it to finish."
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
