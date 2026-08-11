#!/usr/bin/env python3
"""Generate platform-specific BIOS ZIP packs.

Usage:
    python scripts/generate_pack.py --platform retroarch [--output-dir dist/]
    python scripts/generate_pack.py --all [--output-dir dist/]

Reads platform YAML config + database.json -> creates ZIP with correct
file layout for each platform. Handles inheritance, shared groups, variants,
and 3-tier storage (embedded/external/user_provided).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import (
    artifact_lock,
    ArtifactLockBusy,
    build_target_cores_cache,
    build_zip_contents_index,
    check_inside_zip,
    compute_hashes,
    expand_platform_declared_names,
    fetch_large_file,
    filter_systems_by_target,
    group_identical_platforms,
    list_emulator_profiles,
    list_platform_system_ids,
    list_registered_platforms,
    list_system_ids,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    MANUFACTURER_PREFIXES,
    parse_md5_list,
    require_yaml,
    resolution_is_hash_exact,
    resolve_local_file,
    safe_extract_zip,
    yaml_load,
)
import region as region_mod
from deterministic_zip import _FIXED_DATE_TIME, rebuild_zip_deterministic
from nativemode import hash_mismatch_excludes_file
from validation import (
    _build_validation_index,
    check_file_validation,
    filter_files_by_mode,
)

yaml = require_yaml()

DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB_FILE = "database.json"
DEFAULT_OUTPUT_DIR = "dist"
DEFAULT_BIOS_DIR = "bios"

# CLI-wide network policy.  Public helpers can override it explicitly, while
# every CLI mode inherits --offline (including large-file release fallback).
_OFFLINE = False

_HEX_RE = re.compile(r"\b([0-9a-fA-F]{8,40})\b")


def _write_generated_member(zf: zipfile.ZipFile, arcname: str, text: str) -> None:
    """Write a pack member the builder composes rather than copies.

    READMEs, instruction notes and the manifest are produced at build time,
    so writestr would stamp them with the wall clock and give the same pack
    a different hash on every run. Pinning them to the epoch the archive
    rebuilder already uses makes a pack a function of its inputs alone.
    """
    info = zipfile.ZipInfo(filename=arcname, date_time=_FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    zf.writestr(info, text)


def _build_timestamp(db: dict | None = None) -> str:
    """Timestamp for generated artifacts.

    Reads the database snapshot the artifact was built from, so rebuilding
    the same data twice yields the same value. Falls back to the clock only
    when no database is at hand.
    """
    stamp = (db or {}).get("generated_at")
    if isinstance(stamp, str) and stamp:
        return stamp
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_hash_type(h: str) -> str:
    n = len(h)
    if n == 40:
        return "sha1"
    if n == 32:
        return "md5"
    if n == 8:
        return "crc32"
    return "md5"


def parse_hash_input(raw: str) -> list[tuple[str, str]]:
    """Parse comma-separated hash string into (type, hash) tuples."""
    results: list[tuple[str, str]] = []
    for part in raw.split(","):
        part = part.strip().lower()
        if not part:
            continue
        m = _HEX_RE.search(part)
        if m:
            h = m.group(1)
            results.append((_detect_hash_type(h), h))
    return results


def parse_hash_file(path: str) -> list[tuple[str, str]]:
    """Parse hash file (one per line, comments with #, mixed formats)."""
    results: list[tuple[str, str]] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _HEX_RE.search(line.lower())
            if m:
                h = m.group(1)
                results.append((_detect_hash_type(h), h))
    return results


def lookup_hashes(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    emulators_dir: str,
    platforms_dir: str,
) -> None:
    """Print diagnostic info for each hash."""
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_crc32 = db.get("indexes", {}).get("by_crc32", {})

    for hash_type, hash_val in hashes:
        sha1 = None
        if hash_type == "sha1" and hash_val in files_db:
            sha1 = hash_val
        elif hash_type == "md5":
            sha1 = by_md5.get(hash_val)
        elif hash_type == "crc32":
            sha1 = by_crc32.get(hash_val)

        if not sha1 or sha1 not in files_db:
            print(f"\n{hash_type.upper()}: {hash_val}")
            print("  NOT FOUND in database")
            continue

        entry = files_db[sha1]
        name = entry.get("name", "?")
        md5 = entry.get("md5", "?")
        paths = entry.get("paths") or []
        aliases = entry.get("aliases") or []

        print(f"\n{hash_type.upper()}: {hash_val}")
        print(f"  SHA1: {sha1}")
        print(f"  MD5:  {md5}")
        print(f"  Name: {name}")
        if paths:
            print(f"  Path: {paths[0]}")
        if aliases:
            print(f"  Aliases: {aliases}")

        # Check if file exists in repo (by path or by resolve_local_file)
        in_repo = False
        if paths:
            primary = os.path.join(bios_dir, paths[0])
            if os.path.exists(primary):
                in_repo = True
        if not in_repo:
            try:
                fe_check = {"name": name, "sha1": sha1, "md5": md5}
                local, status = resolve_file(fe_check, db, bios_dir, {})
                if local and status != "not_found":
                    in_repo = True
            except (KeyError, OSError):
                pass
        print(f"  In repo: {'YES' if in_repo else 'NO'}")


def _find_candidate_satisfying_both(
    file_entry: dict,
    db: dict,
    local_path: str,
    validation_index: dict,
    bios_dir: str,
) -> str | None:
    """Search for a repo file that satisfies both platform MD5 and emulator validation.

    When the current file passes platform verification but fails emulator checks,
    search all candidates with the same name for one that passes both.
    Returns a better path, or None if no upgrade found.
    """
    fname = file_entry.get("name", "")
    if not fname:
        return None
    entry = validation_index.get(fname)
    if not entry:
        return None

    md5_expected = file_entry.get("md5", "")
    md5_set = (
        {m.strip().lower() for m in md5_expected.split(",") if m.strip()}
        if md5_expected
        else set()
    )

    by_name = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})

    for sha1 in by_name.get(fname, []):
        candidate = files_db.get(sha1, {})
        path = candidate.get("path", "")
        if (
            not path
            or not os.path.exists(path)
            or os.path.realpath(path) == os.path.realpath(local_path)
        ):
            continue
        # Must still satisfy platform MD5
        if md5_set and candidate.get("md5", "").lower() not in md5_set:
            continue
        # Check emulator validation
        reason = check_file_validation(path, fname, validation_index, bios_dir)
        if reason is None:
            return path
    return None


def _target_tag(target_name: str) -> str:
    """Filename tag for a hardware target.

    Without it a targeted pack takes the same name as the full one and
    overwrites it.
    """
    return "".join(
        part.title() for part in re.split(r"[-_\s]+", target_name.strip()) if part
    )


def _sanitize_path(raw: str) -> str:
    """Strip path traversal components from a relative path."""
    raw = raw.replace("\\", "/")
    parts = [p for p in raw.split("/") if p and p not in ("..", ".")]
    return "/".join(parts)


def _path_parents(dest: str) -> list[str]:
    """Return all parent directory segments of a path."""
    parts = dest.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def _has_path_conflict(dest: str, seen_files: set[str], seen_parents: set[str]) -> bool:
    """Check if dest conflicts with existing paths (file vs directory).

    Returns True if adding dest would create an impossible extraction:
    - A parent of dest is already a file (e.g., adding X/Y when X is a file)
    - dest itself is already used as a directory (e.g., adding X when X/Y exists)
    """
    for parent in _path_parents(dest):
        if parent in seen_files:
            return True
    if dest in seen_parents:
        return True
    return False


def _register_path(dest: str, seen_files: set[str], seen_parents: set[str]) -> None:
    """Track a file path and its parent directories."""
    seen_files.add(dest)
    for parent in _path_parents(dest):
        seen_parents.add(parent)


def _flat(arcname: str, prefix: str, flatten: bool) -> str:
    """Strip base_destination prefix from ZIP arcname when flattening."""
    if flatten and prefix and arcname.startswith(prefix + "/"):
        return arcname[len(prefix) + 1:]
    return arcname


def resolve_file(
    file_entry: dict,
    db: dict,
    bios_dir: str,
    zip_contents: dict | None = None,
    dest_hint: str = "",
    data_dir_registry: dict | None = None,
    *,
    offline: bool | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file with storage tiers and release asset fallback.

    Wraps common.resolve_local_file() with pack-specific logic for
    storage tiers (external/user_provided), large file release assets,
    and MAME clone mapping (deduped ZIPs).
    """
    storage = file_entry.get("storage", "embedded")
    if storage == "user_provided":
        return None, "user_provided"
    if storage == "external":
        return None, "external"

    path, status = resolve_local_file(
        file_entry,
        db,
        zip_contents,
        dest_hint=dest_hint,
        data_dir_registry=data_dir_registry,
    )
    if path and status != "hash_mismatch":
        return path, status

    # Large files from GitHub release assets -tried when local file is
    # missing OR has a hash mismatch (wrong variant on disk)
    name = file_entry.get("name", "")
    sha1 = file_entry.get("sha1")
    first_sha1 = (sha1[0] if sha1 else "") if isinstance(sha1, list) else (sha1 or "")
    md5_list = parse_md5_list(file_entry.get("md5"))
    first_md5 = md5_list[0] if md5_list else ""
    cached = fetch_large_file(
        name,
        expected_sha1=first_sha1,
        expected_md5=first_md5,
        offline=_OFFLINE if offline is None else offline,
    )
    if cached:
        return cached, "release_asset"

    # Fall back to hash_mismatch local file if release asset unavailable
    if path:
        return path, status

    return None, "not_found"


def download_external(file_entry: dict, dest_path: str) -> bool:
    """Download an external BIOS file, verify hash, save to dest_path."""
    url = file_entry.get("source_url")
    if not url:
        return False

    sha256 = file_entry.get("sha256")
    sha1 = file_entry.get("sha1")
    md5 = file_entry.get("md5")

    if not (sha256 or sha1 or md5):
        print(
            f"    WARNING: no hash for {file_entry['name']}, skipping unverifiable download"
        )
        return False

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "retrobios-pack-gen/1.0"}
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
    except urllib.error.URLError as e:
        print(f"    WARNING: Failed to download {url}: {e}")
        return False

    if sha256:
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha256:
            print(f"    WARNING: SHA256 mismatch for {file_entry['name']}")
            return False
    elif sha1:
        actual = hashlib.sha1(data).hexdigest()
        if actual != sha1:
            print(f"    WARNING: SHA1 mismatch for {file_entry['name']}")
            return False
    elif md5:
        actual = hashlib.md5(data).hexdigest()
        if actual != md5:
            print(f"    WARNING: MD5 mismatch for {file_entry['name']}")
            return False

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as f:
        f.write(data)
    return True


def _detect_extras_prefix(config: dict, base_dest: str) -> str:
    """Detect the effective BIOS prefix for core extras.

    When base_destination is empty (RetroDECK), infer the prefix from
    the dominant root of YAML-declared destinations.  Returns the prefix
    to prepend to every core-extra destination (may be empty).
    """
    if base_dest:
        return base_dest
    dests: list[str] = []
    for sys_data in config.get("systems", {}).values():
        for f in sys_data.get("files", []):
            d = f.get("destination", "")
            if d and "/" in d:
                dests.append(d)
    if not dests:
        return ""
    from collections import Counter

    roots = Counter(d.split("/", 1)[0] for d in dests)
    most_common, count = roots.most_common(1)[0]
    if count / len(dests) > 0.9:
        return most_common
    return ""


def _detect_slug_structure(config: dict) -> tuple[bool, dict[str, str]]:
    """Detect whether a platform uses per-system slug destinations.

    Returns ``(is_slug_based, system_to_slug)`` where ``system_to_slug``
    maps system IDs to their destination slug prefix.  Slug-based means
    each system's files live under a per-system subfolder (e.g. RomM's
    ``bios/{platform_slug}/{file}``), with varying slugs across systems.

    Only returns True when nearly ALL destinations have a subfolder and
    nearly ALL systems map to a consistent slug, distinguishing true
    slug-based layouts (RomM) from platforms that happen to have some
    subfoldered files (RetroArch ``dc/``, ``neocd/``).
    """
    total_files = 0
    files_with_slash = 0
    sys_to_slug: dict[str, str] = {}
    total_systems_with_files = 0
    for sys_id, sys_data in config.get("systems", {}).items():
        files = sys_data.get("files", [])
        if not files:
            continue
        total_systems_with_files += 1
        slugs: set[str] = set()
        for f in files:
            d = f.get("destination", "")
            if d:
                total_files += 1
                if "/" in d:
                    files_with_slash += 1
                    slugs.add(d.split("/", 1)[0])
        if len(slugs) == 1:
            sys_to_slug[sys_id] = slugs.pop()

    if not sys_to_slug or total_files == 0:
        return False, {}
    # All conditions must hold for slug-based detection:
    # 1. Nearly all files have a subfolder
    # 2. Multiple distinct slugs (not a constant prefix)
    # 3. Nearly all systems with files map to a slug
    # 4. Files are exactly slug/filename (depth 2), not deeper
    unique_slugs = set(sys_to_slug.values())
    all_have_slash = files_with_slash / total_files > 0.95
    varying_slugs = len(unique_slugs) > 1
    high_coverage = len(sys_to_slug) / total_systems_with_files > 0.9
    # Count files deeper than slug/filename (e.g., amiga/bios/kick.rom)
    deep_files = 0
    for sys_data in config.get("systems", {}).values():
        for f in sys_data.get("files", []):
            d = f.get("destination", "")
            if d and d.count("/") > 1:
                deep_files += 1
    shallow = deep_files / total_files < 0.05 if total_files else True
    return (all_have_slash and varying_slugs and high_coverage and shallow), sys_to_slug


def _map_emulator_to_slug(
    profile: dict,
    platform_systems: set[str],
    norm_map: dict[str, str],
    sys_to_slug: dict[str, str],
) -> str:
    """Map an emulator to a destination slug for slug-based platforms."""
    from common import _norm_system_id

    emu_systems = set(profile.get("systems", []))
    # Direct match
    direct = emu_systems & platform_systems
    if direct:
        target = sorted(direct)[0]
        return sys_to_slug.get(target, "")
    # Normalized match
    for es in sorted(emu_systems):
        norm = _norm_system_id(es)
        if norm in norm_map:
            target = norm_map[norm]
            return sys_to_slug.get(target, "")
    return ""


def _collect_emulator_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    seen: set,
    base_dest: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
) -> list[dict]:
    """Collect core requirement files from emulator profiles not in the platform pack.

    Uses the same system-overlap matching as verify.py cross-reference:
    - Matches emulators by shared system IDs with the platform
    - Filters mode: standalone, type: launcher, type: alias
    - Respects data_directories coverage
    - Only returns files that exist in the repo (packable)

    When the same file is needed at multiple destinations by different cores
    (e.g. cdimono1.zip at root for cdi2015 and at same_cdi/bios/ for same_cdi),
    all destinations are included so every core finds its files.

    Works for ANY platform (RetroArch, Batocera, Recalbox, etc.)
    """
    from common import _norm_system_id, resolve_platform_cores
    from verify import find_undeclared_files

    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    # Detect destination conventions for core extras
    extras_prefix = _detect_extras_prefix(config, base_dest)
    is_slug_based, sys_to_slug = _detect_slug_structure(config)
    platform_systems = set(config.get("systems", {}).keys())
    norm_map: dict[str, str] = {}
    if is_slug_based:
        for sid in platform_systems:
            norm_map[_norm_system_id(sid)] = sid

    # Use strict YAML names (no DB alias enrichment) so that files known
    # under an alias still get packed at the emulator's expected path.
    yaml_names: set[str] = set()
    for system in config.get("systems", {}).values():
        for fe in system.get("files", []):
            name = fe.get("name", "")
            if name:
                yaml_names.add(name)

    undeclared = find_undeclared_files(
        config, emulators_dir, db, emu_profiles, target_cores=target_cores,
        include_all=include_all, declared_names=yaml_names,
    )
    extras = []
    seen_dests: set[str] = set(seen)
    for u in undeclared:
        if not u["in_repo"]:
            continue
        # For archive entries, use the archive name for resolution
        archive = u.get("archive")
        name = archive if archive else u["name"]
        raw_dest = archive if archive else (u.get("path") or u["name"])
        # Directory path: append filename (e.g. "cafeLibs/" + "snd_user.rpl")
        dest = f"{raw_dest}{u['name']}" if raw_dest.endswith("/") else raw_dest

        # Slug-based platforms: prefix dest with system slug
        if is_slug_based:
            emu_name = u.get("profile") or u.get("emulator", "")
            profile = profiles.get(emu_name, {})
            # Try finding profile by display name if key lookup failed
            if not profile:
                for pn, pp in profiles.items():
                    if pp.get("emulator") == emu_name:
                        profile = pp
                        break
            slug = _map_emulator_to_slug(
                profile,
                platform_systems,
                norm_map,
                sys_to_slug,
            )
            if not slug:
                continue  # can't place without slug
            dest = f"{slug}/{dest}"

        full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
        if full_dest in seen_dests:
            continue
        seen_dests.add(full_dest)
        extra = {
            "name": name,
            "destination": dest,
            "required": u.get("required", False),
            "hle_fallback": u.get("hle_fallback", False),
            "source_emulator": u.get("emulator", ""),
            "source_profile": u.get("profile", ""),
            "source_system": u.get("system"),
            "source_systems": u.get("systems", []),
            "region": u.get("region"),
            "variant_group": u.get("variant_group"),
        }
        # Keep every reproducible identity constraint carried by the source
        # profile.  Some profiles expose CRC32/SHA-256 only through their
        # validation block; dropping those fields here would let a same-named
        # but different payload enter a generated pack.
        expected = u.get("expected") or {}
        for identity in ("sha1", "md5", "sha256", "crc32", "size"):
            declared = u.get(identity)
            if declared in (None, "", []):
                declared = expected.get(identity)
            if declared not in (None, "", []):
                extra[identity] = declared
        extras.append(extra)

    # Second pass: find alternative destinations for files already in the pack.
    # A file declared by the platform or emitted above may also be needed at a
    # different path by another core (e.g. neocd/ vs root, same_cdi/bios/ vs root).
    # Only adds a copy when the file is ALREADY covered at a different path -
    # never introduces a file that wasn't selected by the first pass.
    #
    # Skip for slug-based platforms (RomM): alternative paths don't map to
    # the required {platform_slug}/{file} structure.
    if is_slug_based:
        return extras

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    standalone_set = {str(c) for c in config.get("standalone_cores", [])}
    by_name = db.get("indexes", {}).get("by_name", {})
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})

    # Build set of filenames already covered (platform baseline + first pass extras)
    # Enriched with canonical names from DB via MD5 (handles platform renaming)
    covered_names = expand_platform_declared_names(config, db)
    for e in extras:
        covered_names.add(e["name"])

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        is_standalone = emu_name in standalone_set or bool(
            standalone_set & {str(c) for c in profile.get("cores", [])}
        )
        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname:
                continue
            # Only duplicate files already covered at another destination
            if fname not in covered_names:
                continue
            file_mode = f.get("mode")
            if file_mode == "standalone" and not is_standalone:
                continue
            if file_mode == "libretro" and is_standalone:
                continue
            # Skip files loaded from non-system directories (save_dir, content_dir)
            load_from = f.get("load_from", "")
            if load_from and load_from != "system_dir":
                continue
            if is_standalone:
                raw = f.get("standalone_path") or f.get("path") or fname
            else:
                raw = f.get("path") or fname
            dest = f"{raw}{fname}" if raw.endswith("/") else raw
            if dest == fname:
                continue  # no alternative destination
            full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
            if full_dest in seen_dests:
                continue
            # Check file exists in repo or data dirs
            if not (
                by_name.get(fname)
                or by_name.get(dest.rsplit("/", 1)[-1])
                or by_path_suffix.get(dest)
            ):
                continue
            seen_dests.add(full_dest)
            extras.append(
                {
                    "name": fname,
                    "destination": dest,
                    "required": f.get("required", False),
                    "hle_fallback": f.get("hle_fallback", False),
                    "source_emulator": profile.get("emulator", emu_name),
                    "source_profile": emu_name,
                    "source_system": f.get("system"),
                    "source_systems": list(profile.get("systems", [])),
                    "region": f.get("region"),
                    "variant_group": f.get("variant_group"),
                }
            )

    # Archive prefix pass: cores that store BIOS archives in a subdirectory
    # (e.g. system/fbneo/neogeo.zip).  When the archive is already covered at
    # the root, add a copy at the prefixed path so the core's .info firmware
    # check finds it.
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        prefix = profile.get("archive_prefix", "")
        if not prefix:
            continue
        profile_archives: dict[str, dict] = {}
        for f in profile.get("files", []):
            archive = f.get("archive", "")
            if archive:
                profile_archives.setdefault(archive, f)
        for archive_name, archive_entry in sorted(profile_archives.items()):
            if archive_name not in covered_names:
                continue
            dest = f"{prefix}/{archive_name}"
            full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
            if full_dest in seen_dests:
                continue
            if not by_name.get(archive_name):
                continue
            seen_dests.add(full_dest)
            extras.append(
                {
                    "name": archive_name,
                    "destination": dest,
                    "required": True,
                    "hle_fallback": False,
                    "source_emulator": profile.get("emulator", emu_name),
                    "source_profile": emu_name,
                    "source_system": archive_entry.get("system"),
                    "source_systems": list(profile.get("systems", [])),
                    "region": archive_entry.get("region"),
                    "variant_group": archive_entry.get("variant_group"),
                }
            )

    # Third pass: agnostic scan — for filename-agnostic cores, include all
    # DB files matching the system path prefix and size criteria.
    files_db = db.get("files", {})
    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue
        is_profile_agnostic = profile.get("bios_mode") == "agnostic"
        if not is_profile_agnostic:
            if not any(f.get("agnostic") for f in profile.get("files", [])):
                continue

        for f in profile.get("files", []):
            if not is_profile_agnostic and not f.get("agnostic"):
                continue
            fname = f.get("name", "")
            if not fname:
                continue

            # Derive path prefix from the representative file in the DB
            path_prefix = None
            sha1_list = by_name.get(fname, [])
            for sha1 in sha1_list:
                entry = files_db.get(sha1, {})
                path = entry.get("path", "")
                if path:
                    parts = path.rsplit("/", 1)
                    if len(parts) == 2:
                        path_prefix = parts[0] + "/"
                    break

            if not path_prefix:
                # Fallback: try other files in the profile for the same system
                for other_f in profile.get("files", []):
                    if other_f is f:
                        continue
                    other_name = other_f.get("name", "")
                    for sha1 in by_name.get(other_name, []):
                        entry = files_db.get(sha1, {})
                        path = entry.get("path", "")
                        if path:
                            parts = path.rsplit("/", 1)
                            if len(parts) == 2:
                                path_prefix = parts[0] + "/"
                            break
                    if path_prefix:
                        break

            if not path_prefix:
                continue

            # Size criteria from the file entry
            min_size = f.get("min_size", 0)
            max_size = f.get("max_size", float("inf"))
            exact_size = f.get("size")
            if exact_size and not min_size:
                min_size = exact_size
                max_size = exact_size

            # Scan DB for all files under this prefix matching size
            for sha1, entry in files_db.items():
                path = entry.get("path", "")
                if not path.startswith(path_prefix):
                    continue
                size = entry.get("size", 0)
                if not (min_size <= size <= max_size):
                    continue
                scan_name = entry.get("name", "")
                if not scan_name:
                    continue
                dest = scan_name
                full_dest = f"{extras_prefix}/{dest}" if extras_prefix else dest
                if full_dest in seen_dests:
                    continue
                seen_dests.add(full_dest)
                extras.append(
                    {
                        "name": scan_name,
                        "destination": dest,
                        "required": False,
                        "hle_fallback": False,
                        "source_emulator": profile.get("emulator", emu_name),
                        "source_profile": emu_name,
                        "source_system": f.get("system"),
                        "source_systems": list(profile.get("systems", [])),
                        "region": f.get("region"),
                        "variant_group": f.get("variant_group"),
                        "agnostic_scan": True,
                    }
                )

    return extras


def _extra_system_ids(extra: dict) -> list[str]:
    """Return the narrowest system ownership preserved on a core extra."""
    explicit = extra.get("source_system")
    if explicit:
        return [str(explicit)]
    return [str(value) for value in extra.get("source_systems", []) if value]


def _emulator_region_group(emu_name: str, profile: dict, file_entry: dict) -> str:
    """Stable group ID for regional alternatives within an emulator profile."""
    variant = file_entry.get("variant_group")
    if variant:
        return f"{emu_name}:variant:{variant}"
    system = file_entry.get("system")
    profile_systems = list(profile.get("systems", []))
    if not system and len(profile_systems) == 1:
        system = profile_systems[0]
    return f"{emu_name}:system:{system or '_profile'}"


def _build_readme(
    platform_name: str,
    platform_display: str,
    base_dest: str,
    total_files: int,
    num_systems: int,
    source: str = "full",
    contributors: list[dict] | None = None,
    regions: list[str] | None = None,
    fallback_systems: list[str] | None = None,
) -> str:
    """Build a personalized step-by-step README for each platform pack."""
    sep = "=" * 50
    header = (
        f"{sep}\n"
        f"  RETROBIOS - {platform_display} BIOS Pack\n"
        f"  {total_files} files for {num_systems} systems\n"
        f"{sep}\n\n"
    )

    guides: dict[str, str] = {
        "retroarch": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Run this in a terminal:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  The script auto-detects your RetroArch install and copies\n"
            "  files to the correct location.\n\n"
            "  Option B: Manual (PC)\n"
            "  ---------------------\n"
            "  1. Find your RetroArch system directory:\n"
            "     - RetroArch > Settings > Directory > System/BIOS\n"
            "     - Default: retroarch/system/\n"
            "  2. Extract all files from this archive directly into your system directory\n"
            "  3. Overwrite if asked\n\n"
            "  Option C: Manual (handheld / SD card)\n"
            "  -------------------------------------\n"
            "  Anbernic, Retroid, Miyoo, Trimui, etc.:\n"
            "  1. Connect your SD card to your PC\n"
            "  2. Find the BIOS folder (usually BIOS/ or system/)\n"
            "  3. Extract all files from this archive directly into that folder\n"
            "  4. Eject SD card and reboot your device\n\n"
            "  Common paths by device:\n"
            "    Anbernic (ArkOS/JELOS): BIOS/\n"
            "    Retroid (RetroArch):     RetroArch/system/\n"
            "    Miyoo Mini (Onion OS):   BIOS/\n"
            "    Steam Deck (RetroArch):  ~/.config/retroarch/system/\n\n"
        ),
        "batocera": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open a terminal (F1 from Batocera menu) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual (network share)\n"
            "  --------------------------------\n"
            "  1. On your PC, open the Batocera network share:\n"
            "     - Windows: \\\\BATOCERA\\share\\bios\\\n"
            "     - Mac/Linux: smb://batocera/share/bios/\n"
            "  2. Extract all files from this archive directly into the share\n"
            "  3. Overwrite if asked\n\n"
            "  Option C: Manual (SD card)\n"
            "  --------------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /userdata/bios/ on the SHARE partition\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
            "  NOTE: Dreamcast flash memory is named dc_nvmem.bin\n"
            "  (if your setup asks for dc_flash.bin, same file).\n\n"
        ),
        "recalbox": (
            "INSTALLATION GUIDE\n\n"
            "  Option A: Automatic\n"
            "  -------------------\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual (network share)\n"
            "  --------------------------------\n"
            "  1. On your PC, open the Recalbox network share:\n"
            "     - Windows: \\\\RECALBOX\\share\\bios\\\n"
            "     - Mac/Linux: smb://recalbox/share/bios/\n"
            "  2. Extract all files from this archive directly into the share\n\n"
            "  Option C: Manual (SD card)\n"
            "  --------------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /recalbox/share/bios/\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
        ),
        "emudeck": (
            "INSTALLATION GUIDE (Steam Deck / Linux)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open Konsole (or any terminal) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  The script places BIOS files AND sets up standalone\n"
            "  emulator keys automatically.\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open Dolphin file manager\n"
            "  2. Navigate to ~/Emulation/bios/\n"
            "  3. Extract all files from this archive directly into ~/Emulation/bios/\n\n"
            "  STANDALONE EMULATORS (extra step)\n"
            "  Switch and 3DS emulators need keys in specific folders:\n"
            "    prod.keys  -> ~/.local/share/yuzu/keys/\n"
            "    prod.keys  -> ~/.local/share/eden/keys/\n"
            "    prod.keys  -> ~/.config/Ryujinx/system/\n"
            "    aes_keys.txt -> ~/Emulation/bios/citra/keys/\n"
            "  The automatic installer handles this for you.\n\n"
        ),
        "retrodeck": (
            "INSTALLATION GUIDE (Steam Deck / Linux)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Open Konsole (or any terminal) and run:\n\n"
            "    curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open Dolphin file manager\n"
            "  2. Show hidden files (Ctrl+H)\n"
            "  3. Navigate to ~/retrodeck/bios/\n"
            "  4. Extract all files from this archive directly into ~/retrodeck/bios/\n\n"
            "  NOTE: RetroDECK uses its own BIOS checker. After\n"
            "  copying, open RetroDECK > Tools > BIOS Checker to\n"
            "  verify everything is detected.\n\n"
        ),
        "retrobat": (
            "INSTALLATION GUIDE (Windows)\n\n"
            "  Option A: Automatic (recommended)\n"
            "  ---------------------------------\n"
            "  Download and run install.bat from:\n"
            "  https://github.com/Abdess/retrobios/releases\n\n"
            "  Option B: Manual\n"
            "  ----------------\n"
            "  1. Open your RetroBat installation folder\n"
            "  2. Navigate to the bios\\ subfolder\n"
            "     (default: C:\\RetroBat\\bios\\)\n"
            "  3. Extract all files from this archive directly into your bios\\ folder\n"
            "  4. Overwrite if asked\n\n"
        ),
        "bizhawk": (
            "INSTALLATION GUIDE\n\n"
            "  1. Open your BizHawk installation folder\n"
            "  2. Navigate to the Firmware subfolder:\n"
            "     - Windows: BizHawk\\Firmware\\\n"
            "     - Linux: ~/.config/BizHawk/Firmware/\n"
            "  3. Extract all files from this archive directly into your Firmware folder\n"
            "  4. In BizHawk: Config > Paths > Firmware should\n"
            "     point to this folder\n\n"
        ),
        "romm": (
            "INSTALLATION GUIDE (RomM server)\n\n"
            "  1. Locate your RomM library folder\n"
            "  2. Navigate to the bios/ subdirectory\n"
            "  3. Extract all files from this archive directly into that folder\n"
            "  4. Restart the RomM service to detect new files\n\n"
        ),
        "retropie": (
            "INSTALLATION GUIDE (Raspberry Pi)\n\n"
            "  Option A: Via network share\n"
            "  --------------------------\n"
            "  1. On your PC, open: \\\\RETROPIE\\bios\\\n"
            "  2. Extract all files from this archive directly into that folder\n\n"
            "  Option B: Via SSH\n"
            "  -----------------\n"
            "  1. SSH into your Pi: ssh pi@retropie\n"
            "  2. Copy files to ~/RetroPie/BIOS/\n\n"
            "  Option C: Via SD card\n"
            "  ---------------------\n"
            "  1. Put the SD card in your PC\n"
            "  2. Navigate to /home/pi/RetroPie/BIOS/\n"
            "  3. Extract all files from this archive directly into that folder\n\n"
        ),
    }

    # Lakka uses same guide as RetroArch
    guides["lakka"] = guides["retroarch"]

    guide = guides.get(
        platform_name,
        (
            f"INSTALLATION\n\n"
            f"  1. Extract all files from this archive directly into your BIOS directory\n"
            f"  2. Overwrite if asked\n\n"
        ),
    )

    if regions:
        region_help = (
            "  - Wrong region? This pack was filtered. Only the\n"
            "    best-matching BIOS was kept per system. Use the\n"
            "    unfiltered pack to play imports.\n"
        )
    else:
        region_help = (
            "  - Wrong region? Some systems have regional BIOS\n"
            "    variants (USA/EUR/JAP). All are included.\n"
        )
    footer = (
        "TROUBLESHOOTING\n\n"
        "  - Core says BIOS missing? Check the exact filename\n"
        "    and make sure it's in the right subfolder.\n"
        f"{region_help}"
        "  - Need help? https://github.com/Abdess/retrobios/issues\n\n"
        f"{sep}\n"
        f"  https://github.com/Abdess/retrobios\n"
        f"{sep}\n"
    )

    source_info = ""
    if source == "platform":
        source_info = (
            "PACK TYPE: Platform Only\n\n"
            f"  This pack contains only files declared by {platform_display}.\n"
            "  Core extras from emulator profiles are not included.\n"
            "  Use the Full pack for maximum coverage.\n\n"
        )
    elif source == "truth":
        source_info = (
            "PACK TYPE: Ground Truth\n\n"
            "  This pack contains files that emulators actually load,\n"
            "  based on source code analysis of emulator profiles.\n"
            "  Independent of platform scraper accuracy.\n\n"
        )

    region_info = ""
    if regions:
        pretty = ", ".join(
            " ".join(w.title() for w in slug.split("-")) for slug in regions
        )
        region_info = (
            "PACK TYPE: Region Filtered\n\n"
            f"  Region priority: {pretty}\n\n"
            "  Only the best-matching BIOS was kept for each system.\n"
        )
        if fallback_systems:
            listed = "\n".join(f"    {s}" for s in fallback_systems)
            region_info += (
                "\n  These systems have no BIOS in those regions, so all\n"
                "  of theirs were kept:\n"
                f"{listed}\n"
            )
        region_info += (
            "\n  This shrinks the pack. It does not change how cores pick\n"
            "  a BIOS: most already select per region from fixed filename\n"
            "  lists driven by the game's region. Loading imports from\n"
            "  another region may need the unfiltered pack.\n\n"
        )

    credits = ""
    if contributors:
        credits = "\nCONTRIBUTORS\n\n"
        for cb in contributors:
            username = cb.get("username", "")
            credits += f"  @{username}\n"
        credits += "\n"

    return header + source_info + region_info + guide + credits + footer


def _build_agnostic_rename_readme(
    destination: str,
    original: str,
    alternatives: list[str],
) -> str:
    """Build a README explaining an agnostic file rename."""
    lines = [
        "This file was renamed for compatibility:",
        f"  {destination} <- {original}",
        "",
    ]
    if alternatives:
        lines.append("All variants included in this pack:")
        for alt in sorted(alternatives):
            lines.append(f"  {alt}")
        lines.append("")
        lines.append(f"To use a different variant, rename it to: {destination}")
    return "\n".join(lines) + "\n"


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    include_extras: bool = False,
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
    system_filter: list[str] | None = None,
    precomputed_extras: list[dict] | None = None,
    source: str = "full",
    flatten: bool = True,
    regions: list[str] | None = None,
    target_name: str | None = None,
    offline: bool | None = None,
) -> str | None:
    """Generate a ZIP pack for a platform.

    Returns the path to the generated ZIP, or None on failure.
    """
    config = load_platform_config(platform_name, platforms_dir)
    if zip_contents is None:
        zip_contents = {}

    verification_mode = config.get("verification_mode", "existence")
    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")

    version = config.get("version", config.get("dat_version", ""))
    version_tag = f"_{version.replace(' ', '')}" if version else ""
    req_tag = "_Required" if required_only else ""
    source_tag = {"platform": "_Platform", "truth": "_Truth"}.get(source, "")
    region_tag_str = f"_{region_mod.region_tag(regions)}" if regions else ""
    target_tag = f"_{_target_tag(target_name)}" if target_name else ""

    sys_tag = ""
    if system_filter:
        display_parts = []
        for sid in system_filter:
            s = sid.lower().replace("_", "-")
            for prefix in MANUFACTURER_PREFIXES:
                if s.startswith(prefix):
                    s = s[len(prefix) :]
                    break
            parts = s.split("-")
            display_parts.append("_".join(p.title() for p in parts if p))
        sys_tag = "_" + "_".join(display_parts)

    zip_name = f"{platform_display.replace(' ', '_')}{version_tag}{source_tag}{region_tag_str}{target_tag}{req_tag}_BIOS_Pack{sys_tag}.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    # Case-insensitive dedup only for platforms targeting Windows/macOS.
    # Linux-only platforms (Batocera, Recalbox, RetroDECK, Lakka, RomM)
    # are case-sensitive and may have distinct files like DISK.ROM vs disk.rom.
    case_insensitive = config.get("case_insensitive_fs", False)

    total_files = 0
    missing_files = []
    # Core extras whose local copy contradicts the profile hash: packed,
    # reported, and never counted against the platform's own file total.
    core_discrepancies: list[str] = []
    user_provided = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()  # only used when case_insensitive=True
    seen_parents: set[str] = (
        set()
    )  # parent dirs of added files (path conflict detection)
    # Per-destination status.  ``excluded`` means a same-named local payload
    # exists but contradicts the declaration and is intentionally not shipped.
    # It is distinct from a genuine coverage gap (``missing``).
    file_status: dict[str, str] = {}
    file_reasons: dict[str, str] = {}

    # Build emulator-level validation index (same as verify.py)
    validation_index = {}
    if emu_profiles:
        validation_index = _build_validation_index(emu_profiles)

    # Filter systems by target if specified
    from common import resolve_platform_cores

    plat_cores = (
        resolve_platform_cores(config, emu_profiles or {}) if target_cores else None
    )
    pack_systems = filter_systems_by_target(
        config.get("systems", {}),
        emu_profiles or {},
        target_cores,
        platform_cores=plat_cores,
    )

    if system_filter:
        from common import _norm_system_id

        norm_filter = {_norm_system_id(s) for s in system_filter}
        filtered = {
            sid: sys_data
            for sid, sys_data in pack_systems.items()
            if sid in system_filter or _norm_system_id(sid) in norm_filter
        }
        if not filtered:
            available = sorted(pack_systems.keys())[:10]
            print(
                f"  WARNING: no systems matched filter {system_filter} "
                f"(available: {', '.join(available)})"
            )
            return None
        pack_systems = filtered

    # Constrained-entry preference: platforms may declare the same
    # destination several times (bare in one system, hash-constrained in
    # another). First-come dedup would let the bare entry pack a wrong
    # same-named file, so when a hash-constrained sibling resolves to a
    # matching repo file, it claims the destination instead.
    preferred_entries: dict[str, int] = {}
    if source != "truth":
        dest_entries: dict[str, list[dict]] = {}
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = _sanitize_path(
                    file_entry.get("destination", file_entry.get("name", ""))
                )
                if not dest:
                    continue
                full = f"{base_dest}/{dest}" if base_dest else dest
                dest_entries.setdefault(full, []).append(file_entry)
        for full, entries in dest_entries.items():
            if len(entries) < 2:
                continue
            constrained = [
                fe
                for fe in entries
                if fe.get("md5") or fe.get("sha1") or fe.get("zipped_file")
            ]
            if not constrained:
                continue
            best = None
            for fe in constrained:
                _lp, _st = resolve_file(
                    fe,
                    db,
                    bios_dir,
                    zip_contents,
                    data_dir_registry=data_registry,
                    offline=offline,
                )
                if _lp and _st == "md5_exact":
                    best = fe
                    break
                if best is None and _lp and resolution_is_hash_exact(_st):
                    best = fe
            if best is not None:
                preferred_entries[full] = id(best)

    # Region selection is decided once, over both the platform baseline and the
    # core extras, so the two phases below consult a single set. Grouping uses a
    # dedicated extras pass with an empty seen set: it only needs group
    # membership, never destinations, and a superset of members is the safe
    # direction. Runs only when --region is given.
    region_drops: set[str] = set()
    region_fallbacks: list[str] = []
    if regions:
        region_index = region_mod.build_region_index(emu_profiles or {})
        region_groups: dict[str, list[tuple[str, str]]] = {}
        for sys_id, system in pack_systems.items():
            members = region_groups.setdefault(sys_id, [])
            for file_entry in system.get("files", []):
                dest = _sanitize_path(
                    file_entry.get("destination", file_entry.get("name", ""))
                )
                if dest:
                    members.append((dest, file_entry.get("name", "")))
        if source != "platform":
            for fe in _collect_emulator_extras(
                config,
                emulators_dir,
                db,
                set(),
                base_dest,
                emu_profiles,
                target_cores=target_cores,
                include_all=(source == "truth"),
            ):
                dest = _sanitize_path(fe.get("destination", fe.get("name", "")))
                if not dest:
                    continue
                systems = _extra_system_ids(fe) or ["_extras"]
                for sys_id in systems:
                    variant = fe.get("variant_group")
                    group_id = f"{sys_id}:variant:{variant}" if variant else sys_id
                    region_groups.setdefault(group_id, []).append(
                        (dest, fe.get("name", ""))
                    )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions
        )
        region_fallbacks = region_mod.fallback_groups(
            region_groups, region_index, regions
        )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
      if source != "truth":
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                if required_only and file_entry.get("required") is False:
                    continue
                dest = _sanitize_path(file_entry.get("destination", file_entry["name"]))
                if region_drops and dest in region_drops:
                    continue
                if not dest:
                    # EmuDeck-style entries (system:md5 whitelist, no filename).
                    fkey = f"{sys_id}/{file_entry.get('name', '')}"
                    md5 = file_entry.get("md5", "")
                    if md5 and md5 in db.get("indexes", {}).get("by_md5", {}):
                        file_status.setdefault(fkey, "ok")
                    else:
                        file_status[fkey] = "missing"
                    continue
                if base_dest:
                    full_dest = f"{base_dest}/{dest}"
                else:
                    full_dest = dest

                dedup_key = full_dest
                already_packed = dedup_key in seen_destinations or (
                    case_insensitive and dedup_key.lower() in seen_lower
                )

                preferred = preferred_entries.get(dedup_key)
                if preferred is not None and id(file_entry) != preferred:
                    continue

                if _has_path_conflict(full_dest, seen_destinations, seen_parents):
                    # Content ships under the conflicting shape (file vs dir,
                    # e.g. SGB1.sfc): count it so pack totals match verify.py,
                    # which resolves each declaration independently
                    file_status.setdefault(dedup_key, "ok")
                    continue

                storage = file_entry.get("storage", "embedded")

                if storage == "user_provided":
                    if already_packed:
                        continue
                    seen_destinations.add(dedup_key)
                    _register_path(dedup_key, seen_destinations, seen_parents)
                    if case_insensitive:
                        seen_lower.add(dedup_key.lower())
                    file_status.setdefault(dedup_key, "ok")
                    instructions = file_entry.get(
                        "instructions", "Please provide this file manually."
                    )
                    instr_name = f"INSTRUCTIONS_{file_entry['name']}.txt"
                    instr_path = (
                        f"{base_dest}/{instr_name}" if base_dest else instr_name
                    )
                    _write_generated_member(
                        zf,
                        _flat(instr_path, base_dest, flatten),
                        f"File needed: {file_entry['name']}\n\n{instructions}\n",
                    )
                    user_provided.append(file_entry["name"])
                    total_files += 1
                    continue

                local_path, status = resolve_file(
                    file_entry,
                    db,
                    bios_dir,
                    zip_contents,
                    data_dir_registry=data_registry,
                    offline=offline,
                )

                if status == "external":
                    file_ext = os.path.splitext(file_entry["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(
                        delete=False, suffix=file_ext
                    ) as tmp:
                        tmp_path = tmp.name

                    try:
                        if download_external(file_entry, tmp_path):
                            extract = file_entry.get("extract", False)
                            if extract and tmp_path.endswith(".zip"):
                                _extract_zip_to_archive(tmp_path, _flat(full_dest, base_dest, flatten), zf)
                            else:
                                zf.write(tmp_path, _flat(full_dest, base_dest, flatten))
                            seen_destinations.add(dedup_key)
                            _register_path(dedup_key, seen_destinations, seen_parents)
                            if case_insensitive:
                                seen_lower.add(dedup_key.lower())
                            file_status.setdefault(dedup_key, "ok")
                            total_files += 1
                        else:
                            file_status[dedup_key] = "missing"
                            file_reasons[dedup_key] = "external download failed"
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status == "not_found":
                    # Agnostic fallback: if an agnostic core covers this system,
                    # find any matching file in the DB
                    by_name = db.get("indexes", {}).get("by_name", {})
                    files_db = db.get("files", {})
                    agnostic_path = None
                    agnostic_resolved = False
                    if emu_profiles:
                        for _emu_key, _emu_prof in emu_profiles.items():
                            if _emu_prof.get("bios_mode") != "agnostic":
                                continue
                            if sys_id not in set(_emu_prof.get("systems", [])):
                                continue
                            for _ef in _emu_prof.get("files", []):
                                ef_name = _ef.get("name", "")
                                for _sha1 in by_name.get(ef_name, []):
                                    _entry = files_db.get(_sha1, {})
                                    _path = _entry.get("path", "")
                                    if _path:
                                        _prefix = _path.rsplit("/", 1)[0] + "/"
                                        _min = _ef.get("min_size", 0)
                                        _max = _ef.get("max_size", float("inf"))
                                        if _ef.get("size") and not _min:
                                            _min = _ef["size"]
                                            _max = _ef["size"]
                                        for _s, _e in files_db.items():
                                            if _e.get("path", "").startswith(_prefix):
                                                if _min <= _e.get("size", 0) <= _max:
                                                    if os.path.exists(_e["path"]):
                                                        local_path = _e["path"]
                                                        agnostic_path = _prefix
                                                        agnostic_resolved = True
                                                        break
                                        break
                                if agnostic_resolved:
                                    break
                            if agnostic_resolved:
                                break

                    if agnostic_resolved and local_path:
                        # Write rename README
                        original_name = os.path.basename(local_path)
                        dest_name = file_entry.get("name", "")
                        if original_name != dest_name and agnostic_path:
                            alt_names = []
                            for _s, _e in files_db.items():
                                _p = _e.get("path", "")
                                if _p.startswith(agnostic_path):
                                    _n = _e.get("name", "")
                                    if _n and _n != original_name:
                                        alt_names.append(_n)
                            readme_text = _build_agnostic_rename_readme(
                                dest_name,
                                original_name,
                                alt_names,
                            )
                            readme_name = f"RENAMED_{dest_name}.txt"
                            readme_full = (
                                f"{base_dest}/{readme_name}"
                                if base_dest
                                else readme_name
                            )
                            if readme_full not in seen_destinations:
                                _write_generated_member(
                                    zf,
                                    _flat(readme_full, base_dest, flatten),
                                    readme_text,
                                )
                                seen_destinations.add(readme_full)
                        status = "agnostic_fallback"
                        # Fall through to normal packing below
                    else:
                        if not already_packed:
                            file_status[dedup_key] = "missing"
                            file_reasons[dedup_key] = "not found"
                        continue

                if status == "hash_mismatch" and verification_mode != "existence":
                    zf_name = file_entry.get("zipped_file")
                    if zf_name and local_path:
                        inner_md5_raw = file_entry.get("md5", "")
                        inner_md5_list = (
                            [m.strip() for m in inner_md5_raw.split(",") if m.strip()]
                            if inner_md5_raw
                            else [""]
                        )
                        zip_ok = False
                        last_result = "not_in_zip"
                        for md5_candidate in inner_md5_list:
                            last_result = check_inside_zip(
                                local_path, zf_name, md5_candidate
                            )
                            if last_result == "ok":
                                zip_ok = True
                                break
                        if zip_ok:
                            status = "zip_exact"
                            file_status.setdefault(dedup_key, "ok")
                        elif last_result == "not_in_zip":
                            file_status[dedup_key] = "excluded"
                            file_reasons[dedup_key] = f"{zf_name} not found inside ZIP"
                        elif last_result == "error":
                            file_status[dedup_key] = "excluded"
                            file_reasons[dedup_key] = "cannot read ZIP"
                        else:
                            file_status[dedup_key] = "excluded"
                            file_reasons[dedup_key] = (
                                f"{zf_name} MD5 mismatch inside ZIP"
                            )
                        if not zip_ok:
                            continue
                    else:
                        file_status[dedup_key] = "excluded"
                        file_reasons[dedup_key] = "hash mismatch"
                        continue
                else:
                    # Existence platforms accept any file at the declared path:
                    # their code never reads the bytes. An upstream hash that
                    # contradicts a local dump is reported, not acted on.
                    if status == "hash_mismatch" and local_path:
                        declared = file_entry.get("md5", "") or file_entry.get(
                            "sha1", ""
                        )
                        actual = compute_hashes(local_path)
                        file_reasons.setdefault(
                            dedup_key,
                            f"packed per {platform_display} existence check; "
                            f"declared hash {declared}, file md5 "
                            f"{actual['md5']} sha1 {actual['sha1']}",
                        )
                    file_status.setdefault(dedup_key, "ok")

                # Emulator-level validation: informational only for platform packs.
                # Platform verification (existence/md5) is the authority for pack status.
                # Emulator checks are supplementary -logged but don't downgrade.
                # When a discrepancy is found, try to find a file satisfying both.
                if (
                    file_status.get(dedup_key) == "ok"
                    and local_path
                    and validation_index
                ):
                    fname = file_entry.get("name", "")
                    check = check_file_validation(
                        local_path, fname, validation_index, bios_dir
                    )
                    if check:
                        reason, emus_list = check
                        better = _find_candidate_satisfying_both(
                            file_entry,
                            db,
                            local_path,
                            validation_index,
                            bios_dir,
                        )
                        if better:
                            local_path = better
                        else:
                            emus = ", ".join(emus_list)
                            file_reasons.setdefault(
                                dedup_key,
                                f"{platform_display} says OK but {emus} says {reason}",
                            )

                if already_packed:
                    continue
                seen_destinations.add(dedup_key)
                _register_path(dedup_key, seen_destinations, seen_parents)
                if case_insensitive:
                    seen_lower.add(dedup_key.lower())

                extract = file_entry.get("extract", False)
                flat_dest = _flat(full_dest, base_dest, flatten)
                if extract and local_path.endswith(".zip"):
                    _extract_zip_to_archive(local_path, flat_dest, zf)
                elif local_path.endswith(".zip"):
                    _add_zip_to_pack(local_path, flat_dest, zf, file_entry)
                else:
                    zf.write(local_path, flat_dest)
                total_files += 1

      # Core requirements: files platform's cores need but YAML doesn't declare
      if emu_profiles is None:
          emu_profiles = load_emulator_profiles(emulators_dir)
      if source == "platform":
          core_files = []
      elif precomputed_extras is not None:
          core_files = precomputed_extras
      elif system_filter and source != "truth":
          core_files = []
      else:
          core_files = _collect_emulator_extras(
              config,
              emulators_dir,
              db,
              seen_destinations,
              base_dest,
              emu_profiles,
              target_cores=target_cores,
              include_all=(source == "truth"),
          )

      # Truth mode + system_filter: filter core files by system ID
      if system_filter and source == "truth" and core_files:
          from common import _norm_system_id

          norm_filter = {_norm_system_id(s) for s in system_filter} | set(
              system_filter
          )
          core_files = [
              fe
              for fe in core_files
              if (
                  set(_extra_system_ids(fe))
                  | {_norm_system_id(s) for s in _extra_system_ids(fe)}
              )
              & norm_filter
          ]
      core_count = 0
      for fe in core_files:
          if required_only and fe.get("required") is False:
              continue
          dest = _sanitize_path(fe.get("destination", fe["name"]))
          if region_drops and dest in region_drops:
              continue
          if not dest:
              continue
          # Core extras: _collect_emulator_extras already adjusted
          # destinations for slug-based platforms.  Apply the effective
          # prefix (base_dest, or inferred from YAML when base_dest is
          # empty — e.g. RetroDECK infers "bios").
          extras_pfx = _detect_extras_prefix(config, base_dest)
          if extras_pfx:
              if not dest.startswith(f"{extras_pfx}/"):
                  full_dest = f"{extras_pfx}/{dest}"
              else:
                  full_dest = dest
          else:
              full_dest = dest
          if full_dest in seen_destinations:
              continue
          # Skip case-insensitive duplicates (Windows/macOS FS safety)
          if full_dest.lower() in seen_lower and case_insensitive:
              continue
          # Skip file/directory path conflicts (e.g., SGB1.sfc file vs SGB1.sfc/ dir)
          if _has_path_conflict(full_dest, seen_destinations, seen_parents):
              continue

          dest_hint = fe.get("destination", "")
          local_path, status = resolve_file(
              fe,
              db,
              bios_dir,
              zip_contents,
              dest_hint=dest_hint,
              data_dir_registry=data_registry,
              offline=offline,
          )
          if status in ("not_found", "external", "user_provided") or not local_path:
              continue
          if status == "hash_mismatch":
              # The core's declared hash comes from its source, the local dump
              # is what the collection holds. Shipping it keeps the emulator
              # working when the code never reads the hash; the divergence is
              # reported so it can be resolved at the profile or the dump.
              # file_status tracks platform declarations only, so the report
              # goes to its own list and never moves the pack's own count.
              core_discrepancies.append(
                  f"{full_dest} -declared hash of "
                  f"{fe.get('source_profile') or fe.get('source_emulator', 'core profile')}"
                  " does not match the packed copy"
              )

          flat_dest = _flat(full_dest, base_dest, flatten)
          if local_path.endswith(".zip"):
              _add_zip_to_pack(local_path, flat_dest, zf, fe)
          else:
              zf.write(local_path, flat_dest)
          if file_status.get(full_dest) in ("missing", "excluded"):
              previous = file_status[full_dest]
              file_status[full_dest] = "ok"
              if previous == "excluded":
                  source_name = fe.get("source_profile") or fe.get(
                      "source_emulator", "core profile"
                  )
                  file_reasons[full_dest] = (
                      "platform-declared hash unavailable; "
                      f"packed the validated {source_name} requirement"
                  )
              else:
                  file_reasons.pop(full_dest, None)
          seen_destinations.add(full_dest)
          _register_path(full_dest, seen_destinations, seen_parents)
          if case_insensitive:
              seen_lower.add(full_dest.lower())
          core_count += 1
          total_files += 1

      # Data directories from _data_dirs.yml
      for sys_id, system in sorted(pack_systems.items()):
          for dd in system.get("data_directories", []):
              ref_key = dd.get("ref", "")
              if not ref_key or not data_registry or ref_key not in data_registry:
                  continue
              entry = data_registry[ref_key]
              allowed = entry.get("for_platforms")
              if allowed and platform_name not in allowed:
                  continue
              local_path = entry.get("local_cache", "")
              if not local_path or not os.path.isdir(local_path):
                  print(
                      f"  WARNING: data directory '{ref_key}' not cached at {local_path} -run refresh_data_dirs.py"
                  )
                  continue
              dd_dest = dd.get("destination", "")
              if base_dest and dd_dest:
                  dd_prefix = f"{base_dest}/{dd_dest}"
              elif base_dest:
                  dd_prefix = base_dest
              else:
                  dd_prefix = dd_dest
              for root, _dirs, filenames in os.walk(local_path):
                  for fname in filenames:
                      src = os.path.join(root, fname)
                      rel = os.path.relpath(src, local_path)
                      full = f"{dd_prefix}/{rel}"
                      if full in seen_destinations or (
                          full.lower() in seen_lower and case_insensitive
                      ):
                          continue
                      if _has_path_conflict(full, seen_destinations, seen_parents):
                          continue
                      seen_destinations.add(full)
                      _register_path(full, seen_destinations, seen_parents)
                      if case_insensitive:
                          seen_lower.add(full.lower())
                      zf.write(src, _flat(full, base_dest, flatten))
                      total_files += 1

      # README.txt for users -personalized step-by-step per platform
      num_systems = len(pack_systems)
      _registry_path = Path(platforms_dir) / "_registry.yml"
      _pack_registry: dict = {}
      if _registry_path.exists():
          with open(_registry_path) as _rf:
              _pack_registry = (yaml_load(_rf) or {}).get("platforms", {})
      readme_text = _build_readme(
          platform_name, platform_display, base_dest, total_files, num_systems,
          source=source,
          contributors=_pack_registry.get(platform_name, {}).get("contributed_by", []),
          regions=regions,
          fallback_systems=region_fallbacks,
      )
      _write_generated_member(zf, "README.txt", readme_text)

    files_ok = sum(1 for s in file_status.values() if s == "ok")
    files_untested = sum(1 for s in file_status.values() if s == "untested")
    files_excluded = sum(1 for s in file_status.values() if s == "excluded")
    files_miss = sum(1 for s in file_status.values() if s == "missing")
    total_checked = len(file_status)

    parts = [f"{files_ok}/{total_checked} files OK"]
    if files_untested:
        parts.append(f"{files_untested} untested")
    if files_excluded:
        parts.append(f"{files_excluded} unsafe excluded")
    if files_miss:
        parts.append(f"{files_miss} missing")
    if source == "platform":
        print(
            f"  {zip_path}: {total_files} files packed (platform baseline only), "
            f"{', '.join(parts)} [{verification_mode}]"
        )
    elif source == "truth":
        print(
            f"  {zip_path}: {total_files} files packed (ground truth only), "
            f"{core_count} from emulator profiles [{verification_mode}]"
        )
    else:
        baseline = total_files - core_count
        print(
            f"  {zip_path}: {total_files} files packed ({baseline} baseline + "
            f"{core_count} from cores), {', '.join(parts)} [{verification_mode}]"
        )

    for key, reason in sorted(file_reasons.items()):
        status = file_status.get(key, "")
        if status == "untested":
            label = "UNTESTED"
        elif status == "excluded":
            label = "EXCLUDED"
        elif status == "missing":
            label = "MISSING"
        else:
            label = "DISCREPANCY"
        print(f"  {label}: {key} -{reason}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    for note in sorted(core_discrepancies):
        print(f"  DISCREPANCY: {note}")
    return zip_path


def _extract_zip_to_archive(
    source_zip: str, dest_prefix: str, target_zf: zipfile.ZipFile
):
    """Extract contents of a source ZIP into target ZIP under dest_prefix."""
    with zipfile.ZipFile(source_zip, "r") as src:
        for info in src.infolist():
            if info.is_dir():
                continue
            clean_name = _sanitize_path(info.filename)
            if not clean_name:
                continue
            data = src.read(info.filename)
            target_path = f"{dest_prefix}/{clean_name}" if dest_prefix else clean_name
            target_zf.writestr(target_path, data)


def _add_zip_to_pack(
    source_zip: str,
    dest_path: str,
    target_zf: zipfile.ZipFile,
    file_entry: dict | None = None,
):
    """Write a source ZIP into the pack.

    A declared outer hash (md5/sha1/crc32) means the platform or profile
    verifies the ZIP bytes themselves (Batocera md5sum, System.dat), so
    the resolved file is copied unchanged: a rebuild would change the
    outer hash and fail the native check. Entries with zipped_file
    declare the hash of a ROM inside the ZIP (checkInsideZip), which a
    content-preserving rebuild does not affect.
    """
    if (
        file_entry
        and not file_entry.get("zipped_file")
        and (
            file_entry.get("md5")
            or file_entry.get("sha1")
            or file_entry.get("crc32")
        )
    ):
        target_zf.write(source_zip, dest_path)
        return
    _normalize_zip_for_pack(source_zip, dest_path, target_zf)


def _normalize_zip_for_pack(
    source_zip: str, dest_path: str, target_zf: zipfile.ZipFile
):
    """Add a MAME BIOS ZIP to the pack as a deterministic rebuild.

    Instead of copying the original ZIP (with non-deterministic metadata),
    extracts the ROM atoms, rebuilds the ZIP deterministically, and writes
    the normalized version into the pack.

    This ensures:
    - Same ROMs -> same ZIP hash in every pack build
    - No dependency on how the user built their MAME ROM set
    - Bit-identical ZIPs across platforms and build times
    """
    import tempfile as _tmp

    # tmp/ is gitignored, so a fresh clone does not carry it. WSL keeps /tmp
    # on a 4 GB tmpfs that MAME sets overflow, hence the repo-local scratch.
    os.makedirs("tmp", exist_ok=True)
    tmp_fd, tmp_path = _tmp.mkstemp(suffix=".zip", dir="tmp")
    os.close(tmp_fd)
    try:
        rebuild_zip_deterministic(source_zip, tmp_path)
        target_zf.write(tmp_path, dest_path)
    except zipfile.BadZipFile:
        # Corrupt source ZIP: copy as-is (will be flagged by verify)
        target_zf.write(source_zip, dest_path)
    finally:
        os.unlink(tmp_path)


# Emulator/system mode pack generation


def _resolve_destination(
    file_entry: dict, pack_structure: dict | None, standalone: bool
) -> str:
    """Resolve the ZIP destination path for a file entry."""
    # 1. standalone_path override
    if standalone and file_entry.get("standalone_path"):
        rel = file_entry["standalone_path"]
    # 2. path field
    elif file_entry.get("path"):
        rel = file_entry["path"]
    # 3. name fallback
    else:
        rel = file_entry.get("name", "")

    rel = _sanitize_path(rel)

    # Prepend pack_structure prefix
    if pack_structure:
        mode_key = "standalone" if standalone else "libretro"
        prefix = pack_structure.get(mode_key, "")
        if prefix:
            rel = f"{prefix}/{rel}"

    return rel


def generate_emulator_pack(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
    regions: list[str] | None = None,
    offline: bool | None = None,
) -> str | None:
    """Generate a ZIP pack for specific emulator profiles."""
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    if zip_contents is None:
        zip_contents = build_zip_contents_index(db)

    # Resolve and validate profile names
    selected: list[tuple[str, dict]] = []
    for name in profile_names:
        if name not in all_profiles:
            available = sorted(
                k
                for k, v in all_profiles.items()
                if v.get("type") not in ("alias", "test")
            )
            print(f"Error: emulator '{name}' not found", file=sys.stderr)
            print(f"Available: {', '.join(available[:10])}...", file=sys.stderr)
            return None
        p = all_profiles[name]
        if p.get("type") == "alias":
            alias_of = p.get("alias_of", "?")
            print(
                f"Error: {name} is an alias of {alias_of} -use --emulator {alias_of}",
                file=sys.stderr,
            )
            return None
        if p.get("type") == "launcher":
            print(
                f"Error: {name} is a launcher -use the emulator it launches",
                file=sys.stderr,
            )
            return None
        ptype = p.get("type", "libretro")
        if standalone and "standalone" not in ptype:
            print(
                f"Error: {name} ({ptype}) does not support --standalone",
                file=sys.stderr,
            )
            return None
        selected.append((name, p))

    # ZIP naming
    display_names = [p.get("emulator", n).replace(" ", "") for n, p in selected]
    region_tag_str = f"_{region_mod.region_tag(regions)}" if regions else ""
    zip_name = "_".join(display_names) + f"{region_tag_str}_BIOS_Pack.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    # One group per system (or explicit variant_group) inside each profile.
    # Multi-system cores such as O2EM therefore retain a fallback BIOS for
    # every system instead of letting one matching system empty another.
    region_drops: set[str] = set()
    if regions:
        region_index = region_mod.build_region_index(dict(selected))
        region_groups: dict[str, list[tuple[str, str]]] = {}
        for emu_name, profile in sorted(selected):
            structure = profile.get("pack_structure")
            for fe in filter_files_by_mode(profile.get("files", []), standalone):
                dest = _resolve_destination(fe, structure, standalone)
                if dest:
                    group_id = _emulator_region_group(emu_name, profile, fe)
                    region_groups.setdefault(group_id, []).append(
                        (dest, fe.get("name", ""))
                    )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions
        )

    total_files = 0
    missing_files = []
    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()
    seen_parents: set[str] = (
        set()
    )  # parent dirs of added files (path conflict detection)
    seen_hashes: set[str] = set()  # SHA1 dedup for same file, different path
    data_dir_notices: list[str] = []
    data_registry = load_data_dir_registry(
        os.path.join(os.path.dirname(__file__), "..", "platforms")
    )

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for emu_name, profile in sorted(selected):
            pack_structure = profile.get("pack_structure")
            files = filter_files_by_mode(profile.get("files", []), standalone)
            for dd in profile.get("data_directories", []):
                ref_key = dd.get("ref", "")
                if not ref_key or not data_registry or ref_key not in data_registry:
                    if ref_key:
                        data_dir_notices.append(ref_key)
                    continue
                entry = data_registry[ref_key]
                local_cache = entry.get("local_cache", "")
                if not local_cache or not os.path.isdir(local_cache):
                    data_dir_notices.append(ref_key)
                    continue
                dd_dest = dd.get("destination", "")
                if pack_structure:
                    mode_key = "standalone" if standalone else "libretro"
                    prefix = pack_structure.get(mode_key, "")
                    if prefix:
                        dd_dest = f"{prefix}/{dd_dest}" if dd_dest else prefix
                for root, _dirs, filenames in os.walk(local_cache):
                    for fname in filenames:
                        src = os.path.join(root, fname)
                        rel = os.path.relpath(src, local_cache)
                        full = f"{dd_dest}/{rel}" if dd_dest else rel
                        if full.lower() in seen_lower:
                            continue
                        if _has_path_conflict(full, seen_destinations, seen_parents):
                            continue
                        seen_destinations.add(full)
                        _register_path(full, seen_destinations, seen_parents)
                        seen_lower.add(full.lower())
                        zf.write(src, full)
                        total_files += 1

            if not files:
                print(f"  No files needed for {profile.get('emulator', emu_name)}")
                continue

            # Collect archives as atomic units
            archives: set[str] = set()
            for fe in files:
                archive = fe.get("archive")
                if archive:
                    archives.add(archive)

            # Pack archives as units
            archive_prefix = profile.get("archive_prefix", "")
            for archive_name in sorted(archives):
                archive_dest = _sanitize_path(archive_name)
                if archive_prefix:
                    archive_dest = f"{archive_prefix}/{archive_dest}"
                if pack_structure:
                    mode_key = "standalone" if standalone else "libretro"
                    prefix = pack_structure.get(mode_key, "")
                    if prefix:
                        archive_dest = f"{prefix}/{archive_dest}"

                if archive_dest.lower() in seen_lower:
                    continue
                if _has_path_conflict(archive_dest, seen_destinations, seen_parents):
                    continue

                # Prefer the profile's own entry for the archive (carries
                # hashes for exact resolution when several dumps share a name)
                archive_entry = next(
                    (
                        f
                        for f in files
                        if f.get("name") == archive_name and not f.get("archive")
                    ),
                    {"name": archive_name},
                )
                local_path, status = resolve_file(
                    archive_entry,
                    db,
                    bios_dir,
                    zip_contents,
                    data_dir_registry=data_registry,
                    offline=offline,
                )
                if local_path and status not in ("not_found",):
                    if local_path.endswith(".zip"):
                        _add_zip_to_pack(local_path, archive_dest, zf, archive_entry)
                    else:
                        zf.write(local_path, archive_dest)
                    seen_destinations.add(archive_dest)
                    _register_path(archive_dest, seen_destinations, seen_parents)
                    seen_lower.add(archive_dest.lower())
                    total_files += 1
                else:
                    missing_files.append(archive_name)

            # Pack individual files (skip archived ones)
            for fe in files:
                if required_only and fe.get("required") is False:
                    continue
                if fe.get("archive"):
                    continue

                dest = _resolve_destination(fe, pack_structure, standalone)
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue

                if dest.lower() in seen_lower:
                    continue
                if _has_path_conflict(dest, seen_destinations, seen_parents):
                    continue

                storage = fe.get("storage", "embedded")
                if storage == "user_provided":
                    seen_destinations.add(dest)
                    _register_path(dest, seen_destinations, seen_parents)
                    seen_lower.add(dest.lower())
                    instr = fe.get("instructions", "Please provide this file manually.")
                    instr_name = f"INSTRUCTIONS_{fe['name']}.txt"
                    _write_generated_member(
                        zf, instr_name, f"File needed: {fe['name']}\n\n{instr}\n"
                    )
                    total_files += 1
                    continue

                dest_hint = fe.get("path", "")
                local_path, status = resolve_file(
                    fe,
                    db,
                    bios_dir,
                    zip_contents,
                    dest_hint=dest_hint,
                    data_dir_registry=data_registry,
                    offline=offline,
                )

                if status == "external":
                    file_ext = os.path.splitext(fe["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(
                        delete=False, suffix=file_ext
                    ) as tmp:
                        tmp_path = tmp.name
                    try:
                        if download_external(fe, tmp_path):
                            zf.write(tmp_path, dest)
                            seen_destinations.add(dest)
                            _register_path(dest, seen_destinations, seen_parents)
                            seen_lower.add(dest.lower())
                            total_files += 1
                        else:
                            missing_files.append(fe["name"])
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status in ("not_found", "user_provided") or not local_path:
                    missing_files.append(fe["name"])
                    continue

                # SHA1 dedup: skip if same physical file AND same destination
                # (but allow same file to be packed under different destinations,
                # e.g., IPL.bin in GC/USA/ and GC/EUR/ from same source)
                if local_path:
                    real = os.path.realpath(local_path)
                    dedup_key_hash = f"{real}:{dest}"
                    if dedup_key_hash in seen_hashes:
                        continue
                    seen_hashes.add(dedup_key_hash)

                if local_path.endswith(".zip"):
                    _add_zip_to_pack(local_path, dest, zf, fe)
                else:
                    zf.write(local_path, dest)
                seen_destinations.add(dest)
                _register_path(dest, seen_destinations, seen_parents)
                seen_lower.add(dest.lower())
                total_files += 1

    # Remove empty ZIP (no files packed and no missing = nothing to ship)
    if total_files == 0 and not missing_files:
        os.unlink(zip_path)

    # Report
    " + ".join(p.get("emulator", n) for n, p in selected)
    missing_count = len(missing_files)
    ok_count = total_files
    parts = [f"{ok_count} files packed"]
    if missing_count:
        parts.append(f"{missing_count} missing")
    print(f"  {zip_path}: {', '.join(parts)}")
    for name in missing_files:
        print(f"  MISSING: {name}")
    for ref in sorted(set(data_dir_notices)):
        print(
            f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)"
        )

    return zip_path if total_files > 0 or missing_files else None


def generate_system_pack(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    required_only: bool = False,
    regions: list[str] | None = None,
    offline: bool | None = None,
) -> str | None:
    """Generate a ZIP pack for all emulators supporting given system IDs."""
    profiles = load_emulator_profiles(emulators_dir)
    matching = []
    for name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias", "test"):
            continue
        emu_systems = set(profile.get("systems", []))
        if emu_systems & set(system_ids):
            ptype = profile.get("type", "libretro")
            if standalone and "standalone" not in ptype:
                continue
            matching.append(name)

    if not matching:
        all_systems: set[str] = set()
        for p in profiles.values():
            all_systems.update(p.get("systems", []))
        if standalone:
            print(
                f"No standalone emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        else:
            print(
                f"No emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        print(
            f"Available systems: {', '.join(sorted(all_systems)[:20])}...",
            file=sys.stderr,
        )
        return None

    # Use system-based ZIP name
    sys_display = "_".join(
        "_".join(w.title() for w in sid.split("-")) for sid in system_ids
    )
    result = generate_emulator_pack(
        matching,
        emulators_dir,
        db,
        bios_dir,
        output_dir,
        standalone,
        zip_contents,
        required_only=required_only,
        regions=regions,
        offline=offline,
    )
    if result:
        # Rename to system-based name
        rgn_tag = f"_{region_mod.region_tag(regions)}" if regions else ""
        new_name = f"{sys_display}{rgn_tag}_BIOS_Pack.zip"
        new_path = os.path.join(output_dir, new_name)
        if new_path != result:
            os.rename(result, new_path)
            result = new_path
    return result


def list_platforms(platforms_dir: str) -> list[str]:
    """List available platform names from registry."""
    return list_registered_platforms(platforms_dir, include_archived=True)


def _system_display_name(system_id: str) -> str:
    """Convert system ID to display name for ZIP naming."""
    s = system_id.lower().replace("_", "-")
    for prefix in MANUFACTURER_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    parts = s.split("-")
    return "_".join(p.title() for p in parts if p)


def _group_systems_by_manufacturer(
    systems: dict[str, dict],
    db: dict,
    bios_dir: str,
) -> dict[str, list[str]]:
    """Group system IDs by manufacturer for --split --group-by manufacturer."""
    from common import derive_manufacturer

    groups: dict[str, list[str]] = {}
    for sid, sys_data in systems.items():
        mfr = derive_manufacturer(sid, sys_data)
        groups.setdefault(mfr, []).append(sid)
    return groups


def generate_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    required_only: bool = False,
    source: str = "full",
    regions: list[str] | None = None,
    target_name: str | None = None,
    offline: bool | None = None,
) -> list[str]:
    """Generate split packs (one ZIP per system or manufacturer)."""
    config = load_platform_config(platform_name, platforms_dir)
    platform_display = config.get("platform", platform_name)
    source_tag = {"platform": "_Platform", "truth": "_Truth"}.get(source, "")
    split_dir = os.path.join(output_dir, f"{platform_display.replace(' ', '_')}{source_tag}_Split")
    os.makedirs(split_dir, exist_ok=True)

    systems = config.get("systems", {})

    if group_by == "manufacturer":
        groups = _group_systems_by_manufacturer(systems, db, bios_dir)
    else:
        groups = {_system_display_name(sid): [sid] for sid in systems}

    # Pre-compute core extras once (expensive: scans 260+ emulator profiles)
    # then distribute per group based on emulator system overlap
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)
    base_dest = config.get("base_destination", "")
    if source == "platform":
        all_extras = []
    elif emu_profiles:
        all_extras = _collect_emulator_extras(
            config, emulators_dir, db, set(), base_dest, emu_profiles,
            target_cores=target_cores, include_all=(source == "truth"),
        )
    else:
        all_extras = []
    # Extras carry their profile/system identity directly; display labels are
    # presentation only and must never drive routing.
    from common import _norm_system_id

    {_norm_system_id(s): s for s in systems}

    results = []
    for group_name, group_system_ids in sorted(groups.items()):
        group_sys_set = set(group_system_ids)
        group_norm = {_norm_system_id(s) for s in group_system_ids}
        group_match = group_sys_set | group_norm
        group_extras = [
            fe
            for fe in all_extras
            if (
                set(_extra_system_ids(fe))
                | {_norm_system_id(s) for s in _extra_system_ids(fe)}
            )
            & group_match
        ]
        zip_path = generate_pack(
            platform_name,
            platforms_dir,
            db,
            bios_dir,
            split_dir,
            emulators_dir=emulators_dir,
            zip_contents=zip_contents,
            data_registry=data_registry,
            emu_profiles=emu_profiles,
            target_cores=target_cores,
            required_only=required_only,
            system_filter=group_system_ids,
            precomputed_extras=group_extras,
            source=source,
            regions=regions,
            target_name=target_name,
            offline=offline,
        )
        if zip_path:
            version = config.get("version", config.get("dat_version", ""))
            ver_tag = f"_{version.replace(' ', '')}" if version else ""
            req_tag = "_Required" if required_only else ""
            rgn_tag = f"_{region_mod.region_tag(regions)}" if regions else ""
            tgt_tag = f"_{_target_tag(target_name)}" if target_name else ""
            safe_group = group_name.replace(" ", "_")
            new_name = f"{platform_display.replace(' ', '_')}{ver_tag}{source_tag}{rgn_tag}{tgt_tag}{req_tag}_{safe_group}_BIOS_Pack.zip"
            new_path = os.path.join(split_dir, new_name)
            if new_path != zip_path:
                os.rename(zip_path, new_path)
                zip_path = new_path
            results.append(zip_path)

    # Warn about extras that couldn't be distributed (emulators without systems: field)
    all_groups_match = set()
    for group_system_ids in groups.values():
        group_norm = {_norm_system_id(s) for s in group_system_ids}
        all_groups_match |= set(group_system_ids) | group_norm
    undistributed = [
        fe
        for fe in all_extras
        if not (
            set(_extra_system_ids(fe))
            | {_norm_system_id(s) for s in _extra_system_ids(fe)}
        )
        & all_groups_match
    ]
    if undistributed:
        emus = sorted({fe.get("source_emulator", "?") for fe in undistributed})
        print(
            f"  NOTE: {len(undistributed)} core extras from {len(emus)} emulators "
            f"not in split packs (missing systems: field in profiles: "
            f"{', '.join(emus[:5])}{'...' if len(emus) > 5 else ''})"
        )

    return results


def generate_md5_pack(
    hashes: list[tuple[str, str]],
    db: dict,
    bios_dir: str,
    output_dir: str,
    zip_contents: dict | None = None,
    platform_name: str | None = None,
    platforms_dir: str | None = None,
    emulator_name: str | None = None,
    emulators_dir: str | None = None,
    standalone: bool = False,
) -> str | None:
    """Build a pack from an explicit list of hashes with layout context."""
    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_crc32 = db.get("indexes", {}).get("by_crc32", {})
    if zip_contents is None:
        zip_contents = {}

    plat_file_index: dict[str, dict] = {}
    base_dest = ""
    plat_display = "Custom"
    if platform_name and platforms_dir:
        config = load_platform_config(platform_name, platforms_dir)
        base_dest = config.get("base_destination", "")
        plat_display = config.get("platform", platform_name)
        for _sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                plat_file_index[fe.get("name", "").lower()] = fe

    emu_pack_structure = None
    emu_display = ""
    if emulator_name and emulators_dir:
        profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
        if emulator_name in profiles:
            profile = profiles[emulator_name]
            emu_display = profile.get("emulator", emulator_name)
            emu_pack_structure = profile.get("pack_structure")
            for fe in profile.get("files", []):
                plat_file_index[fe.get("name", "").lower()] = fe
                for alias in fe.get("aliases", []):
                    plat_file_index[alias.lower()] = fe

    context_name = plat_display if platform_name else (emu_display or "Custom")
    zip_name = f"{context_name.replace(' ', '_')}_Custom_BIOS_Pack.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    packed: list[tuple[str, str]] = []
    not_in_repo: list[tuple[str, str]] = []
    not_in_db: list[str] = []
    seen: set[str] = set()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for hash_type, hash_val in hashes:
            sha1 = None
            if hash_type == "sha1" and hash_val in files_db:
                sha1 = hash_val
            elif hash_type == "md5":
                sha1 = by_md5.get(hash_val)
            elif hash_type == "crc32":
                sha1 = by_crc32.get(hash_val)

            if not sha1 or sha1 not in files_db:
                not_in_db.append(hash_val)
                continue

            entry = files_db[sha1]
            name = entry.get("name", "")
            aliases = entry.get("aliases") or []
            paths = entry.get("paths") or []

            dest = name
            matched_fe = None
            for lookup_name in [name] + aliases:
                if lookup_name.lower() in plat_file_index:
                    matched_fe = plat_file_index[lookup_name.lower()]
                    break

            if matched_fe:
                if emulator_name and emu_pack_structure is not None:
                    dest = _resolve_destination(
                        matched_fe, emu_pack_structure, standalone
                    )
                else:
                    dest = matched_fe.get("destination", matched_fe.get("name", name))
            elif paths:
                dest = paths[0]

            if base_dest and not dest.startswith(base_dest):
                full_dest = f"{base_dest}/{dest}"
            else:
                full_dest = dest

            if full_dest in seen:
                continue
            seen.add(full_dest)

            fe_for_resolve = {"name": name, "sha1": sha1, "md5": entry.get("md5", "")}
            local_path, status = resolve_file(
                fe_for_resolve, db, bios_dir, zip_contents
            )

            if status == "not_found" or not local_path:
                not_in_repo.append((name, hash_val))
                continue

            zf.write(local_path, full_dest)
            packed.append((name, hash_val))

    total = len(hashes)
    print(f"\nPacked {len(packed)}/{total} requested files")
    for name, h in packed:
        print(f"  PACKED: {name} ({h[:16]}...)")
    for name, h in not_in_repo:
        print(f"  NOT IN REPO: {name} ({h[:16]}...)")
    for h in not_in_db:
        print(f"  NOT IN DB: {h}")

    if not packed:
        if os.path.exists(zip_path):
            os.unlink(zip_path)
        return None
    return zip_path


def generate_target_manifests(targets_dir: str, output_dir: str) -> None:
    """Convert target YAMLs to installer JSON manifests."""
    os.makedirs(output_dir, exist_ok=True)
    targets_path = Path(targets_dir)
    if not targets_path.is_dir():
        print(f"No targets directory at {targets_dir}", file=sys.stderr)
        return
    count = 0
    for yml_file in sorted(targets_path.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        with open(yml_file) as f:
            data = yaml_load(f) or {}
        targets = data.get("targets", {})
        if not isinstance(targets, dict):
            raise ValueError(f"{yml_file}: targets must be a mapping")
        result: dict[str, list[str] | None] = {}
        for target_name, target_info in targets.items():
            if not isinstance(target_name, str) or not target_name:
                raise ValueError(f"{yml_file}: target names must be non-empty strings")
            if not isinstance(target_info, dict):
                raise ValueError(f"{yml_file}: target {target_name!r} must be a mapping")
            cores = target_info.get("cores")
            if cores is None or cores == []:
                result[target_name] = None
                continue
            if (
                not isinstance(cores, list)
                or any(not isinstance(core, str) or not core for core in cores)
                or len(cores) != len(set(cores))
            ):
                raise ValueError(
                    f"{yml_file}: target {target_name!r} cores must be unique "
                    "non-empty strings"
                )
            result[target_name] = cores
        out_path = Path(output_dir) / f"{yml_file.stem}.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        count += 1
        print(f"  {yml_file.stem}: {len(result)} targets")
    print(f"Generated {count} target manifest(s) in {output_dir}")


def _validate_args(args, parser):
    """Validate argument combinations and mutual exclusion rules."""
    has_platform = bool(args.platform)
    has_all = args.all
    has_emulator = bool(args.emulator)
    has_system = bool(args.system)
    has_from_md5 = bool(args.from_md5 or getattr(args, "from_md5_file", None))

    if args.from_md5 and getattr(args, "from_md5_file", None):
        parser.error("--from-md5 and --from-md5-file are mutually exclusive")
    if has_from_md5 and has_all:
        parser.error("--from-md5 requires --platform or --emulator, not --all")
    if has_from_md5 and has_system:
        parser.error("--from-md5 and --system are mutually exclusive")
    if has_from_md5 and args.split:
        parser.error("--split and --from-md5 are mutually exclusive")

    # --platform/--all and --system can combine (system filters within platform)
    # --emulator is exclusive with everything else
    if has_emulator and (has_platform or has_all or has_system):
        parser.error(
            "--emulator is mutually exclusive with --platform, --all, and --system"
        )
    if has_platform and has_all:
        parser.error("--platform and --all are mutually exclusive")
    if not (has_platform or has_all or has_emulator or has_system or has_from_md5):
        parser.error("Specify --platform, --all, --emulator, --system, or --from-md5")
    if args.standalone and not (
        has_emulator or (has_system and not has_platform and not has_all)
    ):
        parser.error(
            "--standalone requires --emulator or --system (without --platform)"
        )
    if args.split and not (has_platform or has_all):
        parser.error("--split requires --platform or --all")
    if args.split and has_emulator:
        parser.error("--split is incompatible with --emulator")
    if args.group_by != "system" and not args.split:
        parser.error("--group-by requires --split")
    if args.target and not (has_platform or has_all):
        parser.error("--target requires --platform or --all")
    if args.target and has_emulator:
        parser.error("--target is incompatible with --emulator")
    if args.manifest and not (has_platform or has_all):
        parser.error("--manifest requires --platform or --all")
    if args.manifest and has_emulator:
        parser.error("--manifest is incompatible with --emulator")
    if args.manifest and args.split:
        parser.error("--manifest is incompatible with --split")
    if getattr(args, "region", None) and has_from_md5:
        parser.error("--region and --from-md5 are mutually exclusive")


def _write_manifest_if_changed(path: str, manifest: dict) -> None:
    """Write manifest JSON only if content (excluding timestamp) changed."""
    new_json = json.dumps(manifest, indent=2)
    if os.path.exists(path):
        with open(path) as f:
            try:
                old = json.load(f)
            except (json.JSONDecodeError, OSError):
                old = None
        if old is not None:
            # Compare everything except the generated timestamp
            old_cmp = {k: v for k, v in old.items() if k != "generated"}
            new_cmp = {k: v for k, v in manifest.items() if k != "generated"}
            if old_cmp == new_cmp:
                return  # no content change, keep existing timestamp
    with open(path, "w") as f:
        f.write(new_json)


def _run_manifest_mode(
    args, groups, db, zip_contents, emu_profiles, target_cores_cache
):
    """Generate JSON manifests instead of ZIP packs."""
    registry_path = os.path.join(args.platforms_dir, "_registry.yml")
    os.makedirs(args.output_dir, exist_ok=True)
    registry: dict = {}
    if os.path.exists(registry_path):
        with open(registry_path) as _rf:
            registry = yaml_load(_rf) or {}

    if args.all_variants:
        variants = [
            ("full", False), ("full", True),
            ("platform", False), ("platform", True),
            ("truth", False), ("truth", True),
        ]
    else:
        variants = [(args.source, args.required_only)]

    for source, required_only in variants:
        for group_platforms, representative in groups:
            print(f"\nGenerating manifest for {representative} [source={source}]...")
            try:
                tc = target_cores_cache.get(representative) if args.target else None
                manifest = generate_manifest(
                    representative,
                    args.platforms_dir,
                    db,
                    args.bios_dir,
                    registry_path,
                    emulators_dir=args.emulators_dir,
                    zip_contents=zip_contents,
                    emu_profiles=emu_profiles,
                    target_cores=tc,
                    source=source,
                    regions=getattr(args, "regions", None),
                    target_name=args.target,
                    offline=args.offline,
                )
                source_suffix = {"platform": "_platform", "truth": "_truth"}.get(source, "")
                req_suffix = "_required" if required_only else ""
                rgn = getattr(args, "regions", None)
                region_suffix = (
                    f"_{region_mod.region_tag(rgn).lower()}" if rgn else ""
                )
                target_suffix = (
                    f"_{_target_tag(args.target).lower()}" if args.target else ""
                )
                out_path = os.path.join(
                    args.output_dir,
                    f"{representative}{source_suffix}{region_suffix}"
                    f"{target_suffix}{req_suffix}.json",
                )
                _write_manifest_if_changed(out_path, manifest)
                print(
                    f"  {out_path}: {manifest['total_files']} files, "
                    f"{manifest['total_size']} bytes, "
                    f"{manifest['total_omitted']} safely omitted"
                )
                # Create aliases for grouped platforms (e.g., lakka -> retroarch)
                for alias_plat in group_platforms:
                    if alias_plat != representative:
                        alias_path = os.path.join(
                            args.output_dir,
                            f"{alias_plat}{source_suffix}{region_suffix}"
                            f"{target_suffix}{req_suffix}.json",
                        )
                        alias_manifest = dict(manifest)
                        alias_manifest["platform"] = alias_plat
                        alias_cfg = load_platform_config(alias_plat, args.platforms_dir)
                        alias_manifest["display_name"] = alias_cfg.get(
                            "platform", alias_plat
                        )
                        alias_registry = registry.get("platforms", {}).get(alias_plat, {})
                        alias_install = alias_registry.get("install", {})
                        alias_manifest["detect"] = alias_install.get("detect", [])
                        alias_manifest["standalone_copies"] = alias_install.get(
                            "standalone_copies", []
                        )
                        _write_manifest_if_changed(alias_path, alias_manifest)
                        print(f"  {alias_path}: alias of {representative}")
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}")


@contextlib.contextmanager
def _pack_output_lock(output_dir: str, exclusive: bool = True):
    """Hold the output directory for the duration of a pack run."""
    try:
        with artifact_lock(output_dir, exclusive=exclusive):
            yield
    except ArtifactLockBusy as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)


def _run_verify_packs(args):
    """Extract each pack and verify file paths + hashes."""
    import shutil

    with open(args.db) as f:
        verify_db = json.load(f)

    platforms = list_registered_platforms(args.platforms_dir)
    if args.platform:
        platforms = [args.platform]
    elif not args.all:
        print("ERROR: --verify-packs requires --platform or --all")
        sys.exit(1)

    all_ok = True
    verify_regions = getattr(args, "regions", None)
    verify_profiles = load_emulator_profiles(args.emulators_dir)
    verify_zip_contents = build_zip_contents_index(verify_db)
    verify_data_registry = load_data_dir_registry(args.platforms_dir)
    for platform_name in platforms:
        config = load_platform_config(platform_name, args.platforms_dir)
        display = config.get("platform", platform_name).replace(" ", "_")
        base_dest = config.get("base_destination", "")
        mode = config.get("verification_mode", "existence")
        systems = config.get("systems", {})

        # Find ZIP
        zip_path = None
        if os.path.isdir(args.output_dir):
            for f in os.listdir(args.output_dir):
                if f.endswith("_BIOS_Pack.zip") and display in f:
                    zip_path = os.path.join(args.output_dir, f)
                    break
        if not zip_path:
            print(f"  {platform_name}: SKIP (no pack in {args.output_dir})")
            continue

        # Detect source from ZIP filename
        pack_source = "full"
        if zip_path:
            bn = os.path.basename(zip_path)
            if "_Platform_" in bn:
                pack_source = "platform"
            elif "_Truth_" in bn:
                pack_source = "truth"

        if pack_source == "truth":
            print(f"  {platform_name}: OK (truth pack, verified by hash integrity)")
            continue

        extract_dir = os.path.join("tmp", "verify_packs", platform_name)
        os.makedirs(extract_dir, exist_ok=True)
        try:
            # Extract
            safe_extract_zip(zip_path, extract_dir)

            # Auto-detect flat vs nested extraction
            is_flat = bool(base_dest) and not os.path.isdir(
                os.path.join(extract_dir, base_dest)
            )

            region_drops: set[str] = set()
            if verify_regions:
                region_index = region_mod.build_region_index(verify_profiles)
                region_groups: dict[str, list[tuple[str, str]]] = {}
                for sys_id, sys_data in systems.items():
                    members = region_groups.setdefault(sys_id, [])
                    for fe in sys_data.get("files", []):
                        d = _sanitize_path(
                            fe.get("destination", fe.get("name", ""))
                        )
                        if d:
                            members.append((d, fe.get("name", "")))
                # Core extras join the groups so a platform file dropped in
                # favour of a better-ranked core file is not reported missing.
                from verify import find_undeclared_files as _fud

                for u in _fud(
                    config, args.emulators_dir, verify_db, verify_profiles
                ):
                    if not u.get("in_repo"):
                        continue
                    raw = u.get("path") or u["name"]
                    d = _sanitize_path(
                        f"{raw}{u['name']}" if raw.endswith("/") else raw
                    )
                    if not d:
                        continue
                    systems_for_extra = (
                        [u["system"]] if u.get("system") else u.get("systems", [])
                    ) or ["_extras"]
                    for sid in systems_for_extra:
                        variant = u.get("variant_group")
                        group_id = f"{sid}:variant:{variant}" if variant else sid
                        region_groups.setdefault(group_id, []).append((d, u["name"]))
                region_drops = region_mod.resolve_region_drops(
                    region_groups, region_index, verify_regions
                )

            missing = []
            hash_fail = []
            excluded = []
            ok = 0
            for sys_id, sys_data in systems.items():
                for fe in sys_data.get("files", []):
                    dest = fe.get("destination", fe.get("name", ""))
                    if not dest:
                        continue
                    if region_drops and _sanitize_path(dest) in region_drops:
                        continue
                    fp = (
                        os.path.join(extract_dir, base_dest, dest)
                        if base_dest and not is_flat
                        else os.path.join(extract_dir, dest)
                    )
                    # Case-insensitive fallback
                    if not os.path.exists(fp):
                        parent = os.path.dirname(fp)
                        bn = os.path.basename(fp)
                        if os.path.isdir(parent):
                            for e in os.listdir(parent):
                                if e.lower() == bn.lower():
                                    fp = os.path.join(parent, e)
                                    break
                    if not os.path.exists(fp):
                        # File-vs-directory conflict: upstream declares both
                        # SGB1.sfc and SGB1.sfc/program.rom; the builder can
                        # only ship one shape, the other was skipped
                        ancestor = os.path.dirname(fp)
                        conflicted = False
                        while len(ancestor) > len(extract_dir):
                            if os.path.isfile(ancestor):
                                conflicted = True
                                break
                            ancestor = os.path.dirname(ancestor)
                        if conflicted or os.path.isdir(fp):
                            ok += 1
                            continue
                        if _intentional_hash_exclusion(
                            [fe],
                            verify_db,
                            args.bios_dir,
                            verify_zip_contents,
                            data_dir_registry=verify_data_registry,
                            verification_mode=mode,
                        ):
                            excluded.append(f"{sys_id}: {dest}")
                            continue
                        missing.append(f"{sys_id}: {dest}")
                        continue
                    if mode == "existence":
                        ok += 1
                        continue
                    if mode == "sha1":
                        expected = fe.get("sha1", "")
                        if not expected:
                            ok += 1
                            continue
                        with open(fp, "rb") as source:
                            actual = hashlib.sha1(source.read()).hexdigest()
                        if actual == expected.lower():
                            ok += 1
                        else:
                            hash_fail.append(f"{sys_id}: {dest}")
                        continue
                    # MD5
                    expected_md5 = fe.get("md5", "")
                    if not expected_md5:
                        ok += 1
                        continue
                    md5_list = [
                        m.strip().lower() for m in expected_md5.split(",") if m.strip()
                    ]
                    with open(fp, "rb") as source:
                        actual_md5 = hashlib.md5(source.read()).hexdigest()
                    if actual_md5 in md5_list or any(
                        actual_md5.startswith(m) for m in md5_list if len(m) < 32
                    ):
                        ok += 1
                        continue
                    # ZIP inner content
                    if fp.endswith(".zip"):
                        ok += 1  # inner content verified by verify.py
                        continue
                    # Path collision
                    bn = os.path.basename(dest)
                    collision = (
                        sum(
                            1
                            for sd in systems.values()
                            for ff in sd.get("files", [])
                            if os.path.basename(
                                ff.get("destination", ff.get("name", "")) or ""
                            )
                            == bn
                        )
                        > 1
                    )
                    if collision:
                        ok += 1
                    elif not _repo_satisfies_declaration([fe], verify_db, "md5"):
                        # No repo file matches the declared hash: shipped file
                        # is the best effort, the gap is a data issue reported
                        # by verify.py, not a pack error
                        ok += 1
                    else:
                        hash_fail.append(f"{sys_id}: {dest}")

            total = sum(
                len(
                    [
                        f
                        for f in s.get("files", [])
                        if f.get("destination", f.get("name", ""))
                    ]
                )
                for s in systems.values()
            )
            if missing or hash_fail:
                print(
                    f"  {platform_name}: FAIL ({len(missing)} missing, {len(hash_fail)} hash errors / {total})"
                )
                for m in missing[:5]:
                    print(f"    MISSING: {m}")
                for h in hash_fail[:5]:
                    print(f"    HASH: {h}")
                all_ok = False
            else:
                exclusion_note = (
                    f", {len(excluded)} unsafe excluded" if excluded else ""
                )
                print(
                    f"  {platform_name}: OK ({ok}/{total} verified"
                    f"{exclusion_note})"
                )
        finally:
            shutil.rmtree(extract_dir, ignore_errors=True)

    if not all_ok:
        sys.exit(1)


def _run_platform_packs(
    args,
    groups,
    db,
    zip_contents,
    data_registry,
    emu_profiles,
    target_cores_cache,
    system_filter,
):
    """Generate ZIP packs for platform groups and verify."""
    if args.all_variants:
        variants = [
            ("full", False), ("full", True),
            ("platform", False), ("platform", True),
            ("truth", False), ("truth", True),
        ]
    else:
        variants = [(args.source, args.required_only)]

    for source, required_only in variants:
        for group_platforms, representative in groups:
            aliases = [p for p in group_platforms if p != representative]
            if aliases:
                all_names = [
                    load_platform_config(p, args.platforms_dir).get("platform", p)
                    for p in group_platforms
                ]
                label = " / ".join(all_names)
                print(f"\nGenerating pack for {label} [source={source}]...")
            else:
                print(f"\nGenerating pack for {representative} [source={source}]...")

            try:
                tc = target_cores_cache.get(representative) if args.target else None
                if args.split:
                    zip_paths = generate_split_packs(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        group_by=args.group_by,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=args.target,
                        offline=args.offline,
                    )
                    print(f"  Split into {len(zip_paths)} packs")
                else:
                    zip_path = generate_pack(
                        representative,
                        args.platforms_dir,
                        db,
                        args.bios_dir,
                        args.output_dir,
                        include_extras=args.include_extras,
                        emulators_dir=args.emulators_dir,
                        zip_contents=zip_contents,
                        data_registry=data_registry,
                        emu_profiles=emu_profiles,
                        target_cores=tc,
                        required_only=required_only,
                        system_filter=system_filter,
                        source=source,
                        regions=getattr(args, "regions", None),
                        target_name=args.target,
                        offline=args.offline,
                    )
                if not args.split and zip_path and aliases:
                    rep_cfg = load_platform_config(representative, args.platforms_dir)
                    ver = rep_cfg.get("version", rep_cfg.get("dat_version", ""))
                    ver_tag = f"_{ver.replace(' ', '')}" if ver else ""
                    all_names = [
                        load_platform_config(p, args.platforms_dir).get("platform", p)
                        for p in group_platforms
                    ]
                    source_tag = {"platform": "_Platform", "truth": "_Truth"}.get(source, "")
                    region_values = getattr(args, "regions", None)
                    rgn_tag = (
                        f"_{region_mod.region_tag(region_values)}"
                        if region_values
                        else ""
                    )
                    req_tag = "_Required" if required_only else ""
                    combined = (
                        "_".join(n.replace(" ", "") for n in all_names)
                        + f"{ver_tag}{source_tag}{rgn_tag}{req_tag}_BIOS_Pack.zip"
                    )
                    new_path = os.path.join(os.path.dirname(zip_path), combined)
                    if new_path != zip_path:
                        os.rename(zip_path, new_path)
                        print(f"  Renamed -> {os.path.basename(new_path)}")
            except (FileNotFoundError, OSError, yaml.YAMLError) as e:
                print(f"  ERROR: {e}")

    print("\nVerifying packs and generating manifests...")
    skip_conf = bool(system_filter or args.split)
    all_ok = verify_and_finalize_packs(
        args.output_dir,
        db,
        skip_conformance=skip_conf,
        data_registry=data_registry,
        regions=getattr(args, "regions", None),
    )
    if args.split:
        for entry in os.listdir(args.output_dir):
            sub = os.path.join(args.output_dir, entry)
            if os.path.isdir(sub) and entry.endswith("_Split"):
                ok = verify_and_finalize_packs(
                    sub,
                    db,
                    skip_conformance=True,
                    data_registry=data_registry,
                    regions=getattr(args, "regions", None),
                )
                all_ok = all_ok and ok
    if not all_ok:
        print("WARNING: some packs have verification errors")
        sys.exit(1)


def main():
    global _OFFLINE

    parser = argparse.ArgumentParser(description="Generate platform BIOS ZIP packs")
    parser.add_argument("--platform", "-p", help="Platform name (e.g., retroarch)")
    parser.add_argument(
        "--all", action="store_true", help="Generate packs for all active platforms"
    )
    parser.add_argument(
        "--emulator", "-e", help="Emulator profile name(s), comma-separated"
    )
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    parser.add_argument(
        "--list-systems", action="store_true", help="List available systems"
    )
    parser.add_argument(
        "--include-archived", action="store_true", help="Include archived platforms"
    )
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="Path to database.json")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    parser.add_argument("--output-dir", "-o", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--include-extras",
        action="store_true",
        help="(no-op) Core requirements are always included",
    )
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip data directory freshness check, use cache only",
    )
    parser.add_argument(
        "--refresh-data",
        action="store_true",
        help="Force re-download all data directories",
    )
    parser.add_argument("--list", action="store_true", help="List available platforms")
    parser.add_argument(
        "--required-only",
        action="store_true",
        help="Only include required files, skip optional",
    )
    parser.add_argument(
        "--source",
        choices=["platform", "truth", "full"],
        default="full",
        help="File source: platform (YAML only), truth (emulator profiles), full (both)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Generate all 6 source x required combinations",
    )
    parser.add_argument(
        "--split", action="store_true", help="Generate one ZIP per system/manufacturer"
    )
    parser.add_argument(
        "--group-by",
        choices=["system", "manufacturer"],
        default="system",
        help="Grouping for --split (default: system)",
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region",
        help="Region priority list, best first (e.g. us,eu,jp)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--from-md5", help="Hash(es) to look up or pack (comma-separated)"
    )
    parser.add_argument("--from-md5-file", help="File with hashes (one per line)")
    parser.add_argument(
        "--manifest",
        action="store_true",
        help="Output JSON manifests instead of ZIP packs",
    )
    parser.add_argument(
        "--manifest-targets",
        action="store_true",
        help="Convert target YAMLs to installer JSON",
    )
    parser.add_argument(
        "--verify-packs",
        action="store_true",
        help="Extract and verify pack integrity (path + hash)",
    )
    args = parser.parse_args()
    _OFFLINE = bool(args.offline)

    # Parsed before the quick-exit modes: --verify-packs returns early and
    # still needs the region priority list to narrow its expectation.
    args.regions = []
    if args.region:
        try:
            args.regions = region_mod.parse_requested(args.region)
        except ValueError as exc:
            parser.error(str(exc))
        if args.manifest_targets:
            parser.error("--region is incompatible with --manifest-targets")

    # Quick-exit modes: --verify-packs alone = verify existing packs only
    # Combined with --all-variants, generation runs first then verify
    if args.verify_packs and not args.all_variants:
        with _pack_output_lock(args.output_dir, exclusive=False):
            _run_verify_packs(args)
        return
    if args.manifest_targets:
        generate_target_manifests(
            os.path.join(args.platforms_dir, "targets"), args.output_dir
        )
        return
    if args.list:
        for p in list_platforms(args.platforms_dir):
            print(p)
        return
    if args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
        return
    if args.list_systems:
        if args.platform:
            list_platform_system_ids(args.platform, args.platforms_dir)
        else:
            list_system_ids(args.emulators_dir)
        return
    if args.list_targets:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        from common import list_available_targets

        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
            return
        for t in targets:
            aliases = f" (aliases: {', '.join(t['aliases'])})" if t["aliases"] else ""
            print(
                f"  {t['name']:30s} {t['architecture']:10s} {t['core_count']:>4d} cores{aliases}"
            )
        return

    _validate_args(args, parser)

    # Hash lookup / pack mode
    has_from_md5 = bool(args.from_md5 or getattr(args, "from_md5_file", None))
    if has_from_md5:
        hashes = (
            parse_hash_input(args.from_md5)
            if args.from_md5
            else parse_hash_file(args.from_md5_file)
        )
        if not hashes:
            print("No valid hashes found in input", file=sys.stderr)
            sys.exit(1)
        db = load_database(args.db)
        if not args.platform and not args.emulator:
            lookup_hashes(
                hashes, db, args.bios_dir, args.emulators_dir, args.platforms_dir
            )
            return
        zip_contents = build_zip_contents_index(db)
        result = generate_md5_pack(
            hashes=hashes,
            db=db,
            bios_dir=args.bios_dir,
            output_dir=args.output_dir,
            zip_contents=zip_contents,
            platform_name=args.platform,
            platforms_dir=args.platforms_dir,
            emulator_name=args.emulator,
            emulators_dir=args.emulators_dir,
            standalone=getattr(args, "standalone", False),
        )
        if not result:
            sys.exit(1)
        return

    db = load_database(args.db)
    zip_contents = build_zip_contents_index(db)

    # Emulator mode
    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        if not generate_emulator_pack(
            names,
            args.emulators_dir,
            db,
            args.bios_dir,
            args.output_dir,
            args.standalone,
            zip_contents,
            required_only=args.required_only,
            regions=getattr(args, "regions", None),
            offline=args.offline,
        ):
            sys.exit(1)
        return

    # System mode (standalone, without platform context)
    if args.system and not args.platform and not args.all:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        if not generate_system_pack(
            system_ids,
            args.emulators_dir,
            db,
            args.bios_dir,
            args.output_dir,
            args.standalone,
            zip_contents,
            required_only=args.required_only,
            regions=getattr(args, "regions", None),
            offline=args.offline,
        ):
            sys.exit(1)
        return

    system_filter = (
        [s.strip() for s in args.system.split(",") if s.strip()]
        if args.system
        else None
    )

    # Platform mode
    if args.all:
        # Install manifests cover every registered platform. "Archived" means
        # upstream is no longer scraped on a schedule, not that the platform
        # lost its users: its packs still ship, so the installer still needs
        # its file list.
        platforms = list_registered_platforms(
            args.platforms_dir,
            include_archived=args.include_archived or args.manifest,
        )
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    data_registry = load_data_dir_registry(args.platforms_dir)
    if data_registry and not args.offline:
        from refresh_data_dirs import load_registry, refresh_all

        registry = load_registry(os.path.join(args.platforms_dir, "_data_dirs.yml"))
        results = refresh_all(registry, force=args.refresh_data)
        updated = sum(1 for v in results.values() if v)
        if updated:
            print(f"Refreshed {updated} data director{'ies' if updated > 1 else 'y'}")

    emu_profiles = load_emulator_profiles(args.emulators_dir)

    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores_cache, platforms = build_target_cores_cache(
                platforms,
                args.target,
                args.platforms_dir,
                is_all=args.all,
            )
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    groups = group_identical_platforms(
        platforms, args.platforms_dir, target_cores_cache if args.target else None
    )

    if args.manifest:
        _run_manifest_mode(
            args, groups, db, zip_contents, emu_profiles, target_cores_cache
        )
    else:
        with _pack_output_lock(args.output_dir):
            _run_platform_packs(
                args,
                groups,
                db,
                zip_contents,
                data_registry,
                emu_profiles,
                target_cores_cache,
                system_filter,
            )


# Manifest generation (JSON inventory for install.py)

_GITIGNORE_ENTRIES: set[str] | None = None


def _load_gitignore_entries(repo_root: str) -> set[str]:
    """Load gitignored paths (large files) from .gitignore at repo root."""
    global _GITIGNORE_ENTRIES
    if _GITIGNORE_ENTRIES is not None:
        return _GITIGNORE_ENTRIES
    gitignore = os.path.join(repo_root, ".gitignore")
    entries: set[str] = set()
    if os.path.exists(gitignore):
        with open(gitignore) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line)
    _GITIGNORE_ENTRIES = entries
    return entries


def _is_large_file(local_path: str, repo_root: str) -> bool:
    """Check if a file is a large file (>50MB or in .gitignore)."""
    if local_path and os.path.exists(local_path):
        if os.path.getsize(local_path) > 50_000_000:
            return True
    gitignore = _load_gitignore_entries(repo_root)
    # Check if the path relative to repo root is in .gitignore
    try:
        rel = os.path.relpath(local_path, repo_root)
    except ValueError:
        rel = ""
    return rel in gitignore


def _get_repo_path(sha1: str, db: dict) -> str:
    """Get the repo path for a file by SHA1 lookup."""
    entry = db.get("files", {}).get(sha1, {})
    return entry.get("path", "")


def generate_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    emulators_dir: str = "emulators",
    zip_contents: dict | None = None,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    source: str = "full",
    regions: list[str] | None = None,
    target_name: str | None = None,
    offline: bool | None = None,
) -> dict:
    """Generate a JSON manifest for a platform (same resolution as generate_pack).

    Returns a dict ready for JSON serialization with file inventory,
    install hints, and download metadata.
    """
    config = load_platform_config(platform_name, platforms_dir)
    if zip_contents is None:
        zip_contents = {}
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)

    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")
    case_insensitive = config.get("case_insensitive_fs", False)
    verification_mode = config.get("verification_mode", "existence")

    # Load registry for install metadata
    registry: dict = {}
    if os.path.exists(registry_path):
        with open(registry_path) as f:
            registry = yaml_load(f) or {}
    plat_registry = registry.get("platforms", {}).get(platform_name, {})
    install_section = plat_registry.get("install", {})
    detect = install_section.get("detect", [])
    standalone_copies = install_section.get("standalone_copies", [])

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Filter systems by target
    from common import resolve_platform_cores

    plat_cores = resolve_platform_cores(config, emu_profiles) if target_cores else None
    pack_systems = filter_systems_by_target(
        config.get("systems", {}),
        emu_profiles,
        target_cores,
        platform_cores=plat_cores,
    )

    seen_destinations: set[str] = set()
    seen_lower: set[str] = set()
    seen_parents: set[str] = set()
    manifest_files: list[dict] = []
    omitted_by_destination: dict[str, dict] = {}
    total_size = 0

    def manifest_destination(full_destination: str) -> str:
        if base_dest and full_destination.startswith(f"{base_dest}/"):
            return full_destination[len(base_dest) + 1:]
        return full_destination

    def record_omission(
        full_destination: str,
        file_entry: dict,
        system_id: str,
        reason: str,
        cores: list[str] | None,
    ) -> None:
        omitted_by_destination[full_destination] = {
            "dest": manifest_destination(full_destination),
            "name": str(file_entry.get("name") or ""),
            "system": system_id,
            "required": bool(file_entry.get("required", True)),
            "reason": reason,
            "cores": cores,
        }

    region_drops: set[str] = set()
    if regions:
        region_index = region_mod.build_region_index(emu_profiles)
        region_groups: dict[str, list[tuple[str, str]]] = {}
        for sys_id, system in pack_systems.items():
            members = region_groups.setdefault(sys_id, [])
            for file_entry in system.get("files", []):
                d = _sanitize_path(
                    file_entry.get("destination", file_entry.get("name", ""))
                )
                if d:
                    members.append((d, file_entry.get("name", "")))
        if source != "platform":
            for fe in _collect_emulator_extras(
                config,
                emulators_dir,
                db,
                set(),
                base_dest,
                emu_profiles,
                target_cores=target_cores,
                include_all=(source == "truth"),
            ):
                d = _sanitize_path(fe.get("destination", fe.get("name", "")))
                if not d:
                    continue
                systems = _extra_system_ids(fe) or ["_extras"]
                for sid in systems:
                    variant = fe.get("variant_group")
                    group_id = f"{sid}:variant:{variant}" if variant else sid
                    region_groups.setdefault(group_id, []).append(
                        (d, fe.get("name", ""))
                    )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions
        )

    # Phase 1: baseline files
    if source != "truth":
        for sys_id, system in sorted(pack_systems.items()):
            for file_entry in system.get("files", []):
                dest = _sanitize_path(file_entry.get("destination", file_entry["name"]))
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue
                full_dest = f"{base_dest}/{dest}" if base_dest else dest

                dedup_key = full_dest
                if dedup_key in seen_destinations:
                    continue
                if case_insensitive and dedup_key.lower() in seen_lower:
                    continue
                if _has_path_conflict(full_dest, seen_destinations, seen_parents):
                    continue

                storage = file_entry.get("storage", "embedded")
                if storage == "user_provided":
                    record_omission(
                        full_dest,
                        file_entry,
                        sys_id,
                        "user_provided",
                        None,
                    )
                    continue

                local_path, status = resolve_file(
                    file_entry,
                    db,
                    bios_dir,
                    zip_contents,
                    offline=offline,
                )
                # An existence platform never reads the bytes, so a declared
                # hash the local dump contradicts is not a reason to withhold
                # the file. Hash platforms would reject it, so they omit it.
                if status in ("not_found", "external") or (
                    status == "hash_mismatch" and verification_mode != "existence"
                ):
                    record_omission(full_dest, file_entry, sys_id, status, None)
                    continue

                # Get SHA1 and size. The installer fetches by hash, so record
                # the copy this repo holds: an upstream hash carried by no
                # local file resolves to no download URL at all.
                sha1 = ""
                sha256 = ""
                file_size = 0
                if local_path and os.path.exists(local_path):
                    file_size = os.path.getsize(local_path)
                    hashes = compute_hashes(local_path)
                    sha1 = hashes["sha1"]
                    sha256 = hashes["sha256"]

                repo_path = _get_repo_path(sha1, db) if sha1 else ""

                entry: dict = {
                    "dest": dest,
                    "sha1": sha1,
                    "sha256": sha256,
                    "size": file_size,
                    "repo_path": repo_path,
                    "cores": None,
                }

                if _is_large_file(local_path or "", repo_root):
                    entry["storage"] = "release"
                    entry["release_asset"] = (
                        os.path.basename(local_path) if local_path else file_entry["name"]
                    )

                manifest_files.append(entry)
                omitted_by_destination.pop(full_dest, None)
                total_size += file_size
                seen_destinations.add(dedup_key)
                _register_path(dedup_key, seen_destinations, seen_parents)
                if case_insensitive:
                    seen_lower.add(dedup_key.lower())

    # Phase 2: core complement (emulator extras)
    if source != "platform":
        core_files = _collect_emulator_extras(
            config,
            emulators_dir,
            db,
            seen_destinations,
            base_dest,
            emu_profiles,
            target_cores=target_cores,
            include_all=(source == "truth"),
        )
    else:
        core_files = []
    extras_pfx = _detect_extras_prefix(config, base_dest)
    for fe in core_files:
        dest = _sanitize_path(fe.get("destination", fe["name"]))
        if not dest:
            continue
        if region_drops and dest in region_drops:
            continue
        if extras_pfx:
            if not dest.startswith(f"{extras_pfx}/"):
                full_dest = f"{extras_pfx}/{dest}"
            else:
                full_dest = dest
        else:
            full_dest = dest

        if full_dest in seen_destinations:
            continue
        if case_insensitive and full_dest.lower() in seen_lower:
            continue
        if _has_path_conflict(full_dest, seen_destinations, seen_parents):
            continue

        dest_hint = fe.get("destination", "")
        local_path, status = resolve_file(
            fe,
            db,
            bios_dir,
            zip_contents,
            dest_hint=dest_hint,
            offline=offline,
        )
        if status in ("not_found", "external", "user_provided") or not local_path:
            source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
            systems = _extra_system_ids(fe)
            record_omission(
                full_dest,
                fe,
                systems[0] if systems else "",
                status,
                [source_emu] if source_emu else [],
            )
            continue

        sha1 = ""
        sha256 = ""
        file_size = 0
        if local_path and os.path.exists(local_path):
            file_size = os.path.getsize(local_path)
            hashes = compute_hashes(local_path)
            sha1 = hashes["sha1"]
            sha256 = hashes["sha256"]

        repo_path = _get_repo_path(sha1, db) if sha1 else ""
        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")

        # Manifest dests are relative to base_destination; keep the inferred
        # extras prefix when it is an internal layout dir (RetroDECK bios/).
        manifest_dest = full_dest
        if base_dest and manifest_dest.startswith(f"{base_dest}/"):
            manifest_dest = manifest_dest[len(base_dest) + 1:]

        entry = {
            "dest": manifest_dest,
            "sha1": sha1,
            "sha256": sha256,
            "size": file_size,
            "repo_path": repo_path,
            "cores": [source_emu] if source_emu else [],
        }

        if _is_large_file(local_path or "", repo_root):
            entry["storage"] = "release"
            entry["release_asset"] = (
                os.path.basename(local_path) if local_path else fe["name"]
            )

        manifest_files.append(entry)
        omitted_by_destination.pop(full_dest, None)
        total_size += file_size
        seen_destinations.add(full_dest)
        _register_path(full_dest, seen_destinations, seen_parents)
        if case_insensitive:
            seen_lower.add(full_dest.lower())

    # No phase 3 (data directories) -skipped for manifest

    now = _build_timestamp(db)

    result: dict = {
        "manifest_version": 2,
        "source": source,
        "regions": list(regions or []),
        # A target-filtered manifest is only distinguishable from the full one
        # by its filename, so it records the filter the way regions does.
        # Absent on an unfiltered manifest rather than empty, to leave the
        # twelve default files byte-identical.
        **({"target": target_name} if target_name else {}),
        "platform": platform_name,
        "display_name": platform_display,
        "version": "1.0",
        "generated": now,
        "base_destination": base_dest,
        "detect": detect,
        "standalone_copies": standalone_copies,
        "total_files": len(manifest_files),
        "total_size": total_size,
        "total_omitted": len(omitted_by_destination),
        "omitted_files": sorted(
            omitted_by_destination.values(), key=lambda entry: entry["dest"]
        ),
        "files": manifest_files,
    }
    return result


# Post-generation pack verification + manifest + SHA256SUMS


def verify_pack(
    zip_path: str, db: dict, data_registry: dict | None = None
) -> tuple[bool, dict]:
    """Verify a generated pack ZIP by re-hashing every file inside.

    Checks against database.json, data directory caches, and verifies
    rebuilt ZIP content by comparing inner CRC32s against source.
    Returns (all_ok, manifest_dict).
    """
    files_db = db.get("files", {})  # SHA1 -> file_info
    by_md5 = db.get("indexes", {}).get("by_md5", {})  # MD5 -> SHA1
    by_name = db.get("indexes", {}).get("by_name", {})  # name -> [SHA1]

    # Data directory file index
    _data_index: dict[str, list[str]] = {}
    _data_path_index: dict[str, str] = {}
    if data_registry:
        for _dk, _de in data_registry.items():
            cache = _de.get("local_cache", "")
            if not cache or not os.path.isdir(cache):
                continue
            for _r, _d, _fns in os.walk(cache):
                for _fn in _fns:
                    _fp = os.path.join(_r, _fn)
                    _rel = os.path.relpath(_fp, cache)
                    _data_path_index[_rel] = _fp
                    _data_index.setdefault(_fn, []).append(_fp)

    manifest = {
        "schema_version": 1,
        "version": 1,
        "generator": "retrobios generate_pack.py",
        "generated": _build_timestamp(db),
        "files": [],
    }
    errors = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith("INSTRUCTIONS_") or name in (
                "manifest.json",
                "README.txt",
            ):
                continue
            with zf.open(info) as f:
                sha1_h = hashlib.sha1()
                md5_h = hashlib.md5()
                size = 0
                for chunk in iter(lambda: f.read(65536), b""):
                    sha1_h.update(chunk)
                    md5_h.update(chunk)
                    size += len(chunk)
            sha1 = sha1_h.hexdigest()
            md5 = md5_h.hexdigest()

            # Look up in database: files_db keyed by SHA1
            db_entry = files_db.get(sha1)
            status = "verified"
            file_name = ""
            if db_entry:
                file_name = db_entry.get("name", "")
            else:
                # Try MD5 -> SHA1 lookup
                ref_sha1 = by_md5.get(md5)
                if ref_sha1:
                    db_entry = files_db.get(ref_sha1)
                    if db_entry:
                        file_name = db_entry.get("name", "")
                        status = "verified_md5"
                    else:
                        status = "untracked"
                else:
                    status = "untracked"

            # Rebuilt ZIP: verify inner ROM CRC32s match source
            if status == "untracked" and name.endswith(".zip"):
                _bn = os.path.basename(name)
                for _src_sha1 in by_name.get(_bn, []):
                    if _src_sha1 not in files_db:
                        continue
                    _src_path = files_db[_src_sha1]["path"]
                    if not os.path.exists(_src_path):
                        continue
                    try:
                        import io as _io

                        with zipfile.ZipFile(_src_path) as _sz:
                            _sc = {
                                i.filename: i.CRC
                                for i in _sz.infolist()
                                if not i.is_dir()
                            }
                        with zipfile.ZipFile(_io.BytesIO(zf.read(name))) as _pz:
                            _pc = {
                                i.filename: i.CRC
                                for i in _pz.infolist()
                                if not i.is_dir()
                            }
                        if _sc == _pc:
                            status = "verified_rebuild"
                            file_name = _bn
                            break
                    except (zipfile.BadZipFile, OSError):
                        continue

            # Data directory: check against cached files
            if status == "untracked" and _data_index:
                _bn = os.path.basename(name)
                _pr = name
                for _known_prefix in ("system/", "bios/", "BIOS/", "Firmware/"):
                    if name.startswith(_known_prefix):
                        _pr = name[len(_known_prefix):]
                        break
                _cands = []
                if _pr in _data_path_index:
                    _cands.append(_data_path_index[_pr])
                for _dp in _data_index.get(_bn, []):
                    if _dp not in _cands:
                        _cands.append(_dp)
                for _dp in _cands:
                    if not os.path.exists(_dp):
                        continue
                    if os.path.getsize(_dp) == size:
                        status = "verified_data"
                        file_name = _bn
                        break
                    if name.endswith(".zip") and _dp.endswith(".zip"):
                        try:
                            import io as _io2

                            with zipfile.ZipFile(_io2.BytesIO(zf.read(name))) as _pz2:
                                _pc2 = {
                                    i.filename: i.CRC
                                    for i in _pz2.infolist()
                                    if not i.is_dir()
                                }
                            with zipfile.ZipFile(_dp) as _dz:
                                _dc = {
                                    i.filename: i.CRC
                                    for i in _dz.infolist()
                                    if not i.is_dir()
                                }
                            if _pc2 == _dc:
                                status = "verified_data"
                                file_name = _bn
                                break
                        except (zipfile.BadZipFile, OSError):
                            continue

            manifest["files"].append(
                {
                    "path": name,
                    "sha1": sha1,
                    "md5": md5,
                    "size": size,
                    "status": status,
                    "name": file_name,
                }
            )

            # Corruption check: SHA1 in DB but doesn't match what we computed
            # This should never happen (we looked up by SHA1), but catches
            # edge cases where by_md5 resolved to a different SHA1
            if db_entry and status == "verified_md5":
                expected_sha1 = db_entry.get("sha1", "")
                if expected_sha1 and expected_sha1.lower() != sha1.lower():
                    errors.append(
                        f"{name}: SHA1 mismatch (expected {expected_sha1}, got {sha1})"
                    )

    verified = sum(1 for f in manifest["files"] if f["status"].startswith("verified"))
    untracked = sum(1 for f in manifest["files"] if f["status"] == "untracked")
    total = len(manifest["files"])
    manifest["summary"] = {
        "total_files": total,
        "verified": verified,
        "untracked": untracked,
        "errors": len(errors),
    }
    manifest["errors"] = errors

    all_ok = len(errors) == 0
    return all_ok, manifest


def inject_manifest(zip_path: str, manifest: dict) -> None:
    """Inject manifest.json into an existing ZIP pack."""
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    # Check if manifest already exists
    with zipfile.ZipFile(zip_path, "r") as zf:
        has_manifest = "manifest.json" in zf.namelist()

    if not has_manifest:
        # Fast path: append directly. Append mode defaults to ZIP_STORED,
        # which would leave the manifest uncompressed and give the same pack
        # two different byte layouts depending on the path taken here.
        with zipfile.ZipFile(zip_path, "a", zipfile.ZIP_DEFLATED) as zf:
            _write_generated_member(zf, "manifest.json", manifest_json)
    else:
        # Rebuild to replace existing manifest
        import tempfile as _tempfile

        tmp_fd, tmp_path = _tempfile.mkstemp(
            suffix=".zip", dir=os.path.dirname(zip_path)
        )
        os.close(tmp_fd)
        try:
            with (
                zipfile.ZipFile(zip_path, "r") as src,
                zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as dst,
            ):
                for item in src.infolist():
                    if item.filename == "manifest.json":
                        continue
                    dst.writestr(item, src.read(item.filename))
                _write_generated_member(dst, "manifest.json", manifest_json)
            os.replace(tmp_path, zip_path)
        except (OSError, zipfile.BadZipFile):
            os.unlink(tmp_path)
            raise


def generate_sha256sums(output_dir: str) -> str | None:
    """Generate SHA256SUMS.txt for all ZIP files in output_dir."""
    sums_path = os.path.join(output_dir, "SHA256SUMS.txt")
    entries = []
    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        path = os.path.join(output_dir, name)
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        entries.append(f"{sha256.hexdigest()}  {name}")
    if not entries:
        return None
    with open(sums_path, "w") as f:
        f.write("\n".join(entries) + "\n")
    print(f"\n{sums_path}: {len(entries)} pack checksums")
    return sums_path


def _hash_matches(declared: str, actual: str) -> bool:
    """Compare a declared hash value against an actual hex digest.

    Handles comma-separated multi-hash lists and uppercase (Recalbox)
    and truncated MD5s (Batocera 29-char): a declared value shorter
    than the digest matches by prefix.
    """
    actual = actual.lower()
    for cand in declared.split(","):
        cand = cand.strip().lower()
        if not cand:
            continue
        if len(cand) < len(actual):
            if actual.startswith(cand):
                return True
        elif actual == cand:
            return True
    return False


def _check_member_hash(
    zf: zipfile.ZipFile, member: str, file_entry: dict, mode: str
) -> str | None:
    """Verify a pack member against its platform-declared hash.

    Reproduces the platform's native check inside the pack: md5/sha1 of
    the member bytes, or checkInsideZip when zipped_file is set
    (Batocera hashes a ROM inside the ZIP, matched case-insensitively).
    Returns an error string, or None when the member passes.
    """
    declared = str(file_entry.get(mode) or "").strip()
    if not declared:
        return None

    zipped_file = file_entry.get("zipped_file")
    if zipped_file:
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(zf.read(member))) as inner:
                want = zipped_file.casefold()
                target = next(
                    (n for n in inner.namelist() if n.casefold() == want), None
                )
                if target is None:
                    return f"{member}: {zipped_file} not found inside ZIP"
                actual = hashlib.md5(inner.read(target)).hexdigest()
        except zipfile.BadZipFile:
            return f"{member}: not a valid ZIP"
        if not _hash_matches(declared, actual):
            return (
                f"{member}: {zipped_file} inside-zip md5 {actual} "
                f"!= declared {declared}"
            )
        return None

    h = hashlib.md5() if mode == "md5" else hashlib.sha1()
    with zf.open(member) as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if _hash_matches(declared, actual):
        return None

    # Recalbox Md5Composite: MD5 over sorted inner contents of a ZIP,
    # independent of compression and metadata (Zip::Md5Composite()).
    if mode == "md5" and member.endswith(".zip"):
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(zf.read(member))) as inner:
                names = sorted(n for n in inner.namelist() if not n.endswith("/"))
                ch = hashlib.md5()
                for n in names:
                    ch.update(inner.read(n))
            if _hash_matches(declared, ch.hexdigest()):
                return None
        except (zipfile.BadZipFile, OSError):
            pass

    return f"{member}: {mode} {actual} != declared {declared}"


def _repo_satisfies_declaration(
    entries: list[dict], db: dict, mode: str
) -> bool:
    """Check whether any repo file matches one of the declared hashes.

    Used to separate pack divergence (a matching file exists but was not
    packed) from data coverage gaps (no repo file matches the upstream
    declaration): only the former is a pack generation error.
    """
    from common import md5_composite

    files_db = db.get("files", {})
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    by_name = db.get("indexes", {}).get("by_name", {})

    for fe in entries:
        declared = str(fe.get(mode) or "").strip()
        if not declared:
            continue
        hashes = [h.strip().lower() for h in declared.split(",") if h.strip()]
        for h in hashes:
            if mode == "sha1":
                entry = files_db.get(h)
            else:
                entry = files_db.get(by_md5.get(h, ""))
            if entry and os.path.exists(entry.get("path", "")):
                return True
        if mode == "md5":
            hash_set = set(hashes)
            for cand_sha in by_name.get(fe.get("name", ""), []):
                entry = files_db.get(cand_sha)
                if not entry:
                    continue
                path = entry.get("path", "")
                if not path.endswith(".zip") or not os.path.exists(path):
                    continue
                try:
                    if md5_composite(path).lower() in hash_set:
                        return True
                except (zipfile.BadZipFile, OSError):
                    continue
    return False


def _intentional_hash_exclusion(
    entries: list[dict],
    db: dict,
    bios_dir: str = DEFAULT_BIOS_DIR,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    verification_mode: str = "md5",
) -> bool:
    """Return whether the builder must omit every declaration as unsafe.

    A hash platform never substitutes a same-named payload for an explicitly
    hash-identified one, so a missing pack member is accounted for when every
    declaration for that destination resolves to a local hash mismatch.  An
    existence platform reads no bytes and the builder ships the file anyway,
    so nothing is ever excluded on its behalf.  Genuine absence,
    external-download failure and a packable alternative stay conformance
    errors in both modes.
    """
    if not entries or not hash_mismatch_excludes_file(verification_mode):
        return False
    archive_index = zip_contents if zip_contents is not None else {}
    for entry in entries:
        local_path, status = resolve_file(
            entry,
            db,
            bios_dir,
            archive_index,
            data_dir_registry=data_dir_registry,
            offline=True,
        )
        if status != "hash_mismatch":
            return False

        # A container can mismatch the outer declaration while still carrying
        # the exact inner ROM requested by Batocera-style zipped_file entries.
        zipped_file = entry.get("zipped_file")
        if zipped_file and local_path:
            declared = str(entry.get("md5") or "")
            candidates = [value.strip() for value in declared.split(",") if value.strip()]
            if not candidates:
                candidates = [""]
            if any(
                check_inside_zip(local_path, zipped_file, candidate) == "ok"
                for candidate in candidates
            ):
                return False
    return True


def verify_pack_against_platform(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    emulators_dir: str = "emulators",
    emu_profiles: dict | None = None,
    regions: list[str] | None = None,
    data_registry: dict | None = None,
) -> tuple[bool, int, int, list[str], int, int, int, int, int, int]:
    """Verify a pack ZIP against its platform config and core requirements.

    A region priority list narrows the expectation to what the builder would
    have packed, using the same selection function.

    Checks:
    1. Every baseline file declared by the platform exists in the ZIP
       at the correct destination path
    2. Every in-repo core extra file (from emulator profiles) is present
    3. No duplicate entries
    4. No path anomalies (double slash, absolute, traversal)
    5. No unexpected zero-byte BIOS files

    Returns ``(all_ok, checked, present, errors, baseline_checked,
    baseline_present, core_checked, core_present, baseline_excluded)``.
    """
    from collections import Counter

    config = load_platform_config(platform_name, platforms_dir)
    base_dest = config.get("base_destination", "")
    errors: list[str] = []
    checked = 0
    present = 0

    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(emulators_dir)

    region_drops: set[str] = set()
    if regions:
        region_index = region_mod.build_region_index(emu_profiles)
        region_groups: dict[str, list[tuple[str, str]]] = {}
        for sys_id, system in config.get("systems", {}).items():
            members = region_groups.setdefault(sys_id, [])
            for fe in system.get("files", []):
                d = _sanitize_path(fe.get("destination", fe.get("name", "")))
                if d:
                    members.append((d, fe.get("name", "")))
        if db is not None:
            for extra in _collect_emulator_extras(
                config,
                emulators_dir,
                db,
                set(),
                base_dest,
                emu_profiles,
            ):
                d = _sanitize_path(
                    extra.get("destination", extra.get("name", ""))
                )
                if not d:
                    continue
                systems_for_extra = _extra_system_ids(extra) or ["_extras"]
                for sys_id in systems_for_extra:
                    variant = extra.get("variant_group")
                    group_id = (
                        f"{sys_id}:variant:{variant}" if variant else sys_id
                    )
                    region_groups.setdefault(group_id, []).append(
                        (d, extra.get("name", ""))
                    )
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions
        )

    with zipfile.ZipFile(zip_path, "r") as zf:
        zip_set = set(zf.namelist())
        zip_lower = {n.lower(): n for n in zip_set}

        # Auto-detect flat vs nested ZIP
        is_flat = bool(base_dest) and not any(
            n.startswith(base_dest + "/")
            for n in zip_set
            if n not in ("README.txt", "manifest.json") and not n.endswith("/")
        )

        # Structural checks
        dupes = sum(1 for c in Counter(zf.namelist()).values() if c > 1)
        if dupes:
            errors.append(f"{dupes} duplicate entries")
        for n in zip_set:
            if "//" in n:
                errors.append(f"double slash: {n}")
            if n.startswith("/"):
                errors.append(f"absolute path: {n}")
            if ".." in n:
                errors.append(f"path traversal: {n}")

        # Zero-byte check (exclude Dolphin GraphicMods markers)
        for info in zf.infolist():
            if info.file_size == 0 and not info.is_dir():
                if "GraphicMods" not in info.filename and info.filename not in (
                    "manifest.json",
                    "README.txt",
                ):
                    errors.append(f"zero-byte: {info.filename}")

        # 1. Baseline file presence + native hash check
        verification_mode = config.get("verification_mode", "existence")
        baseline_checked = 0
        baseline_present = 0
        baseline_excluded = 0
        decl_by_member: dict[str, list[dict]] = {}
        # Mirror the builder's path-conflict logic: a declaration whose path
        # collides file-vs-directory with a packed member was skipped by the
        # builder (upstream declares e.g. both SGB1.sfc and SGB1.sfc/program.rom)
        zip_parents: set[str] = set()
        for n in zip_set:
            parts = n.split("/")
            for i in range(1, len(parts)):
                zip_parents.add("/".join(parts[:i]))
        baseline_groups: dict[str, list[dict]] = {}
        for _sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                dest = _sanitize_path(fe.get("destination", fe.get("name", "")))
                if not dest:
                    continue
                if region_drops and dest in region_drops:
                    continue
                expected = f"{base_dest}/{dest}" if base_dest and not is_flat else dest
                baseline_groups.setdefault(expected, []).append(fe)

        baseline_checked = len(baseline_groups)
        exclusion_index = build_zip_contents_index(db) if db is not None else {}
        for expected, declarations in baseline_groups.items():
            if expected in zip_set:
                member = expected
            elif expected.lower() in zip_lower:
                member = zip_lower[expected.lower()]
            elif _has_path_conflict(expected, zip_set, zip_parents):
                # Skipped by the builder for the same reason: not an error
                baseline_present += 1
                continue
            elif db is not None and _intentional_hash_exclusion(
                declarations,
                db,
                zip_contents=exclusion_index,
                data_dir_registry=data_registry,
                verification_mode=verification_mode,
            ):
                baseline_excluded += 1
                continue
            else:
                errors.append(f"baseline missing: {expected}")
                continue
            baseline_present += 1
            decl_by_member.setdefault(member, []).extend(declarations)

        # Reproduce the platform's native hash check on pack bytes.
        # A destination declared by several entries passes when the packed
        # member satisfies any of them. A failure only counts as a pack
        # error when the repo holds a file matching a declaration: without
        # one, the pack ships its best effort and the gap is a data issue
        # reported by verify.py, not a generation bug.
        if verification_mode in ("md5", "sha1"):
            for member, decl_entries in decl_by_member.items():
                checkable = [
                    fe
                    for fe in decl_entries
                    if str(fe.get(verification_mode) or "").strip()
                ]
                if not checkable:
                    continue
                member_errors = []
                satisfied = False
                for fe in checkable:
                    err = _check_member_hash(zf, member, fe, verification_mode)
                    if err is None:
                        satisfied = True
                        break
                    member_errors.append(err)
                if satisfied:
                    continue
                if db is None or _repo_satisfies_declaration(
                    checkable, db, verification_mode
                ):
                    errors.append(member_errors[0])

        # 2. Core extras presence (files from emulator profiles, in repo)
        #    Mirror the pack builder's skip logic: only count files that
        #    can actually be resolved and don't have path conflicts.
        core_checked = 0
        core_present = 0
        if db is not None:
            core_files = _collect_emulator_extras(
                config,
                emulators_dir,
                db,
                set(),
                base_dest,
                emu_profiles,
            )
            seen_conformance: set[str] = set(zip_set)
            seen_parents: set[str] = set()
            for n in zip_set:
                parts = n.split("/")
                for i in range(1, len(parts)):
                    seen_parents.add("/".join(parts[:i]))
            extras_pfx = _detect_extras_prefix(config, base_dest)
            for fe in core_files:
                raw_dest = fe.get("destination", fe.get("name", ""))
                dest = _sanitize_path(raw_dest)
                if not dest:
                    continue
                if region_drops and _sanitize_path(dest) in region_drops:
                    continue
                if extras_pfx and not (is_flat and extras_pfx == base_dest):
                    if not dest.startswith(f"{extras_pfx}/"):
                        full = f"{extras_pfx}/{dest}"
                    else:
                        full = dest
                else:
                    full = dest
                # Skip path conflicts (same logic as pack builder)
                if _has_path_conflict(full, seen_conformance, seen_parents):
                    continue
                # Skip unresolvable files (game_data dirs, etc.)
                local_path, status = resolve_file(
                    fe,
                    db,
                    "bios",
                    {},
                    dest_hint=raw_dest,
                    data_dir_registry=data_registry,
                    offline=True,
                )
                if status in ("not_found", "external", "user_provided"):
                    continue
                core_checked += 1
                if full in zip_set or full.lower() in zip_lower:
                    core_present += 1
                    seen_conformance.add(full)
                    _register_path(full, seen_conformance, seen_parents)
                else:
                    errors.append(f"core missing: {full}")

        checked = baseline_checked + core_checked
        present = baseline_present + core_present

    return (
        len(errors) == 0,
        checked,
        present,
        errors,
        baseline_checked,
        baseline_present,
        core_checked,
        core_present,
        baseline_excluded,
    )


def _narrows_contents(pack_name: str) -> bool:
    """True when a pack holds fewer files than the platform declares.

    A source-restricted or required-only build is narrower by design, so the
    full platform expectation does not apply to it and conformance is skipped.
    Region is not listed: the region filter is passed to the check itself.
    """
    return any(tag in pack_name for tag in ("_Platform_", "_Truth_", "_Required"))


def verify_and_finalize_packs(
    output_dir: str,
    db: dict,
    platforms_dir: str = "platforms",
    skip_conformance: bool = False,
    data_registry: dict | None = None,
    regions: list[str] | None = None,
) -> bool:
    """Verify all packs, inject manifests, generate SHA256SUMS.

    Two-stage verification:
    1. Hash check against database.json (integrity)
    2. Extract + verify against platform config (conformance)

    Returns True if all packs pass verification.
    """
    all_ok = True

    # Map ZIP names to platform names
    pack_to_platform: dict[str, list[str]] = {}
    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        for pname in list_registered_platforms(platforms_dir):
            cfg = load_platform_config(pname, platforms_dir)
            display = cfg.get("platform", pname).replace(" ", "_")
            if display in name or display.replace("_", "") in name.replace("_", ""):
                pack_to_platform.setdefault(name, []).append(pname)

    for name in sorted(os.listdir(output_dir)):
        if not name.endswith(".zip"):
            continue
        zip_path = os.path.join(output_dir, name)

        # Stage 1: database integrity
        ok, manifest = verify_pack(zip_path, db, data_registry=data_registry)
        summary = manifest["summary"]
        status = "OK" if ok else "ERRORS"
        print(
            f"  verify {name}: {summary['verified']}/{summary['total_files']} verified, "
            f"{summary['untracked']} untracked, {summary['errors']} errors [{status}]"
        )
        if not ok:
            for err in manifest["errors"]:
                print(f"    ERROR: {err}")
            all_ok = False
        inject_manifest(zip_path, manifest)

        # Stage 2: platform conformance (extract + verify)
        # Skipped for filtered/split/custom packs (intentionally partial)
        if skip_conformance:
            continue
        if _narrows_contents(name):
            continue
        platforms = pack_to_platform.get(name, [])
        for pname in platforms:
            (
                p_ok,
                total,
                matched,
                p_errors,
                bl_checked,
                bl_present,
                core_checked,
                core_present,
                bl_excluded,
            ) = verify_pack_against_platform(
                zip_path,
                pname,
                platforms_dir,
                db=db,
                regions=regions,
                data_registry=data_registry,
            )
            status = "OK" if p_ok else "FAILED"
            exclusion_note = (
                f", {bl_excluded} unsafe excluded" if bl_excluded else ""
            )
            print(
                f"  platform {pname}: {bl_present}/{bl_checked} baseline present"
                f"{exclusion_note}, "
                f"{core_present}/{core_checked} cores present, {status}"
            )
            if not p_ok:
                for err in p_errors:
                    print(f"    {err}")
                all_ok = False

    generate_sha256sums(output_dir)
    return all_ok


if __name__ == "__main__":
    main()
