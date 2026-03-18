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
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import load_database, load_platform_config

try:
    import yaml
except ImportError:
    print("Error: PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_DB_FILE = "database.json"
DEFAULT_OUTPUT_DIR = "dist"
DEFAULT_BIOS_DIR = "bios"
LARGE_FILES_RELEASE = "large-files"
LARGE_FILES_REPO = "Abdess/retrobios"

MAX_ENTRY_SIZE = 512 * 1024 * 1024  # 512MB


def _verify_file_hash(path: str, expected_sha1: str = "",
                      expected_md5: str = "") -> bool:
    """Compute and compare hash of a local file."""
    if not expected_sha1 and not expected_md5:
        return True
    h = hashlib.sha1() if expected_sha1 else hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest() == (expected_sha1 or expected_md5)


def fetch_large_file(name: str, dest_dir: str = ".cache/large",
                     expected_sha1: str = "", expected_md5: str = "") -> str | None:
    """Download a large file from the 'large-files' GitHub release if not cached."""
    cached = os.path.join(dest_dir, name)
    if os.path.exists(cached):
        if expected_sha1 or expected_md5:
            if _verify_file_hash(cached, expected_sha1, expected_md5):
                return cached
            os.unlink(cached)
        else:
            return cached

    encoded_name = urllib.request.quote(name)
    url = f"https://github.com/{LARGE_FILES_REPO}/releases/download/{LARGE_FILES_RELEASE}/{encoded_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-pack/1.0"})
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
        if not _verify_file_hash(cached, expected_sha1, expected_md5):
            os.unlink(cached)
            return None
    return cached


def _sanitize_path(raw: str) -> str:
    """Strip path traversal components from a relative path."""
    raw = raw.replace("\\", "/")
    parts = [p for p in raw.split("/") if p and p != ".."]
    return "/".join(parts)


def resolve_file(file_entry: dict, db: dict, bios_dir: str,
                  zip_contents: dict | None = None) -> tuple[str | None, str]:
    """Resolve a BIOS file to its local path using database.json.

    Returns (local_path, status) where status is one of:
    exact, zip_exact, hash_mismatch, external, user_provided, not_found.
    """
    storage = file_entry.get("storage", "embedded")
    if storage == "user_provided":
        return None, "user_provided"
    if storage == "external":
        return None, "external"

    sha1 = file_entry.get("sha1")
    md5 = file_entry.get("md5")
    name = file_entry.get("name", "")
    zipped_file = file_entry.get("zipped_file")

    if sha1 and sha1 in db.get("files", {}):
        local_path = db["files"][sha1]["path"]
        if os.path.exists(local_path):
            return local_path, "exact"

    if md5:
        sha1_from_md5 = db.get("indexes", {}).get("by_md5", {}).get(md5)
        if sha1_from_md5 and sha1_from_md5 in db["files"]:
            local_path = db["files"][sha1_from_md5]["path"]
            if os.path.exists(local_path):
                return local_path, "exact"

        # Truncated MD5 match (batocera-systems bug: 29 chars instead of 32)
        if len(md5) < 32:
            for db_md5, db_sha1 in db.get("indexes", {}).get("by_md5", {}).items():
                if db_md5.startswith(md5) and db_sha1 in db["files"]:
                    local_path = db["files"][db_sha1]["path"]
                    if os.path.exists(local_path):
                        return local_path, "exact"

    if zipped_file and md5 and zip_contents:
        if md5 in zip_contents:
            zip_sha1 = zip_contents[md5]
            if zip_sha1 in db["files"]:
                local_path = db["files"][zip_sha1]["path"]
                if os.path.exists(local_path):
                    return local_path, "zip_exact"

    # Release assets override local files (authoritative large files)
    cached = fetch_large_file(name, expected_sha1=sha1 or "", expected_md5=md5 or "")
    if cached:
        return cached, "release_asset"

    # No MD5 specified = any local file with that name is acceptable
    if not md5:
        name_matches = db.get("indexes", {}).get("by_name", {}).get(name, [])
        for match_sha1 in name_matches:
            if match_sha1 in db["files"]:
                local_path = db["files"][match_sha1]["path"]
                if os.path.exists(local_path):
                    return local_path, "exact"

    # Name fallback (hash mismatch)
    name_matches = db.get("indexes", {}).get("by_name", {}).get(name, [])
    for match_sha1 in name_matches:
        if match_sha1 in db["files"]:
            local_path = db["files"][match_sha1]["path"]
            if os.path.exists(local_path):
                return local_path, "hash_mismatch"

    return None, "not_found"


def build_zip_contents_index(db: dict) -> dict:
    """Build index of {inner_rom_md5: zip_file_sha1} for ROMs inside ZIP files."""
    index = {}
    for sha1, entry in db.get("files", {}).items():
        path = entry["path"]
        if not path.endswith(".zip") or not os.path.exists(path):
            continue
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if info.file_size > MAX_ENTRY_SIZE:
                        continue
                    data = zf.read(info.filename)
                    inner_md5 = hashlib.md5(data).hexdigest()
                    index[inner_md5] = sha1
        except (zipfile.BadZipFile, OSError):
            continue
    return index


def download_external(file_entry: dict, dest_path: str) -> bool:
    """Download an external BIOS file, verify hash, save to dest_path."""
    url = file_entry.get("source_url")
    if not url:
        return False

    sha256 = file_entry.get("sha256")
    sha1 = file_entry.get("sha1")
    md5 = file_entry.get("md5")

    if not (sha256 or sha1 or md5):
        print(f"    WARNING: no hash for {file_entry['name']}, skipping unverifiable download")
        return False

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-pack-gen/1.0"})
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


def _load_emulator_extras(
    platform_name: str,
    platforms_dir: str,
    emulators_dir: str,
    seen: dict,
    base_dest: str,
    config: dict | None = None,
) -> list[dict]:
    """Load extra files from emulator profiles not already in the platform pack.

    Collects emulators from two sources:
    1. Auto-detected from platform config "core:" fields per system
    2. Manual "emulators:" list in _registry.yml
    """
    emu_names = set()

    # Source 1: auto-detect from platform config core: fields
    if config:
        for system in config.get("systems", {}).values():
            core = system.get("core", "")
            if core:
                emu_names.add(core)

    # Source 2: manual list from _registry.yml
    registry_path = os.path.join(platforms_dir, "_registry.yml")
    if os.path.exists(registry_path):
        with open(registry_path) as f:
            registry = yaml.safe_load(f) or {}
        platform_cfg = registry.get("platforms", {}).get(platform_name, {})
        for name in platform_cfg.get("emulators", []):
            emu_names.add(name)

    if not emu_names:
        return []

    extras = []
    emu_dir = Path(emulators_dir)
    for emu_name in emu_names:
        emu_path = emu_dir / f"{emu_name}.yml"
        if not emu_path.exists():
            continue
        with open(emu_path) as f:
            profile = yaml.safe_load(f) or {}

        # Follow alias
        if profile.get("alias_of"):
            parent = emu_dir / f"{profile['alias_of']}.yml"
            if parent.exists():
                with open(parent) as f:
                    profile = yaml.safe_load(f) or {}

        for fe in profile.get("files", []):
            name = fe.get("name", "")
            if not name or name.startswith("<"):
                continue
            dest = fe.get("destination", name)
            full_dest = f"{base_dest}/{dest}" if base_dest else dest
            if full_dest in seen:
                continue
            extras.append({
                "name": name,
                "sha1": fe.get("sha1"),
                "md5": fe.get("md5"),
                "destination": dest,
                "required": fe.get("required", False),
                "source_emulator": emu_name,
            })
    return extras


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db_path: str,
    bios_dir: str,
    output_dir: str,
    include_extras: bool = False,
    emulators_dir: str = "emulators",
) -> str | None:
    """Generate a ZIP pack for a platform.

    Returns the path to the generated ZIP, or None on failure.
    """
    config = load_platform_config(platform_name, platforms_dir)
    db = load_database(db_path)

    zip_contents = build_zip_contents_index(db)

    verification_mode = config.get("verification_mode", "existence")
    platform_display = config.get("platform", platform_name)
    base_dest = config.get("base_destination", "")

    suffix = "Complete_Pack" if include_extras else "BIOS_Pack"
    zip_name = f"{platform_display.replace(' ', '_')}_{suffix}.zip"
    zip_path = os.path.join(output_dir, zip_name)
    os.makedirs(output_dir, exist_ok=True)

    total_files = 0
    missing_files = []
    untested_files = []
    user_provided = []
    seen_destinations = {}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for sys_id, system in sorted(config.get("systems", {}).items()):
            for file_entry in system.get("files", []):
                dest = _sanitize_path(file_entry.get("destination", file_entry["name"]))
                if not dest:
                    continue
                if base_dest:
                    full_dest = f"{base_dest}/{dest}"
                else:
                    full_dest = dest

                dedup_key = full_dest
                if dedup_key in seen_destinations:
                    continue
                seen_destinations[dedup_key] = file_entry.get("sha1") or file_entry.get("md5") or ""

                storage = file_entry.get("storage", "embedded")

                if storage == "user_provided":
                    instructions = file_entry.get("instructions", "Please provide this file manually.")
                    instr_name = f"INSTRUCTIONS_{file_entry['name']}.txt"
                    instr_path = f"{base_dest}/{instr_name}" if base_dest else instr_name
                    zf.writestr(instr_path, f"File needed: {file_entry['name']}\n\n{instructions}\n")
                    user_provided.append(file_entry["name"])
                    total_files += 1
                    continue

                local_path, status = resolve_file(file_entry, db, bios_dir, zip_contents)

                if status == "external":
                    suffix = os.path.splitext(file_entry["name"])[1] or ""
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        tmp_path = tmp.name

                    try:
                        if download_external(file_entry, tmp_path):
                            extract = file_entry.get("extract", False)
                            if extract and tmp_path.endswith(".zip"):
                                _extract_zip_to_archive(tmp_path, full_dest, zf)
                            else:
                                zf.write(tmp_path, full_dest)
                            total_files += 1
                        else:
                            missing_files.append(file_entry["name"])
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    continue

                if status == "not_found":
                    missing_files.append(file_entry["name"])
                    continue

                if status == "hash_mismatch":
                    if verification_mode != "existence":
                        untested_files.append(file_entry["name"])

                extract = file_entry.get("extract", False)
                if extract and local_path.endswith(".zip"):
                    _extract_zip_to_archive(local_path, full_dest, zf)
                else:
                    zf.write(local_path, full_dest)
                total_files += 1

        # Tier 2: emulator extras
        extra_count = 0
        if include_extras:
            extras = _load_emulator_extras(
                platform_name, platforms_dir, emulators_dir,
                seen_destinations, base_dest, config=config,
            )
            for fe in extras:
                dest = _sanitize_path(fe.get("destination", fe["name"]))
                if not dest:
                    continue
                full_dest = f"{base_dest}/{dest}" if base_dest else dest
                if full_dest in seen_destinations:
                    continue

                local_path, status = resolve_file(fe, db, bios_dir, zip_contents)
                if status in ("not_found", "external", "user_provided"):
                    continue

                zf.write(local_path, full_dest)
                seen_destinations[full_dest] = fe.get("sha1") or fe.get("md5") or ""
                extra_count += 1
                total_files += 1

    if missing_files:
        print(f"  Missing ({len(missing_files)}): {', '.join(missing_files[:10])}")
        if len(missing_files) > 10:
            print(f"    ... and {len(missing_files) - 10} more")

    if untested_files:
        print(f"  Untested ({len(untested_files)}): {', '.join(untested_files[:10])}")
        if len(untested_files) > 10:
            print(f"    ... and {len(untested_files) - 10} more")

    if user_provided:
        print(f"  User-provided ({len(user_provided)}): {', '.join(user_provided)}")

    extras_msg = f" + {extra_count} emulator extras" if extra_count else ""
    if verification_mode == "existence":
        print(f"  Generated {zip_path}: {total_files} files ({total_files - extra_count} platform{extras_msg}, {len(missing_files)} missing) [verification: existence]")
    else:
        verified = total_files - len(untested_files)
        print(f"  Generated {zip_path}: {total_files} files ({verified} verified{extras_msg}, {len(untested_files)} untested, {len(missing_files)} missing) [verification: {verification_mode}]")
    return zip_path


def _extract_zip_to_archive(source_zip: str, dest_prefix: str, target_zf: zipfile.ZipFile):
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


def list_platforms(platforms_dir: str) -> list[str]:
    """List available platform names from YAML files."""
    platforms = []
    for f in sorted(Path(platforms_dir).glob("*.yml")):
        if f.name.startswith("_"):
            continue
        platforms.append(f.stem)
    return platforms


def main():
    parser = argparse.ArgumentParser(description="Generate platform BIOS ZIP packs")
    parser.add_argument("--platform", "-p", help="Platform name (e.g., retroarch)")
    parser.add_argument("--all", action="store_true", help="Generate packs for all active platforms")
    parser.add_argument("--include-archived", action="store_true", help="Include archived platforms")
    parser.add_argument("--platforms-dir", default=DEFAULT_PLATFORMS_DIR)
    parser.add_argument("--db", default=DEFAULT_DB_FILE, help="Path to database.json")
    parser.add_argument("--bios-dir", default=DEFAULT_BIOS_DIR)
    parser.add_argument("--output-dir", "-o", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--include-extras", action="store_true",
                        help="Include emulator-recommended files not declared by platform")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--list", action="store_true", help="List available platforms")
    args = parser.parse_args()

    if args.list:
        platforms = list_platforms(args.platforms_dir)
        for p in platforms:
            print(p)
        return

    if args.all:
        sys.path.insert(0, os.path.dirname(__file__))
        from list_platforms import list_platforms as _list_active
        platforms = _list_active(include_archived=args.include_archived)
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    groups = _group_identical_platforms(platforms, args.platforms_dir)

    for group_platforms, representative in groups:
        if len(group_platforms) > 1:
            names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
            combined_name = " + ".join(names)
            print(f"\nGenerating shared pack for {combined_name}...")
        else:
            print(f"\nGenerating pack for {representative}...")

        try:
            zip_path = generate_pack(
                representative, args.platforms_dir, args.db, args.bios_dir, args.output_dir,
                include_extras=args.include_extras, emulators_dir=args.emulators_dir,
            )
            if zip_path and len(group_platforms) > 1:
                # Rename ZIP to include all platform names
                names = [load_platform_config(p, args.platforms_dir).get("platform", p) for p in group_platforms]
                combined_filename = "_".join(n.replace(" ", "") for n in names) + "_BIOS_Pack.zip"
                new_path = os.path.join(os.path.dirname(zip_path), combined_filename)
                if new_path != zip_path:
                    os.rename(zip_path, new_path)
                    print(f"  Renamed -> {os.path.basename(new_path)}")
        except (FileNotFoundError, OSError, yaml.YAMLError) as e:
            print(f"  ERROR: {e}")


def _group_identical_platforms(platforms: list[str], platforms_dir: str) -> list[tuple[list[str], str]]:
    """Group platforms that would produce identical ZIP packs.

    Returns [(group_of_platform_names, representative_platform), ...].
    Platforms with the same resolved systems+files+base_destination are grouped.
    """
    fingerprints = {}
    representatives = {}

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

        fingerprint = hashlib.sha1("|".join(sorted(entries)).encode()).hexdigest()
        fingerprints.setdefault(fingerprint, []).append(platform)
        representatives.setdefault(fingerprint, platform)

    return [(group, representatives[fp]) for fp, group in fingerprints.items()]


if __name__ == "__main__":
    main()
