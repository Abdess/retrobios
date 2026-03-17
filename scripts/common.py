"""Shared utilities for retrobios scripts.

Single source of truth for platform config loading, hash computation,
and file resolution - eliminates DRY violations across scripts.
"""

from __future__ import annotations

import hashlib
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


def md5sum(filepath: str | Path) -> str:
    """Compute MD5 of a file - matches Batocera's md5sum()."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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

    # Resolve shared group includes
    shared_path = os.path.join(platforms_dir, "_shared.yml")
    if os.path.exists(shared_path):
        with open(shared_path) as f:
            shared = yaml.safe_load(f) or {}
        shared_groups = shared.get("shared_groups", {})
        for system in config.get("systems", {}).values():
            for group_name in system.get("includes", []):
                if group_name in shared_groups:
                    system.setdefault("files", []).extend(shared_groups[group_name])

    return config


def safe_extract_zip(zip_path: str, dest_dir: str) -> None:
    """Extract a ZIP file safely, preventing zip-slip path traversal."""
    dest = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(dest, member.filename))
            if not member_path.startswith(dest + os.sep) and member_path != dest:
                raise ValueError(f"Zip slip detected: {member.filename}")
            zf.extract(member, dest)
