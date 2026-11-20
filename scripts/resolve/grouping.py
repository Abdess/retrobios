"""Platforms whose packs are identical, grouped under one build."""

from __future__ import annotations

import hashlib
import json
import os

from model.platforms import load_platform_config
from model.sources import source_yaml_file
from resolve.layout import CORE_DIR_PREFIX
from resolve.standalone import standalone_set


def group_identical_platforms(
    platforms: list[str],
    platforms_dir: str,
    target_cores_cache: dict[str, set[str] | None] | None = None,
) -> list[tuple[list[str], str]]:
    """Group platforms that produce identical packs.

    A pack is the platform's own files plus those of the emulators it runs,
    so two platforms share one only when both agree. base_destination does
    not separate them: destinations inside a pack are relative to it.

    Returns [(group_of_platform_names, representative), ...].
    The representative is the root platform (one that does not inherit).
    """
    fingerprints: dict[str, list[str]] = {}
    representatives: dict[str, str] = {}
    inherits: dict[str, bool] = {}

    for platform in platforms:
        try:
            raw_path = os.path.join(platforms_dir, f"{platform}.yml")
            raw = source_yaml_file(raw_path) or {}
            inherits[platform] = "inherits" in raw
            config = load_platform_config(platform, platforms_dir)
        except FileNotFoundError:
            fingerprints.setdefault(platform, []).append(platform)
            representatives.setdefault(platform, platform)
            inherits[platform] = False
            continue

        # Every field of every entry: the builder reads required, zipped_file,
        # size and crc32 too, so two lists that differ only there are two
        # packs. So is the way the frontend checks a file.
        entries = [
            json.dumps(fe, sort_keys=True, default=str)
            for _sys_id, system in sorted(config.get("systems", {}).items())
            for fe in system.get("files", [])
        ]
        entries.append(
            f"mode={config.get('verification_mode', '')}|rule={config.get('hash_rule', '')}"
        )

        fp = hashlib.sha1("|".join(sorted(entries)).encode()).hexdigest()
        cores = config.get("cores")
        emulators = [
            cores if isinstance(cores, str) else sorted(map(str, cores or [])),
            sorted(map(str, config.get("standalone_cores") or [])),
            sorted(map(str, config.get("dual_mode_cores") or [])),
            sorted(map(str, config.get("installable_cores") or [])),
            # One archive cannot serve a filesystem that folds case and one
            # that does not: Lakka keeps bios.col beside BIOS.col.
            bool(config.get("case_insensitive_fs")),
            # Where each core's files go: the same cores handed other
            # folders make another pack.
            sorted(
                tag for tag in standalone_set(config) if tag.startswith(CORE_DIR_PREFIX)
            ),
        ]
        fp = hashlib.sha1(f"{fp}|{emulators}".encode()).hexdigest()
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
