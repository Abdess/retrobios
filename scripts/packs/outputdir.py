"""The output directory a pack run writes: its lock and the installer JSON it holds."""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path

from core.artifacts import artifact_lock, repository_output_lock
from packs.targets import is_target_list


def json_artifact_kind(path: Path) -> str | None:
    """"manifest" for an install manifest, "targets" for a per-target core
    list, None for anything else. The two share their file names: install.py
    fetches install/<platform>.json and install/targets/<platform>.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data:
        return None
    if "manifest_version" in data:
        return "manifest"
    if is_target_list(data):
        return "targets"
    return None


def holds_other_kind(output_dir: str, writing: str) -> bool:
    """Say so when one kind of installer JSON would overwrite the other.

    Both are named <platform>.json, so --manifest-targets aimed at install/
    replaced install/retroarch.json, the file every installer downloads, with
    a target table, and the reverse replaced a target list by a manifest.
    """
    directory = Path(output_dir)
    if not directory.is_dir():
        return False
    other = "targets" if writing == "manifest" else "manifest"
    held = sorted(
        p.name for p in directory.glob("*.json") if json_artifact_kind(p) == other
    )
    if not held:
        return False
    what = {
        "manifest": "install manifests (install/ in the repository)",
        "targets": "per-target core lists (install/targets/ in the repository)",
    }
    flag = "--manifest" if writing == "manifest" else "--manifest-targets"
    print(
        f"ERROR: {output_dir} holds {what[other]}: {', '.join(held[:3])}"
        f"{', ...' if len(held) > 3 else ''}. {flag} writes {what[writing]} under the "
        f"same file names; pass the --output-dir that holds those instead.",
        file=sys.stderr,
    )
    return True


@contextlib.contextmanager
def pack_output_lock(output_dir: str, exclusive: bool = True) -> Iterator[None]:
    """Hold the output directory for the duration of a pack run, and the
    repository's fixed outputs when it is one of them (install/)."""
    with artifact_lock(output_dir, exclusive=exclusive), \
            repository_output_lock(output_dir) if exclusive else contextlib.nullcontext():
        yield
