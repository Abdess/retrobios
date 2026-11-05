#!/usr/bin/env python3
"""Write install/launchers/index.json: the handheld launchers as files for a card.

    python scripts/generate_launcher_index.py           rewrite the list
    python scripts/generate_launcher_index.py --check   exit 1 when it is stale

install.py --add-app reads this list from the ref its file lists come from,
and puts on a handheld's card the launcher of its system, each file checked
against the size and SHA-256 recorded here. The files are the members of the
archives scripts/build_port.py builds, from the same sources: muOS gets its
application archive, rebuilt by the installer from the members and checked
against the hash recorded for it, the others the archive's files at their
place on the card. Where each system's files go is install.py's APP_PLACES.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from artifacts import write_text_atomic
from build_port import (
    BATOCERA_ZIP,
    MUOS_APP,
    REPO_ROOT,
    TOOLS_ZIP,
    _packs_table,
    archive_members,
    pinned_installer_sha256,
)

OUTPUT = REPO_ROOT / "install" / "launchers" / "index.json"

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_install)

# The archive whose members each system gets, by its key in APP_PLACES.
LAUNCHER_ARCHIVES = {"muos": MUOS_APP, "knulli": BATOCERA_ZIP, "rocknix": TOOLS_ZIP}


def _entry(field: str, name: str, source: Path | None, root: Path) -> dict:
    """A member as the list records it: where it comes from, its size and
    hash, and whether it is executable in the repository."""
    if source is None:
        data = _packs_table(root)
        origin: dict = {"content": data.decode("utf-8")}
        executable = False
    else:
        data = source.read_bytes()
        origin = {"repo_path": source.relative_to(root).as_posix()}
        executable = bool(source.stat().st_mode & 0o111)
    return {field: name, **origin, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "executable": executable}


def _member_bytes(entry: dict, root: Path) -> bytes:
    if "content" in entry:
        return entry["content"].encode("utf-8")
    return (root / entry["repo_path"]).read_bytes()


def build_index(root: Path = REPO_ROOT) -> dict:
    """Every launcher a card can carry, from the archives' members."""
    actual = hashlib.sha256((root / "install.py").read_bytes()).hexdigest()
    if actual != pinned_installer_sha256(root):
        raise ValueError("install.py is not the installer install.sh pins: re-pin the "
                         "bootstraps before writing the launcher list")
    places = {place.key: place for place in _install.APP_PLACES.values()}
    if set(places) != set(LAUNCHER_ARCHIVES):
        raise ValueError(f"APP_PLACES names {sorted(places)}, the archives "
                         f"{sorted(LAUNCHER_ARCHIVES)}")
    launchers: dict[str, dict] = {}
    for key, archive in sorted(LAUNCHER_ARCHIVES.items()):
        folder = places[key].folder
        members = archive_members(archive, root)
        if archive == MUOS_APP:
            entries = [_entry("name", name, source, root) for name, source in members]
            data = _install.app_archive([(entry, _member_bytes(entry, root))
                                         for entry in entries])
            launchers[key] = {
                "archive": {"dest": f"{folder}/{archive}", "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()},
                "members": entries,
            }
        else:
            # Executable only where the menu starts the script as a program:
            # a mode a FAT card cannot hold is refused by its driver.
            files = [_entry("dest", f"{folder}/{name}", source, root)
                     for name, source in members]
            for entry in files:
                entry["executable"] = entry["executable"] and places[key].executable
            launchers[key] = {"files": files}
    return {"schema": _install.APP_SCHEMA, "launchers": launchers}


def render(index: dict) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when the list differs from the launchers, writing nothing")
    parser.add_argument("--output", type=Path, default=OUTPUT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        text = render(build_index())
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
    if current == text:
        return 0
    if args.check:
        print(f"{args.output} differs from the launchers in ports/: run "
              "python scripts/generate_launcher_index.py", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(str(args.output), text)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
