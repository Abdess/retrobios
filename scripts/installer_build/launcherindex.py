"""install/launchers/index.json: the handheld launchers as files for a card."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from core.paths import REPO_ROOT
from installer_build.port import (
    BATOCERA_ZIP,
    MUOS_APP,
    TOOLS_ZIP,
    _packs_table,
    archive_members,
    pinned_installer_sha256,
)


OUTPUT = REPO_ROOT / "install" / "launchers" / "index.json"

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {REPO_ROOT / 'install.py'}")
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
