"""install/launchers/index.json: the handheld launchers as files for a card."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.paths import REPO_ROOT
from installer_build.module import installer_module
from installer_build.pins import installer_sha256, pinned_sha256
from installer_build.handhelds import Launcher, launchers_for
from installer_build.port import MUOS_APP, PORT_ZIP, archive_members, packs_table


OUTPUT = REPO_ROOT / "install" / "launchers" / "index.json"

_install = installer_module()



def own_launcher(system: str) -> Launcher:
    """The row of handhelds.LAUNCHERS that starts *system* from its own menu,
    the one the installer puts on its card. PortMaster's row is not it."""
    own = [launcher for launcher in launchers_for(system) if launcher.archive != PORT_ZIP]
    if len(own) != 1:
        raise ValueError(f"{system}: {len(own)} launcher rows outside PortMaster, "
                         "the card needs exactly one")
    return own[0]


def card_folder(system: str) -> str:
    """The folder below the card's root that *system*'s own row names: the
    first quoted path of its copy_to, a console path ending in it."""
    text = own_launcher(system).folder_for(system)
    return text.split("`")[1].strip("/") if text.count("`") >= 2 else ""


def launcher_archives() -> dict[str, str]:
    """The archive each APP_PLACES system gets, by its key, read from the
    handheld table so the card install and the doc rows agree."""
    archives = {}
    for system, place in _install.APP_PLACES.items():
        folder = card_folder(system)
        if folder != place.folder and not folder.endswith("/" + place.folder):
            raise ValueError(f"{system}: APP_PLACES writes to {place.folder}, "
                             f"the handheld table says {folder or 'no folder'}")
        archives[place.key] = own_launcher(system).archive
    return archives


# The archive whose members each system gets, by its key in APP_PLACES.
LAUNCHER_ARCHIVES = launcher_archives()


def _entry(field: str, name: str, source: Path | None, root: Path) -> dict:
    """A member as the list records it: where it comes from, its size and
    hash, and whether it is executable in the repository."""
    if source is None:
        data = packs_table(root)
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
    actual = installer_sha256(root)
    if actual != pinned_sha256("install.sh", root):
        raise ValueError("install.py is not the installer install.sh pins: re-pin the "
                         "bootstraps before writing the launcher list")
    places = {place.key: place for place in _install.APP_PLACES.values()}
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
