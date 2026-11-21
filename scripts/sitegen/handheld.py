"""The handheld launchers the site serves, and where each one goes.

The four archives scripts/build_port.py writes carry install.py pinned by
SHA-256, so they change with the installer, not with the BIOS packs. The
site builds them from the commit it is built from and serves them under
get/handheld/, beside the bootstraps that pin the same installer
(sitegen/bootstrap.py). build_archive refuses an install.py that install.sh
does not pin: a stale pin stops the site build, the last good archives
staying served.

LAUNCHERS (installer_build/handhelds.py) is the one description of where
each archive goes on the card and which menu starts it. The handheld
tables of wiki/installer.md are written from it, and so is the block each
get/<platform>/ page and the handheld page carry, written here.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.text import series
from sitegen import markup
from core.artifacts import write_bytes_atomic
from installer_build.port import (
    ARCHIVES,
    PORT_ZIP,
    build_archive,
)
from core.paths import REPO_ROOT
from core.sizes import size_text
from installer_build.handhelds import Launcher, PLATFORM_OF, SERVED_DIR, launchers_for, systems

GROUP_TITLE = "RetroBIOS app for handhelds"


def group_systems() -> list[str]:
    return [name for name in systems() if name not in PLATFORM_OF]


@dataclass(frozen=True)
class Served:
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


_built: dict[tuple[str, str], Served] = {}


def served(name: str, root: Path = REPO_ROOT) -> Served:
    """The bytes of archive *name* as build_port builds it from *root*,
    built once per run: the page states the size and hash of the file the
    same run writes."""
    key = (str(root.resolve()), name)
    if key not in _built:
        scratch_root = root / "tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root, prefix="handheld-") as scratch:
            path = build_archive(name, Path(scratch) / name, root)
            _built[key] = Served(path.read_bytes())
    return _built[key]


def write_launchers(public: Path, root: Path = REPO_ROOT) -> list[Path]:
    """Write every launcher archive under the site's public folder, each
    only when its bytes moved."""
    folder = public / SERVED_DIR
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name in ARCHIVES:
        path = folder / name
        data = served(name, root).data
        if not path.is_file() or path.read_bytes() != data:
            write_bytes_atomic(str(path), data)
        written.append(path)
    return written


def _launcher_block(launcher: Launcher, system: str, root: Path) -> list[str]:
    archive = served(launcher.archive, root)
    verb = "Unzip it into" if launcher.extracted else "Copy it to"
    via = " (with PortMaster)" if launcher.archive == PORT_ZIP else ""
    return [
        markup.button(f"Download {launcher.archive}", f"handheld/{launcher.archive}",
                      primary=True) + via,
        "",
        f"- {verb} {launcher.folder_for(system)}.",
        f"- Start it from {launcher.start}.",
        f"- {size_text(archive.size)}. SHA-256: `{archive.sha256}`",
        "",
    ]


APP_LINE = "RetroBIOS also runs on the handheld, with the controller."
# The installer's handheld section opens on the download of every system.
INSTALLER_SECTION = "wiki/installer.md#on-a-handheld-the-retrobios-port"
DETAILS_LINK = f"[Every system's file](../{INSTALLER_SECTION})"


def platform_block(platform: str, root: Path = REPO_ROOT) -> list[str]:
    """The app section of get/<platform>/, empty for a platform no launcher
    runs on."""
    system = next((name for name, key in PLATFORM_OF.items() if key == platform), None)
    if system is None:
        return []
    lines = ["## On the handheld { #on-the-handheld }", "", APP_LINE, ""]
    for launcher in launchers_for(system):
        lines += _launcher_block(launcher, system, root)
    return [*lines, DETAILS_LINK, ""]


def group_page(root: Path = REPO_ROOT) -> str:
    """get/linux-handhelds/: the app for the systems no setup page answers
    for, then the setup pages that carry it for the others."""
    names = group_systems()
    listed = series(names)
    lines = [
        "---", "search: exclude",
        f'description: "The RetroBIOS app for {listed}: the file to put on the card '
        'and the menu that starts it."',
        "---", "",
        f"# {GROUP_TITLE}", "",
        f"{APP_LINE} Each system has its file below.", "",
    ]
    for system in names:
        lines += [f"## {system}", ""]
        for launcher in launchers_for(system):
            lines += _launcher_block(launcher, system, root)
    others = [f"[{name}]({PLATFORM_OF[name]}.md#on-the-handheld)"
              for name in sorted(PLATFORM_OF, key=str.casefold)]
    lines += ["## Other systems", "", f"On {series(others, 'or')}: on its page.", "",
              DETAILS_LINK, ""]
    return "\n".join(lines)
