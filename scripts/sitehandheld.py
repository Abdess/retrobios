"""The handheld launchers the site serves, and where each one goes.

The four archives scripts/build_port.py writes carry install.py pinned by
SHA-256, so they change with the installer, not with the BIOS packs. The
site builds them from the commit it is built from and serves them under
get/handheld/, beside the bootstraps that pin the same installer
(sitebootstrap.py). build_archive refuses an install.py that install.sh
does not pin: a stale pin stops the site build, the last good archives
staying served.

LAUNCHERS is the one description of where each archive goes on the card
and which menu starts it. The handheld tables of wiki/installer.md are
written from it (scripts/generate_installer_doc.py), and so is the block
each get/<platform>/ page and the handheld page carry.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import sitemarkup as markup
from artifacts import write_bytes_atomic
from build_port import ARCHIVES, BATOCERA_ZIP, MUOS_APP, PORT_ZIP, TOOLS_ZIP, build_archive

REPO_ROOT = Path(__file__).resolve().parent.parent
# Below the site's root: get/handheld/RetroBIOS.zip.
SERVED_DIR = "get/handheld"
# The page of the systems no registered platform answers for. It shares
# its name with the handheld guide (platforms/linux-handhelds.md), so the
# sidebar files it with that guide, as get/batocera.md is with
# platforms/batocera.md.
GROUP_PAGE = "linux-handhelds"
GROUP_TITLE = "RetroBIOS app for handhelds"


@dataclass(frozen=True)
class Launcher:
    """One row of the installer's handheld table.

    *systems* are named as the installer page names them. *copy_to* is
    where the file goes, and *places* gives a system its own folder when
    the row's systems differ there. *lead* opens the row's first cell.
    """

    archive: str
    systems: tuple[str, ...]
    copy_to: str
    start: str
    extracted: bool = False
    lead: str = ""
    places: tuple[tuple[str, tuple[str, ...]], ...] = field(default=())

    def folder_for(self, system: str) -> str:
        return next((folder for folder, systems in self.places if system in systems),
                    self.copy_to)


LAUNCHERS: tuple[Launcher, ...] = (
    Launcher(MUOS_APP, ("muOS",),
             "`ARCHIVE` at the root of the card, then install it from the Archive Manager",
             "Applications"),
    Launcher(PORT_ZIP, ("ArkOS", "dArkOS", "ROCKNIX", "AmberELEC", "JELOS", "KNULLI"),
             "PortMaster's `autoinstall` folder", "Ports, after opening PortMaster once",
             lead="Any other system with [PortMaster](https://portmaster.games/)",
             places=(("`/roms/ports/PortMaster/autoinstall/`", ("ROCKNIX", "AmberELEC")),
                     ("`/roms/tools/PortMaster/autoinstall/`", ("ArkOS",)),
                     ("`/userdata/system/.local/share/PortMaster/autoinstall/`", ("KNULLI",)))),
    Launcher(BATOCERA_ZIP, ("Batocera", "KNULLI"), "`roms/ports` on the SHARE partition",
             "Ports, after updating the game list", extracted=True),
    Launcher(TOOLS_ZIP, ("ArkOS", "dArkOS"), "`tools` on the EASYROMS partition",
             "Options, then Tools", extracted=True),
    Launcher(TOOLS_ZIP, ("ROCKNIX", "JELOS"),
             "`/storage/.config/modules`, over the network share or SSH", "Tools",
             extracted=True),
    Launcher(TOOLS_ZIP, ("AmberELEC",), "`/storage/.config/distribution/modules`", "Tools",
             extracted=True),
)

# The registered platform whose get/ page answers for a system. A system
# outside this map is on the handheld page.
PLATFORM_OF = {"Batocera": "batocera", "KNULLI": "knulli", "ROCKNIX": "rocknix",
               "AmberELEC": "amberelec"}


def systems() -> list[str]:
    """Every system a launcher runs on, in table order."""
    return list(dict.fromkeys(name for launcher in LAUNCHERS for name in launcher.systems))


def group_systems() -> list[str]:
    return [name for name in systems() if name not in PLATFORM_OF]


def joined(names: list[str], last: str = "and") -> str:
    """muOS, ArkOS and JELOS."""
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} {last} {names[-1]}"


def page_of(system: str) -> str:
    """The site page that holds the download for *system*."""
    return f"get/{PLATFORM_OF.get(system, GROUP_PAGE)}.md"


def launchers_for(system: str) -> list[Launcher]:
    """The launchers of *system*, its own menu first and PortMaster last."""
    own = [launcher for launcher in LAUNCHERS if system in launcher.systems]
    return sorted(own, key=lambda launcher: launcher.archive == PORT_ZIP)


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


def table_rows() -> list[str]:
    """The handheld table of the installer page, each system linked to the
    page that holds its download. The page sits in wiki/."""
    def name(system: str) -> str:
        return f"[{system}](../{page_of(system)})"

    rows = ["| System | File | Copy it to | Start it from |",
            "|--------|------|------------|---------------|"]
    for launcher in LAUNCHERS:
        names = ", ".join(name(system) for system in launcher.systems)
        first = f"{launcher.lead}: {names}" if launcher.lead else names
        file = f"`{launcher.archive}`" + (", extracted" if launcher.extracted else "")
        copy_to = launcher.copy_to
        if launcher.places:
            copy_to += ": " + ", ".join(
                f"{folder} on {' and '.join(where)}" for folder, where in launcher.places)
        rows.append(f"| {first} | {file} | {copy_to} | {launcher.start} |")
    return rows


def _anchor(system: str) -> str:
    """Where *system*'s downloads sit on its page."""
    return "on-the-handheld" if system in PLATFORM_OF else system.casefold()


def download_rows() -> list[str]:
    """The short table that opens the installer's handheld section: each
    system, its files as links to the site's copies, and its page. The
    page sits in wiki/."""
    rows = ["| System | Download | Steps |", "|--------|----------|-------|"]
    for system in systems():
        files = ", ".join(
            f"[{launcher.archive}](../{SERVED_DIR}/{launcher.archive})"
            + (" (PortMaster)" if launcher.archive == PORT_ZIP else "")
            for launcher in launchers_for(system))
        page = f"../{page_of(system)}#{_anchor(system)}"
        rows.append(f"| {system} | {files} | [{system} steps]({page}) |")
    return rows


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
        f"- {_size(archive.size)}. SHA-256: `{archive.sha256}`",
        "",
    ]


def _size(count: int) -> str:
    if count >= 1024 * 1024:
        return f"{count / 1024 ** 2:.1f} MB"
    return f"{count / 1024:.0f} KB"


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
    listed = joined(names)
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
    lines += ["## Other systems", "", f"On {joined(others, 'or')}: on its page.", "",
              DETAILS_LINK, ""]
    return "\n".join(lines)
