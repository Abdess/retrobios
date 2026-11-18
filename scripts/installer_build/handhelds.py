"""Where each handheld launcher archive goes on the card, and which menu starts it.

LAUNCHERS is the one description of it. The handheld tables of wiki/installer.md are
written from it (installer_build/installerdoc.py), and so is the block each
get/<platform>/ page and the handheld page carry (sitegen/handheld.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from installer_build.port import BATOCERA_ZIP, MUOS_APP, PORT_ZIP, TOOLS_ZIP


# Below the site's root: get/handheld/RetroBIOS.zip.
SERVED_DIR = "get/handheld"
# The page of the systems no registered platform answers for. It shares
# its name with the handheld guide (platforms/linux-handhelds.md), so the
# sidebar files it with that guide, as get/batocera.md is with
# platforms/batocera.md.
GROUP_PAGE = "linux-handhelds"


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


def page_of(system: str) -> str:
    """The site page that holds the download for *system*."""
    return f"get/{PLATFORM_OF.get(system, GROUP_PAGE)}.md"


def launchers_for(system: str) -> list[Launcher]:
    """The launchers of *system*, its own menu first and PortMaster last."""
    own = [launcher for launcher in LAUNCHERS if system in launcher.systems]
    return sorted(own, key=lambda launcher: launcher.archive == PORT_ZIP)


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
