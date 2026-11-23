"""The systems index."""

from __future__ import annotations

from model.collection import SECTION_LABELS, profiles_on_disk, manufacturer_slug
from model.composition import GAME_DATA_TOPS
from model.profiles import is_emulator
from sitegen import starlight as sitestarlight
from sitegen.render import count_text
from sitegen.runlinks import console_href
from sitegen.startwith import section_label


def _console_display(manufacturer: str, console: str) -> str:
    """A console section's name as the reader looks for it: the heading
    system_name gives its id, or the folder alone under a program's top
    (Other, Arcade), where "Other mame" would name nothing."""
    from model.collection import PROGRAM_TOPS
    from model.systemnames import heading_name

    return console if manufacturer in PROGRAM_TOPS else heading_name(manufacturer, console)


def generate_systems_index(manufacturers: dict) -> str:
    """Every console in one table, found by its own name.

    The index listed 74 manufacturers and no console: someone looking for
    PlayStation had to know it is filed under Sony, and Other hid 91
    sections. Manufacturer pages stay the containers.
    """
    for old, new in SYSTEM_PAGES_MOVED.items():
        sitestarlight.MOVED_PAGES.setdefault(old, new)
    total_mfr = len(manufacturers)
    total_consoles = sum(len(c) for c in manufacturers.values())
    # A copy filed under two folders appears on both pages, counted once here.
    total_files = len({
        f.get("sha1") for consoles in manufacturers.values()
        for files in consoles.values() for f in files
    })

    lines = [
        "# Systems",
        "",
        "Every BIOS file the collection holds, by console. Open a console to "
        "see each file, the emulators that read it and the setups that list it.",
        "",
        f"{count_text(total_consoles, 'console')}, {count_text(total_files, 'file')} in the "
        f"repository, from {count_text(total_mfr, 'manufacturer')}.",
        "",
    ]

    # Other holds one folder per emulator: a7800 or altirra in the console
    # table named no console. Arcade boards are neither consoles nor
    # computers, and the crumb of their page says Arcade too.
    def kind(mfr: str) -> str:
        if mfr in GAME_DATA_TOPS:
            return "games"
        if mfr == "Arcade":
            return "arcade"
        return "programs" if mfr == "Other" else "consoles"

    for heading, group, first, note in (
        ("Consoles and computers", "consoles", "Console", ""),
        ("Arcade", "arcade", "Name",
         "Arcade boards, and the sets each arcade emulator family reads."),
        ("Emulator folders", "programs", "Folder",
         "Files kept under the emulator that reads them, not under a console."),
        ("Game engines and PC games", "games", "Name",
         "Game engines and PC games hold the files a game engine reads, such "
         "as the data of a game, rather than the BIOS of a machine."),
    ):
        rows = sorted(
            ((folder_emulator(console)[0] if group == "programs"
              else section_label(mfr, console) if mfr == "Arcade"
              or (mfr, console) in SECTION_LABELS
              else _console_display(mfr, console), mfr, console, len(files))
             for mfr, consoles in manufacturers.items() if kind(mfr) == group
             for console, files in consoles.items()),
            key=lambda row: (row[0].casefold(), row[1].casefold(), row[2]),
        )
        if not rows:
            continue
        lines += [f"## {heading}", ""]
        if note:
            lines += [note, ""]
        if group == "programs":
            # Each folder by the emulator's name, linked to its page: the
            # rows read a7800 and azaharplus beside console names, and
            # every maker cell said Other.
            lines += ["| Emulator | Files |", "|---------|------:|"]
            for name, mfr, console, count in rows:
                href = console_href(manufacturer_slug(mfr), console).removeprefix("systems/")
                key = folder_emulator(console)[1]
                cell = name.replace("|", "-")
                cell = f"[{cell}](../emulators/{key}.md)" if key else cell
                lines.append(f"| {cell} | [{count_text(count, 'file')}]({href}) |")
            lines.append("")
            continue
        lines += [
            # The count before the maker: on a phone the last column is
            # the one scrolled off, and most names carry the maker already.
            f"| {first} | Files | Maker |",
            "|---------|------:|-------|",
        ]
        for name, mfr, console, count in rows:
            cell = name.replace("|", "-")
            href = console_href(manufacturer_slug(mfr), console).removeprefix("systems/")
            lines.append(f"| [{cell}]({href}) | {count:,} | [{mfr}]({manufacturer_slug(mfr)}.md) |")
        lines.append("")

    return "\n".join(lines) + "\n"


def folder_emulator(folder: str) -> tuple[str, str]:
    """The display name and profile of the emulator a folder under Other is
    named after, by its profile key or its name, else the folder and "".
    """
    profiles = profiles_on_disk()
    if folder in profiles and is_emulator(profiles[folder]):
        return str(profiles[folder].get("emulator") or folder), folder
    for key in sorted(profiles):
        profile = profiles[key]
        if not is_emulator(profile):
            continue
        names = {str(profile.get(field) or "").casefold() for field in ("emulator", "display_name")}
        if folder.casefold() in names:
            return str(profile.get("emulator") or key), key
    return folder, ""


# System pages published under an address no page holds since, and where
# their files went: the Atom and the MZ were boards, ScummVM's and SDLPAL's
# files were on two pages, the Dreamcast lost its NAOMI sets. An address
# redirects only while no page takes it back (sitestarlight.redirects).
SYSTEM_PAGES_MOVED = {
    "systems/arcade-acorn-atom.md": "systems/acorn.md",
    "systems/arcade-sharp-mz-2000.md": "systems/sharp.md",
    "systems/arcade-sharp-mz-2500.md": "systems/sharp.md",
    "systems/arcade-miuchiz.md": "systems/arcade.md",
    "systems/arcade-yamaha-ym2608.md": "systems/arcade.md",
    # Oric is filed under its maker since 2026-10-23, and a reader still
    # followed the old address to the 404 page.
    "systems/oric.md": "systems/tangerine.md#oric",
    "systems/other-scummvm.md": "systems/scummvm.md",
    "systems/other-sdlpal.md": "systems/sdlpal.md",
    "systems/sega-dreamcast.md": "systems/sega.md",
}
