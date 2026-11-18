"""Trees of bios/ addressed by path, which deduplication leaves alone."""

from __future__ import annotations

from pathlib import Path


# Directories where deduplication must NOT be applied.
NODEDUP_DIRS = {
    "RPG Maker",
    "ScummVM",
    # A zoneinfo tree is addressed by zone name and its aliases are equal
    # files by design: US/Samoa is Pacific/Midway.
    "tzdata",
    # VICE data is addressed by machine directory: C64, C64DTV and SCPU64
    # share one keymap, C64 and CBM-II one palette. With the copies removed
    # the name step served the C128 keymap to all of them.
    "c64-emu",
    # PinMAME reads a sound-only parent (gts80s) as its own archive, equal
    # byte for byte to the base set. Folding them into the clone map would
    # key gts1.zip twice, once for MAME's set and once for PinMAME's.
    "PinMAME",
    # BBK dictionary ROMs are addressed by model directory, and the OS ROM
    # the A4988 folder needs is the one the gam4980 core is given.
    "BBK",
    # Engine data trees read by path: one sound or one sprite sits under
    # several characters, campaigns or episodes, and each copy is opened
    # where it lies.
    "C-Dogs SDL",
    "Ikemen GO",
    "Theme Hospital",
    "TheXTech",
    # Aleph One opens each scenario's Physics Models and the Splitwolf mod
    # tree its sounds and maps by path: Marathon 2 and Infinity share one
    # Standard.phyA, lwmp/ repeats 182 files across its levels.
    "Bungie",
    "splitwolf",
    # CatacombGL reads each game's folder by name and compares sizes only:
    # the Armageddon and Apocalypse intro shapes SHP1, SHP9 to SHP13 are the
    # Abyss shareware bytes under the retail names, and each game opens
    # its own copy.
    "Softdisk",
    # MAME's support trees (hash, plugins) are read by path as a whole, and
    # two MAME versions share most of their software lists byte for byte.
    "mame",
    # The Tyrian 2.1 distribution ships netset.pcx and tyrset.pcx with the
    # same bytes, and EmuELEC places both names under ports/opentyrian/.
    "opentyrian",
}


def in_nodedup_dir(path: str) -> bool:
    parts = Path(path).parts
    return any(nodedup in parts for nodedup in NODEDUP_DIRS)
