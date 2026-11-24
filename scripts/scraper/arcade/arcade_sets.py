"""Game sets and their BIOS parents as a DAT, FBNeo's driver list and flycast's table declare them."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import IO

from .clex import blank_comments
from .fbneo_parser import zip_name
from ..dats.listxml import Opener, attrs, iter_elements, rom_members


@dataclass
class SetEntry:
    """What the index needs from one machine or game element."""

    name: str
    romof: str | None = None
    isbios: bool = False
    isdevice: bool = False
    runnable: bool = True
    has_roms: bool = False
    disks: bool = False
    devices: list[str] = field(default_factory=list)
    source: str | None = None


_DEVICE_REF = re.compile(rb'<device_ref\b[^>]*\bname="([^"]+)"')
_DISK = re.compile(rb"<disk\b([^>]*)>")


def iter_sets(stream: IO[bytes]) -> Iterator[SetEntry]:
    """Every machine or game element of a DAT or -listxml, streamed."""
    for element in iter_elements(stream, ("machine", "game")):
        found, body = element.attrs, element.body
        disks = [attrs(d) for d in _DISK.findall(body)]
        yield SetEntry(
            name=found.get("name", ""),
            romof=found.get("romof") or None,
            isbios=found.get("isbios") == "yes",
            isdevice=found.get("isdevice") == "yes",
            runnable=found.get("runnable", "yes") != "no",
            has_roms=bool(rom_members(body)),
            disks=any(d.get("status") != "nodump" for d in disks),
            devices=[d.decode() for d in _DEVICE_REF.findall(body)],
            source=found.get("sourcefile"),
        )


def is_bios(entry: SetEntry, marker: str) -> bool:
    if entry.isbios:
        return True
    return marker == "runnable" and not entry.runnable and not entry.isdevice


# --- FBNeo: one namespace per DAT ---------------------------------------------

# Generated at build time from every driver and committed: the set name and the
# source file of each driver.
FBNEO_DRIVERLIST = "src/dep/generated/driverlist.h"
_FBNEO_DRIVER = re.compile(r'\{\s*"([^"]+)",\s*"([^"]+\.cpp)"\s*\}')


def fbneo_drivers(listing: str) -> dict[str, set[str]]:
    """Driver names per source file, from driverlist.h."""
    names: dict[str, set[str]] = {}
    for name, path in _FBNEO_DRIVER.findall(listing):
        names.setdefault(path, set()).add(name)
    if not names:
        raise ValueError(f"{FBNEO_DRIVERLIST} lists no driver")
    return names


def _fbneo_candidates(entry: SetEntry, names: dict[str, set[str]]) -> list[str]:
    """The drivers a DAT set can be. A console DAT writes the archive name,
    which the driver's GetZipName() takes by cutting the system prefix:
    ``1942`` in the MSX DAT is the driver ``msx_1942``."""
    drivers = names.get(entry.source or "", set())
    if entry.name in drivers:
        return [entry.name]
    return sorted(n for n in drivers if "_" in n and zip_name(n) == entry.name)


def _fbneo_driver_names(entries: list[SetEntry], names: dict[str, set[str]]) -> dict[str, str]:
    """Driver name per set of one DAT. Where a source file holds two systems
    (d_nes.cpp builds the NES and the FDS drivers), the prefix the rest of
    the DAT carries decides."""
    candidates = {e.name: _fbneo_candidates(e, names) for e in entries}
    prefixes = Counter(
        found[0].split("_", 1)[0]
        for name, found in candidates.items()
        if len(found) == 1 and found[0] != name
    )
    driver: dict[str, str] = {}
    for entry in entries:
        found = candidates[entry.name]
        if len(found) > 1 and prefixes:
            dominant = prefixes.most_common(1)[0][0]
            found = [n for n in found if n.split("_", 1)[0] == dominant]
        if len(found) != 1:
            raise ValueError(f"{entry.source}: {entry.name} matches drivers {found}")
        driver[entry.name] = found[0]
    return driver


def fbneo_sets(
    openers: list[Opener], names: dict[str, set[str]]
) -> tuple[dict[str, SetEntry], dict[str, str]]:
    """Every set of FBNeo's DATs keyed by its driver, and the archive of each
    set whose driver name is not its archive name.

    Each DAT is its own namespace: the Arcade, MSX, NES and ZX Spectrum DATs
    all carry a ``1942``, and a ``romof`` inside a DAT names a set of that DAT.
    Merged by archive name, the MSX ``1942`` that needs msx.zip was the
    arcade one, which needs nothing. The Arcade and Neo Geo DATs both carry
    the Neo Geo drivers: a driver read twice keeps its first reading.
    """
    sets: dict[str, SetEntry] = {}
    archives: dict[str, str] = {}
    for opener in openers:
        with opener() as stream:
            entries = [e for e in iter_sets(stream) if e.name]
        driver = _fbneo_driver_names(entries, names)
        for entry in entries:
            name = driver[entry.name]
            if name in sets:
                continue
            if name != entry.name:
                archives[name] = entry.name
            if entry.romof:
                entry.romof = driver.get(entry.romof, entry.romof)
            entry.name = name
            sets[name] = entry
    return sets, archives


# --- C table reader (flycast naomi_roms.cpp) ---------------------------------

_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|[{},]|[^\s{},"]+')


def _initializer(text: str, array: str) -> list:
    """The brace initializer of ``const <type> <array>[] = {...}`` as nested
    lists of tokens, each element split on its top-level commas."""
    match = re.search(rf"\b{re.escape(array)}\s*\[\s*\]\s*=\s*\{{", text)
    if not match:
        raise ValueError(f"no initializer for {array}[]")
    tokens = _TOKEN.findall(text[match.end() - 1 :])
    stack: list[list] = []
    item: list = []
    for token in tokens:
        if token == "{":
            stack.append(item)
            item = []
            stack.append([])
        elif token == "}":
            elements = stack.pop()
            if item:
                elements.append(item if len(item) > 1 else item[0])
            item = stack.pop()
            item.append(elements)
            if not stack:
                return item[0]
        elif token == ",":
            elements = stack[-1]
            if item:
                elements.append(item if len(item) > 1 else item[0])
            item = []
        else:
            item.append(token)
    raise ValueError(f"unterminated initializer for {array}[]")


def _string(token: object) -> str | None:
    if isinstance(token, str) and token.startswith('"'):
        return token[1:-1]
    return None


def flycast_index(source: str) -> dict:
    """BIOS archive per NAOMI/Atomiswave game from naomi_roms.cpp."""
    text = blank_comments(source)
    archive_of: dict[str, str] = {}
    for element in _initializer(text, "BIOS"):
        if not isinstance(element, list) or not element:
            continue
        name = _string(element[0])
        if name is None:
            continue
        # BIOS_t: name, blobs[], filename (naomi_roms.h:53-66).
        filename = _string(element[2]) if len(element) > 2 else None
        archive_of[name] = filename or name
    bios: dict[str, set[str]] = {}
    chd: list[str] = []
    unknown: dict[str, str] = {}
    games: set[str] = set()
    for element in _initializer(text, "Games"):
        if not isinstance(element, list) or not element:
            continue
        name = _string(element[0])
        if name is None:
            continue
        # shors2k2 is declared twice at e88b0ced: a name counts once.
        games.add(name)
        # Game: name, parent_name, description, size, key, bios, cart_type,
        # rotation, blobs[], gdrom_name, ... (naomi_roms.h:71-94).
        named = _string(element[5]) if len(element) > 5 else None
        if named is not None and named not in archive_of:
            unknown[name] = named
            continue
        bios.setdefault(archive_of[named or "naomi"], set()).add(name)
        if len(element) > 9 and _string(element[9]):
            chd.append(name)
    return {
        "bios": {k: sorted(v) for k, v in sorted(bios.items())},
        "devices": {},
        "chd": sorted(chd),
        "missing_parents": dict(sorted(unknown.items())),
        "no_bios": [],
        "bios_sets": sorted(set(archive_of.values())),
        "counts": {
            "sets": len(games) + len(archive_of),
            "games": len(games),
            "games_with_bios": len({g for v in bios.values() for g in v}),
            "bios_sets": len(archive_of),
            "bios_roots_used": len(bios),
            "games_with_devices": 0,
            "chd_games": len(chd),
            "missing_parents": len(unknown),
        },
    }
