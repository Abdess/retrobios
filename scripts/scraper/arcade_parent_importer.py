"""Import, per arcade core version, which BIOS set each game set loads.

A game set names its parent through ``romof``: a clone reads its parent game,
and the chain ends at a BIOS set (``neogeo``, ``naomi``, ``pgm``). The archive
the installer has to provide for a game on the card is every BIOS set on that
chain, plus, for the MAME family, the device sets with ROMs the machine
instantiates (``device_ref``), which a split or merged romset reads from their
own archive. The answer is read at the revision the profile pins, from the
DAT of the core version that runs the game where that DAT is the code's own
output, and from the driver code where it is not:

    python -m scripts.scraper.arcade_parent_importer --all
    python -m scripts.scraper.arcade_parent_importer --profile mame2003_plus
    python -m scripts.scraper.arcade_parent_importer --all --offline

A BIOS set is ``isbios="yes"`` (MAME 0.139 and later, FBNeo). mame2000,
mame2003 and mame2003-plus carry a DAT in metadata/ that their code has
moved past (mame2003-plus: 186 compiled sets absent, nbajamex under a BIOS
set the code no longer declares), so they are read from src/driver.c and
src/drivers/: the parent is the GAME macro's PARENT argument and a BIOS set
is flagged NOT_A_DRIVER. Their DAT is still read, to report where it
disagrees. FBNeo's DATs are read one at a time, a console set keyed by its
driver (``msx_1942``): the Arcade, MSX and NES DATs each carry a ``1942``.
flycast keeps its NAOMI and Atomiswave table in code: ``Games[].bios`` names
the BIOS, ``naomi`` when it is null (core/hw/naomi/naomi_cart.cpp:195-197),
and ``BIOS[].filename`` the archive when it differs from the name
(naomi_cart.cpp:75).

Output: games/arcade/<profile>.json. CHD games are listed, not resolved: a
CHD is game content. A ``romof`` pointing outside the sets read is listed
with its target, never guessed. The games that load no BIOS set
(``no_bios``) and every BIOS set (``bios_sets``) are listed too: a set name
on a card that none of the lists holds is one the core does not know.
"""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import json
import re
import sys
import urllib.parse
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from model.database import load_database
from core.artifacts import write_if_changed
from model.profiles import load_emulator_profiles
from core.cli import add_repo_inputs, run_cli
from core.hashing import compute_hashes, git_blob_sha
from core.upstream import parse_repo
from .base_scraper import BlobMismatchError, download, fetch_verified_blob
from .fbneo_parser import zip_name
from .clex import DriverSourceError, blank_comments, call_args, call_span
from .listxml import Opener, attrs, iter_elements, open_listxml, rom_members
from model.mamerelease import mame_tag
from .romset_dat_importer import MAME_LISTXML_URL, _api_json, fetch_pack

SCHEMA_VERSION = 1
DEFAULT_OUTPUT = Path("games") / "arcade"
DEFAULT_CACHE = Path(".cache") / "dats"

# How each profile's DAT is found. "listxml": the -listxml release asset of
# the MAME version core_version names. "fbneo": every DAT of libretro/FBNeo's
# dats/ at source_commit. "repo": files of the profile's source repository at
# source_commit (a ZIP member when the file is an archive). "source": the
# driver code itself at source_commit (src/driver.c and src/drivers/), for the
# cores whose committed DAT contradicts their code; "paths" then names that
# DAT, read only to report where it disagrees. "flycast": the BIOS and Games
# tables of naomi_roms.cpp at source_commit.
PROFILES: dict[str, dict] = {
    "mame": {"kind": "listxml", "marker": "isbios"},
    "mame0258": {"kind": "listxml", "marker": "isbios"},
    "mame0278": {"kind": "listxml", "marker": "isbios"},
    "fbneo": {"kind": "fbneo", "marker": "isbios"},
    "mame2016": {
        "kind": "repo",
        "marker": "isbios",
        "paths": ["metadata/MAME 0.174 Arcade XML DAT.zip", "metadata/MAME 0.174 Home XML DAT.zip"],
    },
    "mame2015": {"kind": "repo", "marker": "isbios", "paths": ["metadata/mame2014-xml.zip"]},
    "mame2010": {"kind": "repo", "marker": "isbios", "paths": ["metadata/mame2010.xml"]},
    "mame2003_plus": {"kind": "source", "marker": "runnable", "paths": ["metadata/mame2003-plus.xml"]},
    "mame2003": {"kind": "source", "marker": "runnable", "paths": ["metadata/mame2003.xml"]},
    "mame2000": {"kind": "source", "marker": "isbios", "paths": ["metadata/MAME 0.37b5 XML.dat"]},
    "flycast": {"kind": "flycast", "paths": ["core/hw/naomi/naomi_roms.cpp"]},
}

# About 95 % of what the pinned DATs gave on 2026-11-03: a build that
# resolves fewer games to a BIOS set has read a DAT of another shape.
FLOORS: dict[str, int] = {
    "mame": 2600,
    "mame0258": 2490,
    "mame0278": 2580,
    "fbneo": 9800,
    "mame2016": 1840,
    "mame2015": 1470,
    "mame2010": 1060,
    "mame2003_plus": 650,
    "mame2003": 420,
    "mame2000": 120,
    "flycast": 330,
}


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


def build_index(
    sets: dict[str, SetEntry], marker: str, archives: dict[str, str] | None = None
) -> dict:
    """BIOS sets per game, device sets per game, CHD games, broken chains.

    A BIOS set none of whose ROMs was dumped is passed over: its archive holds
    nothing, and the loader only warns about a ROM without a dump. *archives*
    names the archive of a set whose name is not its archive's (an FBNeo
    console driver)."""
    archive = (archives or {}).get
    bios_names = {n for n, e in sets.items() if is_bios(e, marker)}
    device_roms = {n for n, e in sets.items() if e.isdevice and e.has_roms}
    games = {
        n: e for n, e in sets.items()
        if n not in bios_names and not e.isdevice and e.runnable and (e.has_roms or e.disks)
    }
    bios: dict[str, set[str]] = {}
    parents: dict[str, set[str]] = {}
    devices: dict[str, set[str]] = {}
    missing: dict[str, str] = {}
    for name, entry in games.items():
        seen = {name}
        current = entry.romof
        while current and current not in seen:
            seen.add(current)
            parent = sets.get(current)
            if parent is None:
                missing[name] = archive(current, current)
                break
            if current in bios_names and parent.has_roms:
                bios.setdefault(archive(current, current), set()).add(name)
            elif current not in bios_names and parent.has_roms:
                # A clone's ROM shared with its parent is looked up in the
                # parent's archive too: MAME's search path is the set and
                # every ancestor (src/emu/driver.cpp:31-38,
                # src/emu/romload.cpp:67-84 at mame0289).
                parents.setdefault(archive(current, current), set()).add(name)
            current = parent.romof
        for device in set(entry.devices) & device_roms:
            devices.setdefault(device, set()).add(name)
    with_bios = {g for members in bios.values() for g in members}
    # The source file of each game and device set: what a launcher that
    # starts whatever set a folder holds selects a folder's machines by
    # (ES-DE runs MAME on any CPS-2 set of roms/cps2).
    sources: dict[str, set[str]] = {}
    for name, entry in sets.items():
        if entry.source and (name in games or name in device_roms):
            sources.setdefault(entry.source, set()).add(archive(name, name))
    return {
        "bios": {k: sorted(v) for k, v in sorted(bios.items())},
        "parents": {k: sorted(v) for k, v in sorted(parents.items())},
        "devices": {k: sorted(v) for k, v in sorted(devices.items())},
        "chd": sorted(n for n, e in games.items() if e.disks),
        "missing_parents": dict(sorted(missing.items())),
        "no_bios": sorted(set(games) - with_bios - set(missing)),
        "bios_sets": sorted(bios_names),
        **({"sources": {k: sorted(v) for k, v in sorted(sources.items())}} if sources else {}),
        "counts": {
            "sets": len(sets),
            "games": len(games),
            "games_with_bios": len(with_bios),
            "bios_sets": len(bios_names),
            "bios_roots_used": len(bios),
            "games_with_devices": len({g for v in devices.values() for g in v}),
            "chd_games": sum(1 for e in games.values() if e.disks),
            "missing_parents": len(missing),
        },
    }


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


# --- MAME 0.37 and 0.78 driver source (mame2000, mame2003, mame2003-plus) ----

# driver.h at each pin: NAME is argument 1 and PARENT argument 2 in every
# form, and a BIOS set carries NOT_A_DRIVER in its flags.
_GAME_MACRO = re.compile(r"\b(GAME|GAMEX|GAMEC|GAMECX|GAMEB|GAMEBX)\s*\(")
_DRIVER_ENTRY = re.compile(r"\bDRIVER\s*\(\s*(\w+)\s*\)")
_ROM_START = re.compile(r"\bROM_START\s*\(\s*(\w+)\s*\)(.*?)\bROM_END\b", re.S)
_ROM_LOAD = re.compile(r"\bROMX?_LOAD\w*\s*\(")
_DISK_IMAGE = re.compile(r"\bDISK_IMAGE\w*\s*\(")
_ROM_START_HEAD = re.compile(r"\bROM_START\s*\(")
_DIRECTIVE = re.compile(r"^[ \t]*#[ \t]*(\w+)[ \t]*(.*)$")
_MACRO_HEAD = re.compile(r"(\w+)(\([^)]*\))?[ \t]*(.*)")
_CONDITION_TOKEN = re.compile(
    r"\s*(?:(0[xX][0-9a-fA-F]+|\d+)[uUlL]*|(defined)|([A-Za-z_]\w*)"
    r"|(&&|\|\||==|!=|<=|>=|<<|>>|[!<>()+\-*/%~&|^]))"
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
_INCLUDE = re.compile(r'"([^"]+)"')


def _condition_value(expr: str, defines: dict[str, str], depth: int = 0) -> int:
    """An ``#if`` expression the way the C preprocessor reads it: a name not
    defined is 0, a defined name is its value."""
    python: list[str] = []
    position = 0
    expr = expr.strip()
    while position < len(expr):
        match = _CONDITION_TOKEN.match(expr, position)
        if not match:
            raise DriverSourceError(f"#if {expr}: cannot read")
        number, defined, name, operator = match.groups()
        position = match.end()
        if number:
            python.append(str(int(number, 0)))
        elif defined:
            target = re.match(r"\s*\(?\s*(\w+)\s*\)?", expr[position:])
            if not target:
                raise DriverSourceError(f"#if {expr}: defined without a name")
            python.append("1" if target.group(1) in defines else "0")
            position += target.end()
        elif name:
            value = defines.get(name, "0").strip() or "1"
            if depth > 8:
                raise DriverSourceError(f"#if {expr}: {name} does not resolve")
            python.append(str(_condition_value(value, defines, depth + 1)))
        else:
            python.append(
                {"&&": " and ", "||": " or ", "!": " not ", "/": "//"}.get(operator, operator)
            )
    try:
        return int(_arithmetic(ast.parse("".join(python).strip(), mode="eval").body))
    except (SyntaxError, ZeroDivisionError, TypeError) as exc:
        raise DriverSourceError(f"#if {expr}: {exc}") from exc


_BINARY = {
    ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b, ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b, ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b, ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b, ast.BitXor: lambda a, b: a ^ b,
}
_COMPARE = {
    ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
}


def _arithmetic(node: ast.AST) -> int:
    """Integer arithmetic of an ``#if``, nothing else evaluated."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp):
        value = _arithmetic(node.operand)
        if isinstance(node.op, ast.Not):
            return int(not value)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.Invert):
            return ~value
    if isinstance(node, ast.BoolOp):
        values = [_arithmetic(v) for v in node.values]
        return int(all(values) if isinstance(node.op, ast.And) else any(values))
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        return _BINARY[type(node.op)](_arithmetic(node.left), _arithmetic(node.right))
    if isinstance(node, ast.Compare):
        left = _arithmetic(node.left)
        for op, right_node in zip(node.ops, node.comparators):
            right = _arithmetic(right_node)
            if type(op) not in _COMPARE or not _COMPARE[type(op)](left, right):
                return 0
            left = right
        return 1
    raise TypeError(f"{type(node).__name__} in a condition")


class _Preprocessor:
    """Conditional compilation over src/, enough to tell which GAME and
    ROM_START a build compiles. Headers are read for their definitions."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers
        self._by_basename: dict[str, list[str]] = {}
        for path in headers:
            self._by_basename.setdefault(path.rsplit("/", 1)[-1], []).append(path)

    def _resolve(self, name: str, including: str) -> str | None:
        folder = including.rsplit("/", 1)[0]
        for candidate in (f"{folder}/{name}", f"src/{name}", f"src/includes/{name}"):
            if candidate in self.headers:
                return candidate
        found = self._by_basename.get(name.rsplit("/", 1)[-1], [])
        return found[0] if len(found) == 1 else None

    def run(
        self, path: str, text: str, defines: dict[str, str],
        local: dict[str, tuple[list[str] | None, str]] | None, seen: set[str],
    ) -> str:
        text = blank_comments(text, keep_lines=False).replace("\\\r\n", " ").replace("\\\n", " ")
        out: list[str] = []
        # Each level: (enclosing level active, a branch already taken, this branch active).
        stack: list[tuple[bool, bool, bool]] = []
        active = True
        for line in text.splitlines():
            directive = _DIRECTIVE.match(line)
            if not directive:
                if active:
                    out.append(line)
                continue
            word, rest = directive.groups()
            if word in _CONDITIONALS:
                active = _branch(path, word, rest, defines, stack, active)
            elif active:
                self._define(path, word, rest, defines, local, seen)
        if stack:
            raise DriverSourceError(f"{path}: #if without #endif")
        return "\n".join(out)

    def _define(
        self, path: str, word: str, rest: str, defines: dict[str, str],
        local: dict[str, tuple[list[str] | None, str]] | None, seen: set[str],
    ) -> None:
        """#define, #undef and #include in an active region."""
        if word == "define":
            head = _MACRO_HEAD.match(rest)
            if head:
                defines[head.group(1)] = head.group(3)
                if local is not None:
                    params = head.group(2)
                    local[head.group(1)] = (
                        [a.strip() for a in params[1:-1].split(",")] if params else None,
                        head.group(3),
                    )
        elif word == "undef":
            defines.pop(rest.strip(), None)
        elif word == "include":
            target = _INCLUDE.match(rest)
            header = self._resolve(target.group(1), path) if target else None
            if header and header not in seen:
                seen.add(header)
                self.run(header, self.headers[header], defines, None, seen)


_CONDITIONALS = frozenset({"if", "ifdef", "ifndef", "elif", "else", "endif"})


def _branch(
    path: str, word: str, rest: str, defines: dict[str, str],
    stack: list[tuple[bool, bool, bool]], active: bool,
) -> bool:
    """Apply one conditional directive to *stack*. Returns the new active state."""
    if word in ("if", "ifdef", "ifndef"):
        if not active:
            stack.append((False, True, False))
            return active
        if word == "if":
            value = bool(_condition_value(rest, defines))
        else:
            value = (rest.split()[0] in defines) == (word == "ifdef")
        stack.append((True, value, value))
        return value
    if word in ("elif", "else"):
        if not stack:
            raise DriverSourceError(f"{path}: #{word} without #if")
        outer, taken, _ = stack[-1]
        value = (
            outer and not taken
            and (word == "else" or bool(_condition_value(rest, defines)))
        )
        stack[-1] = (outer, taken or value, value)
        return value
    if not stack:
        raise DriverSourceError(f"{path}: #endif without #if")
    stack.pop()
    return stack[-1][2] if stack else True


def _dumped(args: list[str]) -> bool:
    """A ROM_LOAD whose ROM was dumped: 0.78 writes ``NO_DUMP`` in the hash
    argument, 0.37 a zero CRC."""
    if any("NO_DUMP" in a for a in args):
        return False
    crc = args[3] if len(args) > 3 else ""
    return not re.fullmatch(r"0[xX]0+|0", crc.strip())


def _argument(values: dict[str, str], match: re.Match[str]) -> str:
    return values.get(match.group(0), match.group(0))


def _expand_declarations(text: str, local: dict[str, tuple[list[str] | None, str]]) -> str:
    """Calls of a file's own function-like macros that write a ROM_START or a
    GAME line, expanded (pgm.c builds every DoDonPachi II set through
    ``DDP2_SET(name, program, asic)``)."""
    writers = {
        name: (params, body)
        for name, (params, body) in local.items()
        if params is not None and (_ROM_START_HEAD.search(body) or _GAME_MACRO.search(body))
    }
    if not writers:
        return text
    call = re.compile(r"\b(" + "|".join(map(re.escape, writers)) + r")\s*\(")
    out: list[str] = []
    position = 0
    for match in call.finditer(text):
        if match.start() < position:
            continue
        params, body = writers[match.group(1)]
        args, end = call_span(text, match.end())
        if len(args) != len(params):
            raise DriverSourceError(f"{match.group(1)} called with {len(args)} arguments")
        values = dict(zip(params, args))
        out.append(text[position : match.start()])
        out.append(_IDENTIFIER.sub(functools.partial(_argument, values), body))
        position = end
    out.append(text[position:])
    return "".join(out)


def compiled_drivers(driver_c: str, preprocessor: _Preprocessor) -> list[str]:
    """The DRIVER() entries driver.c compiles into the driver list."""
    # driver.c is read twice by the build, the second time with
    # DRIVER_RECURSIVE defined: that pass is the list.
    text = preprocessor.run(
        "src/driver.c", driver_c, {"DRIVER_RECURSIVE": "", "DRIVER": ""}, None, set()
    )
    return [n for n in _DRIVER_ENTRY.findall(text) if n != "NAME"]


def _holds_roms(
    body: str, local: dict[str, tuple[list[str] | None, str]], known: dict[str, bool],
    seen: frozenset[str] = frozenset(),
) -> bool:
    for match in _ROM_LOAD.finditer(body):
        if _dumped(call_args(body, match.end())):
            return True
    # A ROM list shared through a macro of the same file (a BIOS
    # block every game of the board pulls in).
    for word in set(_IDENTIFIER.findall(body)) - seen:
        if word in local:
            if word not in known:
                known[word] = _holds_roms(local[word][1], local, known, seen | {word})
            if known[word]:
                return True
    return False


def _read_driver(
    path: str, source: str, preprocessor: _Preprocessor,
    declared: dict[str, tuple[str | None, bool]], roms: dict[str, tuple[bool, bool]],
) -> None:
    """The ROM_START blocks and GAME declarations of one driver file."""
    local: dict[str, tuple[list[str] | None, str]] = {}
    text = _expand_declarations(preprocessor.run(path, source, {}, local, set()), local)
    known: dict[str, bool] = {}
    for match in _ROM_START.finditer(text):
        body = match.group(2)
        roms.setdefault(
            match.group(1), (_holds_roms(body, local, known), bool(_DISK_IMAGE.search(body)))
        )
    for match in _GAME_MACRO.finditer(text):
        args = call_args(text, match.end())
        if len(args) < 9:
            raise DriverSourceError(f"{path}: {match.group(1)} with {len(args)} arguments")
        name, parent = args[1], args[2]
        if name in declared:
            raise DriverSourceError(f"{path}: {name} declared twice")
        declared[name] = (
            None if parent == "0" else parent,
            any("NOT_A_DRIVER" in a for a in args[3:]),
        )


def driver_source_sets(
    driver_c: str, drivers: dict[str, str], headers: dict[str, str]
) -> dict[str, SetEntry]:
    """Every compiled set and every set on its parent chain, from the source.

    *drivers* maps each path under src/drivers/ to its text and *headers*
    every header under src/. A set is declared by a GAME-family macro whose
    ROMs are ``ROM_START(name)``, and a set flagged ``NOT_A_DRIVER`` is a BIOS
    set, the flag the 0.37 and 0.78 info.c use to tell a resource from a game.
    """
    preprocessor = _Preprocessor(headers)
    declared: dict[str, tuple[str | None, bool]] = {}
    roms: dict[str, tuple[bool, bool]] = {}
    for path, source in sorted(drivers.items()):
        _read_driver(path, source, preprocessor, declared, roms)
    compiled = compiled_drivers(driver_c, preprocessor)
    undeclared = [n for n in compiled if n not in declared]
    if undeclared:
        raise DriverSourceError(f"driver.c lists undeclared sets: {', '.join(undeclared[:10])}")
    sets: dict[str, SetEntry] = {}
    pending = list(compiled)
    while pending:
        name = pending.pop()
        if name in sets or name not in declared:
            continue
        parent, bios = declared[name]
        has_roms, disks = roms.get(name, (False, False))
        sets[name] = SetEntry(
            name=name, romof=parent, isbios=bios, runnable=not bios,
            has_roms=has_roms, disks=disks,
        )
        if parent:
            pending.append(parent)
    return sets


def git_tree_sha(entries: dict[str, tuple[str, str]]) -> str:
    """The sha git gives a directory, from ``{path: (mode, blob sha)}`` of
    every file under it, paths relative to it."""
    children: dict[str, dict[str, tuple[str, str]]] = {}
    rows: list[tuple[str, str, str]] = []
    for path, (mode, sha) in entries.items():
        head, sep, tail = path.partition("/")
        if sep:
            children.setdefault(head, {})[tail] = (mode, sha)
        else:
            rows.append((head, mode, sha))
    rows += [(name, "40000", git_tree_sha(sub)) for name, sub in children.items()]
    # git orders a tree by name, a directory compared as if it ended in "/".
    rows.sort(key=lambda row: row[0].encode() + (b"/" if row[1] == "40000" else b""))
    body = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)
        for name, mode, sha in rows
    )
    return hashlib.sha1(f"tree {len(body)}\0".encode() + body).hexdigest()


@dataclass
class DriverSource:
    """What the reader needs from src/ at one commit, and the tree sha of
    src/ computed from every file of it."""

    driver_c: str
    drivers: dict[str, str]
    headers: dict[str, str]
    tree: str


def read_driver_source(tarball: Path) -> DriverSource:
    """src/ of a GitHub tarball: the texts the reader needs, and the git
    tree sha of the whole directory."""
    import tarfile

    entries: dict[str, tuple[str, str]] = {}
    texts: dict[str, str] = {}
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive:
            parts = member.name.split("/", 1)
            if len(parts) < 2 or not parts[1].startswith("src/"):
                continue
            path = parts[1]
            if member.issym():
                entries[path[4:]] = ("120000", git_blob_sha(member.linkname.encode()))
            elif member.isfile():
                handle = archive.extractfile(member)
                data = handle.read() if handle else b""
                mode = "100755" if member.mode & 0o111 else "100644"
                entries[path[4:]] = (mode, git_blob_sha(data))
                if path == "src/driver.c" or path.endswith(".h") or (
                    path.startswith("src/drivers/") and path.endswith(".c")
                ):
                    texts[path] = data.decode("latin-1")
    if "src/driver.c" not in texts:
        raise FileNotFoundError(f"{tarball} has no src/driver.c")
    return DriverSource(
        driver_c=texts["src/driver.c"],
        drivers={p: t for p, t in texts.items() if p.startswith("src/drivers/") and p.endswith(".c")},
        headers={p: t for p, t in texts.items() if p.endswith(".h")},
        tree=git_tree_sha(entries),
    )


def fetch_driver_source(
    slug: str, commit: str, cache_dir: Path, offline: bool = False
) -> DriverSource:
    """src/ at a commit, its tree sha checked against the repository's own
    when online."""
    tarball = cache_dir / "src" / slug / f"{commit}.tar.gz"
    if offline:
        if not tarball.is_file():
            raise FileNotFoundError(f"{tarball} is not cached")
    else:
        download(f"https://codeload.github.com/{slug}/tar.gz/{commit}", tarball,
                 skip_existing=True)
    source = read_driver_source(tarball)
    if not offline:
        listing = _api_json(f"https://api.github.com/repos/{slug}/git/trees/{commit}")
        listed = next(
            (
                item.get("sha")
                for item in (listing.get("tree", []) if isinstance(listing, dict) else [])
                if item.get("path") == "src"
            ),
            None,
        )
        if listed != source.tree:
            tarball.unlink()
            raise BlobMismatchError(f"{slug}@{commit[:8]}:src is tree {listed}, not {source.tree}")
    return source


def dat_gaps(code: dict[str, SetEntry], dat: dict[str, SetEntry], marker: str) -> dict:
    """Where the DAT a repository carries contradicts its own code."""
    both = code.keys() & dat.keys()
    return {
        "code_only": sorted(code.keys() - dat.keys()),
        "dat_only": sorted(dat.keys() - code.keys()),
        "romof": sorted(n for n in both if code[n].romof != dat[n].romof),
        "bios": sorted(n for n in both if is_bios(code[n], marker) != is_bios(dat[n], marker)),
    }


def _dat_cross_check(
    spec: dict, slug: str, commit: str, cache_dir: Path, offline: bool,
    code: dict[str, SetEntry],
) -> dict | None:
    """dat_gaps against the DAT the repository carries, None when the DAT
    is not cached and the run is offline."""
    paths: list[Path] = []
    for path in spec.get("paths", []):
        try:
            local, _ = (
                _cached_repo_file(slug, commit, path, cache_dir)
                if offline
                else fetch_repo_file(slug, commit, path, cache_dir)
            )
        except FileNotFoundError:
            if offline:
                return None
            raise
        paths.append(local)
    if not paths:
        return None
    dat = read_sets([opener for p in paths for opener in _xml_streams(p)])
    return dat_gaps(code, dat, spec["marker"])


# --- Fetching ----------------------------------------------------------------


def _repo_slug(url: str) -> str:
    """owner/name of the GitHub repository a profile's source names."""
    repo = parse_repo(url)
    if repo is None or repo.family != "github":
        raise ValueError(f"not a GitHub repository URL: {url}")
    return repo.slug


def fetch_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """One file of a GitHub repository at a commit, checked against the blob
    sha the repository lists for it, and that sha."""
    folder, _, name = path.rpartition("/")
    listing = _api_json(
        f"https://api.github.com/repos/{slug}/contents/{urllib.parse.quote(folder)}?ref={commit}"
    )
    item = next(
        (i for i in listing if isinstance(i, dict) and i.get("name") == name), None
    ) if isinstance(listing, list) else None
    if item is None:
        raise FileNotFoundError(f"{slug}@{commit[:8]} has no {path}")
    url = (
        f"https://raw.githubusercontent.com/{slug}/{commit}/"
        f"{urllib.parse.quote(path)}"
    )
    destination = fetch_verified_blob(url, cache_dir / "repo" / slug / commit / path, item["sha"])
    return destination, item["sha"]


def _cached_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """The cached copy, offline. Its blob sha is recomputed from the bytes."""
    destination = cache_dir / "repo" / slug / commit / path
    if not destination.is_file():
        raise FileNotFoundError(f"{slug}@{commit[:8]}:{path} is not in {cache_dir}")
    return destination, git_blob_sha(destination.read_bytes())


def _file_opener(path: Path) -> Opener:
    return lambda: path.open("rb")


def _xml_streams(path: Path) -> Iterator[Opener]:
    """Openers for the XML documents a file holds: itself, or each XML or
    DAT member of a ZIP."""
    if path.suffix.lower() != ".zip":
        yield lambda: path.open("rb")
        return
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            n for n in archive.namelist() if n.lower().endswith((".xml", ".dat"))
        )
    for member in names:
        def opener(member: str = member) -> IO[bytes]:
            # The member keeps the archive alive: its shared file closes
            # through the archive's own _fpclose.
            return zipfile.ZipFile(path).open(member)

        yield opener


def read_sets(openers: list[Opener]) -> dict[str, SetEntry]:
    """Every set of several documents. A set read twice keeps its first
    reading: FBNeo's Arcade and Neogeo DATs both carry the neogeo BIOS."""
    sets: dict[str, SetEntry] = {}
    for opener in openers:
        with opener() as stream:
            for entry in iter_sets(stream):
                if entry.name:
                    sets.setdefault(entry.name, entry)
    return sets


def import_profile(
    profile: str, data: dict, cache_dir: Path, offline: bool = False,
    report: dict | None = None,
) -> dict:
    """The index document for one profile, from the DAT or the code its pin
    names. *report* receives, for a profile read from its code, where the DAT
    the repository carries disagrees with that code."""
    spec = PROFILES[profile]
    commit = str(data.get("source_commit") or "")
    source_url = str(data.get("source") or "")
    kind = spec["kind"]
    source: dict[str, object]
    openers: list[Opener]
    if kind == "listxml":
        tag = mame_tag(str(data["core_version"]))
        if offline:
            pack = cache_dir / f"{tag}lx.zip"
            if not pack.is_file():
                raise FileNotFoundError(f"{pack} is not cached")
        else:
            pack, _ = fetch_pack("mame", tag, cache_dir)
        source = {
            "release": f"mamedev/mame {tag}",
            "url": MAME_LISTXML_URL.format(tag=tag),
            "sha256": compute_hashes(pack, frozenset({"sha256"}), cache=False)["sha256"],
        }
        index = build_index(read_sets([lambda: open_listxml(pack)]), spec["marker"])
    elif kind == "fbneo":
        if offline:
            folder = cache_dir / "fbneo-dats"
            blobs = {p.name: git_blob_sha(p.read_bytes()) for p in sorted(folder.glob("*.dat"))}
            if not blobs:
                raise FileNotFoundError(f"{folder} is not cached")
        else:
            folder, blobs = fetch_pack("fbneo", commit, cache_dir)
        slug = _repo_slug(source_url)
        listing, listing_sha = (
            _cached_repo_file(slug, commit, FBNEO_DRIVERLIST, cache_dir)
            if offline
            else fetch_repo_file(slug, commit, FBNEO_DRIVERLIST, cache_dir)
        )
        source = {
            "repo": source_url,
            "commit": commit,
            "files": {
                **{f"dats/{name}": sha for name, sha in sorted(blobs.items())},
                FBNEO_DRIVERLIST: listing_sha,
            },
        }
        openers = [_file_opener(folder / name) for name in sorted(blobs)]
        sets, archives = fbneo_sets(openers, fbneo_drivers(listing.read_text(encoding="utf-8")))
        index = build_index(sets, spec["marker"], archives)
    elif kind == "source":
        slug = _repo_slug(source_url)
        tree = fetch_driver_source(slug, commit, cache_dir, offline)
        sets = driver_source_sets(tree.driver_c, tree.drivers, tree.headers)
        source = {"repo": source_url, "commit": commit, "files": {"src": tree.tree}}
        index = build_index(sets, spec["marker"])
        if report is not None:
            report["dat_gaps"] = _dat_cross_check(spec, slug, commit, cache_dir, offline, sets)
    else:
        slug = _repo_slug(source_url)
        files: dict[str, str] = {}
        paths: list[Path] = []
        for path in spec["paths"]:
            local, sha = (
                _cached_repo_file(slug, commit, path, cache_dir)
                if offline
                else fetch_repo_file(slug, commit, path, cache_dir)
            )
            files[path] = sha
            paths.append(local)
        source = {"repo": source_url, "commit": commit, "files": files}
        if kind == "flycast":
            index = flycast_index(paths[0].read_text(encoding="utf-8"))
        else:
            openers = [opener for p in paths for opener in _xml_streams(p)]
            index = build_index(read_sets(openers), spec["marker"])
    return {
        "schema": SCHEMA_VERSION,
        "profile": profile,
        "core_version": data.get("core_version"),
        "source": source,
        **index,
    }


# --- Checks against the collection -------------------------------------------


def declared_archives(profile: dict) -> set[str]:
    """Archive names a profile declares, lowercased: file names, aliases and
    the archive a member lives in."""
    names: set[str] = set()
    for entry in profile.get("files") or []:
        for value in [entry.get("name"), entry.get("archive"), *(entry.get("aliases") or [])]:
            if isinstance(value, str) and value:
                names.add(value.rsplit("/", 1)[-1].lower())
    return names


def collection_names(database: str) -> set[str]:
    db = load_database(database)
    return {n.lower() for n in db.get("indexes", {}).get("by_name", {})}


def bios_roots(doc: dict) -> list[str]:
    return sorted(doc["bios"])


def dump(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--profile", action="append", choices=sorted(PROFILES),
                       help="profile to import (repeatable)")
    which.add_argument("--all", action="store_true", help="every profile with an arcade source")
    add_repo_inputs(parser, "emulators", "db")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help=f"where the parent maps are written (default {DEFAULT_OUTPUT})")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE,
                        help=f"downloaded DATs and sources (default {DEFAULT_CACHE})")
    parser.add_argument("--offline", action="store_true", help="read the download cache only")
    parser.add_argument("--dry-run", action="store_true", help="print coverage, write nothing")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    names = collection_names(args.db)
    failed = False
    for profile in sorted(PROFILES) if args.all else args.profile:
        if profile not in profiles:
            print(f"FAIL {profile}: no emulators/{profile}.yml", file=sys.stderr)
            failed = True
            continue
        try:
            report: dict = {}
            doc = import_profile(
                profile, profiles[profile], args.cache_dir, args.offline, report
            )
        except (OSError, ValueError, KeyError) as exc:
            print(f"FAIL {profile}: {exc}", file=sys.stderr)
            failed = True
            continue
        counts = doc["counts"]
        roots = bios_roots(doc)
        declared = declared_archives(profiles[profile])
        undeclared = [r for r in roots if f"{r}.zip" not in declared]
        absent = [r for r in roots if f"{r}.zip" not in names]
        print(
            f"{profile}: {counts['games']} games, {counts['games_with_bios']} with a BIOS set, "
            f"{counts['bios_roots_used']} BIOS sets used, "
            f"{counts['games_with_devices']} with device sets, {counts['chd_games']} CHD, "
            f"{counts['missing_parents']} parents absent"
        )
        if PROFILES[profile]["kind"] == "source":
            gaps = report.get("dat_gaps")
            if gaps is None:
                print("  read from the code, the committed DAT is not cached for the cross-check")
            else:
                print(
                    f"  read from the code, the committed DAT disagrees: "
                    f"{len(gaps['code_only'])} sets only in the code, "
                    f"{len(gaps['dat_only'])} only in the DAT, "
                    f"{len(gaps['romof'])} parents and {len(gaps['bios'])} BIOS flags differ"
                )
                for key in ("dat_only", "romof", "bios"):
                    if gaps[key]:
                        print(f"    {key}: {', '.join(gaps[key][:20])}")
        if absent:
            print(f"  BIOS sets absent from the collection: {', '.join(absent)}")
        if undeclared:
            print(f"  BIOS sets the profile does not declare: {', '.join(undeclared)}")
        floor = FLOORS.get(profile, 0)
        if counts["games_with_bios"] < floor:
            print(
                f"FAIL {profile}: {counts['games_with_bios']} games with a BIOS set, "
                f"floor {floor}",
                file=sys.stderr,
            )
            failed = True
            continue
        if not args.dry_run:
            target = args.output_dir / f"{profile}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            if write_if_changed(str(target), dump(doc)):
                print(f"  wrote {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    run_cli(main)
