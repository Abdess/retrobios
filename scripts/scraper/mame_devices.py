"""Device ROM sets of one MAME release, read from its -listxml.

A machine that instantiates a device loads the device's ROMs from
<device shortname>.zip (src/emu/device.cpp:140-152, searchpath), and a missing
ROM that is neither optional nor undumped stops that machine
(src/emu/romload.cpp:529-570, 667-671). The listxml names every such set with
isdevice="yes", its ROMs and the source file defining the device. The lines
cited for a set are the ROM_START block of that file declaring those ROMs, read
at the release tag. A set whose block cannot be told apart is left without
lines and reported.

The same document says which machines load each set, so a set is filed under
the systems of those machines (attribute_systems). It also names the software
lists each machine declares and the floppy drives it can instantiate, which
files hash/<list>.xml (attribute_softlists) and the floppy sound samples
(floppy_sample_systems) the same way.
"""

from __future__ import annotations

import html
import io
import re
import zipfile
from collections.abc import Callable, Collection, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from common import yaml_load

from ._hash_merge import generated_start
from .mame_parser import _collect_rom_macros, _expand_macros, _parse_rom_entries

LISTXML_CHUNK = 8 * 1024 * 1024

_BUILD = re.compile(rb'<mame build="[^"]*\((mame\d+)\)"')
_MACHINE = re.compile(rb'<machine name="([^"]+)"([^>]*)>')
_ATTR = re.compile(rb'(\w+)="([^"]*)"')
_DESCRIPTION = re.compile(rb"<description>(.*?)</description>", re.S)
_BIOSSET = re.compile(rb"<biosset\b([^>]*)>")
_ROM = re.compile(rb"<rom\b([^>]*)>")
_DEVICE_REF = re.compile(rb'<device_ref\b[^>]*\bname="([^"]+)"')
_SLOT_OPTION = re.compile(rb'<slotoption\b[^>]*\bdevname="([^"]+)"')
_SOFTWARE_LIST = re.compile(rb'<softwarelist\b[^>]*\bname="([^"]+)"')

_ROM_START = re.compile(r"ROM_START\s*\(\s*(\w+)\s*\)")
_ROM_END = re.compile(r"\bROM_END\b")
_CRC = re.compile(r"CRC\s*\(\s*([0-9a-fA-F]+)\s*\)")
_COMMENT_OR_LITERAL = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S
)
_ROM_NAME = re.compile(r"\bROM_NAME\s*\(\s*(\w+)\s*\)")
_CLASS_END = re.compile(r"^\};", re.M)

# Why a set carries no line: no block of the file holds its first ROM,
# several remain after every narrowing, or the release lacks the file.
ABSENT = "absent"
AMBIGUOUS = "ambiguous"
NO_FILE = "no file"


def _attrs(raw: bytes) -> dict[str, str]:
    return {
        key.decode(): html.unescape(value.decode())
        for key, value in _ATTR.findall(raw)
    }


def _device_roms(body: bytes) -> list[dict]:
    """Dumped ROMs of one machine element, first of each name kept."""
    bios_names = {
        attrs.get("name", ""): attrs.get("description", "")
        for attrs in map(_attrs, _BIOSSET.findall(body))
    }
    roms: dict[str, dict] = {}
    for match in _ROM.finditer(body):
        attrs = _attrs(match.group(1))
        name, crc = attrs.get("name", ""), attrs.get("crc", "").lower()
        if not name or not crc or name in roms:
            continue
        rom: dict = {
            "name": name,
            "size": int(attrs.get("size", "0") or 0),
            "crc32": crc,
            "sha1": attrs.get("sha1", "").lower(),
        }
        if attrs.get("status") == "baddump":
            rom["bad_dump"] = True
        description = bios_names.get(attrs.get("bios", ""), "")
        if description:
            rom["bios_description"] = description
        roms[name] = rom
    return list(roms.values())


@contextmanager
def open_listxml(path: Path) -> Iterator[io.BufferedIOBase]:
    """Byte stream over a -listxml document, plain or as MAME's release zip."""
    if path.suffix.lower() != ".zip":
        with path.open("rb") as stream:
            yield stream
        return
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.lower().endswith(".xml")]
        if len(names) != 1:
            raise ValueError(f"{path}: expected one .xml member, found {len(names)}")
        with archive.open(names[0]) as stream:
            yield stream


class MachineLinks(NamedTuple):
    """What one listxml element says about the sets it loads.

    *romof* is the parent the element names. *uses* are the devices it can
    instantiate: every subdevice of its default configuration, each device a
    selectable slot option adds, and for a device its parent ROM device,
    whose set the device's ROMs are also searched in. *softlists* are the
    software lists the element declares, *sourcefile* the file defining it.
    """

    romof: str
    isdevice: bool
    uses: tuple[str, ...]
    softlists: tuple[str, ...] = ()
    sourcefile: str = ""


class Release(NamedTuple):
    tag: str
    devices: dict[str, dict]
    machines: dict[str, MachineLinks]


def scan_release(stream: io.BufferedIOBase) -> Release:
    """Release tag, device sets with dumped ROMs and every element's links.

    The document is read through a sliding window, never whole: the 0.289
    listxml is 311 MB. The links are what infoxml.cpp writes: romof is the
    driver's parent (src/frontend/mame/infoxml.cpp:761-765) or a device's
    parent ROM device (856-858), device_ref every subdevice of the default
    configuration (786, 1010-1015), slotoption each selectable card of a
    slot (2129-2172), softwarelist each software list device of the
    configuration (2184-2198). device_t::searchpath puts the parent ROM
    device after the device itself (src/emu/device.cpp:140-152).
    """
    tag = ""
    devices: dict[str, dict] = {}
    machines: dict[str, MachineLinks] = {}
    buffer = b""
    while chunk := stream.read(LISTXML_CHUNK):
        buffer += chunk
        if not tag and (build := _BUILD.search(buffer)):
            tag = build.group(1).decode()
        position = 0
        while match := _MACHINE.search(buffer, position):
            end = buffer.find(b"</machine>", match.end())
            if end == -1:
                break
            name = match.group(1).decode()
            attrs = _attrs(match.group(2))
            body = buffer[match.end() : end]
            isdevice = attrs.get("isdevice") == "yes"
            romof = attrs.get("romof", "")
            uses = {
                ref.decode()
                for ref in (*_DEVICE_REF.findall(body), *_SLOT_OPTION.findall(body))
            }
            if isdevice and romof:
                uses.add(romof)
            uses.discard(name)
            softlists = {found.decode() for found in _SOFTWARE_LIST.findall(body)}
            machines[name] = MachineLinks(
                romof, isdevice, tuple(sorted(uses)), tuple(sorted(softlists)),
                attrs.get("sourcefile", ""),
            )
            if isdevice:
                roms = _device_roms(body)
                if roms:
                    description = _DESCRIPTION.search(body)
                    devices[name] = {
                        "description": html.unescape(description.group(1).decode())
                        if description else "",
                        "sourcefile": attrs.get("sourcefile", ""),
                        "roms": roms,
                    }
            position = end + len(b"</machine>")
        buffer = buffer[position:] if position else buffer[-(2 * LISTXML_CHUNK) :]
    if not tag:
        raise ValueError("no <mame build=...> header: not a MAME -listxml document")
    return Release(tag, devices, machines)


def scan_device_sets(stream: io.BufferedIOBase) -> tuple[str, dict[str, dict]]:
    """Release tag of a -listxml document and its device sets with dumped ROMs."""
    release = scan_release(stream)
    return release.tag, release.devices


def profile_seeds(text: str) -> dict[str, str]:
    """Set name to system, for the bios_zip entries before the generated ones.

    These are the entries a reader wrote, the seeds attribute_systems starts
    from. The generated sections are left out: their systems derive from
    these, and reading them back would carry a previous release's answer
    forward.
    """
    start = generated_start(text)
    written = yaml_load(text if start is None else text[:start]) or {}
    seeds: dict[str, str] = {}
    for entry in written.get("files") or []:
        name = str(entry.get("name") or "")
        if entry.get("category") == "bios_zip" and name.endswith(".zip") and entry.get("system"):
            seeds[name[:-4]] = str(entry["system"])
    return seeds


def _seed_system(
    name: str, machines: dict[str, MachineLinks], seeds: dict[str, str]
) -> str:
    """System a profile entry gives this element, through its romof chain.

    A clone names its parent and a parent its BIOS root set, so a Neo Geo
    game reaches neogeo and takes its system. A device is never walked: its
    romof is a parent ROM device, not the machine it belongs to. The driver
    file decides nothing: one file holds machines of several systems
    (neogeo.cpp declares the MVS and the AES, atari400.cpp the 800 and the
    5200), and filing a machine under the wrong one would take its devices
    away from its own system.
    """
    seen: set[str] = set()
    while name and name not in seen:
        seen.add(name)
        if name in seeds:
            return seeds[name]
        links = machines.get(name)
        if links is None or links.isdevice:
            return ""
        name = links.romof
    return ""


def attribute_systems(
    machines: dict[str, MachineLinks], seeds: dict[str, str]
) -> dict[str, list[str]]:
    """Systems whose machines can load each set.

    *seeds* maps a set name to the system a profile entry states for it.
    Each element _seed_system places passes its system to every device it
    can instantiate, followed through those devices' own links. One walk per
    system, so the cost is the size of the graph times the number of
    systems.
    """
    starts: dict[str, list[str]] = {}
    for name in machines:
        system = _seed_system(name, machines, seeds)
        if system:
            starts.setdefault(system, []).append(name)
    systems: dict[str, set[str]] = {}
    for system, nodes in starts.items():
        seen = set(nodes)
        stack = list(nodes)
        while stack:
            links = machines.get(stack.pop())
            for used in links.uses if links else ():
                if used not in seen:
                    seen.add(used)
                    stack.append(used)
        for name in seen:
            systems.setdefault(name, set()).add(system)
    return {name: sorted(found) for name, found in systems.items()}


def device_systems(
    machines: dict[str, MachineLinks],
    seeds: dict[str, str],
    fallback: str,
) -> dict[str, list[str]]:
    """Systems whose machines can load each set, unplaced machines under *fallback*.

    attribute_systems files a set under the systems of the machines a seed
    places. A machine no seed places (a computer no platform runs through
    this profile, a game outside every BIOS family) still loads its devices,
    and MAME starts it from its set name, the way an arcade folder passes a
    game: it counts as a machine of *fallback*. A set only such machines
    load (an Amiga keyboard, an ISA card) then goes under *fallback* alone,
    and a set both kinds load (ym2413, for the CoCo and for arcade games)
    under both. A set no runnable machine of the release instantiates keeps
    no system: the document never names its machine.
    """
    if not fallback:
        return attribute_systems(machines, seeds)
    unplaced = {
        name: fallback
        for name, links in machines.items()
        if not links.isdevice and not _seed_system(name, machines, seeds)
    }
    return attribute_systems(machines, {**seeds, **unplaced})


def platform_seeds(
    stated: Iterable[tuple[str, str]],
    machines: dict[str, MachineLinks],
    systems: Collection[str],
    written: dict[str, str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Seeds a platform file states, and the sets it states two ways.

    *stated* are (archive name, system) pairs a platform declares. A pair
    seeds a set when the archive is a machine of the release, not a device,
    the system is one the profile lists, and the profile has not written
    the set itself. A set stated under two of the profile's systems seeds
    nothing and is returned with them.
    """
    found: dict[str, set[str]] = {}
    listed = set(systems)
    for archive, system in stated:
        if not archive.endswith(".zip") or system not in listed:
            continue
        name = archive[:-4]
        links = machines.get(name)
        if name in written or links is None or links.isdevice:
            continue
        found.setdefault(name, set()).add(system)
    seeds = {name: next(iter(s)) for name, s in found.items() if len(s) == 1}
    conflicts = {name: sorted(s) for name, s in found.items() if len(s) > 1}
    return seeds, conflicts


def attribute_softlists(
    machines: dict[str, MachineLinks], placed: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Systems whose machines declare each software list.

    *placed* is what attribute_systems returns. A list goes to the systems
    of every element declaring it: a machine writes the lists of its whole
    configuration and a slot card its own (infoxml.cpp:2184-2198).
    software_list_device::parse opens <list>.xml from the hash path
    (src/emu/softlist_dev.cpp:281-313).
    """
    lists: dict[str, set[str]] = {}
    for name, systems in placed.items():
        links = machines.get(name)
        for listed in links.softlists if links else ():
            lists.setdefault(listed, set()).update(systems)
    return {name: sorted(found) for name, found in lists.items()}


# floppy_image_device adds its sound device under this shortname
# (src/devices/imagedev/floppy.cpp:50, 2076-2082).
FLOPPY_SOUND = "flopsnd"

_FORM_FACTOR = re.compile(r"\bm_form_factor\s*=\s*floppy_image::(FF_\w+)")
_SAMPLE_FORM_FACTOR = re.compile(
    r"\bm_default_samples\.set_form_factor\s*\(\s*floppy_image::(FF_\w+)"
    r"|\bm_default_samples\.add_\w+_sample\s*\(\s*\"([^\"]+)\""
)


def default_floppy_samples(text: str) -> dict[str, str]:
    """Each sample of floppy_sound_device's default list, to its form factor.

    The constructor sets a form factor, then adds the samples recorded for
    it (src/devices/imagedev/floppy.cpp:1656-1686).
    """
    body = re.search(
        r"floppy_sound_device::floppy_sound_device\s*\([^)]*\)[^{]*\{(.*?)\n\}",
        blank_comments(text),
        re.S,
    )
    samples: dict[str, str] = {}
    current = ""
    for match in _SAMPLE_FORM_FACTOR.finditer(body.group(1) if body else ""):
        if match.group(1):
            current = match.group(1)
        elif current:
            samples[match.group(2)] = current
    return samples


def drive_form_factor(text: str, shortname: str) -> str:
    """Form factor a floppy drive type sets in setup_characteristics, or ""."""
    text = blank_comments(text)
    declaration = re.search(
        r"DEFINE_DEVICE_TYPE\w*\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*\"" + re.escape(shortname) + '"',
        text,
    )
    if declaration is None:
        return ""
    body = re.search(
        rf"\b{re.escape(declaration.group(1))}::setup_characteristics\s*\(\s*\)\s*\{{(.*?)\n\}}",
        text,
        re.S,
    )
    found = _FORM_FACTOR.search(body.group(1)) if body else None
    return found.group(1) if found else ""


def selected_form_factor(form_factor: str, available: Collection[str]) -> str:
    """The list floppy_sound_samples::select takes for a drive's form factor.

    3" falls back to 3.5", anything else to 5.25", and a form factor no list
    answers takes none (src/devices/imagedev/floppy.cpp:1428-1473).
    """
    while form_factor not in available:
        if form_factor == "FF_3":
            form_factor = "FF_35"
        elif form_factor != "FF_525":
            form_factor = "FF_525"
        else:
            return ""
    return form_factor


def floppy_drives(machines: dict[str, MachineLinks]) -> list[str]:
    """Device types that instantiate the floppy sound device."""
    return sorted(
        name for name, links in machines.items()
        if links.isdevice and FLOPPY_SOUND in links.uses
    )


def floppy_sample_systems(
    machines: dict[str, MachineLinks],
    placed: dict[str, list[str]],
    samples: dict[str, str],
    form_factors: dict[str, str],
) -> dict[str, list[str]]:
    """Systems whose machines load each floppy sound sample.

    Every drive starts a floppy sound device, which loads the default list
    of the form factor its drive selects (floppy.cpp:1709-1738,
    1759-1767). *samples* maps a sample to its form factor
    (default_floppy_samples), *form_factors* a drive to its own
    (drive_form_factor). A drive whose form factor is unknown is taken to
    load every list.
    """
    available = set(samples.values())
    found: dict[str, set[str]] = {}
    for drive in floppy_drives(machines):
        systems = placed.get(drive)
        if not systems:
            continue
        own = form_factors.get(drive, "")
        chosen = {selected_form_factor(own, available)} if own else available
        for sample, form_factor in samples.items():
            if form_factor in chosen:
                found.setdefault(sample, set()).update(systems)
    return {name: sorted(s) for name, s in found.items()}


def source_path(sourcefile: str) -> str:
    """Repository path of a listxml sourcefile.

    The listxml writes device files relative to src/ and driver files
    relative to src/mame/.
    """
    if sourcefile.startswith(("devices/", "emu/", "lib/")):
        return f"src/{sourcefile}"
    return f"src/mame/{sourcefile}"


def blank_comments(text: str) -> str:
    """Text with every comment blanked and its newlines kept.

    Line numbers survive, so a block found in the result is cited at its
    line in the file. A ROM_START written inside a comment is not a block.
    """

    def blank(match: re.Match[str]) -> str:
        found = match.group(0)
        if found[0] in "\"'":
            return found
        return re.sub(r"[^\n]", " ", found)

    return _COMMENT_OR_LITERAL.sub(blank, text)


def rom_region_label(text: str, set_name: str) -> str:
    """ROM_START label the device class of *set_name* returns, or "".

    DEFINE_DEVICE_TYPE names the class right before the quoted shortname, and
    the class's device_rom_region returns ROM_NAME(label), written out of line
    or inside the class body. A class inheriting the method gives nothing.
    """
    declaration = re.search(
        r"DEFINE_DEVICE_TYPE\w*\s*\((?:[^;]*?,)?\s*(\w+)\s*,\s*\"" + re.escape(set_name) + '"',
        text,
    )
    if declaration is None:
        return ""
    cls = re.escape(declaration.group(1))
    method = re.search(rf"\b{cls}::device_rom_region\b[^{{]*\{{([^}}]*)\}}", text)
    if method is None:
        body = re.search(rf"\bclass\s+{cls}\b", text)
        if body is None:
            return ""
        end = _CLASS_END.search(text, body.end())
        scope = text[body.end() : end.start() if end else len(text)]
        method = re.search(r"\bdevice_rom_region\b[^{;]*\{([^}]*)\}", scope)
        if method is None:
            return ""
    label = _ROM_NAME.search(method.group(1))
    return label.group(1) if label else ""


def find_rom_block(
    lines: list[str], set_name: str, roms: list[tuple[str, str]]
) -> tuple[str | None, str]:
    """Lines of the ROM_START block declaring these ROMs, or why there are none.

    The span runs from ROM_START to ROM_END: its label is often not the set
    name, and the ROM_START line alone spells neither the name nor a CRC.

    *roms* are (name, crc32) pairs. A block qualifies when it holds the first
    ROM's CRC, after comments are blanked and the file's ROM macros expanded.
    Several qualifying, the narrowest test that leaves one wins: every ROM by
    name and CRC, then every CRC, then the block named after the set, then the
    block the device class returns from device_rom_region. Two blocks of one
    file can load the same dump under different names, as the Amiga keyboards
    do with their old and new MCU programs.
    """
    text = blank_comments("\n".join(lines))
    macros = _collect_rom_macros(text)
    wanted = {(name, int(crc, 16)) for name, crc in roms}
    crcs = {crc for _name, crc in wanted}
    first = int(roms[0][1], 16)
    blocks: list[tuple[str, str, set[tuple[str, int]], set[int]]] = []
    for start in _ROM_START.finditer(text):
        end = _ROM_END.search(text, start.end())
        if end is None:
            continue
        body = _expand_macros(text[start.end() : end.start()], macros)
        held = {int(crc, 16) for crc in _CRC.findall(body)}
        if first not in held:
            continue
        pairs = {
            (rom["name"], int(rom["crc32"], 16))
            for rom in _parse_rom_entries(body) if rom["crc32"]
        }
        first_line = text.count("\n", 0, start.start()) + 1
        last_line = text.count("\n", 0, end.start()) + 1
        blocks.append((f"{first_line}-{last_line}", start.group(1), pairs, held))
    if not blocks:
        return None, ABSENT
    for narrowed in (
        [b for b in blocks if wanted <= b[2]],
        [b for b in blocks if crcs <= b[3]],
        blocks,
    ):
        if len(narrowed) == 1:
            return narrowed[0][0], ""
        named = [b for b in narrowed if b[1] == set_name]
        if len(named) == 1:
            return named[0][0], ""
        if narrowed:
            label = rom_region_label(text, set_name)
            returned = [b for b in narrowed if label and b[1] == label]
            if len(returned) == 1:
                return returned[0][0], ""
            break
    return None, AMBIGUOUS


def locate_sources(
    devices: dict[str, dict],
    fetch: Callable[[str], list[str] | None],
    workers: int = 8,
) -> dict[str, str]:
    """Write source_file and source_line into each set, return the unplaced.

    *fetch* returns the lines of one repository path at the release, or None
    when the path does not exist there. The result maps each set left without
    a line to the reason.
    """
    paths = sorted({source_path(d["sourcefile"]) for d in devices.values()})
    with ThreadPoolExecutor(max_workers=workers) as pool:
        texts = dict(zip(paths, pool.map(fetch, paths)))
    unplaced: dict[str, str] = {}
    for name, device in sorted(devices.items()):
        path = source_path(device["sourcefile"])
        device["source_file"] = path
        lines = texts[path]
        if lines is None:
            unplaced[name] = NO_FILE
            continue
        line, reason = find_rom_block(
            lines, name, [(rom["name"], rom["crc32"]) for rom in device["roms"]]
        )
        if line is None:
            unplaced[name] = reason
        else:
            device["source_line"] = line
    return unplaced
