"""The PS2 ROM directory test the PCSX2 family runs on every BIOS candidate.

A BIOS image starts with a table of 16-byte entries (a 10-byte name, a
16-bit extended info size, a 32-bit file size) whose first entry is RESET.
``LoadBiosVersion`` (pcsx2/ps2/BiosTools.cpp) reads the file 16 bytes at a
time from its start until an entry named RESET, then walks the table from
there, adding up the entry sizes rounded to 16 bytes to find where each
file of the ROM lies, and reads the 14 bytes of ROMVER at its offset. The
image is a BIOS when the walk met ROMVER.

The forks differ in how they compare the names and in what an unreadable
read does, so a profile declares how its code reads the table (``romdir:``
on the entry) and ``romdir_accepts`` runs that same walk. Stdlib only:
install.py carries a copy of the walk.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ENTRY_SIZE = 16
NAME_SIZE = 10
# for (i = 0; i < 512 * 1024; i++) in every LoadBiosVersion.
SEARCH_ENTRIES = 512 * 1024
ROMVER_SIZE = 14
EXTINFO_SIZE = 15

# What a read the code cannot complete does, by fork.
REJECT = "rejects"     # wxWidgets streams throw (pxStreams.cpp, EndOfStream)
ENDS_WALK = "ends_walk"  # the walk breaks, the result stands
IGNORED = "ignored"    # AetherSX2 zero-fills romver and counts it found

SPEC_KEYS = frozenset({
    "reset_compare", "missing_reset", "terminated_names", "extinfo", "unreadable_romver",
    "truncated_walk", "offset_width", "refused_serials", "zones", "refused_zones",
})


@dataclass(frozen=True)
class Romdir:
    """What a walk that met ROMVER read: its 14 bytes and the EXTINFO serial."""

    romver: bytes
    serial: str


def _name_is(name: bytes, wanted: bytes, compared: int) -> bool:
    """strncmp(name, wanted, compared) == 0 over a 10-byte field."""
    a = name[:compared]
    b = (wanted + b"\x00")[:compared]
    for x, y in zip(a, b.ljust(len(a), b"\x00")):
        if x != y:
            return False
        if x == 0:
            return True
    return True


def walk(data: bytes, spec: dict) -> Romdir | None:
    """The ROM directory walk one fork's LoadBiosVersion runs, or None.

    ``reset_compare`` is the length strncmp compares RESET over: 5 in the
    wxWidgets and AetherSX2 code, which takes any name starting with RESET,
    sizeof(fileName) (10) after, which wants RESET and a NUL.
    ``terminated_names`` stops the walk at a name with no NUL in its 10
    bytes (strnlen check of the later code). ``missing_reset`` says what
    512 Ki entries read without RESET do: ``rejects`` where the code throws
    (wxWidgets), ``ends_walk`` where the loop just ends and the walk starts
    at the last entry read. ``extinfo`` reads 15 bytes at
    the EXTINFO offset + 0x10 and ends the walk when they are not there.
    ``unreadable_romver`` and ``truncated_walk`` say what a ROMVER read and
    a next-entry read past the end of the file do: ``rejects``,
    ``ends_walk`` or, for ROMVER, ``ignored``. ``offset_width`` is the
    width of the offset sum: 32 where it is a uint (wxWidgets code), 64
    where it is an s64.
    """
    size = len(data)
    reset_compare = int(spec.get("reset_compare", NAME_SIZE))
    terminated = bool(spec.get("terminated_names", True))
    extinfo = bool(spec.get("extinfo", True))
    unreadable = spec.get("unreadable_romver", ENDS_WALK)
    truncated = spec.get("truncated_walk", ENDS_WALK)
    missing_reset = spec.get("missing_reset", ENDS_WALK)
    offset_mask = (1 << int(spec.get("offset_width", 64))) - 1

    pos = 0
    for _ in range(SEARCH_ENTRIES):
        if pos + ENTRY_SIZE > size:
            return None
        name = data[pos:pos + NAME_SIZE]
        pos += ENTRY_SIZE
        if _name_is(name, b"RESET", reset_compare):
            break
    else:
        if missing_reset == REJECT:
            return None

    entry = data[pos - ENTRY_SIZE:pos]
    offset = 0
    romver: bytes | None = None
    serial = ""
    while True:
        name = entry[:NAME_SIZE]
        if name[0] == 0 or (terminated and b"\x00" not in name):
            break
        if extinfo and _name_is(name, b"EXTINFO", NAME_SIZE):
            start = offset + 0x10
            if start + EXTINFO_SIZE > size:
                break
            serial = data[start:start + EXTINFO_SIZE].split(b"\x00", 1)[0].decode("latin-1")
        if _name_is(name, b"ROMVER", NAME_SIZE):
            if offset + ROMVER_SIZE > size:
                if unreadable == REJECT:
                    return None
                if unreadable == ENDS_WALK:
                    break
                romver = bytes(ROMVER_SIZE)
            else:
                romver = data[offset:offset + ROMVER_SIZE]
        (file_size,) = struct.unpack_from("<I", entry, 12)
        offset += file_size if file_size % 0x10 == 0 else (file_size + 0x10) & 0xFFFFFFF0
        offset &= offset_mask
        if pos + ENTRY_SIZE > size:
            if truncated == REJECT:
                return None
            break
        entry = data[pos:pos + ENTRY_SIZE]
        pos += ENTRY_SIZE
    if romver is None:
        return None
    return Romdir(romver, serial)


def zone_code(romver: bytes) -> str:
    """The zone characters LoadBiosVersion switches on: ROMVER[4], and [5]
    where the code reads it to tell COH-H (T then Z) from T10K."""
    return romver[4:6].decode("latin-1")


def romdir_accepts(data: bytes, spec: dict) -> bool:
    """Whether a candidate passes the profile's ROM directory test.

    Past the walk, ``refused_serials`` turns away an EXTINFO serial
    (ARMSX2's NOT_PS2_BIOS_STAMPS), and ``zones``/``refused_zones`` keep or
    drop an image by its ROMVER zone, as a scan that wants a COH-H board
    or passes one over does. A zone is written as the code tests it: ``J``
    is ROMVER[4], ``TZ`` ROMVER[4] and [5].
    """
    found = walk(data, spec)
    if found is None:
        return False
    if found.serial in set(spec.get("refused_serials") or ()):
        return False
    code = zone_code(found.romver)

    def matches(zones: list | None) -> bool:
        return any(code.startswith(str(z)) for z in zones or ())

    if spec.get("zones") and not matches(spec["zones"]):
        return False
    return not matches(spec.get("refused_zones"))
