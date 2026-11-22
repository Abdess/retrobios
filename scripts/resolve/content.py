"""The content tests a code runs on a candidate: size, Adler-32, ROMDIR, masked SHA-1, hashes."""

from __future__ import annotations

import functools
import hashlib
import json
import os
from collections.abc import Collection
from typing import TYPE_CHECKING, TypedDict

from core.hashing import compute_hashes
from core.ziptools import check_inside_zip
from model.profiles import CONTENT_CHECKS

if TYPE_CHECKING:
    from typing_extensions import Unpack


def parse_validation(validation: list | dict | None) -> list[str]:
    """Extract the validation check list from a file's validation field.

    Handles both simple list and divergent (core/upstream) dict forms.
    For dicts, uses the ``core`` key since RetroArch users run the core.
    """
    if validation is None:
        return []
    if isinstance(validation, list):
        return validation
    if isinstance(validation, dict):
        return validation.get("core", [])
    return []


def name_match_size_ok(file_entry: dict, candidate_size: int | None) -> bool:
    """Whether a candidate found by name may be the file the entry describes.

    Generic filenames collide across systems: rom1.bin is a Sony PlayStation 2
    firmware and a Roland SC-55mk2 program ROM. A name carries no evidence on
    its own, so a size the emulator verifies settles it. A size declared
    without ``validation: [size]`` is informative and rejects nothing.
    """
    if "size" not in parse_validation(file_entry.get("validation")) or candidate_size is None:
        return True
    return size_fits(file_entry, candidate_size)


def adler32_of(path: str, byteswap: bool = False) -> str:
    """The Adler-32 of a file, over its 16-bit words swapped when asked.

    Dolphin swaps every 16-bit word of its DSP ROMs before hashing them
    (Common::swap16 in DSPLLE.cpp:LoadDSPRom).
    """
    import struct
    import zlib

    with open(path, "rb") as f:
        data = f.read()
    if byteswap:
        if len(data) % 2:
            data += b"\x00"
        count = len(data) // 2
        data = struct.pack(f">{count}H", *struct.unpack(f"<{count}H", data))
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")


def _adler32_value(value: object) -> str:
    return str(value).lower().removeprefix("0x")


def _held_adler32(name: str, db: dict, byteswap: bool) -> set[str]:
    """The Adler-32 of every copy of a name the collection holds."""
    files_db = db.get("files", {})
    held: set[str] = set()
    for sha1 in db.get("indexes", {}).get("by_name", {}).get(name, []):
        path = files_db.get(sha1, {}).get("path", "")
        try:
            held.add(adler32_of(path, byteswap))
        except OSError:
            continue
    return held


def held_adler32_pair(file_entry: dict, db: dict) -> str | None:
    """The entry's own value in the first pair its code accepts that is held.

    Dolphin hashes dsp_rom.bin and dsp_coef.bin together and warns on any
    combination outside its table: two files each accepted alone can still
    be a pair it refuses. ``adler32_pairs`` lists the accepted pairs, the
    entry's own value first, in the code's table order. Both members walk
    the same pairs over the same collection, so they settle on one pair.
    None when the entry declares no pair or none is held whole.
    """
    pairs = file_entry.get("adler32_pairs")
    partner = file_entry.get("adler32_pairs_with")
    if not pairs or not partner:
        return None
    byteswap = bool(file_entry.get("adler32_byteswap"))
    own = _held_adler32(file_entry.get("name", ""), db, byteswap)
    other = _held_adler32(partner, db, byteswap)
    for mine, theirs in pairs:
        if _adler32_value(mine) in own and _adler32_value(theirs) in other:
            return _adler32_value(mine)
    return None


def adler32_fits(file_entry: dict, path: str, db: dict | None = None) -> bool:
    """Whether a candidate carries an Adler-32 the entry's code accepts.

    Dolphin hashes its DSP ROMs and warns on every pair it does not take
    as current: the v0.3.1 free dsp_rom.bin is answered by its path, and
    shipped beside the official dsp_coef.bin it is a pair Dolphin rejects.
    A value declared without ``validation: [adler32]`` rejects nothing.
    With the collection at hand, a candidate outside the held pair the
    code accepts (``held_adler32_pair``) is refused too.
    """
    declared = file_entry.get("known_hash_adler32")
    if "adler32" not in parse_validation(file_entry.get("validation")) or not declared:
        return True
    values = declared if isinstance(declared, list) else [declared]
    accepted = {_adler32_value(v) for v in values}
    try:
        actual = adler32_of(path, bool(file_entry.get("adler32_byteswap")))
    except OSError:
        return False
    if actual not in accepted:
        return False
    chosen = held_adler32_pair(file_entry, db) if db is not None else None
    return chosen is None or actual == chosen


def declared_content_checks(file_entry: dict) -> set[str]:
    """The content tests the entry's code runs on a candidate."""
    return set(CONTENT_CHECKS.intersection(parse_validation(file_entry.get("validation"))))


@functools.lru_cache(maxsize=4096)
def _romdir_verdict(path: str, size: int, mtime_ns: int, spec: str) -> bool:
    from core.romdir import romdir_accepts

    with open(path, "rb") as f:
        data = f.read()
    return romdir_accepts(data, json.loads(spec))


@functools.lru_cache(maxsize=4096)
def _masked_sha1_verdict(path: str, size: int, mtime_ns: int, spec: str) -> bool:
    """Amiberry's flash image identification (getromdatabydata, rommgr.cpp).

    A CyberStorm or Blizzard PPC image carries its board configuration in
    bytes 0x10-0x2f, so the table SHA-1 is taken with those bytes cleared,
    over the first 0x1c000 bytes, and for a 512 KB file also over the
    first 0x50000. ``reads`` lists the file sizes the code tries the
    transform on and the lengths it hashes for each.
    """
    rules = json.loads(spec)
    reads = {int(r["size"]): [int(n) for n in r["lengths"]] for r in rules.get("reads", [])}
    if size not in reads:
        return False
    with open(path, "rb") as f:
        data = bytearray(f.read())
    start, end = (int(v) for v in rules.get("zeroed", [0, 0]))
    data[start:end] = bytes(max(0, min(end, len(data)) - start))
    wanted = str(rules.get("sha1", "")).lower()
    return any(hashlib.sha1(data[:length]).hexdigest() == wanted for length in reads[size])


def content_fits(file_entry: dict, path: str) -> bool:
    """Whether a candidate passes the content tests its entry declares.

    The PCSX2 family lists any file of its BIOS folder whose ROM directory
    holds RESET and ROMVER (LoadBiosVersion, pcsx2/ps2/BiosTools.cpp), with
    no name and, in most forks, no size: ``validation: [romdir]`` and the
    ``romdir:`` spec of how that fork reads the table (romdir.py). Amiberry
    names a flash image by the SHA-1 of its bytes with the configuration
    cleared (``masked_sha1``). A file that cannot be read fails. An entry
    declaring no content test accepts every candidate.
    """
    checks = declared_content_checks(file_entry)
    if not checks:
        return True
    try:
        stat = os.stat(path)
    except OSError:
        return False
    verdicts = {"romdir": _romdir_verdict, "masked_sha1": _masked_sha1_verdict}
    for check in sorted(checks):
        spec = json.dumps(file_entry.get(check) or {}, sort_keys=True)
        try:
            if not verdicts[check](path, stat.st_size, stat.st_mtime_ns, spec):
                return False
        except OSError:
            return False
    return True


def shape_fits(file_entry: dict, path: str, size: int | None = None) -> bool:
    """Size and content together: what a scan by shape checks per candidate."""
    if size is None:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
    return size_fits(file_entry, size) and content_fits(file_entry, path)


def declares_shape(file_entry: dict) -> bool:
    """Whether the entry says anything that tells one candidate from another."""
    return bool(
        file_entry.get("size") or file_entry.get("min_size")
        or file_entry.get("max_size") or file_entry.get("size_multiple")
        or declared_content_checks(file_entry)
    )


def size_fits(file_entry: dict, candidate_size: int) -> bool:
    """Whether a size is one the entry declares (size_refusal)."""
    return size_refusal(file_entry, candidate_size) is None


def size_refusal(file_entry: dict, candidate_size: int) -> str | None:
    """Why the entry's declared sizes turn a size away, or None.

    ``size`` is the exact size, or the list of sizes, the code accepts.
    A ``min_size``/``max_size`` window declared beside it is accepted too:
    LinApple's sector image probe takes 143105 to 143364 bytes plus two
    lone values (SectorDiskImage.cpp), and a 1 MB BS-X dump sits inside the
    32 KB floor MesenCE checks. ``size_multiple`` is a granule a size inside
    the window must be a whole number of, as xemu maps any flash image whose
    size is a positive multiple of 64 KiB (hw/xbox/xbox.c). Nothing declared
    fits all.
    """
    declared = file_entry.get("size")
    allowed = [] if declared is None else declared if isinstance(declared, list) else [declared]
    if candidate_size in allowed:
        return None
    low = file_entry.get("min_size")
    high = file_entry.get("max_size")
    multiple = file_entry.get("size_multiple")
    if low is None and high is None and not multiple:
        if not allowed:
            return None
        accepted = ",".join(str(s) for s in sorted(allowed))
        return f"size mismatch: got {candidate_size}, accepted [{accepted}]"
    exact = f" or [{','.join(str(s) for s in sorted(allowed))}]" if allowed else ""
    if low is not None and candidate_size < low:
        return f"size too small: min {low}{exact}, got {candidate_size}"
    if high is not None and candidate_size > high:
        return f"size too large: max {high}{exact}, got {candidate_size}"
    if multiple and candidate_size % int(multiple):
        return f"size mismatch: got {candidate_size}, accepted multiples of {multiple}{exact}"
    return None


class DeclaredHashes(TypedDict):
    """What an entry declares about its content, as declared_hash_verdict reads it."""

    has_strong_hash: bool
    sha1_candidates: Collection[str]
    sha256_candidates: Collection[str]
    md5_list: list[str]
    crc_candidates: Collection[str]
    zipped_file: str | None
    declared_size: int | list[int] | None


def declared_hash_verdict(
    candidate: str,
    *,
    file_entry: dict | None = None,
    db: dict | None = None,
    **declared: Unpack[DeclaredHashes],
) -> str:
    """Judge a candidate found by name against everything the entry declares.

    A file reached through a directory walk was matched on its filename,
    which is the weakest evidence there is. Whatever the entry declares
    about its content is checked here before the walk may return it,
    including the size and Adler-32 the name steps over bios/ apply.
    """
    sha1_candidates = declared["sha1_candidates"]
    sha256_candidates = declared["sha256_candidates"]
    md5_list = declared["md5_list"]
    crc_candidates = declared["crc_candidates"]
    zipped_file = declared["zipped_file"]
    declared_size = declared["declared_size"]
    if not declared["has_strong_hash"]:
        if file_entry is not None and not (
            name_match_size_ok(file_entry, os.path.getsize(candidate))
            and adler32_fits(file_entry, candidate, db)
            and content_fits(file_entry, candidate)
        ):
            return "hash_mismatch"
        return "data_dir"
    algorithms: set[str] = set()
    if sha1_candidates:
        algorithms.add("sha1")
    if sha256_candidates:
        algorithms.add("sha256")
    if md5_list and not zipped_file:
        algorithms.add("md5")
    if crc_candidates:
        algorithms.add("crc32")
    actual = compute_hashes(candidate, frozenset(algorithms)) if algorithms else {}
    if sha1_candidates and actual.get("sha1", "").lower() not in sha1_candidates:
        return "hash_mismatch"
    if sha256_candidates and actual.get("sha256", "").lower() not in sha256_candidates:
        return "hash_mismatch"
    if md5_list and not zipped_file and not any(
        actual.get("md5", "").lower().startswith(expected) for expected in md5_list
    ):
        return "hash_mismatch"
    if crc_candidates and actual.get("crc32", "").lower() not in crc_candidates:
        return "hash_mismatch"
    if crc_candidates and declared_size is not None:
        allowed_sizes = declared_size if isinstance(declared_size, list) else [declared_size]
        if os.path.getsize(candidate) not in allowed_sizes:
            return "hash_mismatch"
    if zipped_file and md5_list and not any(
        check_inside_zip(candidate, zipped_file, expected) == "ok"
        for expected in md5_list
    ):
        return "hash_mismatch"
    return "data_dir_hash_exact"


def record_answers_declaration(
    record: dict, file_entry: dict, declared: dict[str, list[str]],
) -> bool:
    """Whether a database record carries what declared_hash_verdict asks of the bytes.

    The same rules read without the file: with no hash declared, a size
    counts only under ``validation: [size]``, an md5 matches by prefix and
    is skipped beside a zipped_file, a crc32 is bounded by the declared
    size. What only the bytes tell (the ROM inside a zipped_file, Adler-32,
    content tests) is left to declared_hash_verdict once they are there.
    """
    size = record.get("size")
    if not declared:
        return name_match_size_ok(file_entry, size if isinstance(size, int) else None)

    def field(name: str) -> str:
        return str(record.get(name, "")).lower()

    if "sha1" in declared and field("sha1") not in declared["sha1"]:
        return False
    if "sha256" in declared and field("sha256") not in declared["sha256"]:
        return False
    if "md5" in declared and not file_entry.get("zipped_file") and not any(
        field("md5").startswith(expected) for expected in declared["md5"]
    ):
        return False
    if "crc32" in declared:
        if field("crc32") not in declared["crc32"]:
            return False
        declared_size = file_entry.get("size")
        if declared_size is not None:
            allowed = declared_size if isinstance(declared_size, list) else [declared_size]
            if size not in allowed:
                return False
    return True
