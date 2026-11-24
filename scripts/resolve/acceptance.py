"""The verdict on a held file: the variant a check accepts, the frontend digest, the choice among owners."""

from __future__ import annotations

import os
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, TypedDict

from core.hashing import compute_hashes, lists_hashes, md5_composite, parse_hash_list
from core.paths import BIOS_DIR
from core.ziptools import check_inside_zip, check_inside_zip_data
from model.database import records_for_hash
from resolve.content import content_fits, declared_content_checks, name_match_size_ok, shape_fits
from resolve.nativemode import SIZE_AND_ANY_HASH, digest_algorithm, hash_mismatch_excludes_file
from resolve.validation import Refusal, check_file_validation

if TYPE_CHECKING:
    from typing_extensions import Unpack


def _platform_accepted(file_entry: dict, platform_digest: str) -> set[str]:
    """The values of the digest the frontend compares that the entry declares."""
    declared = file_entry.get(platform_digest) or ""
    if platform_digest == "md5":
        return set(parse_hash_list(declared))
    if isinstance(declared, str) and declared:
        return {declared.lower()}
    if isinstance(declared, list):
        return {str(value).lower() for value in declared}
    return set()


def _variant_candidates(expected: dict, db: dict, fname: str) -> Iterator[str]:
    """The sha1 of each held file that may stand for a name, best evidence first.

    Any one accepted value names a candidate: the index merges what several
    emulators accept, and their own checks then judge each file.
    """
    # Sorted: the index holds sets, whose order follows the per-process
    # string hash, and the first passing candidate is the one shipped.
    for hash_type in ("sha1", "md5", "crc32", "sha256"):
        for value in sorted(expected.get(hash_type) or []):
            yield from records_for_hash(db, hash_type, value)
    yield from db.get("indexes", {}).get("by_name", {}).get(fname, [])


def find_validated_variant(
    file_entry: dict,
    db: dict,
    current_path: str,
    validation_index: dict,
    bios_dir: str = BIOS_DIR,
    platform_digest: str | None = None,
    emulators: set[str] | None = None,
    strict: bool = False,
) -> str | None:
    """A held file the emulator's own checks accept, in place of current_path.

    Candidates come first from the hashes the emulator declares, which finds
    a dump stored under another name, then from the files sharing the name.
    platform_digest is the hash the frontend compares ("md5", "sha1") or None
    when it reads no bytes: a candidate must then also carry a value the
    entry declares, since the frontend would reject anything else. The
    report and the packs read this one function, so the file a report counts
    as satisfying the emulator is the file a pack ships.
    """
    fname = file_entry.get("name", "")
    if not fname or fname not in validation_index:
        return None
    accepted: set[str] = set()
    if platform_digest:
        if file_entry.get("zipped_file"):
            return None
        accepted = _platform_accepted(file_entry, platform_digest)

    files_db = db.get("files", {})
    current_real = os.path.realpath(current_path)
    seen: set[str] = set()

    for sha1 in _variant_candidates(validation_index[fname], db, fname):
        entry = files_db.get(sha1) or {}
        path = entry.get("path", "")
        if not path or not os.path.exists(path):
            continue
        real = os.path.realpath(path)
        if real == current_real or real in seen:
            continue
        seen.add(real)
        if accepted and str(entry.get(platform_digest, "")).lower() not in accepted:
            continue
        if check_file_validation(
            path, fname, validation_index, bios_dir, emulators, strict
        ) is None:
            return path
    return None


def agnostic_substitute(
    file_entry: dict, sys_id: str, db: dict, platform_profiles: dict[str, dict]
) -> tuple[str, str] | None:
    """(path, directory) of a held file a filename-agnostic core can boot.

    A core with `bios_mode: agnostic` (PCSX2 picks any image in its BIOS
    folder) is served by any image of the right size, renamed to what the
    platform declares. That only satisfies a frontend that checks existence:
    a digest frontend compares the bytes. Only the platform's own cores are
    asked, and the pack and verify read this one answer. An entry that
    declares a content hash names one file: no substitute stands for it.
    """
    if lists_hashes(file_entry):
        return None
    by_name = db.get("indexes", {}).get("by_name", {})
    files_db = db.get("files", {})
    for profile in platform_profiles.values():
        if profile.get("bios_mode") != "agnostic":
            continue
        if sys_id not in set(profile.get("systems", [])):
            continue
        for entry in profile.get("files", []):
            for sha1 in by_name.get(entry.get("name", ""), []):
                path = files_db.get(sha1, {}).get("path", "")
                if not path:
                    continue
                prefix = path.rsplit("/", 1)[0] + "/"
                for candidate in files_db.values():
                    held = candidate.get("path", "")
                    if (
                        held.startswith(prefix)
                        and os.path.exists(held)
                        and shape_fits(entry, held, candidate.get("size", 0))
                    ):
                        return held, prefix
                break
    return None


def frontend_digest_matches(
    file_entry: dict, local_path: str | None, algorithm: str, rule: str = ""
) -> bool:
    """Whether the frontend's own digest accepts the file.

    resolve_local_file calls a file `hash_mismatch` when any declared hash
    disagrees, but a frontend compares one digest. verify_entry_md5 reads it
    too: Recalbox hashes a ZIP by its members. Batocera compares the whole
    md5 string (batocera-systems:1088), so a value cut short accepts nothing. Under SIZE_AND_ANY_HASH (RomM) the declared size must
    match and then any one of md5, sha1 and crc32 does: a mistyped hash next
    to a right one does not withhold the file, a wrong size does.
    """
    if not local_path:
        return False

    def composite() -> str | None:
        if ".zip" not in os.path.basename(local_path):
            return None
        try:
            return md5_composite(local_path)
        except (zipfile.BadZipFile, OSError):
            return None

    return digest_verdict(
        file_entry, os.path.getsize(local_path), lambda: compute_hashes(local_path),
        algorithm, rule, composite,
    )


def digest_verdict(
    file_entry: dict,
    size: int,
    hashes: Callable[[], dict[str, str]],
    algorithm: str,
    rule: str = "",
    composite: Callable[[], str | None] = lambda: None,
) -> bool:
    """The frontend's acceptance rule over content given by its size, its
    digests and, for an archive, its member digest.

    One rule for a file on disk and for a member of a built pack: the pack
    check once compared only the md5 and refused, under RomM's rule, the
    revision the builder had rightly shipped on its sha1 and size.
    """
    if rule == SIZE_AND_ANY_HASH:
        # RomM reads an absent size as 0: such an entry never verifies.
        if size != int(file_entry.get("size") or 0):
            return False
        digests = hashes()
        return any(
            digests[field].lower() == str(file_entry[field]).strip().lower()
            for field in ("md5", "sha1", "crc32")
            if file_entry.get(field)
        )
    if algorithm == "md5":
        declared = parse_hash_list(file_entry.get("md5"))
    else:
        value = file_entry.get(algorithm)
        values = value if isinstance(value, list) else [value]
        declared = [str(v).strip().lower() for v in values if v]
    if not declared:
        return False
    actual = hashes()[algorithm].lower()
    if algorithm != "md5":
        return actual in declared
    # Recalbox hashes a .zip by its members only (Bios.cpp:64-68), so the
    # container's own md5 answers nothing there.
    composite_only = file_entry.get("zip_digest") == "composite"
    if not composite_only and actual in declared:
        return True
    member_digest = composite()
    if not member_digest:
        return False
    return member_digest.lower() in declared


def inner_rom_check(file_entry: dict, local_path: str) -> str:
    """How an archive answers an entry that pins a ROM inside it.

    Batocera, RetroBat and ROCKNIX hash a member of the ZIP, never the ZIP:
    the resolver hands back the archive as a mismatch and this decides it.
    Returns check_inside_zip's answer for the first accepted MD5 that
    matches, else for the last one tried. The pack and the install manifest
    both read it, so a file one of them ships is a file the other lists.
    """
    return _first_accepted_md5(
        file_entry,
        lambda md5: check_inside_zip(local_path, file_entry["zipped_file"], md5),
    )


def inner_rom_data_check(file_entry: dict, data: bytes) -> str:
    """inner_rom_check on the bytes of an archive, as a pack holds it."""
    return _first_accepted_md5(
        file_entry,
        lambda md5: check_inside_zip_data(data, file_entry["zipped_file"], md5),
    )


def _first_accepted_md5(file_entry: dict, check: Callable[[str], str]) -> str:
    # With no md5 declared, checkInsideZip still runs and needs the member.
    result = "not_in_zip"
    for candidate in parse_hash_list(file_entry.get("md5")) or [""]:
        result = check(candidate)
        if result == "ok":
            break
    return result


def baseline_verdict(
    file_entry: dict,
    local_path: str | None,
    status: str,
    verification_mode: str,
    rule: str = "",
) -> tuple[str, str | None]:
    """The status a platform entry ships under, or why a hash platform refuses it.

    Batocera hashes the member, never the ZIP: a zipped_file entry is checked
    inside the archive whatever the outer resolution said, as verify does. A
    frontend that hashes one digest accepts a file whose other declared
    hashes disagree. The pack builder and the install manifest both read
    this, so the one-line installer never places a file the pack refused.
    Existence platforms never read the bytes: nothing is refused here.
    """
    if not hash_mismatch_excludes_file(verification_mode):
        return status, None
    member = file_entry.get("zipped_file")
    if member and local_path:
        result = inner_rom_check(file_entry, local_path)
        if result == "ok":
            return "zip_exact", None
        if result == "not_in_zip":
            return status, f"{member} not found inside ZIP"
        if result == "error":
            return status, "cannot read ZIP"
        return status, f"{member} MD5 mismatch inside ZIP"
    if rule == SIZE_AND_ANY_HASH and local_path:
        # A hash found by the resolver does not settle it: the size the
        # frontend compares first can still be declared otherwise.
        if frontend_digest_matches(file_entry, local_path, "", rule):
            return status, None
        return status, "size or hash mismatch"
    if status != "hash_mismatch":
        return status, None
    if frontend_digest_matches(file_entry, local_path, digest_algorithm(verification_mode)):
        return "frontend_digest_exact", None
    return status, "hash mismatch"


def destination_owners(profiles: dict) -> dict[str, list[tuple[str, str]]]:
    """For each file name, the path tail each emulator reads it under."""
    owners: dict[str, list[tuple[str, str]]] = {}
    for emu_name, profile in profiles.items():
        for f in profile.get("files", []):
            name = str(f.get("name") or "")
            if not name:
                continue
            for declared in {f.get("path"), f.get("standalone_path")} - {None, ""} or {name}:
                owners.setdefault(name.lower(), []).append(
                    (str(declared).replace("\\", "/").lower(), emu_name)
                )
    return owners


def _owners_of(destination: str, name: str, owners: dict) -> set[str]:
    """Emulators whose declared path is the longest tail of the destination."""
    destination = destination.replace("\\", "/").lower()
    matching = [
        (tail, emu) for tail, emu in owners.get(name.lower(), [])
        if destination == tail or destination.endswith("/" + tail)
    ]
    if not matching:
        return set()
    longest = max(len(tail) for tail, _emu in matching)
    return {emu for tail, emu in matching if len(tail) == longest}


class Judges(TypedDict, total=False):
    """The cores that judge a file in validated_choice, each by its own entries."""

    emulators: set[str] | None


def validated_choice(
    file_entry: dict,
    local_path: str | None,
    db: dict,
    validation_index: dict,
    bios_dir: str,
    platform_digest: str | None,
    destination: str = "",
    owners: dict | None = None,
    **judging: Unpack[Judges],
) -> tuple[str | None, str | None]:
    """The file a platform destination ships, and the disagreement if any.

    A frontend's own check can pass while an emulator it runs rejects the
    file. A held variant both accept replaces it. The pack and the install
    manifest both read this, so they name the same file. A destination
    another emulator declares more precisely is that emulator's: ZEsarUX's
    48 KB cpc6128.rom check has no say over ep128emu/roms/cpc6128.rom.
    """
    unknown = sorted(set(judging) - set(Judges.__annotations__))
    if unknown:
        raise TypeError(f"validated_choice() got an unexpected keyword argument '{unknown[0]}'")
    emulators = judging.get("emulators")
    if not local_path or not validation_index:
        return local_path, None
    name = file_entry.get("name", "")
    rules = validation_index.get(name)
    judges: set[str] | None = emulators
    if rules and judges is None and owners and destination:
        owning = _owners_of(destination, name, owners)
        if not owning & set(rules["emulators"]):
            # No core that checks this name reads this destination: PC-98's
            # bios.rom rules have no say over roms/ibmpcjr/bios.rom.
            return local_path, None
        # The cores that read this destination judge it, each by its own
        # entries.
        judges = owning & set(rules["emulators"])

    def check(path: str, strict: bool) -> tuple[str, list[str]] | None:
        return check_file_validation(path, name, validation_index, bios_dir, judges, strict)

    def variant(strict: bool) -> str | None:
        return find_validated_variant(
            file_entry, db, local_path, validation_index, bios_dir,
            platform_digest=platform_digest, emulators=judges, strict=strict,
        )

    if not check(local_path, True):
        return local_path, None
    # A held file every check passes, warn-level ones included, comes first,
    # then the file itself when only a warning fails (the core runs it),
    # then a held file the core at least runs.
    better = variant(True)
    if better:
        return better, None
    failed = check(local_path, False)
    if not failed:
        return local_path, None
    better = variant(False)
    if better:
        return better, None
    reason, failing = failed
    said = f"{', '.join(failing)} says {reason}"
    return local_path, Refusal(said, reason.accepted) if isinstance(reason, Refusal) else said


def existence_discrepancy(file_entry: dict, local_path: str, platform_display: str) -> str:
    """What an existence platform is told when its declared hash contradicts
    the file it loads: the file is kept, the gap is said out loud. The pack
    and verify both print this one line."""
    declared = file_entry.get("md5", "") or file_entry.get("sha1", "")
    actual = compute_hashes(local_path)
    return (
        f"packed per {platform_display} existence check: declared hash {declared}, "
        f"file md5 {actual['md5']} sha1 {actual['sha1']}"
    )


def same_slot_entries(files: list, name: str, path: str) -> list[dict]:
    """The entries of one profile that name the same file at the same path.

    A profile lists every version its code takes under one name (each GRP
    of Raze's table, eduke32's demo and retail NWINTER.GRP): any of them
    fills the slot.
    """
    return [
        entry for entry in files or []
        if isinstance(entry, dict) and entry.get("name") == name
        and (entry.get("path") or name) == path
    ]


def slot_index(files: list) -> dict[tuple[str, str], list[dict]]:
    """A profile's entries keyed by (name, path), as same_slot_entries
    matches them: one pass, then one lookup per extra."""
    index: dict[tuple[str, str], list[dict]] = {}
    for entry in files or []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            name = entry["name"]
            index.setdefault((name, entry.get("path") or name), []).append(entry)
    return index


def extra_alternatives(fe: dict, profiles: Mapping | None) -> list[dict]:
    """The versions the extra's own profile accepts at the extra's slot."""
    if not profiles:
        return []
    profile = profiles.get(fe.get("source_profile") or "", {})
    name = fe.get("source_name") or fe.get("name", "")
    return same_slot_entries(
        profile.get("files") or [], name, fe.get("source_path") or name
    )


def core_size_refusal(
    file_entry: dict, local_path: str | None, alternatives: Sequence[dict] = (),
) -> str | None:
    """Why the core refuses this copy by the size its own code checks, or None.

    The one rule the builder, the install manifest and verify read for a
    core's file. An existence platform never opens the bytes, so a copy whose
    hash disagrees still ships to it, but a core that measures the file turns
    one of the wrong size away: Basilisk II stops on the Apple IIGS' 128 KB
    ROM (main_unix.cpp:692), so packing that file for it serves nothing.
    ``alternatives`` are the other versions the profile accepts at the same
    slot: a copy any of them takes is not refused.
    """
    if not local_path or not os.path.isfile(local_path):
        return None
    size = os.path.getsize(local_path)
    sized = [entry for entry in (file_entry, *alternatives) if name_match_size_ok(entry, size)]
    if any(content_fits(entry, local_path) for entry in sized):
        return None
    if sized:
        tests = sorted({check for entry in sized for check in declared_content_checks(entry)})
        return f"the core's {', '.join(tests)} test turns it away"
    declared = file_entry.get("size")
    bounds = [] if declared is None else [str(declared)]
    multiple = file_entry.get("size_multiple")
    if multiple or any(file_entry.get(k) is not None for k in ("min_size", "max_size")):
        window = f"{file_entry.get('min_size', 0)} to {file_entry.get('max_size', 'any')}"
        bounds.append(f"{window} in multiples of {multiple}" if multiple else window)
    return f"{size} bytes, the core checks for {' or '.join(bounds)}"
