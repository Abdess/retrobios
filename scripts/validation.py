"""Emulator-level file validation logic.

Builds validation indexes from emulator profiles, checks files against
emulator-declared constraints (size, hash, crypto), and formats ground
truth data for reporting.
"""

from __future__ import annotations

import os
import re
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence

from common import (
    adler32_of,
    archive_members,
    compute_hashes,
    entry_system_ids,
    name_match_size_ok,
    sanitize_pack_path,
    size_fits,
)
from hashing import md5_composite, parse_hash_list, parse_md5_list
from nativemode import SIZE_AND_ANY_HASH, digest_algorithm, hash_mismatch_excludes_file
from ziptools import check_inside_zip

# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these: size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})


def _adler32_byteswapped(path: str) -> str:
    """Adler-32 over 16-bit byte-swapped data, as Dolphin hashes its DSP ROMs."""
    return adler32_of(path, byteswap=True)


# All reproducible validation types.
_HASH_CHECKS = frozenset({"crc32", "md5", "sha1", "adler32"})


def _parse_validation(validation: list | dict | None) -> list[str]:
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


def _entry_rule(emu_name: str, f: dict, checks: set[str]) -> dict:
    """One profile entry's own checks, kept apart from the merged view.

    Merged by name, Azahar's crypto check on the 3DS otp.bin judged Cemu's
    1 KiB Wii U otp.bin, and the variant search handed Cemu the 3DS file.
    """
    def values(field: str) -> set[str]:
        if field not in checks:
            return set()
        return set(parse_hash_list(f.get(field)))

    raw_size = f.get("size") if "size" in checks else None
    adler = f.get("known_hash_adler32") or f.get("adler32")
    adler_values = adler if isinstance(adler, list) else [adler] if adler else []
    return {
        "emulator": emu_name,
        "checks": set(checks),
        "sizes": set(raw_size if isinstance(raw_size, list) else [raw_size])
        - {None},
        "min_size": f.get("min_size") if "size" in checks else None,
        "max_size": f.get("max_size") if "size" in checks else None,
        "crc32": values("crc32"),
        "md5": values("md5"),
        "sha1": values("sha1"),
        "sha256": values("sha256"),
        "adler32": {
            str(v).lower().removeprefix("0x") for v in adler_values if v
        },
        "adler32_byteswap": bool(f.get("adler32_byteswap")),
        "crypto": {c for c in checks if c in _CRYPTO_CHECKS},
        # The checks whose failure the code only warns about: the file runs.
        "warn": warned_checks(f, checks),
    }


def warned_checks(f: dict, checks: set[str]) -> set[str]:
    """The checks of an entry the code warns about instead of refusing.

    `on_mismatch: warn` covers every check, while a map names them one by one, as
    Azahar refuses a SecureInfo_A of the wrong size and only logs a bad
    signature.
    """
    level = f.get("on_mismatch")
    if level == "warn":
        return set(checks)
    if isinstance(level, dict):
        return {check for check, value in level.items() if value == "warn"} & set(checks)
    return set()


def _rule_failure(
    rule: dict, local_path: str, filename: str, bios_dir: str, hashes: dict,
    strict: bool = False,
) -> str | None:
    """Why one entry's checks reject a file, or None when they accept it.

    A check the code only warns about counts under ``strict`` alone.
    """
    skip = set() if strict else rule["warn"]
    if "size" not in skip:
        actual_size = os.path.getsize(local_path)
        if rule["sizes"] and actual_size not in rule["sizes"]:
            accepted = ",".join(str(s) for s in sorted(rule["sizes"]))
            return f"size mismatch: got {actual_size}, accepted [{accepted}]"
        if rule["min_size"] is not None and actual_size < rule["min_size"]:
            return f"size too small: min {rule['min_size']}, got {actual_size}"
        if rule["max_size"] is not None and actual_size > rule["max_size"]:
            return f"size too large: max {rule['max_size']}, got {actual_size}"
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if rule[hash_type] and hash_type not in skip:
            if not hashes:
                hashes.update(compute_hashes(local_path))
            if hashes[hash_type].lower() not in rule[hash_type]:
                accepted = ",".join(sorted(rule[hash_type]))
                return f"{hash_type} mismatch: got {hashes[hash_type]}, accepted [{accepted}]"
    if rule["adler32"] and "adler32" not in skip:
        if rule["adler32_byteswap"]:
            actual = _adler32_byteswapped(local_path)
        else:
            if not hashes:
                hashes.update(compute_hashes(local_path))
            actual = hashes["adler32"].lower()
        if actual not in rule["adler32"]:
            accepted = ",".join(sorted(rule["adler32"]))
            return f"adler32 mismatch: got 0x{actual}, accepted [{accepted}]"
    if rule["crypto"] - skip:
        from crypto_verify import check_crypto_validation

        return check_crypto_validation(local_path, filename, bios_dir)
    return None


def _found_by_content(entry: dict, profile: dict) -> bool:
    """Whether every build of the core identifies this entry by content."""
    return not opens_by_name(entry, profile) and not opens_by_name(
        entry, profile, standalone=True
    )


def _regions(entry: dict) -> set[str]:
    value = entry.get("region")
    return set(value) if isinstance(value, list) else {value} if value else set()


def content_alternatives(entry: dict, profile: dict) -> list[dict]:
    """The labels a content-found core takes in place of this one.

    rustation scans its folder by sha256 (found_by: content): its
    scph1001.bin is a label for v2.2, and the v2.0 dump ROCKNIX ships under
    that name boots the same North American console, labelled
    scph1001_v20.bin. Alternatives share the entry's system and declared
    region, the slot slot.py groups by: openMSX also finds its ROMs by
    sha1, but each one serves its own machine and declares no region.
    """
    if not _found_by_content(entry, profile):
        return []
    regions = _regions(entry)
    if not regions:
        return []
    systems = set(entry_system_ids(entry, profile))
    return [
        other for other in profile.get("files") or []
        if isinstance(other, dict)
        and _found_by_content(other, profile)
        and regions & _regions(other)
        and systems == set(entry_system_ids(other, profile))
    ]


def _labels_widened(profile: dict) -> list[dict]:
    """The profile's entries, each content-found label accepting the dumps
    of its alternatives (content_alternatives)."""
    widened = []
    for f in profile.get("files") or []:
        if not isinstance(f, dict):
            continue
        siblings = content_alternatives(f, profile)
        if len(siblings) < 2:
            widened.append(f)
            continue
        merged = dict(f)
        for field_name in ("crc32", "md5", "sha1", "sha256"):
            if f.get(field_name):
                merged[field_name] = list(dict.fromkeys(
                    value for other in siblings
                    for value in parse_hash_list(other.get(field_name))
                ))
        if f.get("size") is not None:
            merged["size"] = sorted({
                size for other in siblings
                for size in (other["size"] if isinstance(other.get("size"), list)
                             else [other.get("size")])
                if size is not None
            })
        widened.append(merged)
    return widened


def _build_validation_index(profiles: dict) -> dict[str, dict]:
    """Build per-filename validation rules from emulator profiles.

    Returns {filename: {"checks": [str], "size": int|None, "min_size": int|None,
    "max_size": int|None, "crc32": str|None, "md5": str|None, "sha1": str|None,
    "adler32": str|None, "crypto_only": [str], "per_emulator": {emu: detail}}}.

    ``crypto_only`` lists validation types we cannot reproduce (signature, crypto)
    so callers can report them as non-verifiable rather than silently skipping.

    ``per_emulator`` preserves each core's individual checks, source_ref, and
    expected values before merging, for ground truth reporting.

    When multiple emulators reference the same file, merges checks (union).
    Raises ValueError if two profiles declare conflicting values.
    """
    index: dict[str, dict] = {}
    # A slot where one version is taken without any check (Raze's "BLOOD:
    # Unknown Version", which holds the shareware RFF) accepts every copy for
    # that core: its validated siblings are alternatives, not requirements.
    unchecked: set[tuple[str, str, str]] = set()
    checked: set[tuple[str, str, str]] = set()
    for emu_name, profile in profiles.items():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in _labels_widened(profile):
            fname = f.get("name", "")
            if not fname:
                continue
            checks = _parse_validation(f.get("validation"))
            slot = (fname, emu_name, f.get("path") or fname)
            if not checks:
                unchecked.add(slot)
                continue
            checked.add(slot)
            if fname not in index:
                index[fname] = {
                    "checks": set(),
                    "sizes": set(),
                    "min_size": None,
                    "max_size": None,
                    "crc32": set(),
                    "md5": set(),
                    "sha1": set(),
                    "sha256": set(),
                    "adler32": set(),
                    "adler32_byteswap": False,
                    "crypto_only": set(),
                    "emulators": set(),
                    "per_emulator": {},
                    "rules": [],
                }
            index[fname]["rules"].append(_entry_rule(emu_name, f, checks))
            index[fname]["emulators"].add(emu_name)
            # A warned check is never a rejection, so it stays out of the
            # merged rejection rules.
            warned = warned_checks(f, set(checks))
            checks = [check for check in checks if check not in warned]
            if not checks:
                continue
            index[fname]["checks"].update(checks)
            # Track non-reproducible crypto checks
            index[fname]["crypto_only"].update(c for c in checks if c in _CRYPTO_CHECKS)
            # Size checks
            if "size" in checks:
                raw_size = f.get("size")
                if raw_size is not None:
                    if isinstance(raw_size, list):
                        index[fname]["sizes"].update(raw_size)
                    else:
                        index[fname]["sizes"].add(raw_size)
                if f.get("min_size") is not None:
                    cur = index[fname]["min_size"]
                    index[fname]["min_size"] = (
                        min(cur, f["min_size"]) if cur is not None else f["min_size"]
                    )
                if f.get("max_size") is not None:
                    cur = index[fname]["max_size"]
                    index[fname]["max_size"] = (
                        max(cur, f["max_size"]) if cur is not None else f["max_size"]
                    )
            # Hash checks: collect all accepted hashes as sets (multiple valid
            # versions of the same file, e.g. MT-32 ROM versions)
            if "crc32" in checks and f.get("crc32"):
                crc_val = f["crc32"]
                crc_list = crc_val if isinstance(crc_val, list) else [crc_val]
                for cv in crc_list:
                    norm = str(cv).lower()
                    if norm.startswith("0x"):
                        norm = norm[2:]
                    index[fname]["crc32"].add(norm)
            # A hash field may carry several accepted values, as a list or as
            # the comma-separated string the schema spells out
            for hash_type in ("md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    val = f[hash_type]
                    values = val if isinstance(val, list) else str(val).split(",")
                    for h in values:
                        if str(h).strip():
                            index[fname][hash_type].add(str(h).strip().lower())
            # Adler32: stored as known_hash_adler32 field (not in validation: list
            # for Dolphin, but support it in both forms for future profiles)
            adler_val = f.get("known_hash_adler32") or f.get("adler32")
            for value in adler_val if isinstance(adler_val, list) else [adler_val] if adler_val else []:
                norm = str(value).lower()
                if norm.startswith("0x"):
                    norm = norm[2:]
                index[fname]["adler32"].add(norm)
            if f.get("adler32_byteswap"):
                index[fname]["adler32_byteswap"] = True
            # Per-emulator ground truth detail
            expected: dict = {}
            if "size" in checks:
                for key in ("size", "min_size", "max_size"):
                    if f.get(key) is not None:
                        expected[key] = f[key]
            for hash_type in ("crc32", "md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    expected[hash_type] = f[hash_type]
            adler_val_pe = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val_pe:
                expected["adler32"] = adler_val_pe
            pe_entry = {
                "checks": sorted(checks),
                "source_ref": f.get("source_ref"),
                "expected": expected,
            }
            pe = index[fname]["per_emulator"]
            if emu_name in pe:
                # Merge checks from multiple file entries for same emulator
                existing = pe[emu_name]
                merged_checks = sorted(
                    set(existing["checks"]) | set(pe_entry["checks"])
                )
                existing["checks"] = merged_checks
                existing["expected"].update(pe_entry["expected"])
                if pe_entry["source_ref"] and not existing["source_ref"]:
                    existing["source_ref"] = pe_entry["source_ref"]
            else:
                pe[emu_name] = pe_entry
    for fname, emu_name, _path in sorted(checked & unchecked):
        index[fname]["rules"].append(_entry_rule(emu_name, {}, set()))
    # Convert sets to sorted tuples/lists for determinism
    for v in index.values():
        v["checks"] = sorted(v["checks"])
        v["crypto_only"] = sorted(v["crypto_only"])
        v["emulators"] = sorted(v["emulators"])
        # Keep hash sets as frozensets for O(1) lookup in check_file_validation
    return index


def build_ground_truth(filename: str, validation_index: dict[str, dict]) -> list[dict]:
    """Format per-emulator ground truth for a file from the validation index.

    Returns a sorted list of {emulator, checks, source_ref, expected} dicts.
    Returns [] if the file has no emulator validation data.
    """
    entry = validation_index.get(filename)
    if not entry or not entry.get("per_emulator"):
        return []
    result = []
    for emu_name in sorted(entry["per_emulator"]):
        detail = entry["per_emulator"][emu_name]
        result.append(
            {
                "emulator": emu_name,
                "checks": detail["checks"],
                "source_ref": detail.get("source_ref"),
                "expected": detail.get("expected", {}),
            }
        )
    return result


def _emulators_for_check(
    check_type: str, per_emulator: dict[str, dict],
) -> list[str]:
    """Return emulator names that validate a specific check type."""
    result = []
    for emu, detail in per_emulator.items():
        emu_checks = detail.get("checks", [])
        if check_type in emu_checks:
            result.append(emu)
        # adler32 is stored as known_hash, not always in validation list
        if check_type == "adler32" and detail.get("expected", {}).get("adler32"):
            if emu not in result:
                result.append(emu)
    return sorted(result)


_REASON = re.compile(r"^(\w+ mismatch): got (\S+), accepted \[(.*)\]$")


def _merged_reason(reasons: list[str]) -> str:
    """One reason for every entry of a core that turned the copy away.

    Raze lists three BLOOD.RFF sizes and the message named the first one
    alone. Reasons of one kind are merged into a single accepted list.
    """
    parsed = [_REASON.match(reason) for reason in reasons]
    if all(parsed) and len({(m.group(1), m.group(2)) for m in parsed}) == 1:
        accepted = sorted({v for m in parsed for v in m.group(3).split(",") if v},
                          key=lambda v: (len(v), v))
        return f"{parsed[0].group(1)}: got {parsed[0].group(2)}, accepted [{','.join(accepted)}]"
    return reasons[0]


def check_file_validation(
    local_path: str,
    filename: str,
    validation_index: dict[str, dict],
    bios_dir: str = "bios",
    emulators: set[str] | None = None,
    strict: bool = False,
) -> tuple[str, list[str]] | None:
    """Check emulator-level validation on a resolved file.

    Supports: size (exact/min/max), crc32, md5, sha1, adler32,
    signature (RSA-2048 PKCS1v15 SHA256), crypto (AES-128-CBC + SHA256).

    With ``emulators``, the cores that read the file's destination, each of
    them must accept it through one of its own entries for the name, the
    way each runs its own check. Without, the checks of every core naming
    the file are merged. A check declared `on_mismatch: warn` rejects
    nothing, since the core runs with the file, while ``strict`` counts it, to
    prefer a file that passes it too.

    Returns None if all checks pass or no validation applies.
    Returns (reason, emulators) tuple on failure, where *emulators*
    lists only those cores whose check actually failed.
    """
    entry = validation_index.get(filename)
    if not entry:
        return None
    if emulators is not None:
        hashes: dict = {}
        failures: dict[str, str] = {}
        for emu in sorted(emulators):
            rules = [r for r in entry.get("rules", []) if r["emulator"] == emu]
            if not rules:
                continue
            reasons = [
                _rule_failure(rule, local_path, filename, bios_dir, hashes, strict)
                for rule in rules
            ]
            if all(reasons):
                failures[emu] = _merged_reason(reasons)
        if not failures:
            return None
        first = sorted(failures)[0]
        return failures[first], sorted(failures)
    checks = entry["checks"]
    pe = entry.get("per_emulator", {})

    # Size checks: sizes is a set of accepted values
    if "size" in checks:
        actual_size = os.path.getsize(local_path)
        if entry["sizes"] and actual_size not in entry["sizes"]:
            expected = ",".join(str(s) for s in sorted(entry["sizes"]))
            emus = _emulators_for_check("size", pe)
            return f"size mismatch: got {actual_size}, accepted [{expected}]", emus
        if entry["min_size"] is not None and actual_size < entry["min_size"]:
            emus = _emulators_for_check("size", pe)
            return f"size too small: min {entry['min_size']}, got {actual_size}", emus
        if entry["max_size"] is not None and actual_size > entry["max_size"]:
            emus = _emulators_for_check("size", pe)
            return f"size too large: max {entry['max_size']}, got {actual_size}", emus

    # Hash checks: compute once, reuse for all hash types.
    # Each hash field is a set of accepted values (multiple valid ROM versions).
    need_hashes = any(
        h in checks and entry.get(h) for h in ("crc32", "md5", "sha1", "sha256")
    ) or entry.get("adler32")
    if need_hashes:
        hashes = compute_hashes(local_path)
        for hash_type in ("crc32", "md5", "sha1", "sha256"):
            if hash_type in checks and entry[hash_type]:
                if hashes[hash_type].lower() not in entry[hash_type]:
                    expected = ",".join(sorted(entry[hash_type]))
                    emus = _emulators_for_check(hash_type, pe)
                    return (
                        f"{hash_type} mismatch: got {hashes[hash_type]}, "
                        f"accepted [{expected}]",
                        emus,
                    )
        if entry["adler32"]:
            actual_adler = hashes["adler32"].lower()
            if entry.get("adler32_byteswap"):
                actual_adler = _adler32_byteswapped(local_path)
            if actual_adler not in entry["adler32"]:
                expected = ",".join(sorted(entry["adler32"]))
                emus = _emulators_for_check("adler32", pe)
                return (
                    f"adler32 mismatch: got 0x{actual_adler}, accepted [{expected}]",
                    emus,
                )

    # Signature/crypto checks (3DS RSA, AES)
    if entry["crypto_only"]:
        from crypto_verify import check_crypto_validation

        crypto_reason = check_crypto_validation(local_path, filename, bios_dir)
        if crypto_reason:
            emus = sorted(entry.get("emulators", []))
            return crypto_reason, emus

    return None


def read_from_system_dir(file_entry: dict, standalone: bool = False) -> bool:
    """Whether the emulator reads this entry from the system directory.

    A file loaded from the save, content or working directory is not in the
    BIOS tree: no platform lists it, and the truth model must not ask a
    platform to declare it. Packs place one read below the save directory
    there (read_from_save_dir), never in the BIOS tree. Two builds can read one file from two
    places: libretro Dolphin keeps its User tree in the save directory, the
    standalone app in its own folder, so ``load_from`` can be keyed by build.
    """
    load_from = _load_from(file_entry, standalone)
    return not load_from or load_from == "system_dir"


def _load_from(file_entry: dict, standalone: bool) -> str:
    """The ``load_from`` value that applies to one build."""
    load_from = file_entry.get("load_from", "")
    if isinstance(load_from, dict):
        load_from = load_from.get("standalone" if standalone else "libretro", "")
    return load_from or ""


def read_from_save_dir(file_entry: dict, standalone: bool = False) -> bool:
    """Whether the libretro build reads this entry below the frontend's save
    directory, the one RETRO_ENVIRONMENT_GET_SAVE_DIRECTORY returns.

    ``path`` is then relative to that directory. A standalone app has no
    frontend to hand it one: its files are placed by ``standalone_path``.
    """
    return not standalone and _load_from(file_entry, False) == "save_dir"


def entry_root(file_entry: dict, standalone: bool = False) -> str:
    """The frontend directory an entry's ``path`` is relative to: ``save``
    for a file the libretro build reads below the save directory, else
    ``system``."""
    return "save" if read_from_save_dir(file_entry, standalone) else "system"


def outside_gap_scope(file_entry: dict, is_standalone: bool) -> bool:
    """Whether an entry is a file the platform's pack would carry for this build.

    Read by the gap report and by verify's undeclared-file pass, so both set
    aside the same entries: a placeholder standing for a family of files, a
    file the user imports through the UI (``path: null``), an entry of the
    build the platform does not run, a file read outside the system and
    save directories, and a filename-agnostic entry the builder scans for
    itself. A file the libretro build reads below the save directory is in
    scope: the pack places it there (``entry_root``).
    """
    name = file_entry.get("name", "")
    if "<" in name or ">" in name or "*" in name:
        return True
    if "path" in file_entry and file_entry["path"] is None:
        return True
    mode = file_entry.get("mode")
    if (mode == "standalone" and not is_standalone) or (
        mode == "libretro" and is_standalone
    ):
        return True
    return not (
        read_from_system_dir(file_entry, is_standalone)
        or read_from_save_dir(file_entry, is_standalone)
    ) or bool(file_entry.get("agnostic"))


def case_folded_slots(
    config: dict, declarations: Mapping[str, list[tuple[int | None, str]]],
) -> frozenset[str]:
    """The slots a platform whose filesystem folds case fills, any spelling.

    On RetroBat the 32X_G_BIOS.BIN it declares is the file BlastEm opens as
    32X_G_BIOS.bin. On Lakka bios.col and BIOS.col are two files: nothing.
    """
    if not config.get("case_insensitive_fs", False):
        return frozenset()
    return frozenset(where for places in declarations.values() for _size, where in places)


def declaration_settles(
    file_entry: dict,
    fname: str,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | set[str],
    dest: str = "",
    folded_slots: frozenset[str] = frozenset(),
    declared_contents: Mapping[str, set[str]] | None = None,
) -> bool:
    """Whether a platform declaration meets a core's requirement.

    An entry the core finds by content (``found_by: content`` on the entry)
    is met by any declaration of a file it accepts by hash, in the folder it
    scans: atari800 takes RetroDECK's ROM_BASIC_A by its CRC32, so its own
    label for that ROM is not one more file to ship.

    A platform declaring the name the core reads has met the requirement
    where the declaration fills the entry's own slot, whose content the slot
    arbitration decides, or elsewhere at a size the core accepts: the builder
    copies that file to the core's path. Galaksija's 4 KiB ROM1.BIN does not
    stand for DOSBox's 32 KiB SC-55 one. The builder copies nothing for an
    alias, so an alias answers only where the core reads it: quasi88 reads
    n88sub.rom or disk.rom in quasi88/, and System.dat names quasi88/disk.rom.
    RetroDECK's root MSX.ROM is not CLK's MSX/MSX.ROM, and RetroBat's 16 KiB
    MSX DISK.ROM at the root is not the 256-byte Disk II ROM gsplus also
    accepts as c600.rom. The archive answers by its name. A bare set of names
    carries no slot or size and answers by name.

    Read by verify and by the gap report, which settled on the name alone
    and left DOSBox's SC-55 ROMs off the gaps page. ``folded_slots``
    (case_folded_slots) are slots a declaration fills in another spelling on
    a filesystem that folds case: the core opens that file there.
    """
    if file_entry.get("archive") in declared_names:
        return True
    slot = sanitize_pack_path(dest or fname).lower()
    directory = slot if dest.endswith("/") else slot.rpartition("/")[0]
    if declared_contents and file_entry.get("found_by") == "content":
        for field in ("md5", "sha1", "crc32"):
            values = file_entry.get(field) or []
            for value in values if isinstance(values, list) else str(values).split(","):
                folders = declared_contents.get(f"{field}:{str(value).strip().lower()}")
                if folders and directory in folders:
                    return True
    if not dest.endswith("/") and slot in folded_slots:
        return True
    for name in (fname, *file_entry.get("aliases", [])):
        if name not in declared_names:
            continue
        if not isinstance(declared_names, Mapping):
            return True
        if name == fname:
            if any(
                where == slot or name_match_size_ok(file_entry, size)
                for size, where in declared_names[name]
            ):
                return True
            continue
        read_at = f"{directory}/{name}".lower() if directory else name.lower()
        if any(
            where == read_at and name_match_size_ok(file_entry, size)
            for size, where in declared_names[name]
        ):
            return True
    return False


def with_archive_members(entry: dict, files: list[dict]) -> dict:
    """A loose entry resolved as the archive its profile reads members from.

    gngeopi declares neogeo.zip and, apart, the ROMs it opens inside it. The
    members decide which same-named copy is the archive: resolved by name
    alone, the loose entry took another copy than the archive pass and the
    profile blocked its own archive.
    """
    if entry.get("archive"):
        return entry
    members = archive_members(entry.get("name", ""), files)
    return {**entry, "members": members} if members else entry


def opens_by_name(file_entry: dict, profile: dict, standalone: bool = False) -> bool:
    """Whether the code opens this entry by its name.

    A core that scans a folder and identifies firmware by content
    (DuckStation by MD5, bios.cpp:208) gives its entries names that are
    labels. `found_by` says which, on the file or the profile, keyed by
    build when the two builds differ.
    """
    for source in (file_entry, profile):
        value = source.get("found_by")
        if isinstance(value, dict):
            value = value.get("standalone" if standalone else "libretro")
        if value:
            return value != "content"
    return True


def filter_files_by_mode(files: list[dict], standalone: bool) -> list[dict]:
    """Filter file entries by libretro/standalone mode."""
    result = []
    for f in files:
        fmode = f.get("mode", "")
        if standalone and fmode == "libretro":
            continue
        if not standalone and fmode == "standalone":
            continue
        result.append(f)
    return result


def installed_with_emulator(entry: dict, platform: str = "") -> bool:
    """Whether the emulator as this platform installs it already brings the entry.

    `bundled` describes the emulator's own release. A platform package can
    differ both ways: Batocera's hcl package installs the binary alone and
    sends users to fetch the data (`not_bundled_on`), while its blueMSX core
    package copies the machines and databases beside the core
    (`installed_on`).
    """
    if platform and platform in (entry.get("installed_on") or []):
        return True
    return bool(entry.get("bundled")) and platform not in (entry.get("not_bundled_on") or [])


def unread_on(entry: dict, platform: str) -> bool:
    """Whether this platform's launcher points the emulator at other files.

    RetroBat starts standalone BlastEm with absolute paths to its own BIOS
    names in the config it writes, so the defaults the emulator would read
    (cdbios.bin, colecovision_bios.col) are never opened there.
    """
    return bool(platform) and platform in (entry.get("unread_on") or [])


def deliverable(entries: list[dict], standalone: bool, platform: str = "") -> list[dict]:
    """The entries of one build a pack has to bring.

    A file or tree installed with the emulator is already on the user's
    machine: shipping it again only weighs the pack. `bundled` is scoped by
    `mode` like any entry, so PPSSPP's assets, shipped by the standalone
    release and not by the libretro core, still reach a RetroArch pack.
    """
    return [
        e for e in filter_files_by_mode(entries, standalone)
        if not installed_with_emulator(e, platform) and not unread_on(e, platform)
    ]


def find_validated_variant(
    file_entry: dict,
    db: dict,
    current_path: str,
    validation_index: dict,
    bios_dir: str = "bios",
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
        declared = file_entry.get(platform_digest) or ""
        if platform_digest == "md5":
            accepted = set(parse_md5_list(declared))
        elif isinstance(declared, str) and declared:
            accepted = {declared.lower()}
        elif isinstance(declared, list):
            accepted = {str(value).lower() for value in declared}

    files_db = db.get("files", {})
    indexes = db.get("indexes", {})
    current_real = os.path.realpath(current_path)
    seen: set[str] = set()

    def candidates() -> Iterator[str]:
        # Sorted: the index holds sets, whose order follows the per-process
        # string hash, and the first passing candidate is the one shipped.
        expected = validation_index[fname]
        for hash_type, index_key in (
            ("sha1", None), ("md5", "by_md5"), ("crc32", "by_crc32"), ("sha256", "by_sha256"),
        ):
            for value in sorted(expected.get(hash_type) or []):
                if index_key is None:
                    yield value
                    continue
                found = indexes.get(index_key, {}).get(value)
                if isinstance(found, str):
                    yield found
                elif isinstance(found, list):
                    yield from found
        yield from indexes.get("by_name", {}).get(fname, [])

    for sha1 in candidates():
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
    if any(file_entry.get(h) for h in ("sha1", "md5", "sha256", "crc32")):
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
                        and size_fits(entry, candidate.get("size", 0))
                        and os.path.exists(held)
                    ):
                        return held, prefix
                break
    return None


def frontend_digest_matches(
    file_entry: dict, local_path: str, algorithm: str, rule: str = ""
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
        actual = hashes()
        return any(
            actual[field].lower() == str(file_entry[field]).strip().lower()
            for field in ("md5", "sha1", "crc32")
            if file_entry.get(field)
        )
    if algorithm == "md5":
        declared = parse_md5_list(file_entry.get("md5"))
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
    return bool(member_digest) and member_digest.lower() in declared


def inner_rom_check(file_entry: dict, local_path: str) -> str:
    """How an archive answers an entry that pins a ROM inside it.

    Batocera, RetroBat and ROCKNIX hash a member of the ZIP, never the ZIP:
    the resolver hands back the archive as a mismatch and this decides it.
    Returns check_inside_zip's answer for the first accepted MD5 that
    matches, else for the last one tried. The pack and the install manifest
    both read it, so a file one of them ships is a file the other lists.
    """
    declared = parse_md5_list(file_entry.get("md5"))
    result = "not_in_zip"
    for candidate in declared or [""]:
        result = check_inside_zip(local_path, file_entry["zipped_file"], candidate)
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


def validated_choice(
    file_entry: dict,
    local_path: str | None,
    db: dict,
    validation_index: dict,
    bios_dir: str,
    platform_digest: str | None,
    destination: str = "",
    owners: dict | None = None,
    emulators: set[str] | None = None,
) -> tuple[str | None, str | None]:
    """The file a platform destination ships, and the disagreement if any.

    A frontend's own check can pass while an emulator it runs rejects the
    file. A held variant both accept replaces it. The pack and the install
    manifest both read this, so they name the same file. A destination
    another emulator declares more precisely is that emulator's: ZEsarUX's
    48 KB cpc6128.rom check has no say over ep128emu/roms/cpc6128.rom.
    """
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
    return local_path, f"{', '.join(failing)} says {reason}"


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
        if isinstance(entry, dict):
            name = entry.get("name")
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
    if any(name_match_size_ok(entry, size) for entry in (file_entry, *alternatives)):
        return None
    bounds = (
        f"{file_entry['size']}" if file_entry.get("size") is not None
        else f"{file_entry.get('min_size', 0)} to {file_entry.get('max_size', 'any')}"
    )
    return f"{size} bytes, the core checks for {bounds}"
