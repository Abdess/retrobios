"""Emulator-level file validation logic.

Builds validation indexes from emulator profiles, checks files against
emulator-declared constraints (size, hash, crypto), and formats ground
truth data for reporting.
"""

from __future__ import annotations

import os
from collections.abc import Collection, Mapping, Sequence

from resolve.content import (
    adler32_of,
    content_fits,
    parse_validation,
    merged_size_refusal,
    size_refusal,
    SizeRefusal,
)
from model.profiles import CONTENT_CHECKS, entry_system_ids, lists_files
from core.hashing import compute_hashes, parse_hash_list
from core.paths import BIOS_DIR

from resolve.entryscope import opens_by_name

# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these: size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})


def _adler32_byteswapped(path: str) -> str:
    """Adler-32 over 16-bit byte-swapped data, as Dolphin hashes its DSP ROMs."""
    return adler32_of(path, byteswap=True)


_CONTENT_REASONS = {
    "romdir": "romdir mismatch: no RESET and ROMVER the code accepts",
    "masked_sha1": "masked_sha1 mismatch: the cleared image is not the one the code names",
}


class Refusal(str):
    """A hash check's refusal: the message for people, the accepted values as data.

    ``accepted`` maps the algorithm to the values the check takes, in the
    order the message lists them. Reports that look the dumps up read it,
    never the message, which is free to change.

    ``check``, ``got`` and ``values`` say which check refused which digest
    and what it takes, so refusals of one check merge on data. An Adler-32
    check names its values there but accepts no dump a catalog can look up.
    """

    accepted: dict[str, list[str]]
    check: str
    got: str
    values: list[str]

    def __new__(
        cls, message: str, accepted: Mapping[str, Sequence[str]],
        check: str = "", got: str = "", values: Sequence[str] = (),
    ) -> Refusal:
        refusal = super().__new__(cls, message)
        refusal.accepted = {algo: list(values) for algo, values in accepted.items()}
        refusal.check, refusal.got, refusal.values = check, got, list(values)
        return refusal


def _check_refusal(check: str, got: str, values: list[str], lookup: bool) -> Refusal:
    """The refusal of a digest check, rendered from its data."""
    return Refusal(f"{check} mismatch: got {got}, accepted [{','.join(values)}]",
                   {check: values} if lookup else {}, check, got, values)


def _hash_refusal(hash_type: str, got: str, accepted: Collection[str]) -> Refusal:
    """The refusal of a hash check that does not take ``got``."""
    return _check_refusal(hash_type, got, sorted(accepted), True)


def _adler32_refusal(got: str, accepted: Collection[str]) -> Refusal:
    """The refusal of an Adler-32 check that does not take ``got``."""
    return _check_refusal("adler32", f"0x{got}", sorted(accepted), False)


def accepted_hashes(reason: str | None) -> dict[str, list[str]]:
    """The values a refused check accepts, by algorithm, empty when it
    refused on anything but a hash."""
    return dict(reason.accepted) if isinstance(reason, Refusal) else {}


# All reproducible validation types.
_HASH_CHECKS = frozenset({"crc32", "md5", "sha1", "adler32"})


def _entry_rule(emu_name: str, f: dict, checks: Collection[str]) -> dict:
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
        "size_multiple": f.get("size_multiple") if "size" in checks else None,
        "crc32": values("crc32"),
        "md5": values("md5"),
        "sha1": values("sha1"),
        "sha256": values("sha256"),
        "adler32": {
            str(v).lower().removeprefix("0x") for v in adler_values if v
        },
        "adler32_byteswap": bool(f.get("adler32_byteswap")),
        "crypto": {c for c in checks if c in _CRYPTO_CHECKS},
        "content": {
            check: f.get(check) or {} for check in sorted(CONTENT_CHECKS & set(checks))
        },
        # The checks whose failure the code only warns about: the file runs.
        "warn": warned_checks(f, checks),
    }


def warned_checks(f: dict, checks: Collection[str]) -> set[str]:
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


def _rule_size_failure(rule: dict, local_path: str) -> str | None:
    """Why one entry's size check rejects a file, or None."""
    declared = {
        "size": sorted(rule["sizes"]) or None, "min_size": rule["min_size"],
        "max_size": rule["max_size"], "size_multiple": rule.get("size_multiple"),
    }
    return size_refusal(declared, os.path.getsize(local_path))


def _rule_failure(
    rule: dict, local_path: str, filename: str, bios_dir: str, hashes: dict,
    strict: bool = False,
) -> str | None:
    """Why one entry's checks reject a file, or None when they accept it.

    A check the code only warns about counts under ``strict`` alone.
    """
    skip = set() if strict else rule["warn"]
    if "size" not in skip:
        refused = _rule_size_failure(rule, local_path)
        if refused:
            return refused
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if rule[hash_type] and hash_type not in skip:
            if not hashes:
                hashes.update(compute_hashes(local_path))
            if hashes[hash_type].lower() not in rule[hash_type]:
                return _hash_refusal(hash_type, hashes[hash_type], rule[hash_type])
    if rule["adler32"] and "adler32" not in skip:
        if rule["adler32_byteswap"]:
            actual = _adler32_byteswapped(local_path)
        else:
            if not hashes:
                hashes.update(compute_hashes(local_path))
            actual = hashes["adler32"].lower()
        if actual not in rule["adler32"]:
            return _adler32_refusal(actual, rule["adler32"])
    for check, spec in rule.get("content", {}).items():
        if check not in skip and not content_fits({"validation": [check], check: spec}, local_path):
            return _CONTENT_REASONS[check]
    if rule["crypto"] - skip:
        from core.cryptoverify import check_crypto_validation

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


def _new_index_entry() -> dict:
    return {
        "checks": set(),
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


def _merge_hashes(item: dict, f: dict, checks: list[str]) -> None:
    # Hash checks: collect all accepted hashes as sets (multiple valid
    # versions of the same file, e.g. MT-32 ROM versions)
    if "crc32" in checks and f.get("crc32"):
        item["crc32"].update(parse_hash_list(f["crc32"]))
    # A hash field may carry several accepted values, as a list or as
    # the comma-separated string the schema spells out
    for hash_type in ("md5", "sha1", "sha256"):
        if hash_type in checks and f.get(hash_type):
            item[hash_type].update(parse_hash_list(f[hash_type]))
    # Adler32: stored as known_hash_adler32 field (not in validation: list
    # for Dolphin, but support it in both forms for future profiles)
    item["adler32"].update(parse_hash_list(f.get("known_hash_adler32") or f.get("adler32")))
    if f.get("adler32_byteswap"):
        item["adler32_byteswap"] = True


def _expected_values(f: dict, checks: list[str]) -> dict:
    """The values an entry's checks compare, for ground truth reporting."""
    expected: dict = {}
    if "size" in checks:
        for key in ("size", "min_size", "max_size", "size_multiple"):
            if f.get(key) is not None:
                expected[key] = f[key]
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if hash_type in checks and f.get(hash_type):
            expected[hash_type] = f[hash_type]
    adler_val_pe = f.get("known_hash_adler32") or f.get("adler32")
    if adler_val_pe:
        expected["adler32"] = adler_val_pe
    for check in sorted(CONTENT_CHECKS & set(checks)):
        expected[check] = f.get(check) or {}
    return expected


def _merge_per_emulator(item: dict, emu_name: str, f: dict, checks: list[str]) -> None:
    # Per-emulator ground truth detail
    pe = item["per_emulator"]
    expected = _expected_values(f, checks)
    if emu_name in pe:
        # Merge checks from multiple file entries for same emulator
        existing = pe[emu_name]
        merged_checks = sorted(
            set(existing["checks"]) | set(checks)
        )
        existing["checks"] = merged_checks
        existing["expected"].update(expected)
        if f.get("source_ref") and not existing["source_ref"]:
            existing["source_ref"] = f.get("source_ref")
    else:
        pe[emu_name] = {
            "checks": sorted(checks),
            "source_ref": f.get("source_ref"),
            "expected": expected,
        }


def _index_entry(index: dict[str, dict], emu_name: str, f: dict, checks: list[str]) -> None:
    """Merge one checked profile entry into the index."""
    fname = f.get("name", "")
    if fname not in index:
        index[fname] = _new_index_entry()
    item = index[fname]
    item["rules"].append(_entry_rule(emu_name, f, checks))
    item["emulators"].add(emu_name)
    # A warned check is never a rejection, so it stays out of the
    # merged rejection rules.
    warned = warned_checks(f, set(checks))
    checks = [check for check in checks if check not in warned]
    if not checks:
        return
    item["checks"].update(checks)
    # Track non-reproducible crypto checks
    item["crypto_only"].update(c for c in checks if c in _CRYPTO_CHECKS)
    _merge_hashes(item, f, checks)
    _merge_per_emulator(item, emu_name, f, checks)


def build_validation_index(profiles: dict) -> dict[str, dict]:
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
        if not lists_files(profile):
            continue
        for f in _labels_widened(profile):
            fname = f.get("name", "")
            if not fname:
                continue
            checks = parse_validation(f.get("validation"))
            slot = (fname, emu_name, f.get("path") or fname)
            if not checks:
                unchecked.add(slot)
                continue
            checked.add(slot)
            _index_entry(index, emu_name, f, checks)
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
        if (
            check_type == "adler32" and detail.get("expected", {}).get("adler32")
            and emu not in result
        ):
            result.append(emu)
    return sorted(result)


def _merged_reason(reasons: list[str]) -> str:
    """One reason for every entry of a core that turned the copy away.

    Raze lists three BLOOD.RFF sizes and the message named the first one
    alone. Refusals of one check on one value are merged from their data
    into a single accepted list.
    """
    sized = [reason for reason in reasons if isinstance(reason, SizeRefusal)]
    if len(sized) == len(reasons) and len({reason.got for reason in sized}) == 1:
        return merged_size_refusal(sized)
    checked = [reason for reason in reasons if isinstance(reason, Refusal) and reason.check]
    if len(checked) == len(reasons) and len({(r.check, r.got) for r in checked}) == 1:
        first = checked[0]
        values = sorted({v for r in checked for v in r.values}, key=lambda v: (len(v), v))
        return _check_refusal(first.check, first.got, values,
                              all(r.accepted for r in checked))
    return reasons[0]


def check_file_validation(
    local_path: str,
    filename: str,
    validation_index: dict[str, dict],
    bios_dir: str = BIOS_DIR,
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
        return _per_emulator_failure(
            entry, local_path, filename, bios_dir, emulators, strict,
        )
    checks = entry["checks"]
    pe = entry.get("per_emulator", {})

    # Size checks: sizes is a set of accepted values
    if "size" in checks:
        refused = _merged_size_failure(entry, local_path, pe)
        if refused:
            return refused

    # A content test passes when one of the entries declaring it accepts
    # the file, each read as its own code reads it.
    for check in sorted(CONTENT_CHECKS & set(checks)):
        specs = [r["content"][check] for r in entry.get("rules", []) if check in r.get("content", {})]
        if specs and not any(
            content_fits({"validation": [check], check: spec}, local_path) for spec in specs
        ):
            return _CONTENT_REASONS[check], _emulators_for_check(check, pe)

    refused = _merged_hash_failure(entry, local_path, checks, pe)
    if refused:
        return refused

    # Signature/crypto checks (3DS RSA, AES)
    if entry["crypto_only"]:
        from core.cryptoverify import check_crypto_validation

        crypto_reason = check_crypto_validation(local_path, filename, bios_dir)
        if crypto_reason:
            emus = sorted(entry.get("emulators", []))
            return crypto_reason, emus

    return None


def _per_emulator_failure(
    entry: dict, local_path: str, filename: str, bios_dir: str,
    emulators: set[str], strict: bool,
) -> tuple[str, list[str]] | None:
    """Each core judges the file by its own entries for the name."""
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
        refused = [reason for reason in reasons if reason]
        if len(refused) == len(reasons):
            failures[emu] = _merged_reason(refused)
    if not failures:
        return None
    first = sorted(failures)[0]
    return failures[first], sorted(failures)


def _merged_size_failure(
    entry: dict, local_path: str, pe: dict[str, dict],
) -> tuple[str, list[str]] | None:
    """Refused only when every entry that checks the size turns it away.

    Each entry is judged by its own sizes: pooling one core's exact sizes
    with another's min_size refused the Apple IIGS ROM that gsplus takes.
    """
    rules = [
        r for r in entry.get("rules", [])
        if "size" in r["checks"] and "size" not in r["warn"]
    ]
    reasons = [_rule_size_failure(rule, local_path) for rule in rules]
    if not reasons or not all(reasons):
        return None
    return _merged_reason([r for r in reasons if r]), _emulators_for_check("size", pe)


def _merged_hash_failure(
    entry: dict, local_path: str, checks: list[str], pe: dict[str, dict],
) -> tuple[str, list[str]] | None:
    # Hash checks: compute once, reuse for all hash types.
    # Each hash field is a set of accepted values (multiple valid ROM versions).
    need_hashes = any(
        h in checks and entry.get(h) for h in ("crc32", "md5", "sha1", "sha256")
    ) or entry.get("adler32")
    if not need_hashes:
        return None
    hashes = compute_hashes(local_path)
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if (
            hash_type in checks and entry[hash_type]
            and hashes[hash_type].lower() not in entry[hash_type]
        ):
            emus = _emulators_for_check(hash_type, pe)
            return _hash_refusal(hash_type, hashes[hash_type], entry[hash_type]), emus
    if entry["adler32"]:
        actual_adler = hashes["adler32"].lower()
        if entry.get("adler32_byteswap"):
            actual_adler = _adler32_byteswapped(local_path)
        if actual_adler not in entry["adler32"]:
            emus = _emulators_for_check("adler32", pe)
            return _adler32_refusal(actual_adler, entry["adler32"]), emus
    return None
