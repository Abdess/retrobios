"""Per-file verdicts and their severity, in each platform's native mode."""

from __future__ import annotations

from core.hashing import compute_hashes, md5sum, parse_hash_list
from core.ziptools import check_inside_zip
from resolve.nativemode import SIZE_AND_ANY_HASH, reads_file_contents
from resolve.validation import (
    check_file_validation,
    existence_discrepancy,
    frontend_digest_matches,
    validated_choice,
)


# Status model: aligned with Batocera BiosStatus (batocera-systems:967-969)


class Status:
    OK = "ok"
    UNTESTED = "untested"  # file present, hash not confirmed: a warning, never --strict
    MISSING = "missing"


# A declaration whose file is a release asset the cache does not hold yet:
# an online build fetches it, verify reads the database record instead.
RELEASE_ASSET_PENDING = "release_asset_pending"


class Severity:
    CRITICAL = "critical"  # required file missing or bad hash (Recalbox RED)
    WARNING = "warning"  # optional missing or hash mismatch (Recalbox YELLOW)
    INFO = "info"  # optional missing on existence-only platform
    OK = "ok"  # file verified


STATUS_ORDER = {Status.OK: 0, Status.UNTESTED: 1, Status.MISSING: 2}
SEVERITY_ORDER = {
    Severity.OK: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.CRITICAL: 3,
}


# Verification functions


def verify_entry_existence(
    file_entry: dict,
    local_path: str | None,
    validation_index: dict[str, dict] | None = None,
    db: dict | None = None,
    destination: str = "",
    owners: dict | None = None,
    resolve_status: str = "",
    platform_display: str = "",
) -> dict:
    """RetroArch verification: path_is_valid(), a file that exists is OK.
    The result names the collection file found, as the hash modes do."""
    name = file_entry.get("name", "")
    required = file_entry.get("required", True)
    if not local_path:
        return {"name": name, "status": Status.MISSING, "required": required}
    result = {"name": name, "status": Status.OK, "required": required, "path": local_path}
    if resolve_status == "hash_mismatch":
        # The frontend reads no bytes, so the file stays, and the declared hash
        # it contradicts is reported, as the pack does.
        result["discrepancy"] = existence_discrepancy(
            file_entry, local_path, platform_display
        )
        return result
    if not validation_index:
        return result
    if db:
        # The pack ships the variant this returns, so a disagreement it
        # settles is not reported.
        _chosen, disagreement = validated_choice(
            file_entry, local_path, db, validation_index, "bios", None,
            destination, owners,
        )
    else:
        check = check_file_validation(local_path, name, validation_index)
        disagreement = f"{', '.join(check[1])} says {check[0]}" if check else None
    if disagreement:
        result["discrepancy"] = f"file present (OK) but {disagreement}"
    return result


def _verify_zipped_md5(
    base: dict, local_path: str, zipped_file: str, md5_list: list[str],
) -> dict:
    """The md5 check of an entry naming the ROM inside its ZIP (zipped_file)."""
    found_in_zip = False
    had_error = False
    for md5_candidate in md5_list or [""]:
        result = check_inside_zip(local_path, zipped_file, md5_candidate)
        if result == Status.OK:
            return {**base, "status": Status.OK, "path": local_path}
        if result == "error":
            had_error = True
        elif result != "not_in_zip":
            found_in_zip = True
    if had_error and not found_in_zip:
        return {
            **base,
            "status": Status.UNTESTED,
            "path": local_path,
            "reason": f"{local_path} read error",
        }
    if not found_in_zip:
        return {
            **base,
            "status": Status.UNTESTED,
            "path": local_path,
            "reason": f"{zipped_file} not found inside ZIP",
        }
    return {
        **base,
        "status": Status.UNTESTED,
        "path": local_path,
        "reason": f"{zipped_file} MD5 mismatch inside ZIP",
    }


def verify_entry_md5(
    file_entry: dict,
    local_path: str | None,
    resolve_status: str = "",
    hash_rule: str = "",
) -> dict:
    """MD5 verification -Batocera md5sum + Recalbox multi-hash + Md5Composite.

    Under SIZE_AND_ANY_HASH (RomM) the size and any one declared hash decide.
    """
    name = file_entry.get("name", "")
    expected_md5 = file_entry.get("md5", "")
    zipped_file = file_entry.get("zipped_file")
    required = file_entry.get("required", True)
    base = {"name": name, "required": required}

    # One parse for verify, the builder and the pack check: Recalbox writes
    # md5 in uppercase, and a copy that lowercased only comma lists judged
    # a single uppercase value differently from the others.
    md5_list = parse_hash_list(expected_md5)

    if not local_path:
        return {**base, "status": Status.MISSING}

    if hash_rule == SIZE_AND_ANY_HASH:
        if frontend_digest_matches(file_entry, local_path, "md5", hash_rule):
            return {**base, "status": Status.OK, "path": local_path}
        return {
            **base,
            "status": Status.UNTESTED,
            "path": local_path,
            "reason": "the declared size and at least one declared hash must match",
        }

    if zipped_file:
        return _verify_zipped_md5(base, local_path, zipped_file, md5_list)

    if not md5_list:
        if resolve_status == "hash_mismatch":
            # No md5 to compare does not mean nothing was compared: the entry
            # declares a sha1 or a crc32 the local file contradicts, and the
            # builder drops it for exactly that. Reporting OK here said the
            # collection holds bytes it does not.
            return {
                **base,
                "status": Status.UNTESTED,
                "path": local_path,
                "reason": "declared hash contradicted by the local file",
            }
        return {**base, "status": Status.OK, "path": local_path}

    if resolve_status == "md5_exact":
        return {**base, "status": Status.OK, "path": local_path}

    # The builder's comparison, so the two count the same files as held.
    if frontend_digest_matches(file_entry, local_path, "md5"):
        return {**base, "status": Status.OK, "path": local_path}
    actual_md5 = md5sum(local_path)
    return {
        **base,
        "status": Status.UNTESTED,
        "path": local_path,
        "reason": f"expected {md5_list[0][:12]}... got {actual_md5[:12]}...",
    }


def verify_entry_sha1(
    file_entry: dict,
    local_path: str | None,
) -> dict:
    """SHA1 verification -BizHawk firmware hash check."""
    name = file_entry.get("name", "")
    value = file_entry.get("sha1")
    expected = [str(v).strip().lower() for v in (value if isinstance(value, list) else [value]) if v]
    required = file_entry.get("required", True)
    base = {"name": name, "required": required}

    if not local_path:
        return {**base, "status": Status.MISSING}

    if not expected:
        return {**base, "status": Status.OK, "path": local_path}

    # The builder's comparison, so the two count the same files as held.
    if frontend_digest_matches(file_entry, local_path, "sha1"):
        return {**base, "status": Status.OK, "path": local_path}
    actual_sha1 = compute_hashes(local_path)["sha1"].lower()

    return {
        **base,
        "status": Status.UNTESTED,
        "path": local_path,
        "reason": f"expected {expected[0][:12]}... got {actual_sha1[:12]}...",
    }


# Severity mapping per platform


def emulator_severity(status: str, required: bool, hle_fallback: bool) -> str:
    """Severity when the emulator's own code is the check.

    A file present but refused by the core's validation, or a different dump
    than the one the profile declares, is not a file the core runs with:
    read in existence mode it counted OK, and `verify --emulator` announced
    1/1 OK above the line that said the core would refuse it.
    """
    if status == Status.UNTESTED:
        return Severity.WARNING
    return compute_severity(status, required, "existence", hle_fallback)


def compute_severity(
    status: str,
    required: bool,
    mode: str,
    hle_fallback: bool = False,
) -> str:
    """Map (status, required, verification_mode, hle_fallback) -> severity.

    Based on native platform behavior + emulator HLE capability:
    - RetroArch (existence): required+missing = warning, optional+missing = info
    - Batocera/Recalbox/RetroBat/EmuDeck (md5): hash-based verification
    - BizHawk (sha1): same severity rules as md5
    - hle_fallback: core works without this file via HLE -> always INFO when missing
    """
    if status == Status.OK:
        return Severity.OK

    # HLE fallback: core works without this file regardless of platform requirement
    if hle_fallback and status == Status.MISSING:
        return Severity.INFO

    if not reads_file_contents(mode):
        if status == Status.MISSING:
            return Severity.WARNING if required else Severity.INFO
        return Severity.OK

    # md5 mode (Batocera, Recalbox, RetroBat, EmuDeck)
    if status == Status.MISSING:
        return Severity.CRITICAL if required else Severity.WARNING
    if status == Status.UNTESTED:
        return Severity.WARNING
    return Severity.OK


def blocking_missing(severity_counts: dict[str, int], mode: str) -> int:
    """Destinations whose missing file stops the console, from verify's counts.

    compute_severity gives a required firmware gap with no HLE fallback
    CRITICAL where the frontend reads the bytes and WARNING where it only
    checks the file is there, and nothing else reaches that severity in an
    existence frontend.
    """
    severity = Severity.CRITICAL if reads_file_contents(mode) else Severity.WARNING
    return severity_counts.get(severity, 0)


def storage_verdict(file_entry: dict, emulator_pack: bool) -> dict | None:
    """The result a storage tier fixes before any lookup, as the builder sees it.

    A user_provided entry is never taken from the collection: a platform pack
    writes its instructions in the slot and counts it filled, an emulator pack
    lists it to provide. An external one is fetched from its URL when the pack
    is built, never read from bios/. Resolving either by name credited a
    same-named file the pack does not carry.
    """
    storage = file_entry.get("storage", "embedded")
    base = {"name": file_entry.get("name", ""), "required": file_entry.get("required", True)}
    if storage == "user_provided":
        if emulator_pack:
            stated = file_entry.get("unsourceable")
            why = (
                stated if isinstance(stated, str) and stated
                else file_entry.get("instructions") or "the user provides it"
            )
            return {**base, "status": Status.MISSING, "unsourceable": why}
        return {**base, "status": Status.OK, "user_provided": True}
    if storage == "external":
        return {**base, "status": Status.MISSING, "reason": "fetched from its URL when the pack is built"}
    return None
