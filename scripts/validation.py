"""Emulator-level file validation logic.

Builds validation indexes from emulator profiles, checks files against
emulator-declared constraints (size, hash, crypto), and formats ground
truth data for reporting.
"""

from __future__ import annotations

import os

from common import compute_hashes, size_fits
from hashing import parse_md5_list
from nativemode import digest_algorithm, hash_mismatch_excludes_file
from ziptools import check_inside_zip

# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these -size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})


def _adler32_byteswapped(path: str) -> str:
    """Compute adler32 on 16-bit byte-swapped data.

    Dolphin's DSP loader swaps every 16-bit word before hashing
    (Common::swap16 in DSPLLE.cpp:LoadDSPRom).  This reproduces that
    transform so verify.py can match the expected adler32 values.
    """
    import struct
    import zlib

    with open(path, "rb") as f:
        data = f.read()
    # Pad to even length if necessary
    if len(data) % 2:
        data += b"\x00"
    swapped = struct.pack(f">{len(data) // 2}H", *struct.unpack(f"<{len(data) // 2}H", data))
    return format(zlib.adler32(swapped) & 0xFFFFFFFF, "08x")

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
    for emu_name, profile in profiles.items():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files", []):
            fname = f.get("name", "")
            if not fname:
                continue
            checks = _parse_validation(f.get("validation"))
            if not checks:
                continue
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
                }
            index[fname]["emulators"].add(emu_name)
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
            # Hash checks -collect all accepted hashes as sets (multiple valid
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
            # Adler32 -stored as known_hash_adler32 field (not in validation: list
            # for Dolphin, but support it in both forms for future profiles)
            adler_val = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val:
                norm = adler_val.lower()
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


def check_file_validation(
    local_path: str,
    filename: str,
    validation_index: dict[str, dict],
    bios_dir: str = "bios",
) -> tuple[str, list[str]] | None:
    """Check emulator-level validation on a resolved file.

    Supports: size (exact/min/max), crc32, md5, sha1, adler32,
    signature (RSA-2048 PKCS1v15 SHA256), crypto (AES-128-CBC + SHA256).

    Returns None if all checks pass or no validation applies.
    Returns (reason, emulators) tuple on failure, where *emulators*
    lists only those cores whose check actually failed.
    """
    entry = validation_index.get(filename)
    if not entry:
        return None
    checks = entry["checks"]
    pe = entry.get("per_emulator", {})

    # Size checks -sizes is a set of accepted values
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

    # Hash checks -compute once, reuse for all hash types.
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


def validate_cli_modes(args, mode_attrs: list[str]) -> None:
    """Validate mutual exclusion of CLI mode arguments."""
    modes = sum(1 for attr in mode_attrs if getattr(args, attr, None))
    if modes == 0:
        raise SystemExit(f"Specify one of: --{'  --'.join(mode_attrs)}")
    if modes > 1:
        raise SystemExit(f"Options are mutually exclusive: --{'  --'.join(mode_attrs)}")


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


def find_validated_variant(
    file_entry: dict,
    db: dict,
    current_path: str,
    validation_index: dict,
    bios_dir: str = "bios",
    platform_digest: str | None = None,
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

    def candidates():
        expected = validation_index[fname]
        for hash_type, index_key in (
            ("sha1", None), ("md5", "by_md5"), ("crc32", "by_crc32"), ("sha256", "by_sha256"),
        ):
            for value in expected.get(hash_type) or []:
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
        if check_file_validation(path, fname, validation_index, bios_dir) is None:
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


def frontend_digest_matches(file_entry: dict, local_path: str, algorithm: str) -> bool:
    """Whether the frontend's own digest accepts the file.

    resolve_local_file calls a file `hash_mismatch` when any declared hash
    disagrees, but a frontend compares one digest. RomM's list carries md5,
    sha1 and crc32: a mistyped crc32 next to the right md5 must not withhold
    a file RomM accepts. Same comparison as verify_entry_md5/_sha1.
    """
    if algorithm == "md5":
        declared = parse_md5_list(file_entry.get("md5"))
    else:
        value = file_entry.get(algorithm)
        values = value if isinstance(value, list) else [value]
        declared = [str(v).strip().lower() for v in values if v]
    if not declared or not local_path:
        return False
    return compute_hashes(local_path)[algorithm].lower() in declared


def inner_rom_check(file_entry: dict, local_path: str) -> str:
    """How an archive answers an entry that pins a ROM inside it.

    Batocera, RetroBat and ROCKNIX hash a member of the ZIP, never the ZIP:
    the resolver hands back the archive as a mismatch and this decides it.
    Returns check_inside_zip's answer for the first accepted MD5 that
    matches, else for the last one tried. The pack and the install manifest
    both read it, so a file one of them ships is a file the other lists.
    """
    declared = [m.strip() for m in file_entry.get("md5", "").split(",") if m.strip()]
    result = "not_in_zip"
    for candidate in declared or [""]:
        result = check_inside_zip(local_path, file_entry["zipped_file"], candidate)
        if result == "ok":
            break
    return result


def settle_mismatch(
    file_entry: dict, local_path: str | None, status: str, verification_mode: str
) -> str:
    """Upgrade a hash mismatch the frontend itself would accept.

    Batocera pins the md5 of a ROM inside the archive (zipped_file), and a
    frontend that hashes one digest accepts a file whose other declared
    hashes disagree.
    """
    if status != "hash_mismatch" or not local_path:
        return status
    if file_entry.get("zipped_file"):
        return "zip_exact" if inner_rom_check(file_entry, local_path) == "ok" else status
    if hash_mismatch_excludes_file(verification_mode) and frontend_digest_matches(
        file_entry, local_path, digest_algorithm(verification_mode)
    ):
        return "frontend_digest_exact"
    return status
