"""Emulator-level file validation logic.

Builds validation indexes from emulator profiles, checks files against
emulator-declared constraints (size, hash, crypto), and formats ground
truth data for reporting.
"""

from __future__ import annotations

import os

from common import compute_hashes

# Validation types that require console-specific cryptographic keys.
# verify.py cannot reproduce these — size checks still apply if combined.
_CRYPTO_CHECKS = frozenset({"signature", "crypto"})

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
                    "checks": set(), "sizes": set(),
                    "min_size": None, "max_size": None,
                    "crc32": set(), "md5": set(), "sha1": set(), "sha256": set(),
                    "adler32": set(), "crypto_only": set(),
                    "emulators": set(), "per_emulator": {},
                }
            index[fname]["emulators"].add(emu_name)
            index[fname]["checks"].update(checks)
            # Track non-reproducible crypto checks
            index[fname]["crypto_only"].update(
                c for c in checks if c in _CRYPTO_CHECKS
            )
            # Size checks
            if "size" in checks:
                if f.get("size") is not None:
                    index[fname]["sizes"].add(f["size"])
                if f.get("min_size") is not None:
                    cur = index[fname]["min_size"]
                    index[fname]["min_size"] = min(cur, f["min_size"]) if cur is not None else f["min_size"]
                if f.get("max_size") is not None:
                    cur = index[fname]["max_size"]
                    index[fname]["max_size"] = max(cur, f["max_size"]) if cur is not None else f["max_size"]
            # Hash checks — collect all accepted hashes as sets (multiple valid
            # versions of the same file, e.g. MT-32 ROM versions)
            if "crc32" in checks and f.get("crc32"):
                crc_val = f["crc32"]
                crc_list = crc_val if isinstance(crc_val, list) else [crc_val]
                for cv in crc_list:
                    norm = str(cv).lower()
                    if norm.startswith("0x"):
                        norm = norm[2:]
                    index[fname]["crc32"].add(norm)
            for hash_type in ("md5", "sha1", "sha256"):
                if hash_type in checks and f.get(hash_type):
                    val = f[hash_type]
                    if isinstance(val, list):
                        for h in val:
                            index[fname][hash_type].add(str(h).lower())
                    else:
                        index[fname][hash_type].add(str(val).lower())
            # Adler32 — stored as known_hash_adler32 field (not in validation: list
            # for Dolphin, but support it in both forms for future profiles)
            adler_val = f.get("known_hash_adler32") or f.get("adler32")
            if adler_val:
                norm = adler_val.lower()
                if norm.startswith("0x"):
                    norm = norm[2:]
                index[fname]["adler32"].add(norm)
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
                merged_checks = sorted(set(existing["checks"]) | set(pe_entry["checks"]))
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
        result.append({
            "emulator": emu_name,
            "checks": detail["checks"],
            "source_ref": detail.get("source_ref"),
            "expected": detail.get("expected", {}),
        })
    return result


def check_file_validation(
    local_path: str, filename: str, validation_index: dict[str, dict],
    bios_dir: str = "bios",
) -> str | None:
    """Check emulator-level validation on a resolved file.

    Supports: size (exact/min/max), crc32, md5, sha1, adler32,
    signature (RSA-2048 PKCS1v15 SHA256), crypto (AES-128-CBC + SHA256).

    Returns None if all checks pass or no validation applies.
    Returns a reason string if a check fails.
    """
    entry = validation_index.get(filename)
    if not entry:
        return None
    checks = entry["checks"]

    # Size checks — sizes is a set of accepted values
    if "size" in checks:
        actual_size = os.path.getsize(local_path)
        if entry["sizes"] and actual_size not in entry["sizes"]:
            expected = ",".join(str(s) for s in sorted(entry["sizes"]))
            return f"size mismatch: got {actual_size}, accepted [{expected}]"
        if entry["min_size"] is not None and actual_size < entry["min_size"]:
            return f"size too small: min {entry['min_size']}, got {actual_size}"
        if entry["max_size"] is not None and actual_size > entry["max_size"]:
            return f"size too large: max {entry['max_size']}, got {actual_size}"

    # Hash checks — compute once, reuse for all hash types.
    # Each hash field is a set of accepted values (multiple valid ROM versions).
    need_hashes = (
        any(h in checks and entry.get(h) for h in ("crc32", "md5", "sha1", "sha256"))
        or entry.get("adler32")
    )
    if need_hashes:
        hashes = compute_hashes(local_path)
        for hash_type in ("crc32", "md5", "sha1", "sha256"):
            if hash_type in checks and entry[hash_type]:
                if hashes[hash_type].lower() not in entry[hash_type]:
                    expected = ",".join(sorted(entry[hash_type]))
                    return f"{hash_type} mismatch: got {hashes[hash_type]}, accepted [{expected}]"
        if entry["adler32"]:
            if hashes["adler32"].lower() not in entry["adler32"]:
                expected = ",".join(sorted(entry["adler32"]))
                return f"adler32 mismatch: got 0x{hashes['adler32']}, accepted [{expected}]"

    # Signature/crypto checks (3DS RSA, AES)
    if entry["crypto_only"]:
        from crypto_verify import check_crypto_validation
        crypto_reason = check_crypto_validation(local_path, filename, bios_dir)
        if crypto_reason:
            return crypto_reason

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
