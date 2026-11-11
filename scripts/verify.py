#!/usr/bin/env python3
"""Platform-native BIOS verification engine.

Replicates the exact verification logic of each platform:
- RetroArch/Lakka/RetroPie: file existence only (core_info.c path_is_valid)
- Batocera: MD5 + checkInsideZip, no required distinction (batocera-systems:1062-1091)
- Recalbox: MD5 + mandatory/hashMatchMandatory, 3-color severity (Bios.cpp:109-130)
- RetroBat: same as Batocera
- EmuDeck: MD5 whitelist per system
- RetroDECK: MD5 per file via component manifests
- RomM: size + any hash, no ZIP inspection (firmware.py verify_file_hashes)
- ROCKNIX: MD5 + checkInsideZip with altmd5 (rocknix-systems checkBios)
- MiSTer FPGA: MD5 of the file at its destination, no ZIP inspection
- BizHawk: SHA1 firmware hash verification

Cross-references emulator profiles to detect undeclared files used by available cores.

Usage:
    python scripts/verify.py --all
    python scripts/verify.py --platform batocera
    python scripts/verify.py --all --json
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path

import slots

sys.path.insert(0, os.path.dirname(__file__))
from hashing import parse_md5_list
from alternatives import (
    core_file_spares,
    set_fields,
    set_keys,
    set_requirements,
    settle_sets,
    slot_set_keys,
)
from common import (
    TARGET_KEY,
    canonical_target_name,
    OUTER_ROOTS,
    _foreign_tree,
    _owner_tokens,
    platform_arg,
    work_from_repo_root,
    target_listing_line,
    suggest_names,
    system_index,
    require_platform,
    archive_entry,
    archive_is_optional,
    archive_members,
    profiles_for_systems,
    PROFILE_IDENTITY_FIELDS,
    list_available_targets,
    list_platform_system_ids,
    list_registered_platforms,
    build_target_cores_cache,
    build_zip_contents_index,
    check_inside_zip,
    compute_hashes,
    expand_directory_entries,
    platform_declarations,
    platform_declared_contents,
    group_identical_platforms,
    list_emulator_profiles,
    list_system_ids,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    load_platform_config,
    without_profile_blind,
    resolve_system_arg,
    print_platform_listing,
    select_systems,
    platform_scope_systems,
    system_scope_error,
    md5sum,
    require_yaml,
    resolve_local_file,
    ProfileSelectionError,
    resolve_platform_cores,
    platform_layouts,
    runs_standalone,
    standalone_set as platform_standalone_set,
    entry_serves_systems,
    entry_system_ids,
    sanitize_pack_path,
    select_emulator_profiles,
    system_dir_path,
)

yaml = require_yaml()
from exporter.candidates import BIOS, EntryCategories
from launchers import LauncherLayer, declared_destinations, held_record, launcher_unproven
from cross_reference import launcher_reads_not_held
from nativemode import (
    SIZE_AND_ANY_HASH,
    digest_algorithm,
    hash_mismatch_excludes_file,
    normalize as normalize_mode,
    reads_file_contents,
)
from validation import (
    baseline_verdict,
    case_folded_slots,
    declaration_settles,
    frontend_digest_matches,
    existence_discrepancy,
    destination_owners,
    validated_choice,
    agnostic_substitute,
    _build_validation_index,
    _parse_validation,
    build_ground_truth,
    check_file_validation,
    deliverable,
    installed_with_emulator,
    unread_on,
    outside_gap_scope,
    read_from_save_dir,
    with_archive_members,
    core_size_refusal,
    same_slot_entries,
)
from packpaths import core_save_folder

DEFAULT_DB = "database.json"
DEFAULT_PLATFORMS_DIR = "platforms"
DEFAULT_BIOS_DIR = "bios"
# The repository's platforms wherever the script runs from, for library calls
# that pass no directory.
_REPO_PLATFORMS = os.path.join(os.path.dirname(__file__), "..", "platforms")
DEFAULT_EMULATORS_DIR = "emulators"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


_STATUS_ORDER = {Status.OK: 0, Status.UNTESTED: 1, Status.MISSING: 2}
_SEVERITY_ORDER = {
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
    md5_list = parse_md5_list(expected_md5)

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
    expected_sha1 = file_entry.get("sha1", "")
    required = file_entry.get("required", True)
    base = {"name": name, "required": required}

    if not local_path:
        return {**base, "status": Status.MISSING}

    if not expected_sha1:
        return {**base, "status": Status.OK, "path": local_path}

    hashes = compute_hashes(local_path)
    actual_sha1 = hashes["sha1"].lower()
    if actual_sha1 == expected_sha1.lower():
        return {**base, "status": Status.OK, "path": local_path}

    return {
        **base,
        "status": Status.UNTESTED,
        "path": local_path,
        "reason": f"expected {expected_sha1[:12]}... got {actual_sha1[:12]}...",
    }


# Severity mapping per platform


def _emulator_severity(status: str, required: bool, hle_fallback: bool) -> str:
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


# Cross-reference: undeclared files used by cores


def _build_expected(file_entry: dict, checks: list[str]) -> dict:
    """Extract expected validation values from an emulator profile file entry."""
    expected: dict = {}
    if not checks:
        return expected
    if "size" in checks:
        for key in ("size", "min_size", "max_size", "size_multiple"):
            if file_entry.get(key) is not None:
                expected[key] = file_entry[key]
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if hash_type in checks and file_entry.get(hash_type):
            expected[hash_type] = file_entry[hash_type]
    adler_val = file_entry.get("known_hash_adler32") or file_entry.get("adler32")
    if adler_val:
        expected["adler32"] = adler_val
    return expected


def _in_foreign_tree(db: dict, owners: set[str], sha1: str) -> bool:
    """Whether the collection keeps this sha1 in another emulator's tree."""
    return _foreign_tree(db.get("files", {}).get(sha1, {}).get("path", ""), owners)


def _name_in_index(
    name: str,
    by_name: dict,
    by_path_suffix: dict | None = None,
    data_names: set[str] | None = None,
    by_name_lower: dict[str, str] | None = None,
    foreign: Callable[[str], bool] | None = None,
) -> bool:
    """Check if a name is resolvable in the database indexes or data directories.

    *foreign* tells a copy in another emulator's tree from the sha1 of a
    name: matched in another casing, such a copy is not the asker's, as in
    resolve_local_file's case-insensitive step.
    """
    # Strip trailing slash for directory-type entries (e.g. nestopia/samples/foo/)
    name = name.rstrip("/")
    if name in by_name:
        return True
    basename = name.rsplit("/", 1)[-1] if "/" in name else name
    if basename != name and basename in by_name:
        return True
    if by_name_lower:
        for key in {name.lower(), basename.lower()}:
            if key in by_name_lower and not (
                foreign and all(foreign(s) for s in by_name[by_name_lower[key]])
            ):
                return True
    if by_path_suffix and name in by_path_suffix:
        return True
    if data_names:
        if name in data_names or name.lower() in data_names:
            return True
        if basename != name and (
            basename in data_names or basename.lower() in data_names
        ):
            return True
    return False


def _candidate_verdict(
    file_entry: dict,
    fname: str,
    is_standalone: bool,
    include_all: bool,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | set[str],
    dest: str = "",
    folded_slots: frozenset[str] = frozenset(),
    declared_contents: Mapping[str, set[str]] | None = None,
) -> str:
    """Whether a profile entry can be a gap, and whether it is settled.

    Three answers. "keep" means it is a candidate. "settled" means something
    has answered for it (the platform declares it, or the profile documents
    it as unsourceable), so the same requirement reached from another profile
    must not be reconsidered. "skip" means it does not apply in this context,
    which leaves it open for a profile where it does: the same file can be
    libretro-only here and standalone-only there.
    """
    if file_entry.get("unsourceable"):
        return "settled"
    if outside_gap_scope(file_entry, is_standalone):
        return "skip"
    if not include_all and declaration_settles(
        file_entry, fname, declared_names, dest, folded_slots, declared_contents
    ):
        return "settled"
    return "keep"


def _identity_of(entry: dict) -> dict:
    """The fields that tell a profile's file apart from a same-named one."""
    return {
        field: entry.get(field)
        for field in PROFILE_IDENTITY_FIELDS
        if entry.get(field) not in (None, "", [])
    }


def find_undeclared_files(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    data_names: set[str] | None = None,
    include_all: bool = False,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | None = None,
) -> list[dict]:
    """Find files needed by cores but not declared in platform config.

    declared_names overrides the default enriched declarations from
    platform_declarations.  Pass the strict ones (YAML names only) when
    building packs so alias-only names still get packed.
    """
    if declared_names is None:
        declared_names = platform_declarations(config, db)
    folded_slots = case_folded_slots(config, declared_names)
    declared_contents = platform_declared_contents(config, db)

    # Whether the builder drops a file whose local copy contradicts its
    # declared hash, which decides if such a copy counts as held here.
    shipped_on_mismatch = hash_mismatch_excludes_file(
        config.get("verification_mode")
    )

    declared_dd: set[str] = set()
    for sys_id, system in config.get("systems", {}).items():
        for dd in system.get("data_directories", []):
            ref = dd.get("ref", "")
            if ref:
                declared_dd.add(ref)

    by_name = db.get("indexes", {}).get("by_name", {})
    by_name_lower = {k.lower(): k for k in by_name}
    by_path_suffix = db.get("indexes", {}).get("by_path_suffix", {})
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    standalone_set = platform_standalone_set(config)
    # What the platform's own launchers open, matched to the cores it runs:
    # the one decision the builder and this report both read.
    launcher_layer = LauncherLayer(
        config, profiles, relevant, db, declared_destinations(config)
    )
    launcher_candidates: list[tuple[str, bool, dict, dict]] = []
    # Each grouped requirement met, as (set keys, entry, fills, (reported
    # entry, the entry it is a claim on)): settled once every core is read.
    set_records: list[tuple[tuple, dict, bool, tuple[dict, dict | None] | None]] = []
    undeclared = []
    seen_files: set[tuple] = set()
    # Key -> the entry reported for it. A later profile reading the same
    # requirement is kept on that entry rather than counted again: a pack
    # built without the first profile still has to name the file.
    reported: dict[tuple, dict] = {}
    # Track archives: archive_name -> {in_repo, emulator, files: [...], ...}
    archive_entries: dict[tuple, dict] = {}

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue

        # A filename-agnostic profile is served by the scan (packextras), all
        # but the entries its layout reads outside the BIOS tree: those are
        # named here, or a launcher folder drops them without a word
        # (ARMSX2's arcade/proverb.zip once ROCKNIX binds bios/armsx2).
        agnostic = profile.get("bios_mode") == "agnostic"

        for profile, is_standalone in platform_layouts(emu_name, profile, standalone_set):

            for f in expand_directory_entries(
                profile.get("files", []), db, is_standalone
            ):
                if agnostic and not f.get("unplaced"):
                    continue
                fname = f.get("name", "")
                # One destination rule for the dedup key and for the entry: a
                # standalone build without standalone_path falls back on path.
                # The key used to skip that fallback, so clk's Acorn/basic.rom and
                # Electron/basic.rom both keyed as "basic.rom" under Batocera's
                # standalone clk and the second was dropped.
                # A file the libretro build reads below the save directory is
                # placed there, apart from the system directory the platform
                # lays out: no declaration of the BIOS tree answers for it.
                save_root = read_from_save_dir(f, is_standalone)
                if is_standalone:
                    dest = f.get("standalone_path") or f.get("path") or fname
                elif save_root:
                    dest = f.get("path") or fname
                else:
                    dest = system_dir_path(f, f.get("path") or fname)
                raw_regions = f.get("region") or []
                region_key = tuple(
                    str(value) for value in (
                        raw_regions if isinstance(raw_regions, list) else [raw_regions]
                    )
                )
                # Same-name requirements at different paths, for different systems,
                # or in distinct variant groups are not interchangeable.
                seen_key = (
                    fname,
                    f.get("archive"),
                    dest,
                    f.get("system"),
                    f.get("selection_slot"),
                    region_key,
                    # Below the save directory each core is handed a folder
                    # of its own: two cores reading hiscore.dat there read
                    # two files.
                    ("save", core_save_folder(profile)) if save_root
                    else (f["root"],) if f.get("root") in OUTER_ROOTS
                    # In the emulator's own folder: no other core reads it.
                    else ("emulator", emu_name) if f.get("unplaced") else None,
                )
                if not fname or unread_on(f, config.get("_key", "")):
                    continue
                first = reported.get(seen_key)
                duplicate = seen_key in seen_files
                if duplicate and (first is None or first["profile"] == emu_name):
                    continue
                # Nor does it answer for one read below the roms directory.
                verdict = _candidate_verdict(
                    f, fname, is_standalone, include_all,
                    {} if save_root or f.get("root") in OUTER_ROOTS else declared_names,
                    dest, folded_slots,
                    None if save_root or f.get("root") in OUTER_ROOTS else declared_contents,
                )
                if verdict == "settled":
                    seen_files.add(seen_key)
                    if (launcher_layer and not f.get("unsourceable") and not save_root
                            and f.get("root") not in OUTER_ROOTS and not f.get("unplaced")):
                        launcher_layer.declared_elsewhere(emu_name, is_standalone, f)
                    # Answered by the platform's own declaration, which its
                    # report covers: the set it belongs to is spoken for.
                    set_records.append((set_keys((emu_name, is_standalone), f), f, True, None))
                    continue
                if verdict == "skip":
                    continue

                archive = f.get("archive")
                seen_files.add(seen_key)

                if archive:
                    archive_key = (
                        archive,
                        f.get("system_dir"),
                        f.get("system"),
                        f.get("selection_slot"),
                        region_key,
                        is_standalone,
                    )
                    if archive_key not in archive_entries:
                        in_repo = _name_in_index(
                            archive, by_name, by_path_suffix, data_names,
                            by_name_lower,
                        )
                        archive_entries[archive_key] = {
                            "profile": emu_name,
                            "emulator": profile.get("emulator", emu_name),
                            "systems": entry_system_ids(f, profile),
                            "system": f.get("system"),
                            "region": f.get("region"),
                            "selection_slot": f.get("selection_slot"),
                            "name": archive,
                            "archive": archive,
                            "path": system_dir_path(f, archive),
                            "required": False,
                            "hle_fallback": False,
                            "category": f.get("category", "bios"),
                            "in_repo": in_repo,
                            "note": "",
                            "checks": [],
                            "source_ref": None,
                            "expected": {},
                            "archive_file_count": 0,
                            "archive_required_count": 0,
                            "members": archive_members(archive, profile.get("files", [])),
                        }
                        if f.get("system_dir"):
                            archive_entries[archive_key]["system_dir"] = f["system_dir"]
                        # The archive's own declaration names its sets: an
                        # archive is a member like a loose file.
                        own = archive_entry(archive, profile.get("files", []))
                        archive_entries[archive_key].update(set_fields(own, profile))
                        set_records.append((
                            set_keys((emu_name, is_standalone), own), own, in_repo,
                            (archive_entries[archive_key], None),
                        ))
                    entry = archive_entries[archive_key]
                    entry["archive_file_count"] += 1
                    if f.get("required", False):
                        entry["archive_required_count"] += 1
                        entry["required"] = True
                    continue

                # Resolution: name, then path basename
                # storage: release names where the bytes are served from, not
                # that the collection holds them: resolved like any file.
                # Resolved as the asker, as the builder's ExtraResolver does:
                # another casing of the name in another emulator's tree is
                # not this emulator's file (dosbox-x's et4000.bin and pcem's
                # et4000.BIN).
                owned = {**f, "source_profile": emu_name}
                foreign = functools.partial(_in_foreign_tree, db, _owner_tokens(owned))
                if shipped_on_mismatch and (f.get("md5") or f.get("sha1")):
                    # The entry states what its content should be and the builder
                    # drops a copy that contradicts it, so content decides here
                    # too. A name match would not do: generic names collide across
                    # systems, and answering yes on one describes a pack that will
                    # not contain the file.
                    _lp, _st = resolve_local_file(owned, db, dest_hint=dest)
                    in_repo = _lp is not None and _st != "hash_mismatch"
                else:
                    in_repo = _name_in_index(
                        fname, by_name, by_path_suffix, data_names, by_name_lower,
                        foreign,
                    )
                    if not in_repo and dest != fname:
                        path_base = dest.rsplit("/", 1)[-1]
                        in_repo = _name_in_index(
                            path_base, by_name, by_path_suffix, data_names,
                            by_name_lower, foreign,
                        )
                    if in_repo and not any(
                        f.get(h) for h in ("sha1", "md5", "crc32", "sha256")
                    ):
                        # A name alone answers nothing when every copy of that
                        # name fails the size the code checks: the resolver
                        # rejects them all. NanoBoyAdvance's 16 KB bios.bin met
                        # only PCem's and QEMU's PC BIOS images of that name.
                        # The fallback below then decides as for any mismatch.
                        _lp, _st = resolve_local_file(owned, db, dest_hint=dest)
                        if _st == "hash_mismatch":
                            in_repo = False
                    if not in_repo:
                        # Hash fallback: the repo may hold the content under a
                        # different filename (exos21.rom vs exos21.bin).
                        #
                        # A copy contradicting the declared hash counts as held
                        # only where the builder would ship it. Under existence
                        # the frontend never opens the file, so the pack carries
                        # it and reports the divergence. Under a digest mode the
                        # frontend would reject it, the builder leaves it out, and
                        # calling it available here would describe a pack that
                        # does not contain it.
                        _lp, _st = resolve_local_file(owned, db, dest_hint=dest)
                        in_repo = _st != "not_found" and _lp is not None
                        if in_repo and _st == "hash_mismatch" and shipped_on_mismatch:
                            in_repo = False
                    if in_repo and "size" in _parse_validation(f.get("validation")):
                        # On any platform the core measures what it opens: a
                        # copy it turns away by its own size check is not
                        # held for it, the rule the builder's lookup applies
                        # (packextras.ExtraResolver). The Apple IIGS' 128 KB
                        # ROM is not Basilisk II's ROM.
                        _lp, _st = resolve_local_file(owned, db, dest_hint=dest)
                        if core_size_refusal(
                            f, _lp, same_slot_entries(profile.get("files"), fname, dest)
                        ):
                            in_repo = False

                checks = _parse_validation(f.get("validation"))
                entry = {
                    "profile": emu_name,
                    "emulator": profile.get("emulator", emu_name),
                    "systems": entry_system_ids(f, profile),
                    "system": f.get("system"),
                    "region": f.get("region"),
                    "selection_slot": f.get("selection_slot"),
                    "name": fname,
                    "path": dest,
                    "required": f.get("required", False),
                    "hle_fallback": f.get("hle_fallback", False),
                    "bundled": installed_with_emulator(f, config.get("_key", "")),
                    "category": f.get("category", "bios"),
                    "in_repo": in_repo,
                    "note": f.get("note", ""),
                    "checks": sorted(checks) if checks else [],
                    **set_fields(f, profile),
                    "source_ref": f.get("source_ref"),
                    "expected": _build_expected(f, checks),
                    **_identity_of(f),
                    "sha1": f.get("sha1"),
                    "md5": f.get("md5"),
                }
                if f.get("contents"):
                    entry["contents"] = f["contents"]
                if save_root:
                    entry["root"] = "save"
                    folder = core_save_folder(profile)
                    if folder is not None:
                        entry["core_folder"] = folder
                elif f.get("system_dir"):
                    entry["system_dir"] = f["system_dir"]
                members = with_archive_members(f, profile.get("files", [])).get("members")
                if members:
                    entry["members"] = members
                if f.get("layout_path"):
                    entry["layout_path"] = f["layout_path"]
                if f.get("unprefixed"):
                    entry["unprefixed"] = True
                if f.get("unplaced"):
                    entry["unplaced"] = f["unplaced"]
                elif f.get("root") in OUTER_ROOTS:
                    # Read below the roms directory (ROCKNIX's roms/pico-8)
                    # or in an emulator folder (RetroBat's emulators/pico8).
                    entry["root"] = f["root"]
                if launcher_layer and not save_root and f.get("root") not in OUTER_ROOTS:
                    # One read outside the BIOS tree is still served where a
                    # launcher links that very file: RetroDECK links Cemu's
                    # keys.txt to bios/cemu/keys.txt.
                    launcher_candidates.append((emu_name, is_standalone, f, entry))
                keys = set_keys((emu_name, is_standalone), f)
                if duplicate:
                    first.setdefault("other_claims", []).append(entry)
                    set_records.append((keys, f, in_repo, (entry, first)))
                    continue
                reported[seen_key] = entry
                undeclared.append(entry)
                set_records.append((keys, f, in_repo, (entry, None)))

    settled: set[int] = set()
    if launcher_layer:
        added, settled = launcher_layer.settle(
            launcher_candidates, lambda report: held_record(report, db)
        )
        undeclared = [u for u in undeclared if id(u) not in settled]
        undeclared.extend(added)

    for entry in sorted(archive_entries.values(), key=lambda e: e["name"]):
        undeclared.append(entry)

    return _split_bundled_claims(
        _settle_core_sets(undeclared, set_records, settled, profiles)
    )


def _split_bundled_claims(undeclared: list[dict]) -> list[dict]:
    """A file one emulator installs itself, another reads from the pack.

    The first profile reading a requirement hosts the claims of the others,
    and a host installed with its emulator is left out of the pack with all
    of them: DraStic brings its own usrcheat.dat, and ROCKNIX's DSPerate,
    which reads the same file, lost it wherever DraStic runs too. Built for
    a board without DraStic, the pack carried it.
    """
    out: list[dict] = []
    for entry in undeclared:
        claims = entry.get("other_claims") or []
        rest = [c for c in claims if not c.get("bundled")]
        if not entry.get("bundled") or not rest:
            out.append(entry)
            continue
        own = [c for c in claims if c.get("bundled")]
        kept = {k: v for k, v in entry.items() if k != "other_claims"}
        if own:
            kept["other_claims"] = own
        promoted = dict(rest[0])
        if rest[1:]:
            promoted["other_claims"] = rest[1:]
        out += [kept, promoted]
    return out


def _settle_core_sets(
    undeclared: list[dict],
    records: list[tuple[tuple, dict, bool, tuple[dict, dict | None] | None]],
    launcher_settled: set[int],
    profiles: dict[str, dict],
) -> list[dict]:
    """The core complement with each set of alternatives settled.

    A member the collection lacks is dropped when another member is held,
    declared by the platform or placed by its launcher, and a set nobody
    holds keeps one entry, its first member, naming the others. A claim
    another profile shares stays: its own core may need that very file.
    """
    # Archive units rank first among equals, as the builder orders them.
    grouped = sorted(
        (r for r in records if r[0]),
        key=lambda r: not (r[3] is not None and r[3][0].get("archive")),
    )
    if not grouped:
        return undeclared
    excused, standing = settle_sets([
        (keys, f, fills or (ref is not None and id(ref[0]) in launcher_settled))
        for keys, f, fills, ref in grouped
    ], lambda key: set_requirements(profiles.get(key[0][0], {})).get(key[1], True))
    declared_sets = {
        key for keys, _f, _fills, ref in grouped if ref is None for key in keys
    }
    dropped: set[int] = set()
    for position, (keys, _f, _fills, ref) in enumerate(grouped):
        if ref is None:
            continue
        entry, host = ref
        required_keys = [k for k in keys if k[1] in entry.get("required_groups", ())]
        if required_keys and all(k in declared_sets for k in required_keys):
            # The platform declares a member of each of its required sets:
            # under --required-only that declaration carries them.
            entry["set_declared"] = True
        if position in standing:
            entry["alternatives"] = standing[position].others
            entry["required"] = standing[position].required
        if position not in excused:
            continue
        if host is not None:
            host["other_claims"] = [c for c in host.get("other_claims", []) if c is not entry]
            if not host["other_claims"]:
                del host["other_claims"]
        else:
            dropped.add(id(entry))
    out: list[dict] = []
    for entry in undeclared:
        if id(entry) not in dropped:
            out.append(entry)
            continue
        # Another core reading the same requirement still needs it.
        claims = entry.get("other_claims") or []
        if claims:
            promoted = dict(claims[0])
            if claims[1:]:
                promoted["other_claims"] = claims[1:]
            out.append(promoted)
    return out


def find_exclusion_notes(
    config: dict,
    emulators_dir: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
) -> list[dict]:
    """Document why certain emulator files are intentionally excluded.

    Reports:
    - Launchers (BIOS managed by standalone emulator)
    - Standalone-only files (not needed in libretro mode)
    - Frozen snapshots with files: [] (code doesn't load .info firmware)
    - Files covered by data_directories
    """
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )
    platform_systems = set()
    for sys_id in config.get("systems", {}):
        platform_systems.add(sys_id)

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    notes = []
    for emu_name, profile in sorted(profiles.items()):
        emu_systems = set(profile.get("systems", []))
        # Match by core resolution OR system intersection (documents all potential emulators)
        if emu_name not in relevant and not (emu_systems & platform_systems):
            continue

        emu_display = profile.get("emulator", emu_name)

        if profile.get("type") == "launcher":
            notes.append(
                {
                    "emulator": emu_display,
                    "reason": "launcher",
                    "detail": profile.get(
                        "exclusion_note", "BIOS managed by standalone emulator"
                    ),
                }
            )
            continue

        # Profile-level exclusion note (frozen snapshots, etc.)
        exclusion_note = profile.get("exclusion_note")
        if exclusion_note:
            notes.append(
                {
                    "emulator": emu_display,
                    "reason": "exclusion_note",
                    "detail": exclusion_note,
                }
            )
            continue

        # Count standalone-only files, but only report as excluded if the
        # platform does NOT use this emulator in standalone mode
        standalone_set = platform_standalone_set(config)
        is_standalone = runs_standalone(emu_name, profile, standalone_set)
        if not is_standalone:
            standalone_files = [
                f for f in profile.get("files", []) if f.get("mode") == "standalone"
            ]
            if standalone_files:
                names = [f["name"] for f in standalone_files[:3]]
                more = (
                    f" +{len(standalone_files) - 3}"
                    if len(standalone_files) > 3
                    else ""
                )
                notes.append(
                    {
                        "emulator": emu_display,
                        "reason": "standalone_only",
                        "detail": f"{len(standalone_files)} files for standalone mode only ({', '.join(names)}{more})",
                    }
                )

    return notes


# Platform verification


_UNPLACED_REASONS = {
    "outside_bios_folder": "read in a folder the platform keeps outside the BIOS tree",
    "no_roms_directory": "read below a roms folder the platform's registry does not name",
    "no_emulators_directory": "read in an emulator folder the platform's registry does not describe",
    "no_configs_directory": "read below a configs folder the platform's file does not record",
    "no_platform_slug": "no platform slug for its system",
    "below_platform_folder": "below the folder the platform lists",
    "no_save_directory": "read below a save directory the platform keeps in no fixed place",
    "no_core_folder": "read below the save directory and the profile names no library_name",
    "no_save_system": "read below a save folder per system and no system runs the core there",
}


def _mark_unplaced(config: dict, undeclared: list[dict], profiles: dict) -> None:
    """What the builder cannot place is not in the pack, held or not."""
    from packextras import unplaceable_extras

    unplaced = unplaceable_extras(config, undeclared, profiles)
    for u in undeclared:
        if u.get("bundled"):
            # Installed with the emulator, so already on the user's machine:
            # the pack leaves it out, held or not.
            u["in_pack"] = False
            u["omitted"] = "installed with its emulator"
            continue
        reason = unplaced.get(
            (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
        )
        if not reason and u.get("root") in OUTER_ROOTS:
            # The pack is extracted into the BIOS folder: the installer
            # writes this file into the roms or emulator folder, the pack
            # cannot.
            u["in_pack"] = False
            u["omitted"] = f"read below the {u['root']} folder, which only the installer reaches"
            continue
        if reason:
            u["in_pack"] = False
            u["omitted"] = _UNPLACED_REASONS[reason]


def _storage_verdict(file_entry: dict, emulator_pack: bool) -> dict | None:
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


_HIDDEN_REASONS = {
    "case_twin": "a packed file of the same name in another case takes its place",
    "path_conflict": "a packed file occupies its directory",
}


def _mark_hidden(
    config: dict,
    undeclared: list[dict],
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None,
    shipped: dict[str, str | None],
    target_cores: set[str] | None,
    region_drops: set[str] | None = None,
    report: list[dict] | None = None,
    resolver: object | None = None,
    placed_kind: dict[str, str] | None = None,
    system_ids: list[str] | None = None,
    required_only: bool = False,
) -> set[str]:
    """What the builder holds but cannot place beside the files it packed.

    Returns the full destinations the builder fills with a core's file.
    ``report`` is the gap report the caller already computed with the
    builder's arguments. Without it the builder's pass computes its own.
    """
    from packextras import hidden_extras

    placed: set[str] = set()
    hidden = hidden_extras(
        config, emulators_dir, db,
        emu_profiles if emu_profiles is not None
        else load_emulator_profiles(emulators_dir),
        shipped, target_cores, region_drops, placed, report, resolver, placed_kind,
        system_ids=system_ids, required_only=required_only,
    )
    for u in undeclared:
        reason = hidden.get(
            (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
        )
        if reason and u.get("in_repo") and u.get("in_pack", True):
            u["in_pack"] = False
            u["omitted"] = _HIDDEN_REASONS[reason]
    return placed


def _builder_placement(
    packed_order: list[tuple[str, str, str | None]], case_insensitive: bool,
) -> tuple[dict[str, str], dict[str, str | None]]:
    """The platform files the builder writes, and every path it keeps.

    The builder walks the systems in name order and skips a path that a
    written file blocks as a directory, or the reverse: RetroArch declares
    SGB1.sfc and SGB1.sfc/program.rom, and only the first is in the pack.
    An entry without a destination (EmuDeck's system:md5 whitelist) is
    judged but takes no path. Returns (path -> local copy written there,
    path -> copy or None for each slot kept, a user_provided or external one
    included).
    """
    from packpaths import _has_path_conflict, _register_path

    shipped: dict[str, str] = {}
    occupied: dict[str, str | None] = {}
    seen: set[str] = set()
    folded: set[str] = set()
    parents: set[str] = set()
    for _sys_id, full, local in sorted(packed_order, key=lambda item: item[0]):
        # EmuDeck's system:md5 entries name no file: the builder writes none.
        if not full or full.endswith("/"):
            continue
        if (
            full in occupied
            or (case_insensitive and full.lower() in folded)
            or _has_path_conflict(full, seen, parents)
        ):
            continue
        _register_path(full, seen, parents)
        folded.add(full.lower())
        occupied[full] = local
        if local is not None:
            shipped[full] = local
    return shipped, occupied


def _dest_key(file_entry: dict, sys_id: str) -> str:
    """The path a declaration occupies, as the builder keys its pack."""
    dest = sanitize_pack_path(file_entry.get("destination", file_entry.get("name", "")))
    return dest or f"{sys_id}/{file_entry.get('name', '')}"


def _twin_index(
    verify_systems: dict, db: dict, base_dest: str, zip_contents: dict,
) -> tuple[dict[str, int], dict[int, tuple[str, dict]]]:
    """Which declaration the pack ships at each destination, and every declaration by id."""
    # From the module that defines the rule, not the builder's CLI: importing
    # generate_pack made every verify depend on its argparse and manifest code.
    from packresolve import preferred_entries as _preferred_entries

    preferred_entries = _preferred_entries(
        verify_systems, db, DEFAULT_BIOS_DIR, base_dest, False,
        zip_contents, True,
    )
    winners = {
        id(fe): (sid, fe)
        for sid, system in verify_systems.items()
        for fe in system.get("files", [])
    }
    return preferred_entries, winners


def _resolve_declaration(
    file_entry: dict, sys_id: str, twins: tuple, db: dict, zip_contents: dict,
    data_dir_registry: dict | None, slot_overrides: dict, mode: str,
    platform_profiles: dict,
) -> tuple[str | None, str, str | None]:
    """Resolve a declaration to the file the pack ships at its destination.

    When another declaration holds the destination, that one's file is
    returned and the evidence reset: the winner's hash match is not this
    declaration's, which is hashed against the shipped file.
    """
    preferred_entries, winners, base_dest = twins
    bare = sanitize_pack_path(file_entry.get("destination", file_entry.get("name", "")))
    preferred = preferred_entries.get(f"{base_dest}/{bare}" if base_dest else bare)
    held_by, winner = (None, file_entry)
    if preferred is not None and preferred != id(file_entry):
        held_by, winner = winners[preferred]
    local_path, resolve_status = _resolve_for_platform(
        winner, held_by or sys_id, db, zip_contents, data_dir_registry,
        slot_overrides, mode, platform_profiles,
    )
    return local_path, "" if held_by else resolve_status, held_by


def _twin_unmet(
    result: dict,
    held_by: str | None,
    file_entry: dict | None = None,
    sys_id: str = "",
    destination: str = "",
) -> bool:
    """Mark a declaration unmet at a path another declaration holds.

    The path is answered by the winner's file, which the pack counts once.
    This declaration's failure is reported, never folded into the
    destination's status. The message names the path, both systems and
    what this declaration expects: "is not met at the path coco holds"
    named neither the path nor the file wanted there.
    """
    if held_by is None or result["status"] == Status.OK:
        return False
    entry = file_entry or {}
    expects = next(
        (f" ({h} {str(entry[h]).split(',')[0]})"
         for h in ("sha1", "md5", "crc32") if entry.get(h)),
        "",
    )
    owner = sys_id or "this"
    result["discrepancy"] = (
        f"{destination or result.get('name', '')} is declared for {owner}"
        f" and for {held_by}. The {owner} declaration{expects} is not met at"
        f" the path, which holds the {held_by} file"
    )
    # Read by reports that list entries: the destination itself is held, and
    # a count by destination does not include this one.
    result["settled_by"] = held_by
    return True


def _resolve_for_platform(
    file_entry: dict,
    sys_id: str,
    db: dict,
    zip_contents: dict,
    data_dir_registry: dict | None,
    slot_overrides: dict[str, str],
    mode: str,
    platform_profiles: dict,
) -> tuple[str | None, str]:
    """Resolve one platform entry the way the pack builder does.

    The builder's own resolution (packresolve.resolve_declaration), read from
    disk and the large-file cache: verify never downloads. A frontend that
    never reads the bytes takes the filename-free core's own image.
    """
    from packresolve import pending_release_asset, resolve_declaration, run_is_offline

    override = slot_overrides.get(
        sanitize_pack_path(file_entry.get("destination", file_entry.get("name", "")))
    )
    local_path, status = resolve_declaration(
        file_entry, db, DEFAULT_BIOS_DIR, zip_contents, data_dir_registry,
        override, offline=True,
    )
    if status in ("not_found", "hash_mismatch") and not run_is_offline():
        # Not in the cache, and the release holds a copy that answers the
        # declaration: an online build fetches and packs it (resolve_file).
        asset = pending_release_asset(file_entry, db)
        if asset:
            return asset, RELEASE_ASSET_PENDING
    if status == "not_found" and not reads_file_contents(mode):
        found = agnostic_substitute(file_entry, sys_id, db, platform_profiles)
        if found:
            return found[0], "agnostic_fallback"
    return local_path, status


def verify_platform(
    config: dict,
    db: dict,
    emulators_dir: str = DEFAULT_EMULATORS_DIR,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    data_dir_registry: dict | None = None,
    regions: list[str] | None = None,
    system_filter: list[str] | None = None,
    no_game_data: bool = False,
    required_only: bool = False,
) -> dict:
    """Verify all BIOS files for a platform, including cross-reference gaps.

    ``no_game_data`` reports on the pack built with --no-game-data: the
    game data cut as the builder cuts it, and named in ``left_out``.

    A region priority list narrows the report to the files a pack built with the
    same list would carry, using the same selection function as the builder.
    ``system_filter`` does the same for a pack built with --system: the
    systems it keeps and the core extras those systems own.
    ``required_only`` reports on the pack built with --required-only: the
    declarations, trees and core extras marked ``required: false`` are left
    out before any of them takes a path, as the builder leaves them out.
    """
    left_out: list[str] = []
    if no_game_data:
        from gamedata import without_game_data

        if emu_profiles is None:
            emu_profiles = load_emulator_profiles(emulators_dir)
        cut = without_game_data(config, emu_profiles, data_dir_registry, target_cores)
        config, emu_profiles = cut.config, cut.profiles
        systems = config.get("systems", {})
        in_scope = set(select_systems(systems, system_filter) if system_filter else systems)
        cut.left_out = [
            item for item in cut.left_out
            if item.layer == "core" or item.system in in_scope
        ]
        left_out = cut.report_lines()
    # Normalized once: a typo in a platform YAML must not verify with one
    # mode and be scored with another.
    mode = normalize_mode(config.get("verification_mode"))
    platform = config.get("platform", "unknown")

    # The builder settles a destination claimed by both layers, and this must read
    # the same decision, or the two tools describe different packs.
    has_zipped = any(
        fe.get("zipped_file")
        for sys in config.get("systems", {}).values()
        for fe in sys.get("files", [])
    )
    zip_contents = build_zip_contents_index(db) if has_zipped else {}

    # Loaded before the slot overrides: a caller passing no profiles (the
    # README's coverage) got no override and reported a discrepancy at a slot
    # the pack settles.
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )
    base_dest = config.get("base_destination", "")
    pack_overrides = slots.pack_overrides(
        config, profiles, db, zip_contents, data_dir_registry,
        target_cores=target_cores,
    )
    slot_overrides = {
        (key[len(base_dest) + 1:] if base_dest and key.startswith(f"{base_dest}/") else key): path
        for key, path in pack_overrides.items()
    }

    # Build HLE + validation indexes from emulator profiles
    # Ground truth comes from the emulators the platform runs. A standalone
    # profile that loads a same-named file of its own (ZEsarUX's 48K
    # cpc6128.rom against cap32's 32K one) has nothing to say about a
    # RetroArch pack, nor does its HLE: dosbox-x's FONT.ROM fallback turned a
    # missing required Batocera BIOS into INFO.
    plat_cores = resolve_platform_cores(config, profiles)
    platform_profiles = {name: profiles[name] for name in plat_cores}
    hle_index = {
        f.get("name", ""): True
        for profile in platform_profiles.values()
        for f in profile.get("files", [])
        if f.get("hle_fallback")
    }
    validation_index = _build_validation_index(platform_profiles)
    validation_owners = destination_owners(platform_profiles)

    verify_systems = platform_scope_systems(config, profiles, target_cores, system_filter)
    if required_only:
        verify_systems = {
            sys_id: {
                **system,
                "files": [
                    fe for fe in system.get("files", []) if fe.get("required") is not False
                ],
            }
            for sys_id, system in verify_systems.items()
        }

    details = []
    file_status: dict[str, str] = {}
    file_required: dict[str, bool] = {}
    file_severity: dict[str, str] = {}
    # What each entry is: firmware, a game's data, or a name no core the
    # platform runs opens. Only firmware gaps carry a severity.
    file_category: dict[str, str] = {}
    categories = EntryCategories(config, profiles, data_dir_registry)

    region_drops: set[str] = set()
    region_fallbacks: list[str] = []
    region_extra_dests: dict[tuple[str, str, str], str] = {}
    if regions:
        import region as region_mod

        # The builder owns pack composition, so it owns the grouping the region
        # pass reads.  Grouping the platform files here and the core extras
        # there let the two answer differently on one request: the report kept
        # every core extra a region run withdraws from the pack.
        from packextras import platform_region_groups

        held: set[str] = set()
        region_groups, region_extra_dests = platform_region_groups(
            config,
            verify_systems,
            emulators_dir,
            db,
            config.get("base_destination", ""),
            profiles,
            target_cores=target_cores,
            required_only=required_only,
            held_out=held,
            zip_contents=zip_contents,
            data_registry=data_dir_registry,
            slot_overrides=pack_overrides,
        )
        region_index = region_mod.platform_region_index(config, profiles, target_cores)
        region_drops = region_mod.resolve_region_drops(
            region_groups, region_index, regions, held,
        )
        # The pack README names these: no file answers the request, so every
        # candidate stays. Reported here too, or verify reads all OK for a
        # system that has no BIOS for the region asked.
        region_fallbacks = region_mod.fallback_groups(
            region_groups, region_index, regions
        )

    # A destination two systems declare with two hashes ships one file, the
    # one the builder prefers. The other declaration is scored against that
    # file, as the frontend will score it after installation: RetroDECK's
    # xroar component hashes bios/disk.rom and finds the PC-88 ROM.
    base_dest = config.get("base_destination", "")
    preferred_entries, winners = _twin_index(
        verify_systems, db, base_dest, zip_contents
    )

    # (system, full destination, local copy) of each declaration the builder
    # writes, and None for one whose slot it keeps without a file from the
    # collection (user_provided, external). Placed below in the builder's order.
    packed_order: list[tuple[str, str, str | None]] = []
    shipped_keys: set[str] = set()
    results_at: dict[str, list[dict]] = {}
    for sys_id, system in verify_systems.items():
        for file_entry in system.get("files", []):
            if region_drops and (
                sanitize_pack_path(
                    file_entry.get("destination", file_entry.get("name", ""))
                )
                in region_drops
            ):
                continue
            local_path, resolve_status, held_by = _resolve_declaration(
                file_entry, sys_id, (preferred_entries, winners, base_dest),
                db, zip_contents, data_dir_registry, slot_overrides, mode,
                platform_profiles,
            )
            destination = sanitize_pack_path(
                file_entry.get("destination", file_entry.get("name", ""))
            )
            stored = _storage_verdict(file_entry, emulator_pack=False)
            if resolve_status == RELEASE_ASSET_PENDING:
                # Counted as an online build counts it, which fetches the
                # asset. Under --offline the builder cannot, and neither
                # does this report (_resolve_for_platform).
                result = {
                    "name": file_entry.get("name", ""),
                    "required": file_entry.get("required", True),
                    "status": Status.OK,
                    "release_asset": local_path,
                    "reason": "release asset, fetched when the pack is built",
                }
                # Written at its path like any held file: keyed to None, it
                # stayed out of pack_destinations and step 5 read the pack's
                # copy as a file only the pack holds.
                packed_order.append((
                    sys_id, f"{base_dest}/{destination}" if base_dest else destination,
                    local_path,
                ))
                shipped_keys.add(_dest_key(file_entry, sys_id))
                local_path = None
            elif stored is not None:
                result = stored
                local_path = None
                # The builder keeps the slot: instructions for a user_provided
                # file, the download for an external one, whether it arrives
                # or not. No core file goes there.
                packed_order.append((
                    sys_id, f"{base_dest}/{destination}" if base_dest else destination, None,
                ))
            elif not reads_file_contents(mode):
                result = verify_entry_existence(
                    file_entry,
                    local_path,
                    validation_index,
                    db,
                    destination,
                    validation_owners,
                    resolve_status,
                    config.get("platform", ""),
                )
            elif digest_algorithm(mode) == "sha1":
                result = verify_entry_sha1(file_entry, local_path)
            else:
                result = verify_entry_md5(
                    file_entry, local_path, resolve_status, config.get("hash_rule", "")
                )
                # Emulator-level validation: informational for platform packs.
                # Platform verification (MD5) is the authority. Emulator
                # mismatches are reported as discrepancies, not failures.
                if result["status"] == Status.OK:
                    _chosen, disagreement = validated_choice(
                        file_entry, local_path, db, validation_index, "bios",
                        digest_algorithm(mode), destination, validation_owners,
                    )
                    if disagreement:
                        result["discrepancy"] = f"{platform} says OK but {disagreement}"
            result["system"] = sys_id
            result["hle_fallback"] = hle_index.get(file_entry.get("name", ""), False)
            result["ground_truth"] = build_ground_truth(
                file_entry.get("name", ""),
                validation_index,
            )
            details.append(result)
            # Occupied only where the builder ships the declaration: a hash
            # the frontend refuses is left out, and the destination stays free
            # for a core's file the pack does carry.
            if (
                local_path
                and result["status"] != Status.MISSING
                and baseline_verdict(
                    file_entry, local_path, resolve_status, mode, config.get("hash_rule", "")
                )[1] is None
            ):
                packed_order.append((
                    sys_id,
                    f"{base_dest}/{destination}" if base_dest else destination,
                    local_path,
                ))
                shipped_keys.add(_dest_key(file_entry, sys_id))
            if _twin_unmet(
                result, held_by, file_entry, sys_id,
                f"{base_dest}/{destination}" if base_dest else destination,
            ):
                continue

            # Aggregate by destination, keyed as the builder keys its pack.
            # A declaration that finds nothing leaves the path to one that
            # holds a file: the builder packs that file there, whatever the
            # order the two are read in.
            dest = _dest_key(file_entry, sys_id)
            results_at.setdefault(dest, []).append(result)
            required = file_entry.get("required", True)
            cur = result["status"]
            prev = file_status.get(dest)
            hle = hle_index.get(file_entry.get("name", ""), False)
            sev = compute_severity(cur, required, mode, hle)
            explained = categories.explain(file_entry, destination, sys_id)
            category = explained.pop("category")
            result["category"] = category
            result["category_evidence"] = explained
            if cur != Status.MISSING:
                # A held entry is firmware for the counts: its category only
                # documents it.
                category = BIOS
            if file_category.get(dest, category) == BIOS:
                category = BIOS
            file_category[dest] = category
            if prev is not None and (cur == Status.MISSING) != (prev == Status.MISSING):
                if cur == Status.MISSING:
                    continue
                del file_status[dest], file_severity[dest]
                prev = None
            if prev is None or _STATUS_ORDER.get(cur, 0) > _STATUS_ORDER.get(prev, 0):
                file_status[dest] = cur
                file_required[dest] = required
            prev_sev = file_severity.get(dest)
            if prev_sev is None or _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(
                prev_sev, 0
            ):
                file_severity[dest] = sev

    # RetroBat's group: one file of it held is enough, and the others are
    # reported OPTIONAL (batocera-systems/Program.cs). None held, each stays
    # required.
    members: dict[tuple[str, str], list[str]] = {}
    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            if file_entry.get("group"):
                dest = _dest_key(file_entry, sys_id)
                if dest in file_status:
                    members.setdefault((sys_id, file_entry["group"]), []).append(dest)
    for dests in members.values():
        if any(file_status[d] == Status.OK for d in dests):
            for dest in dests:
                if file_status[dest] == Status.MISSING:
                    file_required[dest] = False
                    file_severity[dest] = compute_severity(Status.MISSING, False, mode)
                    for result in results_at.get(dest, []):
                        result["required"] = False

    shipped, occupied = _builder_placement(
        packed_order, bool(config.get("case_insensitive_fs", False))
    )

    # Cross-reference undeclared files, called exactly as the builder calls
    # it: its declarations, not the enriched ones (a core file the platform
    # also declares under another name is packed at the core's own path, 21
    # such files in the RetroArch pack), and no names from inside archives
    # or data trees (a loose file whose name exists only as a member of
    # naomi2.zip was counted "in pack" while the builder shipped nothing).
    undeclared = find_undeclared_files(
        config,
        emulators_dir,
        db,
        emu_profiles,
        target_cores=target_cores,
        declared_names=platform_declarations(config, db, enrich=False),
    )
    # The builder's own pass reads the same report: computed once here and
    # handed over as it stands now, before the markings below.
    report_for_builder = [dict(u) for u in undeclared]
    if system_filter:
        # A system pack carries the extras its systems own.
        from packextras import report_owned_by_systems

        undeclared = report_owned_by_systems(undeclared, system_filter)
    if required_only:
        undeclared = [u for u in undeclared if u.get("required") is not False]
    if region_drops:
        undeclared = [
            u
            for u in undeclared
            if region_extra_dests.get(
                (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
            )
            not in region_drops
        ]
    if required_only:
        # One member of a required set, as the builder keeps it.
        spares = core_file_spares(undeclared)
        undeclared = [u for u in undeclared if id(u) not in spares]
    _mark_unplaced(config, undeclared, profiles)
    from packextras import ExtraResolver

    placed_kind: dict[str, str] = {}
    placed = _mark_hidden(
        config, undeclared, emulators_dir, db, emu_profiles, occupied, target_cores,
        region_drops, report_for_builder,
        ExtraResolver(
            db, DEFAULT_BIOS_DIR, zip_contents, data_dir_registry, validation_index,
            validation_owners, profiles=profiles, pending_assets=True,
        ),
        placed_kind,
        system_filter,
        required_only,
    )
    # What the builder places from the cores, one per pack path, by category:
    # several entries claim one path (rom.key from three Amiga cores) and the
    # builder ships one file there. The category travels on the extra: a copy
    # the second pass makes has no gap report entry to look it up by.
    packed_extras = {"bios": 0, "game_data": 0}
    for category in placed_kind.values():
        packed_extras["game_data" if category == "game_data" else "bios"] += 1
    if not reads_file_contents(mode):
        # An existence frontend is satisfied by any file at the path, and the
        # builder fills a free platform destination with a core's file.
        for dest, status in file_status.items():
            full = f"{base_dest}/{dest}" if base_dest else dest
            if status == Status.MISSING and full in placed:
                file_status[dest] = Status.OK
                file_severity[dest] = Severity.OK
                for result in results_at.get(dest, []):
                    result["status"] = Status.OK

    counts = {
        Severity.OK: 0,
        Severity.INFO: 0,
        Severity.WARNING: 0,
        Severity.CRITICAL: 0,
    }
    not_firmware: dict[str, list[str]] = {}
    for dest, s in file_severity.items():
        category = file_category.get(dest, BIOS)
        if category != BIOS and file_status.get(dest) == Status.MISSING:
            not_firmware.setdefault(category, []).append(dest)
            continue
        counts[s] = counts.get(s, 0) + 1

    # Held but refused: on a hash platform the builder leaves out a file whose
    # declared hash the local copy contradicts. Counted apart, so a coverage
    # figure never calls present what the pack does not carry.
    excluded = sorted(
        dest for dest, status in file_status.items()
        if status == Status.UNTESTED and dest not in shipped_keys
    )

    # Count by file status (ok/untested/missing)
    status_counts: dict[str, int] = {}
    for s in file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    exclusions = find_exclusion_notes(
        config, emulators_dir, emu_profiles, target_cores=target_cores
    )

    gt_filenames = set(validation_index)
    profiled_names: set[str] = set()
    for profile in profiles.values():
        if profile.get("type") in ("launcher", "alias"):
            continue
        for f in profile.get("files", []):
            name = f.get("name", "")
            if name:
                profiled_names.add(name)
            profiled_names.update(f.get("aliases") or [])
    dest_to_name: dict[str, str] = {}
    for sys_id, system in verify_systems.items():
        for fe in system.get("files", []):
            dest_to_name.setdefault(_dest_key(fe, sys_id), fe.get("name", ""))
    with_validation = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in gt_filenames
    )
    with_profile = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in profiled_names
    )
    total = len(file_status)

    # The paths a pack built from this report holds, as written in the ZIP
    # (base_destination stripped, as the builder flattens it). The pipeline
    # compares this set with the archive: equal counts can hide one file
    # credited here and another written there.
    from packpaths import _flat

    pack_destinations = sorted(
        {_flat(dest, base_dest, True) for dest in shipped} | {
            _flat(dest, base_dest, True) for dest in placed
        }
    )

    return {
        "platform": platform,
        **({"systems": sorted(verify_systems)} if system_filter else {}),
        "verification_mode": mode,
        "total_files": total,
        "pack_destinations": pack_destinations,
        "severity_counts": counts,
        "status_counts": status_counts,
        "missing_not_firmware": {k: sorted(v) for k, v in sorted(not_firmware.items())},
        "excluded_files": excluded,
        "packed_extras": packed_extras,
        "undeclared_files": undeclared,
        # Reported apart, never scored: no severity, count or exit code reads it.
        "launcher_reads_not_held": launcher_reads_not_held(
            {config.get("_key", platform): config}, db, profiles, data_dir_registry
        ),
        # Records a config file does not prove: listed, never consumed.
        "launcher_unproven": launcher_unproven({config.get("_key", platform): config}, profiles),
        "exclusion_notes": exclusions,
        "region_fallbacks": sorted(region_fallbacks),
        **({"left_out": left_out} if no_game_data else {}),
        # Every tree of the registry answers a declaration by its tail, so
        # one that was never refreshed leaves its files missing here while
        # an online pack build refreshes it and packs them.
        "data_dir_notices": sorted(
            key for key, entry in (data_dir_registry or {}).items()
            if not os.path.isdir(entry.get("local_cache", ""))
        ),
        "details": details,
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "with_profile": with_profile,
            "platform_only": total - with_validation,
            "total": total,
            "applicable": bool(resolve_platform_cores(config, profiles)),
        },
    }


# Output


def _format_ground_truth_aggregate(ground_truth: list[dict]) -> str:
    """Format ground truth as a single aggregated line.

    Example: beetle_psx [md5], pcsx_rearmed [existence]
    """
    parts = []
    for gt in ground_truth:
        checks_label = "+".join(gt["checks"]) if gt["checks"] else "existence"
        parts.append(f"{gt['emulator']} [{checks_label}]")
    return ", ".join(parts)


def _format_ground_truth_verbose(ground_truth: list[dict]) -> list[str]:
    """Format ground truth as one line per core with expected values and source ref.

    Example: handy validates crc32=0d973c9d,size=512 [lynx/rom.h:48-49]
    """
    lines = []
    for gt in ground_truth:
        checks_label = "+".join(gt["checks"]) if gt["checks"] else "existence"
        expected = gt.get("expected", {})
        if expected:
            vals = ",".join(f"{k}={v}" for k, v in sorted(expected.items()))
            part = f"{gt['emulator']} validates {vals}"
        else:
            part = f"{gt['emulator']} validates {checks_label}"
        if gt.get("source_ref"):
            part += f" [{gt['source_ref']}]"
        lines.append(part)
    return lines


def _print_ground_truth(gt: list[dict], verbose: bool) -> None:
    """Print ground truth lines for a file entry."""
    if not gt:
        return
    if verbose:
        for line in _format_ground_truth_verbose(gt):
            print(f"    {line}")
    else:
        print(f"    {_format_ground_truth_aggregate(gt)}")


def _discrepancy_keys(details: list[dict]) -> set[str]:
    """The DISCREPANCY lines _print_detail_entries prints for these details.

    A file already reported MISSING or UNTESTED on its own ground is not
    printed again as a discrepancy, and is not counted as one either.
    """
    shown = {
        f"{d['system']}/{d['name']}"
        for d in details
        if d["status"] == Status.MISSING
        or (d["status"] == Status.UNTESTED and not d.get("discrepancy"))
    }
    return {
        key
        for d in details
        if d.get("discrepancy")
        and (key := f"{d['system']}/{d['name']}") not in shown
    }


# A platform entry that is not firmware, as the report names it.
_NOT_FIRMWARE = {
    "game_data": "game data",
    "unread": "no core the platform runs opens it",
}


def category_evidence_text(evidence: dict) -> str:
    """One line saying what establishes a missing entry's category."""
    if evidence.get("read_by"):
        groups: dict[bool, list[str]] = {True: [], False: []}
        for reader in evidence["read_by"]:
            refs = [
                f"{e['name']} at {e['source_ref']}" if e.get("source_ref") else e["name"]
                for e in reader.get("entries", [])
            ]
            groups[bool(reader.get("runs_system"))].append(
                f"{reader['emulator']} ({', '.join(refs)})" if refs
                else f"{reader['emulator']} (by {reader['proof']})"
            )
        if not groups[True]:
            return "read by " + ", ".join(groups[False])
        text = "read by " + ", ".join(groups[True])
        if groups[False]:
            text += ", also named by " + ", ".join(groups[False])
        return text
    examined = evidence.get("cores_examined") or []
    cores = f"cores examined: {', '.join(examined)}" if examined else "no core examined"
    if evidence.get("unsettled"):
        return f"no reader found, not settled: {evidence['unsettled']} ({cores})"
    return f"no reader found ({cores})"


def _print_category_evidence(detail: dict) -> None:
    evidence = detail.get("category_evidence")
    if evidence:
        print(f"      {category_evidence_text(evidence)}")


def _print_detail_entries(details: list[dict], seen: set[str], verbose: bool) -> None:
    """Print UNTESTED, MISSING, and DISCREPANCY entries from verification details."""
    for d in details:
        if d["status"] == Status.UNTESTED:
            if d.get("discrepancy"):
                # Reported below with the ground for it: a declaration
                # unmet at a path another declaration holds.
                continue
            key = f"{d['system']}/{d['name']}"
            if key in seen:
                continue
            seen.add(key)
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}{hle}): {key}: {reason}")
            _print_ground_truth(d.get("ground_truth", []), verbose)
    for d in details:
        if d["status"] == Status.MISSING:
            key = f"{d['system']}/{d['name']}"
            if key in seen:
                continue
            label = _NOT_FIRMWARE.get(d.get("category", BIOS))
            if label:
                # Counted on their own line, named on request.
                if verbose:
                    seen.add(key)
                    print(f"  MISSING ({label}): {key}")
                    _print_category_evidence(d)
                continue
            seen.add(key)
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            print(f"  MISSING ({req}{hle}): {key}")
            if verbose:
                _print_category_evidence(d)
            _print_ground_truth(d.get("ground_truth", []), verbose)
    for d in details:
        disc = d.get("discrepancy")
        if disc:
            key = f"{d['system']}/{d['name']}"
            if key in seen:
                continue
            seen.add(key)
            print(f"  DISCREPANCY: {key}: {disc}")
            _print_ground_truth(d.get("ground_truth", []), verbose)

    if verbose:
        for d in details:
            if d["status"] == Status.OK:
                key = f"{d['system']}/{d['name']}"
                if key in seen:
                    continue
                seen.add(key)
                gt = d.get("ground_truth", [])
                if gt:
                    req = "required" if d.get("required", True) else "optional"
                    print(f"  OK ({req}): {key}")
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")


def _print_undeclared_entry(
    u: dict, prefix: str, verbose: bool, repeated: frozenset[str] = frozenset()
) -> None:
    """Print a single undeclared file entry with its validation checks.

    A name in ``repeated`` is read at more than one path, and the line names
    the path: two identical lines told no one there were two slots to fill.
    """
    name = u["path"] if u["name"] in repeated and u.get("path") else u["name"]
    arc_count = u.get("archive_file_count")
    if arc_count:
        name_label = f"{name} ({arc_count} file{'s' if arc_count != 1 else ''})"
    else:
        name_label = name
    if u.get("alternatives") and not u.get("in_repo"):
        name_label += f" (or {', '.join(u['alternatives'])})"
    print(f"    {prefix}: {u['emulator']} needs {name_label}")
    checks = u.get("checks", [])
    if checks:
        if verbose:
            expected = u.get("expected", {})
            if expected:
                vals = ",".join(f"{k}={v}" for k, v in sorted(expected.items()))
                ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                print(f"      validates {vals}{ref_part}")
            else:
                checks_label = "+".join(checks)
                ref_part = f" [{u['source_ref']}]" if u.get("source_ref") else ""
                print(f"      validates {checks_label}{ref_part}")
        else:
            # A bare "[size]" under the entry said nothing to a reader.
            print(f"      validates {'+'.join(checks)}")


def _split_undeclared(undeclared: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Game data, firmware the pack places, firmware it holds but cannot place.

    Everything that is not game data is firmware the core loads, archives
    included: a bios_zip sat in neither list, so a required one that was
    missing was never printed.
    """
    game_data = [u for u in undeclared if u.get("category", "bios") == "game_data"]
    firmware = [u for u in undeclared if u.get("category", "bios") != "game_data"]
    unplaced = [u for u in firmware if u["in_repo"] and not u.get("in_pack", True)]
    placed = [u for u in firmware if u.get("in_pack", True)]
    return game_data, placed, unplaced


def _core_required_missing(bios_files: list[dict]) -> list[dict]:
    """Core files a core cannot run without, absent from the collection.

    A file bundled with the emulator (DaedalusX64's n64.psh, the shader
    library its renderer installs beside the binary) arrives with it: the
    collection does not hold it by design, and listing it as missing sent
    readers after a file every install already has.
    """
    return [
        u
        for u in bios_files
        if u["required"] and not u["in_repo"] and not u.get("hle_fallback")
        and not u.get("bundled")
    ]


def _repeated_names(entries: list[dict]) -> frozenset[str]:
    """Names more than one of ``entries`` carries."""
    counts = Counter(u["name"] for u in entries)
    return frozenset(name for name, count in counts.items() if count > 1)


def _omission_reasons(entries: list[dict]) -> str:
    """Each reason a held file was left out, with its count when several.

    Printing the first entry's reason for the whole count named one cause
    for 412 RomM files when 20 carried it.
    """
    counts = Counter(u.get("omitted", "not placed") for u in entries)
    if len(counts) == 1:
        return next(iter(counts))
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{count} {reason}" for reason, count in ranked)


def _print_undeclared_section(result: dict, verbose: bool) -> None:
    """Print cross-reference section for undeclared files used by cores."""
    undeclared = result.get("undeclared_files", [])
    # The pack's core copies can come from no gap entry: recalbox
    # --system nec-pc-engine packs six root syscard copies for geargrafx
    # with an empty gap report, and returning here hid them.
    packed = result.get("packed_extras")
    if not undeclared and not (packed and any(packed.values())):
        return

    game_data, bios_files, unplaced = _split_undeclared(undeclared)

    # A file installed with its emulator is never collected, firmware or
    # game data, required or not: cross_reference counts it apart. The
    # firmware already left the pack lists (_mark_unplaced), the game data
    # did not, and Abuse's three bundled data files read as missing.
    bundled = [u for u in undeclared if not u["in_repo"] and u.get("bundled")]
    game_data = [u for u in game_data if u["in_repo"] or not u.get("bundled")]

    req_not_in_repo = _core_required_missing(bios_files)
    req_hle_not_in_repo = [
        u
        for u in bios_files
        if u["required"] and not u["in_repo"] and u.get("hle_fallback")
    ]
    req_in_repo = [u for u in bios_files if u["required"] and u["in_repo"]]
    opt_in_repo = [u for u in bios_files if not u["required"] and u["in_repo"]]
    opt_not_in_repo = [u for u in bios_files if not u["required"] and not u["in_repo"]]
    # The builder's count, one file per pack path, when the platform pass
    # replayed it. Counting entries said 1130 for RetroArch, 48 more than the
    # pack holds: rom.key alone was claimed by three Amiga cores.
    core_in_pack = (
        packed["bios"] if packed is not None else len(req_in_repo) + len(opt_in_repo)
    )
    core_missing_req = len(req_not_in_repo) + len(req_hle_not_in_repo)
    core_missing_opt = len(opt_not_in_repo)

    # Required gaps are always named below, the optional ones on request.
    listed = "" if verbose or not core_missing_opt else " (--verbose lists them)"
    print(
        f"  Core files: {core_in_pack} in pack, {core_missing_req} required missing, "
        f"{core_missing_opt} optional missing{listed}"
    )
    # The missing files follow the line that counts them: printed after the
    # held-but-not-packed line, they read as files installed with their emulator.
    repeated = _repeated_names(req_not_in_repo + req_hle_not_in_repo + opt_not_in_repo)
    for u in req_not_in_repo:
        _print_undeclared_entry(u, "MISSING (required)", verbose, repeated)
    for u in req_hle_not_in_repo:
        _print_undeclared_entry(u, "MISSING (required, HLE fallback)", verbose, repeated)
    if verbose:
        for u in opt_not_in_repo:
            _print_undeclared_entry(u, "MISSING (optional)", verbose, repeated)
    if bundled:
        # The required firmware is named, as a missing one would be. The
        # rest (shaders, runtime libraries, engine data) on request.
        shown = bundled if verbose else [
            u for u in bundled
            if u["required"] and u.get("category", "bios") != "game_data"
        ]
        named = sorted({u["name"] for u in shown})
        # The required firmware alone read as the whole count: 14 names
        # for 154 entries, nothing saying the rest existed.
        hidden = len({u["name"] for u in bundled}) - len(named)
        more = f"{hidden} more, " if named else ""
        items = named + ([f"{more}--verbose lists them"] if hidden else [])
        print(
            f"  Bundled with their emulator, not collected: {len(bundled)}"
            + (f" ({', '.join(items)})" if items else "")
        )
    if unplaced:
        print(f"  Core files held but not packed: {len(unplaced)} "
              f"({_omission_reasons(unplaced)})")

    if game_data or (packed and packed.get("game_data")):
        gd_missing = [u for u in game_data if not u["in_repo"]]
        gd_packed = (
            packed["game_data"] if packed is not None
            else sum(1 for u in game_data if u["in_repo"] and u.get("in_pack", True))
        )
        gd_unplaced = [u for u in game_data if u["in_repo"] and not u.get("in_pack", True)]
        if gd_missing or gd_packed or gd_unplaced:
            listed = "" if verbose or not gd_missing else " (--verbose lists them)"
            print(f"  Game data: {gd_packed} in pack, {len(gd_missing)} missing{listed}")
        if verbose:
            repeated = _repeated_names(gd_missing)
            for u in gd_missing:
                _print_undeclared_entry(u, "MISSING (game data)", verbose, repeated)
        if gd_unplaced:
            print(
                f"  Game data held but not packed: {len(gd_unplaced)} "
                f"({_omission_reasons(gd_unplaced)})"
            )


def _print_launcher_unproven(result: dict, verbose: bool) -> None:
    """Launcher records resting on a config file the code does not prove."""
    rows = result.get("launcher_unproven") or []
    if not rows:
        return
    listed = "" if verbose else " (--verbose lists them)"
    print(f"  Launcher records unproven: {len(rows)}{listed}")
    if not verbose:
        return
    for row in rows:
        print(f"    [{row['index']}] {row['emulator']} {row['kind']}: {row['passes_to']}")
        for link in row["missing"]:
            print(f"      missing {link}")


def _print_launcher_reads(result: dict, verbose: bool) -> None:
    """Names the platform's launch code reads that the collection lacks."""
    every = result.get("launcher_reads_not_held") or []
    rows = [r for r in every if not r.get("unsourceable")]
    unsourceable = [r for r in every if r.get("unsourceable")]
    listed = "" if verbose else " (--verbose lists them)"
    if rows:
        print(f"  Launcher reads, not held: {len(rows)}{listed}")
    if unsourceable:
        print(f"  Launcher reads, unsourceable: {len(unsourceable)}{listed}")
    if not verbose:
        return
    for row in unsourceable:
        print(f"    {row['name']} [{', '.join(row['emulators'])}]: {row['unsourceable']}")
    for row in rows:
        kinds = ", ".join(sorted({r["kind"] for r in row["readers"]}))
        casing = f", held as {row['held_as']}" if row.get("held_as") else ""
        print(f"    {row['name']} [{', '.join(row['emulators'])}, {kinds}{casing}]")
        for reader in row["readers"]:
            print(f"      {reader['emulator']}: {reader['source_ref']}")


def print_platform_result(
    result: dict, group: list[str], verbose: bool = False
) -> None:
    mode = result["verification_mode"]
    total = result["total_files"]
    c = result["severity_counts"]
    label = " / ".join(group)
    if result.get("systems"):
        label += f" ({', '.join(result['systems'])})"
    ok_count = c[Severity.OK]
    problems = total - ok_count

    if not reads_file_contents(mode):
        if problems:
            missing = c.get(Severity.WARNING, 0) + c.get(Severity.CRITICAL, 0)
            optional_missing = c.get(Severity.INFO, 0)
            parts = [f"{ok_count}/{total} present"]
            if missing:
                parts.append(f"{missing} missing")
            if optional_missing:
                parts.append(f"{optional_missing} optional missing")
        else:
            parts = [f"{ok_count}/{total} present"]
    else:
        sc = result.get("status_counts", {})
        untested = sc.get(Status.UNTESTED, 0)
        missing = sc.get(Status.MISSING, 0)
        parts = [f"{ok_count}/{total} OK"]
        if untested:
            parts.append(f"{untested} untested")
        if missing:
            parts.append(f"{missing} missing")
    print(f"{label}: {', '.join(parts)} [{mode}]")
    fetched = sorted({d["name"] for d in result["details"] if d.get("release_asset")})
    if fetched:
        # Counted present: an online build downloads them. --offline counts
        # them missing, as an offline build leaves them out.
        shown = ", ".join(fetched[:10]) + (f" (+{len(fetched) - 10})" if len(fetched) > 10 else "")
        print(f"  Release assets fetched when the pack is built ({len(fetched)}): {shown}")
    uncached = result.get("data_dir_notices") or []
    if uncached and result.get("status_counts", {}).get(Status.MISSING):
        shown = ", ".join(uncached[:10]) + (f" (+{len(uncached) - 10})" if len(uncached) > 10 else "")
        print(
            f"  Data directories not cached ({len(uncached)}), their files count missing "
            f"until refresh_data_dirs.py runs (an online pack build refreshes them): {shown}"
        )
    for line in result.get("left_out") or []:
        print(f"  {line}")
    fallbacks = result.get("region_fallbacks") or []
    if fallbacks:
        from packreadme import _group_label

        print(f"  No BIOS for the requested regions, all kept ({len(fallbacks)}): "
              + ", ".join(_group_label(g) for g in fallbacks))

    not_firmware = result.get("missing_not_firmware") or {}
    if not_firmware:
        counts = ", ".join(
            f"{len(dests)} {_NOT_FIRMWARE[category]}"
            for category, dests in not_firmware.items()
        )
        listed = "" if verbose else " (--verbose lists them)"
        print(f"  Missing, not firmware: {counts}{listed}")

    seen_details: set[str] = set()
    _print_detail_entries(result["details"], seen_details, verbose)
    _print_undeclared_section(result, verbose)
    _print_launcher_reads(result, verbose)
    _print_launcher_unproven(result, verbose)

    # The same notes come back for every platform running these cores and
    # filled 985 of the 1114 lines of verify --all: counted, listed on ask.
    exclusions = result.get("exclusion_notes", [])
    if exclusions and verbose:
        print(f"  No external files ({len(exclusions)}):")
        for ex in exclusions:
            print(f"    {ex['emulator']}: {ex['detail']} [{ex['reason']}]")
    elif exclusions:
        print(f"  No external files: {len(exclusions)} cores (--verbose lists them)")

    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and not gt_cov.get("applicable", True):
        # MiSTer declares no core by design: its BiosDB is the answer, and
        # the site shows "-" for it rather than a 0% gap.
        print("  Ground truth: not applicable, the platform runs no profiled core")
    elif gt_cov and gt_cov["total"] > 0:
        # Rounded, as the site rounds: truncated, RetroArch read 20% here
        # and 21% there for one measure.
        pct = round(gt_cov["with_validation"] * 100 / gt_cov["total"])
        print(
            f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)"
        )
        no_profile = gt_cov["total"] - gt_cov.get("with_profile", gt_cov["with_validation"])
        if no_profile:
            print(f"    {no_profile} platform-only (no emulator profile)")


# Emulator/system mode verification


def _effective_validation_label(details: list[dict], validation_index: dict) -> str:
    """Determine the bracket label for the report.

    Returns the union of all check types used, e.g. [crc32+existence+size].
    """
    all_checks: set[str] = set()
    has_files = False
    for d in details:
        fname = d.get("name", "")
        if d.get("note"):
            continue  # skip informational entries (empty profiles)
        has_files = True
        entry = validation_index.get(fname)
        if entry:
            all_checks.update(entry["checks"])
        else:
            all_checks.add("existence")
    if not has_files:
        return "existence"
    return "+".join(sorted(all_checks))


def _select_profiles(
    profile_names: list[str],
    all_profiles: dict,
    standalone: bool,
) -> list[tuple[str, dict]]:
    """Resolve the named profiles, stopping the run on a bad name."""
    try:
        return select_emulator_profiles(profile_names, all_profiles, standalone)
    except ProfileSelectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

def verify_emulator(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
    regions: list[str] | None = None,
    platforms_dir: str = _REPO_PLATFORMS,
    system_ids: list[str] | None = None,
    required_only: bool = False,
) -> dict:
    """Verify files for specific emulator profiles.

    A region priority list narrows the report the same way a pack built with the
    same list would be narrowed, through the emulator pack's own drop set.
    `system_ids` keeps the entries of those systems, as the system pack does.
    `required_only` reports on the pack built with --required-only: a loose
    file or tree marked ``required: false`` is left out, and an archive when
    it and every member it carries are optional, as the builder leaves them.
    """
    from packextras import expand_agnostic_entries
    from packresolve import pending_release_asset, resolve_file, run_is_offline
    from packpaths import (
        _archive_destination,
        _register_path,
        _resolve_destination,
        placement_block,
    )

    # Also load aliases for redirect messages
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)

    selected = _select_profiles(profile_names, all_profiles, standalone)
    # The member index only answers a zipped_file entry, and decompressing
    # every archive took 23 of the 24 seconds of a run that had none.
    zip_contents = (
        build_zip_contents_index(db)
        if any(f.get("zipped_file") for _name, profile in selected
               for f in profile.get("files") or [])
        else {}
    )

    # Build validation index from selected profiles only
    selected_profiles = {n: p for n, p in selected}
    validation_index = _build_validation_index(selected_profiles)
    data_registry = load_data_dir_registry(platforms_dir)

    def pending(entry: dict, local_path: str | None, status: str) -> tuple[str | None, str]:
        # Read from disk and the cache, as _resolve_for_platform does: a
        # release asset the cache lacks is fetched by an online build
        # (generate_emulator_pack resolves with offline=offline).
        if status in ("not_found", "hash_mismatch") and not run_is_offline():
            asset = pending_release_asset(entry, db)
            if asset:
                return asset, RELEASE_ASSET_PENDING
        return local_path, status

    details = []
    # Members of a set another member fills, or that the set's first member
    # stands for: not missing, and out of every count.
    set_members: list[dict] = []
    file_status: dict[str, str] = {}
    file_severity: dict[str, str] = {}
    dest_to_name: dict[str, str] = {}
    data_dir_notices: list[str] = []
    # The paths the emulator pack writes a profile file to. A copy whose hash
    # the profile contradicts is written too (UNTESTED here, a DISCREPANCY in
    # the pack), so the status alone does not say what the pack holds.
    packed_dests: set[str] = set()

    # The emulator pack withdraws these, and the report withdraws the same.
    region_drops: set[str] = set()
    if regions:
        from packextras import emulator_region_drops

        region_drops = emulator_region_drops(
            selected, standalone, regions, required_only, db=db,
            zip_contents=zip_contents, data_registry=data_registry,
        )

    # The emulator pack walks profiles in name order and keeps the first
    # file at a path, folding case: a later profile's different file there
    # (zesarux pentagon.rom after speccy's PENTAGON.ROM) is not in the pack.
    sha1_by_path = {
        entry.get("path"): sha1 for sha1, entry in db.get("files", {}).items()
    }
    # Destination -> (file packed there, its profile, the path as written).
    # Archives and data trees take paths too, before and after the loose
    # files of their profile, as the pack writes them.
    placed: dict[str, tuple[str | None, str, str]] = {}
    placed_files: set[str] = set()
    placed_parents: set[str] = set()
    content_ids: dict[str, str | None] = {}

    def content_id(path: str | None) -> str | None:
        if not path:
            return None
        if path not in content_ids:
            content_ids[path] = sha1_by_path.get(path) or (
                compute_hashes(path)["sha1"] if os.path.isfile(path) else None
            )
        return content_ids[path]

    def occupy(dest: str, path: str | None, owner: str) -> None:
        if placement_block(dest, placed_files, set(placed), placed_parents, True):
            return
        placed[dest.lower()] = (path, owner, dest)
        _register_path(dest, placed_files, placed_parents)

    def occupy_trees(emu_name: str, profile: dict) -> None:
        """The profile's data trees follow its files in the pack, which
        writes them even when the system filter leaves it no file:
        bluemsx's Machines/ tree holds msx-emu's coleco.rom path in a
        --system colecovision pack."""
        for dd in deliverable(profile.get("data_directories", []), standalone):
            if required_only and dd.get("required") is False:
                continue
            cache = (data_registry or {}).get(dd.get("ref", ""), {}).get("local_cache", "")
            if not cache or not os.path.isdir(cache):
                continue
            dd_dest = dd.get("destination", "")
            structure = profile.get("pack_structure")
            prefix = (
                structure.get("standalone" if standalone else "libretro", "")
                if structure else ""
            )
            if prefix:
                dd_dest = f"{prefix}/{dd_dest}" if dd_dest else prefix
            for root, _dirs, names in os.walk(cache):
                for fname in names:
                    src = os.path.join(root, fname)
                    rel = os.path.relpath(src, cache).replace(os.sep, "/")
                    occupy(f"{dd_dest}/{rel}" if dd_dest else rel, src, emu_name)

    for emu_name, profile in sorted(selected):
        files = expand_agnostic_entries(
            expand_directory_entries(
                deliverable(profile.get("files", []), standalone),
                db,
                standalone,
            ),
            emu_name, profile, db, standalone, all_profiles,
        )
        if system_ids:
            files = [fe for fe in files if entry_serves_systems(fe, profile, system_ids)]
        if required_only:
            optional_archives = {
                fe["archive"] for fe in files
                if fe.get("archive")
                and archive_is_optional(archive_entry(fe["archive"], files), fe["archive"], files)
            }
            files = [
                fe for fe in files
                if fe.get("archive") not in optional_archives
                and (fe.get("archive") or fe.get("required") is not False)
            ]
        if region_drops:
            # Loose files only, as the emulator pack: an archive ships whole,
            # and dropping kronos' regional stvbios.zip members rebuilt the
            # archive here from 4 of its 14 members and changed its required.
            files = [
                fe
                for fe in files
                if fe.get("archive")
                or _resolve_destination(fe, standalone) not in region_drops
            ]
        spares: set[str] = set()
        if required_only:
            from packextras import emulator_required_spares

            spares = emulator_required_spares(
                emu_name, profile, files, standalone, region_drops, db,
                validation_index, zip_contents, data_registry,
            )
            files = [
                fe for fe in files
                if fe.get("archive") or _resolve_destination(fe, standalone) not in spares
            ]

        # Check data directories (only notice if not cached)
        for dd in deliverable(
            profile.get("data_directories", []), standalone
        ):
            if required_only and dd.get("required") is False:
                continue
            ref = dd.get("ref", "")
            if not ref:
                continue
            if data_registry and ref in data_registry:
                cache_path = data_registry[ref].get("local_cache", "")
                if cache_path and os.path.isdir(cache_path):
                    continue  # cached, no notice needed
            data_dir_notices.append(ref)

        if not files:
            details.append(
                {
                    "name": f"({emu_name})",
                    "status": Status.OK,
                    "required": False,
                    "system": "",
                    "note": f"No files needed for {profile.get('emulator', emu_name)}",
                    "ground_truth": [],
                }
            )
            occupy_trees(emu_name, profile)
            continue

        # Each destination's outcome, settled by set once the profile is
        # read: an archive unit is a member like a loose file (Kronos reads
        # kronos/stvbios.zip, else stvbios.zip).
        placed_results: list[tuple[str, dict, bool, bool, list[dict]]] = []
        fallback_reason = "declared hash contradicted by the local file"

        # Verify archives as units (e.g., neogeo.zip, aes.zip)
        seen_archives: set[str] = set()
        for file_entry in files:
            archive = file_entry.get("archive")
            if archive and archive not in seen_archives:
                seen_archives.add(archive)
                own_entry = archive_entry(archive, files)
                if _archive_destination(
                    archive, profile.get("archive_prefix", ""),
                    profile.get("pack_structure"), standalone,
                ) in spares:
                    continue
                local_path, resolve_status = pending(own_entry, *resolve_file(
                    own_entry,
                    db,
                    DEFAULT_BIOS_DIR,
                    zip_contents,
                    data_dir_registry=data_registry,
                    offline=True,
                ))
                required = any(
                    f.get("archive") == archive and f.get("required", True)
                    for f in files
                )
                if local_path and resolve_status == "hash_mismatch":
                    # Same policy as the loose-file branch below: the name
                    # matched while the bytes contradict the hash the profile
                    # declares on the container. Reporting it covered says the
                    # collection holds an archive it does not.
                    result = {
                        "name": archive,
                        "status": Status.UNTESTED,
                        "required": required,
                        "path": local_path,
                        "reason": "declared hash contradicted by the local file",
                    }
                elif local_path:
                    result = {
                        "name": archive,
                        "status": Status.OK,
                        "required": required,
                        "path": local_path,
                    }
                    if resolve_status == RELEASE_ASSET_PENDING:
                        result["release_asset"] = local_path
                else:
                    result = {
                        "name": archive,
                        "status": Status.MISSING,
                        "required": required,
                    }
                result["system"] = file_entry.get("system", "")
                result["hle_fallback"] = False
                result["ground_truth"] = build_ground_truth(archive, validation_index)
                # Where the pack puts it: an archive_prefix or pack_structure
                # moves it, and a loose same-named entry is another file.
                dest = _archive_destination(
                    archive, profile.get("archive_prefix", ""),
                    profile.get("pack_structure"), standalone,
                )
                result["destination"] = dest
                block = placement_block(
                    dest, placed_files, set(placed), placed_parents, True
                )
                if block and local_path and result["status"] != Status.MISSING:
                    other_path, owner, other_dest = placed.get(dest.lower(), (None, "", ""))
                    if block == "path_conflict" or content_id(local_path) != content_id(other_path):
                        # The pack serves the other profile's file here: this
                        # archive is not in it, whatever this profile resolves.
                        result["status"] = Status.MISSING
                        result["reason"] = (
                            "a packed file occupies its directory" if block == "path_conflict"
                            else f"the pack holds {owner}'s {other_dest} at this path"
                        )
                elif local_path:
                    occupy(dest, local_path, emu_name)
                    packed_dests.add(dest)
                placed_results.append((dest, result, required, False, [own_entry]))

        # Results of this emulator, by destination. Several entries of one
        # profile on one destination are the releases the code accepts
        # there (a shareware and a retail HOG, each GRP in a size table):
        # holding one of them fills the slot, and the others are not gaps.
        emu_results: dict[str, list[tuple[dict, bool, bool, dict]]] = {}

        for file_entry in files:
            # Skip archive members (verified as archive units above)
            if file_entry.get("archive"):
                continue

            dest_hint = file_entry.get("path", "")
            # The emulator pack's resolution, release assets included.
            local_path, resolve_status = pending(file_entry, *resolve_file(
                {**with_archive_members(file_entry, files), "source_profile": emu_name},
                db,
                DEFAULT_BIOS_DIR,
                zip_contents,
                dest_hint=dest_hint,
                data_dir_registry=data_registry,
                offline=True,
            ))
            if resolve_status in ("not_found", "user_provided", "external"):
                local_path = None
            name = file_entry.get("name", "")
            required = file_entry.get("required", True)
            hle = file_entry.get("hle_fallback", False)

            stored = _storage_verdict(file_entry, emulator_pack=True)
            if stored is not None:
                result = stored
            elif resolve_status == RELEASE_ASSET_PENDING:
                result = {
                    "name": name,
                    "status": Status.OK,
                    "required": required,
                    "path": local_path,
                    "release_asset": local_path,
                    "reason": "release asset, fetched when the pack is built",
                }
            elif not local_path:
                result = {"name": name, "status": Status.MISSING, "required": required}
                # An entry the profile documents as unsourceable is absent by
                # design: a per-user key, a slot the user fills, a dump nobody
                # has made. Counting it beside a file somebody could still
                # find invites the wrong repair: dropping the flag, or
                # chasing a vendor's whole install tree.
                unsourceable = file_entry.get("unsourceable")
                if unsourceable:
                    result["unsourceable"] = (
                        unsourceable if isinstance(unsourceable, str) else ""
                    )
            else:
                # Apply emulator validation
                # Judged by this emulator's own entries, as it runs its check,
                # through the selection the emulator pack makes.
                chosen, disagreement = validated_choice(
                    file_entry, local_path, db, validation_index, DEFAULT_BIOS_DIR,
                    None, emulators={emu_name},
                )
                if disagreement:
                    result = {
                        "name": name,
                        "status": Status.UNTESTED,
                        "required": required,
                        "path": local_path,
                        "reason": disagreement.split(" says ", 1)[-1],
                    }
                elif chosen != local_path:
                    result = {
                        "name": name,
                        "status": Status.OK,
                        "required": required,
                        "path": chosen,
                    }
                elif resolve_status == "hash_mismatch":
                    # Nothing in validation: caught it, but the name matched
                    # while the bytes contradict the hash the profile
                    # declares. That is a different file wearing the right
                    # name (config.ini and ROM collide across systems), so
                    # calling it covered reports the collection as holding
                    # something it does not. Validation runs first because it
                    # names the specific field that disagrees.
                    result = {
                        "name": name,
                        "status": Status.UNTESTED,
                        "required": required,
                        "path": local_path,
                        "reason": "declared hash contradicted by the local file",
                    }
                else:
                    result = {
                        "name": name,
                        "status": Status.OK,
                        "required": required,
                        "path": local_path,
                    }

            result["system"] = file_entry.get("system", "")
            result["hle_fallback"] = hle
            result["ground_truth"] = build_ground_truth(name, validation_index)
            # The slot the emulator pack places this entry in: standalone_path
            # under --standalone, the sanitised path.
            dest = _resolve_destination(file_entry, standalone) or name
            emu_results.setdefault(dest, []).append((result, required, hle, file_entry))

        for dest, alternatives in emu_results.items():
            # What the emulator pack places here: an accepted file, else a
            # file whose hash the profile contradicts. A refused copy is held
            # but never packed.
            slot_entries = [a[3] for a in alternatives]
            if len(alternatives) > 1:
                # Reduced in the order generate_emulator_pack chooses, so the
                # destination's status is the one the pack reports: a slot it
                # fills with a contradicted copy, or counts as refused by the
                # core, is not missing because another alternative is absent.
                for keep in (
                    lambda a: a[0]["status"] == Status.OK,
                    lambda a: a[0]["status"] == Status.UNTESTED
                    and a[0].get("reason") == fallback_reason,
                    lambda a: a[0]["status"] != Status.MISSING,
                ):
                    chosen = [a for a in alternatives if keep(a)]
                    if chosen:
                        alternatives = chosen[:1]
                        break
            packed = next(
                (a[0].get("path") for a in alternatives
                 if a[0]["status"] == Status.OK and a[0].get("path")),
                None,
            ) or next(
                (a[0].get("path") for a in alternatives
                 if a[0]["status"] == Status.UNTESTED
                 and a[0].get("reason") == fallback_reason and a[0].get("path")),
                None,
            )
            held = packed or next(
                (a[0].get("path") for a in alternatives
                 if a[0]["status"] != Status.MISSING and a[0].get("path")),
                None,
            )
            block = placement_block(
                dest, placed_files, set(placed), placed_parents, True
            )
            block_reason = ""
            if block and held is not None:
                other_path, owner, other_dest = placed.get(dest.lower(), (None, "", ""))
                same = content_id(held) is not None and content_id(held) == content_id(
                    other_path
                )
                if block == "path_conflict":
                    block_reason = "a packed file occupies its directory"
                elif block == "case_twin":
                    block_reason = (
                        f"packed only as {other_dest}, from {owner}"
                        if same
                        else f"the pack holds {owner}'s {other_dest} at this path"
                    )
                elif not same:
                    block_reason = f"the pack holds {owner}'s {other_dest} at this path"
            elif not block and packed is not None:
                occupy(dest, packed, emu_name)
                packed_dests.add(dest)
            for result, required, hle, file_entry in alternatives:
                if block_reason and result["status"] != Status.MISSING:
                    result["status"] = Status.MISSING
                    result["reason"] = block_reason
                result["destination"] = dest
                placed_results.append((dest, result, required, hle, slot_entries))

        # A set the code takes one member of is one need: once a member is
        # in the pack the others are not missing, and a set nobody holds is
        # one gap under its first member. Settled per profile, before the
        # destinations of several profiles are merged.
        excused, standing = settle_sets([
            (
                slot_set_keys(emu_name, entries),
                entries[0],
                result["status"] == Status.OK
                or (result["status"] == Status.UNTESTED
                    and result.get("reason") == fallback_reason),
            )
            for _dest, result, _required, _hle, entries in placed_results
        ], lambda key: set_requirements(profile).get(key[1], True))
        for position, (dest, result, required, hle, _fe) in enumerate(placed_results):
            if position in excused and result["status"] == Status.MISSING:
                set_members.append(result)
                continue
            if position in standing:
                result["alternatives"] = standing[position].others
                result["required"] = required = standing[position].required
            details.append(result)

            # Aggregate by destination (path if available, else name)
            dest_to_name[dest] = result["name"]
            cur = result["status"]
            prev = file_status.get(dest)
            if prev is None or _STATUS_ORDER.get(cur, 0) > _STATUS_ORDER.get(
                prev, 0
            ):
                file_status[dest] = cur
            sev = _emulator_severity(cur, required, hle)
            prev_sev = file_severity.get(dest)
            if prev_sev is None or _SEVERITY_ORDER.get(
                sev, 0
            ) > _SEVERITY_ORDER.get(prev_sev, 0):
                file_severity[dest] = sev

        occupy_trees(emu_name, profile)

    counts = {
        Severity.OK: 0,
        Severity.INFO: 0,
        Severity.WARNING: 0,
        Severity.CRITICAL: 0,
    }
    for s in file_severity.values():
        counts[s] = counts.get(s, 0) + 1
    status_counts: dict[str, int] = {}
    for s in file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    label = _effective_validation_label(details, validation_index)

    gt_filenames = set(validation_index)
    total = len(file_status)
    with_validation = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in gt_filenames
    )

    return {
        "emulators": [n for n, _ in selected],
        "verification_mode": label,
        "total_files": total,
        # The paths the emulator pack fills with the profile's files, for the
        # pipeline's comparison with the pack built in memory.
        "pack_destinations": sorted(packed_dests),
        "severity_counts": counts,
        "status_counts": status_counts,
        "details": details,
        "set_members": set_members,
        "data_dir_notices": sorted(set(data_dir_notices)),
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "platform_only": total - with_validation,
            "total": total,
        },
    }


def verify_system(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    standalone: bool = False,
    regions: list[str] | None = None,
    platforms_dir: str = _REPO_PLATFORMS,
    required_only: bool = False,
) -> dict:
    """Verify files for all emulators supporting given system IDs."""
    profiles = load_emulator_profiles(emulators_dir)
    matching = profiles_for_systems(profiles, system_ids, standalone)

    if not matching:
        all_systems: set[str] = set()
        for p in profiles.values():
            all_systems.update(p.get("systems", []))
        if standalone:
            print(
                f"No standalone emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        else:
            print(
                f"No emulators found for system(s): {', '.join(system_ids)}",
                file=sys.stderr,
            )
        # --list-systems merges spellings that differ in case or separator:
        # the hint counted 579 spellings for the 532 lines it prints.
        print(suggest_names(system_ids, sorted(all_systems), "--list-systems",
                            listed=len(system_index(profiles))),
              file=sys.stderr)
        sys.exit(1)

    return verify_emulator(
        matching, emulators_dir, db, standalone, regions=regions,
        platforms_dir=platforms_dir, system_ids=system_ids, required_only=required_only,
    )


def print_emulator_result(result: dict, verbose: bool = False) -> None:
    """Print verification result for emulator/system mode."""
    label = " + ".join(result["emulators"])
    mode = result["verification_mode"]
    total = result["total_files"]
    c = result["severity_counts"]
    ok_count = c[Severity.OK]

    sc = result.get("status_counts", {})
    untested = sc.get(Status.UNTESTED, 0)
    missing = sc.get(Status.MISSING, 0)
    # Counted by slot, as missing is: xash3d's thirteen unsourceable
    # pak0.pak and liblist.gam were three names and ten "missing".
    missing_slots: dict[str, bool] = {}
    for d in result["details"]:
        if d["status"] == Status.MISSING:
            slot = d.get("destination") or d["name"]
            missing_slots[slot] = missing_slots.get(slot, True) and "unsourceable" in d
    unsourceable = sum(missing_slots.values())
    parts = [f"{ok_count}/{total} OK"]
    if untested:
        parts.append(f"{untested} untested")
    if missing - unsourceable > 0:
        parts.append(f"{missing - unsourceable} missing")
    if unsourceable:
        parts.append(f"{unsourceable} unsourceable")
    print(f"{label}: {', '.join(parts)} [{mode}]")
    fetched = sorted({d["name"] for d in result["details"] if d.get("release_asset")})
    if fetched:
        shown = ", ".join(fetched[:10]) + (f" (+{len(fetched) - 10})" if len(fetched) > 10 else "")
        print(f"  Release assets fetched when the pack is built ({len(fetched)}): {shown}")

    seen = set()
    for d in result["details"]:
        if d["status"] == Status.UNTESTED:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            reason = d.get("reason", "")
            print(f"  UNTESTED ({req}{hle}): {d['name']}: {reason}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        if d["status"] == Status.MISSING and "unsourceable" not in d:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            req = "required" if d.get("required", True) else "optional"
            hle = ", HLE available" if d.get("hle_fallback") else ""
            others = d.get("alternatives")
            either = f" (or {', '.join(others)})" if others else ""
            print(f"  MISSING ({req}{hle}): {d['name']}{either}")
            gt = d.get("ground_truth", [])
            if gt:
                if verbose:
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")
                else:
                    print(f"    {_format_ground_truth_aggregate(gt)}")
    for d in result["details"]:
        if d["status"] == Status.MISSING and "unsourceable" in d:
            if d["name"] in seen:
                continue
            seen.add(d["name"])
            why = d.get("unsourceable") or "documented as unobtainable"
            print(f"  UNSOURCEABLE: {d['name']}: {why}")

    for d in result["details"]:
        if d.get("note"):
            print(f"  {d['note']}")

    if verbose:
        for d in result["details"]:
            if d["status"] == Status.OK:
                if d["name"] in seen:
                    continue
                seen.add(d["name"])
                gt = d.get("ground_truth", [])
                if gt:
                    req = "required" if d.get("required", True) else "optional"
                    print(f"  OK ({req}): {d['name']}")
                    for line in _format_ground_truth_verbose(gt):
                        print(f"    {line}")

    for ref in result.get("data_dir_notices", []):
        print(
            f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)"
        )

    gt_cov = result.get("ground_truth_coverage")
    if gt_cov and gt_cov["total"] > 0:
        pct = round(gt_cov["with_validation"] * 100 / gt_cov["total"])
        print(
            f"  Ground truth: {gt_cov['with_validation']}/{gt_cov['total']} files have emulator validation ({pct}%)"
        )
        if gt_cov["platform_only"]:
            print(f"    {gt_cov['platform_only']} without declared validation")


def _refuse_listing_narrowings(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    """A listing mode reads --platform at most, anything else is refused.

    Printing past a narrowing flag lets the user believe it applied
    (generate_pack applies the same table).
    """
    listing = next(
        (flag for flag, on in (
            ("--list-platforms", args.list_platforms),
            ("--list-emulators", args.list_emulators),
            ("--list-systems", args.list_systems),
            ("--list-targets", args.list_targets),
        ) if on),
        None,
    )
    if not listing:
        return
    reads_platform = listing not in ("--list-emulators", "--list-platforms")
    for flag, on in (
        ("--platform", args.platform and not reads_platform),
        ("--all", args.all),
        ("--emulator", args.emulator),
        ("--system", args.system),
        ("--region", getattr(args, "region", None)),
        ("--target", getattr(args, "target", None)),
        ("--standalone", args.standalone),
        ("--json", args.json),
        ("--strict", args.strict),
        ("--verbose", args.verbose),
        ("--destinations", args.destinations),
        ("--offline", args.offline),
        ("--no-game-data", getattr(args, "no_game_data", False)),
        ("--required-only", args.required_only),
    ):
        if on:
            parser.error(f"{flag} is incompatible with {listing}")


def _refuse_mode_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """A flag the chosen mode does not read is refused, never ignored."""
    for refused, message in (
        (args.standalone and not (args.emulator or args.system),
         "--standalone requires --emulator or --system"),
        (args.standalone and args.platform,
         "--standalone is incompatible with --platform"),
        (args.target and not (args.platform or args.all),
         "--target requires --platform or --all"),
        (args.target and (args.emulator or (args.system and not args.platform)),
         "--target is incompatible with --emulator and --system"),
        (args.destinations and args.system,
         "--destinations describes the full pack and is incompatible with --system"),
        (args.destinations and not (args.platform or args.all),
         "--destinations requires --platform or --all"),
        # Game data is categorized against a platform's list and its cores.
        (getattr(args, "no_game_data", False) and not (args.platform or args.all),
         "--no-game-data requires --platform or --all"),
        (args.destinations and getattr(args, "region", None),
         "--destinations describes the full pack and is incompatible with --region"),
        (args.destinations and args.required_only,
         "--destinations describes the full pack and is incompatible with --required-only"),
    ):
        if refused:
            parser.error(message)


def _run_listing(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.list_platforms:
        print_platform_listing(args.platforms_dir)
    elif args.list_emulators:
        list_emulator_profiles(args.emulators_dir)
    elif args.list_systems and args.platform:
        list_platform_system_ids(args.platform, args.platforms_dir)
    elif args.list_systems:
        list_system_ids(args.emulators_dir)
    else:
        if not args.platform:
            parser.error("--list-targets requires --platform")
        targets = list_available_targets(args.platform, args.platforms_dir)
        if not targets:
            print(f"No targets configured for platform '{args.platform}'")
            return
        for t in targets:
            print(target_listing_line(t))


def main() -> None:
    with contextlib.ExitStack() as held:
        _main(held)


def _main(held: contextlib.ExitStack) -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Platform-native BIOS verification")
    parser.add_argument("--platform", "-p", type=platform_arg, help="Platform name")
    parser.add_argument(
        "--all", action="store_true", help="Verify every registered platform"
    )
    parser.add_argument(
        "--emulator", "-e", help="Emulator profile name(s), comma-separated"
    )
    parser.add_argument("--system", "-s", help="System ID(s), comma-separated")
    parser.add_argument("--standalone", action="store_true", help="Use standalone mode")
    parser.add_argument(
        "--list-emulators", action="store_true", help="List available emulators"
    )
    parser.add_argument(
        "--list-systems", action="store_true", help="List available systems"
    )
    parser.add_argument(
        "--list-platforms", action="store_true", help="List available platforms"
    )
    parser.add_argument("--target", "-t", help="Hardware target (e.g., switch, rpi4)")
    parser.add_argument(
        "--region", help="Region priority list, best first (e.g. us,eu,jp)"
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List available targets for the platform",
    )
    parser.add_argument(
        "--no-game-data", action="store_true",
        help="Report on the pack built with --no-game-data: game data left "
        "out and named, firmware only",
    )
    parser.add_argument(
        "--required-only", action="store_true",
        help="Report on the pack built with --required-only: files the code "
        "runs without are left out",
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB,
        help="database file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default=DEFAULT_PLATFORMS_DIR,
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--emulators-dir", default=DEFAULT_EMULATORS_DIR,
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show emulator ground truth details",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--offline", action="store_true",
        help="Report as an offline build packs: a release asset the cache "
        "lacks is missing. Without it, it counts as fetched at build time",
    )
    parser.add_argument(
        "--destinations", metavar="FILE",
        help="With --platform or --all, also write the paths each pack holds "
        "according to this report to FILE (JSON), for comparison with the archive",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on a required file missing: where the frontend checks "
        "hashes for a platform, without HLE for --emulator and --system. A file "
        "present with an unconfirmed hash is a warning, not a failure",
    )
    args = parser.parse_args()
    work_from_repo_root(args, parser, ["db", "platforms_dir", "emulators_dir"])
    if args.platform:
        require_platform(args.platform, args.platforms_dir)
    if args.offline:
        import packresolve

        packresolve.set_offline(True)

    requested_regions: list[str] = []
    if getattr(args, "region", None):
        import region as region_mod

        try:
            requested_regions = region_mod.parse_requested(args.region)
        except ValueError as exc:
            parser.error(str(exc))

    _refuse_listing_narrowings(args, parser)
    if args.list_platforms or args.list_emulators or args.list_systems or args.list_targets:
        _run_listing(args, parser)
        return

    # --system beside --platform narrows that platform, as in generate_pack.
    system_mode = bool(args.system) and not args.platform
    modes = sum(1 for x in (args.platform, args.all, args.emulator, system_mode) if x)
    if modes == 0:
        parser.error("Specify --platform, --all, --emulator, or --system")
    if modes > 1:
        parser.error(
            "--platform, --all, --emulator, and --system are mutually exclusive"
        )
    _refuse_mode_flags(args, parser)
    platform_systems: list[str] | None = None
    if args.platform and args.system:
        config = load_platform_config(args.platform, args.platforms_dir)
        try:
            platform_systems = resolve_system_arg(
                args.system, list(config.get("systems", {})), config,
                f"--platform {args.platform} --list-systems",
            )
        except ValueError as exc:
            parser.error(f"--system {args.system}: {exc}")
    # The trees stay put while names resolve against them and files are read.
    from refresh_data_dirs import hold_data_dirs

    hold_data_dirs(held, load_data_dir_registry(args.platforms_dir))

    db = load_database(args.db)

    if args.emulator:
        names = [n.strip() for n in args.emulator.split(",") if n.strip()]
        result = verify_emulator(
            names, args.emulators_dir, db, args.standalone,
            regions=requested_regions, platforms_dir=args.platforms_dir,
            required_only=args.required_only,
        )
        if args.json:
            result["details"] = _json_details(result["details"], args.verbose)
            print(json.dumps(result, indent=2))
        else:
            print_emulator_result(result, verbose=args.verbose)
        _exit_if_strict_emulator(args.strict, result)
        return

    if system_mode:
        system_ids = [s.strip() for s in args.system.split(",") if s.strip()]
        result = verify_system(
            system_ids, args.emulators_dir, db, args.standalone,
            regions=requested_regions, platforms_dir=args.platforms_dir,
            required_only=args.required_only,
        )
        if args.json:
            result["details"] = _json_details(result["details"], args.verbose)
            print(json.dumps(result, indent=2))
        else:
            print_emulator_result(result, verbose=args.verbose)
        _exit_if_strict_emulator(args.strict, result)
        return

    # Platform mode (existing)
    if args.all:
        platforms = list_registered_platforms(args.platforms_dir)
    elif args.platform:
        platforms = [args.platform]
    else:
        parser.error("Specify --platform or --all")
        return

    # Load emulator profiles once for cross-reference (not per-platform)
    emu_profiles = load_emulator_profiles(args.emulators_dir)
    data_registry = load_data_dir_registry(args.platforms_dir)

    target_cores_cache: dict[str, set[str] | None] = {}
    if args.target:
        try:
            target_cores_cache, platforms = build_target_cores_cache(
                platforms,
                args.target,
                args.platforms_dir,
                is_all=args.all,
            )
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        # A system the target leaves no core for was reported 0/0 with exit 0,
        # where generate_pack refuses the same request.
        if platform_systems:
            config = load_platform_config(args.platform, args.platforms_dir)
            if not platform_scope_systems(
                config, emu_profiles, target_cores_cache.get(args.platform), platform_systems
            ):
                reason = system_scope_error(
                    config, args.platform, platform_systems, args.target
                )
                print(f"ERROR: {reason}", file=sys.stderr)
                sys.exit(1)

    # generate_pack refuses these on a platform whose cores no profile
    # describes, and the report answers the same request the same way.
    platforms = without_profile_blind(
        platforms,
        [
            flag for flag, given in (
                ("--region", requested_regions),
                ("--no-game-data", getattr(args, "no_game_data", False)),
            ) if given
        ],
        args.platforms_dir,
        emu_profiles,
        target_cores_cache if args.target else None,
        args.all,
    )

    # Group identical platforms (same function as generate_pack)
    groups = group_identical_platforms(
        platforms, args.platforms_dir, target_cores_cache if args.target else None
    )

    all_results = {}
    group_results: list[tuple[dict, list[str]]] = []
    for group_platforms, representative in groups:
        config = load_platform_config(representative, args.platforms_dir)
        tc = target_cores_cache.get(representative) if args.target else None
        if tc is not None:
            # A core a roms folder offers on other boards only is not placed
            # there, as generate_pack builds the board's pack.
            config = {**config, TARGET_KEY: canonical_target_name(
                [representative], args.target, args.platforms_dir)}
        result = verify_platform(
            config,
            db,
            args.emulators_dir,
            emu_profiles,
            target_cores=tc,
            data_dir_registry=data_registry,
            regions=requested_regions,
            system_filter=platform_systems,
            no_game_data=getattr(args, "no_game_data", False),
            required_only=args.required_only,
        )
        names = [
            load_platform_config(p, args.platforms_dir).get("platform", p)
            for p in group_platforms
        ]
        group_results.append((result, names))
        for p in group_platforms:
            all_results[p] = result

    if not args.json:
        for result, group in group_results:
            print_platform_result(result, group, verbose=args.verbose)
            print()
        if len(group_results) > 1:
            print(_overall_summary(group_results))

    if args.destinations:
        destinations = {}
        for (result, names), (group, _rep) in zip(group_results, groups):
            for name, key in zip(names, group):
                destinations[name] = {
                    "platform": key, "pack_destinations": result["pack_destinations"],
                }
        Path(args.destinations).write_text(json.dumps(destinations, indent=1, sort_keys=True))

    if args.json:
        for r in all_results.values():
            r["details"] = _json_details(r["details"], args.verbose)
        print(json.dumps(all_results, indent=2))

    _exit_if_strict(args.strict, [r for r, _ in group_results])


def _json_details(details: list[dict], verbose: bool) -> list[dict]:
    """The entries a JSON report lists: what needs attention, or every one.

    --verbose shows each entry with its ground truth in the text report. It
    used to be accepted beside --json and dropped, the output byte for byte
    the same, so a script asking for the passing entries got nothing.
    """
    return list(details) if verbose else [
        d for d in details if d["status"] != Status.OK or d.get("release_asset")
    ]


def _exit_if_strict(strict: bool, results: list[dict]) -> None:
    """Exit 1 under --strict when a platform result counts a critical file:
    a required file missing where the frontend reads hashes.

    A file present whose hash the frontend does not confirm is UNTESTED, a
    warning (Batocera's BiosStatus calls it so): reported, not failed.
    """
    critical = sum(r["severity_counts"].get(Severity.CRITICAL, 0) for r in results)
    if strict and critical:
        print(f"ERROR: {critical} required file(s) missing where the frontend "
              "checks hashes", file=sys.stderr)
        sys.exit(1)


def _exit_if_strict_emulator(strict: bool, result: dict) -> None:
    """Exit 1 under --strict when an emulator lacks a file it cannot run without.

    The emulator, not a frontend, is the judge here: a required file with no
    HLE fallback that the collection does not hold stops the core.
    """
    missing = sorted({
        d["name"] for d in result["details"]
        if d["status"] == Status.MISSING and d.get("required", True)
        and not d.get("hle_fallback")
    })
    if strict and missing:
        print(f"ERROR: {len(missing)} required file(s) missing: "
              f"{', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def _overall_summary(group_results: list[tuple[dict, list[str]]]) -> str:
    """The closing lines of a multi-platform run, worst severity first.

    Each count names the platforms carrying it, and the core files a core
    cannot run without are counted too: a reader of the summary alone used
    to conclude nothing required was missing, and could not tell where the
    one warning was without reading the whole output.
    """
    platforms = sum(len(group) for _, group in group_results)

    def where(counts: dict[str, int]) -> str:
        named = [f"{name} {count}" for name, count in counts.items() if count]
        return f" ({', '.join(named)})" if named else ""

    def on(groups: tuple[str, ...]) -> str:
        """The platforms a file is missing on, by the shorter side."""
        if len(group_results) < 2 or len(groups) * 2 <= len(group_results):
            return ", ".join(groups)
        others = [" / ".join(g) for _, g in group_results if " / ".join(g) not in groups]
        return "every platform" + (f" but {', '.join(others)}" if others else "")

    parts = []
    for severity, label in ((Severity.CRITICAL, "critical"), (Severity.WARNING, "warning"),
                            (Severity.INFO, "info")):
        counts = {
            " / ".join(group): r["severity_counts"].get(severity, 0)
            for r, group in group_results
        }
        parts.append(f"{sum(counts.values())} {label}{where(counts)}")
    # Shipped files whose bytes contradict a declaration or a core's own
    # check: the body printed 19 of them under a last line that read clean.
    counts = {
        " / ".join(group): len(_discrepancy_keys(r.get("details", [])))
        for r, group in group_results
    }
    total = sum(counts.values())
    parts.append(f"{total} {'discrepancy' if total == 1 else 'discrepancies'}{where(counts)}")
    lines = [f"{platforms} platforms: {', '.join(parts)}"]

    # Grouped by file, not by platform: sfiii2a.zip missing everywhere was
    # counted and printed once per platform, 24 files for 10 distinct ones.
    holders: dict[str, list[str]] = {}
    for r, group in group_results:
        for name in sorted({
            u["name"] for u in _core_required_missing(_split_undeclared(
                r.get("undeclared_files", []))[1])
        }):
            holders.setdefault(name, []).append(" / ".join(group))
    if holders:
        by_platforms: dict[tuple[str, ...], list[str]] = {}
        for name, groups in sorted(holders.items()):
            by_platforms.setdefault(tuple(groups), []).append(name)
        detail = "; ".join(
            f"{', '.join(names)} ({on(groups)})"
            for groups, names in sorted(by_platforms.items(),
                                        key=lambda item: (-len(item[0]), item[1]))
        )
        lines.append(f"{len(holders)} core file(s) a core cannot run without are "
                     f"missing: {detail}")
    for category, label in _NOT_FIRMWARE.items():
        counts = {
            " / ".join(group): len((r.get("missing_not_firmware") or {}).get(category, []))
            for r, group in group_results
        }
        total = sum(counts.values())
        if total:
            lines.append(f"{total} platform entries missing, not firmware, {label}{where(counts)}")
    return "\n".join(lines)


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
