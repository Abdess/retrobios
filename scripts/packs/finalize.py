"""Built packs checked against their platform and given their manifest."""

from __future__ import annotations

import json
import os
import shutil
import sys
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

from core.paths import EMULATORS_DIR, PLATFORMS_DIR
from core.artifacts import atomic_scratch
from core.options import reject_unknown
from model.registry import list_registered_platforms
from model.targets import load_target_config
from packs.archive import write_generated_member
from packs.integrity import generate_sha256sums, verify_pack, verify_pack_against_platform
from packs.naming import expected_pack_names, narrows_contents, pack_archives
from packs.scope import annotate_pack_systems

if TYPE_CHECKING:
    from typing_extensions import Unpack


def baseline_shortfall(excluded: int, absent: int) -> list[str]:
    """Why a verified pack holds fewer baseline files than the platform declares."""
    parts = []
    if excluded:
        parts.append(f"{excluded} unsafe excluded")
    if absent:
        parts.append(f"{absent} not in the collection")
    return parts


# Post-generation pack verification + manifest + SHA256SUMS


def inject_manifest(zip_path: str, manifest: dict) -> None:
    """Inject manifest.json into an existing ZIP pack.

    The pack is rewritten beside its final name and swapped in, as
    writing_pack builds it: appending in place rewrites the central
    directory last, so a process killed in between left an unreadable ZIP
    where a valid pack had been.
    """
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    with zipfile.ZipFile(zip_path, "r") as zf:
        has_manifest = "manifest.json" in zf.namelist()

    with atomic_scratch(zip_path, suffix=".partial") as scratch:
        if not has_manifest:
            # Append to a copy. Append mode defaults to ZIP_STORED, which
            # would leave the manifest uncompressed and give the same pack
            # two different byte layouts depending on the path taken here.
            shutil.copyfile(zip_path, scratch)
            with zipfile.ZipFile(scratch, "a", zipfile.ZIP_DEFLATED) as zf:
                write_generated_member(zf, "manifest.json", manifest_json)
        else:
            with zipfile.ZipFile(zip_path, "r") as src, \
                    zipfile.ZipFile(scratch, "w", zipfile.ZIP_DEFLATED) as dst:
                for item in src.infolist():
                    if item.filename == "manifest.json":
                        continue
                    dst.writestr(item, src.read(item.filename))
                write_generated_member(dst, "manifest.json", manifest_json)


def _target_cores_for(
    platform_name: str, target_name: str | None, platforms_dir: str
) -> set[str] | None:
    """Cores a target leaves available, or None when no target was asked for.

    Called on a platform the build already packed under the target, so the
    target is known to it: a platform without one is left out of the run.
    """
    if not target_name:
        return None
    return load_target_config(platform_name, target_name, platforms_dir)


class FinalizeOptions(TypedDict, total=False):
    """The keyword options of verify_and_finalize_packs."""

    platforms_dir: str
    skip_conformance: bool
    data_registry: dict | None
    regions: list[str] | None
    target_name: str | None
    emulators_dir: str
    no_game_data: bool
    pack_systems_by_name: dict[str, dict] | None
    built: Iterable[str] | None


@dataclass(frozen=True)
class _FinalizeSettings:
    """FinalizeOptions with their defaults."""

    platforms_dir: str = PLATFORMS_DIR
    skip_conformance: bool = False
    data_registry: dict | None = None
    regions: list[str] | None = None
    target_name: str | None = None
    emulators_dir: str = EMULATORS_DIR
    no_game_data: bool = False
    pack_systems_by_name: dict[str, dict] | None = None
    built: Iterable[str] | None = None


def _conforms(zip_path: str, pname: str, db: dict, opts: _FinalizeSettings) -> bool:
    """Stage 2 for one platform of a pack: extract and verify against its
    config. Prints the platform's line and its errors."""
    (
        p_ok,
        _total,
        _matched,
        p_errors,
        bl_checked,
        bl_present,
        core_checked,
        core_present,
        bl_excluded,
        bl_absent,
    ) = verify_pack_against_platform(
        zip_path,
        pname,
        opts.platforms_dir,
        db=db,
        emulators_dir=opts.emulators_dir,
        regions=opts.regions,
        data_registry=opts.data_registry,
        target_cores=_target_cores_for(pname, opts.target_name, opts.platforms_dir),
        no_game_data=opts.no_game_data,
    )
    status = "OK" if p_ok else "FAILED"
    exclusion_note = "".join(
        f", {part}" for part in baseline_shortfall(bl_excluded, bl_absent)
    )
    print(
        f"  platform {pname}: {bl_present}/{bl_checked} baseline present"
        f"{exclusion_note}, "
        f"{core_present}/{core_checked} cores present, {status}"
    )
    if not p_ok:
        for err in p_errors:
            print(f"    {err}")
    return p_ok


def verify_and_finalize_packs(
    output_dir: str,
    db: dict,
    **options: Unpack[FinalizeOptions],
) -> bool:
    """Verify all packs, inject manifests, generate SHA256SUMS.

    pack_systems_by_name gives, per pack file name, the systems its
    manifest.json records (pack_systems).

    ``built`` names the packs this run wrote, and only those are verified
    and get a manifest. A pack another run left in the directory was
    reopened, recompressed and given a manifest without its pack_systems,
    which made the installer refuse to narrow it. None takes every pack.

    Two-stage verification:
    1. Hash check against database.json (integrity)
    2. Extract + verify against platform config (conformance)

    Returns True if all packs pass verification.
    """
    reject_unknown("verify_and_finalize_packs", options, FinalizeOptions.__optional_keys__)
    opts = _FinalizeSettings(**options)
    all_ok = True

    # Map ZIP names to platform names
    # By the exact name this run's reduction gives a platform's pack, never by
    # substring: a _Custom or regional pack left by another run was judged
    # against this run's expectation and failed it.
    registered = list_registered_platforms(opts.platforms_dir)
    expected = expected_pack_names(
        registered, opts.platforms_dir, opts.regions, opts.target_name,
        no_game_data=opts.no_game_data,
    )
    packs = pack_archives(output_dir)
    if opts.built is not None:
        packs = [name for name in packs if name in set(opts.built)]
    pack_to_platform: dict[str, list[str]] = {}
    for name in packs:
        for pname in registered:
            if name in expected[pname]:
                pack_to_platform.setdefault(name, []).append(pname)

    failing: list[str] = []
    for name in packs:
        zip_path = os.path.join(output_dir, name)

        # Stage 1: database integrity
        ok, manifest = verify_pack(zip_path, db, data_registry=opts.data_registry)
        summary = manifest["summary"]
        status = "OK" if ok else "ERRORS"
        print(
            f"  verify {name}: {summary['verified']}/{summary['total_files']} verified, "
            f"{summary['untracked']} untracked, {summary['errors']} errors [{status}]"
        )
        if not ok:
            for err in manifest["errors"]:
                print(f"    ERROR: {err}")
            all_ok = False
            failing.append(name)
        annotate_pack_systems(manifest, (opts.pack_systems_by_name or {}).get(name))
        inject_manifest(zip_path, manifest)

        # Stage 2: platform conformance (extract + verify)
        # Skipped for filtered/split/custom packs (intentionally partial)
        if opts.skip_conformance:
            continue
        if narrows_contents(name):
            continue
        for pname in pack_to_platform.get(name, []):
            if not _conforms(zip_path, pname, db, opts):
                all_ok = False
                failing.append(f"{name} ({pname})")

    generate_sha256sums(output_dir)
    if failing:
        # Named at the end, where a 4,000-line log is read, and on stderr.
        print(f"ERROR: packs failed verification: {', '.join(failing)}", file=sys.stderr)
    return all_ok
