"""A built pack held against its platform's declarations and the builder's extras."""

from __future__ import annotations

import os
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import BIOS_DIR, EMULATORS_DIR, declared_destination
from core.ziptools import build_zip_contents_index, is_archive_path, safe_member_parts
from model.dbpaths import collection_root
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from packs import slots
from packs.archive import PACK_DOCUMENTS
from packs.extraregions import platform_region_groups
from packs.integrity import same_members
from packs.naming import pack_variant
from packs.packhashes import native_hash_errors
from packs.paths import MEDIA_MARKER, flat_arcname, has_path_conflict
from resolve import regions as resolve_regions
from resolve.categories import BIOS, EntryCategories
from resolve.cores import platform_scope_systems, resolve_platform_cores
from resolve.gamedata import without_game_data
from resolve.nativemode import hash_mismatch_excludes_file, platform_mode
from resolve.packfiles import resolve_declaration, resolve_file
from resolve.acceptance import baseline_verdict


# Imported at run time where typing has it: a test reads the signature of
# verify_pack_against_platform with its annotations evaluated.
if sys.version_info >= (3, 11):
    from typing import Unpack
elif TYPE_CHECKING:
    from typing_extensions import Unpack


def _held_nowhere(
    entries: list[dict],
    db: dict,
    zip_contents: dict,
    data_dir_registry: dict | None,
) -> bool:
    """Return whether no declaration for a destination resolves to a file."""
    return bool(entries) and all(
        resolve_file(
            entry,
            db,
            BIOS_DIR,
            zip_contents,
            data_dir_registry=data_dir_registry,
            offline=True,
        )[1] == "not_found"
        for entry in entries
    )


def _intentional_hash_exclusion(
    entries: list[dict],
    db: dict,
    bios_dir: str = BIOS_DIR,
    zip_contents: dict | None = None,
    data_dir_registry: dict | None = None,
    verification_mode: str = "md5",
    hash_rule: str = "",
) -> bool:
    """Return whether the builder must omit every declaration as unsafe.

    A hash platform never substitutes a same-named payload for an explicitly
    hash-identified one, so a missing pack member is accounted for when every
    declaration for that destination resolves to a local hash mismatch.  An
    existence platform reads no bytes and the builder ships the file anyway,
    so nothing is ever excluded on its behalf.  Genuine absence,
    external-download failure and a packable alternative stay conformance
    errors in both modes.
    """
    if not entries or not hash_mismatch_excludes_file(verification_mode):
        return False
    archive_index = zip_contents if zip_contents is not None else {}
    for entry in entries:
        local_path, status = resolve_file(
            entry,
            db,
            bios_dir,
            archive_index,
            data_dir_registry=data_dir_registry,
            offline=True,
        )
        # The builder's own verdict: a zipped_file archive is refused when the
        # member is missing whatever the outer resolution said, a hash
        # mismatch when the frontend's digest disagrees too.
        _status, refusal = baseline_verdict(
            entry, local_path, status, verification_mode, hash_rule
        )
        if refusal is None:
            return False
    return True

def _structural_errors(zf: zipfile.ZipFile, zip_set: set) -> list[str]:
    """Faults in the archive itself, before any file is looked up.

    A duplicate entry, an absolute path or a traversal makes the pack
    unsafe to extract whatever it contains, and a zero-byte member is a
    file the user will believe they have. The markers Dolphin ships for
    its graphics mods are legitimately empty.
    """
    errors: list[str] = []
    # Structural checks
    dupes = sum(1 for c in Counter(zf.namelist()).values() if c > 1)
    if dupes:
        errors.append(f"{dupes} duplicate entries")
    errors.extend(f"double slash: {n}" for n in zip_set if "//" in n)
    for info in zf.infolist():
        try:
            safe_member_parts(info)
        except ValueError as exc:
            errors.append(str(exc))

    # Zero-byte check (exclude Dolphin GraphicMods markers)
    errors.extend(
        f"zero-byte: {info.filename}"
        for info in zf.infolist()
        if info.file_size == 0 and not info.is_dir()
        and "GraphicMods" not in info.filename
        and info.filename not in PACK_DOCUMENTS
        and info.filename.rsplit("/", 1)[-1] != MEDIA_MARKER
    )

    return errors


def _shipped_copy(
    entry: dict, db: dict, data_registry: dict | None, mode: str, hash_rule: str,
) -> str | None:
    """The file the builder packs for a declaration, or None.

    The verdict verify applies before it lets a declaration hold its path.
    """
    local, status = resolve_declaration(
        entry, db, BIOS_DIR, None, data_registry, None, offline=True,
    )
    if local and baseline_verdict(entry, local, status, mode, hash_rule)[1] is None:
        return local
    return None


def _builder_extras(
    expect: _Expectation,
    db: dict,
    baseline_groups: dict[str, list[dict]],
    view: _PackView,
    include_all: bool = False,
) -> dict[str, str]:
    """{full destination: local copy} of each core extra the builder writes.

    The platform's paths come first, as in the builder: a destination the
    pack holds whose declarations resolve to a file it ships, or that the
    platform keeps for a user_provided or external entry. One whose
    declarations resolve to nothing, or to a file the frontend's hash
    refuses, is left free, since the builder then places a core's file
    there: taken by the refused file, that core file was never compared.
    """
    from packs.extraresolver import ExtraResolver, hidden_extras
    from resolve.validation import build_validation_index
    from resolve.acceptance import destination_owners

    config, emu_profiles = expect.config, expect.emu_profiles
    data_registry = expect.opts.data_registry
    base_dest = expect.base_dest
    mode = platform_mode(config)
    hash_rule = config.get("hash_rule", "")
    shipped: dict[str, str | None] = {}
    for expected, declarations in baseline_groups.items():
        if not view.holds(expected):
            continue
        unflat = (
            f"{base_dest}/{expected}"
            if view.is_flat and base_dest and not expected.startswith(f"{base_dest}/")
            else expected
        )
        if any(fe.get("storage") in ("user_provided", "external") for fe in declarations):
            shipped[unflat] = None
            continue
        local = next(
            (
                found for fe in declarations
                if (found := _shipped_copy(fe, db, data_registry, mode, hash_rule))
            ),
            None,
        )
        if local:
            shipped[unflat] = local
    platform_profiles = {
        name: emu_profiles[name] for name in resolve_platform_cores(config, emu_profiles)
    }
    placed_local: dict[str, str] = {}
    hidden_extras(
        config, expect.opts.emulators_dir, db, emu_profiles, shipped, expect.target_cores,
        expect.region_drops or None,
        resolver=ExtraResolver(
            db, BIOS_DIR, build_zip_contents_index(db, collection_root(Path(BIOS_DIR))), data_registry,
            build_validation_index(platform_profiles),
            destination_owners(platform_profiles), True, profiles=emu_profiles,
        ),
        placed_local=placed_local,
        include_all=include_all,
        required_only=expect.opts.required_only,
    )
    return placed_local


def _same_content(zf: zipfile.ZipFile, member: str, local: str) -> bool:
    """Whether a pack member carries the bytes of a local copy, or the
    members of an archive the builder normalized."""
    with open(local, "rb") as handle:
        if zf.read(member) == handle.read():
            return True
    return is_archive_path(local) and same_members(zf, member, local)


class ConformanceOptions(TypedDict, total=False):
    """The keyword options of check_pack_conformance."""

    emulators_dir: str
    emu_profiles: dict | None
    regions: list[str] | None
    data_registry: dict | None
    no_game_data: bool


class PlatformCheckOptions(ConformanceOptions, total=False):
    """The keyword options of verify_pack_against_platform."""

    source: str
    required_only: bool


@dataclass(frozen=True)
class _PlatformCheckSettings:
    """PlatformCheckOptions with their defaults."""

    emulators_dir: str = EMULATORS_DIR
    emu_profiles: dict | None = None
    regions: list[str] | None = None
    data_registry: dict | None = None
    source: str = "full"
    required_only: bool = False
    no_game_data: bool = False


@dataclass(frozen=True)
class _Expectation:
    """What the builder would have packed for a platform, before the pack is read."""

    config: dict
    emu_profiles: dict
    expected_systems: dict
    region_drops: set[str]
    db: dict | None
    target_cores: set[str] | None
    opts: _PlatformCheckSettings

    @property
    def base_dest(self) -> str:
        return self.config.get("base_destination", "")


@dataclass(frozen=True)
class _PackView:
    """A pack's member names as the checks read them."""

    zf: zipfile.ZipFile
    zip_set: set[str]
    zip_lower: dict[str, str]
    zip_parents: set[str]
    is_flat: bool

    def holds(self, expected: str) -> bool:
        return expected in self.zip_set or expected.lower() in self.zip_lower


@dataclass
class _BaselineCount:
    """The baseline destinations checked, and what each came to."""

    checked: int = 0
    present: int = 0
    excluded: int = 0
    absent: int = 0
    decl_by_member: dict[str, list[dict]] = field(default_factory=dict)


def _cut_config(
    platform_name: str,
    platforms_dir: str,
    target_cores: set[str] | None,
    opts: _PlatformCheckSettings,
) -> tuple[dict, dict]:
    """The platform's config and the profiles, without game data when asked."""
    config = load_platform_config(platform_name, platforms_dir)
    emu_profiles = opts.emu_profiles
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(opts.emulators_dir)
    if opts.no_game_data:
        cut = without_game_data(config, emu_profiles, opts.data_registry, target_cores)
        config, emu_profiles = cut.config, cut.profiles
    return config, emu_profiles


def _region_drops(
    config: dict,
    emu_profiles: dict,
    expected_systems: dict,
    db: dict | None,
    *,
    target_cores: set[str] | None,
    opts: _PlatformCheckSettings,
) -> set[str]:
    """The regional variants the builder leaves out, by the same selection."""
    region_drops: set[str] = set()
    if not opts.regions:
        return region_drops
    region_index = resolve_regions.platform_region_index(
        config, emu_profiles, target_cores
    )
    held: set[str] = set()
    held_zip_contents = build_zip_contents_index(db, collection_root(Path(BIOS_DIR))) if db is not None else {}
    region_groups, _extra_dests = platform_region_groups(
        config,
        expected_systems,
        opts.emulators_dir,
        db,
        config.get("base_destination", ""),
        emu_profiles,
        target_cores=target_cores,
        include_extras=(opts.source != "platform"),
        include_all=(opts.source == "truth"),
        required_only=opts.required_only,
        held_out=held,
        zip_contents=held_zip_contents,
        data_registry=opts.data_registry,
        slot_overrides=slots.pack_overrides(
            config, emu_profiles, db, held_zip_contents, opts.data_registry,
            target_cores=target_cores, source=opts.source,
        ) if db is not None else None,
    )
    return resolve_regions.resolve_region_drops(
        region_groups, region_index, opts.regions, held
    )


def _pack_view(zf: zipfile.ZipFile, config: dict, base_dest: str) -> _PackView:
    zip_set = set(zf.namelist())
    # A case twin stands in for the file only where the platform's
    # filesystem folds case, as the builder decides: on Lakka bios.col
    # and BIOS.col are two files two cores open, and either one missing
    # was counted present through the other.
    zip_lower = (
        {n.lower(): n for n in zip_set}
        if config.get("case_insensitive_fs", False) else {}
    )

    # Auto-detect flat vs nested ZIP
    is_flat = bool(base_dest) and not any(
        n.startswith(base_dest + "/")
        for n in zip_set
        if n not in (*PACK_DOCUMENTS, MEDIA_MARKER) and not n.endswith("/")
    )
    # Mirror the builder's path-conflict logic: a declaration whose path
    # collides file-vs-directory with a packed member was skipped by the
    # builder (upstream declares e.g. both SGB1.sfc and SGB1.sfc/program.rom)
    zip_parents: set[str] = set()
    for n in zip_set:
        parts = n.split("/")
        for i in range(1, len(parts)):
            zip_parents.add("/".join(parts[:i]))
    return _PackView(zf, zip_set, zip_lower, zip_parents, is_flat)


def _baseline_groups(
    expect: _Expectation, is_flat: bool,
) -> tuple[dict[str, list[dict]], dict[int, str]]:
    """The platform's declarations by the path they expect in the pack, and
    the system of each declaration."""
    opts = expect.opts
    base_dest = expect.base_dest
    baseline_groups: dict[str, list[dict]] = {}
    system_of: dict[int, str] = {}
    for sys_id, system in (expect.expected_systems if opts.source != "truth" else {}).items():
        for fe in system.get("files", []):
            system_of[id(fe)] = sys_id
            if opts.required_only and fe.get("required") is False:
                continue
            dest = declared_destination(fe)
            if not dest:
                continue
            if expect.region_drops and dest in expect.region_drops:
                continue
            expected = f"{base_dest}/{dest}" if base_dest and not is_flat else dest
            baseline_groups.setdefault(expected, []).append(fe)
    return baseline_groups, system_of


def _count_baseline(
    expect: _Expectation,
    view: _PackView,
    baseline_groups: dict[str, list[dict]],
    system_of: dict[int, str],
    errors: list[str],
) -> _BaselineCount:
    """Each baseline destination present, accounted for, or missing."""
    db = expect.db
    data_registry = expect.opts.data_registry
    count = _BaselineCount(checked=len(baseline_groups))
    # RetroBat's group: one packed file of it is enough, as verify counts it.
    packed_groups = {
        (system_of[id(fe)], fe["group"])
        for expected, declarations in baseline_groups.items()
        if view.holds(expected)
        for fe in declarations
        if fe.get("group")
    }
    exclusion_index = build_zip_contents_index(db, collection_root(Path(BIOS_DIR))) if db is not None else {}
    categories = EntryCategories(expect.config, expect.emu_profiles, data_registry)
    for expected, declarations in baseline_groups.items():
        if expected in view.zip_set:
            member = expected
        elif expected.lower() in view.zip_lower:
            member = view.zip_lower[expected.lower()]
        elif has_path_conflict(expected, view.zip_set, view.zip_parents):
            # Skipped by the builder for the same reason: not an error
            count.present += 1
            continue
        elif db is not None and _intentional_hash_exclusion(
            declarations,
            db,
            zip_contents=exclusion_index,
            data_dir_registry=data_registry,
            verification_mode=platform_mode(expect.config),
            hash_rule=expect.config.get("hash_rule", ""),
        ):
            count.excluded += 1
            continue
        elif all(
            fe.get("group") and (system_of[id(fe)], fe["group"]) in packed_groups
            for fe in declarations
        ):
            count.absent += 1
            continue
        elif db is not None and all(
            categories.category(fe, fe.get("destination", fe.get("name", "")),
                                system_of[id(fe)]) != BIOS
            for fe in declarations
        ) and _held_nowhere(declarations, db, exclusion_index, data_registry):
            # A game's data or an entry no core opens that the collection
            # lacks: verify counts it apart. Missing firmware stays an error.
            count.absent += 1
            continue
        else:
            errors.append(f"baseline missing: {expected}")
            continue
        count.present += 1
        count.decl_by_member.setdefault(member, []).extend(declarations)
    return count


def _check_core_extras(
    expect: _Expectation,
    view: _PackView,
    baseline_groups: dict[str, list[dict]],
    errors: list[str],
) -> tuple[int, int]:
    """(checked, present) of the core extras the builder places."""
    # 2. Core extras: the builder's own placement replayed
    #    (packextras.hidden_extras, which verify reads too), after the
    #    platform files it wrote. Each placed extra must sit at its path
    #    with the bytes the builder resolved: an empty seen set and a
    #    presence test credited a core file at a path where the pack
    #    holds the platform's other dump.
    core_checked = 0
    core_present = 0
    opts = expect.opts
    db = expect.db
    if db is None or opts.source == "platform":
        return core_checked, core_present
    placed_local = _builder_extras(
        expect, db, baseline_groups, view, include_all=(opts.source == "truth"),
    )
    for full, local in sorted(placed_local.items()):
        core_checked += 1
        flat = flat_arcname(full, expect.base_dest, view.is_flat)
        member = flat if flat in view.zip_set else view.zip_lower.get(flat.lower())
        if member is None:
            errors.append(f"core missing: {full}")
        elif not _same_content(view.zf, member, local):
            errors.append(
                f"core file differs: {member} is not the {os.path.basename(local)}"
                " the builder places there"
            )
        else:
            core_present += 1
    return core_checked, core_present


def verify_pack_against_platform(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    *,
    target_cores: set[str] | None = None,
    **options: Unpack[PlatformCheckOptions],
) -> tuple[bool, int, int, list[str], int, int, int, int, int, int]:
    """Verify a pack ZIP against its platform config and core requirements.

    A region priority list narrows the expectation to what the builder would
    have packed, using the same selection function. A hardware target narrows
    it the same way and for the same reason: the systems it removes are not
    missing from the pack, they were never asked for. ``source`` and
    ``required_only`` are the variant the pack was built as: a platform-only
    pack is held to the platform's list alone, a truth pack to the cores'
    files alone, and a required-only pack to the required entries of both.
    ``no_game_data`` holds the pack to the firmware alone, cut as the
    builder cuts it.

    Checks:
    1. Every baseline file declared by the platform exists in the ZIP
       at the correct destination path
    2. Every in-repo core extra file (from emulator profiles) is present
    3. No duplicate entries
    4. No path anomalies (double slash, absolute, traversal)
    5. No unexpected zero-byte BIOS files

    Returns ``(all_ok, checked, present, errors, baseline_checked,
    baseline_present, core_checked, core_present, baseline_excluded,
    baseline_absent)``. ``baseline_absent`` counts destinations the collection
    holds no file for that are a game's data or that no core the platform
    runs opens. verify.py counts them apart from firmware.
    """
    reject_unknown(
        "verify_pack_against_platform", options, PlatformCheckOptions.__optional_keys__
    )
    opts = _PlatformCheckSettings(**options)
    config, emu_profiles = _cut_config(platform_name, platforms_dir, target_cores, opts)
    # The systems the builder packed, by the one rule verify and the pack read.
    expected_systems = platform_scope_systems(config, emu_profiles, target_cores)
    expect = _Expectation(
        config, emu_profiles, expected_systems,
        _region_drops(
            config, emu_profiles, expected_systems, db,
            target_cores=target_cores, opts=opts,
        ),
        db, target_cores, opts,
    )
    errors: list[str] = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        view = _pack_view(zf, expect.config, expect.base_dest)
        errors.extend(_structural_errors(zf, view.zip_set))

        # 1. Baseline file presence + native hash check
        baseline_groups, system_of = _baseline_groups(expect, view.is_flat)
        baseline = _count_baseline(expect, view, baseline_groups, system_of, errors)
        errors.extend(native_hash_errors(zf, baseline.decl_by_member, expect.config, db))
        core_checked, core_present = _check_core_extras(expect, view, baseline_groups, errors)

    return (
        len(errors) == 0,
        baseline.checked + core_checked,
        baseline.present + core_present,
        errors,
        baseline.checked,
        baseline.present,
        core_checked,
        core_present,
        baseline.excluded,
        baseline.absent,
    )


def baseline_shortfall(excluded: int, absent: int) -> list[str]:
    """Why a verified pack holds fewer baseline files than the platform declares."""
    parts = []
    if excluded:
        parts.append(f"{excluded} unsafe excluded")
    if absent:
        parts.append(f"{absent} not in the collection")
    return parts


@dataclass(frozen=True)
class PackConformance:
    """A pack checked against one platform, as verify_pack_against_platform returns it."""

    ok: bool
    checked: int
    present: int
    errors: list[str]
    baseline_checked: int
    baseline_present: int
    core_checked: int
    core_present: int
    baseline_excluded: int
    baseline_absent: int

    @property
    def shortfall(self) -> list[str]:
        """Why the baseline holds fewer files than the platform declares."""
        return baseline_shortfall(self.baseline_excluded, self.baseline_absent)


def check_pack_conformance(
    zip_path: str,
    platform_name: str,
    platforms_dir: str,
    db: dict | None = None,
    *,
    target_cores: set[str] | None = None,
    **options: Unpack[ConformanceOptions],
) -> PackConformance | None:
    """A pack checked against its platform under the variant its name says.

    The build and --verify-packs both read this, so a pack gets one verdict:
    a required-only, platform-only or truth pack is held to its own
    expectation, never skipped by one and failed by the other. None for a
    one-per-slot pack, whose slot choice the check does not replay.
    """
    variant = pack_variant(os.path.basename(zip_path))
    if variant is None:
        return None
    source, required_only = variant
    return PackConformance(*verify_pack_against_platform(
        zip_path, platform_name, platforms_dir, db,
        target_cores=target_cores, source=source, required_only=required_only, **options,
    ))
