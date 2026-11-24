"""A platform's coverage: each declaration resolved and judged as its frontend would."""

from __future__ import annotations

from pathlib import Path
from model.dbpaths import collection_root
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

from core.paths import BIOS_DIR, EMULATORS_DIR
from core.ziptools import build_zip_contents_index
from model.alternatives import core_file_spares
from model.declarations import OUTER_ROOTS, platform_declarations
from model.profiles import lists_files, load_emulator_profiles
from model.systems import select_systems
from packs import slots
from packs.crossreflaunchers import launcher_reads_not_held
from packs.gaps import find_exclusion_notes, scan_core_files
from packs.verdicts import (
    Status,
)
from resolve.categories import EntryCategories
from resolve.cores import platform_scope_systems, resolve_platform_cores
from resolve.launcherconfig import launcher_unproven
from resolve.nativemode import platform_mode, reads_file_contents
from resolve.validation import build_validation_index
from resolve.acceptance import destination_owners

if TYPE_CHECKING:
    from packs.extras import ExtraResolver
    from typing_extensions import Unpack
from packs.platformtally import (
    DeclarationResolver,
    PlatformRun,
    PlatformTally,
    dest_key,
    twin_index,
)


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
    from packs.extras import unplaceable_extras

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


_HIDDEN_REASONS = {
    "case_twin": "a packed file of the same name in another case takes its place",
    "path_conflict": "a packed file occupies its directory",
}


@dataclass(frozen=True)
class _BuilderPass:
    """The arguments the builder's own pass over the core files is run with."""

    emulators_dir: str
    db: dict
    emu_profiles: dict | None
    target_cores: set[str] | None
    region_drops: set[str] | None
    report: list[dict] | None
    resolver: ExtraResolver | None
    placed_kind: dict[str, str] | None
    system_ids: list[str] | None
    required_only: bool


def _mark_hidden(
    config: dict,
    undeclared: list[dict],
    shipped: dict[str, str | None],
    builder: _BuilderPass,
) -> set[str]:
    """What the builder holds but cannot place beside the files it packed.

    Returns the full destinations the builder fills with a core's file.
    ``builder.report`` is the gap report the caller already computed with the
    builder's arguments. Without it the builder's pass computes its own.
    """
    from packs.extras import hidden_extras

    placed: set[str] = set()
    hidden = hidden_extras(
        config, builder.emulators_dir, builder.db,
        builder.emu_profiles if builder.emu_profiles is not None
        else load_emulator_profiles(builder.emulators_dir),
        shipped, builder.target_cores, builder.region_drops, placed,
        report=builder.report, resolver=builder.resolver, placed_kind=builder.placed_kind,
        system_ids=builder.system_ids, required_only=builder.required_only,
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
    from packs.archive import Placed

    shipped: dict[str, str] = {}
    occupied: dict[str, str | None] = {}
    placed = Placed(case_insensitive)
    for _sys_id, full, local in sorted(packed_order, key=lambda item: item[0]):
        # EmuDeck's system:md5 entries name no file: the builder writes none.
        if not full or full.endswith("/"):
            continue
        if placed.block(full):
            continue
        placed.take(full)
        occupied[full] = local
        if local is not None:
            shipped[full] = local
    return shipped, occupied


def _cut_game_data(
    config: dict,
    emu_profiles: dict | None,
    emulators_dir: str,
    data_dir_registry: dict | None,
    target_cores: set[str] | None,
    system_filter: list[str] | None,
) -> tuple[dict, dict, list[str]]:
    """The config and profiles of a --no-game-data pack, and what it leaves out."""
    from resolve.gamedata import without_game_data

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
    return config, emu_profiles, cut.report_lines()


def _required_declarations(verify_systems: dict) -> dict:
    return {
        sys_id: {
            **system,
            "files": [
                fe for fe in system.get("files", []) if fe.get("required") is not False
            ],
        }
        for sys_id, system in verify_systems.items()
    }


def _region_pass(
    run: PlatformRun, verify_systems: dict, pack_overrides: dict, regions: list[str],
) -> tuple[set[str], list[str], dict[tuple[str, str, str], str]]:
    """The destinations a region run withdraws, the groups no file answers,
    and the destination of each core extra."""
    from resolve import regions as resolve_regions

    # The builder owns pack composition, so it owns the grouping the region
    # pass reads.  Grouping the platform files here and the core extras
    # there let the two answer differently on one request: the report kept
    # every core extra a region run withdraws from the pack.
    from packs.extras import platform_region_groups

    config = run.config
    held: set[str] = set()
    region_groups, region_extra_dests = platform_region_groups(
        config,
        verify_systems,
        run.emulators_dir,
        run.db,
        config.get("base_destination", ""),
        run.profiles,
        target_cores=run.target_cores,
        required_only=run.required_only,
        held_out=held,
        zip_contents=run.zip_contents,
        data_registry=run.data_dir_registry,
        slot_overrides=pack_overrides,
    )
    region_index = resolve_regions.platform_region_index(config, run.profiles, run.target_cores)
    region_drops = resolve_regions.resolve_region_drops(
        region_groups, region_index, regions, held,
    )
    # The pack README names these: no file answers the request, so every
    # candidate stays. Reported here too, or verify reads all OK for a
    # system that has no BIOS for the region asked.
    region_fallbacks = resolve_regions.fallback_groups(
        region_groups, region_index, regions
    )
    return region_drops, region_fallbacks, region_extra_dests


def _narrowed(
    run: PlatformRun,
    rows: list[dict],
    region_drops: set[str],
    region_extra_dests: dict[tuple[str, str, str], str],
) -> list[dict]:
    """The rows of the core walk a narrowed pack keeps, as the builder keeps them."""
    if run.system_filter:
        # A system pack carries the extras its systems own.
        from packs.extras import report_owned_by_systems

        rows = report_owned_by_systems(rows, run.system_filter)
    if run.required_only:
        rows = [u for u in rows if u.get("required") is not False]
    if region_drops:
        rows = [
            u
            for u in rows
            if region_extra_dests.get(
                (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
            )
            not in region_drops
        ]
    return rows


def _platform_gaps(
    run: PlatformRun,
    occupied: dict[str, str | None],
    region_drops: set[str],
    region_extra_dests: dict[tuple[str, str, str], str],
    validation_index: dict,
    validation_owners: dict[str, list[tuple[str, str]]],
) -> tuple[list[dict], set[str], dict[str, str], list[dict]]:
    """The core files of the pack: the gap report as the builder narrows it,
    the destinations it fills, the category of each, and the files of the
    pack a profile documents unsourceable."""
    config = run.config
    # Cross-reference undeclared files, called exactly as the builder calls
    # it: its declarations, not the enriched ones (a core file the platform
    # also declares under another name is packed at the core's own path, 21
    # such files in the RetroArch pack), and no names from inside archives
    # or data trees (a loose file whose name exists only as a member of
    # naomi2.zip was counted "in pack" while the builder shipped nothing).
    core_files = scan_core_files(
        config,
        run.emulators_dir,
        run.db,
        run.emu_profiles,
        target_cores=run.target_cores,
        declared_names=platform_declarations(config, run.db, enrich=False),
    )
    undeclared = core_files.undeclared
    # The builder's own pass reads the same report: computed once here and
    # handed over as it stands now, before the markings below.
    report_for_builder = [dict(u) for u in undeclared]
    undeclared = _narrowed(run, undeclared, region_drops, region_extra_dests)
    if run.required_only:
        # One member of a required set, as the builder keeps it.
        spares = core_file_spares(undeclared)
        undeclared = [u for u in undeclared if id(u) not in spares]
    _mark_unplaced(config, undeclared, run.profiles)
    from packs.extras import ExtraResolver

    placed_kind: dict[str, str] = {}
    placed = _mark_hidden(config, undeclared, occupied, _BuilderPass(
        run.emulators_dir, run.db, run.emu_profiles, run.target_cores, region_drops,
        report_for_builder,
        ExtraResolver(
            run.db, BIOS_DIR, run.zip_contents, run.data_dir_registry,
            validation_index, validation_owners, profiles=run.profiles,
            pending_assets=True,
        ),
        placed_kind,
        run.system_filter,
        run.required_only,
    ))
    unsourceable = _narrowed(run, core_files.unsourceable, region_drops, region_extra_dests)
    return undeclared, placed, placed_kind, unsourceable


def _profile_coverage(
    profiles: dict, verify_systems: dict, file_status: dict[str, str],
    validation_index: dict,
) -> tuple[int, int]:
    """Destinations whose file a core validates, and those a profile names."""
    gt_filenames = set(validation_index)
    profiled_names: set[str] = set()
    for profile in profiles.values():
        if not lists_files(profile):
            continue
        for f in profile.get("files", []):
            name = f.get("name", "")
            if name:
                profiled_names.add(name)
            profiled_names.update(f.get("aliases") or [])
    dest_to_name: dict[str, str] = {}
    for sys_id, system in verify_systems.items():
        for fe in system.get("files", []):
            dest_to_name.setdefault(dest_key(fe, sys_id), fe.get("name", ""))
    with_validation = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in gt_filenames
    )
    with_profile = sum(
        1 for dest in file_status if dest_to_name.get(dest, "") in profiled_names
    )
    return with_validation, with_profile


class PlatformNarrowing(TypedDict, total=False):
    """The narrowings of a platform pack verify_platform reports on."""

    regions: list[str] | None
    system_filter: list[str] | None
    no_game_data: bool
    required_only: bool


def verify_platform(
    config: dict,
    db: dict,
    emulators_dir: str = EMULATORS_DIR,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    data_dir_registry: dict | None = None,
    **narrowing: Unpack[PlatformNarrowing],
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
    unknown = sorted(set(narrowing) - set(PlatformNarrowing.__annotations__))
    if unknown:
        raise TypeError(f"verify_platform() got an unexpected keyword argument '{unknown[0]}'")
    regions = narrowing.get("regions")
    system_filter = narrowing.get("system_filter")
    no_game_data = narrowing.get("no_game_data", False)
    required_only = narrowing.get("required_only", False)
    left_out: list[str] = []
    if no_game_data:
        config, emu_profiles, left_out = _cut_game_data(
            config, emu_profiles, emulators_dir, data_dir_registry, target_cores,
            system_filter,
        )
    # Normalized once: a typo in a platform YAML must not verify with one
    # mode and be scored with another.
    mode = platform_mode(config)
    platform = config.get("platform", "unknown")

    # The builder settles a destination claimed by both layers, and this must read
    # the same decision, or the two tools describe different packs.
    has_zipped = any(
        fe.get("zipped_file")
        for sys in config.get("systems", {}).values()
        for fe in sys.get("files", [])
    )
    zip_contents = build_zip_contents_index(db, collection_root(Path(BIOS_DIR))) if has_zipped else {}

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
    validation_index = build_validation_index(platform_profiles)
    validation_owners = destination_owners(platform_profiles)

    verify_systems = platform_scope_systems(config, profiles, target_cores, system_filter)
    if required_only:
        verify_systems = _required_declarations(verify_systems)

    categories = EntryCategories(config, profiles, data_dir_registry)
    run = PlatformRun(
        config, db, emulators_dir, emu_profiles, profiles, target_cores,
        data_dir_registry, zip_contents, system_filter, required_only, mode, base_dest,
    )

    region_drops: set[str] = set()
    region_fallbacks: list[str] = []
    region_extra_dests: dict[tuple[str, str, str], str] = {}
    if regions:
        region_drops, region_fallbacks, region_extra_dests = _region_pass(
            run, verify_systems, pack_overrides, regions,
        )

    # A destination two systems declare with two hashes ships one file, the
    # one the builder prefers. The other declaration is scored against that
    # file, as the frontend will score it after installation: RetroDECK's
    # xroar component hashes bios/disk.rom and finds the PC-88 ROM.
    preferred_entries, winners = twin_index(
        verify_systems, db, base_dest, zip_contents
    )
    tally = PlatformTally(
        run, platform,
        DeclarationResolver(
            db, zip_contents, data_dir_registry, slot_overrides, mode,
            platform_profiles, preferred_entries, winners, base_dest,
        ),
        region_drops, validation_index, validation_owners, hle_index, categories,
    )
    for sys_id, system in verify_systems.items():
        for file_entry in system.get("files", []):
            tally.judge(sys_id, file_entry)
    tally.settle_groups()

    shipped, occupied = _builder_placement(
        tally.packed_order, bool(config.get("case_insensitive_fs", False))
    )
    undeclared, placed, placed_kind, unsourceable = _platform_gaps(
        run, occupied, region_drops, region_extra_dests, validation_index,
        validation_owners,
    )
    # What the builder places from the cores, one per pack path, by category:
    # several entries claim one path (rom.key from three Amiga cores) and the
    # builder ships one file there. The category travels on the extra: a copy
    # the second pass makes has no gap report entry to look it up by.
    packed_extras = {"bios": 0, "game_data": 0}
    for category in placed_kind.values():
        packed_extras["game_data" if category == "game_data" else "bios"] += 1
    if not reads_file_contents(mode):
        tally.credit_placed(placed)

    counts, not_firmware = tally.severity_counts()
    file_status = tally.file_status

    # Held but refused: on a hash platform the builder leaves out a file whose
    # declared hash the local copy contradicts. Counted apart, so a coverage
    # figure never calls present what the pack does not carry.
    excluded = sorted(
        dest for dest, status in file_status.items()
        if status == Status.UNTESTED and dest not in tally.shipped_keys
    )

    # Count by file status (ok/untested/missing)
    status_counts: dict[str, int] = {}
    for s in file_status.values():
        status_counts[s] = status_counts.get(s, 0) + 1

    exclusions = find_exclusion_notes(
        config, emulators_dir, emu_profiles, target_cores=target_cores
    )

    with_validation, with_profile = _profile_coverage(
        profiles, verify_systems, file_status, validation_index,
    )
    total = len(file_status)

    # The paths a pack built from this report holds, as written in the ZIP
    # (base_destination stripped, as the builder flattens it). The pipeline
    # compares this set with the archive: equal counts can hide one file
    # credited here and another written there.
    from packs.paths import flat_arcname

    pack_destinations = sorted(
        {flat_arcname(dest, base_dest, True) for dest in shipped} | {
            flat_arcname(dest, base_dest, True) for dest in placed
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
        # Files of the pack a profile documents unsourceable: needed, never
        # held, counted by the same walk as the undeclared ones.
        "unsourceable_files": unsourceable,
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
        "details": tally.details,
        "ground_truth_coverage": {
            "with_validation": with_validation,
            "with_profile": with_profile,
            "platform_only": total - with_validation,
            "total": total,
            "applicable": bool(resolve_platform_cores(config, profiles)),
        },
    }
