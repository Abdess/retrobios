"""What a platform pack holds before it is written: settings, variants and slot choices."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import EMULATORS_DIR
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from packs import slots
from packs.archive import PackRecord
from packs.extras import platform_region_groups, undeclared_report
from packs.naming import pack_narrowings, platform_pack_name
from packs.packcounts import PackCounts
from resolve import regions as resolve_regions, slot as slot_mod
from resolve.contentlayout import TARGET_KEY
from resolve.cores import platform_scope_systems, system_scope_error
from resolve.gamedata import GameDataCut, without_game_data
from resolve.nativemode import platform_mode
from resolve.packfiles import preferred_entries as _preferred_entries
from resolve.validation import build_validation_index
from resolve.acceptance import destination_owners

if TYPE_CHECKING:
    from typing_extensions import Unpack


class _VariantOptions(TypedDict, total=False):
    """The keyword options of _select_variants."""

    regions: list[str] | None
    one_per_slot: bool
    required_only: bool
    undeclared: list[dict] | None
    zip_contents: dict | None
    data_registry: dict | None
    slot_overrides: dict[str, str] | None


def _select_variants(
    config: dict,
    pack_systems: dict,
    emulators_dir: str,
    db: dict,
    base_dest: str,
    emu_profiles: dict | None,
    target_cores: set[str] | None,
    source: str,
    **options: Unpack[_VariantOptions],
) -> tuple[set, list, list]:
    """Which regional and slot alternatives this pack leaves out.

    Both reductions are decided once, over the platform baseline and the
    core extras together: deciding them separately is how the report and
    the pack came to withdraw different files for the same request.
    Returns the destinations to drop, the groups kept only as a
    fallback, and the slots no profile puts in order.
    """
    reject_unknown("_select_variants", options, _VariantOptions.__optional_keys__)
    regions = options.get("regions")
    one_per_slot = options.get("one_per_slot", False)
    region_drops: set[str] = set()
    region_fallbacks: list[str] = []
    # One grouping for both passes: a file judged in its own system by one
    # pass must not land in every system of its profile for the other.
    region_groups: dict[str, list[tuple[str, str]]] = {}
    held: set[str] = set()
    if regions or one_per_slot:
        region_groups, _extra_dests = platform_region_groups(
            config,
            pack_systems,
            emulators_dir,
            db,
            base_dest,
            emu_profiles,
            target_cores=target_cores,
            include_extras=(source != "platform"),
            include_all=(source == "truth"),
            required_only=options.get("required_only", False),
            held_out=held,
            undeclared=options.get("undeclared"),
            zip_contents=options.get("zip_contents"),
            data_registry=options.get("data_registry"),
            slot_overrides=options.get("slot_overrides"),
        )
    if regions:
        region_index = resolve_regions.platform_region_index(
            config, emu_profiles or {}, target_cores
        )
        region_drops = resolve_regions.resolve_region_drops(
            region_groups, region_index, regions, held
        )
        region_fallbacks = resolve_regions.fallback_groups(
            region_groups, region_index, regions
        )

    slot_undecidable: list[str] = []
    if one_per_slot:
        slot_drops, slot_undecidable = one_per_slot_drops(
            config, emu_profiles, target_cores, region_groups, region_drops, held
        )
        region_drops = region_drops | slot_drops

    return region_drops, region_fallbacks, slot_undecidable


def one_per_slot_drops(
    config: dict,
    emu_profiles: dict | None,
    target_cores: set[str] | None,
    region_groups: dict[str, list[tuple[str, str]]],
    region_drops: set[str],
    held: set[str],
) -> tuple[set[str], list[str]]:
    """What --one-per-slot withdraws once the regions have, and the slots no
    declared order decides. The pack and the manifest both read it."""
    slot_groups = {
        sys_id: [(d, n) for d, n in members if d not in region_drops]
        for sys_id, members in region_groups.items()
    }
    return slot_mod.resolve_slot_drops(
        slot_groups,
        slot_mod.platform_slot_index(config, emu_profiles or {}, target_cores),
        held,
    )


@dataclass(frozen=True)
class PackSettings:
    """PackOptions with their defaults."""

    emulators_dir: str = EMULATORS_DIR
    zip_contents: dict | None = None
    data_registry: dict | None = None
    emu_profiles: dict | None = None
    target_cores: set[str] | None = None
    required_only: bool = False
    system_filter: list[str] | None = None
    precomputed_extras: list[dict] | None = None
    extras_only: bool = False
    source: str = "full"
    flatten: bool = True
    regions: list[str] | None = None
    target_name: str | None = None
    one_per_slot: bool = False
    offline: bool | None = None
    pack_name: str | None = None
    no_game_data: bool = False
    record: PackRecord | None = None
    within: dict[str, str] | None = None
    uncached_out: set[str] | None = None
    counts: list[PackCounts] | None = None


@dataclass
class PlatformPlan:
    """What a platform pack is built from, settled before its first member."""

    platform_name: str
    platforms_dir: str
    db: dict
    bios_dir: str
    opts: PackSettings
    config: dict
    emu_profiles: dict
    zip_contents: dict
    cut: GameDataCut | None
    narrowings: list[tuple[str, str]]
    zip_path: str
    validation_index: dict
    platform_profiles: dict[str, dict]
    validation_owners: dict
    slot_overrides: dict[str, str]
    pack_systems: dict
    preferred_entries: dict[str, int] = field(default_factory=dict)
    undeclared: list[dict] | None = None
    region_drops: set[str] = field(default_factory=set)
    region_fallbacks: list = field(default_factory=list)
    slot_undecidable: list[str] = field(default_factory=list)

    @property
    def verification_mode(self) -> str:
        return platform_mode(self.config)

    @property
    def platform_display(self) -> str:
        return self.config.get("platform", self.platform_name)

    @property
    def base_dest(self) -> str:
        return self.config.get("base_destination", "")

    @property
    def case_insensitive(self) -> bool:
        # Case-insensitive dedup only for platforms targeting Windows/macOS.
        # Linux-only platforms (Batocera, Recalbox, RetroDECK, Lakka, RomM)
        # are case-sensitive and may have distinct files like DISK.ROM vs disk.rom.
        return self.config.get("case_insensitive_fs", False)


def plan_platform_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    opts: PackSettings,
) -> PlatformPlan | str:
    """The configuration, scope and checks a platform pack reads, or the
    reason the systems asked for leave nothing to build."""
    config = load_platform_config(platform_name, platforms_dir)
    if opts.target_name:
        config = {**config, TARGET_KEY: opts.target_name}
    zip_contents = {} if opts.zip_contents is None else opts.zip_contents
    emu_profiles = opts.emu_profiles
    if emu_profiles is None:
        # The pipeline always passes them, but a caller that does not must get the
        # same pack, not one built without validation, slots or agnostic cores.
        emu_profiles = load_emulator_profiles(opts.emulators_dir)
    # Cut from the full config and profiles: the category of a platform
    # entry is read from the profiles' game data entries.
    cut = (
        without_game_data(config, emu_profiles, opts.data_registry, opts.target_cores)
        if opts.no_game_data else None
    )
    if cut is not None:
        config, emu_profiles = cut.config, cut.profiles

    narrowings = pack_narrowings(
        opts.source, opts.regions, opts.target_name, opts.one_per_slot, opts.required_only,
        no_game_data=opts.no_game_data,
    )
    zip_path = os.path.join(
        output_dir,
        platform_pack_name(
            platform_name, platforms_dir, narrowings, opts.system_filter, opts.pack_name
        ),
    )
    if opts.record is None:
        os.makedirs(output_dir, exist_ok=True)

    # Build emulator-level validation index from the platform's own
    # emulators (same scope as verify.py)
    from resolve.cores import resolve_platform_cores

    validation_index = {}
    platform_profiles: dict[str, dict] = {}
    if emu_profiles:
        platform_profiles = {
            name: emu_profiles[name]
            for name in resolve_platform_cores(config, emu_profiles)
        }
        validation_index = build_validation_index(platform_profiles)
    validation_owners = destination_owners(platform_profiles)
    slot_overrides = slots.pack_overrides(
        config, emu_profiles or {}, db, zip_contents, opts.data_registry,
        target_cores=opts.target_cores, source=opts.source,
    )

    pack_systems = platform_scope_systems(
        config, emu_profiles or {}, opts.target_cores, opts.system_filter
    )
    if opts.system_filter and not pack_systems:
        return system_scope_error(config, platform_name, opts.system_filter, opts.target_name)
    if opts.extras_only:
        # The part of a split that carries the core extras no platform system
        # owns: the platform's own files and trees went to the other parts.
        pack_systems = {}

    plan = PlatformPlan(
        platform_name, platforms_dir, db, bios_dir, opts, config, emu_profiles,
        zip_contents, cut, narrowings, zip_path, validation_index, platform_profiles,
        validation_owners, slot_overrides, pack_systems,
    )
    _settle_pack_choices(plan)
    return plan


def _settle_pack_choices(plan: PlatformPlan) -> None:
    """The declaration each destination takes and the variants left out."""
    opts = plan.opts
    if opts.source != "truth":
        # Decided among the declarations this pack keeps: a preferred entry
        # that --required-only drops must not silence its required twin, or
        # the destination leaves the pack without a trace (RetroDECK's four
        # Atari 5200 ROMs, optional under atari-400-800 and required under
        # atari-5200). No data directories: the choice is about the baseline.
        plan.preferred_entries = _preferred_entries(
            plan.pack_systems, plan.db, plan.bios_dir, plan.base_dest, opts.required_only,
            plan.zip_contents, opts.offline,
        )

    # Region selection is decided once, over both the platform baseline and the
    # core extras, so the two phases below consult a single set. Grouping uses a
    # dedicated extras pass with an empty seen set: it only needs group
    # membership, never destinations, and a superset of members is the safe
    # direction. Runs only when --region is given.
    # The gap report both extras passes read, computed once: the region
    # grouping and the core complement below ask it the same question.
    plan.undeclared = (
        undeclared_report(
            plan.config, opts.emulators_dir, plan.db, plan.emu_profiles, opts.target_cores,
            include_all=(opts.source == "truth"),
        )
        if opts.source != "platform" and opts.precomputed_extras is None
        else None
    )
    plan.region_drops, plan.region_fallbacks, plan.slot_undecidable = _select_variants(
        plan.config, plan.pack_systems, opts.emulators_dir, plan.db, plan.base_dest,
        plan.emu_profiles, opts.target_cores, opts.source, regions=opts.regions,
        one_per_slot=opts.one_per_slot, required_only=opts.required_only,
        undeclared=plan.undeclared, zip_contents=plan.zip_contents,
        data_registry=opts.data_registry, slot_overrides=plan.slot_overrides,
    )
