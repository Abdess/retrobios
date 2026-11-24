"""Building a platform pack, whole or cut per system: plan, variant choice, slot settlement, the archive."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.releaserecord import PACK_SUFFIX
from packs.archive import (
    PackRecord,
    writing_pack,
)
from packs.declsettle import DeclarationJudge
from packs.naming import system_display_name
from packs.extras import (
    ExtraResolver,
    collect_emulator_extras,
    extras_for_systems as _extras_for_systems,
)
from packs.naming import file_name_part, pack_narrowings, platform_pack_stem
from packs.packcounts import PackCounts, pack_counts
from packs.platformreport import print_platform_pack, print_split_packs
from resolve.cores import platform_scope_systems
from resolve.gamedata import without_game_data

if TYPE_CHECKING:
    from typing_extensions import Unpack
from packs.packplan import PackSettings, plan_platform_pack
from packs.platformzip import PlatformPackBuild, PlatformPackOutcome, left_out_lines


class PackNarrowing(TypedDict, total=False):
    """How a platform pack is narrowed, shared by a pack and its split parts."""

    emulators_dir: str
    zip_contents: dict | None
    data_registry: dict | None
    emu_profiles: dict | None
    target_cores: set[str] | None
    required_only: bool
    source: str
    regions: list[str] | None
    target_name: str | None
    one_per_slot: bool
    offline: bool | None
    no_game_data: bool


class _PartScope(TypedDict, total=False):
    """What one split part keeps of the platform."""

    system_filter: list[str] | None
    precomputed_extras: list[dict] | None
    extras_only: bool


class PackOptions(PackNarrowing, _PartScope, total=False):
    """The keyword options of generate_pack."""

    flatten: bool
    pack_name: str | None
    record: PackRecord | None
    within: dict[str, str] | None
    uncached_out: set[str] | None
    counts: list[PackCounts] | None


def build_platform_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    **options: Unpack[PackOptions],
) -> PlatformPackOutcome:
    """Build a ZIP pack for a platform. Its report is print_platform_pack's.

    ``no_game_data`` leaves out the platform's entries categorized as game
    data and the cores' ``category: game_data`` files, and names each one.

    ``pack_name`` replaces the derived file name: a split part is named after
    its group, and a name built from every system of a hundred-system group
    is longer than a file name can be.

    ``counts``, when given, receives the pack's PackCounts once it is built.

    ``record`` builds the pack in memory (PackRecord): no archive is written,
    no external file fetched, and the paths are kept on it.

    ``within`` is the full pack's PackRecord.sources, given to a split part:
    a declared file or core extra is written only where the full pack writes
    the same bytes. A part sees neither the other systems' declarations nor
    their extras, so a path the full pack settles (a file/directory conflict,
    a case twin, a path another system's file takes) was written again.

    ``uncached_out`` receives the data directories the pack carries and the
    cache does not hold: the pack is written without them.

    The outcome carries the ZIP path, or the refusal when the systems asked
    for leave nothing to build.
    """
    reject_unknown("generate_pack", options, PackOptions.__optional_keys__)
    opts = PackSettings(**options)
    plan = plan_platform_pack(platform_name, platforms_dir, db, bios_dir, output_dir, opts)
    if isinstance(plan, str):
        return PlatformPackOutcome(zip_path=None, refusal=plan)

    declarations = DeclarationJudge(
        db, bios_dir, plan.zip_contents, opts.data_registry, opts.offline,
        plan.verification_mode, plan.config.get("hash_rule", ""), plan.platform_profiles,
        plan.validation_index, plan.validation_owners,
    )

    extra_resolver = ExtraResolver(
        db, bios_dir, plan.zip_contents, opts.data_registry, plan.validation_index,
        plan.validation_owners, opts.offline, profiles=plan.emu_profiles,
    )

    def resolve_extra(fe: dict, dest: str) -> tuple[str | None, str, str]:
        return extra_resolver.resolve(fe, dest)

    with (
        contextlib.nullcontext(opts.record) if opts.record is not None
        else writing_pack(plan.zip_path)
    ) as zf:
        build = PlatformPackBuild(plan, zf, declarations, resolve_extra)
        build.run()
    if opts.counts is not None:
        opts.counts.append(
            pack_counts(plan.zip_path, build.file_status, build.core_count, build.trees)
        )
    return build.outcome()


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    **options: Unpack[PackOptions],
) -> str | None:
    """Build a platform pack (build_platform_pack) and print its report.

    Returns the path to the generated ZIP, or None when nothing was built.
    """
    outcome = build_platform_pack(platform_name, platforms_dir, db, bios_dir, output_dir, **options)
    print_platform_pack(outcome)
    return outcome.zip_path


def _group_systems_by_manufacturer(
    systems: dict[str, dict],
    db: dict,
    bios_dir: str,
) -> dict[str, list[str]]:
    """Group system IDs by manufacturer for --split --group-by manufacturer."""
    from model.systems import derive_manufacturer

    groups: dict[str, list[str]] = {}
    for sid, sys_data in systems.items():
        mfr = derive_manufacturer(sid, sys_data)
        groups.setdefault(mfr, []).append(sid)
    return groups


class SplitOptions(PackNarrowing, total=False):
    """The keyword options of generate_split_packs."""

    records: dict[str, PackRecord] | None
    uncached_out: set[str] | None


def _split_extras(
    config: dict, db: dict, narrowing: PackNarrowing,
) -> tuple[list[dict], list[str]]:
    """The core extras of every part, collected once (expensive: scans 260+
    emulator profiles), then distributed per group by system overlap, and
    the core game data the run leaves out, named once for all parts."""
    emu_profiles = narrowing["emu_profiles"] or {}
    source = narrowing["source"]
    target_cores = narrowing["target_cores"]
    base_dest = config.get("base_destination", "")
    # Each part cuts the platform's own entries from the full profiles. The
    # extras are collected once here, already without the cores' game data.
    cut = (
        without_game_data(config, emu_profiles, narrowing["data_registry"], target_cores)
        if narrowing["no_game_data"] else None
    )
    if source == "platform":
        all_extras = []
    elif emu_profiles:
        all_extras = collect_emulator_extras(
            cut.config if cut else config, narrowing["emulators_dir"], db,
            set(), base_dest, cut.profiles if cut else emu_profiles,
            target_cores=target_cores, include_all=(source == "truth"),
        )
    else:
        all_extras = []
    left_out = (
        left_out_lines(cut, systems=set(), cores=True)
        if cut is not None and source != "platform" else []
    )
    return all_extras, left_out


@dataclass
class SplitOutcome:
    """What a --split build came to: the core game data left out, then each part."""

    left_out: list[str] = field(default_factory=list)
    parts: list[PlatformPackOutcome] = field(default_factory=list)

    @property
    def zip_paths(self) -> list[str]:
        return [part.zip_path for part in self.parts if part.zip_path]


def build_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    **options: Unpack[SplitOptions],
) -> SplitOutcome:
    """Build split packs (one ZIP per system or manufacturer), printing nothing.

    The parts add up to the full pack: each is built against the full pack's
    own placement (``within``). ``records`` builds the parts in memory, keyed
    by part name, with no archive written.
    """
    reject_unknown("generate_split_packs", options, SplitOptions.__optional_keys__)
    config = load_platform_config(platform_name, platforms_dir)
    records = options.get("records")
    narrowing: PackNarrowing = {
        "emulators_dir": options.get("emulators_dir", "emulators"),
        "zip_contents": options.get("zip_contents"),
        "data_registry": options.get("data_registry"),
        "emu_profiles": options.get("emu_profiles"),
        "target_cores": options.get("target_cores"),
        "required_only": options.get("required_only", False),
        "source": options.get("source", "full"),
        "regions": options.get("regions"),
        "target_name": options.get("target_name"),
        "one_per_slot": options.get("one_per_slot", False),
        "offline": options.get("offline"),
        "no_game_data": options.get("no_game_data", False),
    }
    # The split directory carries the same tags as the packs inside it, or two
    # differently narrowed runs write into one another.
    split_tags = "".join(
        tag
        for tag, _label in pack_narrowings(
            narrowing["source"], narrowing["regions"], narrowing["target_name"],
            narrowing["one_per_slot"], narrowing["required_only"],
            no_game_data=narrowing["no_game_data"],
        )
    )
    # Two groupings write different files. Without the tag they accumulate in
    # one directory under one SHA256SUMS.txt.
    group_tag = "" if group_by == "system" else f"_By{group_by.title()}"
    # The parts carry the version, so the directory does too: a rescrape that
    # moves the version would otherwise leave the old parts beside the new
    # under one SHA256SUMS.txt.
    # Named by the stem the full pack reads: assembled here by hand, a '/' in
    # a version nested the directory where the check never looked for it.
    part_prefix = (
        f"{platform_pack_stem([platform_name], platform_name, platforms_dir)}{split_tags}"
    )
    split_dir = os.path.join(output_dir, f"{part_prefix}{group_tag}_Split")
    if records is None:
        os.makedirs(split_dir, exist_ok=True)

    emu_profiles = narrowing["emu_profiles"]
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(narrowing["emulators_dir"])
        narrowing["emu_profiles"] = emu_profiles
    full = PackRecord()
    # The parts add up to the full pack: its trees are the run's account.
    build_platform_pack(
        platform_name, platforms_dir, db, bios_dir, split_dir,
        record=full, uncached_out=options.get("uncached_out"), **narrowing,
    )

    def part(pack_name: str, scope: _PartScope) -> PlatformPackOutcome:
        record = PackRecord() if records is not None else None
        built = build_platform_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            pack_name=pack_name, record=record, within=full.sources,
            **scope, **narrowing,
        )
        if records is not None and record is not None and built.zip_path:
            records[pack_name] = record
        return built
    # The systems a core of the target runs: a part per declared system sent
    # each one the target drops to a refusal naming it as unknown.
    systems = platform_scope_systems(config, emu_profiles, narrowing["target_cores"])

    if group_by == "manufacturer":
        groups = _group_systems_by_manufacturer(systems, db, bios_dir)
    else:
        groups = {system_display_name(sid): [sid] for sid in systems}

    all_extras, left_out = _split_extras(config, db, narrowing)
    outcome = SplitOutcome(left_out=left_out)
    for group_name, group_system_ids in sorted(groups.items()):
        group_extras = _extras_for_systems(all_extras, group_system_ids)
        outcome.parts.append(part(
            f"{part_prefix}_{file_name_part(group_name, '_')}{PACK_SUFFIX}",
            {"system_filter": group_system_ids, "precomputed_extras": group_extras},
        ))

    # Extras whose system the platform does not declare, or that name none,
    # belong to no group: they go in a part of their own, or the parts would
    # not add up to the full pack (4507 of RetroArch's 5430 were left out).
    distributed = {
        id(fe)
        for fe in _extras_for_systems(
            all_extras, [s for ids in groups.values() for s in ids]
        )
    }
    undistributed = [fe for fe in all_extras if id(fe) not in distributed]
    if undistributed:
        outcome.parts.append(part(
            f"{part_prefix}_Other_Cores{PACK_SUFFIX}",
            {"precomputed_extras": undistributed, "extras_only": True},
        ))

    return outcome


def generate_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    **options: Unpack[SplitOptions],
) -> list[str]:
    """Build split packs (build_split_packs) and print each part's report.

    Returns the path of each part written.
    """
    outcome = build_split_packs(
        platform_name, platforms_dir, db, bios_dir, output_dir, group_by, **options,
    )
    print_split_packs(outcome)
    return outcome.zip_paths
