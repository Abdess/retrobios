"""A platform pack cut into one pack per system or per manufacturer."""

from __future__ import annotations

import contextlib
import io
import os
from typing import TYPE_CHECKING

from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from packs.archive import PackRecord, _reject_unknown
from packs.emulatorpack import _system_display_name
from packs.extras import _collect_emulator_extras, extras_for_systems as _extras_for_systems
from packs.naming import _name_part, _narrowings, _platform_pack_stem
from packs.platformpack import PackNarrowing, _PartScope, _report_left_out, generate_pack
from resolve.cores import platform_scope_systems
from resolve.gamedata import without_game_data

if TYPE_CHECKING:
    from typing_extensions import Unpack


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


def _split_extras(config: dict, db: dict, narrowing: PackNarrowing) -> list[dict]:
    """The core extras of every part, collected once (expensive: scans 260+
    emulator profiles), then distributed per group by system overlap."""
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
        all_extras = _collect_emulator_extras(
            cut.config if cut else config, narrowing["emulators_dir"], db,
            set(), base_dest, cut.profiles if cut else emu_profiles,
            target_cores=target_cores, include_all=(source == "truth"),
        )
    else:
        all_extras = []
    if cut is not None and source != "platform":
        _report_left_out(cut, systems=set(), cores=True)
    return all_extras


def generate_split_packs(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    group_by: str = "system",
    **options: Unpack[SplitOptions],
) -> list[str]:
    """Generate split packs (one ZIP per system or manufacturer).

    The parts add up to the full pack: each is built against the full pack's
    own placement (``within``). ``records`` builds the parts in memory, keyed
    by part name, with no archive written.
    """
    _reject_unknown("generate_split_packs", options, SplitOptions.__optional_keys__)
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
        for tag, _label in _narrowings(
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
        f"{_platform_pack_stem([platform_name], platform_name, platforms_dir)}{split_tags}"
    )
    split_dir = os.path.join(output_dir, f"{part_prefix}{group_tag}_Split")
    if records is None:
        os.makedirs(split_dir, exist_ok=True)

    emu_profiles = narrowing["emu_profiles"]
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(narrowing["emulators_dir"])
        narrowing["emu_profiles"] = emu_profiles
    full = PackRecord()
    with contextlib.redirect_stdout(io.StringIO()):
        generate_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            record=full, **narrowing,
        )

    def part(pack_name: str, scope: _PartScope) -> str | None:
        record = PackRecord() if records is not None else None
        zip_path = generate_pack(
            platform_name, platforms_dir, db, bios_dir, split_dir,
            pack_name=pack_name, record=record, within=full.sources,
            **scope, **narrowing,
        )
        if records is not None and record is not None and zip_path:
            records[pack_name] = record
        return zip_path
    # The systems a core of the target runs: a part per declared system sent
    # each one the target drops to a refusal naming it as unknown.
    systems = platform_scope_systems(config, emu_profiles, narrowing["target_cores"])

    if group_by == "manufacturer":
        groups = _group_systems_by_manufacturer(systems, db, bios_dir)
    else:
        groups = {_system_display_name(sid): [sid] for sid in systems}

    all_extras = _split_extras(config, db, narrowing)
    results = []
    for group_name, group_system_ids in sorted(groups.items()):
        group_extras = _extras_for_systems(all_extras, group_system_ids)
        zip_path = part(
            f"{part_prefix}_{_name_part(group_name, '_')}_BIOS_Pack.zip",
            {"system_filter": group_system_ids, "precomputed_extras": group_extras},
        )
        if zip_path:
            results.append(zip_path)

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
        zip_path = part(
            f"{part_prefix}_Other_Cores_BIOS_Pack.zip",
            {"precomputed_extras": undistributed, "extras_only": True},
        )
        if zip_path:
            results.append(zip_path)

    return results
