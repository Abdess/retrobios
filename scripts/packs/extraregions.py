"""The systems each extra serves, its region groups and its required-only spares."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import declared_destination
from model.alternatives import required_only_spares
from model.declarations import declared_root
from model.profiles import entry_system_ids
from model.systems import norm_system_id
from packs.extraplace import extra_region_key
from packs.extras import collect_emulator_extras
from resolve.nativemode import platform_mode
from resolve.regions import FILE_GROUP

if TYPE_CHECKING:
    from typing_extensions import Unpack


def extra_system_ids(extra: dict) -> list[str]:
    """Return the narrowest system ownership preserved on a core extra."""
    explicit = extra.get("source_system")
    if explicit:
        return [str(explicit)]
    return [str(value) for value in extra.get("source_systems", []) if value]

def serving_system_ids(extra: dict) -> list[str]:
    """Every system the extra's file serves: its own core's and those of the
    other cores whose claim rides on it. One file stands per destination, so
    narrowed to any of their systems the file is what that core reads.
    """
    ids = list(extra_system_ids(extra))
    for claim in extra.get("other_claims", []):
        ids.extend(s for s in extra_system_ids(claim) if s not in ids)
    return ids


def kept_entries(entries: list[dict], required_only: bool) -> list[dict]:
    """The entries a pack keeps: optional ones go under --required-only."""
    if not required_only:
        return entries
    return [e for e in entries if e.get("required") is not False]


def extras_for_systems(extras: list[dict], system_ids: list[str]) -> list[dict]:
    """Core extras owned by one of the given systems.

    Extras carry their profile/system identity directly. Display labels are
    presentation only and must never drive routing.
    """
    wanted = set(system_ids) | {norm_system_id(s) for s in system_ids}
    return [
        fe for fe in extras
        if (
            set(serving_system_ids(fe))
            | {norm_system_id(s) for s in serving_system_ids(fe)}
        ) & wanted
    ]


def report_owned_by_systems(report: list[dict], system_ids: list[str]) -> list[dict]:
    """Gap report entries whose extra a pack built with --system carries.

    The other cores whose claim rides on the entry count, as the builder
    counts them: MAME 2009's taitofx1.zip went into a --system
    panasonic-3do pack for MAME 2016 and was missing from the report.
    """
    def owner(entry: dict) -> dict:
        return {"source_system": entry.get("system"), "source_systems": entry.get("systems", [])}

    return [
        u for u in report
        if extras_for_systems(
            [{**owner(u), "other_claims": [owner(c) for c in u.get("other_claims", [])]}],
            system_ids,
        )
    ]


def _ships(
    config: dict,
    file_entry: dict,
    db: dict,
    zip_contents: dict | None,
    data_registry: dict | None,
    override: str | None,
) -> bool:
    """Whether the builder packs this declaration: resolved, and not refused
    by a hash frontend. A dump whose md5 Recalbox would reject is left out
    of the pack, so it cannot win a regional slot over a file that ships.

    Resolved with the builder's own inputs: without the data directories,
    AmberELEC's bluemsx config.ini read as missing while the pack held it.
    """
    from resolve.packfiles import resolve_declaration
    from resolve.acceptance import baseline_verdict

    path, status = resolve_declaration(
        file_entry, db, "bios", zip_contents, data_registry, override, offline=True,
    )
    if not path:
        return False
    return baseline_verdict(
        file_entry, path, status, platform_mode(config),
        config.get("hash_rule", ""),
    )[1] is None


class RegionGroupOptions(TypedDict, total=False):
    """What platform_region_groups reads besides the platform, and fills."""

    include_all: bool
    required_only: bool
    extras_out: list[dict] | None
    held_out: set[str] | None
    undeclared: list[dict] | None
    zip_contents: dict | None
    data_registry: dict | None
    slot_overrides: dict[str, str] | None


def platform_region_groups(
    config: dict,
    systems: dict,
    emulators_dir: str,
    db: dict | None,
    base_dest: str,
    emu_profiles: dict | None,
    *,
    target_cores: set[str] | None = None,
    include_extras: bool = True,
    **options: Unpack[RegionGroupOptions],
) -> tuple[dict[str, list[tuple[str, str]]], dict[tuple[str, str, str], str]]:
    """Group a platform's pack candidates the way region filtering reads them.

    ``held_out`` receives the destinations whose file the collection holds:
    a missing file is grouped so the report can withdraw it, but it never
    takes the slot of a held one (resolve_region_drops).

    Returns the groups and, for every core extra, the destination it was
    grouped under, keyed by (emulator, name).  verify.py needs that mapping to
    withdraw from its report exactly what the builder withdraws from the pack:
    grouping the declared files here and the core extras there would let the
    two answer differently on the same request.  `extras_out` receives the
    core extras that were grouped, for the install manifest. ``undeclared``
    is the gap report when the caller holds it (undeclared_report, with the
    same target_cores and include_all). ``zip_contents``, ``data_registry``
    and ``slot_overrides`` (keyed by full pack destination) are the ones the
    builder resolves with, so a held declaration is the one the pack ships.
    """
    reject_unknown("platform_region_groups", options, RegionGroupOptions.__optional_keys__)
    include_all = options.get("include_all", False)
    undeclared = options.get("undeclared")
    required_only = options.get("required_only", False)
    held_out = options.get("held_out")
    extras_out = options.get("extras_out")
    zip_contents = options.get("zip_contents")
    data_registry = options.get("data_registry")
    slot_overrides = options.get("slot_overrides")
    groups: dict[str, list[tuple[str, str]]] = {}
    for sys_id, system in systems.items():
        members = groups.setdefault(sys_id, [])
        # Decided over what the pack keeps: an optional winner removed
        # afterwards left its slot empty.
        for file_entry in kept_entries(system.get("files", []), required_only):
            dest = declared_destination(file_entry)
            if dest:
                members.append((dest, file_entry.get("name", "")))
                full_dest = f"{base_dest}/{dest}" if base_dest else dest
                if held_out is not None and db is not None and _ships(
                    config, file_entry, db, zip_contents, data_registry,
                    (slot_overrides or {}).get(full_dest),
                ):
                    held_out.add(dest)

    extra_dests: dict[tuple[str, str, str], str] = {}
    if not include_extras or db is None:
        return groups, extra_dests

    absent: list[dict] = []
    extras = collect_emulator_extras(
        config,
        emulators_dir,
        db,
        set(),
        base_dest,
        emu_profiles,
        target_cores=target_cores,
        include_all=include_all,
        claimants=extra_dests,
        absent=absent,
        undeclared=undeclared,
    )
    held = {id(extra) for extra in extras}
    spellings = system_spellings(systems)
    region_prefix = declared_root(config)
    for extra in kept_entries(extras + absent, required_only):
        dest = extra_region_key(extra, region_prefix)
        if not dest:
            continue
        name = extra.get("name", "")
        extra_dests[
            (
                extra.get("source_emulator", ""),
                extra.get("source_name", ""),
                extra.get("source_path", ""),
            )
        ] = dest
        # A file a filename-agnostic scan accepts by shape competes only if
        # its seed names a region: PCSX2 picks no PS2 BIOS by territory, and
        # looked up by name its scph50006 took DuckStation's [japan], which
        # describes DuckStation's own PS1-on-PS2 choice.
        competes = not extra.get("agnostic_scan") or extra.get("region")
        for group_id in extra_region_groups(extra, spellings) if competes else ():
            groups.setdefault(group_id, []).append((dest, name))
        if extras_out is not None and id(extra) in held:
            extras_out.append(extra)
        if held_out is not None and id(extra) in held:
            held_out.add(dest)
    return groups, extra_dests


def system_spellings(systems: Iterable[str]) -> dict[str, str]:
    """A platform's own spelling of each system, keyed the way ids compare.

    RetroDECK files the Master System as sega-master-system, the profiles as
    sega-mastersystem. Grouped under both, the declared bios/bios_J.sms and
    the core's bios_J.sms were reduced apart and a --region us pack kept the
    Japanese BIOS.
    """
    spellings: dict[str, str] = {}
    for sys_id in sorted(systems):
        spellings.setdefault(norm_system_id(sys_id), sys_id)
    return spellings


def _region_basis(extra: dict) -> tuple[str, str]:
    """What a core extra's region group is keyed on, in either mode.

    A selection slot, else the one system the file is chosen for, else the
    file alone. Platform and emulator mode both read this, so the two
    cannot group the same file apart.
    """
    variant = extra.get("selection_slot")
    if variant:
        # A selection slot is one slot of one core, whatever system each
        # member is filed under: PicoDrive files its US Mega CD BIOS under
        # sega-segacd and the EU/JP ones under sega-megacd, and find_bios
        # picks one of the twelve.
        return "variant", str(variant)
    systems = extra_system_ids(extra)
    if len(systems) == 1:
        return "system", systems[0]
    # No system names the machine this file is chosen for. Filed under every
    # system of a 30-system profile, CLK's American MSX ROM made the
    # Enterprise group drop its German ROM. Alone, it drops nothing and is
    # never dropped.
    return "file", str(extra.get("destination", extra.get("name", "")))


def extra_region_groups(
    extra: dict, spellings: dict[str, str] | None = None
) -> list[str]:
    """The region groups a core extra competes in.

    A group named after a system takes the platform's spelling of it, so the
    extra competes beside the files the platform declares for that system.
    """
    emulator = extra.get("source_emulator", "")
    kind, value = _region_basis(extra)
    if kind == "variant":
        return [f"{emulator}:variant:{value}"]
    if kind == "system":
        return [(spellings or {}).get(norm_system_id(value), value)]
    return [f"{emulator}{FILE_GROUP}{value}"]


def emulator_region_drops(
    selected: list[tuple[str, dict]],
    standalone: bool,
    regions: list[str],
    required_only: bool = False,
    db: dict | None = None,
    zip_contents: dict | None = None,
    data_registry: dict | None = None,
) -> set[str]:
    """Destinations an emulator-mode `--region` withdraws.

    One group per system (or explicit selection_slot) inside each profile, so
    a multi-system core such as O2EM keeps a fallback BIOS for every system
    instead of letting one matching system empty another. The emulator pack
    and `verify --emulator` both read this, keyed by pack destination.

    With `db`, a requested-region file the collection lacks never displaces
    a held one, as in platform mode: a held scph5501.bin was withdrawn for a
    Japanese image nobody had collected, and the pack shipped no PlayStation
    BIOS at all. ``zip_contents`` and ``data_registry`` are the ones the
    emulator pack resolves with.
    """
    from resolve import regions as resolve_regions
    from packs.paths import resolve_destination
    from resolve.validation import build_validation_index
    from resolve.entryscope import filter_files_by_mode

    region_index = resolve_regions.build_region_index(dict(selected))
    region_groups: dict[str, list[tuple[str, str]]] = {}
    held: set[str] | None = set() if db is not None else None
    validation_index = build_validation_index(dict(selected)) if db is not None else {}
    for emu_name, profile in sorted(selected):
        # Decided over what the pack keeps, as on the platform side: an
        # optional winner removed afterwards left its slot empty.
        entries = filter_files_by_mode(profile.get("files", []), standalone)
        for fe in kept_entries(entries, required_only):
            dest = resolve_destination(fe, standalone)
            if dest:
                group_id = _emulator_region_group(emu_name, profile, fe, dest)
                region_groups.setdefault(group_id, []).append(
                    (dest, fe.get("name", ""))
                )
                if held is not None and db is not None and _emulator_ships(
                    fe, emu_name, profile, db, validation_index,
                    zip_contents, data_registry,
                ):
                    held.add(dest)
    return resolve_regions.resolve_region_drops(region_groups, region_index, regions, held)


class SpareOptions(TypedDict, total=False):
    data_registry: dict | None


def emulator_required_spares(
    emu_name: str,
    profile: dict,
    files: list[dict],
    standalone: bool,
    region_drops: set[str],
    db: dict,
    validation_index: dict,
    zip_contents: dict | None,
    **options: Unpack[SpareOptions],
) -> set[str]:
    """The destinations an emulator --required-only pack leaves out: of each
    required set, one held member stays, the first the code loads among
    those the pack still carries after the region filter. An archive unit
    is a member like a loose file: Kronos reads kronos/stvbios.zip, else
    stvbios.zip. The pack and verify --emulator both read this."""
    from model.alternatives import groups_of, rank_in, required_groups
    from resolve.archives import archive_entry
    from packs.paths import archive_destination, resolve_destination

    reject_unknown("emulator_required_spares", options, SpareOptions.__optional_keys__)
    data_registry = options.get("data_registry")
    candidates: list[dict] = []
    archives: list[str] = []
    for fe in files:
        archive = fe.get("archive")
        if archive and archive not in archives:
            archives.append(archive)
            own = archive_entry(archive, files)
            if groups_of(own):
                candidates.append({"dest": archive_destination(
                    archive, profile.get("archive_prefix", ""),
                    profile.get("pack_structure"), standalone,
                ), "entry": own})
    candidates.extend(
        {"dest": resolve_destination(fe, standalone), "entry": fe}
        for fe in files if not fe.get("archive") and groups_of(fe)
    )
    if not candidates:
        return set()
    spares = required_only_spares(
        candidates,
        owner=lambda _c: emu_name,
        held=lambda c: _emulator_ships(
            c["entry"], emu_name, profile, db, validation_index, zip_contents, data_registry,
        ),
        gone=lambda c: c["dest"] in region_drops,
        sets=lambda c: {g: rank_in(c["entry"], g) for g in required_groups(c["entry"], profile)},
    )
    return {c["dest"] for c in candidates if id(c) in spares}


def _emulator_ships(
    file_entry: dict, emu_name: str, profile: dict, db: dict,
    validation_index: dict, zip_contents: dict | None, data_registry: dict | None,
) -> bool:
    """Whether the emulator pack ships this entry: held, and not refused by
    the core's own check, the test _ships applies on the platform side.

    Resolved as generate_emulator_pack resolves: without the data
    directories, dolphin-mmjr2's nwc24msg.cfg read as missing while the pack
    held it.
    """
    from resolve.packfiles import resolve_file
    from resolve.acceptance import validated_choice
    from resolve.entryscope import with_archive_members

    local, status = resolve_file(
        {**with_archive_members(file_entry, profile.get("files", [])),
         "source_profile": emu_name},
        db, "bios", zip_contents,
        dest_hint=file_entry.get("path", ""),
        data_dir_registry=data_registry,
        offline=True,
    )
    if status in ("not_found", "user_provided") or not local:
        return False
    _chosen, disagreement = validated_choice(
        file_entry, local, db, validation_index, "bios", None, emulators={emu_name},
    )
    return disagreement is None


def _emulator_region_group(
    emu_name: str, profile: dict, file_entry: dict, dest: str
) -> str:
    """Stable group ID for regional alternatives within an emulator profile.

    Keyed by _region_basis, the rule extra_region_groups applies on the
    platform side, over the systems entry_system_ids gives the entry. A
    system group carries the emulator, since an emulator pack reduces each
    profile on its own.
    """
    kind, value = _region_basis({
        "selection_slot": file_entry.get("selection_slot"),
        "source_system": file_entry.get("system"),
        "source_systems": entry_system_ids(file_entry, profile),
        "destination": dest,
    })
    if kind == "variant":
        return f"{emu_name}:variant:{value}"
    if kind == "system":
        return f"{emu_name}:system:{value}"
    return f"{emu_name}{FILE_GROUP}{dest}"
