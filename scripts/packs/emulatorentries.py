"""The entries of a profile an emulator pack carries."""

from __future__ import annotations

from dataclasses import dataclass, field

from model.profiles import entry_serves_systems
from packs.extraregions import emulator_required_spares
from packs.extrascan import expand_agnostic_entries
from packs.paths import archive_destination, resolve_destination
from resolve.archives import archive_entry, archive_is_optional
from resolve.directories import expand_directory_entries
from resolve.entryscope import deliverable


@dataclass(frozen=True)
class EmulatorSelection:
    """What narrows every profile of one emulator or system pack."""

    db: dict
    standalone: bool
    all_profiles: dict
    validation_index: dict
    zip_contents: dict | None
    data_registry: dict | None
    system_ids: list[str] | None = None
    required_only: bool = False
    region_drops: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class EmulatorPackEntries:
    """One profile's share of the pack: its archive units and loose slots."""

    # Every entry serving the pack's systems, before narrowing: an archive's
    # members and a loose file resolved as an archive are read from these.
    entries: list[dict]
    # Archive units the pack carries, in declaration order:
    # (archive name, its own entry, destination).
    archives: list[tuple[str, dict, str]]
    # Loose destinations the pack carries, each with the entries the code
    # accepts there, in declaration order.
    slots: dict[str, list[dict]]
    # Whether anything is left once narrowed, archive members included.
    carries_entries: bool


def _profile_entries(emu_name: str, profile: dict, selection: EmulatorSelection) -> list[dict]:
    """The deliverable entries of a profile, expanded, for the pack's systems."""
    files = expand_agnostic_entries(
        expand_directory_entries(
            deliverable(profile.get("files", []), selection.standalone),
            selection.db,
            selection.standalone,
        ),
        emu_name, profile, selection.db, selection.standalone, selection.all_profiles,
    )
    if selection.system_ids:
        system_ids = selection.system_ids
        files = [fe for fe in files if entry_serves_systems(fe, profile, system_ids)]
    return files


def _narrowed(files: list[dict], selection: EmulatorSelection) -> list[dict]:
    """The entries --required-only and the region filter leave."""
    if selection.required_only:
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
    if selection.region_drops:
        # Loose files only: an archive ships whole, and dropping kronos'
        # regional stvbios.zip members rebuilt the archive from 4 of its 14
        # members and changed its required.
        files = [
            fe
            for fe in files
            if fe.get("archive")
                or resolve_destination(fe, selection.standalone) not in selection.region_drops
        ]
    return files


def emulator_pack_entries(
    emu_name: str, profile: dict, selection: EmulatorSelection,
) -> EmulatorPackEntries:
    """What the emulator pack carries of one profile. The builder and
    verify --emulator both read this."""
    standalone = selection.standalone
    entries = _profile_entries(emu_name, profile, selection)
    files = _narrowed(entries, selection)
    spares = emulator_required_spares(
        emu_name, profile, files, standalone, selection.region_drops, selection.db,
        selection.validation_index, selection.zip_contents,
        data_registry=selection.data_registry,
    ) if selection.required_only else set()

    archives: list[tuple[str, dict, str]] = []
    seen: set[str] = set()
    for fe in files:
        name = fe.get("archive")
        if not name or name in seen:
            continue
        seen.add(name)
        # Where the pack puts it: an archive_prefix or pack_structure moves
        # it, and a loose same-named entry is another file.
        dest = archive_destination(
            name, profile.get("archive_prefix", ""), profile.get("pack_structure"), standalone,
        )
        if dest not in spares:
            archives.append((name, archive_entry(name, entries), dest))

    # The entries of one profile on one destination are the releases the
    # code accepts there (raze's seven SW.GRP): the slot has one outcome
    # however many alternatives it lists.
    slots: dict[str, list[dict]] = {}
    carries_entries = False
    for fe in files:
        if fe.get("archive"):
            carries_entries = True
            continue
        dest = resolve_destination(fe, standalone)
        if dest in spares:
            continue
        carries_entries = True
        if dest:
            slots.setdefault(dest, []).append(fe)
    return EmulatorPackEntries(entries, archives, slots, carries_entries)
