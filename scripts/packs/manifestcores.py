"""The manifest's core entries and the scope a manifest selects."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import sanitize_pack_path
from model.alternatives import core_file_spares
from model.declarations import OUTER_ROOTS, ROMS_ROOT, declared_root
from model.profiles import upstream_profile_index
from model.targets import list_available_targets, load_target_config
from packs.extras import (
    ExtraResolver,
    detect_extras_prefix,
    extra_system_ids,
    extra_full_destination,
    extra_region_key,
    platform_region_groups,
    save_entry_fields,
    save_manifest_dest,
)
from packs.manifestentry import (
    ClaimContext,
    attach_claims,
    claim_cores,
    claim_platform_omission,
    manifest_dest_of,
    manifest_entry,
)
from packs.manifestselect import SelectionIndex
from packs.paths import register_path, placement_block
from packs.platformpack import one_per_slot_drops
from resolve import regions as resolve_regions, slot as slot_mod
from resolve.contentlayout import TARGET_KEY, core_key, content_folder_boards
from resolve.cores import (
    downloadable_on,
    downloaded_only_profiles,
    resolve_platform_cores as _platform_cores,
    system_core_reach,
)
from resolve.gamedata import GAME_DATA, is_game_data

if TYPE_CHECKING:
    from typing_extensions import Unpack


class _CoreEntryState(TypedDict):
    """What manifest_core_entries reads and fills of the manifest being listed."""

    region_drops: set
    case_insensitive: bool
    seen_destinations: set
    seen_lower: set
    seen_parents: set
    manifest_files: list
    omitted_by_destination: dict
    record_omission: Callable[..., None]
    pack_only_sizes: list[int]
    selection: SelectionIndex


class _CoreEntryParts(_CoreEntryState, total=False):
    """_CoreEntryState and the optional keywords of manifest_core_entries."""

    required_only: bool
    validation_index: dict | None
    owners: dict | None
    data_registry: dict | None
    profiles: dict | None


@dataclass
class _CoreEntryLister:
    """Lists a platform's core extras into the manifest, one at a time."""

    config: dict
    base_dest: str
    ctx: ClaimContext
    state: _CoreEntryParts
    resolver: ExtraResolver
    total_size: int = 0
    extras_pfx: str = field(init=False)

    def __post_init__(self) -> None:
        self.extras_pfx = detect_extras_prefix(self.config, self.base_dest)

    def region_key(self, fe: dict) -> str:
        return extra_region_key(fe, declared_root(self.config))

    def region_dropped(self, fe: dict) -> bool:
        drops = self.state["region_drops"]
        return bool(drops) and self.region_key(fe) in drops

    def list_extra(self, fe: dict) -> None:
        state = self.state
        dest = sanitize_pack_path(fe.get("destination", fe["name"]))
        if not dest:
            return
        region_key = self.region_key(fe)
        if state["region_drops"] and region_key in state["region_drops"]:
            return
        full_dest = extra_full_destination(fe, self.extras_pfx)
        if not full_dest:
            return

        if (
            state["case_insensitive"]
            and full_dest not in state["seen_destinations"]
            and full_dest.lower() in state["seen_lower"]
        ):
            self._join_spelling(fe, full_dest, dest)
            return

        if placement_block(
            full_dest, state["seen_destinations"], state["seen_lower"], state["seen_parents"],
            state["case_insensitive"],
        ):
            return

        # The builder's own lookup (ExtraResolver): the data directories, the
        # copy the emulator accepts, and the size its code checks. Without
        # the data directories blueMSX's MSX2P.rom named a different dump
        # than the one its pack carried.
        local_path, status, _disagreement = self.resolver.resolve(fe, dest)
        if not local_path:
            self._omit(fe, full_dest, status)
            return
        self._list_held(fe, dest, full_dest, region_key, local_path)

    def _join_spelling(self, fe: dict, full_dest: str, dest: str) -> None:
        # One file under two spellings: BlastEm opens 32X_M_BIOS.bin and
        # PicoDrive 32X_M_BIOS.BIN. The second core's claim joins the
        # entry kept, or a pack built without the first core loses the
        # file the installer would still have to place. Collisions are
        # rare, so the entry is looked up only when one happens.
        save_root = fe.get("root") == "save"
        folded = (
            save_manifest_dest(fe) if save_root
            else manifest_dest_of(full_dest, self.base_dest)
        ).lower()
        held = next(
            (e for e in self.state["manifest_files"]
             if e["dest"].lower() == folded
             and (e.get("root") == "save") == save_root),
            None,
        )
        if held is not None and held.get("cores") is not None:
            attach_claims(held, [fe], self.ctx, dest, held["dest"])

    def _omit(self, fe: dict, full_dest: str, reason: str) -> None:
        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
        if not claim_platform_omission(
            self.state["omitted_by_destination"].get(full_dest), source_emu
        ):
            systems = extra_system_ids(fe)
            self.state["record_omission"](
                full_dest, fe, systems[0] if systems else "", reason, claim_cores(fe),
            )

    def _list_held(
        self, fe: dict, dest: str, full_dest: str, region_key: str, local_path: str,
    ) -> None:
        state = self.state
        source_emu = fe.get("source_profile") or fe.get("source_emulator", "")
        save_root = fe.get("root") == "save"

        # Manifest dests are relative to base_destination. Keep the inferred
        # extras prefix when it is an internal layout dir (RetroDECK bios/).
        # A file read below the save directory is written relative to the
        # directory the core is handed, and says so (save_entry_fields).
        outer_root = fe.get("root") if fe.get("root") in OUTER_ROOTS else None
        if save_root:
            manifest_dest = save_manifest_dest(fe)
        elif outer_root:
            # Relative to the roms or emulators folder the entry names.
            manifest_dest = dest
        else:
            manifest_dest = manifest_dest_of(full_dest, self.base_dest)

        entry, file_size = manifest_entry(
            local_path, manifest_dest, [source_emu] if source_emu else [],
            self.ctx.db, self.ctx.repo_root,
            state["selection"].fields(region_key, fe.get("name", "")),
        )
        if entry is not None and save_root:
            entry.update(save_entry_fields(fe))
        elif entry is not None and outer_root:
            entry["root"] = outer_root
        if entry is None:
            self._omit(fe, full_dest, "not_found")
            if file_size:
                state["pack_only_sizes"].append(file_size)
            return

        if is_game_data(fe) and all(
            is_game_data(claim) for claim in fe.get("other_claims", [])
        ):
            entry["category"] = GAME_DATA
        attach_claims(entry, fe.get("other_claims", []), self.ctx, dest, manifest_dest)

        state["manifest_files"].append(entry)
        displaced = state["omitted_by_destination"].pop(full_dest, None)
        if displaced and displaced.get("cores"):
            # A core that wants this slot and has nothing held: a pack built
            # without the cores served here leaves the slot to it, missing,
            # and the installer narrowing to those cores has to say so too.
            entry.setdefault("absent_claims", []).append(
                {k: v for k, v in displaced.items() if k not in ("dest", "held")}
            )
        self.total_size += file_size
        state["seen_destinations"].add(full_dest)
        register_path(full_dest, state["seen_destinations"], state["seen_parents"])
        if state["case_insensitive"]:
            state["seen_lower"].add(full_dest.lower())


def manifest_core_entries(
    core_files: list,
    config: dict,
    db: dict,
    bios_dir: str,
    base_dest: str,
    repo_root: str,
    zip_contents: dict | None,
    offline: bool | None,
    **state: Unpack[_CoreEntryParts],
) -> int:
    """Add the files a platform's cores need but its list does not name.

    The installer fetches by hash, so an entry records the copy this
    repository holds rather than the value the profile declares: an
    upstream hash carried by no local file leaves the entry with no URL.
    Returns the bytes added.
    """
    reject_unknown(
        "manifest_core_entries", state,
        _CoreEntryParts.__required_keys__ | _CoreEntryParts.__optional_keys__,
    )
    required_only = state.get("required_only", False)
    ctx = ClaimContext(
        db, bios_dir, zip_contents, offline, required_only,
        state.get("validation_index"), state.get("owners"), repo_root,
        state.get("data_registry"),
    )
    lister = _CoreEntryLister(
        config, base_dest, ctx, state,
        ExtraResolver(
            db, bios_dir, zip_contents, ctx.data_registry, ctx.validation_index or {},
            ctx.owners, offline, profiles=state.get("profiles"),
        ),
    )
    spares = core_file_spares(core_files, lister.region_dropped) if required_only else set()
    for fe in core_files:
        if required_only and (fe.get("required") is False or id(fe) in spares):
            continue
        lister.list_extra(fe)
    return lister.total_size


class _SelectionOptions(TypedDict, total=False):
    """The keyword options of manifest_selection."""

    required_only: bool
    regions: list[str] | None
    undeclared: list[dict] | None
    zip_contents: dict | None
    data_registry: dict | None
    slot_overrides: dict[str, str] | None
    one_per_slot: bool


def manifest_selection(
    config: dict,
    pack_systems: dict,
    emulators_dir: str,
    db: dict,
    base_dest: str,
    emu_profiles: dict,
    target_cores: set[str] | None,
    source: str,
    **options: Unpack[_SelectionOptions],
) -> tuple[set[str], SelectionIndex, set[str]]:
    """Destinations a region list and --one-per-slot remove, the groups the
    installer replays, and the destinations the builder holds.

    Grouped as the pack groups them, so a region or a slot the installer
    decides on the full manifest withdraws what `--region` and
    `--one-per-slot` withdraw from the pack.
    """
    reject_unknown("manifest_selection", options, _SelectionOptions.__optional_keys__)
    required_only = options.get("required_only", False)
    regions = options.get("regions")
    one_per_slot = options.get("one_per_slot", False)
    extras: list[dict] = []
    held: set[str] = set()
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
        required_only=required_only,
        extras_out=extras,
        held_out=held,
        undeclared=options.get("undeclared"),
        zip_contents=options.get("zip_contents"),
        data_registry=options.get("data_registry"),
        slot_overrides=options.get("slot_overrides"),
    )
    region_index = resolve_regions.platform_region_index(
        config, emu_profiles, target_cores
    )
    drops = (
        resolve_regions.resolve_region_drops(region_groups, region_index, regions, held)
        if regions
        else set()
    )
    if one_per_slot:
        drops = drops | one_per_slot_drops(
            config, emu_profiles, target_cores, region_groups, drops, held
        )[0]
    return drops, SelectionIndex.build(
        region_groups, region_index, pack_systems, extras, required_only,
        extras_prefix=declared_root(config),
        slot_claims=slot_mod.platform_slot_claims(config, emu_profiles, target_cores),
    ), held


def offered_boards(
    config: dict,
    profiles: dict[str, dict],
    core_names: dict[str, list[str]],
    entries: list[dict],
) -> dict[str, list[dict]]:
    """The roms folders each profile is offered for on some boards only,
    each with those boards, aliases included, where the manifest places a
    file of that profile.

    ROCKNIX writes uae4arm for roms/amiga under the devices it builds it for
    (emulators/package.mk:188), and a board's core list names uae4arm when
    another folder offers it there. The pack builder reads the board from
    the config (TARGET_KEY) and `install.py --target` reads its answer here.
    A manifest built for one board needs none.
    """
    if config.get(TARGET_KEY):
        return {}
    pairs = content_folder_boards(config)
    if all(on is None for on in pairs.values()):
        return {}
    from resolve.launchers import roms_place_of

    by_key: dict[str, set[str]] = {}
    for name, claimants in upstream_profile_index(profiles).items():
        by_key.setdefault(core_key(name), set()).update(claimants)
    free = {
        (profile, folder) for (core, folder), on in pairs.items() if on is None
        for profile in by_key.get(core, ())
    }
    found: dict[tuple[str, str, str], set[str]] = {}
    for (core, folder), on in pairs.items():
        where = roms_place_of(config, folder) if on is not None else None
        if where is None:
            continue
        for profile in by_key.get(core, ()):
            if profile in core_names and (profile, folder) not in free:
                found.setdefault((profile, where[0], where[1]), set()).update(on)
    # An entry below the roms root names it, one in the install tree none.
    trees = {ROMS_ROOT: ROMS_ROOT, None: "install"}
    placed = {
        (profile, trees[entry.get("root")], str(entry.get("dest", "")).rpartition("/")[0])
        for entry in entries if entry.get("root") in trees
        for copy in [entry, *entry.get("alternatives", [])]
        for profile in copy.get("cores") or []
    }
    result: dict[str, list[dict]] = {}
    for (profile, tree, folder), boards in sorted(found.items()):
        if not any(
            p == profile and t == tree and (d == folder or d.startswith(f"{folder}/"))
            for p, t, d in placed
        ):
            continue
        result.setdefault(profile, []).append(
            {"root": tree, "folder": folder, "boards": sorted(boards)}
        )
    return result


def downloaded_cores(
    config: dict,
    profiles: dict[str, dict],
    core_names: dict[str, list[str]],
    platforms_dir: str,
) -> dict[str, list[str]]:
    """The cores only the platform's RetroArch downloader brings, each with
    the boards, aliases included, whose downloader offers it.

    A target list names the board's standalone amiberry and the buildbot's
    amiberry core alike, so the installer cannot tell from the name whether
    the board reaches the core. `resolve_platform_cores` decides it, and
    `install.py --target` reads its answer here.
    """
    reached = {
        profile: names
        for profile, names in downloaded_only_profiles(config, profiles).items()
        if profile in core_names
    }
    if not reached:
        return {}
    platform = str(config.get("_key") or "")
    boards: dict[str, list[str]] = {profile: [] for profile in reached}
    for target in list_available_targets(platform, platforms_dir):
        cores = load_target_config(platform, target["name"], platforms_dir)
        if cores is None:
            continue
        for profile, names in reached.items():
            if downloadable_on(cores, names):
                boards[profile] += [target["name"], *target.get("aliases", [])]
    return {profile: sorted(names) for profile, names in sorted(boards.items())}


def manifest_core_index(
    config: dict,
    profiles: dict[str, dict],
    files: list[dict],
    omitted: list[dict],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """What the installer needs to narrow by a list of core names.

    A target list, or the cores found installed, names cores the way the
    buildbot does, and a file names the profile that reads it: `core_names`
    gives each profile the other names it goes by, and names every core the
    platform runs, one that reads no file included: a core found installed
    that the list does not name is one it has no profile for. `system_cores`
    gives each platform system the cores whose presence keeps it, as
    `filter_systems_by_target` decides. A system absent from it is kept
    whatever is available.
    """
    runs = _platform_cores(config, profiles)
    reach = system_core_reach(config.get("systems", {}), profiles, runs)
    system_cores = {
        sys_id: sorted(cores) for sys_id, cores in sorted(reach.items())
        if cores is not None
    }
    named = {
        c for entry in [*files, *omitted]
        for copy in [entry, *entry.get("alternatives", []), *entry.get("slot_choices", [])]
        for c in copy.get("cores") or []
    }
    named |= {c for cores in system_cores.values() for c in cores}
    named |= set(runs)
    aliases: dict[str, set[str]] = {profile: set() for profile in named & set(runs)}
    for name, claimants in upstream_profile_index(profiles, include_aliases=True).items():
        for profile in claimants & named:
            if name != profile:
                aliases.setdefault(profile, set()).add(name)
    core_names = {profile: sorted(names) for profile, names in sorted(aliases.items())}
    return core_names, system_cores
