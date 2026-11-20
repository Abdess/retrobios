"""The install manifest of a platform."""

from __future__ import annotations

import contextlib
import io
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.artifacts import build_timestamp
from core.options import reject_unknown
from core.paths import EMULATORS_DIR, REPO_ROOT, declared_destination, sanitize_pack_path
from model.declarations import OUTER_ROOTS, declared_root, outer_layout
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.registry import load_data_dir_registry
from model.safeparse import yaml_load
from model.systems import platform_system_names
from packs import slots
from packs.archive import CASE_FOLDING_OS, PACK_DOCUMENTS, Placed
from packs.datatrees import (
    data_directory_members,
    in_data_cache,
    manifest_data_directories,
    core_data_trees,
    pack_markers,
    tree_readers,
)
from packs.extras import (
    collect_emulator_extras,
    extra_region_key,
    save_entry_fields,
    save_manifest_dest,
    undeclared_report,
)
from packs.manifestcores import (
    downloaded_cores,
    manifest_core_entries,
    manifest_core_index,
    manifest_selection,
    offered_boards,
)
from packs.manifestentry import (
    MANIFEST_OUTER_FIELDS,
    ClaimContext,
    attach_claims,
    manifest_dest_of,
    manifest_entry,
    record_absent,
    record_slot_choices,
    record_unplaceable,
)
from packs.manifestselect import SelectionIndex
from packs.paths import save_layout
from packs.scope import platform_list_version, system_titles
from packs.standalone import standalone_copies, standalone_layouts
from resolve.contentlayout import TARGET_KEY
from resolve.cores import filter_systems_by_target, resolve_platform_cores as _platform_cores
from resolve.gamedata import GAME_DATA, is_game_data, platform_game_data, without_game_data
from resolve.nativemode import digest_algorithm, platform_mode, reads_file_contents
from resolve.packfiles import preferred_entries as _preferred_entries, resolve_declaration
from resolve.validation import (
    build_validation_index,
    agnostic_substitute,
    baseline_verdict,
    destination_owners,
    validated_choice,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack


if TYPE_CHECKING:
    # How a manifest settles a platform declaration: the copy served, or None
    # and why not.
    _Settle = Callable[[dict, str, str, "str | None"], "tuple[str | None, str]"]


class InstallListOptions(TypedDict, total=False):
    """The keyword options of generate_install_list, which it hands to
    generate_manifest."""

    emulators_dir: str
    zip_contents: dict | None
    emu_profiles: dict | None
    target_cores: set[str] | None
    source: str
    regions: list[str] | None
    target_name: str | None
    offline: bool | None
    required_only: bool
    data_registry: dict | None
    fold_case: bool | None
    no_game_data: bool
    one_per_slot: bool


class ManifestOptions(InstallListOptions, total=False):
    """The keyword options of generate_manifest."""

    known_slot_choices: dict | None
    build_out: dict | None


@dataclass(frozen=True)
class _ManifestSettings:
    """ManifestOptions with their defaults."""

    emulators_dir: str = EMULATORS_DIR
    zip_contents: dict | None = None
    emu_profiles: dict | None = None
    target_cores: set[str] | None = None
    source: str = "full"
    regions: list[str] | None = None
    target_name: str | None = None
    offline: bool | None = None
    required_only: bool = False
    data_registry: dict | None = None
    fold_case: bool | None = None
    no_game_data: bool = False
    one_per_slot: bool = False
    known_slot_choices: dict | None = None
    build_out: dict | None = None


@dataclass
class _ManifestBuild:
    """One install manifest being listed: its files, omissions and the slots
    they take, settled by the rules the pack builder follows."""

    platform_name: str
    platforms_dir: str
    db: dict
    bios_dir: str
    opts: _ManifestSettings
    config: dict
    emu_profiles: dict
    zip_contents: dict
    data_registry: dict
    game_entries: set[int]
    install_section: dict
    repo_root: str
    pack_systems: dict
    manifest_profiles: dict = field(default_factory=dict)
    manifest_validation: dict = field(default_factory=dict)
    manifest_owners: dict = field(default_factory=dict)
    game_destinations: set[str] = field(default_factory=set)
    placed: Placed = field(init=False)
    # Destination -> (entry, full destination, manifest destination) of each
    # platform file, for the core claims a target build would fall back on.
    platform_entries: dict[str, tuple[dict, str, str]] = field(default_factory=dict)
    # Full destination -> the platform systems declaring it. A file's
    # `systems` also names the systems whose cores read it there. A pack built
    # for a target keeps the file only while a declaring system stays.
    declared_by: dict[str, set[str]] = field(default_factory=dict)
    manifest_files: list[dict] = field(default_factory=list)
    omitted_by_destination: dict[str, dict] = field(default_factory=dict)
    total_size: int = 0
    # Sizes of the files the pack carries and the installer cannot fetch: the
    # collection does not index them, a data directory cache answered.
    pack_only_sizes: list[int] = field(default_factory=list)
    # Platform entries resolved into a data directory cache: destination ->
    # (cache file, size). Settled once the trees are walked.
    cache_held: dict[str, tuple[str, int]] = field(default_factory=dict)
    rename_notes: set[str] = field(default_factory=set)
    slot_choices: dict = field(default_factory=dict)
    slot_overrides: dict[str, str] = field(default_factory=dict)
    undeclared: list[dict] | None = None
    region_drops: set[str] = field(default_factory=set)
    selection: SelectionIndex | None = None
    builder_held: set[str] = field(default_factory=set)
    declarations: dict[str, dict[str, list[dict]]] = field(default_factory=dict)
    data_members: list[tuple[str, str]] = field(default_factory=list)
    data_directories: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.placed = Placed(self.case_insensitive)

    @property
    def base_dest(self) -> str:
        return self.config.get("base_destination", "")

    @property
    def case_insensitive(self) -> bool:
        return self.config.get("case_insensitive_fs", False)

    @property
    def verification_mode(self) -> str:
        return platform_mode(self.config)

    @property
    def fields(self) -> SelectionIndex:
        assert self.selection is not None
        return self.selection

    def manifest_destination(self, full_destination: str) -> str:
        return manifest_dest_of(full_destination, self.base_dest)

    def record_omission(
        self,
        full_destination: str,
        file_entry: dict,
        system_id: str,
        reason: str,
        cores: list[str] | None,
    ) -> None:
        # A core extra (cores given) is keyed as the region pass keys it.
        bare = (
            declared_destination(file_entry)
            if cores is None else extra_region_key(file_entry, declared_root(self.config))
        )
        self.omitted_by_destination[full_destination] = {
            **self._omission_dest(full_destination, file_entry),
            "name": str(file_entry.get("name") or ""),
            "system": system_id,
            "required": bool(file_entry.get("required", True)),
            "reason": reason,
            "cores": cores,
            # An omission keeps its region groups, as the builder groups it:
            # a requested file the collection lacks answers the request
            # without displacing a held fallback (resolve_region_drops,
            # held). One the builder holds and the installer cannot fetch
            # does displace it in the pack, so it says so, and the installer
            # drops the same fallback.
            **self.fields.fields(bare, str(file_entry.get("name") or "")),
            **({"held": True} if bare in self.builder_held else {}),
            **(
                {"category": GAME_DATA}
                if (bare in self.game_destinations if cores is None else is_game_data(file_entry))
                else {}
            ),
        }

    def _omission_dest(self, full_destination: str, file_entry: dict) -> dict:
        # Read in the emulator's own folder, outside the BIOS tree: dest is
        # the path the emulator reads, relative to that folder.
        if file_entry.get("unplaced"):
            return {"dest": sanitize_pack_path(file_entry.get("path") or ""),
                    "root": "emulator"}
        if file_entry.get("root") in OUTER_ROOTS:
            return {"dest": sanitize_pack_path(
                file_entry.get("destination") or file_entry.get("path") or ""
            ), "root": file_entry["root"]}
        if file_entry.get("root") == "save":
            return {"dest": save_manifest_dest(file_entry), **save_entry_fields(file_entry)}
        return {"dest": self.manifest_destination(full_destination)}

    def kept_declarations(self) -> Iterator[tuple[str, dict, str, str]]:
        """(system, entry, destination, full destination) of each platform
        declaration this manifest keeps, in the builder's order."""
        opts = self.opts
        for sys_id, system in sorted(self.pack_systems.items()):
            for file_entry in system.get("files", []):
                if opts.required_only and file_entry.get("required") is False:
                    continue
                dest = sanitize_pack_path(file_entry.get("destination", file_entry["name"]))
                if not dest:
                    continue
                if self.region_drops and dest in self.region_drops:
                    continue
                full_dest = f"{self.base_dest}/{dest}" if self.base_dest else dest
                yield sys_id, file_entry, dest, full_dest

    def declaration_order(self, full_dest: str) -> list[tuple[list[str], dict, str]]:
        """The declarations answering a destination as its systems drop.

        A pack built for a target loses the systems no available core
        reads, and the next declaration takes the destination by the
        same rule: RetroArch's bare nintendo-ds dsi_bios9.bin once the
        pinned nintendo-dsi one is gone.
        """
        remaining = dict(self.declarations.get(full_dest, {}))
        order: list[tuple[list[str], dict, str]] = []
        while remaining:
            winner = _preferred_entries(
                {sid: {"files": fes} for sid, fes in remaining.items()},
                self.db, self.bios_dir, self.base_dest, self.opts.required_only,
                self.zip_contents, self.opts.offline,
            ).get(full_dest)
            first_sys, first = next(
                (sid, fe) for sid, fes in sorted(remaining.items()) for fe in fes
                if winner is None or id(fe) == winner
            )
            systems = sorted(
                sid for sid, fes in remaining.items()
                if any(fe is first for fe in fes)
            )
            order.append((systems, first, first_sys))
            for sid in systems:
                del remaining[sid]
        return order

    def list_baseline(self, settle: _Settle) -> None:
        """Phase 1: the platform's own files."""
        # The same destination can be declared by more than one system, bare
        # in one and hash-constrained in another. The builder lets the
        # constrained sibling claim it. Without the same rule here the
        # manifest named whatever answered to the name, so the pack and the
        # installer disagreed about which file a destination means.
        # Decided among the declarations this manifest keeps, as the pack
        # does. A manifest carries no data directories.
        preferred_entries = _preferred_entries(
            self.pack_systems, self.db, self.bios_dir, self.base_dest,
            self.opts.required_only, self.zip_contents, self.opts.offline,
        )
        for sys_id, file_entry, _dest, full_dest in self.kept_declarations():
            self.declarations.setdefault(full_dest, {}).setdefault(sys_id, []).append(
                file_entry
            )
        for sys_id, file_entry, dest, full_dest in self.kept_declarations():
            self.declared_by.setdefault(full_dest, set()).add(sys_id)
            preferred = preferred_entries.get(full_dest)
            if preferred is not None and id(file_entry) != preferred:
                continue
            if self.placed.holds(full_dest) or self.placed.conflicts(full_dest):
                continue
            if file_entry.get("storage", "embedded") == "user_provided":
                self._list_instructions(file_entry, sys_id, full_dest)
                continue
            local_path, status = settle(
                file_entry, sys_id, dest, self.slot_overrides.get(full_dest)
            )
            if local_path is None:
                self.record_omission(full_dest, file_entry, sys_id, status, None)
                continue
            self._list_declared(file_entry, sys_id, dest, full_dest, local_path, settle)

    def _list_instructions(self, file_entry: dict, sys_id: str, full_dest: str) -> None:
        self.record_omission(
            full_dest,
            file_entry,
            sys_id,
            "user_provided",
            None,
        )
        # The pack writes the instructions in the slot's place
        # and holds it: one more member than the files listed.
        instructions = file_entry.get(
            "instructions", "Please provide this file manually."
        )
        self.pack_only_sizes.append(len(
            f"File needed: {file_entry['name']}\n\n{instructions}\n".encode()
        ))
        self.placed.take(full_dest)

    def _list_declared(
        self,
        file_entry: dict,
        sys_id: str,
        dest: str,
        full_dest: str,
        local_path: str,
        settle: _Settle,
    ) -> None:
        entry, file_size = manifest_entry(
            local_path, dest, None, self.db, self.repo_root,
            self.fields.fields(dest, file_entry["name"]),
        )
        if entry is not None and dest in self.game_destinations:
            entry["category"] = GAME_DATA
        if entry is not None and self.opts.target_cores is None:
            order = self.declaration_order(full_dest)
            if full_dest in self.slot_choices or len(order) > 1:
                record_slot_choices(
                    entry, self.slot_choices.get(full_dest, []), order,
                    settle, dest, self.db, self.repo_root,
                )
        if entry is None:
            self.record_omission(full_dest, file_entry, sys_id, "not_found", None)
            if file_size and full_dest not in self.placed.destinations:
                if in_data_cache(local_path, self.data_registry):
                    self.cache_held[full_dest] = (local_path, file_size)
                else:
                    self.pack_only_sizes.append(file_size)
                self.placed.take(full_dest)
            return

        self.manifest_files.append(entry)
        self.platform_entries[full_dest] = (entry, full_dest, dest)
        self.omitted_by_destination.pop(full_dest, None)
        self.total_size += file_size
        self.placed.take(full_dest)

    def claim_context(self) -> ClaimContext:
        return ClaimContext(
            self.db, self.bios_dir, self.zip_contents, self.opts.offline,
            self.opts.required_only, self.manifest_validation, self.manifest_owners,
            self.repo_root, self.data_registry,
        )

    def list_core_files(self) -> None:
        """Phase 2: core complement (emulator extras)."""
        opts = self.opts
        unplaceable: list[dict] = []
        baseline_claims: dict[str, dict] = {}
        absent: list[dict] = []
        if opts.source != "platform":
            core_files = collect_emulator_extras(
                self.config,
                opts.emulators_dir,
                self.db,
                self.placed.destinations,
                self.base_dest,
                self.emu_profiles,
                target_cores=opts.target_cores,
                include_all=(opts.source == "truth"),
                unplaceable=unplaceable,
                baseline_claims=baseline_claims,
                absent=absent,
                undeclared=self.undeclared,
            )
        else:
            core_files = []
        record_unplaceable(unplaceable, self.record_omission, self.config, self.emu_profiles)
        record_absent(
            absent, self.config, self.base_dest, self.region_drops, opts.required_only,
            self.placed.destinations, self.omitted_by_destination, self.record_omission,
        )
        self.total_size += manifest_core_entries(
            core_files, self.config, self.db, self.bios_dir, self.base_dest, self.repo_root,
            self.zip_contents, opts.offline,
            region_drops=self.region_drops, placed=self.placed,
            manifest_files=self.manifest_files,
            omitted_by_destination=self.omitted_by_destination,
            record_omission=self.record_omission, pack_only_sizes=self.pack_only_sizes,
            selection=self.fields, required_only=opts.required_only,
            validation_index=self.manifest_validation, owners=self.manifest_owners,
            data_registry=self.data_registry, profiles=self.emu_profiles,
        )
        self._settle_claims(baseline_claims)

    def _settle_claims(self, baseline_claims: dict[str, dict]) -> None:
        ctx = self.claim_context()
        for key, (entry, full_dest, dest) in self.platform_entries.items():
            declared = self.declared_by.get(full_dest, set())
            if declared and declared != set(entry.get("systems") or []):
                entry["declared_in"] = sorted(declared)
            claims = baseline_claims.get(key, {}).get("other_claims")
            if claims and any(not is_game_data(claim) for claim in claims):
                # A core reads this path as firmware: a pack without game data
                # still fills it.
                entry.pop("category", None)
            if claims:
                attach_claims(entry, claims, ctx, dest, dest)
        # A platform omission narrows like a platform file: by the systems
        # declaring it, which can be fewer than the ones whose cores read it.
        for full_dest, omission in self.omitted_by_destination.items():
            declared = self.declared_by.get(full_dest, set())
            if (
                omission.get("cores") is None
                and declared
                and declared != set(omission.get("systems") or [])
            ):
                omission["declared_in"] = sorted(declared)

    def list_data_directories(self) -> list[int]:
        """Phase 3: data directories, and the sizes the pack alone holds.

        They are not files of the collection: the installer fetches each
        from its source archive and keeps the members whose hash the list
        below records, the same tree the pack carries.
        """
        opts = self.opts
        required_only = opts.required_only
        data_refs: dict[str, tuple[str, tuple[str, ...], str, bool]] = {}
        reclaim = {full: path for full, (path, _size) in self.cache_held.items()}
        core_trees = ([] if opts.source == "platform"
                      else core_data_trees(self.config, self.emu_profiles, self.platform_name,
                                           self.data_registry, opts.target_cores))
        self.data_members = list(data_directory_members(
            self.pack_systems, self.data_registry, self.platform_name, self.base_dest,
            self.placed, refs_out=data_refs, required_only=required_only,
            core_trees=core_trees,
            reclaim=reclaim,
        ))
        # A platform entry found in a tree the pack carries is that tree's member:
        # the installer rebuilds it from the tree's archive. One found in a tree
        # the pack does not carry stays omitted, held by the pack alone.
        for full_dest, (_path, size) in self.cache_held.items():
            if full_dest in reclaim:
                self.pack_only_sizes.append(size)
            else:
                self.omitted_by_destination.pop(full_dest, None)
        self.data_directories = manifest_data_directories(
            self.data_members, data_refs, self.data_registry or {}, self.base_dest,
            tree_readers(self.pack_systems, core_trees), self.pack_systems,
        )
        return self.pack_only_sizes + [os.path.getsize(src) for src, _dest in self.data_members]

    def result(self, data_sizes: list[int]) -> dict:
        opts, config, pack_systems = self.opts, self.config, self.pack_systems
        manifest_files, platform_name = self.manifest_files, self.platform_name
        omitted = self.omitted_by_destination
        # The pack is unzipped into the BIOS folder: an entry the installer puts
        # in the roms, emulators or configs folder is in its list, not in the ZIP.
        outer = [e for e in manifest_files if e.get("root") in OUTER_ROOTS]
        core_names, system_cores = manifest_core_index(
            config, self.emu_profiles, manifest_files, list(omitted.values())
        )
        result: dict = {
            "manifest_version": 2,
            "source": opts.source,
            "regions": list(opts.regions or []),
            # A target-filtered manifest is only distinguishable from the full one
            # by its filename, so it records the filter the way regions does.
            # Absent on an unfiltered manifest rather than empty, to leave the
            # twelve default files byte-identical.
            **({"target": opts.target_name} if opts.target_name else {}),
            # Every game data file below says so: the installer's --no-game-data
            # relies on it, and refuses a list that does not record categories.
            "categorized": True,
            # The entries a slot decides carry `slot`, which --one-per-slot
            # reads: without this mark the installer refuses it.
            "slot_fields": True,
            **({"no_game_data": True} if opts.no_game_data else {}),
            "platform": platform_name,
            "display_name": config.get("platform", platform_name),
            "version": platform_list_version(config, platform_name),
            "generated": build_timestamp(self.db),
            "base_destination": self.base_dest,
            "detect": self.install_section.get("detect", []),
            "standalone_copies": standalone_copies(
                self.install_section.get("standalone_copies", []), self.manifest_profiles,
                manifest_files,
            ),
            "total_files": len(manifest_files),
            "total_size": self.total_size,
            "pack_files": (
                len(manifest_files) - len(outer) + len(data_sizes) + len(PACK_DOCUMENTS)
                + len(self.rename_notes)
                + len(pack_markers(platform_name, opts.target_name, self.platforms_dir))
            ),
            "pack_size": self.total_size - sum(int(e.get("size") or 0) for e in outer)
            + sum(data_sizes),
            "total_omitted": len(omitted),
            "omitted_files": sorted(
                omitted.values(), key=lambda entry: entry["dest"]
            ),
            "core_names": core_names,
            **({"downloaded_cores": downloaded} if (downloaded := downloaded_cores(
                config, self.emu_profiles, core_names, self.platforms_dir,
            )) else {}),
            **({"offered_boards": offered} if (offered := offered_boards(
                config, self.emu_profiles, core_names,
                [*manifest_files, *omitted.values()],
            )) else {}),
            "system_cores": system_cores,
            # The names the platform itself gives its systems (Batocera's psx),
            # which --system accepts beside the ids.
            "system_names": platform_system_names(config, list(pack_systems)),
            "system_titles": system_titles(manifest_files, omitted.values()),
            "files": manifest_files,
        }
        if self.data_directories:
            result["data_directories"] = self.data_directories
        self._outer_directories(result)
        return result

    def _outer_directories(self, result: dict) -> None:
        for root in OUTER_ROOTS:
            layout = outer_layout(self.config, root) or {}
            if layout and any(entry.get("root") == root
                              for entry in [*self.manifest_files, *result["omitted_files"]]):
                # Where the installer finds the folder: relative to the folder
                # holding the BIOS folder, which the platform names bios_folder.
                result[f"{root}_directory"] = {
                    key: layout[key] for key in MANIFEST_OUTER_FIELDS if key in layout
                }
        saved = [entry for entry in self.manifest_files if entry.get("root") == "save"]
        if saved:
            save = save_layout(self.config)
            result["save_directory"] = {"folder": save.folder, "by_core": save.by_core}
            if save.by_system:
                # The launcher writes the directory at each launch, one folder
                # per system: each dest starts with that folder.
                result["save_directory"]["by_system"] = True


def _start_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    opts: _ManifestSettings,
) -> tuple[_ManifestBuild, dict]:
    """The manifest's configuration and scope, and the profiles before the
    game data cut."""
    config = load_platform_config(platform_name, platforms_dir)
    if opts.fold_case is not None:
        config = {**config, "case_insensitive_fs": opts.fold_case}
    if opts.target_name:
        config = {**config, TARGET_KEY: opts.target_name}
    zip_contents = {} if opts.zip_contents is None else opts.zip_contents
    emu_profiles = opts.emu_profiles
    if emu_profiles is None:
        emu_profiles = load_emulator_profiles(opts.emulators_dir)
    data_registry = opts.data_registry
    if data_registry is None:
        data_registry = load_data_dir_registry(platforms_dir)
    full_profiles = emu_profiles
    game_entries: set[int] = set()
    if opts.no_game_data:
        cut = without_game_data(config, emu_profiles, data_registry, opts.target_cores)
        config, emu_profiles = cut.config, cut.profiles
    else:
        game_entries = platform_game_data(config, emu_profiles, data_registry)

    # Load registry for install metadata
    registry: dict = {}
    if os.path.exists(registry_path):
        with open(registry_path) as f:
            registry = yaml_load(f) or {}
    plat_registry = registry.get("platforms", {}).get(platform_name, {})

    plat_cores = _platform_cores(config, emu_profiles) if opts.target_cores else None
    pack_systems = filter_systems_by_target(
        config.get("systems", {}),
        emu_profiles,
        opts.target_cores,
        platform_cores=plat_cores,
    )
    build = _ManifestBuild(
        platform_name, platforms_dir, db, bios_dir, opts, config, emu_profiles,
        zip_contents, data_registry, game_entries, plat_registry.get("install", {}),
        str(REPO_ROOT), pack_systems,
    )
    build.manifest_profiles = {
        name: emu_profiles[name]
        for name in _platform_cores(config, emu_profiles)
    }
    build.manifest_validation = build_validation_index(build.manifest_profiles)
    build.manifest_owners = destination_owners(build.manifest_profiles)
    _settle_manifest_scope(build)
    return build, full_profiles


def _settle_manifest_scope(build: _ManifestBuild) -> None:
    """Game data destinations, slot choices and the region selection."""
    opts, config, emu_profiles = build.opts, build.config, build.emu_profiles
    # A destination is game data when every declaration of it is: a firmware
    # declaration of the same path keeps it in a pack built without game data.
    declared_kinds: dict[str, set[bool]] = {}
    for system in build.pack_systems.values():
        for fe in system.get("files", []):
            bare = declared_destination(fe)
            if bare:
                declared_kinds.setdefault(bare, set()).add(id(fe) in build.game_entries)
    build.game_destinations = {d for d, kinds in declared_kinds.items() if kinds == {True}}

    # The full manifest records every core's answer at a contested slot, so a
    # target narrowed from it gets what that target's own pack serves.
    whole = opts.target_cores is None and opts.source != "platform" and bool(emu_profiles)
    # The truth list read inside this run takes the choices already made.
    build.slot_choices = (
        opts.known_slot_choices if opts.known_slot_choices is not None and whole
        else slots.slot_choices(config, emu_profiles, build.db, build.zip_contents,
                                build.data_registry)
        if whole else {}
    )
    # Derived from the same choices: computed twice, it was 8% of a run.
    build.slot_overrides = slots.pack_overrides(
        config, emu_profiles, build.db, build.zip_contents, build.data_registry,
        target_cores=opts.target_cores, source=opts.source,
        choices=build.slot_choices if whole else None,
    )

    # Read by the region grouping and by phase 2 with the same arguments.
    build.undeclared = (
        undeclared_report(
            config, opts.emulators_dir, build.db, emu_profiles, opts.target_cores,
            include_all=(opts.source == "truth"),
        )
        if opts.source != "platform"
        else None
    )
    build.region_drops, build.selection, build.builder_held = manifest_selection(
        config, build.pack_systems, opts.emulators_dir, build.db, build.base_dest,
        emu_profiles, opts.target_cores, opts.source,
        required_only=opts.required_only, regions=opts.regions,
        undeclared=build.undeclared, zip_contents=build.zip_contents,
        data_registry=build.data_registry, slot_overrides=build.slot_overrides,
        one_per_slot=opts.one_per_slot,
    )


def generate_manifest(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    **options: Unpack[ManifestOptions],
) -> dict:
    """Generate a JSON manifest for a platform (same resolution as generate_pack).

    Returns a dict ready for JSON serialization with file inventory,
    install hints, and download metadata. ``fold_case`` overrides the
    platform's ``case_insensitive_fs``, for the case variants below.

    A file that is a game's data, not firmware, carries ``"category":
    "game_data"``, so the installer can leave it out as the builder does
    under ``no_game_data``. Firmware carries no category.
    One build: generate_install_list adds what --source truth and
    --standalone read. `build_out` receives the slot choices and the
    profiles this build read, which that second build takes over.
    """
    reject_unknown("generate_manifest", options, ManifestOptions.__optional_keys__)
    opts = _ManifestSettings(**options)
    build, full_profiles = _start_manifest(
        platform_name, platforms_dir, db, bios_dir, registry_path, opts
    )
    config, verification_mode = build.config, build.verification_mode

    def settle(
        file_entry: dict, sys_id: str, dest: str, override: str | None
    ) -> tuple[str | None, str]:
        """The file served once the slot is settled, or None and why not."""
        local_path, status = resolve_declaration(
            file_entry,
            db,
            bios_dir,
            build.zip_contents,
            build.data_registry,
            override,
            offline=opts.offline,
        )
        if status == "not_found" and not reads_file_contents(verification_mode):
            found = agnostic_substitute(file_entry, sys_id, db, build.manifest_profiles)
            if found:
                local_path, status = found[0], "agnostic_fallback"
                if os.path.basename(local_path) != file_entry.get("name", ""):
                    # The pack explains the rename in a note of its own.
                    build.rename_notes.add(file_entry.get("name", ""))
        # The builder's verdict: a hash platform omits what its frontend
        # would reject, a zipped_file archive included when the member is
        # missing whatever the outer resolution said. An existence
        # platform never reads the bytes.
        status, refusal = baseline_verdict(
            file_entry, local_path, status, verification_mode,
            config.get("hash_rule", ""),
        )
        if refusal or status in ("not_found", "external"):
            return None, "hash_mismatch" if refusal else status
        # The variant the pack ships when an emulator rejects the
        # resolved file: the installer must place the same bytes.
        local_path, _disagreement = validated_choice(
            file_entry, local_path, db, build.manifest_validation, bios_dir,
            digest_algorithm(verification_mode), dest, build.manifest_owners,
        )
        return local_path, status

    if opts.source != "truth":
        build.list_baseline(settle)
    build.list_core_files()
    result = build.result(build.list_data_directories())
    detect = build.install_section.get("detect", [])
    if build.case_insensitive and opts.fold_case is None and any(
        d.get("os") not in CASE_FOLDING_OS for d in detect
    ):
        # RetroArch also runs where case is kept: there Mesen-CE opens
        # bios.col and np2kai np2kai/2608_bd.wav, which the folded list
        # serves only as BIOS.col and 2608_BD.WAV. The installer adds these
        # where the directory keeps case, while the pack, extracted on Windows
        # or macOS too, stays folded.
        kept = generate_manifest(
            platform_name, platforms_dir, db, bios_dir, registry_path,
            emulators_dir=opts.emulators_dir, zip_contents=build.zip_contents,
            emu_profiles=full_profiles, target_cores=opts.target_cores, source=opts.source,
            regions=opts.regions, target_name=opts.target_name, offline=opts.offline,
            required_only=opts.required_only, data_registry=build.data_registry,
            fold_case=False, no_game_data=opts.no_game_data,
        )
        folded = {entry["dest"] for entry in build.manifest_files}
        folded_lower = {dest.lower() for dest in folded}
        variants = [
            entry for entry in kept["files"]
            if entry["dest"] not in folded and entry["dest"].lower() in folded_lower
        ]
        if variants:
            result["case_variants"] = variants
    if opts.build_out is not None:
        opts.build_out.update(slot_choices=build.slot_choices, profiles=build.manifest_profiles)
    return result


def generate_install_list(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    registry_path: str,
    standalone_out: dict | None = None,
    **options: Unpack[InstallListOptions],
) -> dict:
    """The list install.py reads: the full manifest, the files and omissions
    the --source truth build holds apart from it, and the emulators with a
    standalone build. `standalone_out` receives, per such emulator, what
    `--emulator X --standalone` packs, written apart from the list
    (install/standalone/<platform>.json) and fetched only by a run given
    --standalone.

    A manifest narrowed by a target, a case fold or --one-per-slot is no
    list install.py reads by default and gets neither.
    """
    settings = _ManifestSettings(**options)
    built: dict = {}
    result = generate_manifest(platform_name, platforms_dir, db, bios_dir, registry_path,
                               build_out=built, **options)
    if (settings.source != "full" or settings.target_cores is not None
            or settings.fold_case is not None or settings.one_per_slot):
        return result
    truth_options: InstallListOptions = {**options, "source": "truth"}
    with contextlib.redirect_stdout(io.StringIO()):
        truth = generate_manifest(
            platform_name, platforms_dir, db, bios_dir, registry_path,
            **truth_options, known_slot_choices=built["slot_choices"],
        )
    _mark_truth(result, truth)
    layouts = standalone_layouts(
        built["profiles"], settings.emulators_dir, db, bios_dir,
        settings.zip_contents or {}, settings.offline, platforms_dir, result,
    )
    if layouts:
        result["standalone_builds"] = sorted(layouts)
        if standalone_out is not None:
            standalone_out.update(layouts)
    return result


def _truth_key(entry: dict) -> tuple:
    """What tells one entry from another, as the installer's _entry_key."""
    root = entry.get("root")
    cores = tuple(entry.get("cores") or []) if root == "emulator" else ()
    return (str(entry.get("dest")), root, cores)


def _mark_truth(result: dict, truth: dict) -> None:
    """What `--source truth` installs, carried in the full list.

    The truth list holds what the emulator profiles prove is read. A file of
    the full list it does not hold, by destination and content, is marked
    `"truth": false`, and what only the truth list holds is `truth_files`.
    Omissions compare by destination. The installer then rebuilds the
    truth list from the full one, and a list without `truth_files` is one
    published before, on which `--source truth` is refused.
    """
    held = {(_truth_key(entry), entry.get("sha1")) for entry in truth["files"]}
    full = {(_truth_key(entry), entry.get("sha1")) for entry in result["files"]}
    for entry in result["files"]:
        if (_truth_key(entry), entry.get("sha1")) not in held:
            entry["truth"] = False
    result["truth_files"] = [
        entry for entry in truth["files"]
        if (_truth_key(entry), entry.get("sha1")) not in full
    ]
    absent = {_truth_key(entry) for entry in truth["omitted_files"]}
    listed = {_truth_key(entry) for entry in result["omitted_files"]}
    for entry in result["omitted_files"]:
        if _truth_key(entry) not in absent:
            entry["truth"] = False
    result["truth_omitted"] = [
        entry for entry in truth["omitted_files"] if _truth_key(entry) not in listed
    ]
