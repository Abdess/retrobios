"""One install manifest being listed, by the rules the pack builder follows."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.artifacts import build_timestamp
from core.paths import EMULATORS_DIR, declared_destination, sanitize_pack_path
from model.declarations import OUTER_ROOTS, declared_root, outer_layout
from model.profiles import installed_data_refs_in
from model.systems import platform_system_names
from packs.archive import PACK_DOCUMENTS, Placed, instructions_note
from packs.datatrees import (
    core_data_trees,
    data_directory_members,
    in_data_cache,
    manifest_data_directories,
    pack_markers,
    tree_readers,
)
from packs.extras import collect_emulator_extras
from packs.extraplace import extra_region_key, save_entry_fields, save_manifest_dest
from packs.manifestcores import (
    downloaded_cores,
    manifest_core_entries,
    manifest_core_index,
    offered_boards,
)
from packs.manifestentry import (
    ClaimContext,
    MANIFEST_OUTER_FIELDS,
    attach_claims,
    manifest_dest_of,
    manifest_entry,
    record_absent,
    record_slot_choices,
    record_unplaceable,
)
from packs.manifestselect import SelectionIndex
from packs.paths import platform_destination, save_layout
from packs.scope import pack_sections, platform_list_version, system_titles
from packs.standalone import standalone_copies
from resolve.gamedata import GAME_DATA, is_game_data
from resolve.nativemode import platform_mode
from resolve.packfiles import preferred_entries as _preferred_entries


if TYPE_CHECKING:
    # How a manifest settles a platform declaration: the copy served, or None
    # and why not.
    _Settle = Callable[[dict, str, str, "str | None"], "tuple[str | None, str]"]


@dataclass(frozen=True)
class ManifestSettings:
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
    uncached_out: dict[str, str] | None = None


@dataclass
class ManifestBuild:
    """One install manifest being listed: its files, omissions and the slots
    they take, settled by the rules the pack builder follows."""

    platform_name: str
    platforms_dir: str
    db: dict
    bios_dir: str
    opts: ManifestSettings
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
                dest, full_dest = platform_destination(file_entry, self.base_dest)
                if not dest:
                    continue
                if self.region_drops and dest in self.region_drops:
                    continue
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
        self.pack_only_sizes.append(len(instructions_note(file_entry)[1].encode()))
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
        uncached: list[tuple[str, str]] = []
        self.data_members = list(data_directory_members(
            self.pack_systems, self.data_registry, self.platform_name, self.base_dest,
            self.placed, refs_out=data_refs, required_only=required_only,
            core_trees=core_trees,
            installed=installed_data_refs_in(self.platform_name, self.emu_profiles),
            reclaim=reclaim, uncached_out=uncached,
        ))
        if opts.uncached_out is not None:
            opts.uncached_out.update(uncached)
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
            "system_titles": system_titles(
                pack_sections(self.db, self.bios_dir, opts.emulators_dir),
                manifest_files, omitted.values(),
            ),
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
