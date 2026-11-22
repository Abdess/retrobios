"""A platform's coverage: each declaration resolved and judged as its frontend would."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.paths import BIOS_DIR, EMULATORS_DIR, declared_destination
from core.ziptools import build_zip_contents_index
from model.alternatives import core_file_spares
from model.declarations import OUTER_ROOTS, declared_components, platform_declarations
from model.profiles import lists_files, load_emulator_profiles
from model.systems import select_systems
from packs import slots
from packs.crossref import launcher_reads_not_held
from packs.gaps import find_exclusion_notes, find_undeclared_files
from packs.verdicts import (
    RELEASE_ASSET_PENDING,
    Severity,
    Status,
    SEVERITY_ORDER,
    STATUS_ORDER,
    storage_verdict,
    compute_severity,
    verify_entry_existence,
    verify_entry_md5,
    verify_entry_sha1,
)
from resolve.categories import BIOS, EntryCategories
from resolve.cores import platform_scope_systems, resolve_platform_cores
from resolve.launchers import launcher_unproven
from resolve.nativemode import digest_algorithm, platform_mode, reads_file_contents
from resolve.validation import (
    build_validation_index,
    agnostic_substitute,
    baseline_verdict,
    build_ground_truth,
    destination_owners,
    validated_choice,
)

if TYPE_CHECKING:
    from packs.extras import ExtraResolver
    from typing_extensions import Unpack


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


def _dest_key(file_entry: dict, sys_id: str) -> str:
    """The path a declaration occupies, as the builder keys its pack."""
    dest = declared_destination(file_entry)
    return dest or f"{sys_id}/{file_entry.get('name', '')}"


def _twin_index(
    verify_systems: dict, db: dict, base_dest: str, zip_contents: dict,
) -> tuple[dict[str, int], dict[int, tuple[str, dict]]]:
    """Which declaration the pack ships at each destination, and every declaration by id."""
    # From the module that defines the rule, not the builder's CLI: importing
    # generate_pack made every verify depend on its argparse and manifest code.
    from resolve.packfiles import preferred_entries as _preferred_entries

    preferred_entries = _preferred_entries(
        verify_systems, db, BIOS_DIR, base_dest, False,
        zip_contents, True,
    )
    winners = {
        id(fe): (sid, fe)
        for sid, system in verify_systems.items()
        for fe in system.get("files", [])
    }
    return preferred_entries, winners


@dataclass(frozen=True)
class _DeclarationResolver:
    """How a platform run resolves its declarations, as the builder does."""

    db: dict
    zip_contents: dict
    data_dir_registry: dict | None
    slot_overrides: dict[str, str]
    mode: str
    platform_profiles: dict
    # Which declaration the pack ships at each destination, and every
    # declaration by id (_twin_index).
    preferred_entries: dict[str, int]
    winners: dict[int, tuple[str, dict]]
    base_dest: str


def _resolve_declaration(
    file_entry: dict, sys_id: str, resolver: _DeclarationResolver,
) -> tuple[str | None, str, str | None, dict]:
    """Resolve a declaration to the file the pack ships at its destination.

    When another declaration holds the destination, that one's file is
    returned and the evidence reset: the winner's hash match is not this
    declaration's, which is hashed against the shipped file. The
    declaration that holds the path comes last.
    """
    base_dest = resolver.base_dest
    bare = declared_destination(file_entry)
    preferred = resolver.preferred_entries.get(f"{base_dest}/{bare}" if base_dest else bare)
    held_by, winner = (None, file_entry)
    if preferred is not None and preferred != id(file_entry):
        held_by, winner = resolver.winners[preferred]
    local_path, resolve_status = _resolve_for_platform(
        winner, held_by or sys_id, resolver.db, resolver.zip_contents,
        resolver.data_dir_registry, resolver.slot_overrides, resolver.mode,
        resolver.platform_profiles,
    )
    return local_path, "" if held_by else resolve_status, held_by, winner


def _expects(entry: dict) -> str:
    """The first hash a declaration names, as the message quotes it."""
    return next(
        (f" ({h} {str(entry[h]).split(',')[0]})"
         for h in ("sha1", "md5", "crc32") if entry.get(h)),
        "",
    )


def _side(sys_id: str, entry: dict) -> str:
    """One declaration named by the platform's own system, or its component."""
    native = entry.get("native_system") or ", ".join(
        declared_components(entry.get("component"))
    )
    return f"{sys_id} ({native})" if native else sys_id


def _twin_unmet(
    result: dict,
    held_by: str | None,
    file_entry: dict | None = None,
    sys_id: str = "",
    destination: str = "",
    holder: dict | None = None,
) -> bool:
    """Mark a declaration unmet at a path another declaration holds.

    The path is answered by the winner's file, which the pack counts once.
    This declaration's failure is reported, never folded into the
    destination's status. The message names the path, both systems and
    what this declaration expects: "is not met at the path coco holds"
    named neither the path nor the file wanted there. Two declarations of
    one system are told apart by the platform's own system (RetroDECK
    declares decocass.zip for MAME and for FBNeo, both arcade here), and by
    the hash the holder names when that is the same too (its three
    64DD_IPL.bin revisions).
    """
    if held_by is None or result["status"] == Status.OK:
        return False
    entry = file_entry or {}
    expects = _expects(entry)
    owner, other, held = sys_id or "this", held_by, ""
    if owner == other and holder is not None:
        owner, other = _side(owner, entry), _side(other, holder)
        if owner == other:
            held = _expects(holder)
    result["discrepancy"] = (
        f"{destination or result.get('name', '')} is declared for {owner}"
        f" and for {other}. The {owner} declaration{expects} is not met at"
        f" the path, which holds the {other} file{held}"
    )
    # Read by reports that list entries: the destination itself is held, and
    # a count by destination does not include this one.
    result["settled_by"] = held_by
    return True


def _resolve_for_platform(
    file_entry: dict,
    sys_id: str,
    db: dict,
    zip_contents: dict,
    data_dir_registry: dict | None,
    slot_overrides: dict[str, str],
    mode: str,
    platform_profiles: dict,
) -> tuple[str | None, str]:
    """Resolve one platform entry the way the pack builder does.

    The builder's own resolution (packresolve.resolve_declaration), read from
    disk and the large-file cache: verify never downloads. A frontend that
    never reads the bytes takes the filename-free core's own image.
    """
    from resolve.packfiles import release_asset_paths, resolve_declaration, run_is_offline

    override = slot_overrides.get(
        declared_destination(file_entry)
    )
    local_path, status = resolve_declaration(
        file_entry, db, BIOS_DIR, zip_contents, data_dir_registry,
        override, offline=True,
    )
    if status in ("not_found", "hash_mismatch") and not run_is_offline():
        # Not in the cache, and the release holds a copy that answers the
        # declaration: an online build fetches and packs it (resolve_file).
        assets = release_asset_paths(file_entry, db)
        if assets:
            return assets[0], RELEASE_ASSET_PENDING
    if status == "not_found" and not reads_file_contents(mode):
        found = agnostic_substitute(file_entry, sys_id, db, platform_profiles)
        if found:
            return found[0], "agnostic_fallback"
    return local_path, status


@dataclass(frozen=True)
class _PlatformRun:
    """The inputs of one verify_platform run, read by each of its stages."""

    config: dict
    db: dict
    emulators_dir: str
    emu_profiles: dict | None
    profiles: dict
    target_cores: set[str] | None
    data_dir_registry: dict | None
    zip_contents: dict
    system_filter: list[str] | None
    required_only: bool
    mode: str
    base_dest: str

    def full(self, destination: str) -> str:
        return f"{self.base_dest}/{destination}" if self.base_dest else destination


@dataclass
class _PlatformTally:
    """Each declaration's verdict, and the verdicts aggregated by destination."""

    run: _PlatformRun
    platform: str
    resolver: _DeclarationResolver
    region_drops: set[str]
    validation_index: dict
    validation_owners: dict[str, list[tuple[str, str]]]
    hle_index: dict[str, bool]
    categories: EntryCategories
    details: list[dict] = field(default_factory=list)
    file_status: dict[str, str] = field(default_factory=dict)
    file_required: dict[str, bool] = field(default_factory=dict)
    file_severity: dict[str, str] = field(default_factory=dict)
    # What each entry is: firmware, a game's data, or a name no core the
    # platform runs opens. Only firmware gaps carry a severity.
    file_category: dict[str, str] = field(default_factory=dict)
    # (system, full destination, local copy) of each declaration the builder
    # writes, and None for one whose slot it keeps without a file from the
    # collection (user_provided, external). Placed below in the builder's order.
    packed_order: list[tuple[str, str, str | None]] = field(default_factory=list)
    shipped_keys: set[str] = field(default_factory=set)
    results_at: dict[str, list[dict]] = field(default_factory=dict)

    def judge(self, sys_id: str, file_entry: dict) -> None:
        """Verify one declaration and add it to its destination's tally."""
        destination = declared_destination(file_entry)
        if self.region_drops and destination in self.region_drops:
            return
        local_path, resolve_status, held_by, holder = _resolve_declaration(
            file_entry, sys_id, self.resolver,
        )
        result, local_path = self._verdict(
            file_entry, sys_id, local_path, resolve_status, destination,
        )
        result["system"] = sys_id
        result["hle_fallback"] = self.hle_index.get(file_entry.get("name", ""), False)
        result["ground_truth"] = build_ground_truth(
            file_entry.get("name", ""),
            self.validation_index,
        )
        self.details.append(result)
        config = self.run.config
        mode = self.run.mode
        # Occupied only where the builder ships the declaration: a hash
        # the frontend refuses is left out, and the destination stays free
        # for a core's file the pack does carry.
        if (
            local_path
            and result["status"] != Status.MISSING
            and baseline_verdict(
                file_entry, local_path, resolve_status, mode, config.get("hash_rule", "")
            )[1] is None
        ):
            self.packed_order.append((sys_id, self.run.full(destination), local_path))
            self.shipped_keys.add(_dest_key(file_entry, sys_id))
        if _twin_unmet(
            result, held_by, file_entry, sys_id, self.run.full(destination), holder,
        ):
            return
        self._aggregate(sys_id, file_entry, destination, result)

    def _verdict(
        self, file_entry: dict, sys_id: str, local_path: str | None,
        resolve_status: str, destination: str,
    ) -> tuple[dict, str | None]:
        """The declaration's result, and the local copy the pack writes for it."""
        config = self.run.config
        mode = self.run.mode
        stored = storage_verdict(file_entry, emulator_pack=False)
        if resolve_status == RELEASE_ASSET_PENDING:
            # Counted as an online build counts it, which fetches the
            # asset. Under --offline the builder cannot, and neither
            # does this report (_resolve_for_platform).
            result = {
                "name": file_entry.get("name", ""),
                "required": file_entry.get("required", True),
                "status": Status.OK,
                "release_asset": local_path,
                "reason": "release asset, fetched when the pack is built",
            }
            # Written at its path like any held file: keyed to None, it
            # stayed out of pack_destinations and step 5 read the pack's
            # copy as a file only the pack holds.
            self.packed_order.append((sys_id, self.run.full(destination), local_path))
            self.shipped_keys.add(_dest_key(file_entry, sys_id))
            return result, None
        if stored is not None:
            # The builder keeps the slot: instructions for a user_provided
            # file, the download for an external one, whether it arrives
            # or not. No core file goes there.
            self.packed_order.append((sys_id, self.run.full(destination), None))
            return stored, None
        if not reads_file_contents(mode):
            return verify_entry_existence(
                file_entry,
                local_path,
                self.validation_index,
                self.run.db,
                destination,
                self.validation_owners,
                resolve_status,
                config.get("platform", ""),
            ), local_path
        if digest_algorithm(mode) == "sha1":
            return verify_entry_sha1(file_entry, local_path), local_path
        result = verify_entry_md5(
            file_entry, local_path, resolve_status, config.get("hash_rule", "")
        )
        # Emulator-level validation: informational for platform packs.
        # Platform verification (MD5) is the authority. Emulator
        # mismatches are reported as discrepancies, not failures.
        if result["status"] == Status.OK:
            _chosen, disagreement = validated_choice(
                file_entry, local_path, self.run.db, self.validation_index, "bios",
                digest_algorithm(mode), destination, self.validation_owners,
            )
            if disagreement:
                result["discrepancy"] = f"{self.platform} says OK but {disagreement}"
        return result, local_path

    def _aggregate(
        self, sys_id: str, file_entry: dict, destination: str, result: dict,
    ) -> None:
        # Aggregate by destination, keyed as the builder keys its pack.
        # A declaration that finds nothing leaves the path to one that
        # holds a file: the builder packs that file there, whatever the
        # order the two are read in.
        dest = _dest_key(file_entry, sys_id)
        self.results_at.setdefault(dest, []).append(result)
        required = file_entry.get("required", True)
        cur = result["status"]
        prev = self.file_status.get(dest)
        hle = self.hle_index.get(file_entry.get("name", ""), False)
        sev = compute_severity(cur, required, self.run.mode, hle)
        explained = self.categories.explain(file_entry, destination, sys_id)
        category = explained.pop("category")
        result["category"] = category
        result["category_evidence"] = explained
        if cur != Status.MISSING:
            # A held entry is firmware for the counts: its category only
            # documents it.
            category = BIOS
        if self.file_category.get(dest, category) == BIOS:
            category = BIOS
        self.file_category[dest] = category
        if prev is not None and (cur == Status.MISSING) != (prev == Status.MISSING):
            if cur == Status.MISSING:
                return
            del self.file_status[dest], self.file_severity[dest]
            prev = None
        if prev is None or STATUS_ORDER.get(cur, 0) > STATUS_ORDER.get(prev, 0):
            self.file_status[dest] = cur
            self.file_required[dest] = required
        prev_sev = self.file_severity.get(dest)
        if prev_sev is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(
            prev_sev, 0
        ):
            self.file_severity[dest] = sev

    def settle_groups(self) -> None:
        """RetroBat's group: one file of it held is enough, and the others are
        reported OPTIONAL (batocera-systems/Program.cs). None held, each stays
        required."""
        members: dict[tuple[str, str], list[str]] = {}
        for sys_id, system in self.run.config.get("systems", {}).items():
            for file_entry in system.get("files", []):
                if file_entry.get("group"):
                    dest = _dest_key(file_entry, sys_id)
                    if dest in self.file_status:
                        members.setdefault((sys_id, file_entry["group"]), []).append(dest)
        for dests in members.values():
            if not any(self.file_status[d] == Status.OK for d in dests):
                continue
            for dest in dests:
                if self.file_status[dest] == Status.MISSING:
                    self.file_required[dest] = False
                    self.file_severity[dest] = compute_severity(
                        Status.MISSING, False, self.run.mode
                    )
                    for result in self.results_at.get(dest, []):
                        result["required"] = False

    def credit_placed(self, placed: set[str]) -> None:
        """An existence frontend is satisfied by any file at the path, and the
        builder fills a free platform destination with a core's file."""
        for dest, status in self.file_status.items():
            if status == Status.MISSING and self.run.full(dest) in placed:
                self.file_status[dest] = Status.OK
                self.file_severity[dest] = Severity.OK
                for result in self.results_at.get(dest, []):
                    result["status"] = Status.OK

    def severity_counts(self) -> tuple[dict[str, int], dict[str, list[str]]]:
        """Destinations by severity, and the missing ones that are not firmware."""
        counts = {
            Severity.OK: 0,
            Severity.INFO: 0,
            Severity.WARNING: 0,
            Severity.CRITICAL: 0,
        }
        not_firmware: dict[str, list[str]] = {}
        for dest, s in self.file_severity.items():
            category = self.file_category.get(dest, BIOS)
            if category != BIOS and self.file_status.get(dest) == Status.MISSING:
                not_firmware.setdefault(category, []).append(dest)
                continue
            counts[s] = counts.get(s, 0) + 1
        return counts, not_firmware


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
    run: _PlatformRun, verify_systems: dict, pack_overrides: dict, regions: list[str],
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


def _platform_gaps(
    run: _PlatformRun,
    occupied: dict[str, str | None],
    region_drops: set[str],
    region_extra_dests: dict[tuple[str, str, str], str],
    validation_index: dict,
    validation_owners: dict[str, list[tuple[str, str]]],
) -> tuple[list[dict], set[str], dict[str, str]]:
    """The core files of the pack: the gap report as the builder narrows it,
    the destinations it fills, and the category of each."""
    config = run.config
    # Cross-reference undeclared files, called exactly as the builder calls
    # it: its declarations, not the enriched ones (a core file the platform
    # also declares under another name is packed at the core's own path, 21
    # such files in the RetroArch pack), and no names from inside archives
    # or data trees (a loose file whose name exists only as a member of
    # naomi2.zip was counted "in pack" while the builder shipped nothing).
    undeclared = find_undeclared_files(
        config,
        run.emulators_dir,
        run.db,
        run.emu_profiles,
        target_cores=run.target_cores,
        declared_names=platform_declarations(config, run.db, enrich=False),
    )
    # The builder's own pass reads the same report: computed once here and
    # handed over as it stands now, before the markings below.
    report_for_builder = [dict(u) for u in undeclared]
    if run.system_filter:
        # A system pack carries the extras its systems own.
        from packs.extras import report_owned_by_systems

        undeclared = report_owned_by_systems(undeclared, run.system_filter)
    if run.required_only:
        undeclared = [u for u in undeclared if u.get("required") is not False]
    if region_drops:
        undeclared = [
            u
            for u in undeclared
            if region_extra_dests.get(
                (u.get("emulator", ""), u.get("name", ""), u.get("path") or "")
            )
            not in region_drops
        ]
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
    return undeclared, placed, placed_kind


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
            dest_to_name.setdefault(_dest_key(fe, sys_id), fe.get("name", ""))
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
    zip_contents = build_zip_contents_index(db) if has_zipped else {}

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
    run = _PlatformRun(
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
    preferred_entries, winners = _twin_index(
        verify_systems, db, base_dest, zip_contents
    )
    tally = _PlatformTally(
        run, platform,
        _DeclarationResolver(
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
    undeclared, placed, placed_kind = _platform_gaps(
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
