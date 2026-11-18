"""Building a platform pack: plan, variant choice, slot settlement, the archive."""

from __future__ import annotations

import contextlib
import os
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from core.hashing import compute_hashes
from core.paths import sanitize_pack_path
from model.alternatives import core_file_spares
from model.declarations import OUTER_ROOTS, declared_root
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles
from model.safeparse import yaml_load
from packs import slots
from packs.archive import (
    CASE_FOLDING_OS,
    PackRecord,
    _Placed,
    _add_pack_member,
    _add_zip_to_pack,
    _extract_zip_to_archive,
    _reject_unknown,
    _same_bytes,
    _write_generated_member,
    _writing_pack,
)
from packs.datatrees import _data_directory_members, core_data_trees, pack_markers
from packs.extras import (
    ExtraResolver,
    _collect_emulator_extras,
    _detect_extras_prefix,
    extra_full_destination,
    extra_region_key,
    extras_for_systems as _extras_for_systems,
    platform_region_groups,
    undeclared_report,
)
from packs.naming import _narrowings, _platform_pack_name
from packs.paths import _flat, save_layout
from packs.readme import _build_agnostic_rename_readme, _build_readme, save_place
from resolve import packfiles as packresolve, regions as resolve_regions, slot as slot_mod
from resolve.contentlayout import TARGET_KEY
from resolve.cores import platform_scope_systems, system_scope_error
from resolve.gamedata import GameDataCut, without_game_data
from resolve.nativemode import digest_algorithm, hash_mismatch_excludes_file, reads_file_contents
from resolve.packfiles import (
    download_external,
    preferred_entries as _preferred_entries,
    resolve_declaration,
    resolve_file,
)
from resolve.validation import (
    _build_validation_index,
    _parse_validation,
    agnostic_substitute,
    baseline_verdict,
    destination_owners,
    existence_discrepancy,
    extra_alternatives,
    validated_choice,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack


def _case_twin_pairs(
    twins: list[str], seen_destinations: set[str], base_dest: str, flatten: bool,
) -> list[tuple[str, str]]:
    """Each spelling left out, with the spelling the pack holds."""
    held = {
        _flat(dest, base_dest, flatten).lower(): _flat(dest, base_dest, flatten)
        for dest in seen_destinations
    }
    return sorted({(twin, held[twin.lower()]) for twin in twins if twin.lower() in held})


def _report_pack_counts(
    zip_path: str,
    file_status: dict,
    total_files: int,
    core_count: int,
    source: str,
    verification_mode: str,
    tree_count: int = 0,
) -> None:
    """Print the line the pipeline's consistency check reads.

    The check compares these counts against what verify.py reports for
    the same platform, so the wording is a contract: parse_pack_counts
    in pipeline.py matches on it.
    """
    files_ok = sum(1 for s in file_status.values() if s == "ok")
    files_untested = sum(1 for s in file_status.values() if s == "untested")
    files_excluded = sum(1 for s in file_status.values() if s == "excluded")
    files_miss = sum(1 for s in file_status.values() if s == "missing")
    total_checked = len(file_status)

    parts = [f"{files_ok}/{total_checked} files OK"]
    if files_untested:
        parts.append(f"{files_untested} untested")
    if files_excluded:
        parts.append(f"{files_excluded} unsafe excluded")
    if files_miss:
        parts.append(f"{files_miss} missing")
    if source == "platform":
        print(
            f"  {zip_path}: {total_files} files packed (platform baseline only), "
            f"{', '.join(parts)} [{verification_mode}]"
        )
    elif source == "truth":
        print(
            f"  {zip_path}: {total_files} files packed (ground truth only), "
            f"{core_count} from emulator profiles [{verification_mode}]"
        )
    else:
        baseline = total_files - core_count - tree_count
        trees = f"{tree_count} in core data trees + " if tree_count else ""
        print(
            f"  {zip_path}: {total_files} files packed ({baseline} baseline + "
            f"{trees}{core_count} from cores), {', '.join(parts)} [{verification_mode}]"
        )

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
    _reject_unknown("_select_variants", options, _VariantOptions.__optional_keys__)
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
        slot_drops, slot_undecidable = _slot_drops(
            config, emu_profiles, target_cores, region_groups, region_drops, held
        )
        region_drops = region_drops | slot_drops
        if slot_undecidable:
            print(
                f"  {len(slot_undecidable)} slot(s) with no declared order: "
                f"every candidate kept"
            )

    return region_drops, region_fallbacks, slot_undecidable


def _slot_drops(
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


def _matches_an_alternative(fe: dict, local_path: str, profiles: dict) -> bool:
    """Whether the copy is another version the same profile accepts there.

    A profile lists every version its code takes under one name (each GRP
    of Raze's table, eduke32's demo and retail NWINTER.GRP). The extra
    carries the first, and the held copy matching a sibling is no mismatch.
    """
    siblings = extra_alternatives(fe, profiles)
    if len(siblings) < 2:
        return False
    # A sibling the code takes without a check (Raze's "BLOOD: Unknown
    # Version") accepts whatever copy fills the slot.
    if any(not _parse_validation(entry.get("validation")) for entry in siblings):
        return True
    actual = compute_hashes(local_path, frozenset({"sha1", "md5", "crc32"}))
    for entry in siblings:
        for algorithm in ("sha1", "md5", "crc32"):
            declared = entry.get(algorithm)
            values = declared if isinstance(declared, list) else [declared]
            if any(v and str(v).lower() == actual.get(algorithm, "") for v in values):
                return True
    return False


def _report_left_out(cut: GameDataCut, systems: set[str], cores: bool) -> None:
    """Name the game data a --no-game-data build left out, and why.

    ``systems`` limits the platform layer to the systems this pack covers,
    and ``cores`` says whether this pack collected the core files itself:
    a split part does not, its run names them once.
    """
    kept = [
        item for item in cut.left_out
        if (item.layer == "platform" and item.system in systems)
        or (item.layer == "core" and cores)
    ]
    for line in GameDataCut(cut.config, cut.profiles, kept).report_lines():
        print(f"  {line}")


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


@dataclass(frozen=True)
class _PackSettings:
    """PackOptions with their defaults."""

    emulators_dir: str = "emulators"
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


@dataclass
class _PlatformPlan:
    """What a platform pack is built from, settled before its first member."""

    platform_name: str
    platforms_dir: str
    db: dict
    bios_dir: str
    opts: _PackSettings
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
        return self.config.get("verification_mode", "existence")

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


def _plan_platform_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    opts: _PackSettings,
) -> _PlatformPlan | None:
    """The configuration, scope and checks a platform pack reads, or None
    when the systems asked for leave nothing to build."""
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

    narrowings = _narrowings(
        opts.source, opts.regions, opts.target_name, opts.one_per_slot, opts.required_only,
        no_game_data=opts.no_game_data,
    )
    zip_path = os.path.join(
        output_dir,
        _platform_pack_name(
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
        validation_index = _build_validation_index(platform_profiles)
    validation_owners = destination_owners(platform_profiles)
    slot_overrides = slots.pack_overrides(
        config, emu_profiles or {}, db, zip_contents, opts.data_registry,
        target_cores=opts.target_cores, source=opts.source,
    )

    pack_systems = platform_scope_systems(
        config, emu_profiles or {}, opts.target_cores, opts.system_filter
    )
    if opts.system_filter and not pack_systems:
        reason = system_scope_error(config, platform_name, opts.system_filter, opts.target_name)
        print(f"  WARNING: {reason}")
        return None
    if opts.extras_only:
        # The part of a split that carries the core extras no platform system
        # owns: the platform's own files and trees went to the other parts.
        pack_systems = {}

    plan = _PlatformPlan(
        platform_name, platforms_dir, db, bios_dir, opts, config, emu_profiles,
        zip_contents, cut, narrowings, zip_path, validation_index, platform_profiles,
        validation_owners, slot_overrides, pack_systems,
    )
    _settle_pack_choices(plan)
    return plan


def _settle_pack_choices(plan: _PlatformPlan) -> None:
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


_STATUS_LABELS = {"untested": "UNTESTED", "excluded": "EXCLUDED", "missing": "MISSING"}


@dataclass
class _PlatformPackBuild:
    """One platform pack being written: its members and what each slot came to.

    The four lookups are bound by generate_pack, the one place that says how
    a platform file and a core extra are found and judged.
    """

    plan: _PlatformPlan
    zf: zipfile.ZipFile | PackRecord
    resolve: Callable[[dict, str], tuple[str | None, str]]
    verdict: Callable[[dict, str | None, str], tuple[str, str | None]]
    judge: Callable[[dict, str | None, str], tuple[str | None, str | None]]
    resolve_extra: Callable[[dict, str], tuple[str | None, str, str]]
    placed: _Placed = field(init=False)
    total_files: int = 0
    core_count: int = 0
    save_count: int = 0
    tree_count: int = 0
    # Per-destination status.  ``excluded`` means a same-named local payload
    # exists but contradicts the declaration and is intentionally not shipped.
    # It is distinct from a genuine coverage gap (``missing``).
    file_status: dict[str, str] = field(default_factory=dict)
    file_reasons: dict[str, str] = field(default_factory=dict)
    # Core extras whose local copy contradicts the profile hash: packed,
    # reported, and never counted against the platform's own file total.
    core_discrepancies: list[str] = field(default_factory=list)
    # Spellings left out as case twins of a packed file, for the README.
    case_twins: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.placed = _Placed(self.plan.case_insensitive)

    def _flat(self, path: str) -> str:
        return _flat(path, self.plan.base_dest, self.plan.opts.flatten)

    def run(self) -> None:
        if self.plan.opts.source != "truth":
            for sys_id, system in sorted(self.plan.pack_systems.items()):
                for file_entry in system.get("files", []):
                    self._pack_declared(sys_id, file_entry)
        # Core requirements: files platform's cores need but YAML doesn't declare
        self._pack_core_files()
        self._pack_trees()
        self._write_readme()

    def _judge_conflict(self, file_entry: dict, full_dest: str) -> None:
        # Content ships under the conflicting shape (file vs dir,
        # e.g. SGB1.sfc). verify.py resolves each declaration on
        # its own, so this one is counted by what it resolves to:
        # an unresolved one counted OK had the pack claim a file
        # verify reports missing.
        plan = self.plan
        conflict_path, conflict_status = resolve_file(
            file_entry, plan.db, plan.bios_dir, plan.zip_contents,
            data_dir_registry=plan.opts.data_registry, offline=plan.opts.offline,
        )
        # The verdict of the main path: a zipped_file archive is
        # judged by the member inside, and a frontend that hashes
        # one digest accepts a file another declared hash
        # contradicts, as verify judges it.
        conflict_status, refusal = baseline_verdict(
            file_entry, conflict_path, conflict_status, plan.verification_mode,
            plan.config.get("hash_rule", ""),
        )
        if conflict_status == "not_found":
            self.file_status[full_dest] = "missing"
            self.file_reasons[full_dest] = "not found"
        elif refusal:
            self.file_status[full_dest] = "excluded"
            self.file_reasons[full_dest] = refusal
        else:
            self.file_status.setdefault(full_dest, "ok")

    def _pack_declared(self, sys_id: str, file_entry: dict) -> None:
        plan, opts = self.plan, self.plan.opts
        if opts.required_only and file_entry.get("required") is False:
            return
        dest = sanitize_pack_path(file_entry.get("destination", file_entry["name"]))
        if plan.region_drops and dest in plan.region_drops:
            return
        if not dest:
            self._judge_unnamed(sys_id, file_entry)
            return
        full_dest = f"{plan.base_dest}/{dest}" if plan.base_dest else dest
        already_packed = self.placed.holds(full_dest)

        preferred = plan.preferred_entries.get(full_dest)
        if preferred is not None and id(file_entry) != preferred:
            return
        if self.placed.conflicts(full_dest):
            self._judge_conflict(file_entry, full_dest)
            return
        storage = file_entry.get("storage", "embedded")
        if storage == "user_provided":
            if not already_packed:
                self._write_instructions(file_entry, full_dest)
            return

        local_path, status = self.resolve(file_entry, full_dest)
        if status == "external":
            self._pack_external(file_entry, full_dest)
            return
        if status == "not_found":
            local_path = self._agnostic_fallback(sys_id, file_entry, full_dest, already_packed)
            if local_path is None:
                return
            status = "agnostic_fallback"
            # Fall through to normal packing below
        chosen = self._settle_declared(file_entry, full_dest, dest, local_path, status, already_packed)
        if chosen is not None:
            self._ship_declared(file_entry, full_dest, chosen, already_packed)

    def _judge_unnamed(self, sys_id: str, file_entry: dict) -> None:
        # EmuDeck-style entries (system:md5 whitelist, no filename).
        # Judged as verify judges it: resolved on disk, the md5
        # list parsed once (case, comma lists).
        plan = self.plan
        fkey = f"{sys_id}/{file_entry.get('name', '')}"
        held, held_status = resolve_file(
            file_entry, plan.db, plan.bios_dir, plan.zip_contents,
            data_dir_registry=plan.opts.data_registry, offline=plan.opts.offline,
        )
        if held_status == "not_found" or not held:
            self.file_status[fkey] = "missing"
        elif self.verdict(file_entry, held, held_status)[1]:
            self.file_status[fkey] = "excluded"
        else:
            self.file_status.setdefault(fkey, "ok")

    def _write_instructions(self, file_entry: dict, full_dest: str) -> None:
        base_dest = self.plan.base_dest
        self.placed.take(full_dest)
        self.file_status.setdefault(full_dest, "ok")
        instructions = file_entry.get(
            "instructions", "Please provide this file manually."
        )
        instr_name = f"INSTRUCTIONS_{file_entry['name']}.txt"
        instr_path = (
            f"{base_dest}/{instr_name}" if base_dest else instr_name
        )
        _write_generated_member(
            self.zf,
            self._flat(instr_path),
            f"File needed: {file_entry['name']}\n\n{instructions}\n",
        )
        self.total_files += 1

    def _pack_external(self, file_entry: dict, full_dest: str) -> None:
        file_ext = os.path.splitext(file_entry["name"])[1] or ""
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=file_ext, dir=packresolve.scratch_dir()
        ) as tmp:
            tmp_path = tmp.name

        # The slot is the platform's file whether the download
        # arrives or not: verify cannot fetch, and a core file
        # filling it on a failed download made the two differ.
        self.placed.take(full_dest)
        try:
            if self.plan.opts.record is None and download_external(file_entry, tmp_path):
                extract = file_entry.get("extract", False)
                if extract and tmp_path.endswith(".zip"):
                    _extract_zip_to_archive(tmp_path, self._flat(full_dest), self.zf)
                else:
                    _add_pack_member(self.zf, tmp_path, self._flat(full_dest))
                self.file_status.setdefault(full_dest, "ok")
                self.total_files += 1
            else:
                self.file_status[full_dest] = "missing"
                self.file_reasons[full_dest] = "external download failed"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _agnostic_fallback(
        self, sys_id: str, file_entry: dict, full_dest: str, already_packed: bool,
    ) -> str | None:
        # A filename-agnostic core takes any image of its system,
        # renamed. Only an existence frontend accepts that.
        plan = self.plan
        found = None
        if not reads_file_contents(plan.verification_mode):
            found = agnostic_substitute(file_entry, sys_id, plan.db, plan.platform_profiles)
        if not found or not found[0]:
            if not already_packed:
                self.file_status[full_dest] = "missing"
                self.file_reasons[full_dest] = "not found"
            return None
        local_path, agnostic_path = found
        original_name = os.path.basename(local_path)
        dest_name = file_entry.get("name", "")
        if original_name != dest_name and agnostic_path:
            alt_names = [
                entry.get("name", "")
                for entry in plan.db.get("files", {}).values()
                if entry.get("path", "").startswith(agnostic_path)
                and entry.get("name", "") and entry.get("name", "") != original_name
            ]
            readme_text = _build_agnostic_rename_readme(dest_name, original_name, alt_names)
            readme_name = f"RENAMED_{dest_name}.txt"
            readme_full = f"{plan.base_dest}/{readme_name}" if plan.base_dest else readme_name
            if readme_full not in self.placed.destinations:
                _write_generated_member(self.zf, self._flat(readme_full), readme_text)
                self.placed.destinations.add(readme_full)
        return local_path

    def _settle_declared(
        self,
        file_entry: dict,
        full_dest: str,
        dest: str,
        local_path: str | None,
        status: str,
        already_packed: bool,
    ) -> str | None:
        """The copy a declaration ships once judged, or None when refused."""
        plan = self.plan
        # The verdict the install manifest reads too: a member missing
        # from a zipped_file archive, or a hash the frontend rejects.
        status, refusal = self.verdict(file_entry, local_path, status)
        if refusal:
            # An earlier declaration of this path shipped a file this
            # one refuses: it is in the pack, untested as verify
            # counts it, not excluded.
            self.file_status[full_dest] = "untested" if already_packed else "excluded"
            self.file_reasons[full_dest] = refusal
            return None
        if not hash_mismatch_excludes_file(plan.verification_mode) and (
            status == "hash_mismatch" and local_path
        ):
            # Existence platforms accept any file at the declared path:
            # their code never reads the bytes. An upstream hash that
            # contradicts a local dump is reported, not acted on.
            self.file_reasons.setdefault(
                full_dest,
                existence_discrepancy(file_entry, local_path, plan.platform_display),
            )
        if self.file_status.get(full_dest) == "missing":
            # An earlier declaration of this path found nothing, and this
            # one fills it, as verify counts it.
            del self.file_status[full_dest]
            self.file_reasons.pop(full_dest, None)
        self.file_status.setdefault(full_dest, "ok")

        # Emulator-level validation: informational only for platform packs.
        # Platform verification (existence/md5) is the authority for pack status.
        # Emulator checks are supplementary: logged but don't downgrade.
        # When a discrepancy is found, try to find a file satisfying both.
        if self.file_status.get(full_dest) == "ok":
            local_path, disagreement = self.judge(file_entry, local_path, dest)
            if disagreement:
                self.file_reasons.setdefault(
                    full_dest, f"{plan.platform_display} says OK but {disagreement}"
                )
        return local_path

    def _ship_declared(
        self, file_entry: dict, full_dest: str, local_path: str, already_packed: bool,
    ) -> None:
        within = self.plan.opts.within
        if already_packed:
            if full_dest not in self.placed.destinations:
                self.case_twins.append(self._flat(full_dest))
            return
        if within is not None and not _same_bytes(local_path, within.get(self._flat(full_dest))):
            # The full pack holds another system's file here.
            return
        if self.file_status.get(full_dest) == "excluded":
            # An earlier declaration refused the file this one ships.
            self.file_status[full_dest] = "untested"
        self.placed.take(full_dest)

        extract = file_entry.get("extract", False)
        flat_dest = self._flat(full_dest)
        if extract and local_path.endswith(".zip"):
            _extract_zip_to_archive(local_path, flat_dest, self.zf)
        elif local_path.endswith(".zip"):
            _add_zip_to_pack(local_path, flat_dest, self.zf, file_entry)
        else:
            _add_pack_member(self.zf, local_path, flat_dest)
        self.total_files += 1

    def _region_dropped(self, fe: dict) -> bool:
        drops = self.plan.region_drops
        return bool(drops) and extra_region_key(fe, declared_root(self.plan.config)) in drops

    def _spares(self, files: list[dict]) -> set[int]:
        if not self.plan.opts.required_only:
            return set()
        return core_file_spares(files, self._region_dropped)

    def _core_files(self) -> list[dict]:
        plan, opts = self.plan, self.plan.opts
        if opts.source == "platform":
            return []
        if opts.precomputed_extras is not None:
            return opts.precomputed_extras
        if opts.system_filter:
            # The systems asked for, with what their cores need: the split
            # packs get exactly this, and a full pack of one system had none.
            return _extras_for_systems(
                _collect_emulator_extras(
                    plan.config, opts.emulators_dir, plan.db, set(), plan.base_dest,
                    plan.emu_profiles, target_cores=opts.target_cores,
                    include_all=(opts.source == "truth"), undeclared=plan.undeclared,
                ),
                opts.system_filter,
            )
        return _collect_emulator_extras(
            plan.config,
            opts.emulators_dir,
            plan.db,
            self.placed.destinations,
            plan.base_dest,
            plan.emu_profiles,
            target_cores=opts.target_cores,
            include_all=(opts.source == "truth"),
            undeclared=plan.undeclared,
        )

    def _pack_core_files(self) -> None:
        core_files = self._core_files()
        spares = self._spares(core_files)
        for fe in core_files:
            if self.plan.opts.required_only and (fe.get("required") is False or id(fe) in spares):
                continue
            self._pack_core_file(fe)

    def _pack_core_file(self, fe: dict) -> None:
        plan = self.plan
        dest = sanitize_pack_path(fe.get("destination", fe["name"]))
        if self._region_dropped(fe):
            return
        if not dest:
            return
        if fe.get("root") in OUTER_ROOTS:
            # Read below the roms directory or in an emulator folder: the
            # pack is extracted into the BIOS folder and cannot reach
            # them, the installer places these files.
            return
        # Core extras: _collect_emulator_extras already adjusted
        # destinations for slug-based platforms.  Apply the effective
        # prefix (base_dest, or inferred from YAML when base_dest is
        # empty, as RetroDECK infers "bios"). A file read below the save
        # directory goes to the pack's save folder instead.
        full_dest = extra_full_destination(
            fe, _detect_extras_prefix(plan.config, plan.base_dest)
        )
        if not full_dest:
            return
        # Taken, a case twin on a case-insensitive filesystem, or a
        # file/directory conflict (SGB1.sfc vs SGB1.sfc/): verify replays
        # the same rule (packextras.hidden_extras).
        block = self.placed.block(full_dest)
        if block:
            if block == "case_twin" and self.resolve_extra(fe, dest)[0]:
                self.case_twins.append(self._flat(full_dest))
            return

        # The emulator's own check picks the copy, as for a declared file
        # and in the emulator pack: the name led RetroArch's GC/dsp_rom.bin
        # to Dolphin's obsolete v0.3.1 free ROM, beside Nintendo's coef
        # ROM, a pair Dolphin warns about at every start.
        local_path, status, disagreement = self.resolve_extra(fe, dest)
        if not local_path:
            return
        self._note_core_discrepancy(fe, full_dest, local_path, status, disagreement)

        flat_dest = self._flat(full_dest)
        within = plan.opts.within
        if within is not None and not _same_bytes(local_path, within.get(flat_dest)):
            return
        if local_path.endswith(".zip"):
            _add_zip_to_pack(local_path, flat_dest, self.zf, fe)
        else:
            _add_pack_member(self.zf, local_path, flat_dest)
        if self.file_status.get(full_dest) in ("missing", "excluded"):
            self._core_fills_declaration(fe, full_dest)
        self.placed.take(full_dest)
        self.core_count += 1
        if fe.get("root") == "save":
            self.save_count += 1
        self.total_files += 1

    def _note_core_discrepancy(
        self, fe: dict, full_dest: str, local_path: str, status: str, disagreement: str,
    ) -> None:
        if disagreement:
            self.core_discrepancies.append(f"{full_dest}: {disagreement}")
        if status == "hash_mismatch" and not _matches_an_alternative(
            fe, local_path, self.plan.emu_profiles or {}
        ):
            # The core's declared hash comes from its source, the local dump
            # is what the collection holds. Shipping it keeps the emulator
            # working when the code never reads the hash, and the divergence is
            # reported so it can be resolved at the profile or the dump.
            # file_status tracks platform declarations only, so the report
            # goes to its own list and never moves the pack's own count.
            self.core_discrepancies.append(
                f"{full_dest}: declared hash of "
                f"{fe.get('source_profile') or fe.get('source_emulator', 'core profile')}"
                " does not match the packed copy"
            )

    def _core_fills_declaration(self, fe: dict, full_dest: str) -> None:
        source_name = fe.get("source_profile") or fe.get(
            "source_emulator", "core profile"
        )
        if reads_file_contents(self.plan.verification_mode):
            # The frontend hashes what sits at the path, and the core's
            # copy is not the hash it declares: the file ships for the
            # core, the platform's own check still fails, as verify says.
            self.file_reasons[full_dest] = (
                "platform-declared hash unavailable; "
                f"packed the validated {source_name} requirement, "
                "which the platform check does not accept"
            )
        else:
            # An existence frontend is satisfied by any file at the path.
            self.file_status[full_dest] = "ok"
            self.file_reasons.pop(full_dest, None)

    def _pack_trees(self) -> None:
        plan, opts = self.plan, self.plan.opts
        # The trees the cores read follow them as their extras do: by the
        # systems asked for, and those of no system in the part of their own.
        core_trees = (
            [] if opts.source == "platform"
            else core_data_trees(
                plan.config, plan.emu_profiles, plan.platform_name, opts.data_registry,
                opts.target_cores,
            )
        )
        if opts.extras_only:
            owned = list(platform_scope_systems(plan.config, plan.emu_profiles, opts.target_cores))
            core_trees = [t for t in core_trees if not _extras_for_systems([t], owned)]
        elif opts.system_filter:
            core_trees = _extras_for_systems(core_trees, opts.system_filter)
        # Counted apart: the trees a core reads are not on the platform's
        # list. MyMinUI declares nothing and its line read "6944 baseline".
        self.total_files += self._pack_data_directories(plan.pack_systems, ())
        self.tree_count = self._pack_data_directories({}, core_trees)
        self.total_files += self.tree_count

    def _pack_data_directories(self, pack_systems: dict, core_trees: Iterable[dict]) -> int:
        """Add the data directories to the pack. Returns how many files went in."""
        plan = self.plan
        required_only = plan.opts.required_only
        seen_parents = self.placed.parents
        added = 0
        for src, full in _data_directory_members(
            pack_systems, plan.opts.data_registry, plan.platform_name, plan.base_dest,
            self.placed.fold, self.placed.destinations, self.placed.lower,
            seen_parents, required_only=required_only,
            core_trees=core_trees,
        ):
            _add_pack_member(self.zf, src, self._flat(full))
            if isinstance(self.zf, PackRecord):
                self.zf.trees.append(self._flat(full))
            added += 1
        return added

    def _unfolded_twins(self) -> None:
        # The spellings a folded platform counts as declared never reach
        # the extras: collected as the filesystem that keeps case sees
        # them, as the manifest's case_variants are (Mesen-CE's bios.col
        # beside the declared BIOS.col).
        plan, opts = self.plan, self.plan.opts
        unfolded = _collect_emulator_extras(
            {**plan.config, "case_insensitive_fs": False}, opts.emulators_dir, plan.db, set(),
            plan.base_dest, plan.emu_profiles, target_cores=opts.target_cores,
            include_all=(opts.source == "truth"),
        )
        if opts.system_filter:
            unfolded = _extras_for_systems(unfolded, opts.system_filter)
        prefix = _detect_extras_prefix(plan.config, plan.base_dest)
        unfolded_spares = self._spares(unfolded)
        for fe in unfolded:
            if opts.required_only and (fe.get("required") is False or id(fe) in unfolded_spares):
                continue
            if self._region_dropped(fe):
                continue
            full = extra_full_destination(fe, prefix)
            if (
                full and full not in self.placed.destinations and full.lower() in self.placed.lower
                and self.resolve_extra(
                    fe, sanitize_pack_path(fe.get("destination", fe["name"]))
                )[0]
            ):
                self.case_twins.append(self._flat(full))

    def _write_readme(self) -> None:
        # README.txt for users: personalized step-by-step per platform
        plan, opts = self.plan, self.plan.opts
        registry = _platform_registry(plan.platforms_dir).get(plan.platform_name, {})
        install = registry.get("install", {}) or {}
        keeps_case = plan.case_insensitive and any(
            d.get("os") not in CASE_FOLDING_OS for d in install.get("detect", [])
        )
        if keeps_case and opts.source != "platform" and opts.precomputed_extras is None:
            self._unfolded_twins()
        save_count = self.save_count
        readme_text = _build_readme(
            plan.platform_name, plan.platform_display, plan.base_dest, self.total_files,
            len(plan.pack_systems),
            source=opts.source,
            contributors=registry.get("contributed_by", []),
            regions=opts.regions,
            fallback_systems=plan.region_fallbacks,
            one_per_slot=opts.one_per_slot,
            undecidable_slots=plan.slot_undecidable,
            narrowings=plan.narrowings,
            system_filter=opts.system_filter,
            detect=install.get("detect", []),
            standalone_copies=install.get("standalone_copies", []),
            launch_folders=len(plan.config.get("core_system_dirs") or {}),
            save_folder=(save_layout(plan.config).in_pack if save_count else ""),
            save_where=(
                save_place(
                    str(registry.get("extract_to") or ""),
                    save_layout(plan.config).folder, plan.base_dest,
                ) if save_count else ""
            ),
            save_by_system=bool(save_count and save_layout(plan.config).by_system),
            case_twins=(
                _case_twin_pairs(
                    self.case_twins, self.placed.destinations, plan.base_dest, opts.flatten
                )
                if keeps_case else []
            ),
        )
        _write_generated_member(self.zf, "README.txt", readme_text)
        for marker in pack_markers(plan.platform_name, opts.target_name, plan.platforms_dir):
            _write_generated_member(
                self.zf,
                self._flat(f"{plan.base_dest}/{marker}" if plan.base_dest else marker),
                "",
            )

    def report(self) -> None:
        plan, opts = self.plan, self.plan.opts
        _report_pack_counts(
            plan.zip_path, self.file_status, self.total_files, self.core_count, opts.source,
            plan.verification_mode, tree_count=self.tree_count,
        )
        if plan.cut is not None:
            _report_left_out(
                plan.cut,
                systems=set(plan.pack_systems) if opts.source != "truth" else set(),
                cores=opts.source != "platform" and opts.precomputed_extras is None,
            )
        for key, reason in sorted(self.file_reasons.items()):
            label = _STATUS_LABELS.get(self.file_status.get(key, ""), "DISCREPANCY")
            print(f"  {label}: {key}: {reason}")
        for note in sorted(self.core_discrepancies):
            print(f"  DISCREPANCY: {note}")


def _platform_registry(platforms_dir: str) -> dict:
    """The platforms of _registry.yml, or nothing when the file is absent."""
    registry_path = Path(platforms_dir) / "_registry.yml"
    if not registry_path.exists():
        return {}
    with open(registry_path) as f:
        return (yaml_load(f) or {}).get("platforms", {})


def generate_pack(
    platform_name: str,
    platforms_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    **options: Unpack[PackOptions],
) -> str | None:
    """Generate a ZIP pack for a platform.

    ``no_game_data`` leaves out the platform's entries categorized as game
    data and the cores' ``category: game_data`` files, and names each one.

    ``pack_name`` replaces the derived file name: a split part is named after
    its group, and a name built from every system of a hundred-system group
    is longer than a file name can be.

    ``record`` builds the pack in memory (PackRecord): no archive is written,
    no external file fetched, and the paths are kept on it.

    ``within`` is the full pack's PackRecord.sources, given to a split part:
    a declared file or core extra is written only where the full pack writes
    the same bytes. A part sees neither the other systems' declarations nor
    their extras, so a path the full pack settles (a file/directory conflict,
    a case twin, a path another system's file takes) was written again.

    Returns the path to the generated ZIP, or None on failure.
    """
    _reject_unknown("generate_pack", options, PackOptions.__optional_keys__)
    opts = _PackSettings(**options)
    plan = _plan_platform_pack(platform_name, platforms_dir, db, bios_dir, output_dir, opts)
    if plan is None:
        return None

    def resolve(file_entry: dict, full_dest: str) -> tuple[str | None, str]:
        return resolve_declaration(
            file_entry,
            db,
            bios_dir,
            plan.zip_contents,
            opts.data_registry,
            plan.slot_overrides.get(full_dest),
            offline=opts.offline,
        )

    def verdict(file_entry: dict, local_path: str | None, status: str) -> tuple[str, str | None]:
        return baseline_verdict(
            file_entry, local_path, status, plan.verification_mode,
            plan.config.get("hash_rule", ""),
        )

    def judge(file_entry: dict, local_path: str | None, dest: str) -> tuple[str | None, str | None]:
        return validated_choice(
            file_entry, local_path, db, plan.validation_index, bios_dir,
            digest_algorithm(plan.verification_mode), dest, plan.validation_owners,
        )

    extra_resolver = ExtraResolver(
        db, bios_dir, plan.zip_contents, opts.data_registry, plan.validation_index,
        plan.validation_owners, opts.offline, profiles=plan.emu_profiles,
    )

    def resolve_extra(fe: dict, dest: str) -> tuple[str | None, str, str]:
        return extra_resolver.resolve(fe, dest)

    with (
        contextlib.nullcontext(opts.record) if opts.record is not None
        else _writing_pack(plan.zip_path)
    ) as zf:
        build = _PlatformPackBuild(plan, zf, resolve, verdict, judge, resolve_extra)
        build.run()
    build.report()
    return plan.zip_path
