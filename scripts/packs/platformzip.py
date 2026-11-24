"""One platform pack's ZIP written from its plan."""

from __future__ import annotations

import os
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from core.hashing import compute_hashes
from core.paths import declared_destination
from core.ziptools import is_archive_path
from model.alternatives import core_file_spares
from model.declarations import OUTER_ROOTS, declared_root
from model.profiles import installed_data_refs_in
from model.registry import load_platform_registry
from packs.archive import (
    CASE_FOLDING_OS,
    PackRecord,
    Placed,
    add_pack_member,
    add_zip_to_pack,
    extract_zip_to_archive,
    instructions_note,
    same_bytes,
    write_generated_member,
)
from packs.datatrees import core_data_trees, data_directory_members, pack_markers
from packs.declsettle import DeclarationJudge, Settlement
from packs.extras import collect_emulator_extras
from packs.extraplace import detect_extras_prefix, extra_full_destination, extra_region_key
from packs.extraregions import extras_for_systems as _extras_for_systems
from packs.packplan import PlatformPlan
from packs.paths import flat_arcname, platform_destination, save_layout
from packs.readme import build_agnostic_rename_readme, build_readme, save_place
from resolve import packfiles as packresolve
from resolve.cores import platform_scope_systems
from resolve.gamedata import GameDataCut
from resolve.nativemode import hash_mismatch_excludes_file, reads_file_contents
from resolve.packfiles import download_external, resolve_file
from resolve.validation import parse_validation
from resolve.acceptance import existence_discrepancy, extra_alternatives


def _case_twin_pairs(
    twins: list[str], seen_destinations: set[str], base_dest: str, flatten: bool,
) -> list[tuple[str, str]]:
    """Each spelling left out, with the spelling the pack holds."""
    held = {
        flat_arcname(dest, base_dest, flatten).lower(): flat_arcname(dest, base_dest, flatten)
        for dest in seen_destinations
    }
    return sorted({(twin, held[twin.lower()]) for twin in twins if twin.lower() in held})


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
    if any(not parse_validation(entry.get("validation")) for entry in siblings):
        return True
    actual = compute_hashes(local_path, frozenset({"sha1", "md5", "crc32"}))
    for entry in siblings:
        for algorithm in ("sha1", "md5", "crc32"):
            declared = entry.get(algorithm)
            values = declared if isinstance(declared, list) else [declared]
            if any(v and str(v).lower() == actual.get(algorithm, "") for v in values):
                return True
    return False


def left_out_lines(cut: GameDataCut, systems: set[str], cores: bool) -> list[str]:
    """The game data a --no-game-data build left out, and why, one line each.

    ``systems`` limits the platform layer to the systems this pack covers,
    and ``cores`` says whether this pack collected the core files itself:
    a split part does not, its run names them once.
    """
    kept = [
        item for item in cut.left_out
        if (item.layer == "platform" and item.system in systems)
        or (item.layer == "core" and cores)
    ]
    return GameDataCut(cut.config, cut.profiles, kept).report_lines()


@dataclass
class PlatformPackOutcome:
    """What one platform pack build came to, as print_platform_pack reports it.

    ``refusal`` is set, and ``zip_path`` None, when the systems asked for
    leave nothing to build.
    """

    zip_path: str | None
    refusal: str = ""
    source: str = "full"
    verification_mode: str = ""
    total_files: int = 0
    core_count: int = 0
    tree_count: int = 0
    file_status: dict[str, str] = field(default_factory=dict)
    file_reasons: dict[str, str] = field(default_factory=dict)
    core_discrepancies: list[str] = field(default_factory=list)
    slot_undecidable: list[str] = field(default_factory=list)
    uncached: list[tuple[str, str]] = field(default_factory=list)
    left_out: list[str] = field(default_factory=list)


@dataclass
class PlatformPackBuild:
    """One platform pack being written: its members and what each slot came to.

    A platform file is settled by the DeclarationJudge the install manifest
    reads too, and a core extra by the lookup build_platform_pack binds.
    """

    plan: PlatformPlan
    zf: zipfile.ZipFile | PackRecord
    declarations: DeclarationJudge
    resolve_extra: Callable[[dict, str], tuple[str | None, str, str]]
    placed: Placed = field(init=False)
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
    # (registry key, cache path) of each data directory the cache lacks.
    uncached: list[tuple[str, str]] = field(default_factory=list)
    # The archive path of each member taken from a data directory.
    trees: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.placed = Placed(self.plan.case_insensitive)

    def _flat(self, path: str) -> str:
        return flat_arcname(path, self.plan.base_dest, self.plan.opts.flatten)

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
        conflict_status, refusal = self.declarations.verdict(
            file_entry, conflict_path, conflict_status,
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
        dest, full_dest = platform_destination(file_entry, plan.base_dest)
        if plan.region_drops and dest in plan.region_drops:
            return
        if not dest:
            self._judge_unnamed(sys_id, file_entry)
            return
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

        settled = self.declarations.settle(
            file_entry, sys_id, dest, plan.slot_overrides.get(full_dest),
        )
        if settled.status == "external":
            self._pack_external(file_entry, full_dest)
            return
        if settled.status == "not_found":
            if not already_packed:
                self.file_status[full_dest] = "missing"
                self.file_reasons[full_dest] = "not found"
            return
        if settled.agnostic_dir and settled.resolved:
            self._note_rename(file_entry, settled.resolved, settled.agnostic_dir)
        if self._settle_declared(file_entry, full_dest, settled, already_packed) and settled.path:
            self._ship_declared(file_entry, full_dest, settled.path, already_packed)

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
        elif self.declarations.verdict(file_entry, held, held_status)[1]:
            self.file_status[fkey] = "excluded"
        else:
            self.file_status.setdefault(fkey, "ok")

    def _write_instructions(self, file_entry: dict, full_dest: str) -> None:
        base_dest = self.plan.base_dest
        self.placed.take(full_dest)
        self.file_status.setdefault(full_dest, "ok")
        instr_name, text = instructions_note(file_entry)
        instr_path = (
            f"{base_dest}/{instr_name}" if base_dest else instr_name
        )
        write_generated_member(self.zf, self._flat(instr_path), text)
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
            # Built in memory, nothing is fetched: verify cannot fetch either.
            fetch = (
                download_external(file_entry, tmp_path)
                if self.plan.opts.record is None else None
            )
            if fetch is not None and fetch.fetched:
                extract = file_entry.get("extract", False)
                if extract and tmp_path.endswith(".zip"):
                    extract_zip_to_archive(tmp_path, self._flat(full_dest), self.zf)
                else:
                    add_pack_member(self.zf, tmp_path, self._flat(full_dest))
                self.file_status.setdefault(full_dest, "ok")
                self.total_files += 1
            else:
                self.file_status[full_dest] = "missing"
                self.file_reasons[full_dest] = (
                    fetch.reason if fetch is not None
                    else "external file not fetched for an in-memory build"
                )
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _note_rename(self, file_entry: dict, local_path: str, agnostic_path: str) -> None:
        # A filename-agnostic core's substitute ships under the declared
        # name: a note says which image it is.
        plan = self.plan
        original_name = os.path.basename(local_path)
        dest_name = file_entry.get("name", "")
        if original_name == dest_name:
            return
        alt_names = [
            entry.get("name", "")
            for entry in plan.db.get("files", {}).values()
            if entry.get("path", "").startswith(agnostic_path)
            and entry.get("name", "") and entry.get("name", "") != original_name
        ]
        readme_text = build_agnostic_rename_readme(dest_name, original_name, alt_names)
        readme_name = f"RENAMED_{dest_name}.txt"
        readme_full = f"{plan.base_dest}/{readme_name}" if plan.base_dest else readme_name
        if readme_full not in self.placed.destinations:
            write_generated_member(self.zf, self._flat(readme_full), readme_text)
            self.placed.destinations.add(readme_full)

    def _settle_declared(
        self, file_entry: dict, full_dest: str, settled: Settlement, already_packed: bool,
    ) -> bool:
        """Record what a declaration came to, and whether its copy ships."""
        plan = self.plan
        if settled.refusal:
            # An earlier declaration of this path shipped a file this
            # one refuses: it is in the pack, untested as verify
            # counts it, not excluded.
            self.file_status[full_dest] = "untested" if already_packed else "excluded"
            self.file_reasons[full_dest] = settled.refusal
            return False
        if not hash_mismatch_excludes_file(plan.verification_mode) and (
            settled.status == "hash_mismatch" and settled.resolved
        ):
            # Existence platforms accept any file at the declared path:
            # their code never reads the bytes. An upstream hash that
            # contradicts a local dump is reported, not acted on.
            self.file_reasons.setdefault(
                full_dest,
                existence_discrepancy(file_entry, settled.resolved, plan.platform_display),
            )
        if self.file_status.get(full_dest) == "missing":
            # An earlier declaration of this path found nothing, and this
            # one fills it, as verify counts it.
            del self.file_status[full_dest]
            self.file_reasons.pop(full_dest, None)
        self.file_status.setdefault(full_dest, "ok")

        # Emulator-level validation: informational only for platform packs.
        # Platform verification (existence/md5) is the authority for pack
        # status. The copy the cores chose ships whatever an earlier
        # declaration of this path came to, as the installer places it.
        if settled.disagreement and self.file_status.get(full_dest) == "ok":
            self.file_reasons.setdefault(
                full_dest, f"{plan.platform_display} says OK but {settled.disagreement}"
            )
        return True

    def _ship_declared(
        self, file_entry: dict, full_dest: str, local_path: str, already_packed: bool,
    ) -> None:
        within = self.plan.opts.within
        if already_packed:
            if full_dest not in self.placed.destinations:
                self.case_twins.append(self._flat(full_dest))
            return
        if within is not None and not same_bytes(local_path, within.get(self._flat(full_dest))):
            # The full pack holds another system's file here.
            return
        if self.file_status.get(full_dest) == "excluded":
            # An earlier declaration refused the file this one ships.
            self.file_status[full_dest] = "untested"
        self.placed.take(full_dest)

        extract = file_entry.get("extract", False)
        flat_dest = self._flat(full_dest)
        if extract and is_archive_path(local_path):
            extract_zip_to_archive(local_path, flat_dest, self.zf)
        elif is_archive_path(local_path):
            add_zip_to_pack(local_path, flat_dest, self.zf, file_entry)
        else:
            add_pack_member(self.zf, local_path, flat_dest)
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
                collect_emulator_extras(
                    plan.config, opts.emulators_dir, plan.db, set(), plan.base_dest,
                    plan.emu_profiles, target_cores=opts.target_cores,
                    include_all=(opts.source == "truth"), undeclared=plan.undeclared,
                ),
                opts.system_filter,
            )
        return collect_emulator_extras(
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
        dest = declared_destination(fe)
        if self._region_dropped(fe):
            return
        if not dest:
            return
        if fe.get("root") in OUTER_ROOTS:
            # Read below the roms directory or in an emulator folder: the
            # pack is extracted into the BIOS folder and cannot reach
            # them, the installer places these files.
            return
        # Core extras: collect_emulator_extras already adjusted
        # destinations for slug-based platforms.  Apply the effective
        # prefix (base_dest, or inferred from YAML when base_dest is
        # empty, as RetroDECK infers "bios"). A file read below the save
        # directory goes to the pack's save folder instead.
        full_dest = extra_full_destination(
            fe, detect_extras_prefix(plan.config, plan.base_dest)
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
        if within is not None and not same_bytes(local_path, within.get(flat_dest)):
            return
        if is_archive_path(local_path):
            add_zip_to_pack(local_path, flat_dest, self.zf, fe)
        else:
            add_pack_member(self.zf, local_path, flat_dest)
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
        added = 0
        uncached: list[tuple[str, str]] = []
        for src, full in data_directory_members(
            pack_systems, plan.opts.data_registry, plan.platform_name, plan.base_dest,
            self.placed, required_only=required_only,
            core_trees=core_trees, uncached_out=uncached,
            installed=installed_data_refs_in(plan.platform_name, plan.emu_profiles or {}),
        ):
            arcname = self._flat(full)
            # The installer writes a data tree member without the bit.
            add_pack_member(self.zf, src, arcname, executable=False)
            self.trees.append(arcname)
            if isinstance(self.zf, PackRecord):
                self.zf.trees.append(arcname)
            added += 1
        self.uncached.extend(uncached)
        if plan.opts.uncached_out is not None:
            plan.opts.uncached_out.update(ref_key for ref_key, _path in uncached)
        return added

    def _unfolded_twins(self) -> None:
        # The spellings a folded platform counts as declared never reach
        # the extras: collected as the filesystem that keeps case sees
        # them, as the manifest's case_variants are (Mesen-CE's bios.col
        # beside the declared BIOS.col).
        plan, opts = self.plan, self.plan.opts
        unfolded = collect_emulator_extras(
            {**plan.config, "case_insensitive_fs": False}, opts.emulators_dir, plan.db, set(),
            plan.base_dest, plan.emu_profiles, target_cores=opts.target_cores,
            include_all=(opts.source == "truth"),
        )
        if opts.system_filter:
            unfolded = _extras_for_systems(unfolded, opts.system_filter)
        prefix = detect_extras_prefix(plan.config, plan.base_dest)
        unfolded_spares = self._spares(unfolded)
        for fe in unfolded:
            if opts.required_only and (fe.get("required") is False or id(fe) in unfolded_spares):
                continue
            if self._region_dropped(fe):
                continue
            full = extra_full_destination(fe, prefix)
            if (
                full and self.placed.block(full) == "case_twin"
                and self.resolve_extra(fe, declared_destination(fe))[0]
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
        readme_text = build_readme(
            plan.platform_name, plan.platform_display, plan.base_dest, self.total_files,
            len(plan.pack_systems),
            platforms_dir=plan.platforms_dir,
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
        write_generated_member(self.zf, "README.txt", readme_text)
        for marker in pack_markers(plan.platform_name, opts.target_name, plan.platforms_dir):
            write_generated_member(
                self.zf,
                self._flat(f"{plan.base_dest}/{marker}" if plan.base_dest else marker),
                "",
            )

    def outcome(self) -> PlatformPackOutcome:
        plan, opts = self.plan, self.plan.opts
        return PlatformPackOutcome(
            zip_path=plan.zip_path,
            source=opts.source,
            verification_mode=plan.verification_mode,
            total_files=self.total_files,
            core_count=self.core_count,
            tree_count=self.tree_count,
            file_status=self.file_status,
            file_reasons=self.file_reasons,
            core_discrepancies=self.core_discrepancies,
            slot_undecidable=plan.slot_undecidable,
            uncached=self.uncached,
            left_out=(
                left_out_lines(
                    plan.cut,
                    systems=set(plan.pack_systems) if opts.source != "truth" else set(),
                    cores=opts.source != "platform" and opts.precomputed_extras is None,
                )
                if plan.cut is not None else []
            ),
        )


def _platform_registry(platforms_dir: str) -> dict:
    """The platforms of _registry.yml, or nothing when the file is absent."""
    return load_platform_registry(platforms_dir)
