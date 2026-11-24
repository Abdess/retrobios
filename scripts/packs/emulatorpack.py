"""Packs for one emulator or one system."""

from __future__ import annotations

from pathlib import Path
from model.dbpaths import collection_root
import contextlib
import functools
import os
import shutil
import sys
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from core.paths import REPO_ROOT
from core.ziptools import build_zip_contents_index, is_archive_path
from model.alternatives import settle_sets, slot_set_keys
from model.profiles import (
    ProfileSelectionError,
    load_emulator_profiles,
    no_profile_for_systems,
    profiles_for_systems,
    select_emulator_profiles,
)
from model.registry import load_data_dir_registry
from model.releaserecord import PACK_SUFFIX
from packs.archive import (
    PackRecord,
    Placed,
    add_pack_member,
    add_zip_to_pack,
    instructions_note,
    same_bytes,
    write_generated_member,
    writing_pack,
)
from packs.datatrees import carried_trees, pack_data_tree
from packs.emulatorentries import EmulatorSelection, emulator_pack_entries
from packs.extras import emulator_region_drops
from packs.naming import (
    MAX_PACK_NAME_BYTES, bounded_join, file_name_part, pack_narrowings, system_display_name,
)
from resolve import packfiles as packresolve
from resolve.packfiles import download_external, resolve_file
from resolve.validation import (
    build_validation_index,
    validated_choice,
    with_archive_members,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack


if TYPE_CHECKING:
    # What a destination came to: its entries, whether it was filled, and the
    # report to make if no other member of its set fills it.
    _Outcome = tuple[list[dict], bool, "Callable[[], None] | None"]


# Emulator/system mode pack generation


class EmulatorPackOptions(TypedDict, total=False):
    """The keyword options of generate_emulator_pack."""

    zip_contents: dict | None
    offline: bool | None
    platforms_dir: str | None
    pack_name: str | None
    system_ids: list[str] | None
    final_dir: str | None
    record: PackRecord | None
    progress: Callable[[str], None] | None


@dataclass
class _EmulatorPackBuild:
    """One emulator pack being written, and what each destination came to."""

    db: dict
    bios_dir: str
    standalone: bool
    required_only: bool
    zip_contents: dict
    data_registry: dict
    validation_index: dict
    region_drops: set[str]
    all_profiles: dict
    zf: zipfile.ZipFile | PackRecord
    offline: bool | None = None
    system_ids: list[str] | None = None
    record: PackRecord | None = None
    progress: Callable[[str], None] = lambda _line: None
    total_files: int = 0
    data_files: int = 0
    missing_files: list[str] = field(default_factory=list)
    rejected_files: list[str] = field(default_factory=list)
    discrepancies: list[str] = field(default_factory=list)
    unsourceable_files: list[str] = field(default_factory=list)
    instruction_files: list[str] = field(default_factory=list)
    placed: Placed = field(default_factory=lambda: Placed(True))
    seen_hashes: set[str] = field(default_factory=set)  # SHA1 dedup for same file, different path
    # Loose file packed at each folded destination, to tell a profile asking
    # for the same file there from one asking for other bytes.
    packed_at: dict[str, str] = field(default_factory=dict)
    # A destination is missing once, however many profiles ask for it:
    # verify --emulator counts by destination.
    missing_at: set[str] = field(default_factory=set)
    data_dir_notices: list[str] = field(default_factory=list)

    def report_missing(self, name: str, destination: str) -> None:
        if destination not in self.missing_at:
            self.missing_at.add(destination)
            self.missing_files.append(name)

    def _add(self, local_path: str, dest: str, fe: dict | None) -> None:
        """Write a loose file or an archive at dest and count it."""
        if fe is not None and is_archive_path(local_path):
            add_zip_to_pack(local_path, dest, self.zf, fe)
        else:
            add_pack_member(self.zf, local_path, dest)
        self.placed.take(dest)
        self.total_files += 1
        if self.record is not None:
            self.record.files.append(dest)

    def pack_profile(self, emu_name: str, profile: dict) -> None:
        carried = emulator_pack_entries(emu_name, profile, EmulatorSelection(
            self.db, self.standalone, self.all_profiles, self.validation_index,
            self.zip_contents, self.data_registry, system_ids=self.system_ids,
            required_only=self.required_only, region_drops=self.region_drops,
        ))
        files = carried.entries
        if not files and not profile.get("data_directories"):
            self.progress(f"  No files needed for {profile.get('emulator', emu_name)}")

        # What each destination came to, settled by set once the
        # profile is read: a member another member fills is not missing,
        # and a set nobody holds is reported once (alternatives.py). An
        # archive unit is a member like a loose file.
        outcomes: list[_Outcome] = [
            self._pack_archive(own_entry, archive_name, archive_dest)
            for archive_name, own_entry, archive_dest in sorted(
                carried.archives, key=lambda unit: unit[0]
            )
        ]
        for dest, alternatives in carried.slots.items():
            outcome = self._pack_slot(emu_name, files, dest, alternatives)
            if outcome is not None:
                outcomes.append(outcome)

        excused, _standing = settle_sets([
            (slot_set_keys(emu_name, entries), entries[0], fills)
            for entries, fills, _report in outcomes
        ])
        for position, (_entries, _fills, report) in enumerate(outcomes):
            if report is not None and position not in excused:
                report()
        self._pack_trees(profile)

    def _pack_archive(self, own_entry: dict, archive_name: str, archive_dest: str) -> _Outcome:
        local_path, status = resolve_file(
            own_entry,
            self.db,
            self.bios_dir,
            self.zip_contents,
            data_dir_registry=self.data_registry,
            offline=self.offline,
        )
        taken = self.placed.holds(archive_dest)
        if taken or self.placed.conflicts(archive_dest):
            # Another profile's file holds this path. The same archive
            # asked for twice is served. Anything else leaves this
            # profile without its archive, which used to pass in
            # silence: a neocdz.zip lacking 000-lo.lo shipped as the
            # one the second core needs.
            if not (taken and local_path and same_bytes(
                local_path, self.packed_at.get(archive_dest.lower())
            )):
                return ([own_entry], False, functools.partial(
                    self.report_missing, archive_name, archive_dest
                ))
            return ([own_entry], True, None)
        if local_path and status not in ("not_found",):
            self._add(local_path, archive_dest, own_entry)
            self.packed_at[archive_dest.lower()] = local_path
            return ([own_entry], True, None)
        return ([own_entry], False, functools.partial(
            self.report_missing, archive_name, archive_dest
        ))

    def _write_instructions(self, provided: dict, dest: str) -> None:
        # Instructions, not a file: written beside the slot the
        # user fills, and counted apart from what the pack holds.
        self.placed.take(dest)
        instr_name, text = instructions_note(provided)
        folder = dest.rsplit("/", 1)[0] + "/" if "/" in dest else ""
        write_generated_member(self.zf, f"{folder}{instr_name}", text)
        # verify --emulator counts an unsourceable one as such.
        (self.unsourceable_files if provided.get("unsourceable") else self.instruction_files).append(
            provided["name"]
        )

    def _choose(
        self, emu_name: str, files: list[dict], alternatives: list[dict],
    ) -> tuple[tuple[dict, str, str | None] | None, str | None, str | None]:
        """The alternative the core accepts, with the refusal of the first
        one it turned away and that copy."""
        fallback: tuple[dict, str, str | None] | None = None
        refusal: str | None = None
        refused_path: str | None = None
        for fe in alternatives:
            local_path, status = resolve_file(
                {**with_archive_members(fe, files), "source_profile": emu_name},
                self.db,
                self.bios_dir,
                self.zip_contents,
                dest_hint=fe.get("path", ""),
                data_dir_registry=self.data_registry,
                offline=self.offline,
            )
            if status == "external":
                return (fe, "", "external"), refusal, refused_path
            if status in ("not_found", "user_provided") or not local_path:
                continue
            # The file verify --emulator credits is the one shipped:
            # a dump the core's own check rejects gives way to a held
            # one it accepts (azahar's otp.bin, dolphin's dsp_rom.bin).
            better, disagreement = validated_choice(
                fe, local_path, self.db, self.validation_index, self.bios_dir, None,
                emulators={emu_name},
            )
            if disagreement:
                reason = disagreement.split(" says ", 1)[-1]
                refusal = refusal or f"{fe['name']}: {reason}"
                refused_path = refused_path or local_path
                continue
            if better != local_path:
                return (fe, better, None), refusal, refused_path
            if status == "hash_mismatch":
                # Not a check the core runs, so the file still serves,
                # but it is not the dump the profile documents.
                fallback = fallback or (fe, local_path, "mismatch")
                continue
            return (fe, local_path, None), refusal, refused_path
        return fallback, refusal, refused_path

    def _pack_slot(
        self, emu_name: str, files: list[dict], dest: str, alternatives: list[dict],
    ) -> _Outcome | None:
        # Name order, first file wins, case folded: verify replays
        # the rule and reports a later profile's file as missing.
        block = self.placed.block(dest)

        provided = next(
            (fe for fe in alternatives if fe.get("storage") == "user_provided"),
            None,
        )
        if provided is not None:
            if not block:
                self._write_instructions(provided, dest)
            return None

        chosen, refusal, refused_path = self._choose(emu_name, files, alternatives)
        if block:
            held = (
                chosen[1] if chosen is not None and chosen[2] != "external"
                else None if chosen is not None else refused_path
            )
            if chosen is not None or held is not None:
                if block == "taken" and held and same_bytes(
                    held, self.packed_at.get(dest.lower())
                ):
                    # The file already at this path, asked for twice.
                    return (alternatives, True, None)
                return (alternatives, False, functools.partial(
                    self.report_missing, alternatives[0]["name"], dest
                ))

        if chosen is None:
            return self._unfilled(alternatives, dest, refusal)
        fe, local_path, how = chosen
        if how == "external":
            return self._pack_external(fe, dest, alternatives)
        if how == "mismatch":
            self.discrepancies.append(
                f"{fe['name']}: not the dump the {emu_name} profile declares"
            )

        # SHA1 dedup: skip if same physical file AND same destination
        # (but allow same file to be packed under different destinations,
        # e.g., IPL.bin in GC/USA/ and GC/EUR/ from same source)
        dedup_key_hash = f"{os.path.realpath(local_path)}:{dest}"
        if dedup_key_hash not in self.seen_hashes:
            self.seen_hashes.add(dedup_key_hash)
            self._add(local_path, dest, fe)
            self.packed_at[dest.lower()] = local_path
        return (alternatives, True, None)

    def _unfilled(self, alternatives: list[dict], dest: str, refusal: str | None) -> _Outcome:
        if refusal:
            self.rejected_files.append(refusal)
            return (alternatives, False, None)
        if all(fe.get("unsourceable") for fe in alternatives):
            return (alternatives, False, functools.partial(
                self.unsourceable_files.append, alternatives[0]["name"]
            ))
        return (alternatives, False, functools.partial(
            self.report_missing, alternatives[0]["name"], dest
        ))

    def _pack_external(self, fe: dict, dest: str, alternatives: list[dict]) -> _Outcome:
        file_ext = os.path.splitext(fe["name"])[1] or ""
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=file_ext, dir=packresolve.scratch_dir()
        ) as tmp:
            tmp_path = tmp.name
        try:
            # Built in memory, nothing is fetched: verify --emulator
            # cannot fetch either and reports the file missing.
            if self.record is None:
                fetch = download_external(fe, tmp_path)
                if fetch.fetched:
                    self._add(tmp_path, dest, None)
                    return (alternatives, True, None)
                self.progress(f"    WARNING: {fe['name']}: {fetch.reason}")
            return (alternatives, False, functools.partial(
                self.missing_files.append, fe["name"]
            ))
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _pack_trees(self, profile: dict) -> None:
        # The trees after the files, as in a platform pack: a dump the
        # profile declares wins over the copy a tree bundles at the same
        # path (Dolphin's real dsp_rom.bin over Sys/GC's free one).
        for ref_key, local_cache, dd_dest in carried_trees(
            profile, self.standalone, self.required_only, self.data_registry,
        ):
            if local_cache is None:
                self.data_dir_notices.append(ref_key)
                continue
            self.data_files += pack_data_tree(
                self.zf, local_cache, dd_dest, self.placed, self.packed_at,
            )

    def nothing_needed(self) -> bool:
        return self.total_files + self.data_files == 0 and not (
            self.missing_files or self.rejected_files or self.instruction_files
            or self.unsourceable_files
        )

    def outcome(self, path: str | None, shown: str, display_names: list[str]) -> EmulatorPackOutcome:
        return EmulatorPackOutcome(
            path=path, shown=shown, display_names=display_names,
            total_files=self.total_files, data_files=self.data_files,
            missing=self.missing_files, rejected=self.rejected_files,
            unsourceable=self.unsourceable_files, to_provide=self.instruction_files,
            discrepancies=self.discrepancies,
            data_dir_notices=sorted(set(self.data_dir_notices)),
        )


@dataclass
class EmulatorPackOutcome:
    """What an emulator pack build came to: its archive and what it left out.

    `path` is the archive, "" when no file is needed, None on failure.
    """

    path: str | None
    shown: str = ""
    display_names: list[str] = field(default_factory=list)
    total_files: int = 0
    data_files: int = 0
    missing: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    unsourceable: list[str] = field(default_factory=list)
    to_provide: list[str] = field(default_factory=list)
    discrepancies: list[str] = field(default_factory=list)
    data_dir_notices: list[str] = field(default_factory=list)
    error: str = ""


def print_emulator_pack(outcome: EmulatorPackOutcome) -> str | None:
    """Print what a build came to, and return its archive path."""
    if outcome.error:
        print(outcome.error, file=sys.stderr)
        return outcome.path
    if outcome.path == "":
        # What verify --emulator reports as 0/0 OK: no file is needed, so
        # no pack is written and the run succeeds. Printed with the path,
        # the run named a file it had just removed and exited 1.
        print(f"  {', '.join(outcome.display_names)}: no file needed, no pack written")
        return ""
    # The members of data trees are counted apart: verify --emulator
    # counts the profile's files, and folding 3500 tree members into the
    # same number made the two impossible to compare.
    parts = [f"{outcome.total_files} files packed"]
    if outcome.data_files:
        parts.append(f"{outcome.data_files} from data directories")
    if outcome.missing:
        parts.append(f"{len(outcome.missing)} missing")
    if outcome.rejected:
        parts.append(f"{len(outcome.rejected)} refused by the core")
    if outcome.unsourceable:
        parts.append(f"{len(outcome.unsourceable)} unsourceable")
    if outcome.to_provide:
        parts.append(f"{len(outcome.to_provide)} to provide")
    print(f"  {outcome.shown}: {', '.join(parts)}")
    for name in outcome.missing:
        print(f"  MISSING: {name}")
    for name in outcome.unsourceable:
        print(f"  UNSOURCEABLE: {name}")
    for name in outcome.to_provide:
        print(f"  TO PROVIDE: {name} (instructions in the pack)")
    for line in outcome.rejected:
        print(f"  REFUSED: {line}")
    for line in outcome.discrepancies:
        print(f"  DISCREPANCY: {line}")
    for ref in outcome.data_dir_notices:
        print(
            f"  Note: data directory '{ref}' required but not included (use refresh_data_dirs.py)"
        )
    return outcome.path


def generate_emulator_pack(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    *,
    required_only: bool = False,
    regions: list[str] | None = None,
    **options: Unpack[EmulatorPackOptions],
) -> str | None:
    """build_emulator_pack, printed: the path, "" when no file is needed,
    None on failure."""
    reject_unknown("generate_emulator_pack", options, EmulatorPackOptions.__optional_keys__)
    said: EmulatorPackOptions = {"progress": print, **options}
    return print_emulator_pack(build_emulator_pack(
        profile_names, emulators_dir, db, bios_dir, output_dir, standalone,
        required_only=required_only, regions=regions, **said,
    ))


def build_emulator_pack(
    profile_names: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    *,
    required_only: bool = False,
    regions: list[str] | None = None,
    **options: Unpack[EmulatorPackOptions],
) -> EmulatorPackOutcome:
    """Build a ZIP pack for specific emulator profiles, printing nothing.

    The outcome's path is the archive, "" when no file is needed (verify
    --emulator reports 0/0 OK), None on failure.

    `pack_name` is the caller's own file name: the system pack names its
    archive after the system, and joining 23 SNES emulator names went past
    the 255 bytes a file name may hold. `system_ids` keeps only the entries
    of those systems, as a platform pack narrows core extras. `final_dir`
    is where the caller moves the archive, the path the report names.
    `record` builds the pack in memory instead (PackRecord): nothing is
    written or read, and the paths are kept on it. `progress` receives the
    lines said while the profiles are read.
    """
    reject_unknown("build_emulator_pack", options, EmulatorPackOptions.__optional_keys__)
    all_profiles = load_emulator_profiles(emulators_dir, skip_aliases=False)
    zip_contents = options.get("zip_contents")
    if zip_contents is None:
        zip_contents = build_zip_contents_index(db, collection_root(Path(bios_dir)))

    try:
        selected = select_emulator_profiles(profile_names, all_profiles, standalone)
    except ProfileSelectionError as exc:
        return EmulatorPackOutcome(None, error=f"Error: {exc}")

    record = options.get("record")
    # ZIP naming
    display_names = [file_name_part(p.get("emulator", n)) for n, p in selected]
    validation_index = build_validation_index(dict(selected))
    narrow_tags = "".join(
        tag
        for tag, _label in pack_narrowings(
            "full", regions, None, False, required_only, standalone
        )
    )
    zip_name = options.get("pack_name") or bounded_join(
        display_names,
        [n for n, _p in selected],
        joiner="_",
        budget=MAX_PACK_NAME_BYTES,
        suffix=f"{narrow_tags}{PACK_SUFFIX}",
    )
    zip_path = os.path.join(output_dir, zip_name)
    if record is None:
        os.makedirs(output_dir, exist_ok=True)

    data_registry = load_data_dir_registry(
        options.get("platforms_dir") or str(REPO_ROOT / "platforms")
    )
    region_drops: set[str] = (
        emulator_region_drops(
            selected, standalone, regions, required_only, db,
            zip_contents=zip_contents, data_registry=data_registry,
        )
        if regions
        else set()
    )
    with (
        contextlib.nullcontext(record) if record is not None
        else writing_pack(zip_path)
    ) as zf:
        build = _EmulatorPackBuild(
            db, bios_dir, standalone, required_only, zip_contents, data_registry,
            validation_index, region_drops, all_profiles, zf,
            offline=options.get("offline"), system_ids=options.get("system_ids"), record=record,
            progress=options.get("progress") or (lambda _line: None),
        )
        for emu_name, profile in sorted(selected):
            build.pack_profile(emu_name, profile)

    # Remove empty ZIP (no files packed and no missing = nothing to ship)
    if record is None and build.nothing_needed():
        os.unlink(zip_path)
        return build.outcome("", "", display_names)

    final_dir = options.get("final_dir")
    return build.outcome(
        None if build.nothing_needed() else zip_path,
        os.path.join(final_dir, zip_name) if final_dir else zip_path,
        display_names,
    )


class SystemPackOptions(TypedDict, total=False):
    """The keyword options of generate_system_pack."""

    required_only: bool
    regions: list[str] | None
    offline: bool | None
    platforms_dir: str | None
    progress: Callable[[str], None] | None


def generate_system_pack(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    **options: Unpack[SystemPackOptions],
) -> str | None:
    """build_system_pack, printed: the path, "" when no file is needed,
    None on failure."""
    reject_unknown("generate_system_pack", options, SystemPackOptions.__optional_keys__)
    said: SystemPackOptions = {"progress": print, **options}
    return print_emulator_pack(build_system_pack(
        system_ids, emulators_dir, db, bios_dir, output_dir, standalone, zip_contents, **said,
    ))


def build_system_pack(
    system_ids: list[str],
    emulators_dir: str,
    db: dict,
    bios_dir: str,
    output_dir: str,
    standalone: bool = False,
    zip_contents: dict | None = None,
    **options: Unpack[SystemPackOptions],
) -> EmulatorPackOutcome:
    """Build a ZIP pack for all emulators supporting given system IDs, printing nothing.

    The outcome's path is the archive, "" when no file is needed, None on failure.
    """
    reject_unknown("build_system_pack", options, SystemPackOptions.__optional_keys__)
    required_only = options.get("required_only", False)
    regions = options.get("regions")
    offline = options.get("offline")
    platforms_dir = options.get("platforms_dir")
    profiles = load_emulator_profiles(emulators_dir)
    matching = profiles_for_systems(profiles, system_ids, standalone)

    if not matching:
        return EmulatorPackOutcome(
            None, error=no_profile_for_systems(profiles, system_ids, standalone)
        )

    # Named like the platform's --system tag: one spelling of a system is
    # one file name, and one selection.
    sys_display = bounded_join(
        [system_display_name(sid) for sid in system_ids], list(system_ids)
    )
    # Built in a scratch directory: under its emulator name in output_dir it
    # overwrote, then carried away, an --emulator pack already there.
    os.makedirs(output_dir, exist_ok=True)
    # Every dimension goes through the one list: keeping only the region
    # tag made --system X --required-only overwrite the pack built without it.
    tags = "".join(
        tag
        for tag, _label in pack_narrowings(
            "full", regions, None, False, required_only, standalone=standalone
        )
    )
    # The selection mode is part of the name: `--system sega-triforce`
    # and `--emulator triforce` both wrote Triforce_BIOS_Pack.zip, and
    # the second run replaced the first without a word.
    final_name = f"{sys_display}_System{tags}{PACK_SUFFIX}"
    scratch = tempfile.mkdtemp(prefix=".system-", dir=output_dir)
    try:
        outcome = build_emulator_pack(
            matching,
            emulators_dir,
            db,
            bios_dir,
            scratch,
            standalone,
            zip_contents=zip_contents,
            required_only=required_only,
            regions=regions,
            offline=offline,
            platforms_dir=platforms_dir,
            pack_name=final_name,
            system_ids=system_ids,
            final_dir=output_dir,
            progress=options.get("progress"),
        )
        if not outcome.path:
            return outcome
        new_path = os.path.join(output_dir, final_name)
        os.replace(outcome.path, new_path)
        outcome.path = new_path
        return outcome
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


