"""Files the cores load that a platform does not declare, and why some are left out."""

from __future__ import annotations

import functools
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from model.alternatives import set_fields, set_keys, set_requirements, settle_sets
from model.declarations import OUTER_ROOTS, platform_declarations, platform_declared_contents
from model.profiles import PROFILE_IDENTITY_FIELDS, entry_system_ids, load_emulator_profiles
from packs.paths import core_save_folder
from resolve.archives import archive_entry, archive_members
from resolve.cores import resolve_platform_cores
from resolve.directories import expand_directory_entries
from resolve.launchers import LauncherLayer, declared_destinations, held_record
from resolve.layout import runs_standalone, system_dir_path
from resolve.localfile import resolve_local_file
from resolve.nativemode import hash_mismatch_excludes_file
from resolve.ownership import _foreign_tree, _owner_tokens
from resolve.standalone import platform_layouts, standalone_set as platform_standalone_set
from resolve.validation import (
    _parse_validation,
    case_folded_slots,
    core_size_refusal,
    declaration_settles,
    installed_with_emulator,
    outside_gap_scope,
    read_from_save_dir,
    same_slot_entries,
    unread_on,
    with_archive_members,
)


def _build_expected(file_entry: dict, checks: list[str]) -> dict:
    """Extract expected validation values from an emulator profile file entry."""
    expected: dict = {}
    if not checks:
        return expected
    if "size" in checks:
        for key in ("size", "min_size", "max_size", "size_multiple"):
            if file_entry.get(key) is not None:
                expected[key] = file_entry[key]
    for hash_type in ("crc32", "md5", "sha1", "sha256"):
        if hash_type in checks and file_entry.get(hash_type):
            expected[hash_type] = file_entry[hash_type]
    adler_val = file_entry.get("known_hash_adler32") or file_entry.get("adler32")
    if adler_val:
        expected["adler32"] = adler_val
    return expected


def _in_foreign_tree(db: dict, owners: set[str], sha1: str) -> bool:
    """Whether the collection keeps this sha1 in another emulator's tree."""
    return _foreign_tree(db.get("files", {}).get(sha1, {}).get("path", ""), owners)


def _name_in_index(
    name: str,
    by_name: dict,
    by_path_suffix: dict | None = None,
    data_names: set[str] | None = None,
    by_name_lower: dict[str, str] | None = None,
    foreign: Callable[[str], bool] | None = None,
) -> bool:
    """Check if a name is resolvable in the database indexes or data directories.

    *foreign* tells a copy in another emulator's tree from the sha1 of a
    name: matched in another casing, such a copy is not the asker's, as in
    resolve_local_file's case-insensitive step.
    """
    # Strip trailing slash for directory-type entries (e.g. nestopia/samples/foo/)
    name = name.rstrip("/")
    if name in by_name:
        return True
    basename = name.rsplit("/", 1)[-1] if "/" in name else name
    if basename != name and basename in by_name:
        return True
    if by_name_lower:
        for key in {name.lower(), basename.lower()}:
            if key in by_name_lower and not (
                foreign and all(foreign(s) for s in by_name[by_name_lower[key]])
            ):
                return True
    if by_path_suffix and name in by_path_suffix:
        return True
    if data_names:
        if name in data_names or name.lower() in data_names:
            return True
        if basename != name and (
            basename in data_names or basename.lower() in data_names
        ):
            return True
    return False


def _candidate_verdict(
    file_entry: dict,
    fname: str,
    is_standalone: bool,
    include_all: bool,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | set[str],
    dest: str = "",
    folded_slots: frozenset[str] = frozenset(),
    declared_contents: Mapping[str, set[str]] | None = None,
) -> str:
    """Whether a profile entry can be a gap, and whether it is settled.

    Three answers. "keep" means it is a candidate. "settled" means something
    has answered for it (the platform declares it, or the profile documents
    it as unsourceable), so the same requirement reached from another profile
    must not be reconsidered. "skip" means it does not apply in this context,
    which leaves it open for a profile where it does: the same file can be
    libretro-only here and standalone-only there.
    """
    if file_entry.get("unsourceable"):
        return "settled"
    if outside_gap_scope(file_entry, is_standalone):
        return "skip"
    if not include_all and declaration_settles(
        file_entry, fname, declared_names, dest, folded_slots, declared_contents
    ):
        return "settled"
    return "keep"


def _identity_of(entry: dict) -> dict:
    """The fields that tell a profile's file apart from a same-named one."""
    return {
        field: entry.get(field)
        for field in PROFILE_IDENTITY_FIELDS
        if entry.get(field) not in (None, "", [])
    }


def _gap_destination(f: dict, fname: str, is_standalone: bool, save_root: bool) -> str:
    """The destination a gap entry is keyed and reported at."""
    # One destination rule for the dedup key and for the entry: a
    # standalone build without standalone_path falls back on path.
    # The key used to skip that fallback, so clk's Acorn/basic.rom and
    # Electron/basic.rom both keyed as "basic.rom" under Batocera's
    # standalone clk and the second was dropped.
    # A file the libretro build reads below the save directory is
    # placed there, apart from the system directory the platform
    # lays out: no declaration of the BIOS tree answers for it.
    if is_standalone:
        return f.get("standalone_path") or f.get("path") or fname
    if save_root:
        return f.get("path") or fname
    return system_dir_path(f, f.get("path") or fname)


def _region_key(f: dict) -> tuple[str, ...]:
    raw_regions = f.get("region") or []
    return tuple(
        str(value) for value in (
            raw_regions if isinstance(raw_regions, list) else [raw_regions]
        )
    )


SetRecord = tuple[tuple, dict, bool, "tuple[dict, dict | None] | None"]


@dataclass
class _GapScan:
    """What find_undeclared_files reads and gathers while it walks the cores."""

    config: dict
    db: dict
    data_names: set[str] | None
    include_all: bool
    declared_names: Mapping[str, list[tuple[int | None, str]]]
    folded_slots: frozenset[str]
    declared_contents: Mapping[str, set[str]]
    # Whether the builder drops a file whose local copy contradicts its
    # declared hash, which decides if such a copy counts as held here.
    shipped_on_mismatch: bool
    launcher_layer: LauncherLayer
    by_name: dict = field(init=False)
    by_name_lower: dict[str, str] = field(init=False)
    by_path_suffix: dict = field(init=False)
    launcher_candidates: list[tuple[str, bool, dict, dict]] = field(default_factory=list)
    # Each grouped requirement met, as (set keys, entry, fills, (reported
    # entry, the entry it is a claim on)): settled once every core is read.
    set_records: list[SetRecord] = field(default_factory=list)
    undeclared: list[dict] = field(default_factory=list)
    seen_files: set[tuple] = field(default_factory=set)
    # Key -> the entry reported for it. A later profile reading the same
    # requirement is kept on that entry rather than counted again: a pack
    # built without the first profile still has to name the file.
    reported: dict[tuple, dict] = field(default_factory=dict)
    # Track archives: archive_name -> {in_repo, emulator, files: [...], ...}
    archive_entries: dict[tuple, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.by_name = self.db.get("indexes", {}).get("by_name", {})
        self.by_name_lower = {k.lower(): k for k in self.by_name}
        self.by_path_suffix = self.db.get("indexes", {}).get("by_path_suffix", {})

    def scan_file(self, emu_name: str, layout: dict, is_standalone: bool, f: dict) -> None:
        """Consider one profile entry of one build as a gap."""
        fname = f.get("name", "")
        save_root = read_from_save_dir(f, is_standalone)
        dest = _gap_destination(f, fname, is_standalone, save_root)
        region_key = _region_key(f)
        # Same-name requirements at different paths, for different systems,
        # or in distinct variant groups are not interchangeable.
        seen_key = (
            fname,
            f.get("archive"),
            dest,
            f.get("system"),
            f.get("selection_slot"),
            region_key,
            # Below the save directory each core is handed a folder
            # of its own: two cores reading hiscore.dat there read
            # two files.
            ("save", core_save_folder(layout)) if save_root
            else (f["root"],) if f.get("root") in OUTER_ROOTS
            # In the emulator's own folder: no other core reads it.
            else ("emulator", emu_name) if f.get("unplaced") else None,
        )
        config = self.config
        if not fname or unread_on(f, config.get("_key", "")):
            return
        first = self.reported.get(seen_key)
        duplicate = seen_key in self.seen_files
        if duplicate and (first is None or first["profile"] == emu_name):
            return
        outer = save_root or f.get("root") in OUTER_ROOTS
        # Nor does it answer for one read below the roms directory.
        verdict = _candidate_verdict(
            f, fname, is_standalone, self.include_all,
            {} if outer else self.declared_names,
            dest, self.folded_slots,
            None if outer else self.declared_contents,
        )
        if verdict == "settled":
            self.seen_files.add(seen_key)
            if (self.launcher_layer and not f.get("unsourceable") and not outer
                    and not f.get("unplaced")):
                self.launcher_layer.declared_elsewhere(emu_name, is_standalone, f)
            # Answered by the platform's own declaration, which its
            # report covers: the set it belongs to is spoken for.
            self.set_records.append((set_keys((emu_name, is_standalone), f), f, True, None))
            return
        if verdict == "skip":
            return

        archive = f.get("archive")
        self.seen_files.add(seen_key)

        if archive:
            self._count_archive_member(emu_name, layout, is_standalone, f, region_key)
            return

        in_repo = self._held(emu_name, layout, f, fname, dest)
        entry = self._gap_entry(emu_name, layout, f, fname, dest, in_repo, save_root)
        if self.launcher_layer and not outer:
            # One read outside the BIOS tree is still served where a
            # launcher links that very file: RetroDECK links Cemu's
            # keys.txt to bios/cemu/keys.txt.
            self.launcher_candidates.append((emu_name, is_standalone, f, entry))
        keys = set_keys((emu_name, is_standalone), f)
        if duplicate and first is not None:
            first.setdefault("other_claims", []).append(entry)
            self.set_records.append((keys, f, in_repo, (entry, first)))
            return
        self.reported[seen_key] = entry
        self.undeclared.append(entry)
        self.set_records.append((keys, f, in_repo, (entry, None)))

    def _count_archive_member(
        self, emu_name: str, layout: dict, is_standalone: bool, f: dict,
        region_key: tuple[str, ...],
    ) -> None:
        archive = f["archive"]
        archive_key = (
            archive,
            f.get("system_dir"),
            f.get("system"),
            f.get("selection_slot"),
            region_key,
            is_standalone,
        )
        if archive_key not in self.archive_entries:
            in_repo = _name_in_index(
                archive, self.by_name, self.by_path_suffix, self.data_names,
                self.by_name_lower,
            )
            self.archive_entries[archive_key] = {
                "profile": emu_name,
                "emulator": layout.get("emulator", emu_name),
                "systems": entry_system_ids(f, layout),
                "system": f.get("system"),
                "region": f.get("region"),
                "selection_slot": f.get("selection_slot"),
                "name": archive,
                "archive": archive,
                "path": system_dir_path(f, archive),
                "required": False,
                "hle_fallback": False,
                "category": f.get("category", "bios"),
                "in_repo": in_repo,
                "note": "",
                "checks": [],
                "source_ref": None,
                "expected": {},
                "archive_file_count": 0,
                "archive_required_count": 0,
                "members": archive_members(archive, layout.get("files", [])),
            }
            if f.get("system_dir"):
                self.archive_entries[archive_key]["system_dir"] = f["system_dir"]
            # The archive's own declaration names its sets: an
            # archive is a member like a loose file.
            own = archive_entry(archive, layout.get("files", []))
            self.archive_entries[archive_key].update(set_fields(own, layout))
            self.set_records.append((
                set_keys((emu_name, is_standalone), own), own, in_repo,
                (self.archive_entries[archive_key], None),
            ))
        entry = self.archive_entries[archive_key]
        entry["archive_file_count"] += 1
        if f.get("required", False):
            entry["archive_required_count"] += 1
            entry["required"] = True

    def _held(self, emu_name: str, layout: dict, f: dict, fname: str, dest: str) -> bool:
        """Whether the collection holds the file as the builder would ship it."""
        # Resolution: name, then path basename
        # storage: release names where the bytes are served from, not
        # that the collection holds them: resolved like any file.
        # Resolved as the asker, as the builder's ExtraResolver does:
        # another casing of the name in another emulator's tree is
        # not this emulator's file (dosbox-x's et4000.bin and pcem's
        # et4000.BIN).
        owned = {**f, "source_profile": emu_name}
        if self.shipped_on_mismatch and (f.get("md5") or f.get("sha1")):
            # The entry states what its content should be and the builder
            # drops a copy that contradicts it, so content decides here
            # too. A name match would not do: generic names collide across
            # systems, and answering yes on one describes a pack that will
            # not contain the file.
            _lp, _st = resolve_local_file(owned, self.db, dest_hint=dest)
            return _lp is not None and _st != "hash_mismatch"
        in_repo = self._held_by_name(owned, f, fname, dest)
        if in_repo and "size" in _parse_validation(f.get("validation")):
            # On any platform the core measures what it opens: a
            # copy it turns away by its own size check is not
            # held for it, the rule the builder's lookup applies
            # (packextras.ExtraResolver). The Apple IIGS' 128 KB
            # ROM is not Basilisk II's ROM.
            _lp, _st = resolve_local_file(owned, self.db, dest_hint=dest)
            if core_size_refusal(
                f, _lp, same_slot_entries(layout.get("files"), fname, dest)
            ):
                in_repo = False
        return in_repo

    def _held_by_name(self, owned: dict, f: dict, fname: str, dest: str) -> bool:
        foreign = functools.partial(_in_foreign_tree, self.db, _owner_tokens(owned))
        in_repo = _name_in_index(
            fname, self.by_name, self.by_path_suffix, self.data_names, self.by_name_lower,
            foreign,
        )
        if not in_repo and dest != fname:
            path_base = dest.rsplit("/", 1)[-1]
            in_repo = _name_in_index(
                path_base, self.by_name, self.by_path_suffix, self.data_names,
                self.by_name_lower, foreign,
            )
        if in_repo and not any(
            f.get(h) for h in ("sha1", "md5", "crc32", "sha256")
        ):
            # A name alone answers nothing when every copy of that
            # name fails the size the code checks: the resolver
            # rejects them all. NanoBoyAdvance's 16 KB bios.bin met
            # only PCem's and QEMU's PC BIOS images of that name.
            # The fallback below then decides as for any mismatch.
            _lp, _st = resolve_local_file(owned, self.db, dest_hint=dest)
            if _st == "hash_mismatch":
                in_repo = False
        if not in_repo:
            # Hash fallback: the repo may hold the content under a
            # different filename (exos21.rom vs exos21.bin).
            #
            # A copy contradicting the declared hash counts as held
            # only where the builder would ship it. Under existence
            # the frontend never opens the file, so the pack carries
            # it and reports the divergence. Under a digest mode the
            # frontend would reject it, the builder leaves it out, and
            # calling it available here would describe a pack that
            # does not contain it.
            _lp, _st = resolve_local_file(owned, self.db, dest_hint=dest)
            in_repo = _st != "not_found" and _lp is not None
            if in_repo and _st == "hash_mismatch" and self.shipped_on_mismatch:
                in_repo = False
        return in_repo

    def _gap_entry(
        self, emu_name: str, layout: dict, f: dict, fname: str, dest: str,
        in_repo: bool, save_root: bool,
    ) -> dict:
        checks = _parse_validation(f.get("validation"))
        entry = {
            "profile": emu_name,
            "emulator": layout.get("emulator", emu_name),
            "systems": entry_system_ids(f, layout),
            "system": f.get("system"),
            "region": f.get("region"),
            "selection_slot": f.get("selection_slot"),
            "name": fname,
            "path": dest,
            "required": f.get("required", False),
            "hle_fallback": f.get("hle_fallback", False),
            "bundled": installed_with_emulator(f, self.config.get("_key", "")),
            "category": f.get("category", "bios"),
            "in_repo": in_repo,
            "note": f.get("note", ""),
            "checks": sorted(checks) if checks else [],
            **set_fields(f, layout),
            "source_ref": f.get("source_ref"),
            "expected": _build_expected(f, checks),
            **_identity_of(f),
            "sha1": f.get("sha1"),
            "md5": f.get("md5"),
        }
        if f.get("contents"):
            entry["contents"] = f["contents"]
        if save_root:
            entry["root"] = "save"
            folder = core_save_folder(layout)
            if folder is not None:
                entry["core_folder"] = folder
        elif f.get("system_dir"):
            entry["system_dir"] = f["system_dir"]
        members = with_archive_members(f, layout.get("files", [])).get("members")
        if members:
            entry["members"] = members
        if f.get("layout_path"):
            entry["layout_path"] = f["layout_path"]
        if f.get("unprefixed"):
            entry["unprefixed"] = True
        if f.get("unplaced"):
            entry["unplaced"] = f["unplaced"]
        elif f.get("root") in OUTER_ROOTS:
            # Read below the roms directory (ROCKNIX's roms/pico-8)
            # or in an emulator folder (RetroBat's emulators/pico8).
            entry["root"] = f["root"]
        return entry


def find_undeclared_files(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    data_names: set[str] | None = None,
    include_all: bool = False,
    declared_names: Mapping[str, list[tuple[int | None, str]]] | None = None,
) -> list[dict]:
    """Find files needed by cores but not declared in platform config.

    declared_names overrides the default enriched declarations from
    platform_declarations.  Pass the strict ones (YAML names only) when
    building packs so alias-only names still get packed.
    """
    if declared_names is None:
        declared_names = platform_declarations(config, db)
    folded_slots = case_folded_slots(config, declared_names)
    declared_contents = platform_declared_contents(config, db)

    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    standalone_set = platform_standalone_set(config)
    # What the platform's own launchers open, matched to the cores it runs:
    # the one decision the builder and this report both read.
    launcher_layer = LauncherLayer(
        config, profiles, relevant, db, declared_destinations(config)
    )
    scan = _GapScan(
        config, db, data_names, include_all, declared_names, folded_slots,
        declared_contents,
        hash_mismatch_excludes_file(config.get("verification_mode")),
        launcher_layer,
    )

    for emu_name, profile in sorted(profiles.items()):
        if profile.get("type") in ("launcher", "alias"):
            continue
        if emu_name not in relevant:
            continue

        # A filename-agnostic profile is served by the scan (packextras), all
        # but the entries its layout reads outside the BIOS tree: those are
        # named here, or a launcher folder drops them without a word
        # (ARMSX2's arcade/proverb.zip once ROCKNIX binds bios/armsx2).
        agnostic = profile.get("bios_mode") == "agnostic"

        for layout, is_standalone in platform_layouts(emu_name, profile, standalone_set):
            for f in expand_directory_entries(
                layout.get("files", []), db, is_standalone
            ):
                if agnostic and not f.get("unplaced"):
                    continue
                scan.scan_file(emu_name, layout, is_standalone, f)

    undeclared = scan.undeclared
    settled: set[int] = set()
    if launcher_layer:
        added, settled = launcher_layer.settle(
            scan.launcher_candidates, lambda report: held_record(report, db)
        )
        undeclared = [u for u in undeclared if id(u) not in settled]
        undeclared.extend(added)

    undeclared.extend(sorted(scan.archive_entries.values(), key=lambda e: e["name"]))

    return _split_bundled_claims(
        _settle_core_sets(undeclared, scan.set_records, settled, profiles)
    )


def _split_bundled_claims(undeclared: list[dict]) -> list[dict]:
    """A file one emulator installs itself, another reads from the pack.

    The first profile reading a requirement hosts the claims of the others,
    and a host installed with its emulator is left out of the pack with all
    of them: DraStic brings its own usrcheat.dat, and ROCKNIX's DSPerate,
    which reads the same file, lost it wherever DraStic runs too. Built for
    a board without DraStic, the pack carried it.
    """
    out: list[dict] = []
    for entry in undeclared:
        claims = entry.get("other_claims") or []
        rest = [c for c in claims if not c.get("bundled")]
        if not entry.get("bundled") or not rest:
            out.append(entry)
            continue
        own = [c for c in claims if c.get("bundled")]
        kept = {k: v for k, v in entry.items() if k != "other_claims"}
        if own:
            kept["other_claims"] = own
        promoted = dict(rest[0])
        if rest[1:]:
            promoted["other_claims"] = rest[1:]
        out += [kept, promoted]
    return out


def _settle_core_sets(
    undeclared: list[dict],
    records: list[tuple[tuple, dict, bool, tuple[dict, dict | None] | None]],
    launcher_settled: set[int],
    profiles: dict[str, dict],
) -> list[dict]:
    """The core complement with each set of alternatives settled.

    A member the collection lacks is dropped when another member is held,
    declared by the platform or placed by its launcher, and a set nobody
    holds keeps one entry, its first member, naming the others. A claim
    another profile shares stays: its own core may need that very file.
    """
    # Archive units rank first among equals, as the builder orders them.
    grouped = sorted(
        (r for r in records if r[0]),
        key=lambda r: not (r[3] is not None and r[3][0].get("archive")),
    )
    if not grouped:
        return undeclared
    excused, standing = settle_sets([
        (keys, f, fills or (ref is not None and id(ref[0]) in launcher_settled))
        for keys, f, fills, ref in grouped
    ], lambda key: set_requirements(profiles.get(key[0][0], {})).get(key[1], True))
    declared_sets = {
        key for keys, _f, _fills, ref in grouped if ref is None for key in keys
    }
    dropped: set[int] = set()
    for position, (keys, _f, _fills, ref) in enumerate(grouped):
        if ref is None:
            continue
        entry, host = ref
        required_keys = [k for k in keys if k[1] in entry.get("required_groups", ())]
        if required_keys and all(k in declared_sets for k in required_keys):
            # The platform declares a member of each of its required sets:
            # under --required-only that declaration carries them.
            entry["set_declared"] = True
        if position in standing:
            entry["alternatives"] = standing[position].others
            entry["required"] = standing[position].required
        if position not in excused:
            continue
        if host is not None:
            host["other_claims"] = [c for c in host.get("other_claims", []) if c is not entry]
            if not host["other_claims"]:
                del host["other_claims"]
        else:
            dropped.add(id(entry))
    out: list[dict] = []
    for entry in undeclared:
        if id(entry) not in dropped:
            out.append(entry)
            continue
        # Another core reading the same requirement still needs it.
        claims = entry.get("other_claims") or []
        if claims:
            promoted = dict(claims[0])
            if claims[1:]:
                promoted["other_claims"] = claims[1:]
            out.append(promoted)
    return out


def find_exclusion_notes(
    config: dict,
    emulators_dir: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
) -> list[dict]:
    """Document why certain emulator files are intentionally excluded.

    Reports:
    - Launchers (BIOS managed by standalone emulator)
    - Standalone-only files (not needed in libretro mode)
    - Frozen snapshots with files: [] (code doesn't load .info firmware)
    - Files covered by data_directories
    """
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )
    platform_systems = set()
    for sys_id in config.get("systems", {}):
        platform_systems.add(sys_id)

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    notes = []
    for emu_name, profile in sorted(profiles.items()):
        emu_systems = set(profile.get("systems", []))
        # Match by core resolution OR system intersection (documents all potential emulators)
        if emu_name not in relevant and not (emu_systems & platform_systems):
            continue

        emu_display = profile.get("emulator", emu_name)

        if profile.get("type") == "launcher":
            notes.append(
                {
                    "emulator": emu_display,
                    "reason": "launcher",
                    "detail": profile.get(
                        "exclusion_note", "BIOS managed by standalone emulator"
                    ),
                }
            )
            continue

        # Profile-level exclusion note (frozen snapshots, etc.)
        exclusion_note = profile.get("exclusion_note")
        if exclusion_note:
            notes.append(
                {
                    "emulator": emu_display,
                    "reason": "exclusion_note",
                    "detail": exclusion_note,
                }
            )
            continue

        # Count standalone-only files, but only report as excluded if the
        # platform does NOT use this emulator in standalone mode
        standalone_set = platform_standalone_set(config)
        is_standalone = runs_standalone(emu_name, profile, standalone_set)
        if not is_standalone:
            standalone_files = [
                f for f in profile.get("files", []) if f.get("mode") == "standalone"
            ]
            if standalone_files:
                names = [f["name"] for f in standalone_files[:3]]
                more = (
                    f" +{len(standalone_files) - 3}"
                    if len(standalone_files) > 3
                    else ""
                )
                notes.append(
                    {
                        "emulator": emu_display,
                        "reason": "standalone_only",
                        "detail": f"{len(standalone_files)} files for standalone mode only ({', '.join(names)}{more})",
                    }
                )

    return notes
