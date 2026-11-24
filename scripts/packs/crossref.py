"""Emulator profiles against platform declarations: what the cores load that a platform omits."""

from __future__ import annotations

import dataclasses
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

from model.alternatives import set_keys, set_requirements, settle_sets
from model.database import get_mame_clone_map
from model.declarations import OUTER_ROOTS
from model.platforms import load_platform_config
from model.profilekinds import is_emulator
from model.registry import list_registered_platforms
from model.systems import norm_system_id
from packs.gaps import gap_destination
from packs.supplemental import SupplementalIndex, data_hit, declared_content
from resolve.archives import archive_entry
from resolve.content import content_fits, name_match_size_ok
from resolve.directories import directory_members
from resolve.launcherlayer import LauncherLayer, held_record
from resolve.layout import system_dir_path
from resolve.lookup import held_record_for
from resolve.ownership import foreign_tree, owner_tokens
from resolve.launches import PlatformLaunches
from resolve.standalone import platform_layouts
from resolve.entryscope import (
    case_folded_slots,
    declaration_settles,
    installed_everywhere,
    installed_with_emulator,
    outside_gap_scope,
    read_from_save_dir,
    unread_on,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack


def platform_configs(platforms_dir: str, platforms: list[str] | None = None) -> list[dict]:
    """The configs of *platforms*, otherwise of every registered platform."""
    return [
        load_platform_config(platform_name, platforms_dir)
        for platform_name in platforms or list_registered_platforms(platforms_dir)
    ]


def global_report_scope(
    configs: list[dict], db: dict, profiles: dict[str, dict],
) -> tuple[dict[str, set[str]], ReportScope]:
    """What a gap report over *configs* compares against: the names each
    system declares, and the scope cross_reference reads.

    The declared names are keyed by the normalized system ID: a profile
    writes `sega-megacd` where RetroArch writes `sega-mega-cd`, and an exact
    match called 924 declared files undeclared. `all_declared` is every name
    with each declaration's size and slot: judged per normalized system id,
    646 entries whose exact name a platform declares (bk and elektronika-bk,
    nintendo-sgb and nintendo-super-game-boy) were counted undeclared.
    `folded_slots` holds the slots a case-folding filesystem fills under any
    spelling (RetroBat's 32X_G_BIOS.BIN is BlastEm's 32X_G_BIOS.bin), and
    `declared_contents` the members of a declared archive. The command line
    and the site's gap page read this one scope.
    """
    from model.declarations import (
        merged_platform_declarations,
        merged_platform_declared_contents,
        platform_declarations,
    )
    from resolve.standalone import merged_launches

    declared: dict[str, set[str]] = {}
    for config in configs:
        for sys_id, system in config.get("systems", {}).items():
            for fe in system.get("files", []):
                name = fe.get("name", "")
                if name:
                    declared.setdefault(norm_system_id(sys_id), set()).add(name)
    folded: frozenset[str] = frozenset().union(*(
        case_folded_slots(config, platform_declarations(config, db)) for config in configs
    ))
    return declared, {
        "all_declared": merged_platform_declarations(configs, db),
        "standalone_cores": merged_launches(configs, profiles),
        "folded_slots": folded,
        "declared_contents": merged_platform_declared_contents(configs, db),
    }


def emulator_profiles(profiles: dict[str, dict]) -> dict[str, dict]:
    """The profiles a gap report compares: neither aliases nor test cores."""
    return {key: profile for key, profile in profiles.items() if is_emulator(profile)}


def whole_tree_gaps(
    configs: list[dict], db: dict, profiles: dict[str, dict],
    data_names: SupplementalIndex | None = None,
    compared: dict[str, dict] | None = None,
) -> dict:
    """Each emulator of *compared* (every one of *profiles* by default) with
    the files no platform of *configs* declares.

    The command line without --platform, the site's gap page and the gaps
    export read this one report. *profiles* is every profile of the run: the
    standalone layout is proven against them.
    """
    declared, scope = global_report_scope(configs, db, profiles)
    report = cross_reference(
        emulator_profiles(profiles if compared is None else compared),
        declared, db, data_names, **scope,
    )
    _record_needing_platforms(report, configs, profiles)
    return report


def _record_needing_platforms(
    report: dict, configs: list[dict], profiles: dict[str, dict],
) -> None:
    """Give each missing row the platforms whose build of its emulator needs it.

    A platform needs the entry when the build it runs reads it (BlastEm's
    cdbios.bin is read by the standalone build only), its launcher does not
    point the emulator elsewhere (`unread_on`) and its package of the
    emulator does not install it (`installed_on`, `not_bundled_on`).
    """
    from resolve.cores import resolve_platform_cores
    from resolve.standalone import platform_launches
    from resolve.entryscope import filter_files_by_mode

    missing = [
        (emu_name, gap) for emu_name, data in report.items()
        for gap in data["gap_details"] if gap["source"] == "missing"
    ]
    if not missing:
        return
    runners: dict[str, list[tuple[str, set[str]]]] = {}
    runnable = emulator_profiles(profiles)
    for config in configs:
        platform = str(config.get("_key") or "")
        standalone = platform_launches(config, profiles)
        for emu_name in resolve_platform_cores(config, runnable):
            runners.setdefault(emu_name, []).append((platform, standalone))
    for emu_name, gap in missing:
        profile = profiles[emu_name]
        gap["platforms"] = sorted(
            platform for platform, standalone in runners.get(emu_name, [])
            if any(
                f.get("name") == gap["name"] and not unread_on(f, platform)
                and not installed_with_emulator(f, platform)
                for view, is_standalone in platform_layouts(emu_name, profile, standalone)
                for f in filter_files_by_mode(view.get("files") or [], is_standalone)
            )
        )




def _resolve_source(
    fname: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: SupplementalIndex | None = None,
    by_path_suffix: dict | None = None,
    file_entry: dict | None = None,
    db_files: dict | None = None,
    bios_dir: str | None = None,
) -> str | None:
    """Return the source category for a file, or None if not found.

    Returns ``"bios"`` (in database.json / bios/), ``"data"`` (in data/),
    or ``None`` (not available anywhere).

    A name hit whose size contradicts a size the emulator verifies is not the
    file, so it does not count as available. Nor is one whose bytes carry
    none of the hashes the entry declares: a name never wins over a declared
    hash, and zquestclassic's ending.mid read as held because Hydra Castle
    Labyrinth has another file of that name.

    Another casing of the name in another emulator's tree proves nothing, as
    in resolve_local_file's case-insensitive step: dosbox-x's et4000.bin read
    as held through pcem's et4000.BIN, which the pack and the installer
    refuse it.
    """
    declared = declared_content(file_entry or {})
    owners = owner_tokens(file_entry or {})

    def _can_be(sha1s: list | str) -> bool:
        if not file_entry or db_files is None:
            return True
        if not isinstance(sha1s, list):
            sha1s = [sha1s]
        return any(
            name_match_size_ok(file_entry, db_files.get(sha1, {}).get("size"))
            and content_fits(file_entry, db_files.get(sha1, {}).get("path", ""))
            and _record_carries(sha1, db_files.get(sha1, {}), declared)
            for sha1 in sha1s
        )

    def _name_hit(name: str) -> bool:
        """Whether the files indexed under *name* can be this entry."""
        return _can_be(by_name.get(name) or [])

    def _folded_hit(name: str) -> bool:
        """_name_hit for a name matched in another casing."""
        return _can_be([
            sha1 for sha1 in by_name.get(name) or []
            if db_files is None
            or not foreign_tree(db_files.get(sha1, {}).get("path", ""), owners)
        ])

    # bios/ via database.json by_name
    if fname in by_name and _name_hit(fname):
        return "bios"
    stripped = fname.rstrip("/")
    basename = stripped.rsplit("/", 1)[-1] if "/" in stripped else None
    if basename and basename in by_name and _name_hit(basename):
        return "bios"
    key = fname.lower()
    if key in by_name_lower and _folded_hit(by_name_lower[key]):
        return "bios"
    if basename and basename.lower() in by_name_lower and _folded_hit(
        by_name_lower[basename.lower()]
    ):
        return "bios"
    # bios/ via by_path_suffix (regional variants)
    if by_path_suffix and fname in by_path_suffix and _can_be(by_path_suffix[fname]):
        return "bios"
    # bios/ under the canonical MAME set name, as resolve_local_file does:
    # a renamed archive is held once, under the name the dedup kept.
    canonical = get_mame_clone_map(bios_dir).get(fname)
    if canonical and canonical != fname:
        if canonical in by_name and _name_hit(canonical):
            return "bios"
        if canonical.lower() in by_name_lower and _folded_hit(
            by_name_lower[canonical.lower()]
        ):
            return "bios"
    if data_names and data_hit(fname, basename, file_entry, data_names):
        return "data"
    return None




def _record_carries(sha1: str, record: dict, declared: dict[str, set[str]]) -> bool:
    """Whether a database record has one of the declared hashes, or none is declared."""
    if not declared:
        return True
    actual = {
        "sha1": sha1.lower(),
        **{field: str(record.get(field) or "").lower() for field in ("md5", "sha256", "crc32")},
    }
    return any(
        actual[field] and actual[field] in values
        for field, values in declared.items()
    )





def entry_index(db: dict, data_names: SupplementalIndex | None) -> dict:
    """The collection indexes entry_source reads, one build for every caller."""
    indexes = db.get("indexes", {})
    by_name = indexes.get("by_name", {})
    return {
        "by_name": by_name,
        "by_name_lower": {k.lower(): k for k in by_name},
        "by_md5": indexes.get("by_md5", {}),
        "by_crc32": indexes.get("by_crc32", {}),
        "by_sha256": indexes.get("by_sha256", {}),
        "by_path_suffix": indexes.get("by_path_suffix", {}),
        "db_files": db.get("files", {}),
        "data_names": data_names,
        "bios_dir": db.get("bios_dir"),
    }


def entry_source(f: dict, index: dict) -> str | None:
    """Where the collection holds a profile entry, or None.

    By name, path and alias, then by any hash the entry declares. The gap
    report and the site pages read this one function, so a file is held or
    missing in the same way on both.
    """
    by_name, by_name_lower = index["by_name"], index["by_name_lower"]
    data_names, by_path_suffix = index.get("data_names"), index["by_path_suffix"]
    db_files = index["db_files"]
    fname = f.get("name", "")
    path_field = f.get("path") or ""
    # A directory is held when the collection holds files under it, the rule
    # the pack and verify --emulator expand it by, and by nothing else: a
    # bare-name lookup missed cdogs' .wolf3d/, whose 695 files every pack
    # carries, and called SuperTux's data/ held by MAME's plugins/data/.
    if f.get("type") == "directory" or fname.endswith("/"):
        members = directory_members(
            {"indexes": {"by_path_suffix": by_path_suffix}}, path_field or fname
        )
        return "bios" if members else None
    found = None
    for candidate in [fname, *([path_field] if path_field != fname else []),
                      *(f.get("aliases") or [])]:
        if not candidate:
            continue
        source = _resolve_source(
            candidate, by_name, by_name_lower, data_names, by_path_suffix, f, db_files,
            index.get("bios_dir"),
        )
        if source == "bios":
            return source
        found = found or source

    # The declared content anywhere in bios/ comes before a data/ copy, as in
    # the resolver: the hash steps run before the data directories, and the
    # held record is the one every declared hash agrees with.
    held = held_record_for(f, {
        "files": db_files,
        "indexes": {key: index[key] for key in ("by_md5", "by_sha256", "by_crc32")},
    })
    return "bios" if held is not None else found


def _resolve_archive_source(
    archive_name: str,
    by_name: dict[str, list],
    by_name_lower: dict[str, str],
    data_names: SupplementalIndex | None = None,
    by_path_suffix: dict | None = None,
) -> str:
    """Resolve source for an archive (ZIP) name, returning a source category string."""
    result = _resolve_source(
        archive_name, by_name, by_name_lower, data_names, by_path_suffix,
    )
    return result if result is not None else "missing"


def first_hash(entry: dict) -> str:
    """The first hash an entry declares, strongest first, or ''."""
    for field in ("sha1", "sha256", "md5", "crc32"):
        value = entry.get(field)
        if isinstance(value, list):
            value = value[0] if value else ""
        if value:
            return f"{field}:{str(value).lower()}"
    return ""


def declared_as(f: dict, fname: str) -> dict[str, str]:
    """The category and path the profile gives the entry a row stands for.

    A row's own path is the destination the running build reads, so a
    reader that needs the profile's declaration takes it from here.
    """
    return {
        "category": str(f.get("category") or "bios"),
        "profile_path": str(f.get("path") or fname),
    }


def slot_key(f: dict, standalone: bool = False) -> tuple:
    """The slot a profile entry fills: its entries on one slot are the
    versions its code accepts there, and holding any of them fills it.

    The path is the one the running build reads: b2's standalone build
    reads MOS 3.20 and 3.50 from two directories, two slots, while the
    entries share a name and no `path:`."""
    fname = f.get("name", "")
    where = (f.get("standalone_path") if standalone else None) or f.get("path")
    return (
        fname,
        f.get("archive"),
        system_dir_path(f, where or fname),
        f.get("system"),
        f.get("selection_slot"),
        f.get("mode", "both"),
        read_from_save_dir(f, standalone),
    )


# Why an entry is left out of the comparison, in the order reports print them.
SET_ASIDE = ("other_versions", "not_read", "outside_scope", "launcher")


GAP_SOURCES = ("bios", "data", "large_file", "missing", "bundled")


def gap_source_counts(data: dict) -> dict[str, int]:
    """Where each undeclared file of one emulator comes from.

    A file installed with its emulator is neither one to source nor one the
    pack brings, held or not (validation.deliverable leaves it out of every
    pack): it counts as bundled whatever its source.
    """
    counts = dict.fromkeys(GAP_SOURCES, 0)
    for gap in data.get("gap_details") or []:
        source = "bundled" if gap.get("bundled") else gap.get("source", "missing")
        if source in counts:
            counts[source] += 1
    return counts



@dataclass
class _ProfileComparison:
    """One profile's entries against the platforms' declarations."""

    emu_name: str
    profile: dict
    index: dict
    platform_names: set[str]
    platform: str
    layouts: list
    versions: dict[tuple, list[dict]] = dataclasses.field(default_factory=dict)
    position: dict[int, int] = dataclasses.field(default_factory=dict)
    gaps: list[dict] = dataclasses.field(default_factory=list)
    covered: list[dict] = dataclasses.field(default_factory=list)
    unsourceable_list: list[dict] = dataclasses.field(default_factory=list)
    archive_gaps: dict[tuple, dict] = dataclasses.field(default_factory=dict)
    seen_files: set[tuple] = dataclasses.field(default_factory=set)
    fates: dict[int, str] = dataclasses.field(default_factory=dict)
    # Grouped entries met, as (set keys, entry, fills, the list holding
    # its row, the row): settled once the profile is read.
    set_records: list[tuple[tuple, dict, bool, list | None, dict | None]] = dataclasses.field(
        default_factory=list
    )
    archive_rows: list[dict] = dataclasses.field(default_factory=list)

    def fate(self, f: dict, what: str) -> None:
        key = self.position[id(f)]
        current = self.fates.get(key)
        if current is None or (current in SET_ASIDE and what not in SET_ASIDE):
            self.fates[key] = what

    def compare(self, f: dict, is_standalone: bool) -> None:
        """File one entry of one build: declared, a gap, or set aside."""
        fname = f.get("name", "")
        platform = self.platform
        save_root = read_from_save_dir(f, is_standalone)
        # The destination the running build reads, as find_undeclared_files
        # takes it: Batocera's standalone Cemu reads keys.txt at
        # standalone_path, and the libretro Cemu/keys.txt reported here
        # settled the declaration on a slot the platform never fills.
        effective_path = gap_destination(f, fname, is_standalone, save_root)
        slot = slot_key(f, is_standalone)
        seen_key = slot
        if len(self.layouts) > 1:
            # One file read at one path by both builds counts once.
            seen_key = (effective_path.casefold(), seen_key)
        if not fname:
            self.fate(f, "outside_scope")
            return
        if seen_key in self.seen_files:
            self.fate(f, "other_versions")
            return
        if unread_on(f, platform):
            self.fate(f, "not_read")
            return

        # Collect unsourceable files separately (documented, not a gap)
        unsourceable_reason = f.get("unsourceable", "")
        keys = set_keys((self.emu_name, is_standalone), f)
        if unsourceable_reason:
            self.seen_files.add(seen_key)
            self.fate(f, "unsourceable")
            row = {
                "name": fname,
                # Where the file goes once found, as a gap row says it.
                "path": effective_path,
                "required": f.get("required", False),
                "reason": unsourceable_reason,
                "source_ref": f.get("source_ref", ""),
                **declared_as(f, fname),
            }
            self.unsourceable_list.append(row)
            self.set_records.append((keys, f, False, self.unsourceable_list, row))
            return

        if outside_gap_scope(f, is_standalone):
            self.fate(f, "outside_scope")
            return

        archive = f.get("archive")

        # Check platform declaration: by name, by an alias the core answers
        # to (RetroArch lists amiberry's cd32.rom as kick40060.CD32), or by
        # archive.
        # A platform declares files of its BIOS tree: none answers for one
        # the core reads below the save directory.
        in_platform = not save_root and f.get("root") not in OUTER_ROOTS and declaration_settles(
            f, fname, self.platform_names, effective_path,
            self.index.get("folded_slots", frozenset()),
            self.index.get("declared_contents"),
        )

        if in_platform:
            self.seen_files.add(seen_key)
            self.fate(f, "declared")
            self.set_records.append((keys, f, True, None, None))
            self.covered.append({
                "name": fname,
                "path": effective_path,
                "required": f.get("required", False),
                "in_platform": True,
            })
            return

        self.seen_files.add(seen_key)
        self.fate(f, "undeclared")

        if archive:
            self._archive_gap(f, archive, is_standalone)
            return
        self._loose_gap(f, fname, is_standalone, save_root, effective_path, slot, keys)

    def _archive_gap(self, f: dict, archive: str, is_standalone: bool) -> None:
        archive_key = (
            archive,
            f.get("system"),
            f.get("selection_slot"),
            f.get("mode", "both"),
        )
        if archive_key not in self.archive_gaps:
            source = _resolve_archive_source(
                archive, self.index["by_name"], self.index["by_name_lower"],
                self.index["data_names"], self.index["by_path_suffix"],
            )
            self.archive_gaps[archive_key] = {
                "name": archive,
                "path": archive,
                "required": False,
                "note": "",
                "source_ref": "",
                "in_platform": False,
                "in_repo": source != "missing",
                "source": source,
                "archive": archive,
                "archive_file_count": 0,
                "archive_required_count": 0,
            }
        entry = self.archive_gaps[archive_key]
        if entry["archive_file_count"] == 0:
            # The archive's own declaration names its sets: an archive
            # is a member like a loose file (Kronos' stvbios.zip).
            own = archive_entry(archive, self.profile.get("files", []))
            # Without a declaration of its own, the archive is what its
            # members are.
            entry.update(declared_as(
                {**own, "category": own.get("category") or f.get("category")}, archive))
            self.set_records.append((
                set_keys((self.emu_name, is_standalone), own), own,
                entry["in_repo"], self.archive_rows, entry,
            ))
            self.archive_rows.append(entry)
        entry["archive_file_count"] += 1
        if f.get("required", False):
            entry["archive_required_count"] += 1
            entry["required"] = True
        if not entry["source_ref"] and f.get("source_ref"):
            entry["source_ref"] = f["source_ref"]

    def _loose_gap(
        self, f: dict, fname: str, is_standalone: bool, save_root: bool,
        effective_path: str, slot: tuple, keys: tuple,
    ) -> None:
        emu_name = self.emu_name
        platform = self.platform
        # --- resolve source provenance ---
        # A release asset is held when the database records it, as any other
        # file: storage says where the bytes are served from, not that the
        # collection has them (kenji-nx's user-picked firmware package).
        source = next(
            (
                found for version in self.versions[slot]
                if (found := entry_source(
                    {**version, "source_profile": emu_name}, self.index,
                )) is not None
            ),
            "missing",
        )
        if source != "missing" and f.get("storage", "") in ("release", "large_file"):
            source = "large_file"

        in_repo = source != "missing"

        entry = {
            "name": fname,
            "path": effective_path,
            "required": f.get("required", False),
            "bundled": (installed_with_emulator(f, platform) if platform
                        else installed_everywhere(f)),
            "note": f.get("note", ""),
            "source_ref": f.get("source_ref", ""),
            "in_platform": False,
            "in_repo": in_repo,
            "source": source,
            # What tells this file from a homonym another emulator wants.
            "identity": first_hash(f),
            **declared_as(f, fname),
        }
        if save_root:
            entry["root"] = "save"
        elif f.get("unplaced"):
            entry["unplaced"] = f["unplaced"]
        elif f.get("root") in OUTER_ROOTS:
            entry["root"] = f["root"]
        elif self.index.get("launcher_candidates") is not None:
            # What verify hands the launcher layer for the same entry.
            probe = {
                **f,
                "profile": emu_name,
                "emulator": self.profile.get("emulator", emu_name),
                "path": effective_path,
                "in_repo": in_repo,
                "bundled": entry["bundled"],
            }
            self.index["launcher_candidates"].append(
                (emu_name, is_standalone, f, probe, entry)
            )
        self.gaps.append(entry)
        self.set_records.append((keys, f, in_repo, self.gaps, entry))

    def settle(self) -> None:
        # One need per set: a member another one fills is not a gap, and a set
        # nobody holds is one gap under its first member (alternatives.py), as
        # verify and the packs count it.
        # Archive units rank first among equals, as the builder orders them.
        grouped = sorted(
            (r for r in self.set_records if r[0]), key=lambda r: r[3] is not self.archive_rows
        )
        requirements = set_requirements(self.profile)
        excused, standing = settle_sets(
            [(keys, f, fills) for keys, f, fills, _l, _r in grouped],
            lambda key: requirements.get(key[1], True),
        )
        for at, (_keys, member, _fills, rows, set_row) in enumerate(grouped):
            if set_row is None or rows is None:
                continue
            if at in standing:
                set_row["alternatives"] = standing[at].others
                set_row["required"] = standing[at].required
            if at in excused:
                rows.remove(set_row)
                if id(member) in self.position:
                    self.fates[self.position[id(member)]] = "other_versions"

        for ag in sorted(self.archive_gaps.values(), key=lambda e: e["name"]):
            if any(ag is row for row in self.archive_rows):
                self.gaps.append(ag)

    def summary(self) -> dict:
        tally = Counter(self.fates.values())
        profile = self.profile
        return {
            "emulator": profile.get("emulator", self.emu_name),
            "systems": profile.get("systems", []),
            "total_files": len(profile.get("files", [])),
            "platform_covered": len(self.covered),
            **_gap_counts(self.gaps),
            "gap_details": self.gaps,
            "unsourceable": self.unsourceable_list,
            # Entries, not rows: an archive's members are one gap row.
            "declared_files": tally["declared"],
            "undeclared_files": tally["undeclared"],
            "unsourceable_files": tally["unsourceable"],
            "set_aside": {key: tally[key] for key in SET_ASIDE},
        }


def _cross_reference_profile(
    emu_name: str,
    profile: dict,
    declared: dict[str, set[str]],
    report: dict,
    index: dict,
    standalone_cores: PlatformLaunches | None = None,
    platform: str = "",
) -> None:
    """Compare one emulator profile against what the platforms declare.

    *platform* is the platform key under --platform, empty for the whole
    tree. It decides, through the functions verify reads, which entries the
    platform's launcher never opens and which ones its emulator package
    already installs.

    Split out of cross_reference, where it was a 200-line loop body that
    carried the whole function's branching: every file is resolved by name,
    by path, by hash and by archive membership before it can be called a
    gap. *index* carries the database lookups those steps share.
    """
    all_declared = index["all_declared"]
    systems = profile.get("systems", [])

    # Skip filename-agnostic profiles (BIOS detected without fixed names)
    if profile.get("bios_mode") == "agnostic":
        return

    if all_declared is not None:
        platform_names = all_declared
    else:
        platform_names = set()
        for sys_id in systems:
            platform_names.update(declared.get(norm_system_id(sys_id), set()))

    # The build a platform runs decides which entries it reads, as in
    # find_undeclared_files: without a platform, the libretro build.
    layouts = platform_layouts(emu_name, profile, standalone_cores or PlatformLaunches())
    comparison = _ProfileComparison(emu_name, profile, index, platform_names, platform, layouts)
    # Each file under each layout the platform gives the emulator: both, for
    # one it launches as a libretro core and standalone.
    layout_files = [(f, standalone) for view, standalone in layouts for f in view.get("files", [])]

    # The entries of one profile on one slot are the versions its code
    # accepts there (raze's ten DUKE3D.GRP): holding any of them fills the
    # slot, as verify --emulator credits it.
    for f, is_standalone in layout_files:
        comparison.versions.setdefault(slot_key(f, is_standalone), []).append(f)

    # What became of each entry, so the heading adds up: a file a platform
    # declares, one it does not, or one set aside and why. An entry read by
    # two builds keeps the first answer that compares it. Each layout lists
    # the profile's entries in their order, so a position names one entry.
    comparison.position = {
        id(f): i for view, _ in layouts for i, f in enumerate(view.get("files", []))
    }

    for f, is_standalone in layout_files:
        comparison.compare(f, is_standalone)
    comparison.settle()
    report[emu_name] = comparison.summary()


def _gap_counts(gaps: list[dict]) -> dict[str, int]:
    """The per-source tallies of a profile's gap rows."""
    return {
        "gaps": len(gaps),
        "gap_in_repo": sum(1 for g in gaps if g["in_repo"]),
        "gap_missing": sum(1 for g in gaps if g["source"] == "missing"),
        "gap_bios": sum(1 for g in gaps if g["source"] == "bios"),
        "gap_data": sum(1 for g in gaps if g["source"] == "data"),
        "gap_large_file": sum(1 for g in gaps if g["source"] == "large_file"),
    }


def _settle_launcher_places(
    report: dict,
    candidates: list[tuple[str, bool, dict, dict, dict]],
    layer: LauncherLayer,
    db: dict,
) -> None:
    """Apply the platform's launcher places as find_undeclared_files does.

    Batocera's DuckStation generator fills the PAL slot with scph5502.bin,
    yet the report listed duckstation's scph1002a.bin as a file the pack
    carries, which neither the pack nor the manifest does.
    """
    added, settled = layer.settle(
        [(emu, standalone, f, probe) for emu, standalone, f, probe, _ in candidates],
        lambda probe: held_record(probe, db),
    )
    for emu, _standalone, _f, probe, gap in candidates:
        if id(probe) not in settled:
            continue
        data = report[emu]
        data["gap_details"] = [g for g in data["gap_details"] if g is not gap]
        data["undeclared_files"] -= 1
        data["set_aside"]["launcher"] += 1
    for entry in added:
        data = report[entry["profile"]]
        data["gap_details"].append({
            "name": entry["name"],
            "path": entry["path"],
            "required": entry.get("required", False),
            "bundled": False,
            "note": "",
            "source_ref": "",
            "in_platform": False,
            "in_repo": True,
            "source": "bios",
            "identity": entry.get("sha1") or "",
            "launcher": entry["launcher"],
            "launcher_of": entry["launcher_of"],
            # The entry the launcher's name stands for, under that name.
            **declared_as(entry, entry["path"]),
        })
    for data in report.values():
        data.update(_gap_counts(data["gap_details"]))



class ReportScope(TypedDict, total=False):
    """What a cross_reference run compares against and answers for."""

    all_declared: dict[str, list[tuple[int | None, str]]] | None
    standalone_cores: PlatformLaunches | None
    folded_slots: frozenset[str]
    platform: str
    launcher_layer: LauncherLayer | None
    declared_contents: dict[str, set[str]] | None


def cross_reference(
    profiles: dict[str, dict],
    declared: dict[str, set[str]],
    db: dict,
    data_names: SupplementalIndex | None = None,
    **scope: Unpack[ReportScope],
) -> dict:
    """Compare emulator profiles against platform declarations.

    Returns a report with gaps (files emulators need but platforms don't list)
    and coverage stats.  Each gap entry carries a ``source`` field indicating
    where the file is available: ``"bios"`` (bios/ via database.json),
    ``"data"`` (data/ directory), ``"large_file"`` (GitHub release asset),
    or ``"missing"`` (not available anywhere).

    The boolean ``in_repo`` is derived: ``source != "missing"``.

    When *all_declared* is provided (every filename declared by any platform
    for any system, with its sizes and slots), it is used for the ``in_platform`` check
    instead of the per-system lookup.  This is appropriate for the global
    gap analysis page where "undeclared" means "no platform declares it at all".
    """
    unknown = sorted(set(scope) - set(ReportScope.__annotations__))
    if unknown:
        raise TypeError(f"cross_reference() got an unexpected keyword argument '{unknown[0]}'")
    all_declared = scope.get("all_declared")
    standalone_cores = scope.get("standalone_cores")
    folded_slots = scope.get("folded_slots", frozenset())
    platform = scope.get("platform", "")
    launcher_layer = scope.get("launcher_layer")
    declared_contents = scope.get("declared_contents")
    report: dict[str, dict] = {}

    index = {
        **entry_index(db, data_names),
        "all_declared": all_declared,
        "folded_slots": folded_slots,
        "declared_contents": declared_contents,
        "launcher_candidates": [] if launcher_layer else None,
    }
    for emu_name, profile in profiles.items():
        _cross_reference_profile(
            emu_name, profile, declared, report, index, standalone_cores,
            platform,
        )
    if launcher_layer:
        _settle_launcher_places(report, index["launcher_candidates"], launcher_layer, db)

    return report
