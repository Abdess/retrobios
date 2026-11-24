"""What the cores need that the platform does not declare.

A pack is the platform's own list plus the files its cores load. The
second half is derived here, and the region pass reads the grouping
this module builds so the report and the pack withdraw the same files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from core.options import reject_unknown
from model.profiles import PROFILE_IDENTITY_FIELDS, entry_system_ids, lists_files
from model.alternatives import set_fields
from resolve.archives import contents_members, holds_required_members
from model.declarations import declared_root, expand_platform_declared_names, platform_declarations
from model.profiles import core_key, core_key_index, load_emulator_profiles
from resolve.localfile import resolution_is_hash_exact
from resolve.localfile import resolve_local_file
from resolve.cores import resolve_platform_cores
from resolve.standalone import platform_layouts
from resolve.standalone import platform_launches
from model.declarations import OUTER_ROOTS
from core.paths import sanitize_pack_path
from resolve.entryscope import deliverable, read_by_build, read_from_system_dir
from packs.gaps import gap_destination

if TYPE_CHECKING:
    from typing_extensions import Unpack
from packs.extraplace import (
    ExtraPlacement,
    another_claim,
    archive_prefix_extras,
    extra_dest,
    prefixed_destination,
    take,
)
from packs.extrascan import agnostic_scan_extras


def undeclared_report(
    config: dict,
    emulators_dir: str,
    db: dict,
    emu_profiles: dict | None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
) -> list[dict]:
    """The gap report collect_emulator_extras reads, for a caller that
    collects the extras more than once with these arguments: the region
    grouping and the pack or manifest phase 2 each computed it in full."""
    from packs.gaps import find_undeclared_files

    return find_undeclared_files(
        config, emulators_dir, db, emu_profiles, target_cores=target_cores,
        include_all=include_all,
        declared_names=platform_declarations(config, db, enrich=False),
    )


class CollectOptions(TypedDict, total=False):
    """The records collect_emulator_extras fills, and the report it reuses."""

    claimants: dict[tuple[str, str, str], str] | None
    unplaceable: list[dict] | None
    baseline_claims: dict[str, dict] | None
    absent: list[dict] | None
    undeclared: list[dict] | None


@dataclass
class _FirstPass:
    """The state the gap report's pass threads through its entries."""

    config: dict
    placement: ExtraPlacement
    rank: _ClaimRanks
    seen_dests: set[str]
    # Destination -> the extra that took it, to record later claimants on.
    taken: dict[str, dict]
    claimants: dict[tuple[str, str, str], str] | None
    unplaceable: list[dict] | None
    absent: list[dict] | None
    extras: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class _CopyScope:
    """What the second pass reads to copy a covered file to another path."""

    config_key: str
    covered_names: set[str]
    platform_names: set[str]
    seen: set
    seen_dests: set[str]
    taken: dict[str, dict]
    copied: dict[str, list[dict]]
    by_name: dict
    by_path_suffix: dict
    extras_prefix: str


def collect_emulator_extras(
    config: dict,
    emulators_dir: str,
    db: dict,
    seen: set,
    base_dest: str,
    emu_profiles: dict | None = None,
    target_cores: set[str] | None = None,
    include_all: bool = False,
    **options: Unpack[CollectOptions],
) -> list[dict]:
    """Collect core requirement files from emulator profiles not in the platform pack.

    ``undeclared`` is the gap report when the caller already holds it,
    computed with the same arguments (verify's own pass).

    ``absent`` receives, placed like the others, the entries the collection
    does not hold: the region pass groups them as it groups the platform's
    own missing files, so the report withdraws the ones a request excludes.

    ``baseline_claims`` receives, for each destination in ``seen``, the core
    claims made on it: a pack built for a target that drops the platform's
    system frees the destination, and the first core claiming it fills it.

    ``claimants`` receives the destination of every report entry that
    asked for one, the ones a sibling already took included: the region
    report withdraws by that key, and an entry without one stayed listed
    after the builder had withdrawn its destination. ``unplaceable``
    receives the entries a slug-based platform cannot place, so the
    manifest and the report can say so instead of counting them packed.

    Uses the same system-overlap matching as verify.py cross-reference:
    - Matches emulators by shared system IDs with the platform
    - Filters mode: standalone, type: launcher, type: alias
    - Respects data_directories coverage
    - Only returns files that exist in the repo (packable)

    When the same file is needed at multiple destinations by different cores
    (e.g. cdimono1.zip at root for cdi2015 and at same_cdi/bios/ for same_cdi),
    all destinations are included so every core finds its files.

    Works for ANY platform (RetroArch, Batocera, Recalbox, etc.)
    """
    reject_unknown("collect_emulator_extras", options, CollectOptions.__optional_keys__)
    undeclared = options.get("undeclared")
    claimants = options.get("claimants")
    unplaceable = options.get("unplaceable")
    absent = options.get("absent")
    baseline_claims = options.get("baseline_claims")
    profiles = (
        emu_profiles
        if emu_profiles is not None
        else load_emulator_profiles(emulators_dir)
    )

    # Detect destination conventions for core extras
    placement = ExtraPlacement(config, base_dest, profiles)
    extras_prefix = placement.prefix

    if undeclared is None:
        undeclared = undeclared_report(
            config, emulators_dir, db, emu_profiles, target_cores, include_all
        )
    # A destination two cores claim goes to the strongest proof of what the
    # collection holds for it, then to the one that names its content:
    # hypseus-singe asks for gamecontrollerdb.txt by name alone and took the
    # BIOS root before Solarus, which pins its own by sha1, and fbalpha2012's
    # hashless hiscore.dat took RetroDECK's over mame2015's sha1. Profile
    # order decides only between claims of equal proof.
    undeclared = sorted(undeclared, key=lambda u: not _names_content(u))
    rank = _ClaimRanks(
        undeclared, placement, db, bool(config.get("case_insensitive_fs", False))
    )
    undeclared = rank.ordered(undeclared)
    state = _FirstPass(
        config, placement, rank, set(seen), {}, claimants, unplaceable, absent,
    )
    if baseline_claims is not None:
        for destination in seen:
            state.taken[destination] = baseline_claims.setdefault(destination, {})
    for u in undeclared:
        _place_report_entry(state, u)
    extras = state.extras

    # Second pass: find alternative destinations for files already in the pack.
    # A file declared by the platform or emitted above may also be needed at a
    # different path by another core (e.g. neocd/ vs root, same_cdi/bios/ vs root).
    # Only adds a copy when the file is ALREADY covered at a different path -
    # never introduces a file that wasn't selected by the first pass.
    #
    # Skip for slug-based platforms (RomM): alternative paths don't map to
    # the required {platform_slug}/{file} structure.
    if placement.slug_based:
        return extras

    relevant = resolve_platform_cores(config, profiles, target_cores=target_cores)
    launches = platform_launches(config, profiles)
    by_name = db.get("indexes", {}).get("by_name", {})

    # Build set of filenames already covered (platform baseline + first pass extras)
    # Enriched with canonical names from DB via MD5 (handles platform renaming)
    platform_names = expand_platform_declared_names(config, db)
    covered_names = set(platform_names)
    for e in extras:
        covered_names.add(e["name"])

    # Destination -> the copies cores ask for there, in profile order.
    scope = _CopyScope(
        config.get("_key", ""), covered_names, platform_names, seen, state.seen_dests,
        state.taken, {}, by_name, db.get("indexes", {}).get("by_path_suffix", {}),
        extras_prefix,
    )
    for emu_name, profile in sorted(profiles.items()):
        if not lists_files(profile):
            continue
        if emu_name not in relevant:
            continue
        for layout, is_standalone in platform_layouts(emu_name, profile, launches):
            for f in layout.get("files", []):
                copy = _second_pass_copy(scope, emu_name, layout, is_standalone, f)
                if copy is not None:
                    scope.copied.setdefault(copy[0], []).append(copy[1])

    # Several cores reading one archive in one roms folder: the copy of the
    # core the folder starts by default goes first, then the copy serving
    # the most of them. Five cores AmberELEC offers for roms/arcade read
    # neogeo.zip there, and the copy holding the 18 members its default
    # MAME 2003-Plus requires also holds the 3 MAME 2000 requires.
    defaults = _folder_defaults(config, profiles)
    for full_dest, claims in scope.copied.items():
        if len(claims) > 1:
            claims = sorted(claims, key=lambda c: (
                not _starts_by_default(c, defaults), -_copy_serves(c, claims, db),
            ))
        extras.extend(
            extra for extra in claims
            if take(extra, full_dest, state.seen_dests, state.taken)
        )

    extras.extend(
        archive_prefix_extras(
            profiles, relevant, covered_names, state.seen_dests, extras_prefix,
            by_name, state.taken, launches,
        )
    )

    extras.extend(
        agnostic_scan_extras(
            profiles, relevant, db, by_name, state.seen_dests, extras_prefix,
            launches, state.taken,
        )
    )

    return extras


def _place_report_entry(state: _FirstPass, u: dict) -> None:
    """First pass: place one gap report entry, or record why it is not."""
    if u.get("bundled"):
        # Installed with the emulator for this build: already on the
        # user's machine. The mode a file is bundled for was settled
        # upstream, an entry scoped to another build never gets here.
        return
    if u.get("unplaced"):
        # Read in a folder outside the BIOS tree: named, held or not,
        # never written where the emulator does not read it.
        if state.unplaceable is not None:
            state.unplaceable.append({**u, "unplaceable": u["unplaced"]})
        return
    absent = state.absent
    if not u["in_repo"] and absent is None:
        return
    # For archive entries, use the archive name for resolution
    archive = u.get("archive")
    name = archive if archive else u["name"]
    dest = extra_dest(u)

    # Slug-based platforms: prefix dest with system slug. A file read
    # below a save directory kept per system goes below each system.
    placement = state.placement
    placements = placement.places(u, dest)
    save_root = u.get("root") == "save"
    if not u["in_repo"]:
        # Each core reading it is named on the omission: a list built
        # without the first reader still has to say the file is missing.
        if absent is not None:
            for placed in placements:
                for claim in (u, *u.get("other_claims", [])):
                    missing = _report_extra(claim, name, placed[0])
                    if save_root:
                        _save_fields(missing, placed[1], placement)
                    absent.append(missing)
        return
    if not placements:
        if state.unplaceable is not None:
            reason = placement.unplaced_reason(u, dest)
            state.unplaceable.append(
                u if reason == "no_platform_slug" else {**u, "unplaceable": reason}
            )
        return
    if state.claimants is not None:
        # Keyed as extra_region_key keys the extra that wins the path: a
        # losing claim kept the bare path, and on RetroDECK (declared
        # root bios/) verify --region listed Rustation's scph1002b.bin
        # as packed while the builder had withdrawn bios/scph1002b.bin.
        state.claimants[(u.get("emulator", ""), u.get("name", ""), u.get("path") or "")] = (
            prefixed_destination(
                sanitize_pack_path(placements[0][0]), declared_root(state.config)
            )
        )
    for dest, full_dest in placements:
        _claim_placement(state, u, name, dest, full_dest, save_root)


def _claim_placement(
    state: _FirstPass, u: dict, name: str, dest: str, full_dest: str, save_root: bool,
) -> None:
    """Race the entry's claims for one of its destinations."""
    candidates = [
        _report_extra(c, name, dest) for c in (u, *u.get("other_claims", []))
    ]
    if save_root:
        for item in candidates:
            _save_fields(item, full_dest, state.placement)
    # Where the builder meets each claim: the strongest proof first, the
    # report's profile order between equals, archives after loose files.
    for item in candidates:
        item["claim_order"] = (
            1, 1 if u.get("archive") else 0, -state.rank.of_extra(item, full_dest),
            item["source_profile"],
        )
    candidates.sort(key=lambda item: item["claim_order"])
    extra, claims = candidates[0], candidates[1:]
    if not take(extra, full_dest, state.seen_dests, state.taken):
        for claim in claims:
            another_claim(state.taken.get(full_dest), claim)
        return
    for claim in claims:
        another_claim(extra, claim)
    state.extras.append(extra)


def _copies_entry(f: dict, is_standalone: bool, scope: _CopyScope) -> bool:
    """Whether the second pass may copy this layout entry to its own path."""
    fname = f.get("name", "")
    if not fname:
        return False
    # Only duplicate files already covered at another destination.
    # An unsourceable entry is a file no collection holds: the name
    # covered elsewhere belongs to another program's file.
    # Nor is one placed outside the BIOS tree by the layout.
    if (fname not in scope.covered_names or f.get("unsourceable") or f.get("unplaced")
            or f.get("root") in OUTER_ROOTS):
        return False
    # Installed with the emulator or by the platform's package,
    # as the first pass already decided for the same entry.
    if not deliverable([f], is_standalone, scope.config_key):
        return False
    # A member of an archive is read inside it, never as a loose
    # file. The archive itself is placed by the passes above.
    if f.get("archive"):
        return False
    # No path: the core reads it from nowhere a pack reaches
    # (Dolphin's codehandler.bin ships in its Sys tree).
    if "path" in f and f["path"] is None:
        return False
    if not read_by_build(f, is_standalone):
        return False
    return read_from_system_dir(f, is_standalone)


def _second_pass_copy(
    scope: _CopyScope, emu_name: str, layout: dict, is_standalone: bool, f: dict,
) -> tuple[str, dict] | None:
    """(full destination, extra) of a covered file this core reads elsewhere."""
    if not _copies_entry(f, is_standalone, scope):
        return None
    fname = f.get("name", "")
    raw = gap_destination(f, fname, is_standalone, False)
    dest = f"{raw}{fname}" if raw.endswith("/") and not fname.endswith("/") else raw
    # A bare name is a destination too: the core reads it at the root
    # of the directory core files go to, which the platform may not
    # declare (Recalbox has its System Cards under pcenginecd/ only,
    # geargrafx reads them from the root).
    # A path of the install tree outside the BIOS folder keeps no
    # prefix: EmuELEC's dolphin/dolphin-emu/GBA/gba_bios.bin.
    full_dest = (
        sanitize_pack_path(dest) if f.get("unprefixed")
        else prefixed_destination(dest, scope.extras_prefix)
    )
    if full_dest in scope.seen_dests and full_dest not in scope.taken:
        return None
    if (full_dest in scope.taken or full_dest in scope.copied) and full_dest not in scope.seen \
            and fname not in scope.platform_names:
        # Another core's extra holds this path and only that
        # extra covers the name: a pack without that core never
        # reaches this copy, so this core claims nothing here.
        # Batocera's launcher hands DuckStation one named BIOS;
        # recorded on duckstation-legacy's scph100.bin, its claim
        # kept the file for a target without legacy.
        return None
    # Only files the database indexes: members of a data
    # directory are not in it and are not duplicated here.
    if not (
        scope.by_name.get(fname)
        or scope.by_name.get(dest.rsplit("/", 1)[-1])
        or scope.by_path_suffix.get(dest)
    ):
        return None
    return full_dest, _copy_extra(f, layout, emu_name, dest, raw)


def _copy_extra(f: dict, layout: dict, emu_name: str, dest: str, raw: str) -> dict:
    """The extra the second pass emits for a copy."""
    fname = f.get("name", "")
    extra = {
        "name": fname,
        "destination": dest,
        "required": f.get("required", False),
        "hle_fallback": f.get("hle_fallback", False),
        "source_emulator": layout.get("emulator", emu_name),
        "source_profile": emu_name,
        # The key the gap report gives the same entry.
        "source_name": fname,
        "source_path": raw,
        "category": f.get("category", "bios"),
        "source_system": f.get("system"),
        "source_systems": entry_system_ids(f, layout),
        "region": f.get("region"),
        "selection_slot": f.get("selection_slot"),
        **set_fields(f, layout),
    }
    # The same identity the first pass carries: without it the copy
    # resolves on its name alone and a same-named file of another
    # game fills the slot the profile marks as not held.
    for identity in PROFILE_IDENTITY_FIELDS:
        if f.get(identity) not in (None, "", []):
            extra[identity] = f[identity]
    if f.get("contents"):
        extra["contents"] = f["contents"]
    if f.get("system_dir"):
        extra["system_dir"] = f["system_dir"]
    if f.get("unprefixed"):
        extra["unprefixed"] = True
    # A copy placed outside the BIOS tree resolves by its layout
    # path alone, as the first pass does: EmuELEC's
    # roms/mame/stvbios.zip took bios/Arcade/MAME's set by that tail.
    if f.get("layout_path"):
        extra["layout_path"] = f["layout_path"]
    extra["claim_order"] = (2, 0, emu_name)
    return extra


class _ClaimRanks:
    """How strongly each claim on a contested destination proves its file.

    2 a declared hash the collection holds, 1 a path or every member the
    core requires inside an archive, 0 a name, -1 a copy
    contradicting the hash the claim declares, -2 nothing held. Resolved only
    where two claims meet: a destination one core asks for has no contest.
    """

    def __init__(
        self, undeclared: list[dict], placement: ExtraPlacement, db: dict, fold: bool,
    ) -> None:
        self._db = db
        # Two spellings of one path are one file where the filesystem folds case.
        self._key = (lambda dest: dest.lower()) if fold else (lambda dest: dest)
        # An entry can take several destinations: one per system folder of a
        # save directory kept per system.
        self._placed: dict[int, list[tuple[str, str]]] = {}
        counts: dict[str, int] = {}
        for u in undeclared:
            placed = (
                placement.places(u, extra_dest(u))
                if u.get("in_repo") and not u.get("bundled") else []
            )
            self._placed[id(u)] = placed
            for _dest, full in placed:
                key = self._key(full)
                counts[key] = counts.get(key, 0) + 1 + len(u.get("other_claims", []))
        self._contested = {dest for dest, n in counts.items() if n > 1}
        self._cache: dict[tuple, int] = {}

    def _contests(self, u: dict) -> list[tuple[str, str]]:
        """The entry's destinations another claim also asks for."""
        return [
            placed for placed in self._placed.get(id(u), [])
            if self._key(placed[1]) in self._contested
        ]

    def of_extra(self, extra: dict, full_dest: str) -> int:
        if self._key(full_dest) not in self._contested:
            return 0
        key = (extra.get("source_profile"), extra.get("source_name"),
               extra.get("source_path"), full_dest)
        if key not in self._cache:
            path, status = resolve_local_file(
                extra, self._db, dest_hint=extra.get("destination", "")
            )
            self._cache[key] = (
                -2 if not path
                else -1 if status == "hash_mismatch"
                else 2 if resolution_is_hash_exact(status)
                else 1 if status == "path_exact" or (
                    extra.get("members") and holds_required_members(path, extra["members"])
                )
                else 0
            )
        return self._cache[key]

    def ordered(self, undeclared: list[dict]) -> list[dict]:
        """The entries in their order, the claims on one contested path
        reordered among themselves by proof. Nothing else moves, so the
        pack and the manifest keep their order."""
        first: dict[str, int] = {}
        keys: list[tuple[int, int, int]] = []
        for position, u in enumerate(undeclared):
            contests = self._contests(u)
            if not contests:
                keys.append((position, 0, position))
                continue
            group = first.setdefault(self._key(contests[0][1]), position)
            keys.append((group, -self.of_entry(u), position))
        order = sorted(range(len(undeclared)), key=keys.__getitem__)
        return [undeclared[i] for i in order]

    def of_entry(self, u: dict) -> int:
        contests = self._contests(u)
        if not contests:
            return 0
        name = u.get("archive") or u["name"]
        return max(
            self.of_extra(_report_extra(c, name, dest), full)
            for dest, full in contests
            for c in (u, *u.get("other_claims", []))
        )


def _folder_defaults(config: dict, profiles: dict) -> dict[str, set[str]]:
    """Roms folder -> the profiles its default core or emulator names."""
    by_key = core_key_index(profiles, include_aliases=True)
    out: dict[str, set[str]] = {}
    for row in config.get("_rom_folders") or []:
        chosen = {str(row.get("core") or ""), str(row.get("emulator") or "")} - {""}
        out[str(row.get("folder"))] = {
            name for c in chosen for name in by_key.get(core_key(c), ())
        }
    return out


def _starts_by_default(extra: dict, defaults: dict[str, set[str]]) -> bool:
    """Whether the extra's core is the one its roms folder starts by default."""
    layout = str(extra.get("layout_path") or "")
    destination = str(extra.get("destination") or "")
    if not layout or not destination.endswith("/" + layout):
        return False
    folder = destination[: -len(layout) - 1].removeprefix("roms/")
    return extra.get("source_profile") in defaults.get(folder, set())


def _copy_serves(extra: dict, claims: list[dict], db: dict) -> int:
    """How many of the claims on one path the copy an extra resolves to
    holds every required member of."""
    wanted = [members for c in claims if (members := contents_members(c))]
    if not wanted:
        return 0
    path, _status = resolve_local_file(extra, db, dest_hint=extra.get("destination", ""))
    if not path:
        return 0
    return sum(1 for members in wanted if holds_required_members(path, members))


def _names_content(entry: dict) -> bool:
    """Whether a report entry declares the bytes it wants, not only a name.

    The claims folded onto the entry count: bsnes asks for SGB1.sfc by name
    and bsnes-hd pins its md5 under the same system, and the entry carrying
    both went after nSide's SGB1.sfc/ tree, which took the path from the file.
    """
    return any(
        claim.get(field)
        for claim in (entry, *entry.get("other_claims", []))
        for field in ("sha1", "md5", "sha256", "crc32")
    )


def _save_fields(extra: dict, pack_path: str, placement: ExtraPlacement) -> None:
    """Record where a file read below the save directory goes in the pack.

    ``core_folder`` stays only where the frontend sorts saves by core for
    every core, the one setting a frontend config can turn off and the
    installer then reads (RetroArch's sort_savefiles_enable). A launcher
    writing the save directory at each launch fixes the path the pack
    already spells out.
    """
    extra["pack_path"] = pack_path
    if placement.save is not None:
        # The path below the save directory, what the manifest writes.
        extra["save_dest"] = pack_path[len(placement.save.in_pack) + 1:]
        if not placement.save.by_core:
            extra.pop("core_folder", None)


def _report_extra(u: dict, name: str, dest: str) -> dict:
    """The extra a cross-reference entry asks for at its destination."""
    extra = {
        "name": name,
        "destination": dest,
        "required": u.get("required", False),
        "hle_fallback": u.get("hle_fallback", False),
        "source_emulator": u.get("emulator", ""),
        "source_profile": u.get("profile", ""),
        # Identity of the report entry this extra came from.  The name
        # alone does not identify it: Dolphin declares three IPL.bin that
        # differ only by path, and collapsing them onto one key withdraws
        # the wrong regional variant from the report.
        "source_name": u.get("name", ""),
        "source_path": u.get("path") or "",
        "category": u.get("category", "bios"),
        "source_system": u.get("system"),
        "source_systems": u.get("systems", []),
        "region": u.get("region"),
        "selection_slot": u.get("selection_slot"),
        **{k: u[k] for k in ("required_groups", "set_declared") if k in u},
    }
    if u.get("members"):
        extra["members"] = u["members"]
    if u.get("root") == "save":
        extra["root"] = "save"
        if u.get("core_folder") is not None:
            extra["core_folder"] = u["core_folder"]
    elif u.get("root") in OUTER_ROOTS:
        extra["root"] = u["root"]
    if u.get("system_dir"):
        extra["system_dir"] = u["system_dir"]
    if u.get("layout_path"):
        extra["layout_path"] = u["layout_path"]
    if u.get("unprefixed"):
        extra["unprefixed"] = True
    # The archive layout the core opens ranks same-named copies by what
    # they hold. Without it the first copy indexed won.
    if u.get("contents"):
        extra["contents"] = u["contents"]
    # Keep every reproducible identity constraint carried by the source
    # profile.  Some profiles expose CRC32/SHA-256 only through their
    # validation block, and dropping those fields here would let a same-named
    # but different payload enter a generated pack.
    expected = u.get("expected") or {}
    for identity in PROFILE_IDENTITY_FIELDS:
        declared = u.get(identity)
        if declared in (None, "", []):
            declared = expected.get(identity)
        if declared not in (None, "", []):
            extra[identity] = declared
    return extra
