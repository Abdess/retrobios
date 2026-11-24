"""The name stages of resolve_local_file: candidates by name, alias and case, an md5 under a name, zip contents."""

from __future__ import annotations

import functools
import os
import zipfile

from core.hashing import md5_composite
from core.memo import DerivedView
from core.ziptools import check_inside_zip
from resolve.archives import (
    contents_members,
    covering_archives,
    holding_members,
    warn_unreadable_archive,
)
from resolve.content import (
    content_fits,
    declared_hash_verdict,
    declares_shape,
    name_match_size_ok,
    shape_fits,
)
from resolve.datadirs import resolve_in_data_dirs
from resolve.lookup import Resolution, Lookup, name_size_ok
from resolve.ownership import (
    affinity_tokens,
    engine_tree,
    foreign_tree,
    maker_folder,
    makers_named_by,
    other_maker,
    owner_tokens,
)


def _fold_names(by_name: dict) -> dict[str, list[str]]:
    """A casefolded view of the by_name index."""
    folded: dict[str, list[str]] = {}
    for name, sha1s in by_name.items():
        folded.setdefault(name.casefold(), []).extend(sha1s)
    return folded


_casefold_name_index = DerivedView(_fold_names)


def _by_affinity(paths: list[str], file_entry: dict, dest_hint: str) -> list[str]:
    """Same-named candidates, the likeliest first.

    A name step without a tie-break took whichever path sorted first: the
    TheXTech coin.ogg for Syobon Action, a Hurrican sound for ARMSX2, the
    1 MB CM-32L PCM ROM for ScummVM's 512 KB MT32_PCM.ROM. A size the entry
    declares orders the candidates first (ordering rejects nothing, so an
    unvalidated size keeps its informative status). Then the destination's
    directories and the profile that asks name where its own copy lives. The
    order is otherwise kept.
    """
    if len(paths) < 2:
        return paths
    hint = dest_hint or file_entry.get("path") or file_entry.get("destination") or ""
    wanted = affinity_tokens(hint.rsplit("/", 1)[0] if "/" in hint else "")
    owners = owner_tokens(file_entry)
    sized = declares_shape(file_entry)

    def score(path: str) -> tuple[int, bool, bool, bool, int]:
        fits = 0
        if sized and os.path.exists(path):
            fits = int(shape_fits(file_entry, path))
        tokens = affinity_tokens(path.rsplit("/", 1)[0])
        # The owner's own copy ranks above any shared tree segment: NetherSX2's
        # shaders/common/ beat armsx2's own fxaa.fx on two directory tokens.
        # Another emulator's own tree ranks below everything else.
        # A game's folder under Game Engines/ holds that game's data: for a
        # name-only match, a neutral copy goes first. hypseus-singe,
        # flycast-dojo, lindbergh-loader and vvvvvv took C-Dogs' 98-line
        # gamecontrollerdb.txt by index order.
        return (
            fits, bool(owners & tokens), not foreign_tree(path, owners | wanted),
            not engine_tree(path, owners | wanted), len(wanted & tokens),
        )

    return sorted(paths, key=score, reverse=True)


def _exact_name_candidates(q: Lookup) -> list[str]:
    """The held files answering to the entry's names, exact casing."""
    candidates: list[str] = []
    # The entry's own names first, the destination's basename only when
    # none of them answers. melonDS Nightly's dsi_nand.bin is read at
    # dsi/nand.bin: with the DSi image absent from the checkout, the
    # basename let the Wii nand.bin outrank the entry's own DSi variant.
    # A name whose held file no declaration proves, while declarations
    # of that name prove another dump beside it, means that dump: the
    # DSi devkit boot ROMs filed as dsi_bios7.bin went to RetroBat.
    by_proven_name = q.db.get("indexes", {}).get("by_proven_name", {})
    for tier in (q.own_names, q.names_to_try[len(q.own_names):]):
        for try_name in tier:
            for match_sha1 in (
                by_proven_name.get(try_name) or q.by_name.get(try_name, [])
            ):
                if match_sha1 in q.files_db and name_size_ok(q, match_sha1):
                    path = q.files_db[match_sha1]["path"]
                    if os.path.exists(path) and path not in candidates:
                        candidates.append(path)
        if candidates:
            break
    return candidates


def _add_variant_primaries(q: Lookup, candidates: list[str]) -> None:
    """Add the primaries that variants answering the exact casing stand in for."""
    # Only variants answer the exact casing, but the primary they
    # stand in for may be stored under another one: x1 asked for
    # IPLROM.X1 and got Recalbox's second md5 while iplrom.x1, the
    # dump every platform pins, sat in the same directory. A primary
    # counts here only in a variant's own directory and under its own
    # file name: an alias (iplrom.x1t names a font in System.dat) or
    # another machine's font.rom is not that file.
    homes = {p.split("/.variants/", 1)[0] for p in candidates}
    folded = _casefold_name_index(q.by_name)
    for try_name in q.names_to_try:
        wanted = try_name.rsplit("/", 1)[-1].casefold()
        for match_sha1 in folded.get(try_name.casefold(), []):
            path = q.files_db.get(match_sha1, {}).get("path", "")
            if (
                "/.variants/" not in path
                and os.path.dirname(path) in homes
                and os.path.basename(path).casefold() == wanted
                and name_size_ok(q, match_sha1)
                and os.path.exists(path)
                and path not in candidates
            ):
                candidates.append(path)


def _add_casefold_candidates(q: Lookup, candidates: list[str], owners: set[str]) -> None:
    """Add the held files answering to the entry's names in another casing."""
    # Case-insensitive fallback: upstream platforms disagree on
    # casing (VEC_MineStorm.vec vs VEC_Minestorm.vec). Two casings
    # can name two contents (FONT.ROM and font.rom), so this only
    # runs when no casing matches exactly, or when only another
    # emulator's tree does: xm6typeg got XM6 Utility's synthesized
    # SCSIINROM.DAT while the X68000 dump sat as scsiinrom.dat.
    # Another casing in another emulator's tree proves nothing:
    # reminiscence's music module reunion took skyline's
    # zoneinfo/Indian/Reunion.
    folded = _casefold_name_index(q.by_name)
    for try_name in q.names_to_try:
        for match_sha1 in folded.get(try_name.casefold(), []):
            if match_sha1 in q.files_db and name_size_ok(q, match_sha1):
                path = q.files_db[match_sha1]["path"]
                if foreign_tree(path, owners):
                    continue
                if os.path.exists(path) and path not in candidates:
                    candidates.append(path)


def _same_maker(q: Lookup, candidates: list[str], makers: frozenset[str]) -> list[str]:
    """The candidates filed under the system's maker, or its shadowed aliases."""
    candidates = [p for p in candidates if not other_maker(p, makers, q.db)]
    if candidates:
        return candidates
    # The name belongs to another maker's file here. An emulator
    # of this system may still read it as an alias of one of its
    # own files, an alias by_name leaves out because a primary
    # already carries the name: QUASI88 reads DISK.ROM as
    # n88sub.rom.
    shadowed = q.db.get("indexes", {}).get("by_shadowed_alias", {})
    for try_name in q.own_names:
        for match_sha1 in shadowed.get(try_name, []):
            path = q.files_db.get(match_sha1, {}).get("path", "")
            if (
                maker_folder(path, str(q.db.get("bios_dir") or "bios"))
                in makers
                and name_size_ok(q, match_sha1)
                and os.path.exists(path)
                and path not in candidates
            ):
                candidates.append(path)
    return candidates


def _choose_by_name(
    q: Lookup,
    candidates: list[str],
    owners: set[str],
    exact_foreign: bool,
    data_dir_registry: dict | None,
) -> Resolution | None:
    """The best of the files a name step found, or the data directory's own."""
    if q.zipped_file:
        candidates = [p for p in candidates if ".zip" in os.path.basename(p)]
    members = q.file_entry.get("members") or contents_members(q.file_entry)
    if members or (len(candidates) > 1 and q.name.casefold().endswith(".zip")):
        # Another emulator's own copy takes no part in the ranking:
        # Demul's naomi.zip holds more NAOMI BIOS rows than any MAME
        # set and broke the superset the MAME cores were served.
        candidates = [
            p for p in candidates if not foreign_tree(p, owners)
        ] or candidates
    if members:
        candidates = holding_members(candidates, members)
    elif len(candidates) > 1 and q.name.casefold().endswith(".zip"):
        candidates = covering_archives(candidates)
    candidates = _by_affinity(candidates, q.file_entry, q.dest_hint)
    best = candidates[0] if candidates else ""
    # A copy outside another emulator's tree comes first: the
    # affinity read pcsx2 in bios/Other/armsx2/pcsx2/ and served
    # upstream PCSX2 the patches.zip of ARMSX2.
    candidates = [
        p for p in candidates if not foreign_tree(p, owners)
    ] or candidates
    primary = [p for p in candidates if "/.variants/" not in p]
    if not (primary or candidates):
        return None
    chosen = primary[0] if primary else candidates[0]
    # The best of them is another emulator's own copy, served or
    # set aside: the name says nothing about this profile's file,
    # and a data directory it reads may hold it. Dolphin got
    # Dolphin-MMJR's codehandler.bin while data/dolphin-sys held
    # its own, and blueMSX got the 16 KB RS232.ROM once msx-emu's
    # 8 KB copy was set aside, while data/bluemsx held its own,
    # and MSX2P.ROM of another dump once only msx-emu answered
    # the exact casing.
    if data_dir_registry and (exact_foreign or foreign_tree(best, owners)):
        hit, _mismatch = resolve_in_data_dirs(
            q.names_to_try, data_dir_registry,
            functools.partial(
                declared_hash_verdict,
                has_strong_hash=False,
                sha1_candidates=set(),
                sha256_candidates=set(),
                md5_list=[],
                crc_candidates=set(),
                zipped_file=q.zipped_file,
                declared_size=q.declared_size,
                file_entry=q.file_entry,
                db=q.db,
            ),
        )
        if hit:
            return hit
    return chosen, "name_exact"


def name_or_alias_match(
    q: Lookup, makers: frozenset[str], data_dir_registry: dict | None
) -> tuple[Resolution | None, bool]:
    """Any file with that name or alias (existence check).

    The second value says the name proved nothing, which makes the entry
    unsourceable for the steps after this one.
    """
    candidates = _exact_name_candidates(q)
    if candidates and all("/.variants/" in p for p in candidates):
        _add_variant_primaries(q, candidates)
    owners = owner_tokens(q.file_entry)
    # Only another emulator's tree answers the exact casing: what it
    # holds there says nothing about this entry's file.
    exact_foreign = bool(candidates) and all(
        foreign_tree(p, owners) for p in candidates
    )
    if not candidates or exact_foreign:
        _add_casefold_candidates(q, candidates, owners)
    # A platform entry names no profile, but a system that lists its
    # cores says whose files it asks for. A name only another emulator's
    # tree answers is no evidence, and the data directories hold those
    # emulators' trees too: EmuELEC's VVVVVV data.zip was served xrick's
    # archive of the same name, then xrick's data directory copy.
    core_owners = {
        token
        for core in q.file_entry.get("platform_cores") or ()
        for token in affinity_tokens(str(core))
    }
    if (
        not owners
        and core_owners
        and candidates
        and all(foreign_tree(p, core_owners) for p in candidates)
    ):
        return None, True
    if makers and candidates:
        candidates = _same_maker(q, candidates, makers)
    if not candidates:
        return None, False
    return _choose_by_name(q, candidates, owners, exact_foreign, data_dir_registry), False


def named_candidates(q: Lookup, makers: frozenset[str]) -> list[tuple[str, str, int | None]]:
    """Every held file of the entry's names: path, md5, size."""
    named: list[tuple[str, str, int | None]] = []
    seen_paths = set()
    for try_name in q.names_to_try:
        for match_sha1 in q.by_name.get(try_name, []):
            if match_sha1 in q.files_db:
                entry = q.files_db[match_sha1]
                path = entry["path"]
                if os.path.exists(path) and path not in seen_paths:
                    seen_paths.add(path)
                    named.append(
                        (path, entry.get("md5", ""), entry.get("size"))
                    )

    if q.zipped_file:
        named = [c for c in named if ".zip" in os.path.basename(c[0])]
    # Another maker's file is no mismatch of this one, it is another file.
    named = [c for c in named if not other_maker(c[0], makers, q.db)]
    # A size the emulator itself verifies settles a name collision, so a
    # candidate that fits is preferred over one that does not: "ROM" answers
    # both an Apple IIgs image and a Macintosh one. It ranks rather than
    # excludes, because a present file of the wrong size is reported as
    # present and untested, and dropping it would report it as absent.
    sized = [
        c for c in named
        if name_match_size_ok(q.file_entry, c[2]) and content_fits(q.file_entry, c[0])
    ]
    if sized:
        return sized
    return [c for c in named if not _homonym(q, c[0])]


def _homonym(q: Lookup, path: str) -> bool:
    """Whether a same-named file that fails the entry's checks belongs elsewhere.

    Such a file is reported as this entry's mismatch only when it can be the
    same file: not another emulator's own copy, not filed under a maker the
    entry's system does not name. NanoBoyAdvance reads a 16 KB bios.bin and
    was reported the 64 KB PC BIOS of PCem.
    """
    if foreign_tree(path, owner_tokens(q.file_entry)):
        return True
    sys_id = str(q.file_entry.get("system") or "")
    return bool(sys_id) and other_maker(path, makers_named_by(sys_id, q.db), q.db)


def named_md5_match(q: Lookup, named: list[tuple[str, str, int | None]]) -> Resolution | None:
    """A named file whose md5, or archive composite, is a declared one.

    Sorts *named* in place for a composite-only entry, as the steps after
    this one read it.
    """
    md5_set = set(q.md5_list)
    if not md5_set or q.sha1_candidates or q.sha256_candidates or q.crc_candidates:
        return None
    if q.composite_only:
        named.sort(key=lambda c: "/.variants/" in c[0])
    for path, db_md5, _size in named:
        if ".zip" in os.path.basename(path):
            try:
                composite = md5_composite(path).lower()
                # A zipped_file md5 is the member's: one member of
                # another name has the same composite, and Batocera
                # looks the member up by name.
                if composite in md5_set and (
                    not q.zipped_file
                    or check_inside_zip(path, q.zipped_file, composite) == "ok"
                ):
                    return path, "md5_composite_exact"
            except (zipfile.BadZipFile, OSError) as exc:
                warn_unreadable_archive(path, exc)
        if db_md5.lower() in md5_set and not q.composite_only:
            return path, "md5_exact"
    return None


def zipped_named(
    q: Lookup, named: list[tuple[str, str, int | None]], zipped_file: str
) -> Resolution | None:
    """When zipped_file is set, only accept candidates that contain it."""
    valid = []
    for path, m, size in named:
        try:
            with zipfile.ZipFile(path) as zf:
                inner_names = {n.casefold() for n in zf.namelist()}
                if zipped_file.casefold() in inner_names:
                    valid.append((path, m, size))
        except (zipfile.BadZipFile, OSError) as exc:
            warn_unreadable_archive(path, exc)
    # The archive whose member carries the declared md5 is the one:
    # neogeo.zip is held twice, each with its own sfix.sfix, and the
    # first by name was returned as a mismatch while the other matched.
    for path, _m, _size in sorted(valid, key=lambda c: "/.variants/" in c[0]):
        if any(check_inside_zip(path, zipped_file, md5) == "ok" for md5 in q.md5_list):
            return path, "zip_exact"
    if valid:
        primary = [c[0] for c in valid if "/.variants/" not in c[0]]
        return (primary[0] if primary else valid[0][0]), "hash_mismatch"
    # No candidate contains the zipped_file: fall through to step 5
    return None


def ranked_mismatch(q: Lookup, named: list[tuple[str, str, int | None]]) -> Resolution:
    """The named file the entry would take, reported as a hash mismatch."""
    ordered = _by_affinity([c[0] for c in named], q.file_entry, q.dest_hint)
    primary = [c for c in ordered if "/.variants/" not in c]
    return (primary[0] if primary else ordered[0]), "hash_mismatch"


def by_zip_contents(q: Lookup, zip_contents: dict | None) -> Resolution | None:
    """zipped_file content match via pre-built index.

    Last resort: matches inner ROM MD5 across ALL ZIPs in the repo, so only
    used when name-based resolution failed entirely.
    """
    if not (
        q.zipped_file
        and q.md5_list
        and zip_contents
        and not (q.sha1_candidates or q.sha256_candidates or q.crc_candidates)
    ):
        return None
    for md5_candidate in q.md5_list:
        if md5_candidate in zip_contents:
            zip_sha1 = zip_contents[md5_candidate]
            if zip_sha1 in q.files_db:
                path = q.files_db[zip_sha1]["path"]
                if os.path.exists(path):
                    return path, "zip_exact"
    return None
