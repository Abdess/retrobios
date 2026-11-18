"""resolve_local_file and its stages: from a declared entry to a file of the collection."""

from __future__ import annotations

import functools
import os
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from core.hashing import cut_md5_owner, md5_composite, parse_md5_list
from core.ziptools import check_inside_zip
from model.database import get_mame_clone_map
from model.profiles import CONTENT_CHECKS
from resolve.archives import (
    covering_archives,
    holding_members,
    warn_unreadable_archive,
    contents_members,
)
from resolve.content import (
    adler32_fits,
    content_fits,
    declared_hash_verdict,
    declares_shape,
    name_match_size_ok,
    shape_fits,
)
from resolve.datadirs import data_dir_tail, resolve_in_data_dirs
from resolve.ownership import (
    affinity_tokens,
    engine_tree,
    foreign_tree,
    maker_folder,
    own_tree,
    owner_tokens,
    other_maker,
    system_makers,
)


# One slot: the dict it was built from, its size then, and the folded view.
# Keyed by id() alone, a database freed and replaced by another at the same
# address got the old index back, and the case-insensitive step answered from
# a collection that no longer existed.
_casefold_index_cache: list[tuple[dict, int, dict[str, list[str]]]] = []


def _casefold_name_index(by_name: dict) -> dict[str, list[str]]:
    """Build (and cache) a casefolded view of the by_name index."""
    if _casefold_index_cache:
        source, size, cached = _casefold_index_cache[0]
        if source is by_name and size == len(by_name):
            return cached
    folded: dict[str, list[str]] = {}
    for name, sha1s in by_name.items():
        folded.setdefault(name.casefold(), []).extend(sha1s)
    _casefold_index_cache[:] = [(by_name, len(by_name), folded)]
    return folded


HASH_EXACT_RESOLUTION_STATUSES = frozenset(
    {
        "sha1_exact",
        "sha256_exact",
        "crc32_exact",
        "md5_exact",
        "md5_composite_exact",
        "zip_exact",
        "data_dir_hash_exact",
    }
)


def resolution_is_hash_exact(status: str) -> bool:
    """Whether *status* proves content identity with a declared hash."""
    return status in HASH_EXACT_RESOLUTION_STATUSES


def _resolve_agnostic(
    file_entry: dict, files_db: dict, has_strong_hash: bool
) -> tuple[str, str] | None:
    """Any file of the right shape under the declared prefix.

    Some cores accept whatever filename sits in their BIOS directory, so the
    shape (a size or a size range) is all that identifies a candidate. A
    declared hash outranks that, and stops this step being reached.
    """
    if not file_entry.get("agnostic") or has_strong_hash:
        return None
    prefix = file_entry.get("agnostic_path_prefix", "")
    if not prefix:
        return None
    for entry in files_db.values():
        path = entry.get("path", "")
        if not path.startswith(prefix):
            continue
        if os.path.exists(path) and shape_fits(file_entry, path, entry.get("size", 0)):
            return path, "agnostic_fallback"
    return None


_VARIANT_SUFFIX = re.compile(r"\.[0-9a-f]{8}$")


def variant_base_name(name: str) -> str:
    """The name a .variants/ copy stands in for: naomi2.zip.da79eca4 -> naomi2.zip.

    Only an eight-hex-digit suffix is a variant tag. A variant stored under
    its plain name (.variants/aes.zip) already is that name.
    """
    return _VARIANT_SUFFIX.sub("", name)


def _rank_tail_candidates(
    candidates: list[str], start: int, tail: str, files_db: dict, owners: set[str],
    asker: frozenset[str] = frozenset(),
) -> list[str]:
    """Order the files a destination tail designates, the likeliest first.

    A tail found in another emulator's tree is that emulator's asset, not
    evidence about this entry, whatever its length. A full tail claimed
    twice goes to the file whose path carries the least on top of the
    destination, then to the owner's own copy (super3's Games.xml was served
    to Supermodel-Dojo by index order alone), then to any copy outside
    another emulator's tree (upstream PCSX2 took EmuCoreX's GameIndex.yaml
    over the system directory's).
    """
    def path_of(sha1: str) -> str:
        return files_db.get(sha1, {}).get("path", "")

    # Another emulator's tree answers that emulator's entry, at any tail
    # length when a profile asks: lrps2 names no hash for
    # pcsx2/resources/GameIndex.yaml, and the only full-tail copy was ARMSX2's,
    # which then counted as path proof and replaced the GameIndex RetroArch
    # pins on every desktop target. A platform's own declaration has no
    # asker, and the tree whose path is its destination still answers it.
    if start or asker:
        # The database keeps one path per content. When that path does not
        # end with the tail, the tail was indexed from an identical copy
        # elsewhere, and the recorded path says nothing about whose tree it
        # sits in: PCSX2x6's RedumpDatabase.yaml has EmuCoreX's bytes.
        candidates = [
            h for h in candidates
            if not path_of(h).endswith("/" + tail)
            or not foreign_tree(path_of(h), owners if start else set(asker))
        ]
    if len(candidates) < 2:
        return candidates
    depth = len(tail.split("/"))
    return sorted(
        candidates,
        key=lambda h: (
            len(path_of(h).split("/")) - depth,
            not owners & affinity_tokens(path_of(h).rsplit("/", 1)[0]),
            foreign_tree(path_of(h), owners),
        ),
    )


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


Resolution = tuple[str, str]


@dataclass(frozen=True)
class _Lookup:
    """One entry as resolve_local_file reads it: its names and declared hashes."""

    file_entry: dict
    db: dict
    dest_hint: str
    name: str
    zipped_file: str | None
    names_to_try: list[str]
    own_names: list[str]
    md5_list: list[str]
    sha1_candidates: list[str]
    sha256_candidates: list[str]
    crc_candidates: dict[str, None]
    declared_size: Any
    files_db: dict
    by_name: dict
    by_path_suffix: dict
    composite_only: bool

    @property
    def has_strong_hash(self) -> bool:
        return bool(
            self.sha1_candidates or self.sha256_candidates or self.md5_list or self.crc_candidates
        )


def _lookup_names(name: str, aliases: list, dest_hint: str) -> tuple[list[str], list[str]]:
    """The names an entry answers to, and the part of them that is its own."""
    names_to_try = [name] + [a for a in aliases if a != name]

    # When name contains a path separator (e.g. "res/tilemap.bin"), also
    # try the basename since by_name indexes filenames without directories
    if "/" in name:
        name_base = name.rsplit("/", 1)[-1]
        if name_base and name_base not in names_to_try:
            names_to_try.append(name_base)

    # When dest_hint contains a path, also try its basename as a name
    # (handles emulator profiles where name: is descriptive and path: is
    # the actual filename, e.g. name: "MDA font ROM", path: "mda.rom")
    own_names = list(names_to_try)
    if dest_hint:
        hint_base = dest_hint.rsplit("/", 1)[-1] if "/" in dest_hint else dest_hint
        if hint_base and hint_base not in names_to_try:
            names_to_try.append(hint_base)
    return names_to_try, own_names


def _lookup(
    file_entry: dict, db: dict, dest_hint: str, md5_list: list[str], *, composite_only: bool
) -> _Lookup:
    """Read the names and every declared hash of an entry once."""
    sha1 = file_entry.get("sha1")
    name = file_entry.get("name", "")
    names_to_try, own_names = _lookup_names(name, file_entry.get("aliases", []), dest_hint)
    sha1_candidates = [
        str(value).strip().lower()
        for value in (sha1 if isinstance(sha1, list) else [sha1] if sha1 else [])
        if str(value).strip()
    ]
    sha256_raw = file_entry.get("sha256")
    sha256_values = sha256_raw if isinstance(sha256_raw, list) else [sha256_raw]
    sha256_candidates = [
        candidate.strip().lower()
        for value in sha256_values
        if value
        for candidate in str(value).split(",")
        if len(candidate.strip()) == 64
    ]
    # One value, a list, or a comma-separated string, like the other hashes.
    crc_values = file_entry.get("crc32") or []
    # Kept in the order declared, which is the order a lookup tries them.
    crc_candidates = dict.fromkeys(
        candidate.strip().lower().removeprefix("0x")
        for value in (crc_values if isinstance(crc_values, list) else [crc_values])
        for candidate in str(value).split(",")
        if candidate.strip()
    )
    indexes = db.get("indexes", {})
    return _Lookup(
        file_entry=file_entry,
        db=db,
        dest_hint=dest_hint,
        name=name,
        zipped_file=file_entry.get("zipped_file"),
        names_to_try=names_to_try,
        own_names=own_names,
        md5_list=md5_list,
        sha1_candidates=sha1_candidates,
        sha256_candidates=sha256_candidates,
        crc_candidates=crc_candidates,
        declared_size=file_entry.get("size"),
        files_db=db.get("files", {}),
        by_name=indexes.get("by_name", {}),
        by_path_suffix=indexes.get("by_path_suffix", {}),
        composite_only=composite_only,
    )


def _record_match_status(q: _Lookup, match_sha1: str) -> str | None:
    """Return hash evidence when a DB record satisfies every declaration."""
    entry = q.files_db.get(match_sha1)
    if not entry:
        return None
    statuses: list[str] = []
    if q.sha1_candidates:
        if match_sha1.lower() not in q.sha1_candidates:
            return None
        statuses.append("sha1_exact")
    if q.sha256_candidates:
        if str(entry.get("sha256", "")).lower() not in q.sha256_candidates:
            return None
        statuses.append("sha256_exact")
    # With zipped_file the MD5 identifies the member, not the container.
    if q.md5_list and not q.zipped_file:
        actual_md5 = str(entry.get("md5", "")).lower()
        if actual_md5 not in q.md5_list:
            return None
        statuses.append("md5_exact")
    if q.crc_candidates:
        if str(entry.get("crc32", "")).lower() not in q.crc_candidates:
            return None
        if q.declared_size is not None:
            allowed_sizes = (
                q.declared_size if isinstance(q.declared_size, list) else [q.declared_size]
            )
            if entry.get("size") not in allowed_sizes:
                return None
        statuses.append("crc32_exact")
    return statuses[0] if statuses else None


def _held_record(q: _Lookup, match_sha1: str) -> Resolution | None:
    """The record's path and evidence, when it satisfies the entry and is on disk."""
    path = q.files_db[match_sha1]["path"]
    status = _record_match_status(q, match_sha1)
    if status and os.path.exists(path):
        return path, status
    return None


def _by_sha1(q: _Lookup) -> Resolution | None:
    """SHA1 exact match (accept list-valued sha1 from profiles)."""
    for cand in q.sha1_candidates:
        if cand in q.files_db:
            found = _held_record(q, cand)
            if found:
                return found
    return None


def _by_sha256(q: _Lookup) -> Resolution | None:
    """SHA256 exact match, through the by_sha256 index."""
    if not q.sha256_candidates:
        return None
    by_sha256 = q.db.get("indexes", {}).get("by_sha256", {})
    for cand in q.sha256_candidates:
        match = by_sha256.get(cand)
        if match and match in q.files_db:
            found = _held_record(q, match)
            if found:
                return found
    return None


def _by_crc32(q: _Lookup) -> Resolution | None:
    """CRC32 lookup, only when no stronger hash is declared."""
    if (
        not q.crc_candidates
        or q.zipped_file
        or q.md5_list
        or q.sha1_candidates
        or q.sha256_candidates
    ):
        return None
    by_crc32 = q.db.get("indexes", {}).get("by_crc32", {})
    crc_matches: list[Resolution] = []
    for crc in q.crc_candidates:
        match = by_crc32.get(crc)
        if match and match in q.files_db:
            found = _held_record(q, match)
            if found:
                crc_matches.append(found)
    # A primary copy over a .variants/ one, as everywhere else.
    for path, status in crc_matches:
        if "/.variants/" not in path:
            return path, status
    if crc_matches:
        return crc_matches[0]
    return None


def _md5_hits(q: _Lookup) -> Iterator[tuple[str, str, str]]:
    """Each held record a declared md5 names: path, evidence, md5 asked.

    Skipped for zipped_file: the md5 is the inner ROM's, not the container's.
    """
    if not q.md5_list or q.zipped_file or q.composite_only:
        return
    by_md5 = q.db.get("indexes", {}).get("by_md5", {})
    for md5_candidate in q.md5_list:
        sha1_match = by_md5.get(md5_candidate)
        if sha1_match and sha1_match in q.files_db:
            found = _held_record(q, sha1_match)
            if found:
                yield found[0], found[1], md5_candidate


def _named_or_variant(names: frozenset[str], candidate_path: str) -> bool:
    """Whether a path's file name is one of these names, or a variant of one."""
    bn = os.path.basename(candidate_path)
    if bn in names:
        return True
    # .variants/ pattern: filename like "neogeo.zip.fc398ab4"
    return any(bn.startswith(n + ".") for n in names)


def _tail_candidates(q: _Lookup, start: int, tail: str, owners: set[str]) -> list[str]:
    """The records a destination tail names, ranked, ambiguity read."""
    candidates = _rank_tail_candidates(
        q.by_path_suffix.get(tail, []), start, tail, q.files_db, owners,
        frozenset(owner_tokens(q.file_entry)),
    )
    raw = q.by_path_suffix.get(tail, [])
    if start and len(raw) > 1:
        # Ambiguity is read before the foreign trees are set aside:
        # PCSX2x6's bin/resources/GameIndex.yaml met four copies
        # under resources/GameIndex.yaml, three in other emulators'
        # trees, and the fourth (PCSX2's console database, not
        # PCSX2x6's arcade one) passed for proof. Only the asker's own
        # tree still answers a tail several files share.
        candidates = [
            h for h in candidates
            if own_tree(q.files_db.get(h, {}).get("path", ""), owners)
        ]
    return candidates


def _tail_match(q: _Lookup, candidates: list[str]) -> Resolution | None:
    """The first candidate of a tail on disk that the entry accepts."""
    for match_sha1 in candidates:
        if match_sha1 not in q.files_db:
            continue
        path = q.files_db[match_sha1]["path"]
        if not os.path.exists(path):
            continue
        if not q.has_strong_hash:
            # A path names the file, the size the code checks still
            # bounds it, as on the name step: ZEsarUX's 48 KB
            # cpc6128.rom is not cap32's 32 KB one at the same tail.
            if not name_match_size_ok(
                q.file_entry, q.files_db[match_sha1].get("size")
            ) or not adler32_fits(q.file_entry, path, q.db) or not content_fits(
                q.file_entry, path
            ):
                continue
            return path, "path_exact"
        status = _record_match_status(q, match_sha1)
        if status:
            return path, status
    return None


def _by_path_suffix(q: _Lookup) -> tuple[Resolution | None, bool]:
    """The file at the destination's tail, and whether the indexed one is absent."""
    own_file_absent = False
    if not (q.dest_hint and q.by_path_suffix):
        return None, own_file_absent
    # A destination is written from the emulator's point of view
    # ("pcsx2/resources/GameIndex.yaml") and the index from the repo's
    # layout, so the two meet on a tail rather than on the whole string.
    # Longest tail first, and never down to the bare filename: that is the
    # weaker step below, and five files answer to GameIndex.yaml.
    # Two kinds of ambiguity appear once every tail is indexed. A
    # shortened tail can be claimed by several emulators shipping the same
    # asset tree, and it then proves nothing: skip it. The full tail can be
    # claimed twice as well, one storing it at the root of its own
    # directory and one nested deeper. There the file whose path carries
    # the least on top of the destination is the one that IS the
    # destination.
    # The descent drops at most one leading segment. A destination and the
    # tree differ by the wrapper directory at most. Beyond that the tail
    # stops describing this file and starts describing whichever emulator
    # happens to store the same asset tree.
    hint_parts = q.dest_hint.split("/")
    # The asking profile and the destination's own directories both name
    # whose tree a copy may come from.
    owners = owner_tokens(q.file_entry) | affinity_tokens("/".join(hint_parts[:-1]))
    for start in range(min(2, len(hint_parts) - 1)):
        candidates = _tail_candidates(q, start, "/".join(hint_parts[start:]), owners)
        if start and len(candidates) > 1:
            continue
        # The index names the file this destination designates. Not on
        # disk, it is a release asset the checkout does not hold, and no
        # other file of that name is it.
        if not start and candidates and not any(
            os.path.exists(q.files_db.get(h, {}).get("path", ""))
            for h in candidates
        ):
            own_file_absent = True
        found = _tail_match(q, candidates)
        if found:
            return found, own_file_absent
    return None, own_file_absent


def _by_data_dir_tail(q: _Lookup, data_dir_registry: dict | None) -> Resolution | None:
    """The same tail in a data directory, for a platform's hashless entry."""
    # by_path_suffix indexes bios/
    # only, so AmberELEC's Machines/MSX - Arabic/config.ini fell through to
    # the name step and got msx-emu's ColecoVision config.ini, while
    # data/bluemsx held blueMSX's own at that very path. A platform
    # declaration is resolved without a hint, and its destination is that
    # path. The descent and the ambiguity rule are those of the bios/ tails.
    # A profile's entry is not asked here: it names its owner, the name step
    # sends it to its data directories when another emulator's copy answers,
    # and a dump it declares outranks the free one its tree bundles at the
    # same path (Dolphin's dsp_coef.bin over Sys/GC's).
    tail_hint = q.dest_hint or str(q.file_entry.get("destination") or "")
    if (
        tail_hint
        and data_dir_registry
        and not q.has_strong_hash
        and not owner_tokens(q.file_entry)
    ):
        hit = data_dir_tail(tail_hint, data_dir_registry, q.file_entry, q.db)
        if hit:
            return hit, "path_exact"
    return None


def _name_size_ok(q: _Lookup, match_sha1: str) -> bool:
    """Whether a record found by name has the shape the entry's code checks."""
    record = q.files_db.get(match_sha1, {})
    return name_match_size_ok(q.file_entry, record.get("size")) and adler32_fits(
        q.file_entry, record.get("path", ""), q.db
    ) and content_fits(q.file_entry, record.get("path", ""))


def _exact_name_candidates(q: _Lookup) -> list[str]:
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
                if match_sha1 in q.files_db and _name_size_ok(q, match_sha1):
                    path = q.files_db[match_sha1]["path"]
                    if os.path.exists(path) and path not in candidates:
                        candidates.append(path)
        if candidates:
            break
    return candidates


def _add_variant_primaries(q: _Lookup, candidates: list[str]) -> None:
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
                and _name_size_ok(q, match_sha1)
                and os.path.exists(path)
                and path not in candidates
            ):
                candidates.append(path)


def _add_casefold_candidates(q: _Lookup, candidates: list[str], owners: set[str]) -> None:
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
            if match_sha1 in q.files_db and _name_size_ok(q, match_sha1):
                path = q.files_db[match_sha1]["path"]
                if foreign_tree(path, owners):
                    continue
                if os.path.exists(path) and path not in candidates:
                    candidates.append(path)


def _same_maker(q: _Lookup, candidates: list[str], makers: frozenset[str]) -> list[str]:
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
                and _name_size_ok(q, match_sha1)
                and os.path.exists(path)
                and path not in candidates
            ):
                candidates.append(path)
    return candidates


def _choose_by_name(
    q: _Lookup,
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


def _by_name(
    q: _Lookup, makers: frozenset[str], data_dir_registry: dict | None
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


def _named_candidates(q: _Lookup, makers: frozenset[str]) -> list[tuple[str, str, int | None]]:
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
        named = sized
    return named


def _named_md5_match(q: _Lookup, named: list[tuple[str, str, int | None]]) -> Resolution | None:
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


def _zipped_named(
    q: _Lookup, named: list[tuple[str, str, int | None]], zipped_file: str
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


def _ranked_mismatch(q: _Lookup, named: list[tuple[str, str, int | None]]) -> Resolution:
    """The named file the entry would take, reported as a hash mismatch."""
    ordered = _by_affinity([c[0] for c in named], q.file_entry, q.dest_hint)
    primary = [c for c in ordered if "/.variants/" not in c]
    return (primary[0] if primary else ordered[0]), "hash_mismatch"


def _by_zip_contents(q: _Lookup, zip_contents: dict | None) -> Resolution | None:
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


def _by_mame_clone(
    q: _Lookup, zip_contents: dict | None, depth: int, data_dir_registry: dict | None
) -> Resolution | None:
    """If a file was deduped, resolve via canonical."""
    clone_map = get_mame_clone_map(q.db.get("bios_dir"))
    canonical = clone_map.get(q.name)
    if not canonical or canonical == q.name:
        return None
    canonical_entry = {
        field: q.file_entry[field]
        for field in (
            "size", "min_size", "max_size", "size_multiple", "validation",
            *sorted(CONTENT_CHECKS),
        )
        if field in q.file_entry
    }
    canonical_entry["name"] = canonical
    result = resolve_local_file(
        canonical_entry,
        q.db,
        zip_contents,
        q.dest_hint,
        _depth=depth + 1,
        data_dir_registry=data_dir_registry,
    )
    if result[0] and result[1] != "hash_mismatch":
        return result[0], "mame_clone"
    return None


def _in_data_dirs(q: _Lookup, data_dir_registry: dict) -> tuple[Resolution | None, str | None]:
    """Data directory fallback: scan data/ caches for matching filename."""
    verdict = functools.partial(
        declared_hash_verdict,
        has_strong_hash=q.has_strong_hash,
        sha1_candidates=q.sha1_candidates,
        sha256_candidates=q.sha256_candidates,
        md5_list=q.md5_list,
        crc_candidates=set(q.crc_candidates),
        zipped_file=q.zipped_file,
        declared_size=q.declared_size,
        file_entry=q.file_entry,
        db=q.db,
    )
    return resolve_in_data_dirs(q.names_to_try, data_dir_registry, verdict)


def _resolve_layout(
    file_entry: dict,
    db: dict,
    zip_contents: dict | None,
    dest_hint: str,
    *,
    depth: int,
    data_dir_registry: dict | None,
) -> tuple[str | None, str]:
    """Resolve an entry whose launcher moves it, at both destinations."""
    layout = file_entry.get("layout_path")
    plain = {k: v for k, v in file_entry.items() if k != "layout_path"}
    # A destination outside the BIOS tree says nothing of the collection:
    # EmuELEC's roms/mame/konamigv.zip is not bios/Arcade/MAME's set.
    outside = file_entry.get("unprefixed") or file_entry.get("root")
    answers = [
        resolve_local_file(
            plain, db, zip_contents, dest_hint=hint, _depth=depth,
            data_dir_registry=data_dir_registry,
        )
        for hint in ((str(layout),) if outside else (dest_hint, str(layout)))
    ]
    for found in answers:
        if found[0] is not None and (
            resolution_is_hash_exact(found[1]) or found[1] == "path_exact"
        ):
            return found
    for found in answers:
        if found[0] is not None and found[1] not in ("not_found", "hash_mismatch"):
            return found
    return next((found for found in answers if found[0] is not None), answers[0])


def _entry_hint(file_entry: dict, dest_hint: str) -> str:
    """The destination tail the collection indexes the entry under."""
    # A platform that hands each core a system directory of its own (MinUI's
    # Bios/<TAG>/) writes that folder in front of the core's path. The tail
    # the collection indexes is the core's path alone.
    system_dir = file_entry.get("system_dir")
    if system_dir and dest_hint.startswith(f"{system_dir}/"):
        dest_hint = dest_hint[len(system_dir) + 1:]
    return dest_hint


def _name_as_hint(name: str, dest_hint: str) -> str:
    """A name written with its directory is the destination when no path is given."""
    # gam4980/E.BIN resolved by its basename took another model's OS
    # in verify --emulator and the emulator pack, while the platform pack,
    # which passes the destination, served the GAM4980's.
    if not dest_hint and "/" in name.strip("/"):
        return name
    return dest_hint


def resolve_local_file(
    file_entry: dict,
    db: dict,
    zip_contents: dict | None = None,
    dest_hint: str = "",
    _depth: int = 0,
    data_dir_registry: dict | None = None,
) -> tuple[str | None, str]:
    """Resolve a BIOS file to its local path using database.json.

    Single source of truth for file resolution, used by both verify.py
    and generate_pack.py. Does NOT handle storage tiers (external/user_provided)
    or release assets - callers handle those.

    dest_hint: optional destination path (e.g., "GC/USA/IPL.bin") used to
    disambiguate when multiple files share the same name. Matched against
    the by_path_suffix index built from the repo's directory structure.

    Returns ``(local_path, status)``.  Statuses describe the evidence used:
    ``sha1_exact``, ``sha256_exact``, ``crc32_exact``, ``md5_exact``,
    ``md5_composite_exact``, ``zip_exact``, ``path_exact``, ``name_exact``,
    ``hash_mismatch`` or ``not_found`` (plus documented fallback statuses).

    A path or filename is never allowed to override a declared strong hash.
    """
    dest_hint = _entry_hint(file_entry, dest_hint)
    # A launcher that moves the layout (EmuDeck links azahar's sysdata to
    # bios/azahar/keys) changes where the file goes, not the tail the
    # collection indexes it under. Both are asked, and the stronger proof
    # wins: a content or path match over a name, the destination on a tie.
    layout = file_entry.get("layout_path")
    if layout and layout != dest_hint:
        return _resolve_layout(
            file_entry, db, zip_contents, dest_hint,
            depth=_depth, data_dir_registry=data_dir_registry,
        )
    md5_list = parse_md5_list(file_entry.get("md5"))
    by_md5 = db.get("indexes", {}).get("by_md5", {})
    # A value cut short stands for the one held md5 it starts, and only
    # then (cut_md5_owner): the dump it names is still name-guarded below.
    cut_owners = {
        cut: owner for cut in md5_list
        if len(cut) < 32 and (owner := cut_md5_owner(cut, by_md5))
    }
    # A frontend that hashes an archive by its members (Recalbox) never reads
    # the container's own md5: neocd.bin's md5 is also the composite of a
    # one-member neocdz.zip, and the raw ROM shipped under the archive's name.
    composite_only = file_entry.get("zip_digest") == "composite"
    q = _lookup(
        file_entry, db, _name_as_hint(file_entry.get("name", ""), dest_hint),
        [cut_owners.get(value, value) for value in md5_list],
        composite_only=composite_only,
    )
    has_strong_hash = q.has_strong_hash
    # Guard of step 2: only accept if the found file's name matches the
    # requested name (or is a .variants/ derivative). Prevents
    # cross-contamination when an unrelated file happens to share the same
    # MD5 in the index.
    _md5_name_ok = functools.partial(_named_or_variant, frozenset(q.names_to_try))

    found = (
        # 1. SHA1 exact match (accept list-valued sha1 from profiles)
        _by_sha1(q)
        # 1b. SHA256 exact match (profiles hashed from sources that publish
        # sha256, e.g. MesenCE). A full sha256 is a strong identifier.
        or _by_sha256(q)
        # 1c. CRC32 lookup, only when no stronger hash is declared.  A declared
        # size confirms it when available. A handful of emulators validate CRC32
        # alone, so those entries retain the same (weaker) evidence as the core.
        or _by_crc32(q)
        # 2. MD5 direct lookup (skip for zipped_file: md5 is inner ROM, not container)
        # A full md5 as declared is a strong identifier: trusted without
        # name guard. One completed from a cut value still needs the name
        # check to avoid cross-contamination.
        or next(
            (
                (path, status)
                for path, status, md5_candidate in _md5_hits(q)
                if md5_candidate not in cut_owners.values() or _md5_name_ok(path)
            ),
            None,
        )
    )
    if found:
        return found

    # 2b. Path suffix lookup is useful for same-named regional files, but it
    # is identity evidence only when no content hash was declared.  A stale
    # or incorrect destination can therefore never mask a hash mismatch.
    found, own_file_absent = _by_path_suffix(q)
    # 2c. The same tail in a data directory.
    found = found or _by_data_dir_tail(q, data_dir_registry)
    if found:
        return found

    # 3. No MD5 = any file with that name or alias (existence check)
    # An entry the profile documents as unsourceable is one the collection
    # cannot hold: a font that only exists inside a paid package, cheat codes
    # written per title. A file answering to its name is therefore a homonym
    # from another system, not a stale dump of the same file - kanji.rom names
    # an FPseNG font, an openMSX one and a 3DO ROM. Content still decides: the
    # hash and path steps above run first, so collecting the real bytes makes
    # the entry resolve.
    unsourceable = bool(file_entry.get("unsourceable")) or own_file_absent
    # A platform's own hashless entry whose system names a maker takes no copy
    # filed under another maker: AmberELEC's nec-pc-88 DISK.ROM, which QUASI88
    # reads as the 2 KB PC-88 disk ROM, got the 16 KB MSX one by name.
    makers: frozenset[str] = frozenset() if has_strong_hash else system_makers(file_entry, db)

    if not has_strong_hash and not unsourceable:
        found, unsourceable = _by_name(q, makers, data_dir_registry)
        if found:
            return found

    # 4. Name + alias fallback with md5_composite + direct MD5 per candidate
    named = _named_candidates(q, makers)
    if named:
        found = _named_md5_match(q, named)
        if q.zipped_file:
            found = found or _zipped_named(q, named, q.zipped_file)
        elif not unsourceable:
            found = found or _ranked_mismatch(q, named)
        if found:
            return found

    # 5. zipped_file content match via pre-built index (last resort:
    # matches inner ROM MD5 across ALL ZIPs in the repo, so only use
    # when name-based resolution failed entirely)
    found = _by_zip_contents(q, zip_contents)

    # MAME clone fallback: if a file was deduped, resolve via canonical. The
    # clone name is a name step like the others: an unsourceable entry skips
    # it, and the size the code checks travels with it (dedup only merges
    # identical bytes, so the canonical copy has the clone's size).
    if _depth < 3 and not has_strong_hash and not unsourceable:
        found = found or _by_mame_clone(q, zip_contents, _depth, data_dir_registry)
    if found:
        return found

    # Data directory fallback: scan data/ caches for matching filename
    data_dir_mismatch: str | None = None
    # Without a hash the cache walk matches on filename alone, which is the
    # step an unsourceable entry has to skip: hiscore.dat names one file per
    # driver set, so FBNeo's copy would answer for MAME's.
    if data_dir_registry and (has_strong_hash or not unsourceable):
        found, data_dir_mismatch = _in_data_dirs(q, data_dir_registry)
    if found:
        return found

    if data_dir_mismatch and not unsourceable:
        return data_dir_mismatch, "hash_mismatch"

    return _resolve_agnostic(file_entry, q.files_db, has_strong_hash) or (None, "not_found")
