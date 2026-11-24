"""resolve_local_file and its stages: from a declared entry to a file of the collection."""

from __future__ import annotations

import functools
import os
from collections.abc import Iterator

from core.hashing import cut_md5_owner, parse_hash_list
from model.database import get_mame_clone_map
from model.profiles import CONTENT_CHECKS
from resolve.content import (
    adler32_fits,
    content_fits,
    declared_hash_verdict,
    name_match_size_ok,
    shape_fits,
)
from resolve.datadirs import data_dir_tail, resolve_in_data_dirs
from resolve.ownership import (
    affinity_tokens,
    foreign_tree,
    own_tree,
    owner_tokens,
    system_makers,
)
from resolve.lookup import Resolution, _Lookup, _entry_hint, _lookup, _record_match_status
from resolve.namestages import (
    _by_name,
    _by_zip_contents,
    _named_candidates,
    _named_md5_match,
    _ranked_mismatch,
    _zipped_named,
)


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
    md5_list = parse_hash_list(file_entry.get("md5"))
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
