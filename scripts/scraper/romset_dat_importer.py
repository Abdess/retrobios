"""Import romset recipes from a MAME or FBNeo DAT.

A DAT states, per set, the members an emulator version expects: name, size
and CRC32. That is a recipe, and TorrentZip turns a recipe plus the ROM bytes
into the exact archive. Profiles document a few hundred sets by hand, while a DAT
documents every set of one version at once.

MAME ships its ``-listxml`` output as a release asset and FBNeo keeps its DATs
in its repository, so both are fetched without a browser:

    python -m scripts.scraper.romset_dat_importer --source mame --fetch
    python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289
    python -m scripts.scraper.romset_dat_importer --source fbneo --fetch
    python -m scripts.scraper.romset_dat_importer --source fbneo --fetch v1.0.0.02
    python -m scripts.scraper.romset_dat_importer --source mame --pack local.dat

Only sets the collection has a reason to know are kept, so the committed
snapshot stays small: the archive names that emulator profiles or platform
BIOS lists reference, the archives the collection holds, the sets holding a
dump-catalog entry the collection lacks (provenance_report names the set as
where to find it), and every set whose members equal an archive the
collection keeps under another name. That last entry carries the
collection's name and keeps the upstream one in ``set``. ``--all`` keeps
everything.

Members without a CRC32 are undumped. A real romset does not carry them, so
they are dropped from the recipe rather than disqualifying the whole set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

from core.ziptools import is_archive_path, zip_members
from model.registry import list_registered_platforms
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from core.cli import add_repo_inputs, run_cli
from model.database import load_database
from model.dumpcatalog import build_snapshot, load_provenance_snapshots, write_snapshot
from resolve.localfile import variant_base_name
from .base_scraper import (
    BlobMismatchError,
    download,
    fetch_branch_head,
    fetch_github_latest_version,
    fetch_verified_blob,
    github_json,
)
from .listxml import (
    Opener,
    iter_dat_documents,
    iter_elements,
    open_listxml,
    rom_members,
    xml_members,
)
from .logiqx_parser import LogiqxDat, parse_logiqx

SOURCES = ("mame", "fbneo")
DEFAULT_OUTPUT = "recipes/{source}.json"


def relevant_archives(emulators_dir: str, platforms_dir: str) -> set[str]:
    """Archive names any profile or platform refers to."""
    names: set[str] = set()
    for profile in load_emulator_profiles(
        emulators_dir, skip_aliases=False
    ).values():
        for entry in profile.get("files", []) or []:
            name = entry.get("name", "")
            if name.endswith(".zip"):
                names.add(name)
            archive = entry.get("archive", "")
            if archive:
                names.add(archive)
    for platform_name in list_registered_platforms(platforms_dir):
        config = load_platform_config(platform_name, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                name = entry.get("name", "")
                if name.endswith(".zip"):
                    names.add(name)
    return names


Targets = dict[tuple[str, int], set[str]]
MemberList = tuple[tuple[str, str], ...]
ByMembers = dict[MemberList, set[str]]

def member_list(members: list[dict]) -> MemberList:
    """Sorted (name, crc32) of a recipe, the key an archive is matched on."""
    return tuple(
        sorted((str(m["name"]), str(m.get("crc32") or "").lower()) for m in members)
    )


def collection_archives(db: dict) -> tuple[set[str], ByMembers]:
    """Names and member lists of every archive the collection holds.

    A set the collection keeps under another name is still that set:
    ``aga.zip`` holds exactly MAME's ``isa_aga`` and ``votrax.zip`` its
    ``votrsc01a``. Matched by name alone, neither ever entered the snapshot.
    A ``.variants/`` copy stands for the name its tag is cut from.
    """
    names: set[str] = set()
    by_members: ByMembers = {}
    for entry in db.get("files", {}).values():
        path = Path(entry.get("path", ""))
        name = variant_base_name(path.name)
        if not is_archive_path(path.name) or not path.is_file():
            continue
        try:
            held = [
                {"name": member.name, "crc32": member.crc32}
                for member in zip_members(path)
            ]
        except (OSError, zipfile.BadZipFile) as exc:
            print(f"  UNREADABLE: {path}: {exc}", file=sys.stderr)
            continue
        names.add(name)
        if held:
            by_members.setdefault(member_list(held), set()).add(name)
    return names, by_members


def _entry(
    dat: str, archive: str, set_name: str, description: str, members: list[dict]
) -> dict:
    return {
        "dat": dat,
        "name": archive,
        "set": set_name,
        "description": description,
        "members": sorted(members, key=lambda member: member["name"]),
    }


def named_entries(
    dat: str,
    set_name: str,
    description: str,
    members: list[dict],
    kept: bool,
    by_members: ByMembers | None,
) -> list[dict]:
    """The snapshot entries one upstream set gives.

    Under its own name when kept, and under every collection name whose
    archive holds exactly its members. ``set`` keeps the upstream name.
    """
    archives = {f"{set_name}.zip"} if kept else set()
    if by_members:
        archives |= by_members.get(member_list(members), set())
    return [
        _entry(dat, archive, set_name, description, members)
        for archive in sorted(archives)
    ]


def catalog_targets(provenance_dir: str, db: dict) -> Targets:
    """(crc32, size) -> sha1 of each dump-catalog entry the collection lacks.

    fm7740sx carries DICROM.rom, EXTSUB.rom and KANJI2.rom, which No-Intro
    lists and the collection misses: filtered on archive names alone, the
    snapshot never held the set and the missing report named no source.
    """
    held = set(db.get("files", {}))
    targets: Targets = {}
    for snapshot in load_provenance_snapshots(provenance_dir).values():
        for entry in snapshot.get("entries", []):
            crc, size = str(entry.get("crc32") or "").lower(), entry.get("size")
            sha1 = str(entry.get("sha1") or "").lower()
            if not crc or size is None or (sha1 and sha1 in held):
                continue
            targets.setdefault((crc.zfill(8), int(size)), set()).add(sha1)
    return targets


def holds_target(members: list[dict], targets: Targets | None) -> bool:
    """Whether a set carries a missing catalog dump. A sha1 on both sides
    must agree: crc32 and size alone collide across 40 000 ROMs."""
    if not targets:
        return False
    for member in members:
        key = (str(member.get("crc32") or "").lower().zfill(8), int(member.get("size") or 0))
        wanted = targets.get(key)
        sha1 = str(member.get("sha1") or "").lower()
        if wanted is not None and (not sha1 or "" in wanted or sha1 in wanted):
            return True
    return False


def one_set_per_archive(entries: list[dict]) -> list[dict]:
    """One entry per archive and member list, its own set preferred.

    Thirty MAME keyboard sets carry the same ROM, so ``a500kbd_ch.zip``
    matches all of them. The set named like the archive is the one kept,
    then the first by name.
    """
    chosen: dict[tuple[str, MemberList], dict] = {}
    for entry in entries:
        key = (entry["name"], member_list(entry["members"]))
        current = chosen.get(key)
        own = entry["name"] == f"{entry['set']}.zip"
        if current is None or (own and current["name"] != f"{current['set']}.zip"):
            chosen[key] = entry
    return sorted(chosen.values(), key=lambda e: (e["name"], e["set"]))


def recipe_entries(
    dat: LogiqxDat,
    keep: set[str] | None = None,
    targets: Targets | None = None,
    by_members: ByMembers | None = None,
) -> list[dict]:
    """Group a parsed DAT into one recipe per set."""
    by_set: dict[str, list] = {}
    for rom in dat.roms:
        if not rom.crc32:
            continue
        by_set.setdefault(rom.game, []).append(rom)

    entries: list[dict] = []
    for set_name, roms in sorted(by_set.items()):
        members = [
            {"name": rom.name, "size": rom.size, "crc32": rom.crc32, "sha1": rom.sha1}
            for rom in roms
        ]
        kept = (
            keep is None
            or f"{set_name}.zip" in keep
            or holds_target(members, targets)
        )
        entries.extend(
            named_entries(
                dat.name or "unnamed", set_name, roms[0].description, members,
                kept, by_members,
            )
        )
    return one_set_per_archive(entries)


def _scan_listxml(
    stream: IO[bytes],
    selector: Callable[[str], bool],
    targets: Targets | None = None,
) -> dict[str, tuple[str | None, list[dict]]]:
    """Stream a MAME -listxml document, keeping the machines *selector* wants
    and those holding one of *targets*."""
    found: dict[str, tuple[str | None, list[dict]]] = {}
    for element in iter_elements(stream):
        name = element.attrs.get("name", "")
        wanted = selector(name)
        if wanted or targets:
            roms = rom_members(element.body)
            if wanted or holds_target(roms, targets):
                found[name] = (element.attrs.get("romof") or None, roms)
    return found


def listxml_entries(
    open_stream: Opener,
    label: str,
    keep: set[str] | None,
    targets: Targets | None = None,
    by_members: ByMembers | None = None,
) -> list[dict]:
    """Recipes from a MAME -listxml document, parents resolved.

    A non-merged archive carries its parent set's ROMs as well as its own, so
    a machine with ``romof`` is read as the union, its own members winning a
    name collision. Two passes: the parents a set needs are only known once
    that set has been seen. Matching by member list reads every machine in
    one pass, every parent included.
    """
    def kept(name: str) -> bool:
        return keep is None or f"{name}.zip" in keep

    with open_stream() as stream:
        wanted = _scan_listxml(
            stream, (lambda _name: True) if by_members else kept, targets
        )
    requested = (
        {
            name for name, (_parent, roms) in wanted.items()
            if kept(name) or holds_target(roms, targets)
        }
        if by_members
        else set(wanted)
    )
    parents = {
        parent for parent, _roms in wanted.values() if parent and parent not in wanted
    }
    if parents:
        with open_stream() as stream:
            for name, value in _scan_listxml(stream, parents.__contains__).items():
                wanted.setdefault(name, value)

    entries: list[dict] = []
    for name, (parent, roms) in sorted(wanted.items()):
        if not by_members and name not in requested:
            # A parent read only to complete a child is not itself an entry.
            continue
        members = {member["name"]: member for member in wanted.get(parent, (None, []))[1]} if parent else {}
        members.update({member["name"]: member for member in roms})
        if not members:
            continue
        entries.extend(
            named_entries(
                label, name, f"parent {parent}" if parent else name,
                list(members.values()), name in requested, by_members,
            )
        )
    return one_set_per_archive(entries)


def _recipe_key(entry: dict) -> tuple[str, str]:
    """Identity of a recipe: which archive, and exactly which members."""
    members = json.dumps(entry.get("members", []), sort_keys=True)
    return entry.get("name", ""), hashlib.sha1(members.encode()).hexdigest()


def compact_entries(entries: list[dict]) -> list[dict]:
    """Collapse identical recipes shared by several versions.

    Most sets do not change between MAME releases: 22 imported versions give
    23,679 entries but only 1,726 distinct recipes. Each is stored once, with
    ``dats`` listing every version that agrees and ``dat`` naming the earliest,
    so a match reads as "unchanged since that version" rather than "is that
    version".
    """
    grouped: dict[tuple[str, str], dict] = {}
    for entry in entries:
        key = _recipe_key(entry)
        existing = grouped.get(key)
        labels = entry.get("dats") or ([entry["dat"]] if entry.get("dat") else [])
        if existing is None:
            merged = dict(entry)
            merged["dats"] = sorted(set(labels))
            grouped[key] = merged
        else:
            existing["dats"] = sorted(set(existing["dats"]) | set(labels))
    for entry in grouped.values():
        entry["dat"] = entry["dats"][0]
    return sorted(grouped.values(), key=lambda e: (e["name"], e["dat"]))


def merge_snapshot(
    output: str,
    source: str,
    dats: dict[str, str],
    entries: list[dict],
    upstream: dict[str, str] | None = None,
) -> bool:
    """Accumulate recipes across versions instead of replacing them.

    A platform pins the archive of whichever version its list was built
    against, so the snapshot is a growing library of versions, not a picture
    of the newest one. ``upstream`` (DAT file -> git blob sha) replaces the
    previous one: it describes the files this import read, not a history.
    """
    path = Path(output)
    known_entries: list[dict] = []
    known_dats: dict[str, str] = {}
    known_upstream: dict = {}
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            existing = json.load(handle)
        known_entries = list(existing.get("entries", []))
        known_dats = dict(existing.get("dats", {}))
        known_upstream = dict(existing.get("upstream", {}))

    known_dats.update(dats)
    if upstream:
        known_upstream["blobs"] = dict(sorted(upstream.items()))
    snapshot = build_snapshot(
        source,
        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        known_dats,
        compact_entries(known_entries + entries),
    )
    if known_upstream:
        snapshot["upstream"] = dict(sorted(known_upstream.items()))
    return write_snapshot(output, snapshot)


MAME_LISTXML_URL = (
    "https://github.com/mamedev/mame/releases/download/{tag}/{tag}lx.zip"
)
MAME_REPO = "mamedev/mame"


FBNEO_REPO = "libretro/FBNeo"
FBNEO_API = f"https://api.github.com/repos/{FBNEO_REPO}"


def _api_json(url: str) -> object:
    """An api.github.com answer, ConnectionError when it cannot be read."""
    return github_json(url, f"cannot read {url}", timeout=60, error=ConnectionError)


def fetch_tag(source: str, requested: str) -> str:
    """The revision a ``--fetch`` names: bare, the newest MAME release or
    the tip of FBNeo's default branch."""
    if source == "mame" and requested == "latest":
        tag = fetch_github_latest_version(MAME_REPO)
        print(f"  Derniere release MAME : {tag}")
        return tag
    return requested


def fetch_pack(
    source: str, tag: str, cache_dir: Path
) -> tuple[Path, dict[str, str]]:
    """Download the upstream DAT for *source*.

    MAME ships its ``-listxml`` output as a release asset, and FBNeo keeps its
    DATs in the repository, so neither needs a browser. The second value
    names the upstream state fetched: empty for a release asset, whose tag
    already says which version it is, and the git blob sha of every DAT for
    FBNeo, whose files change under a constant header version.
    """
    if source == "mame":
        listxml = cache_dir / f"{tag}lx.zip"
        download(MAME_LISTXML_URL.format(tag=tag), listxml, skip_existing=True)
        return listxml, {}

    # The revision is resolved to a commit first and everything is read at
    # that commit: a branch URL is served through a CDN cache, so the bytes
    # could predate the listing that named their blob.
    sha = fetch_branch_head(FBNEO_REPO, None if tag == "latest" else tag)
    listing = _api_json(f"{FBNEO_API}/contents/dats?ref={sha}")
    if not isinstance(listing, list):
        raise BlobMismatchError(f"libretro/FBNeo lists no dats at {sha}")
    target = cache_dir / "fbneo-dats"
    target.mkdir(parents=True, exist_ok=True)
    blobs: dict[str, str] = {}
    for item in listing:
        if item.get("type") != "file" or not item["name"].lower().endswith(".dat"):
            continue
        fetch_verified_blob(
            item["download_url"], target / item["name"], item["sha"],
            f" of libretro/FBNeo {sha}",
        )
        blobs[item["name"]] = item["sha"]
    # A DAT the revision does not carry is not read from an older fetch.
    for stale in target.glob("*"):
        if stale.is_file() and stale.name not in blobs:
            stale.unlink()
    return target, blobs


def _is_listxml(pack: Path) -> bool:
    """Whether *pack* holds a MAME -listxml document rather than a DAT.

    A ZIP of several XML documents is a DAT collection."""
    if pack.is_dir():
        return False
    if pack.suffix.lower() == ".zip":
        with zipfile.ZipFile(pack) as archive:
            if len(xml_members(archive)) != 1:
                return False
    with open_listxml(pack) as handle:
        return b"<!ELEMENT mame" in handle.read(4096)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument(
        "--source", choices=SOURCES, required=True,
        help="emulator whose DATs are imported",
    )
    parser.add_argument("--pack", help="DAT file, ZIP or directory")
    parser.add_argument(
        "--fetch",
        nargs="?",
        const="latest",
        help="download upstream instead of using --pack: a MAME tag such as "
        "mame0289 or an FBNeo tag, branch or commit; bare, the newest MAME "
        "release or the tip of FBNeo's default branch",
    )
    parser.add_argument(
        "--cache-dir", default=".cache/dats",
        help="download cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--output", default="",
        help="snapshot to write (default: recipes/<source>.json)",
    )
    add_repo_inputs(parser, "emulators", "platforms", "db")
    parser.add_argument(
        "--all", action="store_true", help="keep every set, not only referenced ones"
    )
    parser.add_argument(
        "--provenance-dir", default="provenance",
        help="dump catalogs whose missing entries keep the sets holding them "
             "(default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print what would change and write nothing",
    )
    return parser


@dataclass(frozen=True)
class _Selection:
    """Which sets a snapshot keeps: None everywhere keeps every set."""

    keep: set[str] | None = None
    targets: Targets | None = None
    by_members: ByMembers | None = None


def _selection(args: argparse.Namespace) -> _Selection:
    if args.all:
        return _Selection()
    db = load_database(args.db)
    held, by_members = collection_archives(db)
    keep = relevant_archives(args.emulators_dir, args.platforms_dir) | held
    targets = catalog_targets(args.provenance_dir, db)
    return _Selection(keep, targets, by_members)


def _import_listxml(pack: Path, args: argparse.Namespace, output: str, chosen: _Selection) -> int:
    label = f"MAME {pack.stem.replace('lx', '')}"
    entries = listxml_entries(
        lambda: open_listxml(pack), label, chosen.keep, chosen.targets, chosen.by_members
    )
    dats = {label: pack.stem}
    print(f"  {label}: {len(entries)} sets retenus")
    members = sum(len(entry["members"]) for entry in entries)
    print(f"{len(entries)} recettes, {members} membres, depuis 1 listxml")
    if args.dry_run:
        return 0
    changed = merge_snapshot(output, args.source, dats, entries)
    print(f"{'Wrote' if changed else 'Unchanged'} {output}")
    return 0


def _dat_recipes(
    pack: Path, revision: str, chosen: _Selection
) -> tuple[dict[str, str], list[dict]]:
    """Recipes of every Logiqx DAT a pack holds, and each DAT's version."""
    dats: dict[str, str] = {}
    entries: list[dict] = []
    skipped = 0
    for member, content in iter_dat_documents(pack):
        try:
            dat = parse_logiqx(content)
        except (ValueError, SyntaxError) as exc:
            print(f"  Skipped {member}: {exc}", file=sys.stderr)
            skipped += 1
            continue
        if not dat.roms:
            skipped += 1
            continue
        if revision:
            dat.name = f"{dat.name or member} @ {revision}"
        found = recipe_entries(dat, chosen.keep, chosen.targets, chosen.by_members)
        if not found:
            continue
        dats[dat.name or member] = dat.version
        entries.extend(found)
        print(f"  {dat.name or member}: {len(found)} sets retenus")

    if skipped:
        print(f"  {skipped} fichier(s) ignore(s) (non-Logiqx ou vides)")
    return dats, entries


def main() -> int:
    parser = _parser()
    args = parser.parse_args()

    blobs: dict[str, str] = {}
    # FBNeo's DAT headers keep one version across commits, so a DAT read at
    # a named revision is labelled with it: under the bare header name it
    # merged into the tip's recipes. Its blobs describe that revision, not
    # the upstream state the freshness check compares with, and are not
    # recorded.
    revision = ""
    if args.fetch:
        try:
            pack, blobs = fetch_pack(
                args.source, fetch_tag(args.source, args.fetch), Path(args.cache_dir)
            )
        except (BlobMismatchError, ConnectionError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(f"  Recupere {pack}")
        if args.source == "fbneo" and args.fetch != "latest":
            revision = args.fetch
            blobs = {}
    elif args.pack:
        pack = Path(args.pack)
    else:
        parser.error("either --pack or --fetch is required")
    if not pack.exists():
        print(f"ERROR: {pack} does not exist", file=sys.stderr)
        return 1

    output = args.output or DEFAULT_OUTPUT.format(source=args.source)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    chosen = _selection(args)

    if _is_listxml(pack):
        return _import_listxml(pack, args, output, chosen)

    dats, entries = _dat_recipes(pack, revision, chosen)
    members = sum(len(entry["members"]) for entry in entries)
    print(f"{len(entries)} recettes, {members} membres, depuis {len(dats)} DAT")

    if args.dry_run:
        return 0

    changed = merge_snapshot(output, args.source, dats, entries, blobs)
    print(f"{'Wrote' if changed else 'Unchanged'} {output}")
    return 0


if __name__ == "__main__":
    run_cli(main)
