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
BIOS lists reference, and the sets holding a dump-catalog entry the
collection lacks (provenance_report names the set as where to find it).
``--all`` keeps everything.

Members without a CRC32 are undumped. A real romset does not carry them, so
they are dropped from the recipe rather than disqualifying the whole set.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..common import (
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    run_cli,
)
from ..dumpcatalog import build_snapshot, load_provenance_snapshots, write_snapshot
from .logiqx_parser import LogiqxDat, parse_logiqx

MAX_MEMBER_SIZE = 200 * 1024 * 1024

SOURCES = ("mame", "fbneo")
DEFAULT_OUTPUT = "recipes/{source}.json"


def relevant_archives(emulators_dir: str, platforms_dir: str) -> set[str]:
    """Archive names any profile or platform refers to."""
    names: set[str] = set()
    for _profile_name, profile in load_emulator_profiles(
        emulators_dir, skip_aliases=False
    ).items():
        for entry in profile.get("files", []) or []:
            name = entry.get("name", "")
            if name.endswith(".zip"):
                names.add(name)
            archive = entry.get("archive", "")
            if archive:
                names.add(archive)
    for platform_name in list_registered_platforms(platforms_dir, include_archived=True):
        config = load_platform_config(platform_name, platforms_dir)
        for system in config.get("systems", {}).values():
            for entry in system.get("files", []) or []:
                name = entry.get("name", "")
                if name.endswith(".zip"):
                    names.add(name)
    return names


Targets = dict[tuple[str, int], set[str]]


def catalog_targets(provenance_dir: str, db_path: str) -> Targets:
    """(crc32, size) -> sha1 of each dump-catalog entry the collection lacks.

    fm7740sx carries DICROM.rom, EXTSUB.rom and KANJI2.rom, which No-Intro
    lists and the collection misses: filtered on archive names alone, the
    snapshot never held the set and the missing report named no source.
    """
    with open(db_path, encoding="utf-8") as handle:
        held = set(json.load(handle).get("files", {}))
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


def recipe_entries(
    dat: LogiqxDat, keep: set[str] | None = None, targets: Targets | None = None
) -> list[dict]:
    """Group a parsed DAT into one recipe per set."""
    by_set: dict[str, list] = {}
    for rom in dat.roms:
        if not rom.crc32:
            continue
        by_set.setdefault(rom.game, []).append(rom)

    entries: list[dict] = []
    for set_name, roms in sorted(by_set.items()):
        archive = f"{set_name}.zip"
        if keep is not None and archive not in keep and not holds_target(
            [{"crc32": r.crc32, "size": r.size, "sha1": r.sha1} for r in roms], targets
        ):
            continue
        entries.append(
            {
                "dat": dat.name or "unnamed",
                "name": archive,
                "set": set_name,
                "description": roms[0].description,
                "members": sorted(
                    (
                        {
                            "name": rom.name,
                            "size": rom.size,
                            "crc32": rom.crc32,
                            "sha1": rom.sha1,
                        }
                        for rom in roms
                    ),
                    key=lambda member: member["name"],
                ),
            }
        )
    return entries


_MACHINE = re.compile(rb'<machine name="([^"]+)"([^>]*)>')
_ROM = re.compile(
    rb'<rom name="([^"]+)"(?=[^>]*\bcrc="([0-9a-fA-F]+)")[^>]*>'
)
_ROM_ATTR = re.compile(rb'(\w+)="([^"]*)"')
_ROMOF = re.compile(r'romof="([^"]+)"')
LISTXML_CHUNK = 8 * 1024 * 1024


def _machine_roms(blob: bytes) -> list[dict]:
    """ROM members of one machine element, undumped ones dropped."""
    members: list[dict] = []
    for match in re.finditer(rb"<rom\b([^>]*)>", blob):
        attrs = {
            key.decode(): value.decode()
            for key, value in _ROM_ATTR.findall(match.group(1))
        }
        crc = attrs.get("crc", "").lower()
        name = attrs.get("name", "")
        if not name or not crc:
            continue
        try:
            size = int(attrs.get("size", "0"))
        except ValueError:
            size = 0
        members.append(
            {
                "name": name,
                "size": size,
                "crc32": crc,
                "sha1": attrs.get("sha1", "").lower(),
            }
        )
    return members


def _scan_listxml(
    stream: io.BufferedIOBase,
    selector: Callable[[str], bool],
    targets: Targets | None = None,
) -> dict[str, tuple[str | None, list[dict]]]:
    """Stream a MAME -listxml document, keeping the machines *selector* wants
    and those holding one of *targets*.

    The document is 311 MB for MAME 0.289, so it is never held whole: the
    window keeps the element still open from its start tag, and grows until
    that element closes, whatever its size.
    """
    found: dict[str, tuple[str | None, list[dict]]] = {}
    buffer = b""
    while chunk := stream.read(LISTXML_CHUNK):
        buffer += chunk
        position = 0
        keep_from = None
        while True:
            match = _MACHINE.search(buffer, position)
            if not match:
                break
            end = buffer.find(b"</machine>", match.end())
            if end == -1:
                keep_from = match.start()
                break
            name = match.group(1).decode()
            wanted = selector(name)
            if wanted or targets:
                roms = _machine_roms(buffer[match.end() : end])
                if wanted or holds_target(roms, targets):
                    parent = _ROMOF.search(match.group(2).decode())
                    found[name] = (parent.group(1) if parent else None, roms)
            position = end + len(b"</machine>")
        if keep_from is None:
            # No element open: only a start tag cut by the read can follow.
            start = buffer.rfind(b"<machine", position)
            tail = max(position, len(buffer) - len(b"<machine"))
            keep_from = start if start != -1 else tail
        buffer = buffer[keep_from:]
    return found


def listxml_entries(
    open_stream: Callable[[], io.BufferedIOBase],
    label: str,
    keep: set[str] | None,
    targets: Targets | None = None,
) -> list[dict]:
    """Recipes from a MAME -listxml document, parents resolved.

    A non-merged archive carries its parent set's ROMs as well as its own, so
    a machine with ``romof`` is read as the union, its own members winning a
    name collision. Two passes: the parents a set needs are only known once
    that set has been seen.
    """
    with open_stream() as stream:
        wanted = _scan_listxml(
            stream, lambda name: keep is None or f"{name}.zip" in keep, targets
        )
    requested = set(wanted)
    parents = {
        parent for parent, _roms in wanted.values() if parent and parent not in wanted
    }
    if parents:
        with open_stream() as stream:
            for name, value in _scan_listxml(stream, parents.__contains__).items():
                wanted.setdefault(name, value)

    entries: list[dict] = []
    for name, (parent, roms) in sorted(wanted.items()):
        # A parent read only to complete a child is not itself an entry.
        if name not in requested:
            continue
        members = {member["name"]: member for member in wanted.get(parent, (None, []))[1]} if parent else {}
        members.update({member["name"]: member for member in roms})
        if not members:
            continue
        entries.append(
            {
                "dat": label,
                "name": f"{name}.zip",
                "set": name,
                "description": f"parent {parent}" if parent else name,
                "members": sorted(members.values(), key=lambda m: m["name"]),
            }
        )
    return entries


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


def _iter_dat_contents(pack: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (member name, content bytes) for DAT files in *pack*."""
    if pack.is_dir():
        for path in sorted(pack.rglob("*")):
            if path.suffix.lower() in (".dat", ".xml") and path.is_file():
                yield path.name, path.read_bytes()
        return
    if pack.suffix.lower() == ".zip":
        with zipfile.ZipFile(pack) as archive:
            for info in sorted(archive.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                if Path(info.filename).suffix.lower() not in (".dat", ".xml"):
                    continue
                if info.file_size > MAX_MEMBER_SIZE:
                    # Said out loud: a DAT left out silently ended the run
                    # on "Unchanged" with a version missing.
                    print(
                        f"  Skipping {info.filename}: {info.file_size} bytes "
                        f"exceeds {MAX_MEMBER_SIZE}",
                        file=sys.stderr,
                    )
                    continue
                yield info.filename, archive.read(info)
        return
    yield pack.name, pack.read_bytes()


MAME_LISTXML_URL = (
    "https://github.com/mamedev/mame/releases/download/{tag}/{tag}lx.zip"
)
MAME_LATEST_API = "https://api.github.com/repos/mamedev/mame/releases/latest"
FBNEO_API = "https://api.github.com/repos/libretro/FBNeo"


def _api_json(url: str) -> object:
    from .base_scraper import github_headers

    request = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


class NoReleaseError(ValueError):
    def __init__(self) -> None:
        super().__init__("the newest MAME release carries no tag")


def latest_mame_tag() -> str:
    """Tag of the newest MAME release, the one ``--fetch`` takes by default."""
    payload = _api_json(MAME_LATEST_API)
    tag = payload.get("tag_name") if isinstance(payload, dict) else None
    if not tag:
        raise NoReleaseError
    return str(tag)


def fetch_tag(source: str, requested: str) -> str:
    """The revision a ``--fetch`` names: bare, the newest MAME release or
    the tip of FBNeo's default branch."""
    if source == "mame" and requested == "latest":
        tag = latest_mame_tag()
        print(f"  Derniere release MAME : {tag}")
        return tag
    return requested


class BlobMismatchError(ValueError):
    """A downloaded DAT is not the blob the repository listing names."""


def git_blob_sha(data: bytes) -> str:
    """The sha git gives a blob, so a cached file can be checked against a
    repository listing without any other state."""
    digest = hashlib.sha1(f"blob {len(data)}\0".encode())
    digest.update(data)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> Path:
    """Fetch *url* to *destination* unless it is already there."""
    if destination.is_file():
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "retrobios"})
    scratch = destination.with_suffix(destination.suffix + f".{os.getpid()}.part")
    try:
        with urllib.request.urlopen(request, timeout=300) as response, scratch.open(
            "wb"
        ) as handle:
            shutil.copyfileobj(response, handle)
        scratch.replace(destination)
    finally:
        if scratch.exists():
            scratch.unlink()
    return destination


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
        return (
            _download(MAME_LISTXML_URL.format(tag=tag), cache_dir / f"{tag}lx.zip"),
            {},
        )

    # The revision is resolved to a commit first and everything is read at
    # that commit: a branch URL is served through a CDN cache, so the bytes
    # could predate the listing that named their blob.
    ref = "HEAD" if tag == "latest" else urllib.parse.quote(tag, safe="")
    commit = _api_json(f"{FBNEO_API}/commits/{ref}")
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not sha:
        raise BlobMismatchError(f"libretro/FBNeo has no revision {tag}")
    listing = _api_json(f"{FBNEO_API}/contents/dats?ref={sha}")
    target = cache_dir / "fbneo-dats"
    target.mkdir(parents=True, exist_ok=True)
    blobs: dict[str, str] = {}
    for item in listing:
        if item.get("type") != "file" or not item["name"].lower().endswith(".dat"):
            continue
        destination = target / item["name"]
        # The cache is addressed by content: a file already there is kept
        # only while its blob sha is the one the repository lists.
        if destination.is_file() and git_blob_sha(destination.read_bytes()) != item["sha"]:
            destination.unlink()
        _download(item["download_url"], destination)
        if git_blob_sha(destination.read_bytes()) != item["sha"]:
            destination.unlink()
            raise BlobMismatchError(
                f"{item['name']} downloaded from {item['download_url']} is not "
                f"blob {item['sha']} of libretro/FBNeo {sha}"
            )
        blobs[item["name"]] = item["sha"]
    # A DAT the revision does not carry is not read from an older fetch.
    for stale in target.glob("*"):
        if stale.is_file() and stale.name not in blobs:
            stale.unlink()
    return target, blobs


def _is_listxml(pack: Path) -> bool:
    """Whether *pack* holds a MAME -listxml document rather than a DAT."""
    if pack.is_dir():
        return False
    if pack.suffix.lower() == ".zip":
        with zipfile.ZipFile(pack) as archive:
            names = [n for n in archive.namelist() if n.lower().endswith(".xml")]
            if not names:
                return False
            with archive.open(names[0]) as handle:
                return b"<!ELEMENT mame" in handle.read(4096)
    with pack.open("rb") as handle:
        return b"<!ELEMENT mame" in handle.read(4096)


def _listxml_opener(pack: Path) -> Callable[[], io.BufferedIOBase]:
    """A callable giving a fresh byte stream over the listxml document."""
    if pack.suffix.lower() == ".zip":
        def opener() -> zipfile.ZipExtFile:
            archive = zipfile.ZipFile(pack)
            name = next(n for n in archive.namelist() if n.lower().endswith(".xml"))
            stream = archive.open(name)
            stream.close_archive = archive  # keep the archive alive
            return stream

        return opener
    return lambda: pack.open("rb")


def main() -> int:
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
    parser.add_argument(
        "--emulators-dir", default="emulators",
        help="emulator profile directory (default: %(default)s)",
    )
    parser.add_argument(
        "--platforms-dir", default="platforms",
        help="platform YAML directory (default: %(default)s)",
    )
    parser.add_argument(
        "--all", action="store_true", help="keep every set, not only referenced ones"
    )
    parser.add_argument(
        "--provenance-dir", default="provenance",
        help="dump catalogs whose missing entries keep the sets holding them "
             "(default: %(default)s)",
    )
    parser.add_argument(
        "--db", default="database.json",
        help="collection database the catalogs are compared with (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print what would change and write nothing",
    )
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
        except BlobMismatchError as exc:
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
    keep = (
        None
        if args.all
        else relevant_archives(args.emulators_dir, args.platforms_dir)
    )
    targets = None if args.all else catalog_targets(args.provenance_dir, args.db)

    dats: dict[str, str] = {}
    entries: list[dict] = []
    skipped = 0

    if _is_listxml(pack):
        label = f"MAME {pack.stem.replace('lx', '')}"
        entries = listxml_entries(_listxml_opener(pack), label, keep, targets)
        dats[label] = pack.stem
        print(f"  {label}: {len(entries)} sets retenus")
        members = sum(len(entry["members"]) for entry in entries)
        print(f"{len(entries)} recettes, {members} membres, depuis 1 listxml")
        if args.dry_run:
            return 0
        changed = merge_snapshot(output, args.source, dats, entries)
        print(f"{'Wrote' if changed else 'Unchanged'} {output}")
        return 0

    for member, content in _iter_dat_contents(pack):
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
        found = recipe_entries(dat, keep, targets)
        if not found:
            continue
        dats[dat.name or member] = dat.version
        entries.extend(found)
        print(f"  {dat.name or member}: {len(found)} sets retenus")

    if skipped:
        print(f"  {skipped} fichier(s) ignore(s) (non-Logiqx ou vides)")
    members = sum(len(entry["members"]) for entry in entries)
    print(f"{len(entries)} recettes, {members} membres, depuis {len(dats)} DAT")

    if args.dry_run:
        return 0

    changed = merge_snapshot(output, args.source, dats, entries, blobs)
    print(f"{'Wrote' if changed else 'Unchanged'} {output}")
    return 0


if __name__ == "__main__":
    run_cli(main)
