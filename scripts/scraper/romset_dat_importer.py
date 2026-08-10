"""Import romset recipes from a MAME or FBNeo DAT.

A DAT states, per set, the members an emulator version expects: name, size
and CRC32. That is a recipe, and TorrentZip turns a recipe plus the ROM bytes
into the exact archive. Profiles document a few hundred sets by hand; a DAT
documents every set of one version at once.

MAME ships its ``-listxml`` output as a release asset and FBNeo keeps its DATs
in its repository, so both are fetched without a browser:

    python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289
    python -m scripts.scraper.romset_dat_importer --source fbneo --fetch
    python -m scripts.scraper.romset_dat_importer --source mame --pack local.dat

Only sets the collection has a reason to know are kept, so the committed
snapshot stays small: the archive names that emulator profiles or platform
BIOS lists reference. ``--all`` keeps everything.

Members without a CRC32 are undumped. A real romset does not carry them, so
they are dropped from the recipe rather than disqualifying the whole set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ..common import (
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    write_provenance_snapshot,
)
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


def recipe_entries(
    dat: LogiqxDat, keep: set[str] | None = None
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
        if keep is not None and archive not in keep:
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


def _scan_listxml(stream, selector) -> dict[str, tuple[str | None, list[dict]]]:
    """Stream a MAME -listxml document, keeping the machines *selector* wants.

    The document is 311 MB for MAME 0.289, so it is never held whole: the
    reader keeps a sliding window just large enough to close the element it
    is in the middle of.
    """
    found: dict[str, tuple[str | None, list[dict]]] = {}
    buffer = b""
    while chunk := stream.read(LISTXML_CHUNK):
        buffer += chunk
        position = 0
        while True:
            match = _MACHINE.search(buffer, position)
            if not match:
                break
            end = buffer.find(b"</machine>", match.end())
            if end == -1:
                break
            name = match.group(1).decode()
            if selector(name):
                parent = _ROMOF.search(match.group(2).decode())
                found[name] = (
                    parent.group(1) if parent else None,
                    _machine_roms(buffer[match.end() : end]),
                )
            position = end + len(b"</machine>")
        buffer = buffer[position:] if position else buffer[-(2 * LISTXML_CHUNK) :]
    return found


def listxml_entries(
    open_stream, label: str, keep: set[str] | None
) -> list[dict]:
    """Recipes from a MAME -listxml document, parents resolved.

    A non-merged archive carries its parent set's ROMs as well as its own, so
    a machine with ``romof`` is read as the union, its own members winning a
    name collision. Two passes: the parents a set needs are only known once
    that set has been seen.
    """
    with open_stream() as stream:
        wanted = _scan_listxml(
            stream, lambda name: keep is None or f"{name}.zip" in keep
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
    output: str, source: str, dats: dict[str, str], entries: list[dict]
) -> bool:
    """Accumulate recipes across versions instead of replacing them.

    A platform pins the archive of whichever version its list was built
    against, so the snapshot is a growing library of versions, not a picture
    of the newest one.
    """
    path = Path(output)
    known_entries: list[dict] = []
    known_dats: dict[str, str] = {}
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            existing = json.load(handle)
        known_entries = list(existing.get("entries", []))
        known_dats = dict(existing.get("dats", {}))

    known_dats.update(dats)
    return write_provenance_snapshot(
        output,
        source,
        datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        known_dats,
        compact_entries(known_entries + entries),
    )


def _iter_dat_contents(pack: Path):
    """Yield (member name, content bytes) for DAT files in *pack*."""
    if pack.is_dir():
        for path in sorted(pack.rglob("*")):
            if path.suffix.lower() in (".dat", ".xml") and path.is_file():
                yield path.name, path.read_bytes()
        return
    if pack.suffix.lower() == ".zip":
        with zipfile.ZipFile(pack) as archive:
            for info in sorted(archive.infolist(), key=lambda i: i.filename):
                if info.is_dir() or info.file_size > MAX_MEMBER_SIZE:
                    continue
                if Path(info.filename).suffix.lower() not in (".dat", ".xml"):
                    continue
                yield info.filename, archive.read(info)
        return
    yield pack.name, pack.read_bytes()


MAME_LISTXML_URL = (
    "https://github.com/mamedev/mame/releases/download/{tag}/{tag}lx.zip"
)
FBNEO_DATS_API = "https://api.github.com/repos/libretro/FBNeo/contents/dats"


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


def fetch_pack(source: str, tag: str, cache_dir: Path) -> Path:
    """Download the upstream DAT for *source*.

    MAME ships its ``-listxml`` output as a release asset, and FBNeo keeps its
    DATs in the repository, so neither needs a browser.
    """
    if source == "mame":
        return _download(
            MAME_LISTXML_URL.format(tag=tag), cache_dir / f"{tag}lx.zip"
        )

    request = urllib.request.Request(
        FBNEO_DATS_API, headers={"User-Agent": "retrobios"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        listing = json.load(response)
    target = cache_dir / "fbneo-dats"
    target.mkdir(parents=True, exist_ok=True)
    for item in listing:
        if item.get("type") == "file" and item["name"].lower().endswith(".dat"):
            _download(item["download_url"], target / item["name"])
    return target


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


def _listxml_opener(pack: Path):
    """A callable giving a fresh byte stream over the listxml document."""
    if pack.suffix.lower() == ".zip":
        def opener():
            archive = zipfile.ZipFile(pack)
            name = next(n for n in archive.namelist() if n.lower().endswith(".xml"))
            stream = archive.open(name)
            stream.close_archive = archive  # keep the archive alive
            return stream

        return opener
    return lambda: pack.open("rb")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=SOURCES, required=True)
    parser.add_argument("--pack", help="DAT file, ZIP or directory")
    parser.add_argument(
        "--fetch",
        nargs="?",
        const="mame0289",
        help="download upstream instead of using --pack (MAME tag, e.g. mame0289)",
    )
    parser.add_argument("--cache-dir", default=".cache/dats")
    parser.add_argument("--output", default="")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--platforms-dir", default="platforms")
    parser.add_argument(
        "--all", action="store_true", help="keep every set, not only referenced ones"
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.fetch:
        pack = fetch_pack(args.source, args.fetch, Path(args.cache_dir))
        print(f"  Recupere {pack}")
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

    dats: dict[str, str] = {}
    entries: list[dict] = []
    skipped = 0

    if _is_listxml(pack):
        label = f"MAME {pack.stem.replace('lx', '')}"
        entries = listxml_entries(_listxml_opener(pack), label, keep)
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
        found = recipe_entries(dat, keep)
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

    changed = merge_snapshot(output, args.source, dats, entries)
    print(f"{'Wrote' if changed else 'Unchanged'} {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
