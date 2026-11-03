"""Import, per arcade core version, which BIOS set each game set loads.

A game set names its parent through ``romof``: a clone reads its parent game,
and the chain ends at a BIOS set (``neogeo``, ``naomi``, ``pgm``). The archive
the installer has to provide for a game on the card is every BIOS set on that
chain, plus, for the MAME family, the device sets with ROMs the machine
instantiates (``device_ref``), which a split or merged romset reads from their
own archive. The DAT that answers is the one of the core version that runs
the game, read at the revision its profile pins:

    python -m scripts.scraper.arcade_parent_importer --all
    python -m scripts.scraper.arcade_parent_importer --profile mame2003_plus
    python -m scripts.scraper.arcade_parent_importer --all --offline

A BIOS set is ``isbios="yes"`` (MAME 0.139 and later, FBNeo) or, in the
MAME 0.78 lineage (mame2003, mame2003-plus), which has no such attribute, a
set marked ``runnable="no"``. flycast keeps its NAOMI and Atomiswave table in
code: ``Games[].bios`` names the BIOS, ``naomi`` when it is null
(core/hw/naomi/naomi_cart.cpp:195-197), and ``BIOS[].filename`` the archive
when it differs from the name (naomi_cart.cpp:75).

Output: games/arcade/<profile>.json. CHD games are listed, not resolved: a
CHD is game content. A ``romof`` pointing outside the DAT is listed with its
target, never guessed. The games that load no BIOS set (``no_bios``) and
every BIOS set (``bios_sets``) are listed too: a set name on a card that
none of the lists holds is one the core's DAT does not know.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.parse
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..common import load_emulator_profiles
from .romset_dat_importer import (
    LISTXML_CHUNK,
    MAME_LISTXML_URL,
    BlobMismatchError,
    _api_json,
    _download,
    _listxml_opener,
    _machine_roms,
    fetch_pack,
    git_blob_sha,
)

SCHEMA_VERSION = 1
DEFAULT_OUTPUT = Path("games") / "arcade"
DEFAULT_CACHE = Path(".cache") / "dats"

# How each profile's DAT is found. "listxml": the -listxml release asset of
# the MAME version core_version names. "fbneo": every DAT of libretro/FBNeo's
# dats/ at source_commit. "repo": files of the profile's source repository at
# source_commit (a ZIP member when the file is an archive). "flycast": the
# BIOS and Games tables of naomi_roms.cpp at source_commit.
PROFILES: dict[str, dict] = {
    "mame": {"kind": "listxml", "marker": "isbios"},
    "mame0258": {"kind": "listxml", "marker": "isbios"},
    "mame0278": {"kind": "listxml", "marker": "isbios"},
    "fbneo": {"kind": "fbneo", "marker": "isbios"},
    "mame2016": {
        "kind": "repo",
        "marker": "isbios",
        "paths": ["metadata/MAME 0.174 Arcade XML DAT.zip", "metadata/MAME 0.174 Home XML DAT.zip"],
    },
    "mame2015": {"kind": "repo", "marker": "isbios", "paths": ["metadata/mame2014-xml.zip"]},
    "mame2010": {"kind": "repo", "marker": "isbios", "paths": ["metadata/mame2010.xml"]},
    "mame2003_plus": {"kind": "repo", "marker": "runnable", "paths": ["metadata/mame2003-plus.xml"]},
    "mame2003": {"kind": "repo", "marker": "runnable", "paths": ["metadata/mame2003.xml"]},
    "mame2000": {"kind": "repo", "marker": "isbios", "paths": ["metadata/MAME 0.37b5 XML.dat"]},
    "flycast": {"kind": "flycast", "paths": ["core/hw/naomi/naomi_roms.cpp"]},
}

# About 95 % of what the pinned DATs gave on 2026-11-03: a build that
# resolves fewer games to a BIOS set has read a DAT of another shape.
FLOORS: dict[str, int] = {
    "mame": 2600,
    "mame0258": 2490,
    "mame0278": 2580,
    "fbneo": 9800,
    "mame2016": 1840,
    "mame2015": 1470,
    "mame2010": 1060,
    "mame2003_plus": 650,
    "mame2003": 420,
    "mame2000": 120,
    "flycast": 330,
}


@dataclass
class SetEntry:
    """What the index needs from one machine or game element."""

    name: str
    romof: str | None = None
    isbios: bool = False
    isdevice: bool = False
    runnable: bool = True
    has_roms: bool = False
    disks: bool = False
    devices: list[str] = field(default_factory=list)


_ELEMENT = re.compile(rb"<(machine|game)\b([^>]*)>")
_ATTR = re.compile(rb'([\w:-]+)="([^"]*)"')
_DEVICE_REF = re.compile(rb'<device_ref\b[^>]*\bname="([^"]+)"')
_DISK = re.compile(rb"<disk\b([^>]*)>")
# Longer than any start tag the DATs write, shorter than any element.
_TAG_TAIL = 4096


def _attrs(raw: bytes) -> dict[str, str]:
    return {k.decode(): v.decode() for k, v in _ATTR.findall(raw)}


def iter_sets(stream: io.BufferedIOBase) -> Iterator[SetEntry]:
    """Every machine or game element of a DAT or -listxml, streamed.

    Attributes come in any order (mame2003 writes ``<game runnable="no"
    name="neogeo">``), and the document is never held whole: the window
    keeps only the element being closed.
    """
    buffer = b""
    while True:
        chunk = stream.read(LISTXML_CHUNK)
        buffer += chunk
        position = 0
        # Where the next read has to resume: the start of an element still
        # open, else a tail long enough to hold a start tag cut in two.
        keep_from = max(0, len(buffer) - _TAG_TAIL)
        while True:
            match = _ELEMENT.search(buffer, position)
            if not match:
                break
            closing = b"</" + match.group(1) + b">"
            end = buffer.find(closing, match.end())
            if end == -1:
                keep_from = match.start()
                break
            attrs = _attrs(match.group(2))
            body = buffer[match.end() : end]
            disks = [_attrs(d) for d in _DISK.findall(body)]
            yield SetEntry(
                name=attrs.get("name", ""),
                romof=attrs.get("romof") or None,
                isbios=attrs.get("isbios") == "yes",
                isdevice=attrs.get("isdevice") == "yes",
                runnable=attrs.get("runnable", "yes") != "no",
                has_roms=bool(_machine_roms(body)),
                disks=any(d.get("status") != "nodump" for d in disks),
                devices=[d.decode() for d in _DEVICE_REF.findall(body)],
            )
            position = end + len(closing)
            keep_from = max(position, len(buffer) - _TAG_TAIL)
        if not chunk:
            return
        buffer = buffer[keep_from:]


def is_bios(entry: SetEntry, marker: str) -> bool:
    if entry.isbios:
        return True
    return marker == "runnable" and not entry.runnable and not entry.isdevice


def build_index(sets: dict[str, SetEntry], marker: str) -> dict:
    """BIOS sets per game, device sets per game, CHD games, broken chains."""
    bios_names = {n for n, e in sets.items() if is_bios(e, marker)}
    device_roms = {n for n, e in sets.items() if e.isdevice and e.has_roms}
    games = {
        n: e for n, e in sets.items()
        if n not in bios_names and not e.isdevice and e.runnable and (e.has_roms or e.disks)
    }
    bios: dict[str, set[str]] = {}
    devices: dict[str, set[str]] = {}
    missing: dict[str, str] = {}
    for name, entry in games.items():
        seen = {name}
        current = entry.romof
        while current and current not in seen:
            seen.add(current)
            parent = sets.get(current)
            if parent is None:
                missing[name] = current
                break
            if current in bios_names:
                bios.setdefault(current, set()).add(name)
            current = parent.romof
        for device in set(entry.devices) & device_roms:
            devices.setdefault(device, set()).add(name)
    with_bios = {g for members in bios.values() for g in members}
    return {
        "bios": {k: sorted(v) for k, v in sorted(bios.items())},
        "devices": {k: sorted(v) for k, v in sorted(devices.items())},
        "chd": sorted(n for n, e in games.items() if e.disks),
        "missing_parents": dict(sorted(missing.items())),
        "no_bios": sorted(set(games) - with_bios - set(missing)),
        "bios_sets": sorted(bios_names),
        "counts": {
            "sets": len(sets),
            "games": len(games),
            "games_with_bios": len(with_bios),
            "bios_sets": len(bios_names),
            "bios_roots_used": len(bios),
            "games_with_devices": len({g for v in devices.values() for g in v}),
            "chd_games": sum(1 for e in games.values() if e.disks),
            "missing_parents": len(missing),
        },
    }


# --- C table reader (flycast naomi_roms.cpp) ---------------------------------

_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|[{},]|[^\s{},"]+')


def _strip_comments(text: str) -> str:
    """C source with comments removed, string literals kept intact."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            i = text.find("\n", i)
            i = n if i == -1 else i
        elif text.startswith("/*", i):
            i = text.find("*/", i + 2)
            i = n if i == -1 else i + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _initializer(text: str, array: str) -> list:
    """The brace initializer of ``const <type> <array>[] = {...}`` as nested
    lists of tokens, each element split on its top-level commas."""
    match = re.search(rf"\b{re.escape(array)}\s*\[\s*\]\s*=\s*\{{", text)
    if not match:
        raise ValueError(f"no initializer for {array}[]")
    tokens = _TOKEN.findall(text[match.end() - 1 :])
    stack: list[list] = []
    item: list = []
    for token in tokens:
        if token == "{":
            stack.append(item)
            item = []
            stack.append([])
        elif token == "}":
            elements = stack.pop()
            if item:
                elements.append(item if len(item) > 1 else item[0])
            item = stack.pop()
            item.append(elements)
            if not stack:
                return item[0]
        elif token == ",":
            elements = stack[-1]
            if item:
                elements.append(item if len(item) > 1 else item[0])
            item = []
        else:
            item.append(token)
    raise ValueError(f"unterminated initializer for {array}[]")


def _string(token: object) -> str | None:
    if isinstance(token, str) and token.startswith('"'):
        return token[1:-1]
    return None


def flycast_index(source: str) -> dict:
    """BIOS archive per NAOMI/Atomiswave game from naomi_roms.cpp."""
    text = _strip_comments(source)
    archive_of: dict[str, str] = {}
    for element in _initializer(text, "BIOS"):
        if not isinstance(element, list) or not element:
            continue
        name = _string(element[0])
        if name is None:
            continue
        # BIOS_t: name, blobs[], filename (naomi_roms.h:53-66).
        filename = _string(element[2]) if len(element) > 2 else None
        archive_of[name] = filename or name
    bios: dict[str, set[str]] = {}
    chd: list[str] = []
    unknown: dict[str, str] = {}
    games: set[str] = set()
    for element in _initializer(text, "Games"):
        if not isinstance(element, list) or not element:
            continue
        name = _string(element[0])
        if name is None:
            continue
        # shors2k2 is declared twice at e88b0ced: a name counts once.
        games.add(name)
        # Game: name, parent_name, description, size, key, bios, cart_type,
        # rotation, blobs[], gdrom_name, ... (naomi_roms.h:71-94).
        named = _string(element[5]) if len(element) > 5 else None
        if named is not None and named not in archive_of:
            unknown[name] = named
            continue
        bios.setdefault(archive_of[named or "naomi"], set()).add(name)
        if len(element) > 9 and _string(element[9]):
            chd.append(name)
    return {
        "bios": {k: sorted(v) for k, v in sorted(bios.items())},
        "devices": {},
        "chd": sorted(chd),
        "missing_parents": dict(sorted(unknown.items())),
        "no_bios": [],
        "bios_sets": sorted(set(archive_of.values())),
        "counts": {
            "sets": len(games) + len(archive_of),
            "games": len(games),
            "games_with_bios": len({g for v in bios.values() for g in v}),
            "bios_sets": len(archive_of),
            "bios_roots_used": len(bios),
            "games_with_devices": 0,
            "chd_games": len(chd),
            "missing_parents": len(unknown),
        },
    }


# --- Fetching ----------------------------------------------------------------


def _repo_slug(url: str) -> str:
    parts = [p for p in urllib.parse.urlsplit(url).path.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"not a repository URL: {url}")
    return f"{parts[0]}/{parts[1].removesuffix('.git')}"


def fetch_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """One file of a GitHub repository at a commit, checked against the blob
    sha the repository lists for it, and that sha."""
    folder, _, name = path.rpartition("/")
    listing = _api_json(
        f"https://api.github.com/repos/{slug}/contents/{urllib.parse.quote(folder)}?ref={commit}"
    )
    item = next(
        (i for i in listing if isinstance(i, dict) and i.get("name") == name), None
    ) if isinstance(listing, list) else None
    if item is None:
        raise FileNotFoundError(f"{slug}@{commit[:8]} has no {path}")
    destination = cache_dir / "repo" / slug / commit / path
    if destination.is_file() and git_blob_sha(destination.read_bytes()) != item["sha"]:
        destination.unlink()
    url = (
        f"https://raw.githubusercontent.com/{slug}/{commit}/"
        f"{urllib.parse.quote(path)}"
    )
    _download(url, destination)
    if git_blob_sha(destination.read_bytes()) != item["sha"]:
        destination.unlink()
        raise BlobMismatchError(f"{url} is not blob {item['sha']}")
    return destination, item["sha"]


def _cached_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """The cached copy, offline. Its blob sha is recomputed from the bytes."""
    destination = cache_dir / "repo" / slug / commit / path
    if not destination.is_file():
        raise FileNotFoundError(f"{slug}@{commit[:8]}:{path} is not in {cache_dir}")
    return destination, git_blob_sha(destination.read_bytes())


def _xml_streams(path: Path) -> Iterator[Callable[[], io.BufferedIOBase]]:
    """Openers for the XML documents a file holds: itself, or each XML or
    DAT member of a ZIP."""
    if path.suffix.lower() != ".zip":
        yield lambda: path.open("rb")
        return
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            n for n in archive.namelist() if n.lower().endswith((".xml", ".dat"))
        )
    for member in names:
        def opener(member: str = member) -> io.BufferedIOBase:
            archive = zipfile.ZipFile(path)
            stream = archive.open(member)
            stream.close_archive = archive  # keep the archive alive
            return stream

        yield opener


def read_sets(openers: list[Callable[[], io.BufferedIOBase]]) -> dict[str, SetEntry]:
    """Every set of several documents. A set read twice keeps its first
    reading: FBNeo's Arcade and Neogeo DATs both carry the neogeo BIOS."""
    sets: dict[str, SetEntry] = {}
    for opener in openers:
        with opener() as stream:
            for entry in iter_sets(stream):
                if entry.name:
                    sets.setdefault(entry.name, entry)
    return sets


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def import_profile(
    profile: str, data: dict, cache_dir: Path, offline: bool = False
) -> dict:
    """The index document for one profile, from the DAT its pin names."""
    spec = PROFILES[profile]
    commit = str(data.get("source_commit") or "")
    source_url = str(data.get("source") or "")
    kind = spec["kind"]
    if kind == "listxml":
        tag = "mame" + str(data["core_version"]).replace(".", "").zfill(4)
        if offline:
            pack = cache_dir / f"{tag}lx.zip"
            if not pack.is_file():
                raise FileNotFoundError(f"{pack} is not cached")
        else:
            pack, _ = fetch_pack("mame", tag, cache_dir)
        source = {
            "release": f"mamedev/mame {tag}",
            "url": MAME_LISTXML_URL.format(tag=tag),
            "sha256": _sha256(pack),
        }
        index = build_index(read_sets([_listxml_opener(pack)]), spec["marker"])
    elif kind == "fbneo":
        if offline:
            folder = cache_dir / "fbneo-dats"
            blobs = {p.name: git_blob_sha(p.read_bytes()) for p in sorted(folder.glob("*.dat"))}
            if not blobs:
                raise FileNotFoundError(f"{folder} is not cached")
        else:
            folder, blobs = fetch_pack("fbneo", commit, cache_dir)
        source = {
            "repo": source_url,
            "commit": commit,
            "files": {f"dats/{name}": sha for name, sha in sorted(blobs.items())},
        }
        openers = [
            (lambda p=folder / name: p.open("rb")) for name in sorted(blobs)
        ]
        index = build_index(read_sets(openers), spec["marker"])
    else:
        slug = _repo_slug(source_url)
        files: dict[str, str] = {}
        paths: list[Path] = []
        for path in spec["paths"]:
            local, sha = (
                _cached_repo_file(slug, commit, path, cache_dir)
                if offline
                else fetch_repo_file(slug, commit, path, cache_dir)
            )
            files[path] = sha
            paths.append(local)
        source = {"repo": source_url, "commit": commit, "files": files}
        if kind == "flycast":
            index = flycast_index(paths[0].read_text(encoding="utf-8"))
        else:
            openers = [opener for p in paths for opener in _xml_streams(p)]
            index = build_index(read_sets(openers), spec["marker"])
    return {
        "schema": SCHEMA_VERSION,
        "profile": profile,
        "core_version": data.get("core_version"),
        "source": source,
        **index,
    }


# --- Checks against the collection -------------------------------------------


def declared_archives(profile: dict) -> set[str]:
    """Archive names a profile declares, lowercased: file names, aliases and
    the archive a member lives in."""
    names: set[str] = set()
    for entry in profile.get("files") or []:
        for value in [entry.get("name"), entry.get("archive"), *(entry.get("aliases") or [])]:
            if isinstance(value, str) and value:
                names.add(value.rsplit("/", 1)[-1].lower())
    return names


def collection_names(database: Path) -> set[str]:
    if not database.is_file():
        return set()
    with database.open(encoding="utf-8") as handle:
        db = json.load(handle)
    return {n.lower() for n in db.get("indexes", {}).get("by_name", {})}


def bios_roots(doc: dict) -> list[str]:
    return sorted(doc["bios"])


def dump(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def write_if_changed(path: Path, text: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_suffix(path.suffix + ".part")
    scratch.write_text(text, encoding="utf-8")
    scratch.replace(path)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--profile", action="append", choices=sorted(PROFILES))
    which.add_argument("--all", action="store_true")
    parser.add_argument("--emulators-dir", default="emulators")
    parser.add_argument("--database", default="database.json")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--offline", action="store_true", help="read the download cache only")
    parser.add_argument("--dry-run", action="store_true", help="print coverage, write nothing")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    names = collection_names(Path(args.database))
    failed = False
    for profile in sorted(PROFILES) if args.all else args.profile:
        if profile not in profiles:
            print(f"FAIL {profile}: no emulators/{profile}.yml", file=sys.stderr)
            failed = True
            continue
        try:
            doc = import_profile(profile, profiles[profile], args.cache_dir, args.offline)
        except (OSError, ValueError, KeyError) as exc:
            print(f"FAIL {profile}: {exc}", file=sys.stderr)
            failed = True
            continue
        counts = doc["counts"]
        roots = bios_roots(doc)
        declared = declared_archives(profiles[profile])
        undeclared = [r for r in roots if f"{r}.zip" not in declared]
        absent = [r for r in roots if names and f"{r}.zip" not in names]
        print(
            f"{profile}: {counts['games']} games, {counts['games_with_bios']} with a BIOS set, "
            f"{counts['bios_roots_used']} BIOS sets used, "
            f"{counts['games_with_devices']} with device sets, {counts['chd_games']} CHD, "
            f"{counts['missing_parents']} parents absent from the DAT"
        )
        if absent:
            print(f"  BIOS sets absent from the collection: {', '.join(absent)}")
        if undeclared:
            print(f"  BIOS sets the profile does not declare: {', '.join(undeclared)}")
        floor = FLOORS.get(profile, 0)
        if counts["games_with_bios"] < floor:
            print(
                f"FAIL {profile}: {counts['games_with_bios']} games with a BIOS set, "
                f"floor {floor}",
                file=sys.stderr,
            )
            failed = True
            continue
        if not args.dry_run:
            target = args.output_dir / f"{profile}.json"
            if write_if_changed(target, dump(doc)):
                print(f"  wrote {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
