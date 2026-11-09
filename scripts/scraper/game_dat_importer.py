"""Import game catalogs from No-Intro and Redump DATs, one file per system.

The games-on-card mode identifies a game from its bytes: a cartridge by the
crc32 and size a ZIP central directory gives without inflating, a disc by
the first data track or the serial its header carries. These catalogs hold
those keys with the title and the territory the DAT names the game for.
They are game catalogues, not dump catalogues of BIOS files, so they live in
games/catalogs/ and never in provenance/.

    python -m scripts.scraper.game_dat_importer --fetch
    python -m scripts.scraper.game_dat_importer --fetch --source redump
    python -m scripts.scraper.game_dat_importer --offline --floor
    python -m scripts.scraper.game_dat_importer --source no-intro --pack no-intro.zip

No-Intro comes from the auto-datfile-generator release asset (Dat-o-Matic
bans automated clients), Redump from redump.info's per-system datfile route.
The mirror is dantob's fork: hugo19941994's original has failed its daily
rebuild since Dat-o-Matic's 2026-07 re-layout (no-intro.zip last rebuilt
2026-07-08), and the fork carries the fix (d4a9d769, 2026-07-31).
Every download is cached under .cache/game-dats/ with what the server said
about it, so a second run reads nothing from the network and writes the same
bytes. A DAT's region tag is a market label, never the value a core computes.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[1])
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from artifacts import copy_stream_atomic, write_if_changed, write_text_atomic  # noqa: E402
from common import parse_untrusted_xml  # noqa: E402
from region import REGIONS, WORLD  # noqa: E402
from region_audit import NOINTRO  # noqa: E402

from .base_scraper import github_headers  # noqa: E402

SOURCES = ("no-intro", "redump")
CACHE_DIR = Path(".cache") / "game-dats"
OUTPUT_DIR = Path("games") / "catalogs"

NOINTRO_MIRROR = "https://github.com/dantob/auto-datfile-generator"
NOINTRO_RELEASE = "Daily_Rebuild"
NOINTRO_RELEASE_API = (
    NOINTRO_MIRROR.replace("https://github.com/", "https://api.github.com/repos/")
    + f"/releases/tags/{NOINTRO_RELEASE}"
)
NOINTRO_ASSET = "no-intro.zip"
REDUMP_DATFILE_URL = "https://redump.info/datfile/{code}"

# DAT header name -> (repository system id, floor). The floor is the least
# number of games the DAT may hold before an import is refused as truncated:
# 95 % of the count read on 2026-11-03, rounded down.
NOINTRO_DATS: dict[str, tuple[str, int]] = {
    "Nintendo - Super Nintendo Entertainment System": ("nintendo-snes", 3920),
    "Nintendo - Game Boy": ("nintendo-gb", 1897),
    "Nintendo - Game Boy Color": ("nintendo-gbc", 1935),
    "Nintendo - Game Boy Advance": ("nintendo-gba", 3356),
    "Nintendo - Nintendo 64 (BigEndian)": ("nintendo-64", 1098),
    "Sega - Mega Drive - Genesis": ("sega-megadrive", 2718),
    "Nintendo - Nintendo Entertainment System (Headered)": ("nintendo-nes", 4276),
    "Nintendo - Nintendo DS (Decrypted)": ("nintendo-ds", 7289),
    "NEC - PC Engine - TurboGrafx-16": ("nec-pc-engine", 438),
    "Sega - Master System - Mark III": ("sega-mastersystem", 665),
    "Sega - Game Gear": ("sega-gamegear", 786),
    "Atari - Atari Lynx (LNX)": ("atari-lynx", 17),
    "Nintendo - Nintendo 64DD": ("nintendo-64dd", 33),
    "Nintendo - Family Computer Disk System (FDS)": ("nintendo-fds", 384),
    "Nintendo - Pokemon Mini": ("nintendo-pokemon-mini", 41),
    "Atari - Atari 7800 (A78)": ("atari-7800", 7),
    "Atari - Atari 5200": ("atari-5200", 197),
    "Mattel - Intellivision": ("intellivision", 197),
    "Coleco - ColecoVision": ("colecovision", 190),
    "Magnavox - Odyssey 2": ("odyssey2", 126),
    "GCE - Vectrex": ("vectrex", 45),
    "Nintendo - Satellaview": ("nintendo-satellaview", 570),
    "Nintendo - Sufami Turbo": ("nintendo-sufami-turbo", 12),
    "NEC - PC Engine SuperGrafx": ("nec-supergrafx", 4),
    "Sega - 32X": ("sega-32x", 202),
    "Bandai - WonderSwan": ("wonderswan", 244),
    "Bandai - WonderSwan Color": ("wonderswan-color", 229),
    "SNK - NeoGeo Pocket": ("snk-ngp", 12),
    "SNK - NeoGeo Pocket Color": ("snk-ngpc", 121),
}

# redump.info datfile code -> (DAT header name, repository system id, floor).
REDUMP_DATS: dict[str, tuple[str, str, int]] = {
    "PSX": ("Sony - PlayStation", "sony-playstation", 10432),
    "PS2": ("Sony - PlayStation 2", "sony-playstation-2", 11252),
    "SS": ("Sega - Saturn", "sega-saturn", 2340),
    "MCD": ("Sega - Mega CD & Sega CD", "sega-megacd", 521),
    "DC": ("Sega - Dreamcast", "sega-dreamcast", 1442),
    "GC": ("Nintendo - GameCube", "nintendo-gamecube", 1920),
    "PCE": ("NEC - PC Engine CD & TurboGrafx CD", "nec-pc-engine-cd", 523),
    "NGCD": ("SNK - Neo Geo CD", "snk-neogeo-cd", 107),
    "3DO": ("3DO Interactive Multiplayer", "panasonic-3do", 635),
}

TERMS_READ = "2026-11-03"
LICENCES: dict[str, dict] = {
    "no-intro": {
        "terms_url": "https://datomatic.no-intro.org/terms.html",
        "terms_title": "Data Usage License",
        "terms_updated": "2026-09-11",
        "read": TERMS_READ,
        "quote": (
            'Unless otherwise stated on the website, the data made available through '
            'this website ("Data") may be freely used, copied, reproduced, modified, '
            "adapted, combined, published, distributed, and otherwise reused by anyone "
            "for any lawful purpose, to the extent that the website operator owns or "
            "controls the applicable rights or is authorized to grant such permission. "
            "No permission, attribution, citation, backlink, or acknowledgment of the "
            "website or its operators is required for such use."
        ),
        "mirror": {
            "repo": NOINTRO_MIRROR,
            "licence": "MIT",
            "scope": "the mirror's scripts only, the DATs it republishes stay under the terms above",
        },
    },
    "redump": {
        "terms_url": "https://redump.info/about",
        "read": TERMS_READ,
        "quote": (
            "Dumpers only submit metadata and Redump only stores metadata. This "
            "information is considered public domain to be used however people see fit"
        ),
    },
}

# Territory words the DATs use that scripts/region.py has no member slug
# for. Each falls under the one super-region that contains it.
EXTRA_TERRITORIES = {
    "Scandinavia": "europe",
    "Belgium": "europe",
    "Switzerland": "europe",
    "Austria": "europe",
    "Ireland": "europe",
    "United Kingdom": "uk",
}
_TERRITORY = {**{k: v for k, v in NOINTRO.items()}, **EXTRA_TERRITORIES}
# A territory word with no slug: the group is a territory tag, but the
# catalog cannot name it and records no region.
_UNMAPPED_TERRITORIES = {"South Africa"}

SERIAL_NOTE = (
    "Serials are written as the DAT writes them, and the DAT uses both forms: "
    "'SLES-01971' and 'SLPS 02251' in the PlayStation DAT of the same day. A "
    "core reads the serial from the disc in its own spelling (SYSTEM.CNF holds "
    "'SLPS_022.51', DuckStation reports 'SLPS-02251'). No source fixes a rule "
    "joining the two, so the comparison rule is the reader's to state."
)

_PAREN = re.compile(r"\(([^)]+)\)")
_NOINTRO_MEMBER = re.compile(r"^(?P<name>.+) \((?P<version>\d{8}-\d{6})\)\.dat$")
_DISPOSITION = re.compile(r'filename="(?P<file>[^"]+)"')
_REDUMP_FILE = re.compile(
    r"^(?P<name>.+) - Datfile \((?P<count>\d+)\) \((?P<date>\d{4}-\d{2}-\d{2}) (?P<time>[\d-]+)\)\.(?:zip|dat)$"
)


def name_regions(name: str) -> list[str] | None:
    """Region slugs of the first parenthesised group made only of territory
    words, or None when the name carries no such group or a word the
    vocabulary cannot name."""
    for group in _PAREN.findall(name):
        words = [w.strip() for w in group.split(",")]
        if not words or not all(w in _TERRITORY or w in _UNMAPPED_TERRITORIES for w in words):
            continue
        if any(w in _UNMAPPED_TERRITORIES for w in words):
            return None
        slugs = sorted({_TERRITORY[w] for w in words})
        if WORLD in slugs:
            return [WORLD]
        unknown = set(slugs) - REGIONS
        if unknown:
            raise ValueError(f"region slugs {sorted(unknown)} are outside scripts/region.py")
        return slugs
    return None


@dataclass
class DatGame:
    name: str
    serials: list[str]
    roms: list[tuple[str, int, str, str]]  # (name, size, crc32, sha1)


def parse_dat(content: bytes) -> tuple[str, str, list[DatGame]]:
    """Header name, version and games of a Logiqx DAT, serials included."""
    root = parse_untrusted_xml(content, "DAT files")
    header = root.find("header")
    name = (header.findtext("name") or "").strip() if header is not None else ""
    version = (header.findtext("version") or "").strip() if header is not None else ""
    games: list[DatGame] = []
    for game in root.iter("game"):
        serial = game.findtext("serial") or ""
        serials = [s.strip() for s in serial.split(",") if s.strip()]
        roms = []
        for rom in game.findall("rom"):
            try:
                size = int(rom.get("size") or 0)
            except ValueError:
                size = 0
            roms.append((rom.get("name") or "", size,
                         (rom.get("crc") or "").lower(), (rom.get("sha1") or "").lower()))
        games.append(DatGame(game.get("name") or "", serials, roms))
    return name, version, games


def _first_data_track(roms: list[tuple[str, int, str, str]]) -> tuple[str, int, str, str] | None:
    for rom in roms:
        if rom[0].lower().endswith((".cue", ".gdi")) or not rom[2]:
            continue
        return rom
    return None


def build_catalog(source: str, system: str, dat_name: str, version: str,
                  games: list[DatGame], origin: dict) -> dict:
    """The catalog document of one DAT."""
    region_ids: dict[tuple[str, ...], int] = {}
    rows: list[list] = []
    for game in games:
        regions = name_regions(game.name)
        index = None
        if regions is not None:
            index = region_ids.setdefault(tuple(regions), len(region_ids))
        if source == "redump":
            track = _first_data_track(game.roms)
            if track is None:
                continue
            rows.append([track[2], track[1], track[3], index, game.name, sorted(game.serials)])
        else:
            for _, size, crc, sha1 in game.roms:
                if crc:
                    rows.append([crc, size, sha1, index, game.name])
    # Region ids are renumbered in sorted order so the table does not depend
    # on the DAT's game order.
    order = sorted(region_ids, key=lambda r: (len(r), r))
    renumber = {region_ids[r]: i for i, r in enumerate(order)}
    for row in rows:
        if row[3] is not None:
            row[3] = renumber[row[3]]
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[4]))
    fields = ["crc32", "size", "sha1", "region", "title"]
    doc = {
        "source": source,
        "system": system,
        "dat": dat_name,
        "version": version,
        **origin,
        "licence": LICENCES[source],
        "fields": fields + (["serials"] if source == "redump" else []),
        "regions": [list(r) for r in order],
        "games": rows,
    }
    if source == "redump":
        doc["serial_note"] = SERIAL_NOTE
    return doc


def dump_catalog(doc: dict) -> str:
    """Compact JSON, one game per line so a refresh diffs by game."""
    head = {k: v for k, v in doc.items() if k != "games"}
    text = json.dumps(head, ensure_ascii=False, separators=(",", ":"))[:-1]
    games = ",\n".join(json.dumps(g, ensure_ascii=False, separators=(",", ":")) for g in doc["games"])
    return f'{text},"games":[\n{games}\n]}}\n'


# Fetching ---------------------------------------------------------------


class NotCachedError(RuntimeError):
    """An offline run asked for a download the cache does not hold."""


def _download(url: str, destination: Path, headers: dict[str, str] | None = None) -> dict[str, str]:
    """Stream url to destination and return the response headers kept."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "retrobios", **(headers or {})})
    with urllib.request.urlopen(request, timeout=300) as response:
        copy_stream_atomic(response, str(destination))
        return {"content_disposition": response.headers.get("Content-Disposition", "")}


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def fetch_nointro(cache_dir: Path, offline: bool, refresh: bool) -> tuple[Path, dict]:
    """The No-Intro pack and what the release said about it."""
    meta_path = cache_dir / "no-intro.json"
    if meta_path.is_file() and not refresh:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        pack = cache_dir / meta["file"]
        if pack.is_file():
            return pack, meta
    if offline:
        raise NotCachedError(f"{meta_path} or its pack is not cached")
    request = urllib.request.Request(NOINTRO_RELEASE_API, headers=github_headers())
    with urllib.request.urlopen(request, timeout=60) as response:
        release = json.loads(response.read())
    asset = next(a for a in release["assets"] if a["name"] == NOINTRO_ASSET)
    stamp = asset["updated_at"].replace(":", "").replace("-", "")
    file = f"no-intro-{stamp}.zip"
    pack = cache_dir / file
    if not pack.is_file():
        _download(asset["browser_download_url"], pack)
    if pack.stat().st_size != asset["size"]:
        pack.unlink()
        raise RuntimeError(f"{NOINTRO_ASSET}: size differs from the release's {asset['size']}")
    meta = {
        "file": file,
        "url": asset["browser_download_url"],
        "asset_updated_at": asset["updated_at"],
        "asset_size": asset["size"],
        "fetched": _today(),
    }
    write_text_atomic(str(meta_path), json.dumps(meta, indent=1) + "\n")
    return pack, meta


def fetch_redump(code: str, cache_dir: Path, offline: bool, refresh: bool) -> tuple[Path, dict]:
    """One redump.info datfile and the name its server gave it."""
    folder = cache_dir / "redump"
    meta_path = folder / f"{code}.json"
    pack = folder / f"{code}.zip"
    if meta_path.is_file() and pack.is_file() and not refresh:
        return pack, json.loads(meta_path.read_text(encoding="utf-8"))
    if offline:
        raise NotCachedError(f"{pack} is not cached")
    url = REDUMP_DATFILE_URL.format(code=code)
    kept = _download(url, pack)
    match = _DISPOSITION.search(kept["content_disposition"])
    if not match:
        raise RuntimeError(f"{url} answered without a datfile name")
    meta = {"file": match["file"], "url": url, "fetched": _today()}
    write_text_atomic(str(meta_path), json.dumps(meta, indent=1) + "\n")
    return pack, meta


# Reading packs ----------------------------------------------------------


def _iter_dats(pack: Path) -> Iterator[tuple[str, bytes]]:
    """(member name, bytes) of every .dat in a ZIP, a directory or a file."""
    if pack.is_dir():
        for path in sorted(pack.rglob("*.dat")):
            yield path.name, path.read_bytes()
        return
    if zipfile.is_zipfile(pack):
        with zipfile.ZipFile(pack) as archive:
            for info in sorted(archive.infolist(), key=lambda i: i.filename):
                if info.filename.lower().endswith(".dat"):
                    yield Path(info.filename).name, archive.read(info)
        return
    yield pack.name, pack.read_bytes()


def import_nointro(pack: Path, meta: dict) -> list[dict]:
    docs = []
    for member, data in _iter_dats(pack):
        match = _NOINTRO_MEMBER.match(member)
        name = match["name"] if match else None
        if name not in NOINTRO_DATS:
            # A member named without the version stamp is read for its header.
            if match:
                continue
            name = parse_dat(data)[0]
            if name not in NOINTRO_DATS:
                continue
        dat_name, version, games = parse_dat(data)
        origin = {
            "fetched_from": meta.get("url", ""),
            "fetched": meta.get("fetched", ""),
            "archive": {"member": member, "asset_updated_at": meta.get("asset_updated_at", "")},
        }
        docs.append(build_catalog("no-intro", NOINTRO_DATS[dat_name][0], dat_name, version,
                                  games, origin))
    return docs


def import_redump(pack: Path, meta: dict) -> list[dict]:
    docs = []
    by_name = {name: (code, system) for code, (name, system, _) in REDUMP_DATS.items()}
    for member, data in _iter_dats(pack):
        dat_name, version, games = parse_dat(data)
        if dat_name not in by_name:
            continue
        file = meta.get("file", member)
        stamp = _REDUMP_FILE.match(file)
        origin = {
            "fetched_from": meta.get("url", ""),
            "fetched": meta.get("fetched", ""),
            "archive": {"member": member, "file": file,
                        "dat_date": stamp["date"] if stamp else ""},
        }
        docs.append(build_catalog("redump", by_name[dat_name][1], dat_name, version,
                                  games, origin))
    return docs


def coverage(doc: dict) -> dict:
    games = {row[4] for row in doc["games"]}
    out = {
        "system": doc["system"],
        "games": len(games),
        "rows": len(doc["games"]),
        "with_region": sum(1 for row in doc["games"] if row[3] is not None),
    }
    if doc["source"] == "redump":
        by_serial: dict[str, set] = {}
        for row in doc["games"]:
            for serial in row[5]:
                by_serial.setdefault(serial, set()).add(row[3])
        out["serials"] = len(by_serial)
        out["multi_region_serials"] = sum(1 for v in by_serial.values() if len(v) > 1)
    return out


def floor_of(doc: dict) -> int:
    if doc["source"] == "no-intro":
        return NOINTRO_DATS[doc["dat"]][1]
    return next(f for name, _, f in REDUMP_DATS.values() if name == doc["dat"])


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--source", choices=SOURCES, action="append",
                        help="limit to one source (repeatable, default both)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fetch", action="store_true", help="download what the cache lacks")
    mode.add_argument("--offline", action="store_true", help="read the cache only (default)")
    mode.add_argument("--pack", type=Path, help="import a local ZIP, directory or DAT")
    parser.add_argument("--refresh", action="store_true", help="ask the servers again")
    parser.add_argument("--floor", action="store_true",
                        help="fail when a system holds fewer games than its stored floor")
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR,
                        help=f"downloaded packs (default {CACHE_DIR})")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR,
                        help=f"where the catalogs are written (default {OUTPUT_DIR})")
    parser.add_argument("--dry-run", action="store_true", help="print coverage, write nothing")
    args = parser.parse_args()

    sources = args.source or list(SOURCES)
    if args.pack and len(sources) != 1:
        parser.error("--pack needs one --source")
    offline = not args.fetch
    docs: list[dict] = []
    try:
        for source in sources:
            if args.pack:
                meta = {"url": "", "fetched": ""}
                docs += (import_nointro if source == "no-intro" else import_redump)(args.pack, meta)
            elif source == "no-intro":
                pack, meta = fetch_nointro(args.cache_dir, offline, args.refresh)
                docs += import_nointro(pack, meta)
            else:
                for code in REDUMP_DATS:
                    pack, meta = fetch_redump(code, args.cache_dir, offline, args.refresh)
                    docs += import_redump(pack, meta)
    except (NotCachedError, OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if isinstance(exc, NotCachedError):
            print("Run with --fetch to download it.", file=sys.stderr)
        return 1

    expected = {(s, sid) for s in sources if not args.pack
                for sid in ([v[0] for v in NOINTRO_DATS.values()] if s == "no-intro"
                            else [v[1] for v in REDUMP_DATS.values()])}
    missing = expected - {(d["source"], d["system"]) for d in docs}
    failures = [f"{s}/{sid}: DAT not in the pack" for s, sid in sorted(missing)]
    raw_total = gz_total = 0
    print(f"{'source':9} {'system':26} {'games':>6} {'rows':>6} {'region':>6} "
          f"{'serials':>7} {'multi':>5} {'raw':>9} {'gzip':>8}")
    for doc in sorted(docs, key=lambda d: (d["source"], d["system"])):
        text = dump_catalog(doc)
        raw = len(text.encode())
        gz = len(gzip.compress(text.encode(), compresslevel=9, mtime=0))
        raw_total += raw
        gz_total += gz
        cov = coverage(doc)
        print(f"{doc['source']:9} {doc['system']:26} {cov['games']:>6} {cov['rows']:>6} "
              f"{cov['with_region']:>6} {cov.get('serials', '-'):>7} "
              f"{cov.get('multi_region_serials', '-'):>5} {raw:>9} {gz:>8}")
        if args.floor and cov["games"] < floor_of(doc):
            failures.append(f"{doc['source']}/{doc['system']}: {cov['games']} games, "
                            f"floor {floor_of(doc)}")
        if not args.dry_run:
            target = args.output_dir / doc["source"] / f"{doc['system']}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            write_if_changed(str(target), text)
    print(f"{len(docs)} catalogs, {raw_total} bytes raw, {gz_total} bytes gzip")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
