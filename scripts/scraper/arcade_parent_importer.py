"""Import, per arcade core version, which BIOS set each game set loads.

A game set names its parent through ``romof``: a clone reads its parent game,
and the chain ends at a BIOS set (``neogeo``, ``naomi``, ``pgm``). The archive
the installer has to provide for a game on the card is every BIOS set on that
chain, plus, for the MAME family, the device sets with ROMs the machine
instantiates (``device_ref``), which a split or merged romset reads from their
own archive. The answer is read at the revision the profile pins, from the
DAT of the core version that runs the game where that DAT is the code's own
output, and from the driver code where it is not:

    python -m scripts.scraper.arcade_parent_importer --all
    python -m scripts.scraper.arcade_parent_importer --profile mame2003_plus
    python -m scripts.scraper.arcade_parent_importer --all --offline

A BIOS set is ``isbios="yes"`` (MAME 0.139 and later, FBNeo). mame2000,
mame2003 and mame2003-plus carry a DAT in metadata/ that their code has
moved past (mame2003-plus: 186 compiled sets absent, nbajamex under a BIOS
set the code no longer declares), so they are read from src/driver.c and
src/drivers/: the parent is the GAME macro's PARENT argument and a BIOS set
is flagged NOT_A_DRIVER. Their DAT is still read, to report where it
disagrees. FBNeo's DATs are read one at a time, a console set keyed by its
driver (``msx_1942``): the Arcade, MSX and NES DATs each carry a ``1942``.
flycast keeps its NAOMI and Atomiswave table in code: ``Games[].bios`` names
the BIOS, ``naomi`` when it is null (core/hw/naomi/naomi_cart.cpp:195-197),
and ``BIOS[].filename`` the archive when it differs from the name
(naomi_cart.cpp:75).

Output: games/arcade/<profile>.json. CHD games are listed, not resolved: a
CHD is game content. A ``romof`` pointing outside the sets read is listed
with its target, never guessed. The games that load no BIOS set
(``no_bios``) and every BIOS set (``bios_sets``) are listed too: a set name
on a card that none of the lists holds is one the core does not know.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from model.database import load_database
from core.artifacts import write_if_changed
from model.profiles import load_emulator_profiles
from core.cli import add_repo_inputs, run_cli
from core.hashing import compute_hashes, git_blob_sha
from core.upstream import parse_repo
from .base_scraper import fetch_verified_blob
from .listxml import Opener, open_listxml
from model.mamerelease import mame_tag
from .dat_fetch import MAME_LISTXML_URL, api_json, cached_pack, fetch_pack
from .arcade_drivers import driver_source_sets, fetch_driver_source
from .arcade_sets import (
    FBNEO_DRIVERLIST,
    SetEntry,
    fbneo_drivers,
    fbneo_sets,
    flycast_index,
    is_bios,
    iter_sets,
)

SCHEMA_VERSION = 1
DEFAULT_OUTPUT = Path("games") / "arcade"
DEFAULT_CACHE = Path(".cache") / "dats"

# How each profile's DAT is found. "listxml": the -listxml release asset of
# the MAME version core_version names. "fbneo": every DAT of libretro/FBNeo's
# dats/ at source_commit. "repo": files of the profile's source repository at
# source_commit (a ZIP member when the file is an archive). "source": the
# driver code itself at source_commit (src/driver.c and src/drivers/), for the
# cores whose committed DAT contradicts their code; "paths" then names that
# DAT, read only to report where it disagrees. "flycast": the BIOS and Games
# tables of naomi_roms.cpp at source_commit.
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
    "mame2003_plus": {"kind": "source", "marker": "runnable", "paths": ["metadata/mame2003-plus.xml"]},
    "mame2003": {"kind": "source", "marker": "runnable", "paths": ["metadata/mame2003.xml"]},
    "mame2000": {"kind": "source", "marker": "isbios", "paths": ["metadata/MAME 0.37b5 XML.dat"]},
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


def build_index(
    sets: dict[str, SetEntry], marker: str, archives: dict[str, str] | None = None
) -> dict:
    """BIOS sets per game, device sets per game, CHD games, broken chains.

    A BIOS set none of whose ROMs was dumped is passed over: its archive holds
    nothing, and the loader only warns about a ROM without a dump. *archives*
    names the archive of a set whose name is not its archive's (an FBNeo
    console driver)."""
    archive = (archives or {}).get
    bios_names = {n for n, e in sets.items() if is_bios(e, marker)}
    device_roms = {n for n, e in sets.items() if e.isdevice and e.has_roms}
    games = {
        n: e for n, e in sets.items()
        if n not in bios_names and not e.isdevice and e.runnable and (e.has_roms or e.disks)
    }
    bios: dict[str, set[str]] = {}
    parents: dict[str, set[str]] = {}
    devices: dict[str, set[str]] = {}
    missing: dict[str, str] = {}
    for name, entry in games.items():
        seen = {name}
        current = entry.romof
        while current and current not in seen:
            seen.add(current)
            parent = sets.get(current)
            if parent is None:
                missing[name] = archive(current, current)
                break
            if current in bios_names and parent.has_roms:
                bios.setdefault(archive(current, current), set()).add(name)
            elif current not in bios_names and parent.has_roms:
                # A clone's ROM shared with its parent is looked up in the
                # parent's archive too: MAME's search path is the set and
                # every ancestor (src/emu/driver.cpp:31-38,
                # src/emu/romload.cpp:67-84 at mame0289).
                parents.setdefault(archive(current, current), set()).add(name)
            current = parent.romof
        for device in set(entry.devices) & device_roms:
            devices.setdefault(device, set()).add(name)
    with_bios = {g for members in bios.values() for g in members}
    # The source file of each game and device set: what a launcher that
    # starts whatever set a folder holds selects a folder's machines by
    # (ES-DE runs MAME on any CPS-2 set of roms/cps2).
    sources: dict[str, set[str]] = {}
    for name, entry in sets.items():
        if entry.source and (name in games or name in device_roms):
            sources.setdefault(entry.source, set()).add(archive(name, name))
    return {
        "bios": {k: sorted(v) for k, v in sorted(bios.items())},
        "parents": {k: sorted(v) for k, v in sorted(parents.items())},
        "devices": {k: sorted(v) for k, v in sorted(devices.items())},
        "chd": sorted(n for n, e in games.items() if e.disks),
        "missing_parents": dict(sorted(missing.items())),
        "no_bios": sorted(set(games) - with_bios - set(missing)),
        "bios_sets": sorted(bios_names),
        **({"sources": {k: sorted(v) for k, v in sorted(sources.items())}} if sources else {}),
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


def dat_gaps(code: dict[str, SetEntry], dat: dict[str, SetEntry], marker: str) -> dict:
    """Where the DAT a repository carries contradicts its own code."""
    both = code.keys() & dat.keys()
    return {
        "code_only": sorted(code.keys() - dat.keys()),
        "dat_only": sorted(dat.keys() - code.keys()),
        "romof": sorted(n for n in both if code[n].romof != dat[n].romof),
        "bios": sorted(n for n in both if is_bios(code[n], marker) != is_bios(dat[n], marker)),
    }


def _dat_cross_check(
    spec: dict, slug: str, commit: str, cache_dir: Path, offline: bool,
    code: dict[str, SetEntry],
) -> dict | None:
    """dat_gaps against the DAT the repository carries, None when the DAT
    is not cached and the run is offline."""
    paths: list[Path] = []
    for path in spec.get("paths", []):
        try:
            local, _ = (
                _cached_repo_file(slug, commit, path, cache_dir)
                if offline
                else fetch_repo_file(slug, commit, path, cache_dir)
            )
        except FileNotFoundError:
            if offline:
                return None
            raise
        paths.append(local)
    if not paths:
        return None
    dat = read_sets([opener for p in paths for opener in _xml_streams(p)])
    return dat_gaps(code, dat, spec["marker"])


# --- Fetching ----------------------------------------------------------------


def _repo_slug(url: str) -> str:
    """owner/name of the GitHub repository a profile's source names."""
    repo = parse_repo(url)
    if repo is None or repo.family != "github":
        raise ValueError(f"not a GitHub repository URL: {url}")
    return repo.slug


def fetch_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """One file of a GitHub repository at a commit, checked against the blob
    sha the repository lists for it, and that sha."""
    folder, _, name = path.rpartition("/")
    listing = api_json(
        f"https://api.github.com/repos/{slug}/contents/{urllib.parse.quote(folder)}?ref={commit}"
    )
    item = next(
        (i for i in listing if isinstance(i, dict) and i.get("name") == name), None
    ) if isinstance(listing, list) else None
    if item is None:
        raise FileNotFoundError(f"{slug}@{commit[:8]} has no {path}")
    url = (
        f"https://raw.githubusercontent.com/{slug}/{commit}/"
        f"{urllib.parse.quote(path)}"
    )
    destination = fetch_verified_blob(url, cache_dir / "repo" / slug / commit / path, item["sha"])
    return destination, item["sha"]


def _cached_repo_file(slug: str, commit: str, path: str, cache_dir: Path) -> tuple[Path, str]:
    """The cached copy, offline. Its blob sha is recomputed from the bytes."""
    destination = cache_dir / "repo" / slug / commit / path
    if not destination.is_file():
        raise FileNotFoundError(f"{slug}@{commit[:8]}:{path} is not in {cache_dir}")
    return destination, git_blob_sha(destination.read_bytes())


def _file_opener(path: Path) -> Opener:
    return lambda: path.open("rb")


def _xml_streams(path: Path) -> Iterator[Opener]:
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
        def opener(member: str = member) -> IO[bytes]:
            # The member keeps the archive alive: its shared file closes
            # through the archive's own _fpclose.
            return zipfile.ZipFile(path).open(member)

        yield opener


def read_sets(openers: list[Opener]) -> dict[str, SetEntry]:
    """Every set of several documents. A set read twice keeps its first
    reading: FBNeo's Arcade and Neogeo DATs both carry the neogeo BIOS."""
    sets: dict[str, SetEntry] = {}
    for opener in openers:
        with opener() as stream:
            for entry in iter_sets(stream):
                if entry.name:
                    sets.setdefault(entry.name, entry)
    return sets


def import_profile(
    profile: str, data: dict, cache_dir: Path, offline: bool = False,
    report: dict | None = None,
) -> dict:
    """The index document for one profile, from the DAT or the code its pin
    names. *report* receives, for a profile read from its code, where the DAT
    the repository carries disagrees with that code."""
    spec = PROFILES[profile]
    commit = str(data.get("source_commit") or "")
    source_url = str(data.get("source") or "")
    kind = spec["kind"]
    source: dict[str, object]
    openers: list[Opener]
    if kind == "listxml":
        tag = mame_tag(str(data["core_version"]))
        pack, _ = (cached_pack if offline else fetch_pack)("mame", tag, cache_dir)
        source = {
            "release": f"mamedev/mame {tag}",
            "url": MAME_LISTXML_URL.format(tag=tag),
            "sha256": compute_hashes(pack, frozenset({"sha256"}), cache=False)["sha256"],
        }
        index = build_index(read_sets([lambda: open_listxml(pack)]), spec["marker"])
    elif kind == "fbneo":
        folder, blobs = (cached_pack if offline else fetch_pack)("fbneo", commit, cache_dir)
        slug = _repo_slug(source_url)
        listing, listing_sha = (
            _cached_repo_file(slug, commit, FBNEO_DRIVERLIST, cache_dir)
            if offline
            else fetch_repo_file(slug, commit, FBNEO_DRIVERLIST, cache_dir)
        )
        source = {
            "repo": source_url,
            "commit": commit,
            "files": {
                **{f"dats/{name}": sha for name, sha in sorted(blobs.items())},
                FBNEO_DRIVERLIST: listing_sha,
            },
        }
        openers = [_file_opener(folder / name) for name in sorted(blobs)]
        sets, archives = fbneo_sets(openers, fbneo_drivers(listing.read_text(encoding="utf-8")))
        index = build_index(sets, spec["marker"], archives)
    elif kind == "source":
        slug = _repo_slug(source_url)
        tree = fetch_driver_source(slug, commit, cache_dir, offline)
        sets = driver_source_sets(tree.driver_c, tree.drivers, tree.headers)
        source = {"repo": source_url, "commit": commit, "files": {"src": tree.tree}}
        index = build_index(sets, spec["marker"])
        if report is not None:
            report["dat_gaps"] = _dat_cross_check(spec, slug, commit, cache_dir, offline, sets)
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


def collection_names(database: str) -> set[str]:
    db = load_database(database)
    return {n.lower() for n in db.get("indexes", {}).get("by_name", {})}


def bios_roots(doc: dict) -> list[str]:
    return sorted(doc["bios"])


def dump(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--profile", action="append", choices=sorted(PROFILES),
                       help="profile to import (repeatable)")
    which.add_argument("--all", action="store_true", help="every profile with an arcade source")
    add_repo_inputs(parser, "emulators", "db")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help=f"where the parent maps are written (default {DEFAULT_OUTPUT})")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE,
                        help=f"downloaded DATs and sources (default {DEFAULT_CACHE})")
    parser.add_argument("--offline", action="store_true", help="read the download cache only")
    parser.add_argument("--dry-run", action="store_true", help="print coverage, write nothing")
    args = parser.parse_args()

    profiles = load_emulator_profiles(args.emulators_dir, skip_aliases=False)
    names = collection_names(args.db)
    failed = False
    for profile in sorted(PROFILES) if args.all else args.profile:
        if profile not in profiles:
            print(f"FAIL {profile}: no emulators/{profile}.yml", file=sys.stderr)
            failed = True
            continue
        try:
            report: dict = {}
            doc = import_profile(
                profile, profiles[profile], args.cache_dir, args.offline, report
            )
        except (OSError, ValueError, KeyError) as exc:
            print(f"FAIL {profile}: {exc}", file=sys.stderr)
            failed = True
            continue
        counts = doc["counts"]
        roots = bios_roots(doc)
        declared = declared_archives(profiles[profile])
        undeclared = [r for r in roots if f"{r}.zip" not in declared]
        absent = [r for r in roots if f"{r}.zip" not in names]
        print(
            f"{profile}: {counts['games']} games, {counts['games_with_bios']} with a BIOS set, "
            f"{counts['bios_roots_used']} BIOS sets used, "
            f"{counts['games_with_devices']} with device sets, {counts['chd_games']} CHD, "
            f"{counts['missing_parents']} parents absent"
        )
        if PROFILES[profile]["kind"] == "source":
            gaps = report.get("dat_gaps")
            if gaps is None:
                print("  read from the code, the committed DAT is not cached for the cross-check")
            else:
                print(
                    f"  read from the code, the committed DAT disagrees: "
                    f"{len(gaps['code_only'])} sets only in the code, "
                    f"{len(gaps['dat_only'])} only in the DAT, "
                    f"{len(gaps['romof'])} parents and {len(gaps['bios'])} BIOS flags differ"
                )
                for key in ("dat_only", "romof", "bios"):
                    if gaps[key]:
                        print(f"    {key}: {', '.join(gaps[key][:20])}")
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
            target.parent.mkdir(parents=True, exist_ok=True)
            if write_if_changed(str(target), dump(doc)):
                print(f"  wrote {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    run_cli(main)
