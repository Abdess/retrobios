"""Publish what the installer reads to install for the games on a card.

The installer's "For the games on this card" mode reads the card's rom
folders, identifies each game and installs only the BIOS those games need.
This step joins the sources that answer each part and writes them next to the
install lists, under install/games/:

- index.json: format version, a digest of the data, and every published
  file with its size, its gzip size (raw.githubusercontent.com compresses on
  request) and its sha256, so a phone fetches only what its card needs.
- setups/<setup>.json: the setup's rom folders (platforms/romfolders/),
  resolved to repository systems and profiles, with the key of each folder's
  fallback set.
- fallback/<platform>.json: per system and default core, the files the
  platform's install list carries for them (computed from install/<platform>.json
  with the installer's own core narrowing), their sizes and whether each is
  required. What an unrecognised game keeps.
- systems/<system>.json: identification (games/catalogs/, crc32 + size to a
  region and a title, disc serials to a region), header readers
  (games/headers.yml), region rules per profile (games/regions.yml joined with
  the profiles' region: fields) and per-game extra files (games/extras.yml).
- arcade/<profile>.json: game set to BIOS parent and device sets
  (games/arcade/).

Nothing here is written by hand: a second run writes the same bytes.

    python scripts/generate_games_index.py
    python scripts/generate_games_index.py --check   # exit 1 if a file would change
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import posixpath
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    native_layer,
    repository_output_lock,
    run_cli,
)
from region import normalize_declared  # noqa: E402
from romfolders import (  # noqa: E402
    ProfileResolver,
    Resolution,
    SystemResolver,
    folder_names,
    load_setups,
)
from artifacts import write_text_atomic  # noqa: E402
from safeparse import yaml_load  # noqa: E402

import install  # noqa: E402

FORMAT_VERSION = 1
OUTPUT = Path("install") / "games"
GAMES = Path("games")

# Coverage the published data may not fall below. A rescrape or a DAT import
# that loses rows fails the step instead of shipping a thinner index.
FLOORS = {
    "folders_resolved_share": 0.84,
    "catalog_systems": 30,
    "arcade_profiles": 6,
}


@dataclass(frozen=True)
class Inputs:
    """Where each source is read from. The defaults are the repository's."""

    games: Path = GAMES
    romfolders: Path = Path("platforms") / "romfolders"
    install: Path = Path("install")
    emulators: str = "emulators"
    platforms: str = "platforms"


def dumps(document: object) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return yaml_load(handle) or {}


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


# --- Profiles ---------------------------------------------------------------


def _entry_systems(profile: dict, entry: dict) -> set[str]:
    """The systems a profile file serves: its own system field, else the profile's."""
    own = entry.get("system") or entry.get("systems")
    if own:
        return {own} if isinstance(own, str) else {str(s) for s in own}
    return {str(s) for s in profile.get("systems") or []}


def _entry_names(entry: dict) -> set[str]:
    names = {str(entry.get("name") or "")}
    names |= {str(a) for a in entry.get("aliases") or []}
    for key in ("path", "standalone_path", "destination"):
        if entry.get(key):
            names.add(Path(str(entry[key])).name)
    return {n.lower() for n in names if n}


class Profiles:
    """Profile lookups the fallback and region sections share."""

    def __init__(self, profiles: dict[str, dict], resolver: SystemResolver) -> None:
        self.profiles = profiles
        self.resolver = resolver
        self._by_name: dict[str, dict[str, list[dict]]] = {}

    def entries_named(self, profile: str, name: str) -> list[dict]:
        table = self._by_name.get(profile)
        if table is None:
            table = {}
            for entry in self.profiles.get(profile, {}).get("files") or []:
                if isinstance(entry, dict):
                    for n in _entry_names(entry):
                        table.setdefault(n, []).append(entry)
            self._by_name[profile] = table
        return table.get(name.lower(), [])

    def serves(self, profile: str, entry: dict, system: str) -> bool:
        wanted = self.resolver.equivalents(system)
        return bool(_entry_systems(self.profiles.get(profile, {}), entry) & wanted)

    def region_files(self, profile: str, system: str) -> dict[str, list[str]]:
        """Region slug -> file names the profile tags for it, for one system.

        `any` holds the files declared with no region: those are installed
        whatever the game's region.
        """
        out: dict[str, set[str]] = {}
        data = self.profiles.get(profile, {})
        for entry in data.get("files") or []:
            if not isinstance(entry, dict) or not self.serves(profile, entry, system):
                continue
            if entry.get("category") == "game_data":
                continue
            regions = normalize_declared(entry.get("region")) or {"any"}
            for region in regions:
                out.setdefault(region, set()).add(str(entry["name"]))
        return {k: sorted(v) for k, v in sorted(out.items())}


# --- Fallback sets ----------------------------------------------------------


def _platform_required(platform: str, platforms_dir: str) -> dict[tuple[str, str], bool]:
    """(system, file name) -> required, as the platform's own list declares it."""
    config = load_platform_config(platform, platforms_dir)
    out: dict[tuple[str, str], bool] = {}
    for sys_id, system in (native_layer(config) or config).get("systems", {}).items():
        for entry in system.get("files", []):
            for name in {entry.get("name"), Path(str(entry.get("destination") or "")).name} - {None, ""}:
                out[(sys_id, str(name).lower())] = entry.get("required") is not False
    return out


def _narrowed(manifest: dict, cores: list[str], cache: dict) -> list[tuple[dict, str]]:
    """The install list under some cores, each file with its lowercased
    base name. The answer depends on the cores alone, and a platform asks
    it once per system they run."""
    key = (id(manifest), tuple(cores))
    if key not in cache:
        files, _omitted = install.narrow(
            manifest["files"], manifest.get("omitted_files", []), [], cores, [])
        cache[key] = [(entry, posixpath.basename(entry["dest"]).lower()) for entry in files]
    return cache[key]


def fallback_set(
    manifest: dict,
    platform_required: dict[tuple[str, str], bool],
    profiles: Profiles,
    system: str,
    profile: str | None,
    narrowed: dict | None = None,
) -> dict:
    """The files an unrecognised game of one system keeps on one platform.

    The platform's own files for the system, plus what the default core's
    profile reads for it. The core step is the installer's own narrowing
    (`install.narrow` with the designated cores). A core file the list does
    not attribute to a platform system is kept when the profile entry that
    declares it serves the system.
    """
    wanted = profiles.resolver.equivalents(system)
    cores = sorted(install.designated_cores(manifest, [profile])) if profile else []
    rows: list[list] = []
    for entry, base in _narrowed(manifest, cores, {} if narrowed is None else narrowed):
        systems = set(entry.get("systems") or [])
        dest = entry["dest"]
        if entry.get("cores") is None:
            if not systems & wanted:
                continue
            required = any(
                platform_required.get((s, base), True) for s in systems & wanted
            )
        else:
            if systems:
                if not systems & wanted:
                    continue
            declared = profiles.entries_named(profile or "", base)
            if not systems and not any(profiles.serves(profile or "", e, system) for e in declared):
                continue
            required = any(e.get("required") is not False for e in declared) if declared else True
        rows.append([dest, int(entry["size"]), required, entry.get("category") or "bios"])
    rows.sort()
    return {
        "files": rows,
        "bytes": sum(r[1] for r in rows),
        "required_bytes": sum(r[1] for r in rows if r[2]),
    }


def _shared_table(platform: str, sets: dict[str, dict]) -> dict:
    """One row per install-list file, and each set as indices into it.

    The sets of the MAME-run systems hold the same thousand files: written
    out per set, Batocera's table weighed half a megabyte compressed.
    """
    rows = sorted({(r[0], r[1], r[3]) for body in sets.values() for r in body["files"]})
    position = {row: i for i, row in enumerate(rows)}
    published = {}
    for key, body in sorted(sets.items()):
        published[key] = {
            "files": [position[(r[0], r[1], r[3])] for r in body["files"]],
            "optional": [position[(r[0], r[1], r[3])] for r in body["files"] if not r[2]],
            "bytes": body["bytes"],
            "required_bytes": body["required_bytes"],
        }
    return {
        "format_version": FORMAT_VERSION,
        "platform": platform,
        "files": [list(r) for r in rows],
        "sets": published,
    }


# --- Setups -----------------------------------------------------------------


def _arcade_profiles(directory: Path) -> set[str]:
    return {p.stem for p in directory.glob("*.json")} if directory.is_dir() else set()


def resolve_folder(
    row: dict, platform: str, profile: str | None, resolver: SystemResolver, profiles: Profiles,
    arcade: frozenset[str] | set[str] = frozenset(),
) -> Resolution:
    """The systems a folder holds: its names first, else its core's machines.

    A name nothing spells, run by a core of one machine, is that machine
    (ECWolf's wolf3d folder, a port's own folder). Run by a core of several,
    its games are one of them (theodore's thomson folder), and every one
    is kept: left empty, the folder had no fallback and its games got no file.
    An arcade core is the exception: the arcade index names each set's
    files, and its hundred machines would make any unknown file a fallback
    for all of them.

    A name that spells a machine its core does not run adds the core's
    machines to it: the games run on that core. Mednafen's PC Engine core
    lists nec-pc-engine, the CD folder resolved to nec-pc-engine-cd alone,
    and an unrecognised CD game got no System Card.
    """
    resolution = resolver.resolve(folder_names(row), platform)
    own = [str(s) for s in profiles.profiles.get(profile or "", {}).get("systems") or []]
    if resolution.systems and own and profile not in arcade:
        runs = {sid for s in own for sid in resolver.equivalents(s)}
        if not runs & set(resolution.systems):
            systems = set(resolution.systems) | {resolver.canonical(s) for s in own}
            return Resolution(sorted(systems), f"{resolution.basis}, and systems of {profile}")
    if resolution.systems or not own:
        return resolution
    if len(own) == 1:
        return Resolution([resolver.canonical(own[0])], f"only system of {profile}")
    if profile in arcade:
        return resolution
    return Resolution(sorted({resolver.canonical(s) for s in own}), f"systems of {profile}")


# The emulator column of a row names the frontend or a launch mode, never
# a program whose files are read: these never answer for a core.
_NOT_PROGRAMS = frozenset({"retroarch", "retroarch32", "libretro", "external", "standalone",
                           "port", "ports", "native", "sh", "os-shell", "none"})


def emulator_profile(row: dict, platform: str, cores: ProfileResolver,
                     resolver: SystemResolver, profiles: Profiles) -> str | None:
    """The profile of the program a row's emulator column names, when its
    core column names a mode, a machine or a plugin of that program: RetroBat
    runs demul for core hikaru, AmberELEC MAME for core gamate, Batocera
    mupen64plus for core glide64mk2.

    Kept only when that profile declares a system of the folder: MAME's
    profile has no GameKing, and answering MAME for its folder would leave
    out the ROM the core needs. Unresolved, the folder keeps the files of
    every core of its systems, as it did.
    """
    emulator = str(row.get("emulator") or "").strip()
    if not emulator or emulator.lower() in _NOT_PROGRAMS or emulator.lower().startswith("standalone"):
        return None
    candidate = cores.resolve(emulator)
    if not candidate:
        return None
    systems = resolver.resolve(folder_names(row), platform).systems
    own = {str(s) for s in profiles.profiles.get(candidate, {}).get("systems") or []}
    declared = {spelling for sid in own for spelling in resolver.equivalents(sid)}
    return candidate if any(resolver.equivalents(sid) & declared for sid in systems) else None


def build_setups(
    setups: dict[str, dict],
    resolver: SystemResolver,
    cores: ProfileResolver,
    profiles: Profiles,
    arcade: set[str],
    inputs: Inputs,
) -> tuple[dict[str, dict], dict[str, dict], dict]:
    """Published setup documents, fallback tables per platform, coverage."""
    manifests: dict[str, dict] = {}
    required: dict[str, dict] = {}
    fallbacks: dict[str, dict[str, dict]] = {}
    narrowed: dict = {}
    out: dict[str, dict] = {}
    coverage: dict[str, dict] = {}
    for setup, doc in sorted(setups.items()):
        platform = doc.get("platform") or ""
        if platform and platform not in manifests:
            path = inputs.install / f"{platform}.json"
            if path.exists():
                manifests[platform] = _load_json(path)
                required[platform] = _platform_required(platform, inputs.platforms)
        manifest = manifests.get(platform)
        folders: list[dict] = []
        counts = {"folders": 0, "resolved": 0, "profile": 0, "fallback": 0}
        for row in doc.get("folders", []):
            counts["folders"] += 1
            profile = (cores.resolve(row.get("core"))
                       or emulator_profile(row, platform, cores, resolver, profiles))
            resolution = resolve_folder(row, platform, profile, resolver, profiles, arcade)
            published: dict = {
                "folder": row["folder"],
                "systems": resolution.systems,
                "basis": resolution.basis,
            }
            for key in ("name", "aliases", "extensions", "files", "core", "emulator", "note"):
                if row.get(key):
                    published[key] = row[key]
            if profile:
                published["profile"] = profile
                counts["profile"] += 1
            if resolution.systems:
                counts["resolved"] += 1

            def fallback_keys(chosen: str | None) -> list[str]:
                """The fallback sets of the folder's systems under one core,
                computed once per platform."""
                keys = []
                table = fallbacks.setdefault(platform, {})
                for system in resolution.systems:
                    key = f"{system}|{chosen or ''}"
                    if key not in table:
                        table[key] = fallback_set(manifest, required[platform], profiles, system,
                                                  chosen, narrowed)
                    keys.append(key)
                return keys

            sets_known = manifest is not None and bool(resolution.systems)
            boards = {}
            for board, spec in sorted((row.get("board_defaults") or {}).items()):
                boards[board] = {"core": spec["core"]}
                board_profile = cores.resolve(spec["core"])
                if board_profile:
                    boards[board]["profile"] = board_profile
                    if board_profile in arcade:
                        boards[board]["arcade"] = board_profile
                if sets_known:
                    # A card moves between boards, and the installer reads
                    # it on a computer: each board's core has its set.
                    boards[board]["fallback"] = fallback_keys(board_profile)
            if boards:
                published["board_defaults"] = boards
            if profile and profile in arcade:
                published["arcade"] = profile
            elif row.get("arcade"):
                published["arcade"] = True
            if sets_known:
                keys = fallback_keys(profile)
                published["fallback"] = keys
                if any(fallbacks[platform][k]["files"] for k in keys):
                    counts["fallback"] += 1
            published["source_ref"] = row["source_ref"]
            folders.append(published)
        out[setup] = {
            "format_version": FORMAT_VERSION,
            "setup": setup,
            "name": doc["name"],
            "platform": platform,
            "sources": doc["sources"],
            "roms_root": doc["roms_root"],
            "case_sensitive": doc["case_sensitive"],
            **{k: doc[k] for k in ("skip", "hidden", "media", "notes") if doc.get(k)},
            "folders": folders,
        }
        coverage[setup] = counts
    published_fallbacks = {
        platform: _shared_table(platform, table) for platform, table in sorted(fallbacks.items())
    }
    return out, published_fallbacks, coverage


# --- Systems ----------------------------------------------------------------


def _catalogs(directory: Path) -> Iterable[dict]:
    if directory.is_dir():
        for path in sorted(directory.glob("*/*.json")):
            yield _load_json(path)


def build_systems(
    resolver: SystemResolver,
    profiles: Profiles,
    used: dict[str, set[str]],
    games: Path,
) -> tuple[dict[str, dict], dict]:
    """Published system documents and per-system coverage.

    `used` holds, per system, the profiles some setup starts for it: their
    region files are published even without a rule of their own.
    """
    headers = _load_yaml(games / "headers.yml").get("systems", {})
    extras: dict[str, list[dict]] = {}
    for entry in _load_yaml(games / "extras.yml").get("extras", []):
        extras.setdefault(entry["system"], []).append(entry)
    rule_file = _load_yaml(games / "regions.yml")
    cases = rule_file.get("cases", {})
    docs: dict[str, dict] = {}

    def doc_for(system: str) -> dict:
        key = resolver.canonical(system)
        return docs.setdefault(key, {"format_version": FORMAT_VERSION, "system": key})

    for catalog in _catalogs(games / "catalogs"):
        doc = doc_for(catalog["system"])
        regions_table = catalog["regions"]
        fields = catalog["fields"]
        col = {name: i for i, name in enumerate(fields)}
        ident = doc.setdefault("identify", {"sources": [], "regions": [], "games": [], "serials": {}})
        region_index: dict[tuple[str, ...], int] = {
            tuple(r): i for i, r in enumerate(ident["regions"])
        }

        def reindex(i: int) -> int:
            value = tuple(regions_table[i]) if i is not None and i >= 0 else ()
            if value not in region_index:
                region_index[value] = len(ident["regions"])
                ident["regions"].append(list(value))
            return region_index[value]

        ident["sources"].append({
            k: catalog[k] for k in ("source", "dat", "version", "fetched_from", "licence", "serial_note") if k in catalog
        })
        for row in catalog["games"]:
            region = reindex(row[col["region"]])
            ident["games"].append([row[col["crc32"]], row[col["size"]], region, row[col["title"]]])
            for serial in row[col["serials"]] if "serials" in col else []:
                ident["serials"].setdefault(serial, set()).add(region)
    for doc in docs.values():
        ident = doc.get("identify")
        if ident:
            ident["games"].sort()
            ident["serials"] = {s: sorted(r) for s, r in sorted(ident["serials"].items())}
    for system, spec in headers.items():
        doc_for(system)["headers"] = spec
    for system, entries in extras.items():
        doc_for(system).setdefault("extras", []).extend(entries)
    rule_profiles: dict[str, set[str]] = {}
    for system, spec in rule_file.get("systems", {}).items():
        doc = doc_for(system)
        rules = doc.setdefault("region_rules", {})
        rules.update(spec)
        named = {
            case["case"] for core in spec.values()
            for case in (core.get("keep_all_regions") or []) if isinstance(case, dict)
        }
        if named:
            doc.setdefault("cases", {}).update({c: cases[c] for c in sorted(named) if c in cases})
        rule_profiles.setdefault(doc["system"], set()).update(spec if isinstance(spec, dict) else ())
    for system, names in used.items():
        rule_profiles.setdefault(resolver.canonical(system), set()).update(names)
    for system, names in rule_profiles.items():
        files = {
            name: tagged for name in sorted(names)
            if name in profiles.profiles
            and (tagged := profiles.region_files(name, system))
            and set(tagged) - {"any"}
        }
        if files:
            doc_for(system)["region_files"] = files
    coverage = {
        system: {
            "games": len(doc.get("identify", {}).get("games", [])),
            "serials": len(doc.get("identify", {}).get("serials", {})),
            "header_readers": len((doc.get("headers") or {}).get("readers", {}) or []),
            "region_profiles": len(doc.get("region_files", {})),
            "extras": bool(doc.get("extras")),
        }
        for system, doc in sorted(docs.items())
    }
    return docs, coverage


# --- Arcade -----------------------------------------------------------------


def build_arcade(directory: Path) -> dict[str, dict]:
    if not directory.is_dir():
        return {}
    # The driver sources and the clone parents place a search path's sets at
    # build time (common.rom_search_sets): the installer reads none of them.
    return {
        path.stem: {k: v for k, v in _load_json(path).items() if k not in ("sources", "parents")}
        for path in sorted(directory.glob("*.json"))
    }


# --- Writing ----------------------------------------------------------------


def _entry(text: str) -> dict:
    data = text.encode("utf-8")
    return {
        "size": len(data),
        "gzip_size": len(gzip.compress(data, compresslevel=9, mtime=0)),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def folder_systems(setups: dict[str, dict]) -> dict[str, list[str]]:
    """Every folder name a setup gives a system, casefolded, with the systems
    any setup reads there, and each system id under its own name.

    What a games folder on a computer is read with when its setup names no
    folder of its own (RetroArch): a name two setups give two systems keeps
    both.
    """
    names: dict[str, set[str]] = {}
    for doc in setups.values():
        for row in doc["folders"]:
            systems = row["systems"]
            if not systems:
                continue
            for name in [row["folder"], *(row.get("aliases") or [])]:
                names.setdefault(str(name).casefold(), set()).update(systems)
            for system in systems:
                names.setdefault(system.casefold(), set()).add(system)
    return {name: sorted(systems) for name, systems in sorted(names.items())}


def render(output: Path = OUTPUT, inputs: Inputs = Inputs()) -> tuple[dict[Path, str], dict]:
    """Every published file's text, keyed by its path, and the coverage."""
    resolver = SystemResolver.from_repo(inputs.emulators, inputs.platforms)
    profiles = Profiles(load_emulator_profiles(inputs.emulators), resolver)
    arcade = build_arcade(inputs.games / "arcade")
    setups, fallbacks, setup_cov = build_setups(
        load_setups(inputs.romfolders), resolver, ProfileResolver.from_repo(inputs.emulators),
        profiles, set(arcade), inputs,
    )
    used: dict[str, set[str]] = {}
    for doc in setups.values():
        for row in doc["folders"]:
            for system in row["systems"]:
                if row.get("profile"):
                    used.setdefault(system, set()).add(row["profile"])
    systems, system_cov = build_systems(resolver, profiles, used, inputs.games)

    files: dict[Path, str] = {}
    index: dict = {"format_version": FORMAT_VERSION, "setups": {}, "fallback": {}, "systems": {}, "arcade": {}}
    for kind, docs in (("setups", setups), ("fallback", fallbacks), ("systems", systems), ("arcade", arcade)):
        for key, doc in sorted(docs.items()):
            rel = Path(kind) / f"{key}.json"
            text = dumps(doc)
            files[output / rel] = text
            index[kind][key] = {"file": rel.as_posix(), **_entry(text)}
    digest = hashlib.sha256(
        "".join(f"{p.relative_to(output).as_posix()} {_entry(t)['sha256']}\n" for p, t in sorted(files.items())).encode()
    ).hexdigest()
    index["data_version"] = digest[:16]
    index["licences"] = sorted(
        {json.dumps(src.get("licence"), sort_keys=True)
         for doc in systems.values() for src in doc.get("identify", {}).get("sources", [])
         if src.get("licence")}
    )
    index["licences"] = [json.loads(x) for x in index["licences"]]
    containers = _load_yaml(inputs.games / "headers.yml").get("containers")
    if containers:
        index["containers"] = containers
    index["folders"] = folder_systems(setups)
    files[output / "index.json"] = dumps(index)
    coverage = {"setups": setup_cov, "systems": system_cov, "arcade": sorted(arcade)}
    return files, coverage


def floor_failures(coverage: dict) -> list[str]:
    total = sum(c["folders"] for c in coverage["setups"].values())
    resolved = sum(c["resolved"] for c in coverage["setups"].values())
    out = []
    share = resolved / total if total else 0.0
    if share < FLOORS["folders_resolved_share"]:
        out.append(f"folders resolved {resolved}/{total} ({share:.1%}) under {FLOORS['folders_resolved_share']:.0%}")
    catalogs = sum(1 for c in coverage["systems"].values() if c["games"])
    if catalogs < FLOORS["catalog_systems"]:
        out.append(f"systems with a game catalog {catalogs} under {FLOORS['catalog_systems']}")
    if len(coverage["arcade"]) < FLOORS["arcade_profiles"]:
        out.append(f"arcade profiles {len(coverage['arcade'])} under {FLOORS['arcade_profiles']}")
    return out


def print_coverage(coverage: dict, files: dict[Path, str]) -> None:
    print("Setups (folders / resolved to a system / default core profiled / with a fallback set):")
    for setup, c in coverage["setups"].items():
        print(f"  {setup:16} {c['folders']:4} {c['resolved']:4} {c['profile']:4} {c['fallback']:4}")
    print("Systems (games by hash / serials / header readers / profiles with region files / extras):")
    for system, c in coverage["systems"].items():
        print(f"  {system:28} {c['games']:6} {c['serials']:6} {c['header_readers']:3} "
              f"{c['region_profiles']:3} {'yes' if c['extras'] else '-'}")
    print(f"Arcade indexes: {', '.join(coverage['arcade']) or 'none'}")
    raw = sum(len(t.encode()) for t in files.values())
    packed = sum(len(gzip.compress(t.encode(), 9, mtime=0)) for t in files.values())
    print(f"{len(files)} files, {raw:,} bytes, {packed:,} bytes gzip")


def _sample(items: list[str], limit: int = 3) -> str:
    shown = ", ".join(items[:limit])
    return f"{shown}, +{len(items) - limit} more" if len(items) > limit else shown


def describe_change(old: str | None, new: str) -> list[str]:
    """What differs between a published document and the one render() makes.

    The documents are single-line JSON of up to 550 KB: STALE alone left a
    diff by hand to find that a manifest gained one file."""
    if old is None:
        return ["not written yet"]
    try:
        before, after = json.loads(old), json.loads(new)
    except ValueError:
        return ["the published file is not valid JSON"]
    if not (isinstance(before, dict) and isinstance(after, dict)):
        return ["document changed"]
    parts = []
    for key in sorted(set(before) | set(after)):
        a, b = before.get(key), after.get(key)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            olds = {json.dumps(x, sort_keys=True) for x in a}
            news = {json.dumps(x, sort_keys=True) for x in b}
            added = sorted(news - olds)
            removed = sorted(olds - news)
            change = []
            if added:
                change.append(f"{len(added)} added ({_sample(added)})")
            if removed:
                change.append(f"{len(removed)} removed ({_sample(removed)})")
            parts.append(f"{key}: {', '.join(change) or 'reordered'}")
        elif isinstance(a, dict) and isinstance(b, dict):
            changed = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
            parts.append(f"{key}: {len(changed)} changed ({_sample(changed)})")
        else:
            parts.append(f"{key} changed" if key in before and key in after
                         else f"{key} {'added' if key in after else 'removed'}")
    return parts or ["formatting changed"]


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, default=OUTPUT,
                        help=f"where the index is written (default {OUTPUT})")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 when a file would change, naming what differs (implies --quiet)")
    parser.add_argument("--quiet", action="store_true", help="print only failures")
    args = parser.parse_args()
    if args.check:
        return _index(args)
    with repository_output_lock(str(args.output_dir)):
        return _index(args)


def _index(args: argparse.Namespace) -> int:
    files, coverage = render(args.output_dir)
    if not (args.quiet or args.check):
        print_coverage(coverage, files)
    failures = floor_failures(coverage)
    for failure in failures:
        print(f"FLOOR {failure}", file=sys.stderr)
    stale = sorted(
        p for p in args.output_dir.rglob("*.json") if p not in files
    ) if args.output_dir.is_dir() else []
    changed = [p for p, t in files.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
    if args.check:
        for path in changed:
            print(f"STALE {path}", file=sys.stderr)
            current = path.read_text(encoding="utf-8") if path.exists() else None
            for line in describe_change(current, files[path]):
                print(f"  {line}", file=sys.stderr)
        for path in stale:
            print(f"STALE {path}", file=sys.stderr)
            print("  no longer generated", file=sys.stderr)
        if changed or stale:
            print("Run python scripts/generate_games_index.py to write them.", file=sys.stderr)
        return 1 if changed or stale or failures else 0
    for path in stale:
        path.unlink()
    for path in changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(str(path), files[path])
    print(f"{len(changed)} written, {len(stale)} removed")
    return 1 if failures else 0


if __name__ == "__main__":
    run_cli(main)
