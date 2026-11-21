"""Games on the card: the BIOS their systems and regions need, from install/games/."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import urllib.error
from collections.abc import Callable, Collection, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.cards import games_part
from installer.console import ReadCounter, detail, fold_line
from installer.destination import card_root_above
from installer.detect_os import detect_os, detected_os
from installer.events import EVENTS
from installer.game_files import (
    ARCADE_SUFFIXES,
    GAMES_SCAN_FILE,
    MAX_GAME_FILES,
    GameFacts,
    SystemData,
    _ScanCache,
    _cache_write,
    _may_hold_games,
    _suffix,
    cache_folder,
    folder_games,
    game_folders,
    games_root,
    read_game,
)
from installer.handheld_app import card_app
from installer.host_fs import _is_dir
from installer.manifest import _SHA256_RE
from installer.network import _fetch_json, _read_capped
from installer.offline import LOCAL, _Offline, offline_words
from installer.paths import shown_path
from installer.platforms import entry_systems, system_title
from installer.regions import WORLD_REGION, _region_comparable, region_title
from installer.remote import BASE_URL
from installer.text import _plural, agree

if TYPE_CHECKING:
    from installer.game_files import GameFolder
    from installer.terminal import Terminal

# --- Games on the card -------------------------------------------------------
#
# --for-games keeps what the games of a card need, read from install/games/
# (scripts/generate_games_index.py): per system the files its default core
# reads (a fallback set), one region where the game's own bytes prove it,
# and for an arcade set the BIOS sets its romof chain reaches. Any doubt
# keeps the wider set: the game must run.

GAMES_URL = f"{BASE_URL}/install/games/{{path}}"
GAMES_FORMAT = 1
MAX_GAMES_INDEX_BYTES = 4 * 1024 * 1024
MAX_GAMES_DOC_BYTES = 32 * 1024 * 1024


_GAMES_DOC_NAME = re.compile(r"^(setups|fallback|systems|arcade)/[A-Za-z0-9_.+-]+\.json$")


# Why a game got every BIOS of its system: said with its name.
GAMES_REASONS = {
    "not_recognised": "not recognised",
    "not_read": "format not read",
    "region_unknown": "region not proven",
    "unknown_set": "set unknown to the core",
    "no_parent": "BIOS set not in the list",
}


class GamesUnavailable(Exception):
    """install/games/ could not be read: the run keeps the wider set."""

    def __init__(self, reason: str, words: str) -> None:
        super().__init__(words)
        self.reason = reason
        self.words = words


class GamesData:
    """install/games/ for this run: index.json, then each document it lists,
    checked against the sha256 the index gives. Read from the games folder
    beside --manifest, the cache, or the network, in that order."""

    def __init__(self) -> None:
        self.index: dict | None = None
        self.docs: dict[str, dict] = {}

    def reset(self) -> None:
        self.index = None
        self.docs = {}

    @staticmethod
    def beside() -> Path | None:
        return LOCAL.manifest.parent / "games" if LOCAL.manifest is not None else None

    @staticmethod
    def cached(name: str) -> Path | None:
        root = cache_folder()
        return root / "games" / name if root is not None else None

    def load_index(self, network: bool = True, attempts: int = 2) -> dict:
        if self.index is not None:
            return self.index
        raw = None
        beside = self.beside()
        if beside is not None:
            raw = _read_capped(beside / "index.json", MAX_GAMES_INDEX_BYTES)
        cached = self.cached("index.json")
        reason = "offline"
        failure = ""
        if raw is None and network:
            try:
                raw = _fetch_json(GAMES_URL.format(path="index.json"), MAX_GAMES_INDEX_BYTES,
                                  "games index", attempts=attempts, raw=True)
            except _Offline:
                reason = "offline"
            except (urllib.error.URLError, OSError, ValueError,
                    http.client.HTTPException) as exc:
                reason = "network"
                failure = str(exc)
            else:
                if cached is not None:
                    _cache_write(cached, raw)
        if raw is None and cached is not None:
            raw = _read_capped(cached, MAX_GAMES_INDEX_BYTES)
        if raw is None:
            raise GamesUnavailable(reason, (
                f"the games index is not on this machine and {offline_words()}"
                if reason == "offline"
                else f"the games index could not be downloaded ({failure})"))
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GamesUnavailable("invalid", f"the games index is not valid ({exc})") from exc
        if (not isinstance(data, dict) or data.get("format_version") != GAMES_FORMAT
                or not all(isinstance(data.get(kind), dict)
                           for kind in ("setups", "fallback", "systems", "arcade"))):
            raise GamesUnavailable("invalid", "the games index is of another format")
        self.index = data
        return data

    @staticmethod
    def _doc_held(beside: Path | None, cached: Path | None, name: str, digest: str,
                  limit: int) -> bytes | None:
        """A listed document beside --manifest or in the cache, of its sha256."""
        for source in (beside / name if beside is not None else None, cached):
            if source is None:
                continue
            found = _read_capped(source, limit)
            if found is not None and hashlib.sha256(found).hexdigest() == digest:
                return found
        return None

    @staticmethod
    def _doc_fetched(kind: str, name: str, digest: str, limit: int, attempts: int,
                     cached: Path | None) -> bytes | None:
        """A listed document downloaded and cached, None when offline."""
        try:
            fetched = _fetch_json(GAMES_URL.format(path=name), limit, f"games {kind}",
                                  attempts=attempts, raw=True)
        except _Offline:
            return None
        except (urllib.error.URLError, OSError, ValueError,
                http.client.HTTPException) as exc:
            raise GamesUnavailable(
                "network", f"install/games/{name} could not be downloaded ({exc})") from exc
        if hashlib.sha256(fetched).hexdigest() != digest:
            raise GamesUnavailable("invalid", f"install/games/{name} is not the one "
                                   "the games index lists")
        if cached is not None:
            _cache_write(cached, fetched)
        return fetched

    def doc(self, kind: str, key: str, network: bool = True,
            attempts: int = 2) -> dict | None:
        """One listed document, None when the index lists none of that name."""
        entry = self.load_index(network, attempts).get(kind, {}).get(key)
        if not isinstance(entry, dict):
            return None
        name = str(entry.get("file", ""))
        digest = str(entry.get("sha256", ""))
        if not _GAMES_DOC_NAME.match(name) or not _SHA256_RE.match(digest):
            raise GamesUnavailable("invalid", f"the games index names {name!r}")
        if name in self.docs:
            return self.docs[name]
        limit = min(int(entry.get("size") or 0), MAX_GAMES_DOC_BYTES)
        beside = self.beside()
        cached = self.cached(f"{digest}.json")
        raw = self._doc_held(beside, cached, name, digest, limit)
        if raw is None and network:
            raw = self._doc_fetched(kind, name, digest, limit, attempts, cached)
        if raw is None:
            raise GamesUnavailable("offline", f"install/games/{name} is not on this machine "
                                   f"and {offline_words()}")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GamesUnavailable("invalid", f"install/games/{name} is not valid") from exc
        if not isinstance(data, dict):
            raise GamesUnavailable("invalid", f"install/games/{name} is not valid")
        self.docs[name] = data
        return data


GAMES = GamesData()


# --- Where the games are -----------------------------------------------------


def _setup_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def games_setups(index: dict, plat: str, bios_path: Path, os_type: str = "") -> list[str]:
    """The setups whose rom folders this BIOS folder's games may sit in,
    best first: the system detection named (muOS, ArkOS), else the
    platform's own."""
    setups = index.get("setups") or {}
    named = detected_os(plat, bios_path)
    if not named:
        above = card_root_above(bios_path)
        named = above[0] if above else ""
    if not named:
        # --platform names the list, not the card: the full screen passes
        # --platform=retroarch for a muOS card, detection never runs in that
        # run, and the card's ROMS/ was never read. The card's own files
        # name its system, as card_app reads them for the app.
        card = card_app(bios_path)
        named = card.system if card else ""
    if not named:
        # --dest on a handheld's games part from a computer (ArkOS's
        # EASYROMS/bios): detection never ran there, and the card's own rom
        # folders sit beside the BIOS folder.
        part = games_part(bios_path.parent)
        named = part.name if part else ""
    key = _setup_key(named) if named else ""
    found = [name for name in sorted(setups) if key and (name == key or name.startswith(key + "-"))]
    if not found and plat in setups:
        found = [plat]
        windows = f"{plat}-windows"
        if (os_type or detect_os()) == "windows" and windows in setups:
            found.insert(0, windows)
    return found


def core_regions(facts: GameFacts, system_id: str, system: SystemData,
                 profile: str) -> frozenset | None:
    """The regions a game is proven to need under one core: the catalog's
    tag of the content matched, the region the core's own readers compute
    from its bytes, or both when they agree. None for no proof or for two
    proofs that disagree."""
    if facts.system != system_id:
        return None
    core = system.cores.get(profile) or {}
    header: frozenset | None = None
    order = [name for name in core.get("order") or [] if isinstance(name, str)]
    all_read = bool(order)
    for name in order:
        value = facts.readings.get(name)
        if value is None:
            all_read = False
            continue
        if isinstance(value, frozenset):
            header = value
            break
    otherwise = core.get("otherwise")
    if header is None and all_read and isinstance(otherwise, list) and otherwise:
        header = frozenset(str(region) for region in otherwise)
    proofs = [proof for proof in (facts.dat_regions, header) if proof]
    if not proofs:
        return None
    if len(proofs) == 2 and not any(_region_comparable(a, b)
                                    for a in proofs[0] for b in proofs[1]):
        return None
    return frozenset().union(*proofs)


# Cases of games/regions.yml a proven region does not settle whatever the
# game: device state (an option, a per-game setting) or the code itself.
_ALWAYS_WIDE = ("always", "option", "user-state")


def region_rule_keeps_all(rule: dict | None, games: list[GameFacts]) -> bool:
    """Whether the core keeps every region whatever its games prove: no rule
    read at its pin, or one of the cases games/regions.yml names (a region
    option, an override BIOS, a fallback across regions, a disc database)."""
    if not isinstance(rule, dict):
        return True
    for case in rule.get("keep_all_regions") or []:
        if not isinstance(case, dict):
            return True
        name, condition = case.get("case"), case.get("condition")
        if condition in _ALWAYS_WIDE:
            return True
        if name == "first-disc-region":
            if any(_suffix(game.path.name) == ".m3u" for game in games):
                return True
        elif name not in ("multi-area-disc", "gamecube-unknown-region", "saturn-kr-ipl"):
            return True
    return False


def needed_regions(rule: dict, proofs: list[frozenset | None]) -> frozenset | None:
    """The regions the games of one core prove, routed as the core routes
    them, None when one game proves none."""
    if not proofs or any(proof is None for proof in proofs):
        return None
    routes = rule.get("routes") or {}
    needed = frozenset(str(routes.get(region, region))
                       for proof in proofs for region in proof or ())
    wide = {str(case.get("case")) for case in rule.get("keep_all_regions") or []
            if isinstance(case, dict)}
    if "saturn-kr-ipl" in wide and needed & {"asia-ntsc", "south-korea"}:
        return None
    return needed


def keep_regions(dests: list[str], entries: dict[str, dict], needed: frozenset,
                 region_free: set[str]) -> list[str]:
    """The files of a set the proven regions keep: every file with no region
    tag, a world or region-free file, and those whose tag a needed region
    matches. A needed region no file matches keeps the whole set."""

    def regions(dest: str) -> list[str]:
        entry = entries.get(dest) or {}
        if Path(dest).name.casefold() in region_free:
            return []
        tags = [str(r) for r in entry.get("regions") or []]
        return [] if WORLD_REGION in tags else tags

    tagged = {dest: regions(dest) for dest in dests if regions(dest)}
    for region in needed:
        if not any(_region_comparable(region, tag) for tags in tagged.values() for tag in tags):
            return list(dests)
    return [dest for dest in dests
            if dest not in tagged
            or any(_region_comparable(region, tag) for region in needed for tag in tagged[dest])]


class GamesPlan:
    """What the games of a card need, and what was read to say so."""

    def __init__(self, root: Path, card: bool) -> None:
        self.root = root
        self.card = card
        self.games: list[GameFacts] = []
        self.not_games = 0
        self.support = 0
        # Per system: folder names, game count, recognised, regions kept
        # (empty for every region), and the cores whose sets were read.
        self.systems: dict[str, dict] = {}
        self.keep: set[str] = set()
        self.required: set[str] = set()
        self.unknown_core: list[str] = []
        self.truncated = False
        # The cores the games run on (a folder's default and its boards'),
        # and the systems of a folder no setup names a core for.
        self.profiles: set[str] = set()
        self.any_core: set[str] = set()

    @property
    def fallback(self) -> list[GameFacts]:
        return [game for game in self.games if game.reason]

    def where(self) -> str:
        return "on this card" if self.card else "in this folder"

    def wanted(self, required_only: bool) -> set[str]:
        return self.required if required_only else self.keep

    def apply(self, files: list[dict], omitted: list[dict],
              required_only: bool) -> tuple[list[dict], list[dict]]:
        """The files and omissions of the list the games need."""
        wanted = self.wanted(required_only)
        folded = {dest.casefold() for dest in wanted}
        kept = [entry for entry in files if entry.get("dest") in wanted
                or (entry.get("case_variant") and str(entry.get("dest")).casefold() in folded)]
        systems = {system for entry in kept for system in entry_systems(entry)}
        kept_omitted = [entry for entry in omitted
                        if (entry.get("dest") in wanted
                            or bool(set(entry_systems(entry)) & systems))
                        and (entry.get("required") or not required_only)]
        return kept, kept_omitted

    def event_systems(self) -> list[dict]:
        return [{"system": system, "folder": ", ".join(info["folders"]),
                 "games": info["games"], "recognised": info["recognised"],
                 "regions": sorted(info["regions"] or ())}
                for system, info in sorted(self.systems.items())]

    def event_fallback(self) -> list[dict]:
        return [{"system": game_system(game), "folder": game.folder.path.name,
                 "name": game.shown, "reason": game.reason} for game in self.fallback]


def game_system(game: GameFacts) -> str:
    systems = game.folder.row.get("systems") or []
    return str(systems[0]) if systems else ""


def _folder_profiles(row: dict) -> list[str | None]:
    """The cores a folder's games may run on: its default, and each board's
    (a card moves between boards, and is often read on a computer)."""
    found: list[str | None] = [row.get("profile")]
    for spec in (row.get("board_defaults") or {}).values():
        if isinstance(spec, dict) and spec.get("profile") not in found:
            found.append(spec.get("profile"))
    return found


def _folder_set_keys(row: dict, fallback: dict) -> list[str]:
    """The fallback sets of a folder: its own and its boards', else, for a
    folder no setup names a core for, every set of its systems."""
    keys = list(row.get("fallback") or [])
    for spec in (row.get("board_defaults") or {}).values():
        if isinstance(spec, dict):
            keys += [key for key in spec.get("fallback") or [] if key not in keys]
    if keys or "fallback" in row:
        return keys
    systems = set(row.get("systems") or [])
    return sorted(key for key in fallback.get("sets") or {}
                  if key.split("|", 1)[0] in systems)


def _set_rows(fallback: dict, key: str) -> tuple[list[str], set[str]]:
    """A fallback set's destinations and those the declaring layer marks optional."""
    table = fallback.get("files") or []
    chosen = (fallback.get("sets") or {}).get(key) or {}

    def dest(index: object) -> str | None:
        if isinstance(index, int) and 0 <= index < len(table):
            return str(table[index][0])
        return None

    files = [d for d in (dest(i) for i in chosen.get("files") or []) if d]
    optional = {d for d in (dest(i) for i in chosen.get("optional") or []) if d}
    return files, optional


def _named_dests(names: Iterable[str], pool: Iterable[str]) -> list[str]:
    wanted = {name.casefold() for name in names}
    return [dest for dest in pool if Path(dest).name.casefold() in wanted]


def plan_games(plat: str, bios_path: Path, manifest: dict, folder: Path | None = None,
               term: Terminal | None = None, data: GamesData | None = None,
               os_type: str = "", network: bool = True) -> GamesPlan | None:
    """What the games of the card (or of folder) need, from install/games/.

    None when the card has no rom folder this setup reads and no folder was
    named. Raises GamesUnavailable when the index cannot be read, or does
    not describe this list (a destination it names is not in the list).
    """
    data = data or GAMES
    index = data.load_index(network)
    fallback = data.doc("fallback", plat, network)
    if fallback is None:
        raise GamesUnavailable("no_sets", f"install/games/ holds no BIOS sets for {plat}")
    setup, root = _games_setup_root(data, index, plat, bios_path, folder, os_type, network)
    if root is None:
        return None
    folders = game_folders(setup, index, root, folder is not None)
    plan = GamesPlan(root, folder is None)
    entries = {str(entry.get("dest")): entry for entry in manifest.get("files") or []}
    listed = set(entries)
    found = _found_games(plan, folders, setup)
    docs = _GamesDocs(data, network)
    cache_root = cache_folder()
    cache = _ScanCache(cache_root / GAMES_SCAN_FILE if cache_root is not None else None)
    progress = ReadCounter(sum(len(games) for _folder, games in found), term, "games_reading",
                           " games")
    read = [(game_folder, _read_folder_games(plan, game_folder, games, docs, cache, progress))
            for game_folder, games in found]
    progress.end()
    cache.save()
    _plan_read_folders(plan, read, fallback, entries, docs)
    missing = sorted((plan.keep | plan.required) - listed)
    if missing:
        raise GamesUnavailable("stale", "the games index does not describe this file list "
                                        f"({missing[0]} is not in it)")
    return plan


def _games_setup_root(data: GamesData, index: dict, plat: str, bios_path: Path,
                      folder: Path | None, os_type: str,
                      network: bool) -> tuple[dict | None, Path | None]:
    """The rom folder setup the card follows, and the root of its games."""
    setup = None
    root = folder
    for key in games_setups(index, plat, bios_path, os_type):
        candidate = data.doc("setups", key, network)
        if candidate is None:
            continue
        setup = setup or candidate
        if folder is None:
            found_root = games_root(candidate, bios_path)
            if found_root is not None:
                setup, root = candidate, found_root
                break
    return setup, root


def _found_games(plan: GamesPlan, folders: list[GameFolder],
                 setup: dict | None) -> list[tuple[GameFolder, list[Path]]]:
    """The games of each folder, up to MAX_GAME_FILES in all."""
    budget = MAX_GAME_FILES
    found: list[tuple[GameFolder, list[Path]]] = []
    for game_folder in folders:
        games, others = folder_games(game_folder, setup, budget)
        budget -= len(games)
        plan.not_games += others
        found.append((game_folder, games))
        if budget <= 0:
            plan.truncated = True
            break
    return found


def _arcade_lookup(doc: dict) -> dict:
    """An arcade document as the lookups of _read_arcade read it."""
    parents: dict[str, list[str]] = {}
    for root_set, members in (doc.get("bios") or {}).items():
        for member in members:
            parents.setdefault(member, []).append(root_set)
    devices: dict[str, list[str]] = {}
    for device, members in (doc.get("devices") or {}).items():
        for member in members:
            devices.setdefault(member, []).append(device)
    known = set(parents) | set(devices) | set(doc.get("no_bios") or [])
    # FBNeo keys a console game by its driver (msx_1942): the
    # MSX, NES and Arcade lists each hold a 1942.
    consoles: dict[str, list[str]] = {}
    for key in known:
        driver, cut, stem = key.partition("_")
        if cut and stem:
            consoles.setdefault(stem, []).append(driver)
    return {
        "parents": parents, "devices": devices, "consoles": consoles,
        "plain": set(doc.get("no_bios") or []),
        "support": (set(doc.get("bios_sets") or []) | set(doc.get("bios") or {})
                    | set(doc.get("devices") or {})),
    }


class _GamesDocs:
    """The system and arcade documents of install/games/, each read once."""

    def __init__(self, data: GamesData, network: bool) -> None:
        self.data = data
        self.network = network
        self.systems: dict[str, SystemData] = {}
        self.arcades: dict[str, dict] = {}

    def system(self, system: str) -> SystemData:
        if system not in self.systems:
            self.systems[system] = SystemData(self.data.doc("systems", system, self.network))
        return self.systems[system]

    def arcade(self, name: str) -> dict | None:
        if name not in self.arcades:
            doc = self.data.doc("arcade", name, self.network)
            self.arcades[name] = {} if doc is None else _arcade_lookup(doc)
        return self.arcades[name] or None


def _folder_readers(row_systems: list[str], profiles: list[str | None],
                    docs: _GamesDocs) -> set[str]:
    """The cores of a folder's profiles that read its first system."""
    readers: set[str] = set()
    if row_systems:
        cores = docs.system(row_systems[0]).cores
        for profile in profiles:
            readers |= {name for name in (cores.get(profile or "") or {}).get("order") or []
                        if isinstance(name, str)}
    return readers


def _count_game(plan: GamesPlan, game_folder: GameFolder, row_systems: list[str],
                facts: GameFacts) -> None:
    """Count a game under each system of its folder."""
    for system in row_systems:
        info = plan.systems.setdefault(system, {"folders": [], "games": 0,
                                                "recognised": 0, "regions": None})
        if game_folder.path.name not in info["folders"]:
            info["folders"].append(game_folder.path.name)
        info["games"] += 1
        info["recognised"] += int(facts.recognised)


def _read_folder_games(plan: GamesPlan, game_folder: GameFolder, games: list[Path],
                       docs: _GamesDocs, cache: _ScanCache,
                       progress: ReadCounter) -> list[GameFacts]:
    """Read the games of one folder: the ones that are not support sets."""
    row = game_folder.row
    row_systems = [str(s) for s in row.get("systems") or []]
    arcade = row.get("arcade") if isinstance(row.get("arcade"), str) else None
    profiles = _folder_profiles(row)
    if row_systems and not row.get("profile") and "fallback" not in row:
        plan.unknown_core += [s for s in row_systems if s not in plan.unknown_core]
    readers = _folder_readers(row_systems, profiles, docs)
    group: list[GameFacts] = []
    for path in games:
        shown = os.path.relpath(path, plan.root).replace(os.sep, "/")
        facts = GameFacts(path, shown, game_folder)
        progress.done += 1
        if row.get("arcade"):
            _read_arcade(facts, docs.arcade(arcade) if arcade else None,
                         _console_hints(game_folder))
        elif row_systems:
            read_game(facts, row_systems[0], docs.system(row_systems[0]), readers, cache)
        progress.step()
        if facts.kind == "support":
            plan.support += 1
            continue
        plan.games.append(facts)
        group.append(facts)
        _count_game(plan, game_folder, row_systems, facts)
    return group


def _plan_read_folders(plan: GamesPlan, read: list[tuple[GameFolder, list[GameFacts]]],
                       fallback: dict, entries: dict[str, dict], docs: _GamesDocs) -> None:
    """Add to the plan what the games read in each folder need."""
    for game_folder, group in read:
        if group:
            for profile in _folder_profiles(game_folder.row):
                if profile:
                    plan.profiles.add(str(profile))
                else:
                    plan.any_core.update(str(s) for s in game_folder.row.get("systems") or [])
            arcade = game_folder.row.get("arcade")
            sets = (docs.arcade(arcade) or {}).get("support", set()) \
                if isinstance(arcade, str) else set()
            _plan_game_folder(plan, game_folder, group, fallback, entries, docs.system, sets)


# Systems whose folder an arcade core reads as arcade sets, by their bare
# set name. Any other system's sets are console games, keyed by driver.
_ARCADE_SYSTEMS = frozenset({"arcade", "neogeo", "snk-neogeo", "sega-naomi", "sega-naomi2",
                             "sammy-atomiswave", "sega-stv", "cps1", "cps2", "cps3"})


def _console_hints(folder: GameFolder) -> tuple[str, ...] | None:
    """None for an arcade folder, else the words of its systems and its
    name, which tell one console's driver prefix from another's."""
    systems = [str(s) for s in folder.row.get("systems") or []]
    if not systems or any(s in _ARCADE_SYSTEMS or s.startswith("arcade") for s in systems):
        return None
    words = {word for system in systems for word in system.split("-")}
    words.add(folder.path.name.lower())
    return tuple(sorted(words))


def _read_arcade(facts: GameFacts, index: dict | None,
                 console: tuple[str, ...] | None = None) -> None:
    """An arcade set: a BIOS or device set (not a game), a game and the BIOS
    sets its romof chain reaches, or a name the core's DAT does not hold. In
    a console's folder (console, the words of its systems) a set is looked
    for under the core's driver name for it (msx_1942): the bare name is an
    arcade set's."""
    if _suffix(facts.path.name) not in ARCADE_SUFFIXES:
        facts.kind = "support"
        return
    name = os.path.splitext(facts.path.name)[0].lower()
    if index is None:
        facts.reason = "not_recognised"
        return
    if name in index["support"]:
        facts.kind = "support"
        return
    keys = [name]
    if console is not None:
        drivers = index.get("consoles", {}).get(name, [])
        hinted = [d for d in drivers if d in console]
        # A prefix no word of the folder names: every console's driver of
        # that name, so that the right one is among them.
        keys = [f"{d}_{name}" for d in sorted(hinted or drivers)] or [name]
    parents = {p for key in keys for p in index["parents"].get(key, ())}
    devices = {d for key in keys for d in index["devices"].get(key, ())}
    facts.parents, facts.devices = tuple(sorted(parents)), tuple(sorted(devices))
    if parents or devices or any(key in index["plain"] for key in keys):
        facts.recognised = True
        facts.title = keys[0] if len(keys) == 1 else name
    else:
        facts.reason = "unknown_set"


def _read_by_profiles(entries: dict[str, dict], dest: str, profiles: list[str]) -> bool:
    """Whether one of a folder's profiles reads dest, every core when the
    entry names none."""
    cores = (entries.get(dest) or {}).get("cores")
    return cores is None or any(name in cores for name in profiles)


def _plan_arcade_folder(plan: GamesPlan, games: list[GameFacts], entries: dict[str, dict],
                        profiles: list[str], sets: dict[str, tuple[list[str], set[str]]],
                        arcade_sets: Collection[str]) -> None:
    """Add to the plan the BIOS and device sets an arcade folder's games need."""
    # A BIOS set is looked for in the whole list, as the platform's own
    # declaration (neogeo.zip) and as the core's (fbneo/neogeo.zip).
    usable = [dest for dest in entries if _read_by_profiles(entries, dest, profiles)]
    whole = False
    for game in games:
        if game.reason:
            whole = True
            continue
        names = set(game.parents + game.devices)
        needed = _named_dests([f"{name}.zip" for name in names], usable)
        held = {Path(dest).name.casefold() for dest in needed}
        if any(f"{name}.zip".casefold() not in held for name in names):
            game.reason = "no_parent"
            whole = True
            continue
        plan.keep.update(needed)
        plan.required.update(needed)
    if whole:
        # Every set of the folder, and every BIOS set the core reads.
        own = _named_dests([f"{name}.zip" for name in arcade_sets],
                           [dest for dest in usable
                            if (entries.get(dest) or {}).get("cores") is not None])
        plan.keep.update(own)
        plan.required.update(own)
        for files, optional in sets.values():
            plan.keep.update(files)
            plan.required.update(dest for dest in files if dest not in optional)


def _region_kept(files: list[str], games: list[GameFacts], entries: dict[str, dict],
                 system: str, info: SystemData,
                 profile: str) -> tuple[list[str], bool, frozenset | None]:
    """The files of a set the games' regions keep, whether every region is
    kept, and the regions it was narrowed to (None when not narrowed)."""
    rule = info.rules.get(profile)
    region_free = {str(name).casefold() for name in (rule or {}).get("region_free") or []}
    tagged = any((entries.get(dest) or {}).get("regions") for dest in files)
    if not tagged:
        return list(files), False, None
    if region_rule_keeps_all(rule, games):
        return list(files), True, None
    proofs = [core_regions(game, system, info, profile) for game in games]
    needed = needed_regions(rule or {}, proofs)
    if needed is None:
        for game, proof in zip(games, proofs):
            if proof is None and not game.reason:
                game.reason = ("not_read" if not game.read
                               else "not_recognised" if not game.recognised
                               else "region_unknown")
        return list(files), True, None
    kept = keep_regions(files, entries, needed, region_free)
    if len(kept) < len(files):
        return kept, False, needed
    return kept, True, None


def _plan_set_extras(plan: GamesPlan, info: SystemData, profile: str, games: list[GameFacts],
                     files: list[str], kept: list[str], entries: dict[str, dict],
                     profiles: list[str]) -> None:
    """Add to the plan the games/extras.yml files of a set that fire."""
    for extra in info.extras:
        if extra.get("profile") != profile or not _extra_fires(extra, games):
            continue
        if extra.get("region_files"):
            named = [dest for dest in kept if (entries.get(dest) or {}).get("regions")]
        else:
            names = extra.get("files") or []
            named = _named_dests(names, files) or _named_dests(
                names, [dest for dest in entries if _read_by_profiles(entries, dest, profiles)])
        plan.keep.update(named)
        if extra.get("required") or extra.get("filename_override"):
            plan.required.update(named)


def _plan_game_folder(plan: GamesPlan, game_folder: GameFolder, games: list[GameFacts],
                      fallback: dict, entries: dict[str, dict],
                      system_data: Callable[[str], SystemData],
                      arcade_sets: Collection[str] = ()) -> None:
    """Add to the plan what one folder's games need. arcade_sets are the
    BIOS and device sets of the folder's arcade index."""
    row = game_folder.row
    profiles = [name for name in _folder_profiles(row) if name]

    if not row.get("systems"):
        # A port's own folder, read by one core and named by no system: what
        # that core loads.
        named = [dest for dest, entry in entries.items()
                 if any(name in (entry.get("cores") or []) for name in profiles)]
        plan.keep.update(named)
        plan.required.update(named)
        return
    keys = _folder_set_keys(row, fallback)
    sets: dict[str, tuple[list[str], set[str]]] = {key: _set_rows(fallback, key) for key in keys}
    if row.get("arcade"):
        _plan_arcade_folder(plan, games, entries, profiles, sets, arcade_sets)
        return
    narrowed: dict[str, set[str]] = {}
    wide: set[str] = set()
    for key, (files, optional) in sets.items():
        system, _, profile = key.partition("|")
        info = system_data(system)
        kept, every, narrowed_to = _region_kept(files, games, entries, system, info, profile)
        if every:
            wide.add(system)
        elif narrowed_to is not None:
            narrowed.setdefault(system, set()).update(narrowed_to)
        plan.keep.update(kept)
        plan.required.update(dest for dest in kept if dest not in optional)
        _plan_set_extras(plan, info, profile, games, files, kept, entries, profiles)
    for system, regions in narrowed.items():
        state = plan.systems.get(system)
        # Said only where no core of the folder keeps the other regions.
        if state is not None and system not in wide:
            state["regions"] = sorted(set(state["regions"] or ()) | regions)


def _extra_fires(extra: dict, games: list[GameFacts]) -> bool:
    """Whether a games/extras.yml entry applies to these games. A trigger on
    header bytes this file does not read applies: the file stays."""
    trigger = extra.get("trigger") or {}
    if trigger.get("every_game") or trigger.get("header"):
        return True
    extensions = {str(ext).lower() for ext in trigger.get("extensions") or []}
    return any(_suffix(game.path.name) in extensions for game in games)


def games_lines(plan: GamesPlan, manifest: dict | None, every: bool = False) -> list[str]:
    """The games read, in words: the head of the plan and of --check."""
    count = len(plan.games)
    if not count:
        lines = [f"No game found {plan.where()} ({shown_path(plan.root)})."]
        if plan.not_games:
            lines.append(f"  {_plural(plan.not_games, 'other file')} in its game folders: "
                         "none has an extension its system reads.")
        return lines
    recognised = sum(1 for game in plan.games if game.recognised)
    lines = [f"Games {plan.where()}: {count} in {_plural(len(plan.systems), 'system')}, "
             f"{recognised} recognised by their content ({shown_path(plan.root)})."]
    narrowed = [f"{system_title(system, manifest)} {', '.join(map(region_title, info['regions']))}"
                for system, info in sorted(plan.systems.items()) if info["regions"]]
    if narrowed:
        lines.append(f"  One region where the games prove it: {'; '.join(narrowed)}.")
    if plan.unknown_core:
        titles = ", ".join(system_title(system, manifest) for system in plan.unknown_core)
        lines.append(f"  No default core is known for {titles}: the files of each of its "
                     "cores are kept.")
    lines += fallback_lines(plan, every)
    if plan.truncated:
        lines.append(f"  Read up to {MAX_GAME_FILES} files: the others are left out of the count.")
    return lines


def fallback_lines(plan: GamesPlan, every: bool = False) -> list[str]:
    """The games that got every BIOS of their system, named."""
    fallback = plan.fallback
    if not fallback:
        return []
    shown = fallback if every else fallback[:3]
    names = ", ".join(f"{game.shown} ({GAMES_REASONS.get(game.reason, game.reason)})"
                      for game in shown)
    more = "" if len(shown) == len(fallback) else f" and {len(fallback) - len(shown)} more"
    their = "its" if len(fallback) == 1 else "their"
    return [f"  {agree(len(fallback), 'game gets', 'games get')} every BIOS of {their} "
            f"system: {names}{more}."]


def emit_games(plat: str, plan: GamesPlan, required_only: bool) -> None:
    EVENTS.emit("games", platform=plat, folder=str(plan.root), games=len(plan.games),
                recognised=sum(1 for game in plan.games if game.recognised),
                found=plan.event_systems(), fallback=plan.event_fallback(),
                not_games=plan.not_games, required_only=required_only)


def games_probe(plat: str, bios_path: Path, network: bool = True,
                data: GamesData | None = None, os_type: str = "",
                attempts: int = 2) -> int | None:
    """How many folders of the card hold a game, read by name alone (no
    file opened), None when it cannot be said: no rom folder near the BIOS
    folder, or install/games/ out of reach. What makes "For the games on this
    card" the first choice."""
    if not _may_hold_games(bios_path):
        return None
    data = data or GAMES
    try:
        index = data.load_index(network, attempts)
        for key in games_setups(index, plat, bios_path, os_type):
            setup = data.doc("setups", key, network, attempts)
            root = games_root(setup, bios_path) if setup is not None else None
            if root is None:
                continue
            held = 0
            for game_folder in game_folders(setup, index, root, False):
                games, _others = folder_games(game_folder, setup, 1)
                held += bool(games)
            return held
    except GamesUnavailable:
        return None
    return None


def read_games(args: argparse.Namespace, plat: str, bios_path: Path, manifest: dict,
               term: Terminal | None, os_type: str) -> GamesPlan | None:
    """The games of the card read for this run, their lines said. None when
    there are none to read, or what they need cannot be known: the run then
    keeps every file, and says so where --for-games asked."""
    asked = args.for_games is not None
    folder = args.for_games if isinstance(args.for_games, Path) else None
    if folder is not None:
        folder = Path(os.path.expanduser(str(folder))).absolute()
        if not _is_dir(folder):
            message = f"the games folder {folder} does not exist or cannot be opened"
            EVENTS.emit("games_unavailable", platform=plat, reason="no_folder", message=message)
            print(f"Error: {message}.", file=sys.stderr)
            sys.exit(1)
    # Not asked for, a run given its list as a file looks for the games index
    # beside it and in the cache only: one fetched now could describe another
    # list.
    network = asked or LOCAL.manifest is None
    if folder is None and not asked and not games_probe(plat, bios_path, network,
                                                       os_type=os_type):
        return None
    where = "on the card" if folder is None else f"in {folder}"
    detail(f"\nReading the games {where}...")
    try:
        plan = plan_games(plat, bios_path, manifest, folder, term, os_type=os_type,
                          network=network)
    except GamesUnavailable as exc:
        if asked:
            EVENTS.emit("games_unavailable", platform=plat, reason=exc.reason,
                        message=exc.words)
            print(fold_line(f"  What the games need is not known: {exc.words}. Every file "
                            "of the list is kept."))
        return None
    if plan is None:
        if asked:
            message = (f"no games folder was found beside {shown_path(bios_path)}: name it "
                       "with --for-games FOLDER")
            EVENTS.emit("games_unavailable", platform=plat, reason="no_folder", message=message)
            print(fold_line(f"  {message[0].upper()}{message[1:]}. Every file of the list "
                            "is kept."))
        return None
    emit_games(plat, plan, bool(args.required_only))
    for line in games_lines(plan, manifest, bool(args.verbose)):
        detail(fold_line(line if line.startswith("  ") else f"  {line}"))
    return plan
