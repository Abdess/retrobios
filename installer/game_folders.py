"""Reading the game folders of a card into the systems and BIOS sets its games need."""

from __future__ import annotations

import os
from collections.abc import Callable, Collection, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from installer.console import ReadCounter
from installer.game_files import (
    ARCADE_SUFFIXES,
    GameFacts,
    SystemData,
    _ScanCache,
    _suffix,
    read_game,
)
from installer.game_regions import _region_kept
from installer.games_index import GamesData
from installer.platforms import entry_systems

if TYPE_CHECKING:
    from installer.game_files import GameFolder


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
