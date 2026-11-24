"""Games on the card: the plan of BIOS they need, its lines and events, and the run that reads them."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import TYPE_CHECKING

from installer.console import ReadCounter, detail, fold_line
from installer.events import EVENTS
from installer.game_files import (
    GAMES_SCAN_FILE,
    MAX_GAME_FILES,
    _ScanCache,
    _may_hold_games,
    cache_folder,
    folder_games,
    game_folders,
    games_root,
)
from installer.game_folders import GamesPlan, _GamesDocs, _plan_read_folders, _read_folder_games
from installer.games_index import GAMES, GAMES_REASONS, GamesData, GamesUnavailable, games_setups
from installer.host_fs import _is_dir
from installer.offline import LOCAL
from installer.paths import shown_path
from installer.platforms import system_title
from installer.refusal import Refusal
from installer.regions import region_title
from installer.text import _plural, agree

if TYPE_CHECKING:
    from installer.game_files import GameFolder
    from installer.terminal import Terminal


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


def games_folder(given: Path) -> Path:
    """The folder --for-games names, as the run reads it."""
    return Path(os.path.expanduser(str(given))).absolute()


def games_folder_refusal(given: object, platform: str) -> Refusal | None:
    """The refusal of a folder named with --for-games that cannot be opened,
    or None. Asked before the run, as for --from and --pack: a typo fetched
    the file list first, and an offline run blamed the list instead."""
    if not isinstance(given, Path):
        return None
    folder = games_folder(given)
    if _is_dir(folder):
        return None
    message = f"the games folder {folder} does not exist or cannot be opened"
    return Refusal("games", "no_folder", platform, f"Error: {message}.", message=message)


def read_games(args: argparse.Namespace, plat: str, bios_path: Path, manifest: dict,
               term: Terminal | None, os_type: str) -> GamesPlan | None:
    """The games of the card read for this run, their lines said. None when
    there are none to read, or what they need cannot be known: the run then
    keeps every file, and says so where --for-games asked."""
    asked = args.for_games is not None
    folder = games_folder(args.for_games) if isinstance(args.for_games, Path) else None
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
