"""What a check counts, and the files a list leaves out, in words and in events."""
from __future__ import annotations

import platform
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

from installer.constants import CATEGORY_LABELS, GAME_DATA, OMISSION_REASONS, OTHER_SYSTEMS
from installer.cores import entry_systems
from installer.detect_os import _parse_os_release
from installer.embedded import display_name
from installer.events import EVENTS
from installer.local_files import _classify_local
from installer.narrowing import _settle_slot
from installer.paths import _entry_path
from installer.text import _plural, format_size


def _os_name() -> str:
    """The OS's own name, from os-release, else the kernel's."""
    release = _parse_os_release()
    return release.get("PRETTY_NAME") or release.get("NAME") or platform.system()


class CheckTally(NamedTuple):
    """What a check found, as _emit_check says it."""

    files: list[dict]
    up_to_date: list[dict]
    mismatched: list[dict]
    data_missing: int = 0
    not_installable: int = 0
    data_bytes: int = 0


def _emit_check(
    plat: str, manifest: dict, bios_path: Path, tally: CheckTally,
    *, chosen: list[str] | None = None,
) -> None:
    """One event per file, per system and per platform after a check, then
    one for the files of the platform's own list.

    With systems chosen, only those are described: a file of SkyEmu's
    carries four systems, and --system nintendo-gba described gb, gbc and
    ds by the few files the choice kept of them.
    """
    files, up_to_date, mismatched = tally.files, tally.up_to_date, tally.mismatched
    present = {id(entry) for entry in up_to_date}
    wrong = {id(entry) for entry in mismatched}
    systems: dict[str, dict[str, int]] = {}
    for entry in files:
        state = ("present" if id(entry) in present
                 else "wrong_hash" if id(entry) in wrong else "missing")
        size = entry.get("size", 0)
        EVENTS.emit("file", platform=plat, dest=entry["dest"],
                    systems=entry_systems(entry), size=size, state=state)
        for system in entry_systems(entry) or [OTHER_SYSTEMS]:
            counts = systems.setdefault(system, {
                "files": 0, "present": 0, "missing": 0, "wrong_hash": 0,
                "bytes_needed": 0,
            })
            counts["files"] += 1
            counts[state] += 1
            if state != "present":
                counts["bytes_needed"] += size
    names = manifest.get("system_names") or {}
    for system in sorted(systems):
        if chosen and system not in chosen:
            continue
        EVENTS.emit("system", platform=plat, system=system,
                    name=", ".join(names.get(system) or [system]), **systems[system])
    needed = [entry for entry in files if id(entry) not in present]
    EVENTS.emit(
        "check", platform=plat, name=display_name(plat, manifest), bios_dir=str(bios_path),
        files=len(files), present=len(up_to_date), missing=len(needed) - len(mismatched),
        wrong_hash=len(mismatched),
        bytes_needed=sum(entry.get("size", 0) for entry in needed),
        data_missing=tally.data_missing, not_installable=tally.not_installable,
    )
    # The copy the platform itself checks at each of its slots, which is
    # what --declared-only checks: a core's copy served in its place is
    # judged against the platform's.
    own_states = []
    for entry in files:
        if entry.get("cores") is not None:
            continue
        copy = declared_copy(entry)
        if copy is entry or copy.get("sha1") == entry.get("sha1"):
            state = ("present" if id(entry) in present
                     else "wrong_hash" if id(entry) in wrong else "missing")
        else:
            state = _declared_state(copy, entry, bios_path)
        own_states.append((entry["dest"], copy.get("size", 0), state))
    EVENTS.emit(
        "declared", platform=plat, files=len(own_states),
        present=sum(1 for _d, _s, state in own_states if state == "present"),
        missing=sum(1 for _d, _s, state in own_states if state == "missing"),
        wrong_hash=sum(1 for _d, _s, state in own_states if state == "wrong_hash"),
        bytes_needed=sum(size for _d, size, state in own_states if state != "present"),
        dests=[dest for dest, _s, _state in own_states],
    )
    EVENTS.emit("data", platform=plat, files=tally.data_missing, bytes=tally.data_bytes)


def _declared_state(copy: dict, entry: dict, bios_path: Path) -> str:
    """present, missing or wrong_hash: the file at entry's place against copy."""
    try:
        path = _entry_path(bios_path, entry)
    except ValueError:
        return "missing"
    try:
        if not path.is_file():
            return "missing" if not path.exists() else "wrong_hash"
        verdict = _classify_local(copy, path)
    except OSError:
        return "wrong_hash"
    return "present" if verdict == "up_to_date" else "wrong_hash"


def leave_out_game_data(
    files: list[dict], omitted: list[dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """The files and omissions without game data, and what was left out.

    The same cut as a pack built with --no-game-data: the manifest marks
    each file that is a game's data, not firmware.
    """
    left_out = [e for e in files + omitted if e.get("category") == GAME_DATA]
    return (
        [e for e in files if e.get("category") != GAME_DATA],
        [e for e in omitted if e.get("category") != GAME_DATA],
        left_out,
    )


class Tally(NamedTuple):
    """Files and bytes of one list, BIOS files and game data apart. bios
    and games add up to files, their bytes to size: every count a run
    prints of a list comes from here."""

    files: int
    size: int
    bios: int
    bios_size: int
    games: int
    game_size: int


def tally(entries: Iterable[dict]) -> Tally:
    """The counts of entries, each with its size and the category the list
    gives it, anything not game data being a BIOS file.

    The run said 8069 files (6.5 GB) while its menu said 8348 (7.1 GB) and
    3259 BIOS files and 5089 game data files: three counts of three lists.
    """
    bios = bios_size = games = game_size = 0
    for entry in entries:
        size = int(entry.get("size") or 0)
        if entry.get("category") == GAME_DATA:
            games += 1
            game_size += size
        else:
            bios += 1
            bios_size += size
    return Tally(bios + games, bios_size + game_size, bios, bios_size, games, game_size)


def sized_words(counts: Tally) -> str:
    """The count and the size, as in 8358 files, 6.6 GB."""
    return f"{_plural(counts.files, 'file')}, {format_size(counts.size)}"


def installed_words(bios: int, games: int, data: int = 0) -> str:
    """The kinds a run installed, those it installed none of left out:
    "6 BIOS files" where the old card's result said no kind at all."""
    parts = [_plural(count, word) for count, word in (
        (bios, "BIOS file"), (games, "game data file"), (data, "data file")) if count]
    if not parts:
        return _plural(0, "file")
    return f"{', '.join(parts[:-1])} and {parts[-1]}" if len(parts) > 1 else parts[0]


def parts_words(counts: Tally, data: int = 0, data_size: int | None = None,
                left_out: int = 0) -> str:
    """The files of a plan by kind, each with its size: BIOS files, game
    data and the data files of the emulators' data folders, then the game
    data left out. "" when one kind alone is counted and nothing is left
    out. "8358 files and 2636 data files" sat above "3269 BIOS files and
    5089 game data files", which add up to 8358 only, and "No game data"
    read as a list holding none."""
    parts = []
    if counts.bios or not (counts.games or data):
        parts.append(f"{_plural(counts.bios, 'BIOS file')} ({format_size(counts.bios_size)})")
    if counts.games:
        parts.append(f"{_plural(counts.games, 'game data file')} "
                     f"({format_size(counts.game_size)})")
    if data:
        parts.append(_plural(data, "data file")
                     + (f" ({format_size(data_size)})" if data_size is not None else ""))
    if len(parts) < 2 and not left_out:
        return ""
    text = f"{', '.join(parts[:-1])} and {parts[-1]}" if len(parts) > 1 else parts[0]
    return text + (f". {_plural(left_out, 'game data file')} left out" if left_out else "")


def kinds_definition(games: bool, data: bool) -> str:
    """What game data and data files are, one sentence each, for the kinds
    a plan counts: said once, after the counts."""
    said = [words[0].upper() + words[1:] + "." for words, shown in (
        (GAME_DATA_WORDS, games), (DATA_FILES_WORDS, data)) if shown]
    return " ".join(said)


def game_data_state(left_out: bool, games: Tally) -> str:
    """The one label of the game data choice, its count after: the plan's
    row and the line menu's g."""
    return (f"Game data: {'left out' if left_out else 'kept'} "
            f"({_plural(games.games, 'file')}, {format_size(games.game_size)})")


def keep_declared(files: list[dict], omitted: list[dict]) -> tuple[list[dict], list[dict]]:
    """The files and omissions the platform's own list declares (cores: null).

    A slot a core contradicts gets the platform's copy, and no core copy
    stays behind as an alternative: narrowing by cores afterwards would
    otherwise put a core's file back where a dropped system's was. Which of
    the platform's declarations answers is left to that narrowing, as
    without --declared-only: the first whose systems remain.
    """
    def own(entries: list[dict]) -> list[dict]:
        result = []
        for entry in entries:
            if entry.get("cores") is not None:
                continue
            kept = {k: v for k, v in _settle_slot(entry, set()).items()
                    if k not in ("alternatives", "declared_copy")}
            declared = entry.get("declared_choices") or []
            if len(declared) > 1:
                kept["declared_choices"] = declared
            result.append(kept)
        return result

    return own(files), own(omitted)


def declared_copy(entry: dict) -> dict:
    """The copy the platform's own list checks at a platform file's slot.

    A narrowing that serves a core's copy there records the platform's
    answer beside it, and an entry not yet settled answers by its first
    declaration. Otherwise the entry is the platform's copy itself.
    """
    recorded = entry.get("declared_copy")
    if recorded is not None:
        return recorded
    declared = entry.get("declared_choices")
    if declared:
        return declared[0]
    return entry


def _left_out_lines(left_out: list[dict], every: bool) -> list[str]:
    """What --no-game-data left out, named per category, ten each unless every."""
    lines = []
    # The omitted ones apart: "leave out the 5089 game data files" was
    # followed by "Left out as game data: 5099 files", the other ten being
    # files the list cannot install anyway.
    for group in _left_out_events(left_out):
        dests = group["dests"]
        shown = dests if every else dests[:10]
        more = (f" ... and {len(dests) - len(shown)} more (--verbose lists them all)"
                if len(shown) < len(dests) else "")
        omitted = sum(1 for entry in left_out if entry.get("reason")
                      and entry.get("category", "") == group["category"])
        aside = f", {omitted} of them not installable" if omitted else ""
        lines.append(f"  {left_out_words(group)} (--no-game-data){aside}: "
                     f"{', '.join(shown)}{more}")
    return lines


def left_out_words(group: dict) -> str:
    """A left_out group in the plan's words: 6 game data files left out."""
    return f"{_plural(group['files'], group['label'] + ' file')} left out"


def _left_out_events(left_out: list[dict]) -> list[dict]:
    """What --no-game-data left out, per category, every file named."""
    groups: dict[str, dict] = {}
    for entry in left_out:
        category = entry.get("category", "")
        group = groups.setdefault(category, {
            "category": category, "label": CATEGORY_LABELS.get(category, category),
            "files": 0, "dests": [],
        })
        group["files"] += 1
        group["dests"].append(entry["dest"])
    return [groups[category] for category in sorted(groups)]


def _skipped(omitted: list[dict]) -> list[dict]:
    """The files the collection cannot supply, grouped by reason."""
    groups: dict[str, dict] = {}
    for entry in omitted:
        reason = entry.get("reason", "unknown")
        group = groups.setdefault(reason, {
            "reason": reason, "label": OMISSION_REASONS.get(reason, reason),
            "files": 0, "required": 0,
        })
        group["files"] += 1
        group["required"] += bool(entry.get("required", True))
    return [groups[reason] for reason in sorted(groups)]


# What game data is, said wherever it is counted or chosen.
GAME_DATA_WORDS = "game data: files a game or a game engine reads, of no use to the other cores"
# The third kind: the files of an emulator's data folder (a data_directories
# entry of the list), apart from BIOS files and game data.
DATA_FILES_WORDS = ("data files: the files an emulator reads from a data folder of its own, "
                    "such as Dolphin's Sys and PPSSPP's assets")
