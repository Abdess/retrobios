"""Removing what a run installed, and the backups it leaves."""
from __future__ import annotations

import argparse
import datetime
import errno
import json
import os
import re
import stat
import sys
import urllib.error
from collections.abc import Collection, Iterable
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.choices import available_choices, emulator_names, resolve_choices
from installer.console import QUIT_CODE, _answer_yes
from installer.destination import card_dest
from installer.detect_frontends import detect_platforms
from installer.detect_os import detect_os
from installer.events import EVENTS
from installer.filesystems import keeps_case
from installer.host_fs import _clear_read_only, _is_link
from installer.install_record import (
    _backup_note,
    _below,
    _check_ours,
    _record_now,
    _update_record,
    day_words,
    load_record,
    record_argv,
    record_options,
    setup_record,
)
from installer.invocation import _INVOCATION, offline_requested
from installer.local_check import _digest_file
from installer.manifest import OTHER_SYSTEMS, _validate_manifest, entry_copies
from installer.narrowing import designated_cores
from installer.network import _fetch_json, fetch_manifest
from installer.paths import shown_path, spelled
from installer.platforms import display_name, entry_systems, normalize_platform, refuse_name, system_title
from installer.remote import MANIFEST_URL, MAX_MANIFEST_BYTES
from installer.safe_replace import (
    BACKUP_DIR,
    KEPT,
    REMOVED_NOTE,
    KeptFiles,
    _backup_files,
    _is_backup_run,
    _move_aside,
    _tree,
)
from installer.text import _plural, agree, format_size

# Removal deletes for good, or moves into a backup with --backup, only what
# the install record proves the installer placed: a file it lists, still
# its recorded bytes, the collection able to serve it again. Anything else
# is named and left. Why each file stays, as removal_plan's kept says it.
REMOVAL_REASONS = {
    "shared": "still needed",
    "changed": "changed since it was installed",
    "link": "a link, never followed",
    "not_a_file": "not a regular file",
    "outside": "outside the BIOS folder",
    "not_servable": "the collection cannot give it again",
    "unreadable": "could not be read",
    "not_recorded": "not installed by RetroBIOS",
}
# Why a planned file stays when it changed between the plan and its removal.
CHANGED_SINCE_PLAN = "changed since the plan"


class Removal(NamedTuple):
    """What a removal takes and leaves. remove holds {dest, root, sha1,
    size, systems, path, inode} per file to remove, kept {dest, root, sha1,
    size, systems, reason, what} per file left, gone the record's entries
    no longer on disk, choice the setup's choice once the removal is done
    (None: the setup goes from the record), systems those losing a file."""

    plat: str
    folder: Path
    remove: list
    kept: list
    gone: list
    choice: list | None
    systems: list


def _drive_key(dest: str, fold: bool) -> str:
    """dest as the drive compares it, folded where it folds case."""
    return dest.casefold() if fold else dest


def _entry_sha1s(entry: dict) -> set[str]:
    return {str(copy.get("sha1")) for copy in entry_copies(entry)
            if copy.get("sha1")}


def _entry_readers(entry: dict) -> set[str] | None:
    """The cores that read an entry, None for a file of the platform's own list."""
    if entry.get("cores") is None:
        return None
    return {core for copy in entry_copies(entry)
            for core in copy.get("cores") or ()}


def _served(manifest: dict, fold: bool) -> dict[tuple[str, str], tuple]:
    """What the list serves, by (root, dest): (the sha1s it serves there,
    its systems, the cores that read it, whether the platform's own list
    names it). A place listed twice keeps both: a core's copy beside the
    platform's own never makes the file a core's alone. A data tree's member
    counts under root data, as the record keeps it."""
    served: dict[tuple[str, str], tuple] = {}
    for entry in [*(manifest.get("files") or []), *(manifest.get("case_variants") or [])]:
        dest = str(entry.get("dest"))
        place = (str(entry.get("root") or ""), _drive_key(dest, fold))
        sha1s, systems, readers, own = served.get(place, (set(), [], set(), False))
        mine = _entry_readers(entry)
        served[place] = (sha1s | _entry_sha1s(entry),
                         sorted(set(systems) | set(entry_systems(entry))),
                         readers | (mine or set()), own or mine is None)
    for tree in manifest.get("data_directories") or []:
        for rel, meta in (tree.get("files") or {}).items():
            dest = f"{tree['dest']}/{rel}" if tree.get("dest") else rel
            served[("data", _drive_key(dest, fold))] = (
                {str(meta.get("sha1"))}, list(tree.get("systems") or []), set(), True)
    return served


def _choice_names(options: list[tuple[str, str | None]], flag: str) -> list[str]:
    return [name.strip() for option, value in options if option == flag
            for name in (value or "").split(",") if name.strip()]


def _choice_without(choice: list[str], flag: str, names: Collection[str],
                    left: list[str]) -> list[str]:
    """A recorded choice once names of flag are taken out: those it named
    go, and a choice that named none gets the names left. A flag left with
    no name is dropped."""
    options = [option for option in record_options(choice) if option[0] != "--all-files"]
    gone = {name.casefold() for name in names}
    remaining = [name for name in (_choice_names(options, flag) or left)
                 if name.casefold() not in gone]
    kept = [option for option in options if option[0] != flag]
    if remaining:
        kept.append((flag, ",".join(remaining)))
    return record_argv(kept)


class _RemovalScope(NamedTuple):
    """What a removal takes out, and what stays chosen once it is done."""

    fold: bool
    known: dict[str, list[str]]
    options: list[tuple[str, str | None]]
    chosen_systems: set[str]
    chosen_cores: set[str]
    staying_systems: set[str]
    staying_cores: set[str]
    named_cores: list[str]
    others: dict[tuple[str, str], str]
    wanted: set[str]

    def norm(self, dest: str) -> str:
        """dest as the drive compares it, folded where it folds case."""
        return _drive_key(dest, self.fold)


def _removal_scope(
    plat: str, record: dict, manifest: dict, fold: bool, *,
    systems: Collection[str], cores: Collection[str],
    emulators: Collection[str], files: Collection[str],
) -> _RemovalScope:
    """The scope of a removal of plat's setup from record."""

    setup = record["setups"][plat]
    known = available_choices(list(manifest.get("files") or []),
                              list(manifest.get("omitted_files") or []))
    options = record_options(setup.get("choice") or [])
    chosen_systems = set(systems)
    chosen_cores = designated_cores(manifest, [*cores, *emulators]) if (
        cores or emulators) else set()
    others = {(str(item.get("root") or ""), _drive_key(item["dest"], fold)): name
              for name, other in record["setups"].items() if name != plat
              for item in other.get("files") or []}
    wanted = {_drive_key(dest, fold) for dest in files}
    # What stays chosen once the removal is done, as an install names it:
    # the systems or cores the record named, else every one of the list.
    named_systems = {name.casefold() for name in _choice_names(options, "--system")}
    staying_systems = {name for name in known["systems"] if not named_systems
                       or name.casefold() in named_systems} - chosen_systems
    named_cores = _choice_names(options, "--core")
    staying_cores = (designated_cores(manifest, named_cores) if named_cores
                     else set(known["cores"]) | set(manifest.get("core_names") or {})
                     ) - chosen_cores
    return _RemovalScope(fold, known, options, chosen_systems, chosen_cores,
                         staying_systems, staying_cores, named_cores, others, wanted)


def _removal_takes(scope: _RemovalScope, found: tuple, dest: str) -> bool:
    """Whether the removal's choice reaches a recorded file at dest."""
    _sha1s, item_systems, readers, own = found
    if scope.chosen_systems and not (scope.chosen_systems & set(item_systems) or (
            not item_systems and OTHER_SYSTEMS in scope.chosen_systems)):
        return False
    # The platform's own list keeps its files whatever core is removed.
    if scope.chosen_cores and (own or not readers & scope.chosen_cores):
        return False
    return not (scope.wanted and scope.norm(dest) not in scope.wanted)


def _removal_needed(scope: _RemovalScope, manifest: dict, item: dict, key: tuple[str, str],
                    found: tuple) -> tuple[str, str]:
    """Why a file of ours on disk stays, and what still needs it: ("", "") when it goes."""
    sha1s, item_systems, readers, _own = found
    if item["sha1"] not in sha1s:
        return "not_servable", ""
    if key in scope.others:
        return "shared", display_name(scope.others[key])
    if scope.chosen_systems and set(item_systems) & scope.staying_systems:
        return "shared", ", ".join(system_title(name, manifest) for name in sorted(
            set(item_systems) & scope.staying_systems))
    if scope.chosen_cores and readers and readers & scope.staying_cores:
        return "shared", ", ".join(sorted(readers & scope.staying_cores))
    return "", ""


def _removal_entry(scope: _RemovalScope, manifest: dict, folder: Path, item: dict,
                   found: tuple) -> tuple[str, dict]:
    """Where a picked file of the record goes: ("remove", entry), ("kept",
    entry) or ("gone", item)."""
    root, dest = str(item.get("root") or ""), str(item["dest"])
    entry = {"dest": dest, "root": root, "sha1": item["sha1"], "size": item["size"],
             "systems": found[1]}
    if root not in ("", "data"):
        return "kept", {**entry, "reason": "outside", "what": ""}
    path, why = _below(folder, dest)
    info = None
    if path is not None:
        why, info = _check_ours(path, item)
    if why == "gone":
        return "gone", item
    what = ""
    if not why:
        why, what = _removal_needed(scope, manifest, item, (root, scope.norm(dest)), found)
    if why or path is None or info is None:
        return "kept", {**entry, "reason": why or "unreadable", "what": what}
    return "remove", {**entry, "path": path, "inode": _stamp(info)}


def _removal_choice(scope: _RemovalScope, recorded: list[str], *, files: Collection[str],
                    cores: Collection[str], emulators: Collection[str]) -> list | None:
    """The setup's choice once the removal is done, None when it goes."""
    if files:
        return recorded
    if scope.chosen_systems:
        choice = _choice_without(recorded, "--system", scope.chosen_systems,
                                 sorted(scope.staying_systems | scope.chosen_systems))
        if not _choice_names(record_options(choice), "--system"):
            return None
        return choice
    if scope.chosen_cores and emulators and _choice_names(scope.options, "--emulator"):
        return _choice_without(recorded, "--emulator", emulators, [])
    if scope.chosen_cores:
        left = ([] if scope.named_cores
                else sorted(set(scope.known["cores"]) - scope.chosen_cores))
        return _choice_without(recorded, "--core", scope.chosen_cores | set(cores), left)
    return None


def plan_removal(
    plat: str, folder: Path, record: dict, manifest: dict, *,
    systems: Collection[str] = (), cores: Collection[str] = (),
    emulators: Collection[str] = (), files: Collection[str] = (),
) -> Removal:
    """What removing the chosen part of a setup takes and leaves.

    Only the record of plat in folder says what may go: every file it
    lists, or those of systems, of cores (or of the emulators' cores), or
    the dests in files. A file still needed by what stays (a system or a
    core still chosen, another setup of the same folder) stays, and so do a
    file changed since, a link, anything that is not a regular file, any
    file outside the BIOS folder, and any the list can no longer serve. A
    drive that folds case compares dests folded, as FAT and exFAT open them.
    """
    folder = Path(os.path.abspath(folder))
    setup = record["setups"][plat]
    fold = not keeps_case(folder)
    served = _served(manifest, fold)
    scope = _removal_scope(plat, record, manifest, fold, systems=systems, cores=cores,
                           emulators=emulators, files=files)
    planned_entries: dict[str, list] = {"remove": [], "kept": [], "gone": []}
    picked: set[str] = set()
    planned: set[tuple[str, str]] = set()
    for item in setup.get("files") or []:
        key = (str(item.get("root") or ""), scope.norm(str(item["dest"])))
        found = served.get(key, (set(), [], set(), False))
        if not _removal_takes(scope, found, str(item["dest"])):
            continue
        if key in planned:
            # Two entries the drive opens as one file: planned once.
            continue
        planned.add(key)
        picked.add(key[1])
        where, entry = _removal_entry(scope, manifest, folder, item, found)
        planned_entries[where].append(entry)
    remove, kept, gone = (planned_entries["remove"], planned_entries["kept"],
                          planned_entries["gone"])
    kept += [{"dest": dest, "root": "", "sha1": "", "size": 0, "systems": [],
              "reason": "not_recorded", "what": ""}
             for dest in files if scope.norm(dest) not in picked]
    choice = _removal_choice(scope, list(setup.get("choice") or []), files=files,
                             cores=cores, emulators=emulators)
    lost = sorted({name for entry in remove for name in entry["systems"]})
    return Removal(plat, folder, remove, kept, gone, choice, lost)


def _parent_of(dest: str) -> str:
    """The folder of a dest, "" at the top: dc for dc/dc_boot.bin."""
    parent = PurePosixPath(dest).parent.as_posix()
    return "" if parent == "." else parent


def _misplaced_known(record: dict, manifests: list[dict], fold: bool
                     ) -> tuple[set[str], bool, set[str]]:
    """The places any list of manifests reads or any setup recorded, whether
    a list places files at the top, and the game data dests."""

    known: set[str] = set()
    top_placed = False
    # Game data sits in folders a frontend lists as games: DOOM2.WAD beside
    # doom2.wad is a game entry of its own there, never a copy.
    games = {_drive_key(str(entry.get("dest", "")), fold) for manifest in manifests
             for entry in manifest.get("files") or [] if entry.get("category") == "game_data"}
    for manifest in manifests:
        for root, dest in _served(manifest, fold):
            known.add(dest)
            top_placed = top_placed or (root == "" and "/" not in dest)
        known |= {_drive_key(str(entry.get("dest", "")), fold)
                  for entry in manifest.get("omitted_files") or []}
    known |= {_drive_key(str(item["dest"]), fold) for setup in record["setups"].values()
              for item in setup.get("files") or []}
    return known, top_placed, games


def _misplaced_entries(folder: Path, rel_dir: str) -> list[os.DirEntry[str]]:
    """The entries of a folder the installer placed files in, by name: none
    when it is reached through a link or cannot be read."""
    # The folder reached through no link, as _below reaches a file in it.
    inside, why = _below(folder, f"{rel_dir}/-" if rel_dir else "-")
    if inside is None or why:
        return []
    try:
        return sorted(os.scandir(inside.parent), key=lambda entry: entry.name)
    except OSError:
        return []


def _misplaced_candidate(entry: os.DirEntry[str], sizes: Collection[int]
                         ) -> tuple[Path, os.stat_result, str] | None:
    """The path, lstat and sha1 of a lone regular file of a placed file's size."""
    path = Path(entry.path)
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if (not stat.S_ISREG(info.st_mode) or _is_link(info) or info.st_nlink != 1
            or info.st_size not in sizes):
        return None
    try:
        sha1 = _digest_file(path, ("sha1",))["sha1"]
    except OSError:
        return None
    return path, info, sha1


def plan_misplaced_removal(
    plat: str, folder: Path, record: dict, manifests: list[dict],
) -> Removal:
    """The copies in the wrong place of the BIOS folder that removing takes.

    A copy goes when its bytes are those of a file plat's record says the
    installer placed, read again now at that place, under that file's own
    name, and it sits beside that file (the name in another case), or at
    the top of the folder where the list places files there itself:
    GBA_BIOS.BIN beside gba_bios.bin, dc_boot.bin at the top of RetroArch's
    system folder for dc/dc_boot.bin. A renamed copy stays: a core option,
    a launcher or a frontend entry may name it. Only those folders
    are read, so a games folder (ports/doom on a card whose install folder
    is the roms folder), the save folder and any other tree are never
    looked at. Even there these stay:

    - a place any list of manifests reads or any setup recorded, in any
      root, whole or as the end of the path from a folder down
    - a link, anything but a regular file, a file with a second name, and
      the installer's own file under a spelling the record does not use.
    """
    folder = Path(os.path.abspath(folder))
    fold = not keeps_case(folder)

    known, top_placed, games = _misplaced_known(record, manifests, fold)
    placed: dict[int, list[dict]] = {}
    # The folders read: each one the installer placed a file in, and the
    # top where the list places files there itself.
    folders: dict[str, str] = {"": ""} if top_placed else {}
    for item in record["setups"][plat].get("files") or []:
        if str(item.get("root") or "") == "" and isinstance(item.get("size"), int):
            placed.setdefault(item["size"], []).append(item)
            parent = _parent_of(str(item["dest"]))
            folders.setdefault(_drive_key(parent, fold), parent)
    proven: dict[str, tuple[str, os.stat_result, Path] | None] = {}

    def in_place(item: dict) -> tuple[str, os.stat_result, Path] | None:
        """The placed file's dest, lstat and path when it still holds its bytes."""
        if item["dest"] not in proven:
            path, why = _below(folder, item["dest"])
            info = None
            if path is not None and not why:
                why, info = _check_ours(path, item)
            proven[item["dest"]] = ((item["dest"], info, path)
                                    if not why and info and path is not None else None)
        return proven[item["dest"]]

    def read_somewhere(rel: str) -> bool:
        """Whether rel is a known place, or ends with one that names a
        folder: saves/n3ds/Azahar/sysdata/keys.txt is the save folder's
        n3ds/Azahar/sysdata/keys.txt. A bare name is no such end."""
        parts = _drive_key(rel, fold).split("/")
        return "/".join(parts) in known or any(
            "/".join(parts[index:]) in known for index in range(1, len(parts) - 1))

    remove: list[dict] = []
    for rel_dir in sorted(folders.values()):
        for entry in _misplaced_entries(folder, rel_dir):
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if entry.name in (".nomedia", BACKUP_DIR) or read_somewhere(rel):
                continue
            candidate = _misplaced_candidate(entry, placed)
            if candidate is None:
                continue
            path, info, sha1 = candidate
            found = [(other, hit) for other in placed[info.st_size] if other["sha1"] == sha1
                     for hit in [in_place(other)] if hit is not None]
            if any(_drive_key(str(other["dest"]), fold) in games for other, _hit in found):
                continue
            if any((hit[1].st_dev, hit[1].st_ino) == (info.st_dev, info.st_ino)
                   for _other, hit in found):
                # The installer's own file under a spelling the record does not use.
                continue
            # Under its twin's own name: a copy renamed (SCPH-39001 USA.bin, a
            # game's own title) may be read by that name, a core option or a
            # frontend entry naming it. Beside its twin that name differs in
            # case only, and at the top it is a twin's anywhere below.
            near = [hit for other, hit in found
                    if PurePosixPath(str(other["dest"])).name.casefold()
                    == entry.name.casefold()
                    and ((not rel_dir and top_placed)
                         or _drive_key(_parent_of(str(other["dest"])), fold) == _drive_key(rel_dir, fold))]
            if not near:
                continue
            remove.append({"dest": rel, "root": "", "sha1": sha1, "size": info.st_size,
                           "systems": [], "path": path, "inode": _stamp(info),
                           "placed": near[0][0], "placed_path": near[0][2],
                           "placed_inode": _stamp(near[0][1])})
    remove.sort(key=lambda entry: str(entry["dest"]))
    return Removal(plat, folder, remove, [], [], list(record["setups"][plat].get("choice")
                                                      or []), [])


def _left_by_hand(folder: Path, record: dict, fold: bool) -> list[str]:
    """The files in folder that no setup of its record names: placed by the
    user or another program, never touched, counted in the summary."""
    named = {_drive_key(item["dest"], fold)
             for setup in record["setups"].values() for item in setup.get("files") or []
             if str(item.get("root") or "") in ("", "data")}
    found = []
    for base, dirs, names in os.walk(folder, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != BACKUP_DIR)
        for name in sorted(names):
            rel = (Path(base) / name).relative_to(folder).as_posix()
            if _drive_key(rel, fold) not in named and name != ".nomedia":
                found.append(rel)
    return found


def _kept_words(kept: list[dict]) -> str:
    """Why files stay, counted by reason: 2 still needed, 1 changed since."""
    counts: dict[str, int] = {}
    for item in kept:
        counts[item["reason"]] = counts.get(item["reason"], 0) + 1
    order = list(REMOVAL_REASONS)
    return ", ".join(f"{count} {REMOVAL_REASONS[reason]}" for reason, count in sorted(
        counts.items(), key=lambda pair: (-pair[1], order.index(pair[0]))))


def kept_line(item: dict) -> str:
    """One file a removal leaves, and why."""
    why = REMOVAL_REASONS[item["reason"]]
    if item["reason"] == "shared" and item["what"]:
        why += f" by {item['what']}"
    return f"{item['dest']}: {why}"


def _stamp(info: os.stat_result) -> tuple[int, int, int, int]:
    """What tells a file from itself edited: device, inode, size, mtime."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _other_setup_list(name: str) -> tuple[dict | None, str]:
    """The list of another setup of the folder, fetched from the address
    whatever list this run was given, or None and why it is not at hand."""
    if offline_requested():
        return None, "this run is offline: run it again with the internet"
    try:
        return _validate_manifest(_fetch_json(MANIFEST_URL.format(platform=name),
                                              MAX_MANIFEST_BYTES, "file list"), name), ""
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, "no such list exists, as for a setup this installer no longer serves"
        return None, f"the server answered HTTP {exc.code}: run it again later"
    except (ValueError, OSError):
        return None, "it could not be fetched: run it again with the internet"


def _still_in_place(entry: dict) -> bool:
    """For a misplaced copy, whether the file it duplicates is still the one
    the plan read at its place: a copy is deleted only while that one holds
    its bytes. True for any other entry."""
    placed = entry.get("placed_path")
    if placed is None:
        return True
    try:
        info = os.lstat(placed)
        return (stat.S_ISREG(info.st_mode) and not _is_link(info)
                and _stamp(info) == entry["placed_inode"]
                and _digest_file(placed, ("sha1",))["sha1"] == entry["sha1"])
    except OSError:
        return False


class _ChangedSincePlan(OSError):
    """The file is not the one the plan read: it stays."""


def remove_files(removal: Removal, setup: dict, backup: bool
                 ) -> tuple[list[dict], list[dict], Path | None]:
    """Delete each file of the plan, or with backup move it into a new
    backup folder: (removed, failed {dest, reason, changed}, the backup
    folder). Each file is read again just before, and hashed again: one
    edited in place during the question, swapped, or turned into a link
    stays, as changed since the plan."""
    removed, failed = [], []
    run: Path | None = None
    under: Path | None = None
    for entry in removal.remove:
        path = entry["path"]
        kept: Path | None = None
        try:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or _is_link(info)
                    or _stamp(info) != entry["inode"]
                    or _digest_file(path, ("sha1",))["sha1"] != entry["sha1"]
                    or not _still_in_place(entry)):
                raise _ChangedSincePlan(errno.ESTALE, CHANGED_SINCE_PLAN)
            if backup:
                if run is None or under is None:
                    run, under = KEPT.place(removal.folder, create=True)
                    _write_removed_note(run, removal, setup)
                kept = under / Path(*PurePosixPath(entry["dest"]).parts)
                kept.parent.mkdir(parents=True, exist_ok=True)
                _move_aside(path, kept)
            else:
                _clear_read_only(path)
                path.unlink()
        except OSError as exc:
            reason = exc.strerror or str(exc)
            failed.append({"dest": entry["dest"], "reason": reason,
                           "changed": isinstance(exc, _ChangedSincePlan)})
            EVENTS.emit("removed", platform=removal.plat, dest=entry["dest"],
                        size=entry["size"], ok=False, reason=reason, moved_to="")
            continue
        removed.append(entry)
        EVENTS.emit("removed", platform=removal.plat, dest=entry["dest"],
                    size=entry["size"], ok=True, reason="",
                    moved_to="" if kept is None else str(spelled(kept)))
    return removed, failed, run


def _write_removed_note(run: Path, removal: Removal, setup: dict) -> None:
    """What --restore needs to give the moved files back to their setup:
    the record's entries of every file the plan moves, the choice before."""
    dests = {entry["dest"] for entry in removal.remove}
    note = {"platform": removal.plat, "folder": str(removal.folder),
            "choice": list(setup.get("choice") or []),
            "files": [item for item in setup.get("files") or [] if item["dest"] in dests]}
    (run / REMOVED_NOTE).write_text(json.dumps(note, sort_keys=True), encoding="utf-8")


def _record_after_removal(removal: Removal, removed: list[dict]) -> str:
    """The setup's record without the files removed and those gone, with the
    choice left: the setup goes once it holds no file."""
    taken = {(entry["root"], entry["dest"]) for entry in removed} | {
        (str(item.get("root") or ""), item["dest"]) for item in removal.gone}

    def change(setup: dict | None) -> dict | None:
        if setup is None:
            return None
        files = [item for item in setup.get("files") or []
                 if (str(item.get("root") or ""), item["dest"]) not in taken]
        if not files:
            return None
        # A file that stayed (it failed, changed, or something still needs
        # it) keeps its entry. With nothing left chosen, the choice stays the
        # one recorded: no choice would read as the whole list.
        choice = setup.get("choice") if removal.choice is None else removal.choice
        return {**setup, "written": _record_now(), "choice": list(choice or []),
                "files": files}

    return _update_record(removal.folder, removal.plat, change)


def _named_files(values: Iterable[Path], folder: Path) -> list[str] | None:
    """The --file values as dests below folder, None for one outside it."""
    files = []
    for value in values:
        given = Path(os.path.expanduser(str(value)))
        if given.is_absolute():
            try:
                given = Path(os.path.abspath(given)).relative_to(folder)
            except ValueError:
                print(f"Error: {value} is not inside {shown_path(folder)}: --file names a "
                      "file of the BIOS folder.", file=sys.stderr)
                return None
        files.append(PurePosixPath(*given.parts).as_posix())
    return files


def _removal_refused(plat: str, folder: Path, message: str, backup: bool) -> int:
    """A removal that touches nothing: the reason said and sent, exit 2."""
    print(message, file=sys.stderr)
    EVENTS.emit("removal_plan", platform=plat, folder=str(folder), files=0, bytes=0,
                systems=[], dests=[], kept=[], gone=0, backup=backup,
                message=message)
    return 2


def _misplaced_others(plat: str, folder: Path, dropped: tuple, setups: dict
                      ) -> tuple[list[dict], str]:
    """The lists of the other setups of folder, or why nothing is removed."""
    # Every setup of the folder protects the places its list reads: one
    # whose list or record entry cannot be read leaves nothing to tell
    # its files from copies, so nothing is removed.
    message = ""
    if dropped:
        message = (f"Nothing was removed from {shown_path(folder)}: the install "
                   f"record's entry for {display_name(dropped[0])}, which shares "
                   "the folder, cannot be used, so its files would not be told from "
                   f"copies. Install {display_name(dropped[0])} again, with the "
                   "choice it was installed with, to rewrite it.")
    others = []
    for name in setups:
        if name == plat or message:
            continue
        other, why = _other_setup_list(name)
        if other is None:
            message = (f"Nothing was removed from {shown_path(folder)}: the file list "
                       f"of {display_name(name)}, which shares the folder, is needed "
                       f"to tell its files from copies, and {why}.")
        else:
            others.append(other)
    return others, message


def _removal_headline(removal: Removal, where: str, size: int, *, misplaced: bool,
                      backup: bool) -> str:
    """The plan's first line: what goes from where, and the space freed."""
    if not removal.remove:
        return (f"No copy in the wrong place of {where}." if misplaced
                else f"Nothing to remove from {where}.")
    if misplaced:
        return (f"Remove {_plural(len(removal.remove), 'copy')} in the wrong "
                f"place of {where}, {format_size(size)} freed. Each is a file "
                "RetroBIOS placed where the cores read it.")
    if backup:
        return (f"Move {_plural(len(removal.remove), 'file')} "
                f"({format_size(size)}) from {where} to a backup.")
    return (f"Remove {_plural(len(removal.remove), 'file')} from {where}, "
            f"{format_size(size)} freed.")


def _print_removal_plan(args: argparse.Namespace, removal: Removal, by_hand: list[str],
                        misplaced: bool) -> None:
    """The files a removal takes and those it leaves, as the plan lists them."""
    # The copies are the user's: they are named before any question.
    listed = (removal.remove if args.dry_run or args.verbose
              else removal.remove[:REMOVAL_KEPT_SHOWN] if misplaced else [])
    for entry in listed:
        print(f"  {entry['dest']}" + (f" (in place: {entry['placed']})"
                                      if entry.get("placed") else ""))
    if len(listed) < len(removal.remove) and misplaced:
        print(f"  and {len(removal.remove) - len(listed)} more (--dry-run lists them)")
    if removal.kept:
        print(f"{agree(len(removal.kept), 'file stays', 'files stay')}: "
              f"{_kept_words(removal.kept)}.")
        shown = removal.kept if args.verbose else removal.kept[:REMOVAL_KEPT_SHOWN]
        for item in shown:
            print(f"  {kept_line(item)}")
        if len(shown) < len(removal.kept):
            print(f"  and {len(removal.kept) - len(shown)} more (--verbose lists them)")
    if by_hand:
        print(f"{agree(len(by_hand), 'other file stays', 'other files stay')}, not "
              "installed by RetroBIOS.")
        if args.verbose:
            for rel in by_hand:
                print(f"  {rel}")


def _removal_answer(args: argparse.Namespace) -> int | None:
    """The exit code when the plan stops before removing, None to go on."""
    if args.dry_run:
        print("Nothing was removed (--dry-run).")
        return 0
    if not args.yes:
        if args.no_input or not sys.stdin.isatty():
            print("Error: removing files needs a yes: add --yes to remove them without "
                  "a question, or --dry-run to list them.", file=sys.stderr)
            return 2
        question = ("Move them to a backup? [y/N] " if args.backup
                    else "Remove them for good? [y/N] ")
        if not _answer_yes(question):
            print("Nothing was removed.")
            return QUIT_CODE
    return None


def _report_removal(removed: list[dict], failed: list[dict], run: Path | None, *,
                    misplaced: bool, problem: str) -> int:
    """What a removal did, said once it is done: 0 done, 1 a file or the record failed."""
    freed = sum(entry["size"] for entry in removed)
    if run is not None:
        print(f"Moved {_plural(len(removed), 'file')} ({format_size(freed)}) to "
              f"{shown_path(run)}.")
        print(f"To put them back: {_INVOCATION.launcher()} --restore "
              f"{_INVOCATION.word(str(spelled(run)))}")
        EVENTS.emit("backup", folder=str(spelled(run)), date=_backup_date(run),
                    files=len(removed), bytes=freed, source="remove", status="made",
                    message=f"Moved {_plural(len(removed), 'file')} here.")
    elif removed:
        print(f"Removed {_plural(len(removed), 'copy' if misplaced else 'file')}, "
              f"{format_size(freed)} freed.")
    changed = [item for item in failed if item["changed"]]
    if changed:
        print(f"{agree(len(changed), 'file stays', 'files stay')}: "
              f"{len(changed)} {CHANGED_SINCE_PLAN}.")
        for item in changed:
            print(f"  {item['dest']}: {CHANGED_SINCE_PLAN}")
    failed = [item for item in failed if not item["changed"]]
    for item in failed:
        print(f"  failed: {item['dest']} ({item['reason']})", file=sys.stderr)
    if problem:
        print(f"The install record could not be updated ({problem}).", file=sys.stderr)
    return 1 if failed or problem else 0


def run_removal(args: argparse.Namespace) -> int:
    """--remove: the plan, one confirmation, then each file deleted (or
    moved with --backup), and the record made to say so. 0 done, 1 a file
    or the record failed, 2 nothing done."""
    plat, folder = _action_setup(args)
    if not os.path.isdir(folder):
        # An unmounted card looks like every file gone: nothing is touched.
        message = (f"Nothing was removed: {shown_path(folder)} is not there (a card "
                   "not mounted?).")
        return _removal_refused(plat, folder, message, bool(args.backup))
    read = load_record(folder)
    setup, _path, problem = setup_record(plat, folder)
    if setup is None or read.data is None:
        why = problem or (f"its install record holds nothing for {display_name(plat)}"
                          if read.data is not None else
                          "no install record is beside it, so no file is known to be "
                          "the installer's")
        message = f"Nothing was removed from {shown_path(folder)}: {why}."
        return _removal_refused(plat, folder, message, bool(args.backup))
    manifest = fetch_manifest(plat)
    every = list(manifest.get("files") or [])
    omitted = list(manifest.get("omitted_files") or [])
    known = available_choices(every, omitted)
    try:
        systems = resolve_choices(args.system, known["systems"], "system") \
            if args.system else []
        cores = resolve_choices(args.core, known["cores"], "core") if args.core else []
        emulators = resolve_choices(args.emulator, sorted(emulator_names(
            manifest, every, omitted)), "emulator") if args.emulator else []
    except ValueError as exc:
        refuse_name(plat, f"Error: {plat}: {exc}")
    files = _named_files(args.file or [], folder)
    if files is None:
        return 2
    misplaced = bool(getattr(args, "misplaced", False))
    if misplaced:
        others, message = _misplaced_others(plat, folder, read.dropped, read.data["setups"])
        if message:
            return _removal_refused(plat, folder, message, False)
        removal = plan_misplaced_removal(plat, folder, read.data, [manifest, *others])
    else:
        removal = plan_removal(plat, folder, read.data, manifest, systems=systems,
                               cores=cores, emulators=emulators, files=files)
    size = sum(entry["size"] for entry in removal.remove)
    whole = not (systems or cores or emulators or files or misplaced)
    by_hand = _left_by_hand(folder, read.data, not keeps_case(folder)) if whole else []
    where = f"{shown_path(folder)} for {display_name(plat, manifest)}"
    headline = _removal_headline(removal, where, size, misplaced=misplaced,
                                 backup=bool(args.backup))
    EVENTS.emit("removal_plan", platform=plat, folder=str(folder), files=len(removal.remove),
                bytes=size, systems=removal.systems,
                dests=[entry["dest"] for entry in removal.remove],
                kept=[{"dest": item["dest"], "reason": item["reason"]}
                      for item in removal.kept],
                gone=len(removal.gone), backup=bool(args.backup), message=headline)
    print(headline)
    _print_removal_plan(args, removal, by_hand, misplaced)
    if not removal.remove:
        # The record keeps what it says until a removal is confirmed.
        return 2
    stop = _removal_answer(args)
    if stop is not None:
        return stop
    KEPT.reset()
    removed, failed, run = remove_files(removal, setup, bool(args.backup))
    # The copies were never the record's: it stays as it is.
    problem = "" if misplaced else _record_after_removal(removal, removed)
    return _report_removal(removed, failed, run, misplaced=misplaced, problem=problem)


# The files a removal leaves named one by one by default: past this, a
# count and --verbose.
REMOVAL_KEPT_SHOWN = 10


def _backup_date(run: Path) -> str:
    """When a run folder was made, read from its name: 2026-11-03 12:00:00."""
    match = re.match(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)", run.name)
    if not match:
        return ""
    year, month, day, hour, minute, second = match.groups()
    return f"{year}-{month}-{day} {hour}:{minute}:{second}"


def backup_words(date: str) -> str:
    """A backup's date as a list says it: 3 Nov 12:00."""
    try:
        when = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return date or "unknown date"
    return f"{day_words(when)} {when.hour:02d}:{when.minute:02d}"


def list_backups(folder: Path) -> list[dict]:
    """The backups of a BIOS folder, newest first: {folder, date, files,
    bytes, source}, source remove for a removal's and install for the files
    an install replaced. Only dated folders holding the marker count."""
    folder = Path(os.path.abspath(folder))
    found = []
    for holder, prefix in KeptFiles._holders(folder):
        try:
            if not stat.S_ISDIR(os.lstat(holder).st_mode):
                continue
            runs = sorted(holder.iterdir())
        except OSError:
            continue
        for run in runs:
            if not _is_backup_run(run):
                continue
            under = run / prefix if prefix else run
            files = [path for path in _backup_files(run) if under in path.parents]
            if files:
                found.append({"folder": run, "date": _backup_date(run), "files": len(files),
                              "bytes": sum(path.stat().st_size for path in files),
                              "source": "remove" if _backup_note(run) is not None
                              else "install"})
    return sorted(found, key=lambda item: item["folder"].name, reverse=True)


def run_backups(args: argparse.Namespace) -> int:
    """--backups: the backups of the BIOS folder, newest first."""
    folder = _action_folder(args)
    backups = list_backups(folder)
    if not backups:
        print(f"No backup of {shown_path(folder)}.")
        return 0
    print(f"Backups of {shown_path(folder)}, newest first:")
    for item in backups:
        made = "removed" if item["source"] == "remove" else "replaced by an install"
        print(f"  {backup_words(item['date'])}  {_plural(item['files'], 'file')}, "
              f"{format_size(item['bytes'])}, {made}")
        print(f"    {shown_path(item['folder'])}")
        EVENTS.emit("backup", folder=str(spelled(item["folder"])), date=item["date"],
                    files=item["files"], bytes=item["bytes"], source=item["source"],
                    status="listed", message="")
    print(f"To put one back: {_INVOCATION.launcher()} --restore FOLDER")
    return 0


def run_delete_backup(args: argparse.Namespace) -> int:
    """--delete-backup: one backup folder deleted after one confirmation.
    0 done, 1 a file failed, 2 refused or declined."""
    run = Path(os.path.abspath(os.path.expanduser(str(args.delete_backup))))
    if not _is_backup_run(run):
        print(f"Error: {run} is not a folder the installer kept files in.", file=sys.stderr)
        print("  Name one of the dated folders --backups lists.", file=sys.stderr)
        return 2
    files = _backup_files(run)
    size = sum(path.stat().st_size for path in files)
    date = _backup_date(run)
    source = "remove" if _backup_note(run) is not None else "install"
    print(f"Delete the backup of {backup_words(date)}: {_plural(len(files), 'file')}, "
          f"{format_size(size)}.")
    if args.dry_run:
        print("Nothing was deleted (--dry-run).")
        return 0
    if not args.yes:
        if args.no_input or not sys.stdin.isatty():
            print("Error: deleting a backup needs a yes: add --yes to delete it without "
                  "a question.", file=sys.stderr)
            return 2
        if not _answer_yes("Delete it for good? [y/N] "):
            print("Nothing was deleted.")
            return QUIT_CODE
    failed = 0
    # Bottom up, never through a link: a link goes, not what it names. A
    # junction is removed as a folder, which leaves its target alone.
    for path, info in _tree(run):
        try:
            if stat.S_ISDIR(info.st_mode):
                path.rmdir()
            else:
                _clear_read_only(path)
                path.unlink()
        except OSError as exc:
            failed += 1
            print(f"  failed: {path} ({exc.strerror or exc})", file=sys.stderr)
    try:
        run.rmdir()
    except OSError as exc:
        failed += 1
        print(f"  failed: {run} ({exc.strerror or exc})", file=sys.stderr)
    EVENTS.emit("backup", folder=str(spelled(run)), date=date, files=len(files), bytes=size,
                source=source, status="not_deleted" if failed else "deleted",
                message=f"{_plural(failed, 'file')} could not be deleted." if failed else "")
    if failed:
        return 1
    print(f"Deleted, {format_size(size)} freed.")
    return 0


def _action_folder(args: argparse.Namespace) -> Path:
    """The BIOS folder a listing of backups is for: --dest, else the one
    setup found here."""
    if args.dest and not args.platform:
        return Path(os.path.abspath(os.path.expanduser(str(args.dest))))
    return _action_setup(args)[1]


def _action_setup(args: argparse.Namespace) -> tuple[str, Path]:
    """The setup and BIOS folder a removal is for: --platform and --dest,
    the one setup a record names or the search here finds, never a guess.
    A choice left open exits 2, naming the option that settles it."""
    named = args.platform or ""
    plat = normalize_platform(args.platform, say=False) if args.platform else ""
    if args.dest:
        dest = Path(args.dest)
        if plat:
            plat, dest = card_dest(named, plat, dest)
        folder = Path(os.path.abspath(os.path.expanduser(str(dest))))
        if plat:
            return plat, folder
        setups = sorted((load_record(folder).data or {}).get("setups") or {})
        if len(setups) == 1:
            return setups[0], folder
        print(f"Error: name the setup of {shown_path(folder)} with --platform"
              + (f": {', '.join(setups)}." if setups else "."), file=sys.stderr)
        sys.exit(2)
    found = [(name, path) for name, path in detect_platforms(detect_os())
             if not plat or name == plat]
    if len(found) == 1:
        return found[0][0], Path(os.path.abspath(found[0][1]))
    if not found:
        print("Error: no setup found here: name its BIOS folder with --dest"
              + ("." if plat else " and its setup with --platform."), file=sys.stderr)
    else:
        print("Error: several setups found here: name one with --platform and --dest.",
              file=sys.stderr)
        for name, path in found:
            print(f"  --platform {name} --dest {_INVOCATION.word(str(path))}",
                  file=sys.stderr)
    sys.exit(2)
