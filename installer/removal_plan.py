"""Which installed files a removal takes, which it keeps and why."""

from __future__ import annotations

import os
import stat
from collections.abc import Collection, Mapping
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.choices import available_choices, system_ids
from installer.filesystems import keeps_case
from installer.host_fs import _is_link
from installer.restore import _below, _check_ours
from installer.install_record import record_argv, record_options
from installer.local_check import _digest_file
from installer.manifest import OTHER_SYSTEMS, entry_copies
from installer.narrowing import designated_cores
from installer.platforms import display_name, entry_systems, system_title
from installer.safe_replace import BACKUP_DIR


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


def _recorded_served(setup: dict, manifest: dict, fold: bool
                     ) -> list[tuple[dict, tuple[str, str], tuple]]:
    """Each file a setup's record holds, with its place as the drive opens
    it and what the list serves there, by the one rule removal reads."""
    served = _served(manifest, fold)
    places = [(item, (str(item.get("root") or ""), _drive_key(str(item["dest"]), fold)))
              for item in setup.get("files") or []]
    return [(item, place, served.get(place, (set(), [], set(), False)))
            for item, place in places]


def recorded_systems(setup: dict, manifest: dict, folder: Path) -> list[tuple[dict, list[str]]]:
    """Each file a setup's record holds, with the list's systems of it: a
    drive that folds case finds a recased dest under the list's spelling."""
    return [(item, list(found[1]))
            for item, _place, found in _recorded_served(setup, manifest, not keeps_case(folder))]


def _choice_names(options: list[tuple[str, str | None]], flag: str) -> list[str]:
    return [name.strip() for option, value in options if option == flag
            for name in (value or "").split(",") if name.strip()]


def _choice_without(choice: list[str], flag: str, names: Collection[str],
                    left: list[str], ids: Mapping[str, str] | None = None) -> list[str]:
    """A recorded choice once names of flag are taken out: those it named
    go, and a choice that named none gets the names left. A flag left with
    no name is dropped. ids gives a recorded name the id it stands for."""
    options = [option for option in record_options(choice) if option[0] != "--all-files"]
    gone = {name.casefold() for name in names}
    same = ids or {}
    remaining = [name for name in (_choice_names(options, flag) or left)
                 if same.get(name, name).casefold() not in gone]
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
    system_ids: dict[str, str]

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
    recorded_systems = _choice_names(options, "--system")
    ids = system_ids(recorded_systems, manifest, list(manifest.get("files") or []),
                     list(manifest.get("omitted_files") or []))
    named_systems = {ids.get(name, name).casefold() for name in recorded_systems}
    staying_systems = {name for name in known["systems"] if not named_systems
                       or name.casefold() in named_systems} - chosen_systems
    named_cores = _choice_names(options, "--core")
    staying_cores = (designated_cores(manifest, named_cores) if named_cores
                     else set(known["cores"]) | set(manifest.get("core_names") or {})
                     ) - chosen_cores
    return _RemovalScope(fold, known, options, chosen_systems, chosen_cores,
                         staying_systems, staying_cores, named_cores, others, wanted, ids)


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
                                 sorted(scope.staying_systems | scope.chosen_systems),
                                 scope.system_ids)
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
    scope = _removal_scope(plat, record, manifest, fold, systems=systems, cores=cores,
                           emulators=emulators, files=files)
    planned_entries: dict[str, list] = {"remove": [], "kept": [], "gone": []}
    picked: set[str] = set()
    planned: set[tuple[str, str]] = set()
    for item, key, found in _recorded_served(setup, manifest, fold):
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


def _stamp(info: os.stat_result) -> tuple[int, int, int, int]:
    """What tells a file from itself edited: device, inode, size, mtime."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
