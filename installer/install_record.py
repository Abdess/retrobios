"""The install record a run leaves beside the BIOS folder, and --restore."""
from __future__ import annotations

import argparse
import datetime
import errno
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.arguments import build_parser
from installer.events import EVENTS
from installer.host_fs import _clear_read_only, _is_dir, _is_link, _replace_with_copy
from installer.invocation import _INVOCATION, _VALUED_OPTIONS, _command_rank, installer_id
from installer.local_check import _digest_file
from installer.offline import LOCAL
from installer.paths import _safe_relative_path
from installer.platforms import system_title
from installer.safe_replace import (
    BACKUP_DIR,
    KEPT,
    REMOVED_NOTE,
    KeptFiles,
    _NotKept,
    _backup_files,
    _check_holder,
    _is_backup_run,
)
from installer.text import _plural, format_size

# The install record: what the runs placed in a BIOS folder, each file with
# its hash, and the choice they made, which the next run's plan takes. It
# lives in the backup holder beside the folder, never loose in it, for the
# reason the backups do. On a card it travels with the card.
RECORD_SCHEMA = 1
RECORD_SUFFIX = ".install.json"
# The options a record keeps as the choice: what the list was narrowed to.
RECORD_CHOICE = ("--system", "--core", "--emulator", "--region", "--for-games",
                 "--required-only", "--all-files", "--target", "--every-board",
                 "--no-game-data", "--installed-cores", "--declared-only")
# The record's choice options that narrow the list, --all-files aside.
RECORD_NARROWING = tuple(flag for flag in RECORD_CHOICE if flag != "--all-files")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
           "Dec")
# The records already said unreadable in this run, said once each.
_RECORD_SAID: set[str] = set()
# Per platform, the record whose choice this run took (apply_record).
_RECORD_TAKEN: dict[str, dict] = {}


def record_paths(folder: Path) -> list[Path]:
    """Where the record of folder is looked for, in order: the holder beside
    it, then the one inside it that a folder with no writable parent gets."""
    folder = Path(os.path.abspath(folder))
    name = f"{folder.name or 'folder'}{RECORD_SUFFIX}"
    return [holder / name for holder, _prefix in KeptFiles._holders(folder)]


# Read whole, never past this: a record of every file of the longest list
# holds 1.6 MB per setup, and a few setups share one folder.
MAX_RECORD_BYTES = 16 * 1024 * 1024
# The choice options that take a value. --for-games takes one or none.
_RECORD_VALUED = ("--system", "--core", "--emulator", "--region", "--target")


def games_folder_kept(value: str, folder: Path) -> bool:
    """Whether a recorded --for-games folder may be read again: an absolute
    path under the folder that holds the BIOS folder (a card's root, the
    setup's own folder), never another drive or a network share."""
    if not value or value.startswith(("\\\\", "//")) or not os.path.isabs(value):
        return False
    parent = os.path.normcase(os.path.normpath(os.path.dirname(os.path.abspath(folder))))
    games = os.path.normcase(os.path.normpath(value))
    try:
        return os.path.commonpath([parent, games]) == parent
    except ValueError:
        # Two drives on Windows: no common path.
        return False


def valid_choice(choice: list[str], folder: Path) -> bool:
    """Whether every word of a recorded choice is an option of the choice or
    the value right after one: a record naming --dest, --from or --manifest
    would put them in the commands printed for the user to copy."""
    words = list(choice)
    while words:
        flag = words.pop(0)
        if flag not in RECORD_CHOICE:
            return False
        if flag in _RECORD_VALUED:
            if not words or words[0].startswith("-") or not words[0].strip():
                return False
            value = words.pop(0)
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                return False
        elif flag == "--for-games" and words and not words[0].startswith("--"):
            if not games_folder_kept(words.pop(0), folder):
                return False
    return True


def _valid_setup(setup: object, folder: Path) -> bool:
    if not isinstance(setup, dict):
        return False
    choice, files = setup.get("choice"), setup.get("files")
    return (isinstance(setup.get("written"), str) and isinstance(choice, list)
            and all(isinstance(word, str) for word in choice) and valid_choice(choice, folder)
            and isinstance(files, list)
            and all(isinstance(item, dict) and isinstance(item.get("dest"), str)
                    and isinstance(item.get("sha1"), str) and isinstance(item.get("size"), int)
                    for item in files))


class RecordRead(NamedTuple):
    """What reading a record found: the record with its usable setups, where
    it is, why it cannot be used, whether a newer installer wrote it, and
    the setups it holds that cannot be used."""

    data: dict | None
    path: Path | None
    problem: str
    newer: bool = False
    dropped: tuple = ()


def _read_record_bytes(path: Path) -> bytes:
    """The bytes of a record that is a regular file of a record's size. A
    FIFO, a device or a folder is refused before it is read: reading one
    waited forever."""
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(errno.EINVAL, "it is not a file")
    if info.st_size > MAX_RECORD_BYTES:
        raise OSError(errno.EFBIG, "it is larger than any record")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    handle = os.open(path, flags)
    try:
        # Opened without waiting, then checked again: what is open now is
        # what is read, whatever took the name since the stat.
        if not stat.S_ISREG(os.fstat(handle).st_mode):
            raise OSError(errno.EINVAL, "it is not a file")
        chunks, left = [], MAX_RECORD_BYTES + 1
        while left > 0:
            chunk = os.read(handle, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
    finally:
        os.close(handle)
    data = b"".join(chunks)
    if len(data) > MAX_RECORD_BYTES:
        raise OSError(errno.EFBIG, "it is larger than any record")
    return data


def load_record(folder: Path) -> RecordRead:
    """The record of folder, read once (RecordRead)."""
    for path in record_paths(folder):
        try:
            text = _read_record_bytes(path).decode("utf-8")
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, UnicodeDecodeError) as exc:
            reason = getattr(exc, "strerror", None) or str(exc)
            return RecordRead(None, path, f"The install record {path} cannot be read ({reason})")
        try:
            data = json.loads(text)
        except ValueError:
            return RecordRead(None, path, f"The install record {path} is damaged")
        schema = data.get("schema") if isinstance(data, dict) else None
        if isinstance(schema, int) and not isinstance(schema, bool) and schema > RECORD_SCHEMA:
            # Its shape is the newer installer's: kept for it, never read.
            return RecordRead(None, path, f"The install record {path} was written by a newer "
                                          "installer", newer=True)
        if (not isinstance(data, dict) or not isinstance(data.get("setups"), dict)
                or not isinstance(data.get("folder"), str) or schema != RECORD_SCHEMA):
            return RecordRead(None, path, f"The install record {path} is damaged")
        setups = {name: setup for name, setup in data["setups"].items()
                  if _valid_setup(setup, folder)}
        dropped = tuple(sorted(str(name) for name in data["setups"] if name not in setups))
        return RecordRead({**data, "setups": setups}, path, "", dropped=dropped)
    return RecordRead(None, None, "")


def read_record(folder: Path) -> tuple[dict | None, Path | None, str]:
    """(the record of folder, where it is, why it cannot be used). Neither a
    record nor a reason where there is none."""
    found = load_record(folder)
    return found.data, found.path, found.problem


def setup_record(plat: str, folder: Path) -> tuple[dict | None, Path | None, str]:
    """The record of plat in folder, where it is, and why it cannot be used.
    A record written for a folder of another name (copied, or renamed with
    it) is not this folder's. A setup of it that cannot be used (an option
    the choice has no place for, a games folder elsewhere) is damaged, the
    others still read."""
    found = load_record(folder)
    if found.data is None:
        return None, found.path, found.problem
    written_for = str(found.data.get("folder") or "")
    if Path(written_for).name != Path(os.path.abspath(folder)).name:
        return None, found.path, ""
    if plat in found.dropped:
        return None, found.path, f"The install record {found.path} is damaged"
    return found.data["setups"].get(plat), found.path, ""


def record_day(setup: dict) -> str:
    """The day a record was written, as the plan says it: 3 Nov."""
    try:
        when = datetime.datetime.fromisoformat(setup["written"].replace("Z", "+00:00"))
        # Year 1 or 9999 cannot be moved to local time: an unknown day.
        local = when.astimezone()
    except (KeyError, TypeError, AttributeError, ValueError, OverflowError, OSError):
        return ""
    day = f"{local.day} {_MONTHS[local.month - 1]}"
    return day if local.year == datetime.datetime.now().year else f"{day} {local.year}"


def record_options(argv: list[str]) -> list[tuple[str, str | None]]:
    """A record's choice as (option, value) pairs."""
    options: list[tuple[str, str | None]] = []
    words = list(argv)
    while words:
        flag = words.pop(0)
        valued = flag in _VALUED_OPTIONS or (
            flag == "--for-games" and words and not words[0].startswith("--"))
        options.append((flag, words.pop(0) if valued and words else None))
    return options


def record_argv(options: Iterable[tuple[str, str | None]]) -> list[str]:
    """The choice options a record keeps, as words, in the command's order."""
    kept = sorted((option for option in options if option[0] in RECORD_CHOICE),
                  key=_command_rank)
    if not any(flag in RECORD_NARROWING for flag, _value in kept):
        # The whole list, chosen as such: a card that holds games later
        # still gets what was installed before.
        kept = [("--all-files", None)]
    return [word for flag, value in kept for word in ([flag] if value is None else [flag, value])]


def record_says(setup: dict, manifest: dict | None = None) -> str:
    """The recorded choice in words: Game Boy Advance, the games, the
    options chosen, every file."""
    options = record_options(setup.get("choice") or [])
    systems = [system_title(value, manifest) for flag, value in options
               if flag == "--system" and value]
    if systems:
        shown = ", ".join(systems[:3])
        return shown + (f" and {len(systems) - 3} more" if len(systems) > 3 else "")
    if any(flag == "--for-games" for flag, _value in options):
        return "the games"
    if any(flag in RECORD_NARROWING for flag, _value in options):
        return "the options chosen"
    return "every file"


def record_changes(setup: dict, entries: Iterable[dict]) -> tuple[int, int]:
    """Of the files a choice keeps now, those the list changed since the
    record and those it did not hold then: (updated, new)."""
    recorded = {(str(item.get("root") or ""), item["dest"]): item["sha1"]
                for item in setup.get("files") or []}
    updated = new = 0
    for entry in entries:
        sha1 = recorded.get((str(entry.get("root") or ""), str(entry.get("dest"))))
        if sha1 is None:
            new += 1
        elif entry.get("sha1") and sha1 != entry.get("sha1"):
            updated += 1
    return updated, new


def record_file(entry: dict, origin: str, root: str = "") -> dict:
    """One file a run wrote, as the record keeps it."""
    return {"dest": str(entry["dest"]), "root": root or str(entry.get("root") or ""),
            "sha1": str(entry.get("sha1") or ""), "size": int(entry.get("size") or 0),
            "from": origin}


def write_record(
    folder: Path, plat: str, manifest: dict, choice: list[str], files: list[dict],
) -> tuple[Path | None, dict, str]:
    """Write what this run placed in folder for plat, merged with what
    earlier runs placed: (where, the record of plat, why it was not
    written). A record that cannot be read is replaced."""
    folder = Path(os.path.abspath(folder))
    read = load_record(folder)
    if read.newer:
        # What a newer installer wrote is kept for it: rewritten here, the
        # other setups' history would go.
        if str(read.path) not in _RECORD_SAID:
            _RECORD_SAID.add(str(read.path))
            print(f"  {read.problem}: left as it is.")
        return None, {"files": [], "written": ""}, f"{read.problem}: left as it is"
    found = read.path
    # A record that cannot be read is replaced, said when it was read. One
    # with a setup that cannot be used keeps its others.
    data = read.data if read.data is not None else {"setups": {}}
    previous = data["setups"].get(plat) or {}
    merged = {(str(item.get("root") or ""), item["dest"]): item
              for item in previous.get("files") or []}
    for item in files:
        merged[(item["root"], item["dest"])] = item
    setup = {
        "written": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "list": {"version": manifest.get("version"), "generated": manifest.get("generated")},
        "choice": choice,
        "files": [merged[key] for key in sorted(merged)],
    }
    data = {"schema": RECORD_SCHEMA, "installer": installer_id(), "folder": str(folder),
            "setups": {**data["setups"], plat: setup}}
    where, failure = _save_record(folder, data, found)
    if where is None:
        return None, setup, f"The install record could not be written ({failure})"
    return where, setup, ""


def _save_record(folder: Path, data: dict, found: Path | None) -> tuple[Path | None, str]:
    """Write a record's data where it was read, else where it goes: (where,
    why nothing could be written)."""
    text = json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n"
    places = record_paths(folder)
    if found is not None and found in places:
        # Rewritten where it was read: never a second record of one folder.
        places = [found] + [place for place in places if place != found]
    failure = "nothing could be written beside the folder"
    for path in places:
        scratch: Path | None = None
        try:
            path.parent.mkdir(exist_ok=True)
            _check_holder(path.parent)
            with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.",
                    suffix=".part", delete=False) as handle:
                scratch = Path(handle.name)
                handle.write(text)
            os.replace(scratch, path)
        except OSError as exc:
            failure = exc.strerror or str(exc)
            if scratch is not None and os.path.lexists(scratch):
                try:
                    scratch.unlink()
                except OSError as left:
                    failure += f", and {scratch} stays ({left.strerror or left})"
            continue
        return path, ""
    return None, failure


def record_menu_words(setup: dict | None) -> str:
    """What line mode's menu says of a recorded choice it opens on."""
    if setup is None:
        return ""
    day = record_day(setup)
    return f"Same choice as on {day}." if day else "Same choice as last time."


def choice_given(args: argparse.Namespace) -> bool:
    """Whether the command line chose what to install, which a record then
    never replaces: an option of the choice, or a file list of its own."""
    # A namespace built by a caller that predates an option lacks it.
    return (getattr(args, "for_games", None) is not None or LOCAL.manifest is not None
            or any(getattr(args, flag[2:].replace("-", "_"), None)
                   for flag in RECORD_CHOICE if flag != "--for-games"))


def say_record_problem(plat: str, folder: Path, path: Path | None, problem: str) -> None:
    """A record that cannot be used, said once and ignored."""
    key = str(path)
    if not problem or key in _RECORD_SAID:
        return
    _RECORD_SAID.add(key)
    message = f"{problem}, so it is ignored."
    print(f"  {message}")
    EVENTS.emit("record", platform=plat, folder=str(folder), path=key, status="unreadable",
                choice=[], date="", files=0, message=message)


def by_record(args: argparse.Namespace) -> bool:
    """Whether the run's choice came from the install record: nothing of
    it was typed, so a part that cannot apply is left out, never refused."""
    return bool(getattr(args, "from_record", False))


def drop_recorded(args: argparse.Namespace, plat: str, flag: str, why: str,
                  keep: list[str] | None = None) -> None:
    """Leave out a recorded option that cannot apply, in one line: the run
    goes on, and the record written after it no longer holds it. keep, for
    an option of several names, is the names that still apply."""
    name = flag[2:].replace("-", "_")
    chosen = _INVOCATION.chosen.get(plat, [])
    if keep:
        setattr(args, name, list(keep))
        _INVOCATION.chosen[plat] = [option for option in chosen if option[0] != flag] + [
            (flag, value) for value in keep]
    else:
        setattr(args, name, build_parser().get_default(name))
        _INVOCATION.chosen[plat] = [option for option in chosen if option[0] != flag]
    print(f"  Left out of the recorded choice: {flag} ({why}).")


def apply_record(args: argparse.Namespace, plat: str, folder: Path) -> dict | None:
    """Take the choice recorded for plat in folder as the run's, as if its
    options had been typed: the plan's first choice. Returns the record,
    None where none is taken."""
    setup, path, problem = setup_record(plat, folder)
    say_record_problem(plat, folder, path, problem)
    if setup is None:
        return None
    try:
        parsed = build_parser().parse_args(setup["choice"])
    except SystemExit:
        say_record_problem(plat, folder, path,
                           f"The install record {path} names options this installer lacks")
        return None
    for flag in RECORD_CHOICE:
        name = flag[2:].replace("-", "_")
        setattr(args, name, getattr(parsed, name))
    if args.for_games is not None:
        args.all_files = False
    args.from_record = True
    options = record_options(setup["choice"])
    if any(flag in RECORD_NARROWING for flag, _value in options):
        # Said where it narrows the list: the whole list again is the run
        # a person expects, and said nothing new.
        _RECORD_TAKEN[plat] = setup
    _INVOCATION.chosen[plat] = [option for option in options if option[0] != "--all-files"]
    if isinstance(args.for_games, Path) and not _is_dir(args.for_games):
        # The games folder recorded is gone: the card's own games are read.
        _INVOCATION.chosen[plat] = [(flag, None if flag == "--for-games" else value)
                                    for flag, value in _INVOCATION.chosen[plat]]
        args.for_games = True
        print("  Left out of the recorded choice: its games folder (no longer there).")
    message = record_menu_words(setup)
    EVENTS.emit("record", platform=plat, folder=str(folder), path=str(path), status="applied",
                choice=list(setup["choice"]), date=setup["written"],
                files=len(setup["files"]), message=message)
    return setup


def _backup_note(run: Path) -> dict | None:
    """What a removal wrote beside the files it moved into run: the setup,
    its folder, its choice before and the record's entries. None for the
    backup of files an install replaced, or a note that cannot be read."""
    try:
        data = json.loads(_read_record_bytes(run / REMOVED_NOTE).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("platform"), str) \
            or not isinstance(data.get("folder"), str):
        return None
    setup = {"written": "", "choice": data.get("choice"), "files": data.get("files")}
    return data if _valid_setup(setup, Path(data["folder"])) else None


def _record_folder(run: Path, path: Path) -> tuple[Path, str] | None:
    """The BIOS folder whose record may name a file put back at path, and
    its dest there. The holder beside a folder keeps the folder's name as
    the first level of each run, the one inside it none."""
    holder, root = run.parent, run.parent.parent
    rel = PurePosixPath(*path.relative_to(root).parts)
    if len(rel.parts) > 1 and (holder / f"{rel.parts[0]}{RECORD_SUFFIX}").is_file():
        return root / rel.parts[0], PurePosixPath(*rel.parts[1:]).as_posix()
    if (holder / f"{root.name or 'folder'}{RECORD_SUFFIX}").is_file():
        return root, rel.as_posix()
    return None


def _record_without(gone: set[str]) -> Callable[[dict | None], dict | None]:
    """The change taking out a setup's entries at the folded dests of gone."""
    def change(setup: dict | None) -> dict | None:
        return None if setup is None else {
            **setup, "files": [item for item in setup["files"]
                               if str(item.get("root") or "") not in ("", "data")
                               or item["dest"].casefold() not in gone]}
    return change


def _record_after_restore(run: Path, put_back: list[Path]) -> str:
    """The record of the folder files went back into, made to say what is
    there now: "" once written, else why not. A removal's backup gives its
    files back to their setup, with the choice it had. Any other backup
    holds the user's own files, which the record never names: its entries
    at their places go."""
    note = _backup_note(run)
    if note is not None:
        folder = Path(note["folder"])
        back = []
        for item in note["files"]:
            path = _below(folder, item["dest"])[0]
            if path is not None and not _check_ours(path, item)[0]:
                back.append(item)
        if not back and put_back:
            # The files went back, but not where the record's folder is: the
            # folder moved or was renamed since the removal.
            return f"it is for {folder}, which does not hold the files put back"
        if not back:
            return ""
        return _update_record(folder, note["platform"],
                              lambda setup: _record_merge(setup, back, note["choice"]))
    by_folder: dict[Path, set[str]] = {}
    for path in put_back:
        found = _record_folder(run, path)
        if found is not None:
            by_folder.setdefault(found[0], set()).add(found[1].casefold())
    problems = [_update_record(folder, plat, _record_without(gone))
                for folder, gone in by_folder.items()
                for plat in sorted((load_record(folder).data or {}).get("setups") or {})]
    return next((problem for problem in problems if problem), "")


def _recorded_copy(run: Path, dest: Path) -> bool:
    """Whether the file at dest is the installer's own copy, as the record
    of its folder names it: the collection gives it again, so a restore
    replaces it without keeping it."""
    found = _record_folder(run, dest)
    if found is None:
        return False
    try:
        info = os.lstat(dest)
    except OSError:
        return False
    if not stat.S_ISREG(info.st_mode) or _is_link(info):
        return False
    folder, rel = found
    items = [item for setup in ((load_record(folder).data or {}).get("setups") or {}).values()
             for item in setup.get("files") or []
             if str(item.get("root") or "") in ("", "data")
             and item["dest"].casefold() == rel.casefold() and item["size"] == info.st_size]
    if not items:
        return False
    try:
        sha1 = _digest_file(dest, ("sha1",))["sha1"]
    except OSError:
        return False
    return any(item["sha1"] == sha1 for item in items)


def _record_merge(setup: dict | None, files: list[dict], choice: list[str]) -> dict:
    """A setup with files given back and the choice it had before a removal."""
    merged = {(str(item.get("root") or ""), item["dest"]): item
              for item in (setup or {}).get("files") or []}
    for item in files:
        merged[(str(item.get("root") or ""), item["dest"])] = item
    return {"list": {"version": None, "generated": None}, **(setup or {}),
            "written": _record_now(), "choice": list(choice),
            "files": [merged[key] for key in sorted(merged)]}


def _record_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _update_record(folder: Path, plat: str,
                   change: Callable[[dict | None], dict | None]) -> str:
    """Rewrite the setup plat of folder's record as change makes it, None
    taking it out: "" once written, else why not. A record that cannot be
    read, or that a newer installer wrote, is left as it is."""
    folder = Path(os.path.abspath(folder))
    read = load_record(folder)
    if read.newer or (read.data is None and read.path is not None):
        return read.problem
    data = read.data or {"setups": {}, "folder": str(folder)}
    setups = dict(data["setups"])
    new = change(setups.get(plat))
    if new is None:
        setups.pop(plat, None)
    else:
        setups[plat] = new
    if not setups:
        if read.path is None:
            return ""
        # Nothing of ours is left in the folder: the record goes with it.
        try:
            read.path.unlink()
        except OSError as exc:
            return exc.strerror or str(exc)
        return ""
    data = {"schema": RECORD_SCHEMA, "installer": installer_id(),
            "folder": str(data.get("folder") or folder), "setups": setups}
    where, failure = _save_record(folder, data, read.path)
    return "" if where is not None else failure


def restore_kept(run: Path, dry_run: bool = False) -> int:
    """Put every file of a backup run folder back where it was.

    run is a <holder>/<date-time> folder a run wrote, its holder named
    retrobios-backup. Each file goes to the same path below the holder's
    parent. A file there with other contents is moved into a new dated
    backup first, never lost. The install record of its folder is made to
    say so. The backup is left in place. Returns the exit code:
    0 when every file went back, 1 when one failed, 2 when the folder is no
    backup.
    """
    run = Path(os.path.abspath(os.path.expanduser(str(run))))
    if not _is_backup_run(run):
        print(f"Error: {run} is not a folder the installer kept files in.", file=sys.stderr)
        print(f"  Name one of the dated folders inside a {BACKUP_DIR} folder, as "
              "--backups lists them.", file=sys.stderr)
        return 2
    root = run.parent.parent
    files = _backup_files(run)
    if not files:
        print(f"{run} holds no file. Nothing to put back.")
        return 0
    restored = size = failed = 0
    put_back: list[Path] = []
    KEPT.reset()
    for src in files:
        rel = PurePosixPath(*src.relative_to(run).parts)
        dest = root / Path(*rel.parts)
        length = src.stat().st_size
        if dry_run:
            print(f"  would put back {dest}")
            restored += 1
            size += length
            continue
        try:
            sha1 = _digest_file(src, ("sha1",))["sha1"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            # A file at the place that is not the backup's copy (a newer one,
            # one the user put there) is moved aside first, into a new dated
            # backup, as an install keeps what it replaces. Its first level
            # is the folder the backup's holder sits in.
            holder = (root / rel.parts[0], PurePosixPath(*rel.parts[1:])) \
                if len(rel.parts) > 1 else (root, rel)
            if not _recorded_copy(run, dest):
                KEPT.keep(*holder, dest, {"sha1": sha1})
            _clear_read_only(dest)
            _replace_with_copy(src, dest)
        except (OSError, _NotKept) as exc:
            reason = getattr(exc, "strerror", None) or str(exc)
            print(f"  failed: {dest} ({reason})", file=sys.stderr)
            EVENTS.emit("restored", folder=str(run), path=str(dest), size=length, ok=False,
                        reason=reason)
            failed += 1
            continue
        EVENTS.emit("restored", folder=str(run), path=str(dest), size=length, ok=True,
                    reason="")
        put_back.append(dest)
        restored += 1
        size += length
    if dry_run:
        print(f"\nWould put back {_plural(restored, 'file')} ({format_size(size)}) "
              f"under {root}. Nothing was written.")
        return 0
    problem = _record_after_restore(run, put_back)
    print(f"\nPut back {_plural(restored, 'file')} ({format_size(size)}) under {root}.")
    for item in KEPT.summary():
        # The files that sat at those places, never lost.
        print(f"Kept {_plural(item['files'], 'file')} that were in their place "
              f"({format_size(item['bytes'])}) in {item['folder']}")
    if failed:
        print(f"{_plural(failed, 'file')} could not be put back.", file=sys.stderr)
    if problem:
        print(f"The install record could not be updated ({problem}).", file=sys.stderr)
    print(f"The copies are still in {run}. To free the space: {_INVOCATION.launcher()} "
          f"--delete-backup {_INVOCATION.word(str(run))}")
    return 1 if failed or problem else 0


def _below(folder: Path, dest: str) -> tuple[Path | None, str]:
    """The file a record's dest names below folder, reached through no link:
    (path, "") or (None, why it is left). A dest that climbs or is absolute
    is outside, whatever a record says."""
    try:
        rel = _safe_relative_path(dest, "dest")
    except ValueError:
        return None, "outside"
    path = folder
    for part in rel.parts[:-1]:
        path = path / part
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None, "gone"
        except OSError:
            return None, "unreadable"
        if _is_link(info):
            return None, "link"
        if not stat.S_ISDIR(info.st_mode):
            return None, "not_a_file"
    return path / rel.parts[-1], ""


def _check_ours(path: Path, item: dict) -> tuple[str, os.stat_result | None]:
    """Why the file at path is not the one the record names, "" when it
    is, and what lstat read of it."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "gone", None
    except OSError:
        return "unreadable", None
    if _is_link(info):
        return "link", info
    if not stat.S_ISREG(info.st_mode):
        return "not_a_file", info
    if not re.fullmatch(r"[0-9a-f]{40}", str(item["sha1"])) or info.st_size != item["size"]:
        return "changed", info
    try:
        same = _digest_file(path, ("sha1",))["sha1"] == item["sha1"]
    except OSError:
        return "unreadable", info
    return ("" if same else "changed"), info
