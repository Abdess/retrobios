"""The JSON event stream of --events: schema 1, new kinds only, never a new key."""
from __future__ import annotations

import argparse
import json
import threading
from typing import TextIO

from installer.text import _CONTROLS

EVENT_KEYS: dict[str, tuple[str, ...]] = {
    # mode: install, check, dry-run, list, remove (--remove, --delete-backup),
    # restore or pack (--pack, with --dry-run too).
    "start": ("schema", "installer", "mode"),
    # A folder detection could not look in, once each, before detect: the
    # probes under it counted as absent and the others went on. reason is
    # why in words (Permission denied). A kind of its own, since schema 1
    # never adds a key to detect, and not an error: the run goes on.
    "unsearched": ("folder", "reason", "message"),
    # platforms: [{"platform", "name", "bios_dir"}], empty when none is found.
    "detect": ("os", "os_name", "platforms"),
    # stage: manifest (reason: network, not_found, invalid, clock for a
    # refused certificate under a clock set in the past, no_ca for no
    # trusted certificates on the machine, or no_ssl for a Python built
    # without ssl) or detect (reason: conflict, two
    # systems found on one machine, or not_found, the platform named with
    # --platform, or by a file list or a pack in a run without questions,
    # found nowhere and no folder to assume) or from (a folder named with --from,
    # reason: not_found, not_a_folder, unreadable, or system for the root
    # of the system and /proc, /sys, /dev) or dest (reason: unreadable, a
    # folder above it this user cannot open, not_a_folder, the BIOS folder
    # is a file or lies under one, or not_writable, the BIOS folder cannot
    # be created, a summary following) or option (reason:
    # unknown, a platform, target, system, core or emulator the run cannot
    # use, refused before any download).
    "error": ("stage", "reason", "platform", "message"),
    # A folder named with --from, once read: the files it holds (counted
    # up to MAX_SCANNED_FILES, truncated past them), and the folders below
    # it on another drive, not entered.
    "scanned": ("folder", "files", "truncated", "other_drives"),
    # Before choices, once a list is read: the system here runs another
    # version than the one the list was built for (list_version, from the
    # manifest, installed_version, from the system's own version file).
    # message says it and what it means. Not written when either version
    # is unknown, and never a refusal.
    "version": ("platform", "list_version", "installed_version", "message"),
    # Before choices: the board the system or its card names, read with no
    # --target given. applied is whether the run keeps its cores' files
    # only, false for a board the platform's list does not name. message
    # says it. A kind of its own: the full-screen interface always gives
    # --dest, and the board was never applied there.
    "board": ("platform", "board", "applied", "message"),
    # --installed-cores, before choices, once per installed core the list
    # has no profile for: info is whether its .info was found, dests the
    # firmware paths it declares, kept whatever the narrowing drops. A
    # core with no .info keeps nothing it alone reads, and message says so.
    "unknown_core": ("platform", "core", "info", "dests", "message"),
    # Before the file events of a check: the systems the run's list lets
    # one choose among, --system aside, in id order (other for the files
    # no system names). What Choose systems lists, and what the plan counts
    # a --system out of: it said 12 where Choose systems listed 11. A kind
    # of its own, since schema 1 never adds a key to check.
    "choices": ("platform", "systems"),
    # Right after choices: the dests of the list's files the run sets aside
    # before any choice, those read from a save directory whose place is
    # not known among them, in list order. What Cores lists and counts is
    # the list without them: it listed 189 cores where --core accepted 181,
    # and an untick sent the 8 others to a run that refused them. A kind of
    # its own, since schema 1 never adds a key to choices.
    "set_aside": ("platform", "dests"),
    # state: present (hash verified), wrong_hash or missing.
    "file": ("platform", "dest", "systems", "size", "state"),
    "system": ("platform", "system", "name", "files", "present", "missing",
               "wrong_hash", "bytes_needed"),
    # The files in place being read, at most every half second, and the last.
    "checking": ("files_done", "files_total"),
    # --for-games: the games of the card being read (a cartridge hashed, a
    # disc's header read), at most every half second, and the last.
    "games_reading": ("files_done", "files_total"),
    # --for-games, once the games are read, before choices: the games
    # folder, the games found and those recognised by their content.
    # found: [{"system", "folder", "games", "recognised", "regions"}],
    # regions the ones kept where the games prove one, empty for every
    # region. fallback: [{"system", "folder", "name", "reason"}], each game
    # that got every BIOS of its system (reason: not_recognised, not_read,
    # region_unknown, unknown_set, no_parent). not_games: the other files
    # of the game folders. required_only: --required-only given.
    "games": ("platform", "folder", "games", "recognised", "found", "fallback",
              "not_games", "required_only"),
    # --for-games could not read what the games need (reason: offline,
    # network, invalid, stale, no_sets, no_folder): the run keeps every
    # file of the list, and message says why.
    "games_unavailable": ("platform", "reason", "message"),
    "check": ("platform", "name", "bios_dir", "files", "present", "missing",
              "wrong_hash", "bytes_needed", "data_missing", "not_installable"),
    # Right after check: the same counts over the files the platform's own
    # list declares (cores: null), and their dests in file-event order. A
    # kind of its own, since schema 1 never adds a key to the file event.
    "declared": ("platform", "files", "present", "missing", "wrong_hash",
                 "bytes_needed", "dests"),
    # Right after declared: the files of the data trees to fetch (check's
    # data_missing) and the bytes they write. A kind of its own, since
    # schema 1 never adds a key to check.
    "data": ("platform", "files", "bytes"),
    # A file to install that this machine already holds: misplaced in the
    # BIOS folder (folder is its bios_dir, reason says why in words) or in
    # a folder named with --from (reason empty). member names the ZIP member
    # when path is an archive, else "". Its copy is a downloaded event.
    "found": ("platform", "dest", "folder", "path", "member", "reason"),
    # What a folder named with --from holds that could not be read, of the
    # size of a file no copy was found for, or of no known size (a folder,
    # a ZIP that would not open). member as in found, reason in words.
    "unreadable": ("platform", "folder", "path", "member", "reason"),
    # The files of the list read from the frontend's save directory, and
    # where they go (<system> and <core> stand for a folder per system or
    # per core), once that directory is known. Not written when it is not:
    # the summary's skipped then counts them (no_save_directory).
    "saves": ("platform", "files", "folder"),
    "download": ("platform", "files", "bytes"),
    "progress": ("files_done", "files_total", "bytes_done", "bytes_total"),
    # Right after each progress event, and once when the files of a
    # download event are done: bytes_done split into the bytes this machine
    # held (a copy found here, the pack, a resumed partial copy) and the
    # bytes the network brought. A speed is bytes_network over time.
    "transfer": ("bytes_local", "bytes_network"),
    "downloaded": ("dest", "ok", "reason", "size", "files_done", "files_total",
                   "bytes_done", "bytes_total"),
    # failed: [{"dest", "reason"}]. skipped: [{"reason", "label", "files",
    # "required"}], the files the collection cannot supply. left_out:
    # [{"category", "label", "files", "dests"}], what --no-game-data left
    # out, empty without it. kept: [{"folder", "files", "bytes"}], the files
    # in place the run moved aside before replacing them (under --dry-run,
    # would move), one per backup folder, empty when none.
    "summary": ("mode", "installed", "up_to_date", "pending", "failed", "skipped",
                "left_out", "kept", "interrupted"),
    # --add-app, or yes to its question, after the summary: the RetroBIOS
    # app put on the handheld card (folder, its root) of system. dests are
    # the app's files below the root, written those this run wrote (none
    # when all were in place), kept the backup folders as in summary.
    # ok false with reason when it was refused or failed.
    "app": ("system", "folder", "ok", "reason", "dests", "written", "kept"),
    # The install record of the BIOS folder (path, beside it in
    # retrobios-backup). status: applied (before choices, its choice taken
    # as the run's because nothing on the command line chose), written
    # (before the summary, once the install placed files), unreadable (said
    # once and ignored) or not_written (the install itself unharmed). choice is
    # the recorded options as words, date when it was written, files the
    # files it holds for the platform. A kind of its own, since schema 1
    # never adds a key to an existing kind.
    "record": ("platform", "folder", "path", "status", "choice", "date", "files", "message"),
    # --remove, before anything is removed (with --dry-run, all it writes):
    # the files that go (dests, in record order), their bytes, the systems
    # losing a file, kept [{"dest", "reason"}] for each file left (reason
    # one of REMOVAL_REASONS), gone the recorded files no longer there,
    # backup whether they are moved rather than deleted. message says it.
    # Written with files 0 when no record says what is the installer's.
    "removal_plan": ("platform", "folder", "files", "bytes", "systems", "dests", "kept",
                     "gone", "backup", "message"),
    # Each file --remove took: ok false with reason when it stays, moved_to
    # the file's place in the backup with --backup, else "".
    "removed": ("platform", "dest", "size", "ok", "reason", "moved_to"),
    # Each file --restore put back from the backup folder to path.
    "restored": ("folder", "path", "size", "ok", "reason"),
    # A backup folder: listed by --backups, made by --remove --backup, or
    # deleted (not_deleted when a file stayed) by --delete-backup. date is
    # when it was made (local time), source remove for a removal's, install
    # for the files an install replaced.
    "backup": ("folder", "date", "files", "bytes", "source", "status", "message"),
    # --pack: planned (--dry-run), written or failed. files and bytes are
    # the pack's members, each stored once, size what it takes on disk,
    # parts each file written (the pack alone when it is one ZIP).
    "pack": ("platform", "path", "files", "bytes", "size", "parts", "status", "message"),
    "end": ("code",),
}


class EventStream:
    """The --events output: closed (nothing written) until opened."""

    def __init__(self) -> None:
        self.stream: TextIO | None = None
        self._lock = threading.Lock()

    def open(self, stream: TextIO) -> None:
        self.stream = stream

    @property
    def on(self) -> bool:
        return self.stream is not None

    def emit(self, kind: str, **fields: object) -> None:
        if self.stream is None:
            return
        keys = EVENT_KEYS[kind]
        if set(fields) != set(keys):
            raise ValueError(f"event {kind}: keys {sorted(fields)} != {sorted(keys)}")
        # Every string a script reads goes through the terminal's filter,
        # a new line kept: a consumer printing a folder or a name obeyed
        # the control characters a card label or a list held.
        line = json.dumps({"event": kind, **{key: _clean_strings(fields[key], "\n")
                                             for key in keys}})
        with self._lock:
            self.stream.write(line + "\n")
            self.stream.flush()


EVENTS = EventStream()


def _event_mode(args: argparse.Namespace) -> str:
    if getattr(args, "remove", False) or getattr(args, "delete_backup", None) is not None:
        return "remove"
    if getattr(args, "restore", None) is not None:
        return "restore"
    if getattr(args, "backups", False):
        return "list"
    if getattr(args, "pack", None) is not None:
        return "pack"
    if args.check:
        return "check"
    if args.dry_run:
        return "dry-run"
    if (args.list_platforms or args.list_targets or args.list_systems
            or args.list_cores or args.list_emulators):
        return "list"
    return "install"


def _event_exit_code(code: object) -> int:
    """The process status sys.exit(code) gives."""
    if code is None:
        return 0
    return code if isinstance(code, int) else 1


def _clean_strings(value: object, keep: str = "") -> object:
    """value with a "?" for each control character of its strings, keys
    included, those of keep left: the one filter between a list, a card or
    a config and the terminal, its paths refused before (_safe_relative_path)."""
    if isinstance(value, str):
        return _CONTROLS.sub(lambda found: found.group() if found.group() in keep else "?",
                             value)
    if isinstance(value, dict):
        return _clean_mapping(value, keep)
    if isinstance(value, (list, tuple)):
        return [_clean_strings(item, keep) for item in value]
    return value


def _clean_mapping(value: dict, keep: str = "") -> dict:
    """value with its keys and items through _clean_strings."""
    return {_clean_strings(key, keep): _clean_strings(item, keep)
            for key, item in value.items()}
