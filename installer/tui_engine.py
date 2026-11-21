"""The work the screens hand off: child runs, fetches in this process, and their work folders."""
from __future__ import annotations

import io
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import urllib.error
from pathlib import Path
from typing import TYPE_CHECKING

from installer.events import _event_exit_code
from installer.games import games_probe
from installer.handheld_app import put_app
from installer.manifest import _validate_manifest
from installer.network import _fetch_json, fetch_manifest, fetch_targets, missing_list_advice, network_words
from installer.offline import LOCAL, offline_named, offline_undo
from installer.platforms import display_name
from installer.remote import MAX_MANIFEST_BYTES, active_remote
from installer.tui_rows import TUI_OFFLINE_TITLE

if TYPE_CHECKING:
    from installer.handheld_app import CardApp


def _log_tail(path: Path, count: int = 12) -> list[str]:
    """The last lines a child wrote for a person, which say why it stopped."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [f"The log {path} cannot be read: {exc.strerror or exc}"]
    lines = [line.rstrip() for line in text.replace("\r", "\n").splitlines()]
    # The banner says which installer ran, not what went wrong.
    return [line for line in lines if line.strip() and not line.startswith("RetroBIOS ")
            ][-count:]


class _EngineRun:
    """This installer run as a child with --events, read line by line."""

    def __init__(
        self, argv: list[str], log: Path, inbox: queue.Queue, run_id: int,
        env: dict | None = None,
    ) -> None:
        self.log = log
        # Its own session: a signal typed at the terminal reaches the
        # interface alone, which forwards one Ctrl-C and waits for the summary.
        options: dict = {} if os.name == "nt" else {"start_new_session": True}
        if env is not None:
            options["env"] = env
        with open(log, "w", encoding="utf-8", errors="replace") as handle:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=handle,
                text=True, encoding="utf-8", errors="replace", **options,
            )
        threading.Thread(target=self._read, args=(inbox, run_id), daemon=True).start()

    def _read(self, inbox: queue.Queue, run_id: int) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict):
                inbox.put(("event", run_id, event))
        code = self.proc.wait()
        inbox.put(("ended", run_id, code, _log_tail(self.log)))

    def running(self) -> bool:
        return self.proc.poll() is None

    def pause(self, stopped: bool) -> None:
        """Stop the child where it is, or let it carry on. It runs in a
        session of its own, which a Ctrl-Z stopping the terminal's process
        group never reaches: an install went on writing for as long as the
        screen was suspended."""
        if os.name == "nt" or not self.running():
            return
        try:
            os.killpg(self.proc.pid, signal.SIGSTOP if stopped
                      else signal.SIGCONT)
        except ProcessLookupError:
            # It ended between the two calls: there is nothing to stop.
            return

    def interrupt(self, from_key: bool) -> None:
        if not self.running():
            return
        if os.name != "nt":
            self.proc.send_signal(signal.SIGINT)
        elif from_key:
            # The child shares the console: Ctrl-C read as a key reached no
            # one, so it is sent to the console, this process ignoring it.
            # typeshed declares CTRL_C_EVENT for win32 only.
            ctrl_c: int = vars(signal)["CTRL_C_EVENT"]
            os.kill(0, ctrl_c)

    def stop(self, grace: float) -> None:
        """End the child, letting it write its summary for up to grace seconds."""
        if not self.running():
            return
        if grace:
            self.interrupt(from_key=True)
            try:
                self.proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                # It ignored Ctrl-C for that long: it is stopped outright.
                self.proc.kill()
        self.proc.kill()
        self.proc.wait()


# One try, for a screen with Try again on it: three tries of 30 s were 85 s
# of a bare timer before the error said there was no network.
TUI_FETCH_TIMEOUT = 15


def _tui_put_app(card: CardApp, inbox: queue.Queue) -> None:
    """The app put on the card in this process, what it did sent back."""
    inbox.put(("app", put_app(card)))


def _tui_fetch(plat: str, inbox: queue.Queue, log: io.StringIO) -> None:
    """The file list, fetched once in this process, or what went wrong."""
    if LOCAL.manifest is not None or LOCAL.pack is not None:
        mark = len(log.getvalue())
        try:
            inbox.put(("manifest", plat, fetch_manifest(plat)))
        except SystemExit as exc:
            inbox.put(("manifest_failed", plat, "", log.getvalue()[mark:].splitlines(),
                       _event_exit_code(exc.code)))
        return
    remote = active_remote()
    url = remote.manifest_url.format(platform=plat)
    try:
        data = _fetch_json(url, MAX_MANIFEST_BYTES, "file list", attempts=1,
                           timeout=TUI_FETCH_TIMEOUT)
        inbox.put(("manifest", plat, _validate_manifest(data, plat)))
        return
    except ValueError as exc:
        title, lines = "The file list is not valid", [f"What arrived is not a file list: {exc}."]
        if isinstance(exc.__cause__, (json.JSONDecodeError, UnicodeDecodeError)):
            # The parser's "Expecting value: line 2 column 1" told no one anything.
            lines = ["What arrived is not a file list: a Wi-Fi sign-in page or a cut "
                     "download looks like this.", "Check the connection, then choose Try again."]
    except urllib.error.HTTPError as exc:
        title = "No file list"
        lines = [f"There is no file list for {display_name(plat)} at this address."
                 if exc.code == 404 else f"The server answered HTTP {exc.code}."]
        if exc.code == 404 and not remote.overridden:
            # Line mode named RETROBIOS_REF as the cause, the screen nothing.
            lines.append(missing_list_advice(plat, "choose Try again"))
    except (urllib.error.URLError, OSError) as exc:
        code, words = network_words(exc)
        if code == "offline":
            # Asked for, not a failure: no Try again, and the two ways a
            # run without the network gets its list.
            inbox.put(("manifest_failed", plat, TUI_OFFLINE_TITLE, [
                f"This run makes no network request ({offline_named()}), and the list "
                "of BIOS files comes from the network.",
                "Run the installer again with the list saved as a file "
                f"(--manifest FILE, a copy of install/{plat}.json) or with a pack "
                f"(--from-pack PACK), or {offline_undo()}."], 1))
            return
        title = {"clock": "The clock is wrong",
                 "no_ca": "No trusted certificates",
                 "no_ssl": "This Python cannot use HTTPS"}.get(code, "No connection")
        # The screen's first row is Try again: "then run again" was a second way.
        lines = [words[0].upper() + words[1:].replace(", then run again",
                                                      ", then choose Try again") + "."]
        if code == "network":
            lines = [f"The list of BIOS files could not be downloaded: {words}.",
                     "Check the Wi-Fi or the cable, then choose Try again.",
                     # A handheld with no Wi-Fi has the pack as its way.
                     "Or copy a pack to the card and run the installer with --from-pack "
                     "PACK: no network is needed then."]
            proxy = next((name for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY",
                                            "all_proxy") if os.environ.get(name)), "")
            if proxy:
                # Named, never shown: the value can hold a password.
                lines.append(f"{proxy} is set, so the connection goes through a proxy: "
                             "check that it answers.")
    if remote.overridden:
        lines.append(f"RETROBIOS_BASE_URL chose the address: {url}")
    inbox.put(("manifest_failed", plat, title, lines, 1))


def _tui_fetch_targets(plat: str, inbox: queue.Queue, log: io.StringIO) -> None:
    """The platform's board list for Device, fetched in this process as a
    --target run reads it: the pack's or the list's beside --manifest, else
    the network's. None and why when it cannot be read."""
    mark = len(log.getvalue())
    try:
        # One attempt and the list's own timeout, as the file list is
        # fetched here: Device says Reading while it waits.
        targets = fetch_targets(plat, attempts=1, timeout=TUI_FETCH_TIMEOUT)
    except SystemExit:
        targets = None
    said = [line.strip() for line in log.getvalue()[mark:].splitlines() if line.strip()]
    problem = "" if targets is not None else (
        f"The board list could not be read{': ' + said[0] if said else '.'}")
    inbox.put(("targets", plat, targets, problem))


def _tui_fetch_games(plat: str, inbox: queue.Queue, log: io.StringIO, dest: Path | None,
                     look: bool) -> None:
    """The file list, then, once it came, a look at the card for games
    (look), said before the list so that the check reads them."""
    held: queue.Queue = queue.Queue()
    _tui_fetch(plat, held, log)
    message = held.get()
    if look and message[0] == "manifest" and dest is not None:
        # One attempt, as the list's own: a retry says so on stderr, under
        # the screen.
        count = games_probe(plat, dest, attempts=1)
        inbox.put(("games_here", plat, dest, count))
    inbox.put(message)


TUI_WORK_PREFIX = "retrobios-tui-"
# The interface's process id, in its work folder: a folder whose process is
# gone was left by a kill no handler sees (SIGKILL, a power cut).
TUI_OWNER = "owner"
# Written when a failed run's log is kept: it stays a week, then goes.
TUI_KEPT = "kept"
TUI_KEEP_SECONDS = 7 * 24 * 3600


def _owner_alive(folder: Path) -> bool | None:
    """Whether the run that made folder is still running, None when unknown."""
    try:
        pid = int((folder / TUI_OWNER).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if os.name == "nt" or pid <= 0:
        # os.kill(pid, 0) ends a process on Windows instead of asking, and
        # 0 or a negative number names a process group, not the run.
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError):
        # A number past what a pid holds is no process this run can ask.
        return None
    return True


def _mark_kept(work: Path) -> None:
    try:
        (work / TUI_KEPT).write_text("", encoding="utf-8")
    except OSError as exc:
        # The log is still there, only its week is not counted.
        print(f"The log folder {work} could not be marked: {exc}", file=sys.stderr)


def _prune_work_folders(root: Path, now: float) -> list[Path]:
    """Remove what earlier runs of the interface left in root: the folder of
    a run killed outright, and a failed run's log after a week. A folder
    whose run is still going, or unknown and recent, stays."""
    removed: list[Path] = []
    try:
        folders = [path for path in root.glob(TUI_WORK_PREFIX + "*") if path.is_dir()]
    except OSError:
        return removed
    for folder in folders:
        try:
            age = now - folder.stat().st_mtime
            kept = (folder / TUI_KEPT).exists()
        except OSError:
            continue
        alive = _owner_alive(folder)
        if alive or ((alive is None or kept) and age < TUI_KEEP_SECONDS):
            continue
        shutil.rmtree(folder, ignore_errors=True)
        removed.append(folder)
    return removed


def _tui_work_folder(handlers: dict[int, object]) -> Path | None:
    """The run's own work folder, marked as this process's, or None (said)."""
    try:
        work = Path(tempfile.mkdtemp(prefix=TUI_WORK_PREFIX))
    except OSError as exc:
        _restore_handlers(handlers)
        print(f"Error: no work folder could be made in {tempfile.gettempdir()}: {exc}. "
              "Free some space there, or point TMPDIR (TEMP on Windows) at another "
              "folder.", file=sys.stderr)
        return None
    try:
        (work / TUI_OWNER).write_text(str(os.getpid()), encoding="utf-8")
    except OSError as exc:
        # A full temp disk: the folder has no owner, and a later run leaves
        # it a week like any unknown one. The logs fail as they come.
        print(f"The work folder {work} could not be marked as this run's: {exc}",
              file=sys.stderr)
    return work


def _restore_handlers(handlers: dict) -> None:
    for number, previous in handlers.items():
        signal.signal(number, previous)
