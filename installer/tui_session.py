"""The full-screen session: the terminal, signals, the child runs and the farewell."""
from __future__ import annotations

import argparse
import codecs
import contextlib
import errno
import functools
import io
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, TextIO

from installer.app import CardApp, put_app
from installer.cards import card_choice, dest_default
from installer.constants import MANIFEST_URL, MAX_MANIFEST_BYTES
from installer.cores import normalize_platform
from installer.detect_frontends import detect_frontends
from installer.detect_os import _enter_wsl, _wsl_dest, detect_os, detected_os
from installer.embedded import _SHARE_FOLDERS, _mounted_cards, card_bound, card_platform, display_name, share_doubt
from installer.events import _event_exit_code
from installer.from_folders import _open_local_sources, from_folder_problem
from installer.games import games_probe
from installer.invocation import _INVOCATION
from installer.line_ui import _pad
from installer.manifest import _validate_manifest
from installer.narrowing import resolve_regions
from installer.network import _fetch_json, fetch_manifest, fetch_targets, network_words
from installer.offline import LOCAL, offline_named, offline_undo
from installer.outcome import LINE_SAVE_REMEDY
from installer.probe import _DETECTION_REFUSED, refused_words
from installer.prompt import QUIT_CODE
from installer.record import choice_given
from installer.run import TUI_ESC_WAIT, TUI_FRAME, TUI_MAX_WIDTH, _MOUSE_OFF, _MOUSE_ON, _SCREEN_OFF, _SCREEN_ON
from installer.setups import _default_dest, _tui_passthrough, found_setups, setup_list
from installer.terminal import _enable_ansi
from installer.text import cell_width, screen_text
from installer.tui_actions import (
    _card_status,
    _choose,
    _open_folder_screen,
    _platform_focus,
    _take_card,
    open_tui_pack,
    set_offline,
    tui_interrupt,
    use_tui_pack,
)
from installer.tui_results import _bar_click, tui_view
from installer.tui_rows import TUI_OFFLINE_TITLE
from installer.tui_state import (
    TUI_IDLE_WORDS,
    TuiState,
    _terminal_size,
    colour_blocker,
    tui_argv,
    tui_idle_exit,
    tui_mouse_blocker,
    tui_pad_route,
    tui_run_env,
    tui_wants_mouse,
)
from installer.tui_text import (
    KeyDecoder,
    TerminalInput,
    TuiKey,
    TuiMouse,
    _short_path,
    ascii_text,
    decode_windows_key,
    tui_paint,
)
from installer.tui_update import tui_receive, tui_update
from installer.tui_view import (
    TUI_ESDE_NOTE,
    TUI_RESULT_AGAIN,
    TUI_RESULT_COPY,
    TUI_SAVE_REMEDY,
    _shown,
    tui_keeps_log,
    tui_outcome,
)


class TuiHits(NamedTuple):
    """What a click reaches on one drawn frame (tui_hits): each target is
    (line, first column, column past the last, what it does), lines and
    columns counted from 0. listing is (first row shown, rows shown, rows)
    for a list taller than its room, scroll "pager" or "error" for a text
    that scrolls."""

    screen: str
    help: bool
    size: tuple[int, int]
    targets: tuple
    listing: tuple | None = None
    scroll: str = ""
    # How many screens deep the frame was drawn, and its number: a frame
    # whose targets differ from the one before it is another frame.
    depth: int = 0
    frame: int = 0
    # When this screen was first drawn (state.now): a press sooner than
    # TUI_TAP_SETTLE after it belongs to a tap made on the screen before.
    shown: float = 0.0

    def at(self, col: int, line: int) -> tuple | None:
        return next((target for row, first, end, target in self.targets
                     if row == line and first <= col < end), None)


_BAR_ENTRY = re.compile(r"\S+(?: \S+)*")


def tui_hits(state: TuiState, lines: list[str]) -> TuiHits:
    """The targets of the frame tui_view drew: a row of the list across
    the whole width, its text or not, each entry of the bar that names a
    key, and the line saying which lines are in view."""
    cols = max([state.cols, *(cell_width(str(line)) for line in lines)])
    targets: list[tuple] = []
    shown: list[int] = []
    listed = None
    scroll = ""
    for number, line in enumerate(lines):
        mark = getattr(line, "mark", None)
        if not mark:
            continue
        if mark[0] == "row":
            targets.append((number, 0, cols, mark))
            shown.append(mark[1])
        elif mark[0] == "scroll":
            targets.append((number, 0, cols, mark))
            if mark[1] == "list":
                listed = mark[2]
            else:
                scroll = mark[1]
        elif mark[0] == "bar" and not state.help:
            for entry in _BAR_ENTRY.finditer(str(line)):
                key = _bar_click(state, entry.group().split(" ", 1)[0])
                if key is not None:
                    targets.append((number, entry.start(), entry.end(), ("key", key)))
    rows = (min(shown), len(shown), listed) if listed is not None and shown else None
    hits = TuiHits(state.screen, state.help, (state.cols, state.rows), tuple(targets),
                   rows, scroll, len(state.stack))
    before = state.hits
    if before is None:
        return hits._replace(frame=0, shown=state.now)
    same = before[:7] == hits[:7]
    # Another screen, its help or its size: what a finger aimed at was
    # elsewhere, and the settle time starts again.
    moved = (before.screen, before.help, before.size, before.depth) != (
        hits.screen, hits.help, hits.size, hits.depth)
    return hits._replace(frame=before.frame if same else before.frame + 1,
                         shown=state.now if moved else before.shown)


def _tui_take_args(state: TuiState, args: argparse.Namespace) -> None:
    """The choice the command line names, as the screens start from it."""
    state.cli_systems = list(args.system or [])
    state.regions = resolve_regions(args.region) if args.region else []
    state.cli_regions = list(state.regions)
    # Resolved as written, .. taken out: the copy browser opened on t/.., and
    # a link stays the link typed (os.path.normpath reads no folder).
    state.from_folders = [Path(os.path.normpath(Path(folder).absolute()))
                          for folder in getattr(args, "from") or []]
    state.cores = list(dict.fromkeys(
        token.strip() for value in args.core or [] for token in value.split(",")
        if token.strip()))
    state.cli_cores = list(state.cores)
    state.no_game_data = state.cli_no_game_data = bool(args.no_game_data)
    state.one_per_slot = bool(getattr(args, "one_per_slot", False))
    state.standalone = bool(getattr(args, "standalone", False))
    state.installed_only = bool(args.installed_cores)
    state.jobs = args.jobs
    state.add_app = bool(getattr(args, "add_app", False))
    state.passthrough = _tui_passthrough(args)
    state.target = str(args.target or "")
    state.every_board = bool(args.every_board)
    state.emulators = list(args.emulator or [])
    state.packs = [Path(pack).absolute() for pack in args.from_pack or []]
    if getattr(args, "for_games", None) is not None:
        state.for_games, state.games_choice = True, "cli"
        if isinstance(args.for_games, Path):
            state.games_folder = Path(os.path.normpath(args.for_games.absolute()))
    state.required_only = bool(getattr(args, "required_only", False))
    if args.manifest is not None:
        state.manifest_path = Path(args.manifest).absolute()
        state.manifest_given = True
    state.cli_choice = choice_given(args) or state.manifest_given


def _tui_detect(state: TuiState, os_type: str) -> None:
    """The setups and cards found here, and what detection said."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        state.setups, state.mounted_setups = found_setups(os_type)
        frontends = detect_frontends(os_type)
    # Said on the normal screen before this one covered it, and kept
    # above the list: a status line under 18 setups was never drawn.
    state.refused = [refused_words(folder, why, _short_path(folder, state.home))
                     for folder, why in _DETECTION_REFUSED]
    unsaid = {refused_words(*refused) for refused in _DETECTION_REFUSED}
    if "esde" in frontends:
        state.notes.append(TUI_ESDE_NOTE)
    state.notes += [line.strip() for line in captured.getvalue().splitlines()
                    if line.strip() and line.strip() not in unsaid]


def _start_on_platform(state: TuiState, args: argparse.Namespace, plat: str,
                       os_type: str) -> list[tuple]:
    """The first screen for a system named without its folder."""
    bound = card_bound(args.platform, plat)
    # A system that runs from its card is its card or the device, never
    # this machine's own folder for the same list.
    matched = [setup for setup in state.setups if setup[0] == plat
               and (bound is None or detected_os(setup[0], setup[1]) == bound[0])]
    # Named by the file list alone, a lone card found is asked about
    # first, as without the list: its folder was the first screen.
    if len(matched) == 1 and not getattr(args, "platform_from_list", False):
        state.stack = []
        return _choose(state, plat, matched[0][1], proposed=True)
    if matched:
        state.setups = matched
        return []
    if (getattr(args, "platform_from_list", False) and not bound and len(setup_list(
            state.setups, state.mounted_setups, "", os_type, LOCAL.serves())) > 1):
        # A list or a pack card setups read too: the setup list, filtered
        # to them and RetroArch first, as line mode asks. The folder
        # question alone left them out of reach.
        state.stack = ["platforms"]
        state.focus["platforms"] = _platform_focus(state, plat)
        return []
    state.platform = plat
    state.card_bound = bound
    state.stack = []
    if plat in _SHARE_FOLDERS and not bound:
        return _open_folder_screen(state, None, "share")
    default = None if bound else _default_dest(os_type, plat)
    return _open_folder_screen(state, default)


def _start_on_dest(state: TuiState, dest: Path) -> list[tuple] | None:
    """The first screen for a folder named without its system, None when
    the folder is left to the setup list."""
    card = card_platform(dest)
    if card:
        state.stack = []
        return _choose(state, card, dest)
    # A card whose own files name its system is read as line mode reads
    # it (card_dest): RetroArch was under A for a KNULLI card when this
    # computer had RetroArch too, and its files went to the card's root.
    choice = card_choice("", "", dest)
    if choice.plat and not choice.refused:
        state.stack = []
        return _take_card(state, choice, dest)
    state.dest_given = dest
    return None


def tui_start(
    args: argparse.Namespace, os_type: str, detect: bool = True,
) -> tuple[TuiState, list[tuple]]:
    """The first screen, from what is found here and what the command named."""
    state = TuiState(os_type=os_type, home=Path.home())
    state.pad = tui_pad_route(os_type)
    _tui_take_args(state, args)
    plat = normalize_platform(args.platform, say=False) if args.platform else ""
    if detect:
        _tui_detect(state, os_type)
    if plat and args.dest is not None:
        state.stack = []
        state.platform, state.card_bound = plat, card_bound(args.platform, plat)
        dest = Path(args.dest)
        # Read as the line mode reads --dest: an Onion card's root gets its
        # BIOS folder, another system's card is refused, a list named for
        # another system's card is said.
        choice = card_choice(args.platform, plat, dest)
        if choice.refused:
            _card_status(state, choice)
            return state, _open_folder_screen(state, None)
        return state, _take_card(state, choice, dest)
    if plat:
        return state, _start_on_platform(state, args, plat, os_type)
    if args.dest is not None:
        effects = _start_on_dest(state, Path(args.dest))
        if effects is not None:
            return state, effects
    if state.dest_given is None and not args.platform:
        state.doubts = [(plat, mount) for mount in _mounted_cards()
                        for plat in share_doubt(mount)[0]]
    if (state.dest_given is None and not state.doubts and not state.refused
            and len(state.setups) == 1):
        # One setup found and no card in doubt: its plan, Change where (or
        # Back) one press away. A folder detection could not look in may
        # hold another setup: the setups are listed then, with it.
        found, folder, _label = state.setups[0]
        state.opened_on_plan = True
        return state, _choose(state, found, folder, proposed=True)
    if state.dest_given is not None or not (state.setups or state.doubts):
        state.stack = ["platforms"]
        state.focus["platforms"] = _platform_focus(state, dest_default(state.setups))
    return state, []


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
    url = MANIFEST_URL.format(platform=plat)
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
    if os.environ.get("RETROBIOS_BASE_URL"):
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


class _TuiTerminal:
    """The terminal in raw mode: keys in, frames out, put back as found."""

    def __init__(self, stdin: TextIO, stdout: TextIO) -> None:
        self.stdin, self.stdout = stdin, stdout
        self.fd = stdin.fileno()
        self.saved: list | None = None
        self.decoder = KeyDecoder()
        self.input = TerminalInput(getattr(stdin, "encoding", None) or "utf-8")
        self.encoding = getattr(stdout, "encoding", None) or "utf-8"
        locale_name = os.environ.get("LC_ALL") or os.environ.get("LANG") or ""
        try:
            utf8 = codecs.lookup(self.encoding).name == "utf-8"
        except LookupError:
            utf8 = False
        # Python turns a C locale into UTF-8 for itself, not for the
        # terminal: a console font there has no CJK, often no accents.
        self.ascii = not utf8 or locale_name in ("C", "POSIX")
        # The same text without colour: NO_COLOR, a dumb or unset TERM, a
        # description naming fewer than 8 colours, an output no terminal.
        self.colour = not colour_blocker(os.environ, stdout) and _enable_ansi()
        self.ended = False
        self.heard = 0.0
        self.frame: list[tuple[str, str]] = []
        self.entered = False
        # Whether clicks may be asked for here (tui_mouse_blocker), and
        # whether they are now: off on a screen whose text is copied.
        self.mouse_allowed = not tui_mouse_blocker(stdin, stdout)
        self.mouse = False

    def set_mouse(self, on: bool) -> None:
        """Ask for clicks or give them back to the terminal, written only
        when that changes."""
        on = on and getattr(self, "mouse_allowed", False) and self.entered
        if on != getattr(self, "mouse", False):
            self.mouse = on
            self.write(_MOUSE_ON if on else _MOUSE_OFF)

    def enter(self) -> None:
        if os.name != "nt":
            import termios

            # Entered again after a stop, the mode to go back to stays the
            # one found the first time.
            if self.saved is None:
                self.saved = termios.tcgetattr(self.fd)
            mode = termios.tcgetattr(self.fd)
            mode[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR | termios.IXON)
            # ISIG off: Ctrl-C arrives as a key and is forwarded once, by hand.
            mode[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN)
            mode[6][termios.VMIN] = 1
            mode[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, mode)
        self.entered = True
        self.write(_SCREEN_ON)

    def leave(self) -> None:
        """The main screen and the mode found, the mode even when the write
        fails: a closed window answers EIO."""
        try:
            # Never entered (stopped while it started): the main screen and
            # the cursor are as they were, nothing is written over them.
            if getattr(self, "entered", True):
                self.entered = False
                # The mouse modes go with the screen (_SCREEN_OFF), and come
                # back with the next frame once entered again.
                self.mouse = False
                self.write(_SCREEN_OFF)
        finally:
            if self.saved is not None:
                import termios

                saved, self.saved = self.saved, None
                termios.tcsetattr(self.fd, termios.TCSADRAIN, saved)

    def write(self, text: str) -> None:
        self.stdout.write(text.encode(self.encoding, "replace").decode(self.encoding))
        self.stdout.flush()

    def size(self) -> tuple[int, int]:
        return _terminal_size(self.stdout)

    def draw(self, lines: list[str], cols: int) -> None:
        """Rewrite the lines that changed since the last frame, and only those."""
        out = [] if self.frame else ["\x1b[H\x1b[2J"]
        frame = [(str(line), getattr(line, "style", "")) for line in lines]
        covered = 0
        for index, (text, style) in enumerate(frame):
            if style == "cont" and covered:
                # A row the long line above folds into.
                covered -= 1
                continue
            covered = (max(0, -(-cell_width(text) // max(1, cols)) - 1)
                       if style == "long" else 0)
            if index < len(self.frame) and self.frame[index] == (text, style):
                continue
            text = screen_text(text)
            if getattr(self, "ascii", False):
                text = ascii_text(text)
            if style == "focus":
                text = _pad(text, min(cols, TUI_MAX_WIDTH) - (index == len(frame) - 1))
            out.append(f"\x1b[{index + 1};1H"
                       f"{tui_paint(text, style, getattr(self, 'colour', False))}\x1b[0m\x1b[K")
        self.frame = frame
        if out:
            self.write("".join(out))

    def keys(self, timeout: float) -> list[TuiKey | TuiMouse]:
        if os.name == "nt":
            return self._console_keys(timeout)
        if self.ended:
            time.sleep(timeout)
            return []
        import select

        if not select.select([self.fd], [], [], timeout)[0]:
            # A paste whose end never came, after a second of silence.
            if self.decoder.paste is not None and time.monotonic() - self.heard > 1:
                return self.decoder.close_paste()
            return []
        keys = self._read()
        while self.decoder.buffer and not self.ended:
            if select.select([self.fd], [], [], TUI_ESC_WAIT)[0]:
                keys += self._read()
            else:
                self.input.flush()
                keys += self.decoder.flush()
                break
        return keys

    def _read(self) -> list[TuiKey | TuiMouse]:
        data = os.read(self.fd, 4096)
        self.heard = time.monotonic()
        if not data:
            # The terminal went away: what Ctrl-D at a question does.
            self.ended = True
            return [TuiKey("ctrl-d")]
        return self.decoder.feed(self.input.decode(data))

    def _console_keys(self, timeout: float) -> list[TuiKey | TuiMouse]:
        import importlib

        # typeshed declares msvcrt for win32 only: the module is read as the
        # runtime holds it.
        msvcrt = importlib.import_module("msvcrt")
        kbhit: Callable[[], bool] = msvcrt.kbhit
        getwch: Callable[[], str] = msvcrt.getwch
        end = time.monotonic() + timeout
        keys: list[TuiKey | TuiMouse] = []
        while True:
            while kbhit():
                key = decode_windows_key(getwch(), getwch)
                if key is not None:
                    keys.append(key)
            if keys or time.monotonic() >= end:
                return keys
            time.sleep(0.01)


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


def tui_farewell(state: TuiState) -> list[str]:
    """What stays in the terminal once the full screen is gone."""
    return [screen_text(line) for line in _farewell_lines(state)]


def tui_idle_code(state: TuiState) -> int:
    """The exit code of an idle close: an error's or a result's on those
    screens, so a launcher tells them from a close with nothing to say.
    Elsewhere nothing was installed, and 0 said it all was: QUIT_CODE, as a
    quit before the install."""
    if state.screen == "error":
        return state.error_code
    if state.screen == "result" and state.code is not None:
        return state.code
    return QUIT_CODE


def _farewell_lines(state: TuiState) -> list[str]:
    lines = _said_lines(state)
    # The version note in every farewell of a run that read it: with
    # everything in place it was the one thing left to say, and the
    # farewell said only that.
    if state.version and state.screen != "crashed" and state.version not in lines:
        lines.append(state.version)
    return lines


def _said_lines(state: TuiState) -> list[str]:
    if not state.idle_closed:
        return _closing_lines(state)
    idle = f"RetroBIOS: {TUI_IDLE_WORDS}"
    # What an error or a result screen said stays said.
    if state.screen in ("error", "result"):
        return [idle, *_closing_lines(state)]
    return [idle]


def _closing_lines(state: TuiState) -> list[str]:
    if state.screen not in ("result", "details") and state.download is not None:
        # An install ran: what it wrote is said, whatever ended it.
        title, lines = tui_outcome(state)
        return [f"RetroBIOS: {title}", *_terminal_words(_farewell_shown(state, lines))]
    if state.screen == "crashed":
        return [f"RetroBIOS stopped on an unexpected error. What it was is in {state.log}."]
    if state.screen == "result" or (state.screen == "details" and "result" in state.stack):
        title, lines = tui_outcome(state)
        return [f"RetroBIOS: {title}", *_terminal_words(_farewell_shown(state, lines))]
    if state.screen == "error":
        return [f"RetroBIOS: {state.error_title or 'something went wrong'}",
                *(line.replace("then choose Try again", "then run the installer again")
                  for line in state.error)]
    if state.exit_code == 0:
        return [f"RetroBIOS: everything is in place in {state.dest}."]
    if state.quit_asked:
        return [TUI_QUIT_WORDS]
    return ["RetroBIOS: stopped. Nothing was installed."]


TUI_QUIT_WORDS = "RetroBIOS: quit. Nothing was installed."


def _farewell_shown(state: TuiState, lines: list) -> list:
    """The result as the terminal keeps it: Details too once they were
    opened, as the result's copy hint says."""
    return list(lines) if state.details_seen else _shown(state, lines)


def _terminal_words(lines: list[str]) -> list[str]:
    """The result's lines as the terminal prints them after the screen."""
    return [line.replace(TUI_SAVE_REMEDY, LINE_SAVE_REMEDY) for line in lines
            if line not in (TUI_RESULT_COPY, TUI_RESULT_AGAIN)]


def tui_quit_chosen(state: TuiState) -> bool:
    """Whether the screen ended on a quit the user chose, nothing installed."""
    return tui_farewell(state) == [TUI_QUIT_WORDS]


CTRL_Z_NO_SHELL = ("Ctrl-Z is ignored: no shell started this installer, and none could "
                   "bring it back.")


def tui_ctrl_z(state: TuiState) -> bool:
    """Whether a Ctrl-Z typed on the screen stops it: only where a shell
    with job control can resume it, the installer's process group being one
    of its jobs, not its session's own. Started from a terminal app's -e,
    a desktop entry or a launcher's sh -c, nothing ever sent SIGCONT, and
    the screen and its launcher stayed stopped for good. Otherwise the key is
    ignored and the bar says why."""
    if (hasattr(signal, "SIGSTOP") and hasattr(os, "getsid")
            and os.getpgrp() != os.getsid(0)):
        return True
    state.status, state.status_more = CTRL_Z_NO_SHELL, ""
    return False


def tui_suspend(runs: list[_EngineRun], whole: bool) -> None:
    """Stop the screen and the runs it started until fg continues them.

    whole is a Ctrl-Z typed on the screen, which stops what the terminal's
    Ctrl-Z stops: every process of the foreground group. The installer
    stopping alone left install.sh, run as `sh install.sh` or `curl | sh`,
    waiting on it, and the shell never got its prompt back. A kill -TSTP
    sent to the installer stops the installer alone. The runs are stopped
    either way, an install having gone on writing behind a stopped screen.
    """
    for run in runs:
        run.pause(True)
    if whole:
        # SIGSTOP and not SIGTSTP: a group no shell watches over (the
        # installer started on a terminal of its own) discards SIGTSTP.
        os.killpg(os.getpgrp(), signal.SIGSTOP)
    else:
        os.kill(os.getpid(), signal.SIGSTOP)
    for run in runs:
        run.pause(False)


class _TuiSignals:
    """What the signal handlers saw, read by the screen between frames."""

    def __init__(self) -> None:
        self.interrupt = False
        self.resized = False
        # True from SIGTSTP, "key" from Ctrl-Z read as a key.
        self.suspend: bool | str = False
        self.resume = False
        self.term = 0

    def on_stop(self, signum: int, _frame: object) -> None:
        self.term = self.term or signum

    def on_interrupt(self, _signum: int, _frame: object) -> None:
        self.interrupt = True

    def on_resize(self, _signum: int, _frame: object) -> None:
        self.resized = True

    def on_suspend(self, _signum: int, _frame: object) -> None:
        self.suspend = True

    def on_resume(self, _signum: int, _frame: object) -> None:
        self.resume = True


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


class _TuiSession:
    """One full-screen run: its state, its child runs, and the frame loop."""

    def __init__(self, state: TuiState, work: Path, signals: _TuiSignals) -> None:
        self.state = state
        self.work = work
        self.signals = signals
        self.script = str(Path(__file__).resolve())
        self.inbox: queue.Queue = queue.Queue()
        self.current: list[_EngineRun] = []
        self.written: dict[str, Path] = {}
        # Select+Start on a handheld is gptokeyb's pkill: SIGTERM, then SIGKILL
        # 3 s later. The install gets 2 s to say what it wrote.
        self.terminating = 0
        self.deadline = 0.0
        self.ignore_interrupt_until = 0.0
        self.buffer = io.StringIO()
        self.quiet_since = 0.0
        self.pressed = False

    def write_lists(self) -> None:
        """The list and its boards beside it, for a run the list is not given to."""
        state, work, written = self.state, self.work, self.written
        if state.platform not in written:
            path = work / f"{state.platform}.json"
            path.write_text(json.dumps(state.manifest), encoding="utf-8")
            written[state.platform] = path
        state.manifest_path = written[state.platform]
        if state.targets_for == state.platform and state.targets:
            # Beside the list, where a --target run without the
            # internet reads the boards (local_targets).
            boards = work / "targets" / f"{state.platform}.json"
            boards.parent.mkdir(exist_ok=True)
            boards.write_text(json.dumps(state.targets), encoding="utf-8")
            written[f"targets:{state.platform}"] = boards

    def start_run(self, run: str) -> None:
        state = self.state
        for engine in self.current:
            engine.stop(0)
        self.current.clear()
        if not state.manifest_given and not state.packs and state.manifest:
            self.write_lists()
        log = self.work / f"{run}.log"
        if run == "install":
            state.log = str(log)
        own_list = state.manifest_path in self.written.values()
        try:
            self.current.append(_EngineRun(
                tui_argv(state, run, sys.executable, self.script), log, self.inbox,
                state.run_id, tui_run_env(state, own_list)))
        except OSError as exc:
            self.inbox.put(("ended", state.run_id, 1,
                            [f"The installer could not be started: {exc}"]))

    def perform_aside(self, effect: tuple) -> None:
        """An effect that starts no child run and stops none."""
        kind, state, inbox = effect[0], self.state, self.inbox
        if kind == "fetch":
            threading.Thread(target=_tui_fetch_games,
                             args=(effect[1], inbox, self.buffer, state.dest,
                                   state.games_choice not in ("user", "cli", "record")),
                             daemon=True).start()
        elif kind == "app":
            threading.Thread(target=_tui_put_app, args=(effect[1], inbox),
                             daemon=True).start()
        elif kind == "targets":
            threading.Thread(target=_tui_fetch_targets, args=(effect[1], inbox, self.buffer),
                             daemon=True).start()
        elif kind == "pack":
            inbox.put(("pack_opened", effect[1],
                       *open_tui_pack(effect[1], state.platform)))
        elif kind == "use_pack":
            use_tui_pack(effect[1])
        elif kind == "close_pack":
            effect[1].close()
        elif kind == "offline":
            set_offline(effect[1])

    def perform(self, todo: list[tuple], from_key: bool = True) -> None:
        for effect in todo:
            kind = effect[0]
            if kind == "run":
                self.start_run(effect[1])
            elif kind == "stop":
                for run in self.current:
                    run.interrupt(from_key)
                if os.name == "nt" and from_key:
                    self.ignore_interrupt_until = time.monotonic() + 1.0
            elif kind == "kill":
                for run in self.current:
                    run.stop(0)
            else:
                self.perform_aside(effect)

    def wake(self, terminal: _TuiTerminal) -> tuple[int, int]:
        """The terminal back after a suspend, and its size."""
        state, signals = self.state, self.signals
        if signals.suspend:
            # The shell gets its terminal back as it lent it, and the
            # screen returns on fg.
            whole = signals.suspend == "key"
            signals.suspend = False
            terminal.leave()
            tui_suspend(self.current, whole)
            signals.resume = True
        if signals.resume:
            signals.resume = False
            terminal.enter()
            terminal.frame = []
        cols, rows = terminal.size()
        if (cols, rows) != (state.cols, state.rows) or signals.resized:
            signals.resized = False
            state.cols, state.rows = cols, rows
            terminal.frame = []
        return cols, rows

    def draw(self, terminal: _TuiTerminal, cols: int, rows: int) -> None:
        state = self.state
        state.now = time.monotonic()
        lines = tui_view(state, cols, rows)
        # A click is read against the frame it was made on.
        before = state.hits
        hits = state.hits = tui_hits(state, lines)
        # Before the frame: a frame on screen takes clicks as it shows.
        terminal.set_mouse(tui_wants_mouse(state, lines))
        terminal.draw(lines, cols)
        if before is None or hits.shown != before.shown:
            # A new screen's settle runs from when it is on the screen,
            # after its layout and its write: the second click of a
            # double click waited out a slow layout in the input and
            # acted on the screen it had never seen.
            state.hits = hits._replace(shown=time.monotonic())

    def take_keys(self, terminal: _TuiTerminal) -> None:
        state = self.state
        for key in terminal.keys(TUI_FRAME):
            if key.name == "ctrl-z":
                # ISIG is off, so Ctrl-Z comes as a key: it stops what
                # the terminal's would, where a shell can resume it.
                if tui_ctrl_z(state):
                    self.signals.suspend = "key"
                    break
                continue
            self.pressed = True
            state.now = time.monotonic()
            self.perform(tui_update(state, key))
            if state.exit_code is not None:
                break

    def take_signals(self, idle: float | None) -> None:
        """The idle timer, Ctrl-C and a stop signal, between frames."""
        state, signals = self.state, self.signals
        if state.running:
            self.quiet_since = time.monotonic()
        elif (idle is not None and not self.pressed and state.exit_code is None
                and time.monotonic() - self.quiet_since >= idle):
            state.idle_closed, state.exit_code = True, tui_idle_code(state)
        if signals.interrupt:
            signals.interrupt = False
            if time.monotonic() >= self.ignore_interrupt_until:
                self.perform(tui_interrupt(state), from_key=False)
        if signals.term and not self.terminating:
            self.terminating = signals.term
            if state.run == "install" and state.running:
                self.deadline = time.monotonic() + 2
                if not state.stopping:
                    self.perform(tui_interrupt(state))
            elif state.screen == "result" and state.code is not None:
                state.exit_code = state.code
            else:
                state.exit_code = 128 + self.terminating
        if self.terminating and state.running and time.monotonic() > self.deadline:
            self.perform([("kill",)])

    def take_messages(self) -> None:
        state = self.state
        while state.exit_code is None:
            try:
                message = self.inbox.get_nowait()
            except queue.Empty:
                break
            state.now = time.monotonic()
            self.perform(tui_receive(state, message))
        if self.terminating and state.screen == "result":
            # The result is printed in the terminal on the way out.
            state.exit_code = state.code if state.code is not None else 1

    def loop(self, terminal: _TuiTerminal, effects: list[tuple],
             handlers: dict[int, object]) -> None:
        state, signals = self.state, self.signals
        for name, handler in (("SIGINT", signals.on_interrupt), ("SIGWINCH", signals.on_resize),
                              ("SIGTSTP", signals.on_suspend), ("SIGCONT", signals.on_resume)):
            number = getattr(signal, name, None)
            if number is not None:
                handlers[number] = signal.signal(number, handler)
        idle = tui_idle_exit()
        # Counted from the moment the screen last waited for a key with no
        # run going: given --platform, the first screen moves on by itself
        # to the plan once the check is read, and no key comes either.
        self.quiet_since, self.pressed = time.monotonic(), False
        sys.stdout = sys.stderr = self.buffer
        try:
            _prune_work_folders(self.work.parent, time.time())
        except OSError as exc:
            # What earlier runs left stays until a later run: this one opens.
            print(f"Earlier work folders could not be removed: {exc}", file=sys.stderr)
        if state.exit_code is None:
            # Stopped while it started: the screen never opens.
            terminal.enter()
            self.perform(effects)
        while state.exit_code is None:
            cols, rows = self.wake(terminal)
            self.draw(terminal, cols, rows)
            self.take_keys(terminal)
            self.take_signals(idle)
            self.take_messages()


def _tui_goodbye(state: TuiState, problems: list) -> int:
    """The farewell printed in the terminal, and the exit code."""
    # A quit chosen goes where an error goes, its code not 0: a launcher
    # reads its first line there and stays silent (ports/shared/tui.txt).
    stream = (sys.stderr if state.screen in ("error", "crashed") or tui_quit_chosen(state)
              else sys.stdout)
    lines = tui_farewell(state)
    if problems:
        lines.append(f"The terminal may not be restored ({problems[0]}): type reset "
                     "and press Enter if it looks wrong.")
    try:
        for line in lines:
            print(line, file=stream)
        stream.flush()
    except OSError:
        # The terminal is gone (a closed window answers EIO, a closed pipe
        # EPIPE): the exit code is all that still reaches anyone, and the
        # flush at exit would replace it with 120.
        _drop_closed_terminal()
    return state.exit_code if state.exit_code is not None else 1


def run_tui(args: argparse.Namespace) -> int:
    """The full-screen interface, until it closes: the exit code it ends with."""
    signals = _TuiSignals()
    handlers: dict[int, object] = {}
    # Before the start, whose detection and pack opening take seconds on a
    # handheld: a Select+Start then ended on the default action, without a
    # word or the terminal put back.
    for name in ("SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is not None:
            handlers[number] = signal.signal(number, signals.on_stop)
    try:
        started = _tui_startup(args)
    except BaseException:
        _restore_handlers(handlers)
        raise
    if started is None:
        _restore_handlers(handlers)
        return 1
    state, effects = started
    if signals.term:
        state.exit_code = 128 + signals.term
    work = _tui_work_folder(handlers)
    if work is None:
        return 1
    session = _TuiSession(state, work, signals)
    terminal = _TuiTerminal(sys.stdin, sys.stdout)
    state.mouse = getattr(terminal, "mouse_allowed", False)
    real_out, real_err = sys.stdout, sys.stderr
    try:
        session.loop(terminal, effects, handlers)
    except Exception as exc:
        if signals.term or _closed_terminal(exc, terminal):
            # The window closed under a screen that was changing, or the
            # SIGCONT that comes with its SIGHUP put the screen back: the
            # write failed before the signal was read. That is its exit.
            state.exit_code = 128 + (signals.term or getattr(signal, "SIGHUP", 1))
        else:
            _tui_crashed(state, work)
    finally:
        # Each step on its own: a write the closed window refuses, or a
        # second signal while the install writes its summary, must not
        # skip the ones after it and leave the terminal raw.
        problems = _tui_cleanup(terminal, session.current, handlers, state)
        sys.stdout, sys.stderr = real_out, real_err
        for path in session.written.values():
            if path.exists():
                path.unlink()
        if not tui_keeps_log(state):
            shutil.rmtree(work, ignore_errors=True)
        else:
            _mark_kept(work)
    return _tui_goodbye(state, problems)


def _tui_startup(args: argparse.Namespace) -> tuple[TuiState, list[tuple]] | None:
    """The local sources opened and the first screen chosen, None when a
    --from folder cannot be read (said on stderr)."""
    os_type = _INVOCATION.os_type or detect_os()
    if os_type == "wsl":
        _enter_wsl()
        _wsl_dest(args)
    # The --from folders are read by each check, not here: indexing a large
    # card held the first frame back. Only whether each can be read is asked.
    folders = getattr(args, "from") or []
    setattr(args, "from", None)
    try:
        _open_local_sources(args)
    finally:
        setattr(args, "from", folders)
    for folder in folders:
        problem = from_folder_problem(str(folder))
        if problem is not None:
            print(f"Error: {screen_text(str(folder))} {problem[1]}: --from names the folder "
                  "to copy BIOS files from.", file=sys.stderr)
            return None
    return tui_start(args, os_type)


# What a write to a closed window or a closed pipe answers.
_CLOSED_TERMINAL = frozenset({errno.EIO, errno.EPIPE, errno.ENXIO})


def _closed_terminal(exc: BaseException, terminal: _TuiTerminal | None = None) -> bool:
    """Whether exc is the terminal gone: an OSError, or a termios.error,
    whose first argument is the errno, answering EIO, EPIPE or ENXIO, and,
    given the terminal, that terminal no longer answering. A failing SD
    card answers EIO too, and that read error is kept in a crash log."""
    if isinstance(exc, OSError):
        closed = exc.errno in _CLOSED_TERMINAL
    elif type(exc).__name__ == "error" and type(exc).__module__ == "termios":
        closed = bool(exc.args) and exc.args[0] in _CLOSED_TERMINAL
    else:
        closed = False
    return closed and (terminal is None or _terminal_gone(terminal))


def _terminal_gone(terminal: _TuiTerminal) -> bool:
    """Whether the terminal hung up: a closed window answers EIO to
    tcgetattr and to a write, a live one its settings. A Windows console
    has no settings to ask, and an empty write to it reaches nothing: the
    error is taken as it reads."""
    if os.name == "nt":
        return True
    import termios

    try:
        termios.tcgetattr(terminal.fd)
        terminal.stdout.write("")
        terminal.stdout.flush()
    except (termios.error, OSError, ValueError):
        return True
    return False


def _tui_crashed(state: TuiState, work: Path) -> None:
    """A traceback is where every reporter of #71, #73 and #74 stopped: it
    goes to a file, and the terminal says one sentence."""
    crash = work / "error.log"
    try:
        crash.write_text(traceback.format_exc(), encoding="utf-8")
    except OSError as exc:
        print(f"The error could not be written to {crash}: {exc}", file=sys.stderr)
    state.log, state.code, state.exit_code = str(crash), 1, 1
    state.stack = ["crashed"]


def _restore_handlers(handlers: dict) -> None:
    for number, previous in handlers.items():
        signal.signal(number, previous)


def _drop_closed_terminal() -> None:
    """Point stdout and stderr at nothing once the terminal is gone, so what
    they still hold is flushed somewhere at exit."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        # No null device to point them at: the flush at exit fails as before.
        return
    try:
        for stream in (sys.stdout, sys.stderr):
            try:
                fd = stream.fileno()
            except (ValueError, AttributeError, io.UnsupportedOperation):
                # A stream with no descriptor (a test's StringIO) has no
                # terminal behind it to lose.
                continue
            os.dup2(null, fd)
    finally:
        os.close(null)


def _tui_cleanup(
    terminal: _TuiTerminal, runs: list[_EngineRun], handlers: dict, state: TuiState,
) -> list[str]:
    """Stop the child, put the terminal and the signal handlers back: what failed."""
    failures: tuple = (OSError, ValueError)
    if os.name != "nt":
        import termios

        failures += (termios.error,)
    problems: list[str] = []

    def step(action: Callable[[], object]) -> None:
        try:
            action()
        except failures as exc:
            problems.append(str(exc) or type(exc).__name__)

    for name in ("SIGTERM", "SIGHUP", "SIGTSTP"):
        number = getattr(signal, name, None)
        if number is not None:
            step(functools.partial(signal.signal, number, signal.SIG_IGN))
    # An install stopped by a signal still gets to write its summary.
    for run in runs:
        step(functools.partial(run.stop, 10 if state.running and state.run == "install"
                               else 0))
    step(terminal.leave)
    for number, previous in handlers.items():
        step(functools.partial(signal.signal, number, previous))
    return problems
