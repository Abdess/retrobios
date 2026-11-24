"""The full-screen session: its loop from start to farewell, and the end it gives a crash."""
from __future__ import annotations

import argparse
import io
import json
import os
import queue
import shutil
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

from installer.console import QUIT_CODE
from installer.detect_os import _enter_wsl, _wsl_dest, detect_os
from installer.from_folders import from_folder_refusal, open_list_and_pack, reset_local_sources
from installer.games import games_folder_refusal
from installer.invocation import _INVOCATION, OFFLINE_VARIABLE
from installer.offline import OFFLINE_FLAG_VALUE
from installer.outcome import LINE_SAVE_REMEDY
from installer.text import screen_text
from installer.tui_actions import open_tui_pack, use_tui_pack
from installer.tui_steps import tui_interrupt
from installer.tui_commands import tui_argv, tui_run_env
from installer.tui_engine import (
    _EngineRun,
    _mark_kept,
    _prune_work_folders,
    _restore_handlers,
    _tui_fetch_games,
    _tui_fetch_targets,
    _tui_put_app,
    _tui_work_folder,
)
from installer.tui_input import tui_hits, tui_update
from installer.tui_outcome import TUI_RESULT_AGAIN, TUI_RESULT_COPY, tui_keeps_log, tui_outcome
from installer.tui_plan_view import TUI_SAVE_REMEDY, _shown
from installer.tui_receive import tui_receive
from installer.tui_routes import (
    TUI_IDLE_WORDS,
    tui_idle_exit,
    tui_wants_mouse,
)
from installer.tui_help import tui_view
from installer.tui_state import TuiState

from installer.tui_first_screen import tui_start
from installer.tui_terminal import (
    _TuiSignals,
    _TuiTerminal,
    _closed_terminal,
    _drop_closed_terminal,
    _tui_cleanup,
    tui_ctrl_z,
    tui_suspend,
)

TUI_FRAME = 0.1


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
    if _quit_closing(state):
        return [TUI_QUIT_WORDS]
    return ["RetroBIOS: stopped. Nothing was installed."]


def _quit_closing(state: TuiState) -> bool:
    """Whether the screen closes on the quit the user asked for: no install
    ran, no result, error or crash to report, and the exit not a success."""
    if state.screen not in ("result", "details") and state.download is not None:
        return False
    if state.screen in ("crashed", "error", "result"):
        return False
    if state.screen == "details" and "result" in state.stack:
        return False
    return state.exit_code != 0 and state.quit_asked


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
    """Whether the screen ended on a quit the user chose, nothing installed:
    read from the state, so a version note after the quit line changes
    nothing."""
    return not state.idle_closed and _quit_closing(state)


def set_offline(on: bool) -> None:
    """Without the internet on or off for this process and the runs it
    starts, as --offline sets it."""
    if on:
        os.environ[OFFLINE_VARIABLE] = OFFLINE_FLAG_VALUE
    else:
        os.environ.pop(OFFLINE_VARIABLE, None)


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
                             args=(effect[1], inbox, state.dest,
                                   state.games_choice not in ("user", "cli", "record")),
                             daemon=True).start()
        elif kind == "app":
            threading.Thread(target=_tui_put_app, args=(effect[1], inbox),
                             daemon=True).start()
        elif kind == "targets":
            threading.Thread(target=_tui_fetch_targets, args=(effect[1], inbox),
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
    --from or --for-games folder cannot be read (said on stderr)."""
    os_type = _INVOCATION.os_type or detect_os()
    if os_type == "wsl":
        _enter_wsl()
        _wsl_dest(args)
    reset_local_sources(args)
    open_list_and_pack(args)
    # The --from folders are read by each check, not here: indexing a large
    # card held the first frame back. Only whether each can be read is asked.
    for folder in getattr(args, "from") or []:
        refusal = from_folder_refusal(str(folder))
        if refusal is not None:
            for line in refusal.lines:
                print(line, file=sys.stderr)
            return None
    refusal = games_folder_refusal(getattr(args, "for_games", None), args.platform or "")
    if refusal is not None:
        for line in refusal.lines:
            print(line, file=sys.stderr)
        return None
    return tui_start(args, os_type)


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
