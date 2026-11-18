"""The full-screen interface: its state, how it starts, and the runs it starts."""
from __future__ import annotations

import argparse
import io
import os
import re
import sys
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TextIO

from installer.app import CardApp, card_app
from installer.invocation import OFFLINE_VARIABLE, Invocation, offline_option
from installer.line_ui import TUI_MIN_COLS, emulator_names
from installer.narrowing import choosable_cores
from installer.offline import LOCAL, OFFLINE_FLAG_VALUE
from installer.probe import _is_dir
from installer.record import RECORD_NARROWING, record_argv, record_options
from installer.run import TUI_LIST_ENV, TUI_MIN_ROWS, TUI_MOUSE_ENV, TUI_RECORD_ENV
from installer.tally import leave_out_game_data
from installer.terminal import _enable_ansi, terminal_few_colours, terminal_without_ansi
from installer.text import screen_text

if TYPE_CHECKING:
    from installer.tui_session import TuiHits

# Full-screen interface
#
# A bare run at a terminal opens it, and --tui asks for it. It decides and the
# installer acts: every check and install is this file run again as a child,
# with --events, the contract the handheld port reads, and the choices made on
# screen as its options. The line questions stay behind --plain, for screen
# readers and for any terminal this cannot drive. Stdlib only: curses is
# missing from Windows CPython and from some Buildroot images.


class TuiState:
    """Everything the screens show. Nothing here touches the terminal."""

    def __init__(self, os_type: str = "linux", home: Path | None = None) -> None:
        self.os_type = os_type
        self.home = home or Path("/home/user")
        # The buttons the bar names: a pad route (TUI_PAD_ROUTES), "keys"
        # for a keyboard alone, "both" where the code cannot tell.
        self.pad: str = "both"
        self.stack: list = ["setup"]
        self.focus: dict = {}
        self.filters: dict = {}
        self.editing: str = ""
        self.help: bool = False
        self.status: str = ""
        # What the status says in full, shown under it where there is room
        # and in the help: the folder refused and what was looked for.
        self.status_more: str = ""
        self.cols: int = 80
        self.rows: int = 24
        # A check started before the loop's first tick counted the
        # machine's uptime.
        self.now: float = time.monotonic()
        # (platform, folder, label) for each setup found here.
        self.setups: list = []
        # (platform, card) of each mounted drive whose files fit two systems
        # (share_doubt): offered under each, never taken for one.
        self.doubts: list = []
        # (platform, folder) of the setups that are a card in a reader, not
        # this machine: a setup chosen for that system asks for its card.
        self.mounted_setups: set = set()
        self.notes: list = []
        # The folders detection could not look in, one line each.
        self.refused: list = []
        self.platform: str = ""
        self.dest: Path | None = None
        # A --dest given without --platform: the list asks whose files go there.
        self.dest_given: Path | None = None
        self.folder_default: Path | None = None
        # What folder_default is, for the words above it: "usual" (the
        # platform's built-in folder), "found" (the one detected here),
        # "chosen" (the run's folder, from Change folder) or "closed" (the
        # one chosen could not be opened, none is offered).
        self.folder_kind: str = "usual"
        # (system, BIOS folder below the card root) when the setup asked for
        # runs from an SD card: the folder screen offers the mounted cards.
        self.card_bound: tuple[str, str] | None = None
        # What card_choice said of the card chosen (a stick nothing names
        # taken for KNULLI), kept from Create the folder? to the plan.
        self.card_note: str = ""
        # The rows the last view drew in its list, what a page moves by.
        self.page_rows: int = 0
        self._init_frame()
        self._init_run()
        self._init_install()

    def _init_frame(self) -> None:
        # The targets of the frame on screen (tui_hits), the target a
        # button went down on, and per screen the first row of a list the
        # wheel scrolled.
        self.hits: TuiHits | None = None
        self.pressed: tuple | None = None
        # The row a tap last focused, with its screen and depth: a second
        # tap on it opens it. A screen just opened has none, so the row it
        # opens on is never chosen by one tap.
        self.tapped: tuple | None = None
        # Whether the terminal reports clicks here (tui_mouse_blocker): the
        # help and the bar say how to tap only then.
        self.mouse: bool = False
        self.list_top: dict = {}
        # The mounted cards of that system, as last looked for.
        self.cards: list | None = None
        # (width and text, lines) of the last pager wrapped.
        self.pager_cache: tuple | None = None
        self.path_text: str = ""
        self.browse_dir: Path | None = None
        self.browse_rows: list = []
        self.manifest: dict | None = None
        self.manifest_for: str = ""
        self.manifest_path: Path | None = None
        self.manifest_given: bool = False
        self.error: list = []
        self.error_title: str = ""
        self.error_code: int = 1
        # Typed over in one key: a field opening on a long path took one
        # Backspace per character before anything could be typed.
        self.path_selected: bool = False
        # The ticks kept across a check run again for new options.
        self.keep_ticked: set | None = None
        # The regions in the order Preferred regions opened on: kept while
        # it is open, whatever is ticked.
        self.region_order: list[str] = []
        # The cores of every system listed, after "Cores of the other systems".
        self.cores_all: bool = False
        # None pressed on Cores: no core ticked, which no option says
        # (state.cores empty is every core). Done is refused until one is.
        self.no_cores: bool = False
        # The cores --core named, as line mode names them on its head.
        self.cli_cores: list = []
        # The names of the systems ticked before a check counted again, and
        # those of them that hold nothing under its options.
        self.ticked_names: dict[str, str] = {}
        self.emptied: list[str] = []
        # Systems ticked that the last check did not list, game data left
        # out: still the choice, ticked again by the check that lists them
        #, as line mode's g keeps its choice.
        self.hidden_ticks: set[str] = set()
        # Choose systems asked on a plan --system narrowed: the systems are
        # opened once the check of every system is in.
        self.widen: bool = False
        # The plan row a recount started from, focused again once it is in:
        # the plan came back on Install, and a second Enter to undo the
        # Game data change opened Confirm.
        self.refocus: str = ""
        # The --system plan Choose systems widened, by _CHECK_FIELDS.
        self.widened_from: dict | None = None
        # (files read, files to read) while the check hashes what is in place.
        self.reading: tuple | None = None
        # Folders to copy BIOS files from (--from), and what the check found.
        self.from_folders: list = []
        self.found: list = []
        # What the browser is choosing: the BIOS folder, or one to copy from.
        self.browse_for: str = "dest"
        # Files an install copies from this machine, whose bytes are no
        # download: dest to (folder, reason), reason set for a misplaced one.
        self.local_dests: dict = {}
        # Per --from folder, its scanned event, and the files on those
        # folders that could not be read (unreadable events).
        self.scanned: list = []
        self.unreadable: list = []

    def _init_run(self) -> None:
        # The child run in progress: check, confirm, preview or install.
        self.run: str = ""
        self.running: bool = False
        self.run_id: int = 0
        self.started: float = 0.0
        self.checked_flags: list = []
        self.check: dict | None = None
        # The systems the check's list lets one choose among (choices event).
        self.choices: list | None = None
        # The install's error event when its BIOS folder could not be made.
        self.dest_error: dict | None = None
        # The dests the check set aside before any choice (the set_aside
        # event), None before it says: Cores chooses among the rest.
        self.set_aside: set | None = None
        # The run's file list and the Cores rows' sizes, kept while the
        # list, the set aside files and the game data choice stay.
        self.run_files_cache: tuple | None = None
        self.core_sizes_cache: tuple | None = None
        self.files: list = []
        # Every destination the check named, in place or not: the second
        # spellings a folder that keeps case installs are among them.
        self.checked_dests: set = set()
        self.systems: list = []
        self.facts: dict = {}
        self.dry: dict | None = None
        self.dry_files: list = []
        self.dry_summary: dict | None = None
        # Closed by RETROBIOS_IDLE_EXIT, no key ever pressed.
        self.idle_closed = False
        # The check run's summary: what it left out and why.
        self.check_summary: dict | None = None
        # The saves event of the check: the files that go to the save folder.
        self.saves: dict | None = None
        # The version event of the check: the list built for another
        # release than the one this machine runs, said on the plan and the
        # result as line mode says it.
        self.version: str = ""
        # The note in one line, for a plan with no room for its sentences.
        self.version_short: str = ""
        # The board event of the check: the board read from the system or
        # its card, said on the plan.
        self.board: str = ""
        # The same of the confirm or preview run, and of the install: a
        # choice of systems can leave the save file out, or keep it.
        self.dry_saves: dict | None = None
        self.done_saves: dict | None = None
        # The confirm screen waits for A even when the plan is unchanged:
        # it was opened by Space, which never installs by itself.
        self.must_confirm: bool = False
        # Choices, each one an option of the command line.
        self.ticked: set = set()
        # The ticks the systems list opened with: Back with none ticked
        # brings them back, nothing having been chosen.
        self.ticked_before: set | None = None
        self.cli_systems: list = []
        self.regions: list = []
        self.cli_regions: list = []
        self.cores: list = []
        self.no_game_data: bool = False
        # --one-per-slot and --standalone, set on Change or given.
        self.one_per_slot: bool = False
        self.standalone: bool = False
        # --no-game-data on the command line: the plan has no game data row,
        # as line mode has no g then.
        self.cli_no_game_data: bool = False
        # A quit the user chose, said as one (tui_quit).
        self.quit_asked: bool = False
        self.installed_only: bool = False
        self.jobs: int = 8
        self.passthrough: list = []
        # Whether Details were opened on the result: the terminal keeps
        # them after Exit too.
        self.details_seen = False

    def _init_install(self) -> None:
        # The install.
        self.download: dict | None = None
        self.progress: dict | None = None
        # (time, bytes from the network) of the last transfer events: what
        # came from this machine (a copy, the pack, a partial file resumed)
        # is never in a speed.
        self.samples: list = []
        self.network: int = 0
        self.finished: list = []
        self.summary: dict | None = None
        self.code: int | None = None
        self.stopping: bool = False
        self.tail: list = []
        self.log: str = ""
        self.exit_code: int | None = None
        # The RetroBIOS app on the card the BIOS folder is on: asked for
        # (--add-app, the options), what putting it did (the app event),
        # and the card, read once per folder.
        self.add_app: bool = False
        self.app: dict | None = None
        self.app_running: bool = False
        self.card_for: Path | None = None
        self.card: CardApp | None = None
        # The games on the card (--for-games): None until a look at the card
        # or the user decides, then whether the runs read them. games_choice
        # says who decided: "probe", "user" or "cli".
        self.for_games: bool | None = None
        self.games_choice: str = ""
        # A games folder named with --for-games FOLDER.
        self.games_folder: Path | None = None
        self.required_only: bool = False
        # The (platform, folder) the card was looked at for, and how many of
        # its folders hold a game.
        self.games_probed: tuple | None = None
        self.games_here: int = 0
        # The check's games event, its reading progress, and why what the
        # games need could not be read.
        self.games: dict | None = None
        self.games_reading: tuple | None = None
        self.games_unavailable: dict | None = None
        # The install record of the setup and folder chosen (read for
        # record_for), whose choice the plan opens on when the command line
        # chose nothing (cli_choice), and the options of it no row shows.
        self.record: dict | None = None
        self.record_for: tuple | None = None
        self.record_flags: list = []
        self.cli_choice: bool = False
        # Opened on the plan of the one setup found: its Change where row
        # goes back to the setups.
        self.opened_on_plan: bool = False
        # The device chosen on Device (--target, "" for the board the run
        # reads itself) or every board (--every-board), the emulators
        # ticked on Emulators (--emulator), and the packs read in place of
        # the network (--from-pack).
        self.target: str = ""
        self.every_board: bool = False
        self.emulators: list[str] = []
        self.packs: list[Path] = []
        # The platform's board list, as fetched for Device: None until it
        # comes or when it could not be read, and why.
        self.targets: dict | None = None
        self.targets_for: str = ""
        self.targets_problem: str = ""
        # (platform, folder, board, applied, here) of the last board event:
        # kept across checks, a --target chosen since stops the event.
        self.board_seen: tuple | None = None
        # More: what to remove (the --system of a removal, none for
        # everything), whether into a backup, the plan its dry run read,
        # the backups listed and why, the one chosen, the action confirmed
        # (remove, restore, delete_backup), its events and its code.
        self.removal_scope: list[tuple[str, str]] = []
        self.removal_backup: bool = False
        self.removal: dict | None = None
        self.backups: list[dict] | None = None
        self.backups_for: str = "look"
        self.backup_chosen: dict | None = None
        self.action: str = ""
        self.action_events: list[dict] = []
        self.action_code: int | None = None
        # Whether the folder checked has a backup, read once each check.
        self.has_backups: bool = False
        # Make a pack: the folder it goes in (Downloads by default), what
        # its dry run said (the pack event), what the run made, its count
        # of files fetched so far and its code.
        self.pack_dir: Path | None = None
        self.pack_plan: dict | None = None
        self.pack_done: dict | None = None
        self.pack_fetched: tuple[int, int] | None = None
        self.pack_code: int | None = None

    @property
    def screen(self) -> str:
        return self.stack[-1]


def _env_on(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "") not in ("", "0")


def plain_requested(args: argparse.Namespace, env: Mapping[str, str] | None = None) -> bool:
    """Whether the line questions were asked for: --plain, RETROBIOS_PLAIN, ACCESSIBLE."""
    env = os.environ if env is None else env
    return bool(args.plain) or _env_on(env, "RETROBIOS_PLAIN") or _env_on(env, "ACCESSIBLE")


# Each handheld launcher names the buttons that reach the interface
# (ports/shared/tui.txt exports RB_PAD as this), so the bar names those
# buttons and no others.
TUI_PAD_ENV = "RETROBIOS_PAD"


class TuiRoute(NamedTuple):
    """How one input route names the keys, read by the screen and by
    scripts/generate_installer_doc.py for the key table of the page.

    bar maps a key of the bottom line, written in the "both" form ("A/Enter
    Install"), to the route's own name, None for a key the route lacks: a PC
    user read "A/Enter", a muOS player was told a Select+Start that muxterm
    does not have. help names each action of the help screen, the buttons
    first, then the keys a keyboard plugged in also has, None for an action
    the route lacks. stop is what stops an install the second time, then the
    first time.
    """

    bar: Mapping[str, str | None]
    help: Mapping[str, str | None]
    stop: tuple[str, str]


# retrobios.gptk: A Enter, B Esc, X Space, Y Tab, L1 and R1 a page, Start
# Enter, Select Esc, Select then Start the kill.
_GPTOKEYB = TuiRoute(
    {"A/Enter": "A", "B/Esc": "B", "X/Space": "X", "Y/o": "Y", "?": None, "/": None,
     "Ctrl-C": "Select+Start", "Enter": "A", "Esc": "B", "Ctrl-U": None},
    {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
     "tick": "X, Space, Right/Left", "options": "Y, Tab, o", "back": "B, Select, Esc",
     "stop": "B, Esc, Ctrl-C", "kill": "Select, then Start", "enter": "A, Enter",
     "esc": "B, Esc"},
    ("B", "B or Select+Start"))
# keys is a keyboard's, and both names the button and the key where nothing
# says which one is held. The others are the values of RETROBIOS_PAD.
TUI_ROUTES: dict[str, TuiRoute] = {
    "keys": TuiRoute(
        {"A/Enter": "Enter", "B/Esc": "Esc", "X/Space": "Space", "Y/o": "o"},
        {"move": "Up/Down, k/j", "page": "PgUp/PgDn", "ok": "Enter",
         "tick": "Space, Right/Left", "options": "o, Tab", "back": "Esc, Backspace",
         "stop": "Esc, Ctrl-C", "kill": None, "enter": "Enter", "esc": "Esc"},
        ("Esc or Ctrl-C", "Esc or Ctrl-C")),
    "both": TuiRoute(
        {},
        {"move": "Up/Down, k/j", "page": "PgUp/PgDn, L1/R1", "ok": "A/Enter, Start",
         "tick": "X, Space, Right/Left", "options": "Y, o, Tab", "back": "B/Esc, Backspace",
         "stop": "B/Esc, Ctrl-C", "kill": "Select+Start", "enter": "Enter", "esc": "Esc"},
        ("B or Ctrl-C", "B, Ctrl-C or Select+Start")),
    "gptokeyb": _GPTOKEYB,
    # gptokeyb2 with retrobios.gptk inside muxterm, which no longer reads the
    # pad: the gptokeyb buttons. muxterm keeps PgUp and PgDn for its
    # scrollback, and the launcher sends nothing on L1 and R1 there: Left and
    # Right page.
    "gptokeyb_muxterm": _GPTOKEYB._replace(help={**_GPTOKEYB.help,
                                                 "page": "D-pad Left/Right",
                                                 "tick": "X, Space"}),
    # muxterm's own keys: Start Enter, B Backspace, Y Space, Menu closes the
    # terminal. A, X, L1 and R1 send nothing, Select shows its keyboard, and
    # the D-pad's Left and Right page a list.
    "muxterm": TuiRoute(
        {"A/Enter": "Start", "B/Esc": "B", "X/Space": "Y", "Y/o": None, "?": None,
         "/": None, "Ctrl-C": "Menu", "Enter": "Start", "Esc": None, "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "D-pad Left/Right", "ok": "Start, Enter",
         "tick": "Y, Space", "options": "o, Tab", "back": "B, Esc, Backspace",
         "stop": "B, Esc, Ctrl-C", "kill": None, "enter": "Start, Enter", "esc": "Esc"},
        ("B", "B")),
    # RetroBIOS.sh.keys: the gptokeyb buttons, and no combo that ends the run.
    "evmapy": TuiRoute(
        {"A/Enter": "A", "B/Esc": "B", "X/Space": "X", "Y/o": "Y", "?": None, "/": None,
         "Ctrl-C": None, "Enter": "A", "Esc": "B", "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
         "tick": "X, Space, Right/Left", "options": "Y, Tab, o",
         "back": "B, Select, Esc", "stop": "B, Esc, Ctrl-C", "kill": None,
         "enter": "A, Enter", "esc": "B, Esc"},
        ("B", "B")),
    # Buttons that are keys already: A Space, Start Enter, L2 Tab, R2
    # Backspace. B is Left Ctrl, a modifier: alone it sends no byte to a
    # terminal (the console's keyboard driver only records its state), so
    # the interface never sees it, nor X, Y and Select (Shift, Alt, Ctrl).
    "miyoo": TuiRoute(
        {"A/Enter": "A", "B/Esc": "R2", "X/Space": "A", "Y/o": "L2", "?": None, "/": None,
         "Ctrl-C": None, "Enter": "Start", "Esc": None, "Ctrl-U": None},
        {"move": "D-pad, Up/Down", "page": "L1/R1, PgUp/PgDn", "ok": "A, Start, Enter",
         "tick": "A, Space, Right/Left", "options": "L2, Tab, o",
         "back": "R2, Esc, Backspace", "stop": "R2, Esc, Ctrl-C", "kill": None,
         "enter": "Start, Enter", "esc": "Esc"},
        ("R2", "R2")),
}
TUI_PAD_ROUTES = tuple(name for name in TUI_ROUTES if name not in ("keys", "both"))
# Set by Steam for what it starts, and by gamescope: a controller may be
# all there is, mapped by Steam Input to keys nobody here can name.
_STEAM_MARKERS = ("SteamGamepadUI", "SteamDeck", "SteamGameId", "GAMESCOPE_WAYLAND_DISPLAY")


# Seconds the interface waits for a first key, no run going, before it
# closes, set by a launcher whose mapper may never open the pad: the screen
# would otherwise hold a handheld that has no other way out.
TUI_IDLE_ENV = "RETROBIOS_IDLE_EXIT"
TUI_IDLE_WORDS = "No button pressed, closing."


def tui_idle_exit(env: Mapping[str, str] | None = None) -> float | None:
    """The seconds RETROBIOS_IDLE_EXIT names, None when unset or not a
    positive number."""
    env = os.environ if env is None else env
    try:
        seconds = float(env.get(TUI_IDLE_ENV, "").strip())
    except ValueError:
        return None
    return seconds if 0 < seconds < float("inf") else None


def tui_pad_route(os_type: str, env: Mapping[str, str] | None = None) -> str:
    """The keys the hints name: a launcher's pad route, "keys" at a desktop,
    "both" (button and key) where nothing says which one is held."""
    env = os.environ if env is None else env
    named = env.get(TUI_PAD_ENV, "").strip().lower()
    if named:
        return named if named in TUI_PAD_ROUTES else "both"
    if any(env.get(name) for name in _STEAM_MARKERS):
        return "both"
    if os_type in ("windows", "darwin", "wsl"):
        return "keys"
    # A Linux console is where a handheld draws: a desktop or a remote
    # shell is a keyboard's.
    if os_type == "linux" and env.get("TERM") != "linux" and any(
            env.get(name) for name in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION",
                                       "SSH_TTY")):
        return "keys"
    return "both"


def _terminal_size(stream: TextIO) -> tuple[int, int]:
    try:
        size = os.get_terminal_size(stream.fileno())
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        return 0, 0
    return size.columns, size.lines


def colour_blocker(env: Mapping[str, str], stream: TextIO) -> str:
    """Why the full-screen interface draws without colour, "" when it paints
    with the roles of COLOUR_ROLES. The text is the same either way."""
    if env.get("NO_COLOR"):
        return "NO_COLOR is set"
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()):
        return "the output is not a terminal"
    if os.name != "nt" and env.get("TERM", "") in ("", "dumb"):
        return "TERM is dumb or not set"
    return terminal_few_colours(env)


def _tui_flag_blocker(args: argparse.Namespace) -> str:
    """The option of a run without questions, said as the reason."""
    for flag, given in (
        ("--check", args.check), ("--dry-run", args.dry_run),
        ("--list-platforms", args.list_platforms), ("--list-targets", args.list_targets),
        ("--list-systems", args.list_systems), ("--list-cores", args.list_cores),
        ("--list-emulators", args.list_emulators), ("--events", args.events),
        ("--quiet", args.quiet), ("--yes", args.yes), ("--no-input", args.no_input),
        ("--restore", args.restore is not None),
        ("--pack", getattr(args, "pack", None) is not None),
    ):
        if given:
            return f"{flag} runs without questions"
    return ""


def _tui_keys_blocker(stdin: TextIO) -> str:
    """Why single key presses cannot be read here, "" when they can."""
    if os.name == "nt":
        import importlib

        try:
            importlib.import_module("msvcrt")
        except ImportError:
            return "this Python has no msvcrt to read keys"
        if not _enable_ansi():
            return "this console does not draw escape sequences (Windows 10 or later does)"
        return ""
    try:
        import termios
    except ImportError:
        return "this Python has no termios to read keys"
    try:
        termios.tcgetattr(stdin.fileno())
    except (termios.error, OSError, ValueError, AttributeError,
            io.UnsupportedOperation) as exc:
        return f"single key presses cannot be read here ({exc})"
    return ""


def tui_blocker(
    args: argparse.Namespace, stdin: TextIO | None = None, stdout: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Why the full-screen interface cannot run here, "" when it can."""
    env = os.environ if env is None else env
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    flag_blocker = _tui_flag_blocker(args)
    if flag_blocker:
        return flag_blocker
    for name, stream in (("input", stdin), ("output", stdout)):
        isatty = getattr(stream, "isatty", None)
        if not (isatty and isatty()):
            return f"the {name} is not a terminal"
    if os.name != "nt" and env.get("TERM", "") in ("", "dumb"):
        return "TERM is dumb or not set"
    drawing = terminal_without_ansi(env)
    if drawing:
        return drawing
    # A pseudo-terminal nobody sized reports 0x0: script(1) fed from a pipe
    # is one, and the line questions run there as they always have.
    cols, rows = _terminal_size(stdout)
    if cols < TUI_MIN_COLS or rows < TUI_MIN_ROWS:
        return (f"the terminal is {cols}x{rows}, smaller than "
                f"{TUI_MIN_COLS}x{TUI_MIN_ROWS}")
    return _tui_keys_blocker(stdin)


def line_mode_reason(blocker: str, env: Mapping[str, str] | None = None) -> str:
    """Why the questions come line by line, in one line, for a terminal the
    full screen cannot draw on: its size or its TERM. "" for a run that
    asks nothing (--check, a pipe), and for a pseudo-terminal nobody sized
    (script fed from a pipe is 0x0), which is no window."""
    env = os.environ if env is None else env
    small = re.match(r"the terminal is (\d+x\d+), smaller than", blocker)
    if small:
        if "0" in small[1].split("x"):
            return ""
        return (f"The window is {small[1]}: questions come line by line "
                f"({TUI_MIN_COLS}x{TUI_MIN_ROWS} for the full screen).")
    if blocker == "TERM is dumb or not set":
        term = screen_text(env.get("TERM", ""))
        return (f"TERM={term}: questions come line by line." if term
                else "TERM is not set: questions come line by line.")
    if blocker.startswith("TERM="):
        return f"{blocker}: questions come line by line."
    return ""


# TERM values of terminals that report no mouse the xterm way: the Linux
# console (gpm is its own protocol), the DEC VTs and BSD consoles.
_NO_MOUSE_TERMS = ("linux", "vt", "cons", "ansi")


def tui_mouse_blocker(
    stdin: TextIO | None = None, stdout: TextIO | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Why the full screen leaves the mouse to the terminal, "" when it
    asks for clicks. A pad route has no pointer and its mapper may send
    anything a report would be confused with, and RETROBIOS_NO_MOUSE keeps
    the terminal's own selection everywhere."""
    env = os.environ if env is None else env
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    if _env_on(env, TUI_MOUSE_ENV):
        return f"{TUI_MOUSE_ENV} is set"
    if env.get(TUI_PAD_ENV, "").strip():
        return f"{TUI_PAD_ENV} names a controller route"
    if os.name == "nt":
        # msvcrt.getwch reads keys, never a console mouse record.
        return "a Windows console reports no clicks as keys"
    for name, stream in (("input", stdin), ("output", stdout)):
        isatty = getattr(stream, "isatty", None)
        if not (isatty and isatty()):
            return f"the {name} is not a terminal"
    term = env.get("TERM", "").strip().lower()
    if term in ("", "dumb", "unknown") or term.startswith(_NO_MOUSE_TERMS):
        return f"TERM={term} reports no clicks" if term else "TERM is not set"
    return ""


def tui_wants_mouse(state: TuiState, lines: list[str]) -> bool:
    """Whether the frame takes clicks: not where a command or the result is
    shown, so the terminal's own selection copies it as it always has, nor
    where a path is typed, which a middle or right click pastes into."""
    if state.help:
        return True
    if state.screen == "result":
        # A tap on the bar's Exit closes it, where a touch screen has no
        # Enter: the result is printed again in the terminal once the
        # screen closes, its commands selected there as anywhere.
        return True
    if state.screen in ("command", "path"):
        return False
    # Read from the frame's model: a command wrapped over lines was missed
    # by a match on the drawn text, its URL cut in two.
    return not any(getattr(line, "command", False) for line in lines)


def _tui_system_flags(state: TuiState) -> list[tuple[str, str | None]]:
    """The --system the screen's ticks stand for."""
    needed = {row["system"] for row in state.systems
              if row["missing"] + row["wrong_hash"] > 0}
    if state.systems and not needed <= state.ticked:
        return [("--system", name) for name in sorted(state.ticked)]
    return [("--system", name) for name in state.cli_systems]


def tui_flags(state: TuiState) -> list[tuple[str, str | None]]:
    """The options that carry the choices made on screen, CLI ones included."""
    flags = list(state.passthrough)
    if state.target:
        flags.append(("--target", state.target))
    if state.every_board:
        flags.append(("--every-board", None))
    flags += [("--emulator", name) for name in state.emulators]
    flags += [("--from-pack", str(pack)) for pack in state.packs]
    flags += _tui_system_flags(state)
    flags += [("--core", name) for name in tui_core_flags(state)]
    if state.regions:
        flags.append(("--region", ",".join(state.regions)))
    if state.for_games:
        flags.append(("--for-games", str(state.games_folder) if state.games_folder else None))
        if state.required_only:
            flags.append(("--required-only", None))
    if state.no_game_data:
        flags.append(("--no-game-data", None))
    if state.standalone and _tui_standalone_offered(state):
        flags.append(("--standalone", None))
    if state.one_per_slot and _tui_slot_offered(state, flags):
        flags.append(("--one-per-slot", None))
    if state.installed_only and not any(flag == "--cores-dir" for flag, _v in flags):
        flags.append(("--installed-cores", None))
    if state.jobs != 8:
        flags.append(("--jobs", str(state.jobs)))
    flags += state.record_flags
    if (state.record is not None and not state.for_games
            and not any(flag in RECORD_NARROWING for flag, _value in flags)):
        # The whole list, chosen over a recorded narrower one: said so to
        # the runs, whose own reading of the record would narrow it again.
        flags.append(("--all-files", None))
    flags += [("--from", str(folder)) for folder in state.from_folders]
    if (os.environ.get(OFFLINE_VARIABLE) == OFFLINE_FLAG_VALUE
            and not any(flag == "--offline" for flag, _v in flags)):
        # Given as --offline: said so in the command. Set as the variable,
        # the runs inherit it and the words name it.
        flags.append(("--offline", None))
    return flags


_TUI_MODES = {
    "check": ["--check", "--events"],
    "confirm": ["--dry-run", "--events"],
    "preview": ["--dry-run", "--events"],
    "install": ["--events", "--yes"],
}


def tui_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child that does what the screen decided."""
    if run in TUI_ACTION_RUNS:
        return tui_action_argv(state, run, python, script)
    # --dest=VALUE: a folder typed as -x would otherwise be read as an option.
    argv = [python, script, f"--platform={state.platform}", f"--dest={state.dest}"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    argv += [flag if value is None else f"{flag}={value}" for flag, value in tui_flags(state)]
    if run == "install" and state.add_app and _tui_app_ready(state):
        # Only the install writes: --check and --dry-run refuse it.
        argv.append("--add-app")
    return argv + _TUI_MODES[run]


def tui_run_env(state: TuiState, own_list: bool) -> dict | None:
    """The environment of a child run: None for this one's own, else with
    the markers the run reads (TUI_LIST_ENV, TUI_RECORD_ENV)."""
    marks = {TUI_LIST_ENV: "1"} if own_list else {}
    if tui_record_kept(state):
        marks[TUI_RECORD_ENV] = "1"
    if not marks and TUI_RECORD_ENV not in os.environ:
        return None
    env = {key: value for key, value in os.environ.items() if key != TUI_RECORD_ENV}
    env.update(marks)
    return env


def tui_hint(state: TuiState) -> Invocation:
    """The command the screen's choices make, every option of the run in
    it: what "Same choice without questions" and the sudo advice give."""
    hint = Invocation()
    hint.os_type = state.os_type
    hint.options = ([("--manifest", str(state.manifest_path))]
                    if state.manifest_given and state.manifest_path else [])
    hint.options += tui_flags(state)
    if state.add_app and _tui_app_ready(state):
        hint.options.append(("--add-app", None))
    # The runs inherit the variable, a command shown to the user does not.
    if offline_option(False) and ("--offline", None) not in hint.options:
        hint.options.append(("--offline", None))
    return hint


def tui_command(state: TuiState) -> str:
    """The same choice as one command, in the form the run was started with."""
    return tui_hint(state).command(state.platform, state.dest)


def _tui_card(state: TuiState) -> CardApp | None:
    """The card the BIOS folder is on, read once for each folder."""
    if state.dest is None:
        return None
    if state.card_for != state.dest:
        state.card_for, state.card = state.dest, card_app(state.dest)
    return state.card


def _tui_app_ready(state: TuiState) -> bool:
    """Whether the RetroBIOS app can go on this card: its system has one,
    and the run may use the network to fetch it."""
    card = _tui_card(state)
    return card is not None and card.place is not None and not LOCAL.offline


def _tui_installed(state: TuiState) -> bool:
    """An install that finished with every file in place."""
    summary = state.summary or {}
    return bool(summary) and not summary.get("interrupted") and not summary.get("failed") \
        and state.code == 0


def _app_offer(state: TuiState) -> bool:
    """The result offers the app: the install finished, the card can take
    it, and it was neither asked for nor put already."""
    return (state.screen == "result" and state.app is None and not state.app_running
            and _tui_installed(state) and _tui_app_ready(state))


def tui_run_files(state: TuiState) -> tuple[list[dict], list[dict]]:
    """The files and omissions the run chooses among, as the check counted
    them: the list without what it set aside before any choice (the save
    entries of a save directory it cannot place), the game data left out
    when the plan leaves it out. Line mode chooses among the same (bare)."""
    manifest = state.manifest or {}
    key = (id(state.manifest), frozenset(state.set_aside or ()), state.no_game_data)
    if state.run_files_cache is not None and state.run_files_cache[0] == key:
        return state.run_files_cache[1]
    aside = state.set_aside or set()
    files = [entry for entry in manifest.get("files") or [] if entry.get("dest") not in aside]
    omitted = list(manifest.get("omitted_files") or [])
    if state.no_game_data:
        files, omitted = leave_out_game_data(files, omitted)[:2]
    state.run_files_cache = (key, (files, omitted))
    return files, omitted


def _core_base(state: TuiState) -> list[str]:
    """The cores a choice on Cores is made among: those of the systems
    chosen, every core the run accepts else (choosable_cores, as line
    mode counts them)."""
    return choosable_cores(*tui_run_files(state), _tui_systems_chosen(state))


def tui_core_flags(state: TuiState) -> list[str]:
    """The --core the run is given: the cores ticked, none when every core
    of the systems chosen is (the run keeps the same files)."""
    if not state.cores or set(_core_base(state)) <= set(state.cores):
        return []
    return list(state.cores)


def _tui_systems_chosen(state: TuiState) -> list[str]:
    """The systems the run is narrowed to, [] for every system."""
    return [value for _flag, value in _tui_system_flags(state) if value]


def _tui_standalone_offered(state: TuiState) -> bool:
    """Whether Change offers --standalone: emulators are chosen, the list
    records a standalone build for each of them, and no region, core or
    system choice narrows the run, which the option refuses beside it."""
    manifest = state.manifest or {}
    layouts = manifest.get("standalone_builds") or []
    if not state.emulators or not layouts or not _tui_standalone_fits(state):
        return False
    names = emulator_names(manifest, *tui_run_files(state))
    return all(names.get(name) in layouts for name in state.emulators)


def _tui_standalone_fits(state: TuiState) -> bool:
    """No region, core or system choice: --standalone takes none."""
    return not (state.regions or tui_core_flags(state) or _tui_system_flags(state))


def _tui_slot_offered(state: TuiState, flags: list[tuple[str, str | None]]) -> bool:
    """Whether Change offers --one-per-slot: the list records its slots and
    the choice is the whole list, as the pack builder decides slots over it
    (no system, emulator or game choice narrows it first)."""
    return bool((state.manifest or {}).get("slot_fields")) and not any(
        flag in ("--system", "--emulator", "--for-games", "--declared-only")
        for flag, _value in flags)


def _record_key(options: Iterable[tuple[str, str | None]]) -> list:
    """A choice in a form two spellings of it share: one name per --system
    and --core, in any order."""
    pairs = record_options(record_argv(options))
    return sorted((flag, name.strip()) for flag, value in pairs
                  for name in ((value or "").split(",") if flag in ("--system", "--core")
                               else [value or ""]) if name.strip() or value is None)


def tui_record_kept(state: TuiState) -> bool:
    """Whether the plan's choice is the one the record keeps."""
    if state.record is None:
        return False
    return _record_key(tui_flags(state)) == _record_key(
        record_options(state.record["choice"]))


# The runs More starts, each a child as an install is: what --remove would
# take (removal_plan), the removal, the backups listed, one put back and
# one deleted.
TUI_ACTION_RUNS = ("removal_plan", "remove", "backups", "restore", "delete_backup",
                   "pack_plan", "pack")
# The plan's options a pack's run leaves out: each reads or writes the BIOS
# folder of this machine, which --pack refuses.
TUI_PACK_DROPPED = ("--dest", "--installed-cores", "--cores-dir", "--save-dir",
                    "--standalone-copies", "--add-app", "--romm-firmware", "--for-games",
                    "--required-only")


def tui_pack_dir(state: TuiState) -> Path:
    """The folder the pack goes in: the one chosen, else Downloads where
    there is one, else the home folder."""
    if state.pack_dir is not None:
        return state.pack_dir
    downloads = state.home / "Downloads"
    return downloads if _is_dir(downloads) else state.home


def tui_pack_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child that makes the pack, or lists it (pack_plan): the plan's
    choice, none of the options of this machine's folder. The games of a
    folder named stay a choice, the card's own are not read for a pack."""
    argv = [python, script, f"--platform={state.platform}"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    flags = [flag for flag in tui_flags(state) if flag[0] not in TUI_PACK_DROPPED]
    if state.for_games and state.games_folder:
        flags.append(("--for-games", str(state.games_folder)))
        if state.required_only:
            flags.append(("--required-only", None))
    argv += [flag if value is None else f"{flag}={value}" for flag, value in flags]
    argv.append(f"--pack={tui_pack_dir(state)}{os.sep}")
    return argv + (["--dry-run", "--events"] if run == "pack_plan" else ["--events", "--yes"])


def tui_action_argv(state: TuiState, run: str, python: str, script: str) -> list[str]:
    """The child of a More action: its own options and none of the plan's,
    whose --system is an install's choice, not what to remove. A pack
    takes the plan's choice."""
    if run in ("pack_plan", "pack"):
        return tui_pack_argv(state, run, python, script)
    if run in ("restore", "delete_backup"):
        folder = str((state.backup_chosen or {}).get("folder", ""))
        flag = "--restore" if run == "restore" else "--delete-backup"
        return [python, script, f"{flag}={folder}", "--events",
                *(["--yes"] if run == "delete_backup" else [])]
    argv = [python, script, f"--platform={state.platform}", f"--dest={state.dest}"]
    if run == "backups":
        return argv + ["--backups", "--events"]
    if state.manifest_path is not None:
        argv.append(f"--manifest={state.manifest_path}")
    argv += ["--remove", *(f"{flag}={value}" if value else flag
                           for flag, value in state.removal_scope)]
    if state.removal_backup and not _removing_misplaced(state):
        argv.append("--backup")
    return argv + (["--dry-run", "--events"] if run == "removal_plan" else ["--events", "--yes"])


def _removing_misplaced(state: TuiState) -> bool:
    """Whether the removal is of the copies in the wrong place, which are
    deleted: they were never a setup's, so no backup gives them back."""
    return ("--misplaced", "") in state.removal_scope
