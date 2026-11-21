"""The full-screen interface's state, the row a list shows, and the widest its text grows."""
from __future__ import annotations

import time
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from installer.handheld_app import CardApp
    from installer.tui_folder_scan import FolderScan
    from installer.tui_input import TuiHits


def _folded(text: str) -> str:
    """Text compared without case or accents, as a filter reads it."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(char for char in decomposed if not unicodedata.combining(char)).casefold()


class TuiRow(NamedTuple):
    """One row a screen lists: what Enter does on it, and what it shows."""

    action: str
    label: str
    right: str = ""
    value: object = None
    style: str = ""
    # Shorter forms of right, longest first, for a narrow screen: the label
    # keeps its room before the right-hand text does.
    narrow: tuple = ()
    # A name cut to the room left when no form of narrow but a count fits:
    # "1 device" named nothing where "TrimUI Smart P..." fits.
    cut: str = ""
    # The right-hand text is never cut: the label is, once its shortest
    # form does not fit beside it (a system's size).
    keep_right: bool = False
    # The column the right-hand text starts at, one for the whole list: the
    # setup list's devices had three right edges at 120 columns.
    align: int = 0


def _matches(text: str, needle: str) -> bool:
    return not needle or _folded(needle) in _folded(text)


# Text stops growing past this width: on a 200-column window a row and its
# size sat a whole screen apart.
TUI_MAX_WIDTH = 100


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
        # The drives the folder screen lists, as last looked for: read when
        # it opens and on Look again, never by a frame.
        self.folder_scan: FolderScan | None = None
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
