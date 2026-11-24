"""The screen a full-screen session opens on, from the options and what detection found."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from installer.cards import (
    _SHARE_FOLDERS,
    _mounted_cards,
    card_bound,
    card_platform,
    setup_folders,
    share_doubt,
)
from installer.destination import card_choice, dest_default
from installer.detect_frontends import detect_frontends
from installer.detect_os import detected_os
from installer.detection_notes import DETECTION_NOTES, detection_held
from installer.host_fs import _DETECTION_REFUSED, refused_words
from installer.install_record import choice_given
from installer.offline import LOCAL
from installer.platforms import normalize_platform
from installer.regions import resolve_regions
from installer.setups import _default_dest, found_setups, setup_list
from installer.tui_commands import _tui_passthrough
from installer.tui_folder_actions import (
    _card_status,
    _choose,
    _open_folder_screen,
    _platform_focus,
    _take_card,
)
from installer.tui_paint import _short_path
from installer.tui_plan_view import TUI_ESDE_NOTE
from installer.tui_routes import tui_pad_route
from installer.tui_state import TuiState


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
    start = len(DETECTION_NOTES)
    with detection_held():
        state.setups, state.mounted_setups = found_setups(os_type)
        frontends = detect_frontends(os_type)
    state.setup_folders = setup_folders(state.setups)
    # Said on the normal screen before this one covered it, and kept
    # above the list: a status line under 18 setups was never drawn.
    state.refused = [refused_words(folder, why, _short_path(folder, state.home))
                     for folder, why in _DETECTION_REFUSED]
    if "esde" in frontends:
        state.notes.append(TUI_ESDE_NOTE)
    state.notes += [line.strip() for note in DETECTION_NOTES[start:]
                    for line in note.splitlines() if line.strip()]


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
