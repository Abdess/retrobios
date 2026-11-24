"""What the full-screen tests share: the manifests, the states they build, the
keys, the pseudo-terminal and the runs several test classes borrow.

The interface is a model, a pure update on keys and events, and pure views:
most of it is tested without a terminal. The end-to-end cases run the real
install.py --tui on a pseudo-terminal read back with pyte, against a loopback
copy of the repository, and skip when pyte is not installed (CI installs it).
"""

from __future__ import annotations

import tests

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import select
import shutil
import struct
import sys
import tempfile
import termios
import time
import types
import unittest
import warnings
import zipfile
from collections.abc import Iterable
from pathlib import Path
from unittest import mock

import install
from tests.installsupport import FakeRepository, make_card


REPO_ROOT = Path(__file__).resolve().parent.parent


# install.py runs on 3.8, the scripts it is compared with need 3.9.
BUILDER_FLOOR = (3, 9)


def reported(call, *args, **kwargs):
    """call(...), a refusal said as the command says it: a library
    function raises it, and the command prints it."""
    try:
        return call(*args, **kwargs)
    except install.Refusal as refusal:
        refusal.report()
        raise


try:
    import pyte
except ImportError:
    pyte = None


try:
    import pty
except ImportError:
    pty = None


GOLDEN = REPO_ROOT / "tests" / "fixtures" / "tui"


SIZES = ((40, 12), (40, 15), (80, 24), (120, 40))


# RETROBIOS_PAD's values, and "keys" for a desktop that sets none.
ROUTES = ("keys", "gptokeyb", "gptokeyb_muxterm", "evmapy", "muxterm", "miyoo")


UP, DOWN, RIGHT, LEFT = "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"


Key = install.TuiKey


# The screens as --verbose draws them, every Details line where it belongs:
# the findings marked with it read lines the default leaves to Details.
in_full = mock.patch.object(install, "tui_verbose", lambda _state: True)


def _args(**given) -> argparse.Namespace:
    """The namespace main() parses, every option at its default."""
    values = dict(
        platform=None, dest=None, target=None, every_board=False, check=False,
        list_platforms=False, list_targets=False, jobs=8, verbose=False,
        standalone_copies=False, emulator=None, installed_cores=False, save_dir=None,
        cores_dir=None, system=None, core=None, region=None, no_game_data=False,
        list_systems=False, list_cores=False, romm_firmware=None, list_emulators=False,
        no_input=False, dry_run=False, yes=False, quiet=False, events=False,
        restore=None, from_pack=None, manifest=None, tui=False, plain=False, add_app=False,
    )
    values["from"] = None
    values.update(given)
    return argparse.Namespace(**values)


def install_run(*options: str, env: dict | None = None):
    import subprocess

    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "install.py"), *options], capture_output=True,
        text=True, timeout=60, check=False, stdin=subprocess.DEVNULL,
        env={**os.environ, **(env or {})},
    )


# A repository-like state, as the events of a check fill it.
MANIFEST = {
    "manifest_version": 2, "platform": "retroarch", "categorized": True,
    "system_cores": {"sony-playstation": ["pcsx_rearmed"]},
    "files": [
        {"dest": "scph5500.bin", "size": 524288, "systems": ["sony-playstation"],
         "regions": ["japan"], "cores": None},
        {"dest": "scph5501.bin", "size": 524288, "systems": ["sony-playstation"],
         "regions": ["north-america"], "cores": None},
        {"dest": "gba_bios.bin", "size": 16384, "systems": ["nintendo-gba"], "cores": None},
        {"dest": "pcsx/extra.bin", "size": 4, "systems": ["sony-playstation"],
         "cores": ["pcsx_rearmed"]},
        {"dest": "fc/disksys.rom", "size": 8192, "systems": ["nintendo-famicom-disk"],
         "cores": ["mesen"]},
    ],
}


SYSTEMS = [
    {"event": "system", "platform": "retroarch", "system": "nintendo-famicom-disk",
     "name": "ファミコン", "files": 1, "present": 1, "missing": 0, "wrong_hash": 0,
     "bytes_needed": 0},
    {"event": "system", "platform": "retroarch", "system": "nintendo-gba",
     "name": "gba", "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
     "bytes_needed": 16384},
    {"event": "system", "platform": "retroarch", "system": "sony-playstation",
     "name": "sony-playstation", "files": 3, "present": 0, "missing": 2, "wrong_hash": 1,
     "bytes_needed": 1048580},
]


CHECK = {"event": "check", "platform": "retroarch", "name": "RetroArch",
         "bios_dir": "/home/user/.config/retroarch/system", "files": 5, "present": 1,
         "missing": 3, "wrong_hash": 1, "bytes_needed": 1064964, "data_missing": 0,
         "not_installable": 2}


def plan_event(check: dict, copied: Iterable[str] = (), lacking: Iterable[str] = (),
               sizes: dict | None = None, **plan) -> dict:
    """The fetch_plan event the run sends after check: every file not in
    place fetched, but those copied from this machine and those the pack
    lacks (sizes by dest, those of FILES by default), unless plan says
    otherwise."""
    copied, lacking = list(copied), list(lacking)
    sizes = {event["dest"]: event["size"] for event in FILES} if sizes is None else sizes
    left = [*copied, *lacking]
    return {"event": "fetch_plan", "platform": check["platform"],
            "files": check["missing"] + check["wrong_hash"] - len(left),
            "bytes": check["bytes_needed"] - sum(sizes[dest] for dest in left),
            "copied": copied, "lacking": lacking, "data_files": check.get("data_missing", 0),
            "data_bytes": check.get("data_bytes", 0), **plan}


def planned(check: dict, *given, **plan) -> dict:
    """check as the screen holds it once its fetch_plan event came."""
    return {**check, "fetch_plan": plan_event(check, *given, **plan)}


FILES = [
    {"event": "file", "platform": "retroarch", "dest": "scph5500.bin",
     "systems": ["sony-playstation"], "size": 524288, "state": "missing"},
    {"event": "file", "platform": "retroarch", "dest": "scph5501.bin",
     "systems": ["sony-playstation"], "size": 524288, "state": "wrong_hash"},
    {"event": "file", "platform": "retroarch", "dest": "pcsx/extra.bin",
     "systems": ["sony-playstation"], "size": 4, "state": "missing"},
    {"event": "file", "platform": "retroarch", "dest": "gba_bios.bin",
     "systems": ["nintendo-gba"], "size": 16384, "state": "missing"},
]


PLAN = plan_event(CHECK)


HOME = Path("/home/user")


SYSTEM_DIR = HOME / ".config" / "retroarch" / "system"


def screen_text(lines) -> str:
    """The screen as one line of words, a path broken after a separator
    joined again: a folder under the checkout is as long as the checkout's
    own path, and a deep clone wrapped it across two lines."""
    return re.sub(r"(?<=[/\\]) ", "", " ".join(" ".join(lines).split()))


def listed(state: install.TuiState) -> install.TuiState:
    """The setups found, as Back shows them from the plan the screen opens
    on when it found one setup."""
    if state.opened_on_plan and state.screen != "setup":
        install.tui_update(state, Key("esc"))
    return state


def fresh_state() -> install.TuiState:
    state = install.TuiState(os_type="linux", home=HOME)
    state.setups = [("retroarch", SYSTEM_DIR, "RetroArch"),
                    ("batocera", Path("/userdata/bios"), "KNULLI (Batocera files)")]
    state.setup_folders = install.setup_folders(state.setups)
    return state


GAMES = {"event": "games", "platform": "retroarch", "folder": "/media/user/SDCARD/Roms",
         "games": 412, "recognised": 398,
         "found": [{"system": "sony-playstation", "folder": "PS", "games": 400,
                      "recognised": 390, "regions": []},
                     {"system": "nintendo-gba", "folder": "GBA", "games": 12,
                      "recognised": 8, "regions": ["europe"]}],
         "fallback": [{"system": "nintendo-gba", "folder": "GBA", "name": "GBA/demo.gba",
                       "reason": "not_recognised"},
                      {"system": "nintendo-gba", "folder": "GBA", "name": "GBA/hack.gba",
                       "reason": "not_recognised"}],
         "not_games": 3, "required_only": False}


def games_state() -> install.TuiState:
    """The plan of a card whose games the check read (--for-games)."""
    state = fresh_state()
    state.stack = ["setup"]
    with mock.patch.object(install.Path, "exists", return_value=True):
        install.tui_update(state, Key("enter"))
    install.tui_receive(state, ("games_here", "retroarch", SYSTEM_DIR, 2))
    effects = install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
    assert effects == [("run", "check")], effects
    for event in [GAMES, *FILES, *SYSTEMS, CHECK, PLAN]:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value={
            "free": 50 * 1024 ** 3, "writable": True, "cores": ["pcsx_rearmed"]}):
        install.tui_receive(state, ("ended", state.run_id, 1, []))
    return state


def checked_state(facts: dict | None = None) -> install.TuiState:
    """The plan screen of a RetroArch folder with files missing."""
    state = fresh_state()
    state.stack = ["setup"]
    with mock.patch.object(install.Path, "exists", return_value=True):
        effects = install.tui_update(state, Key("enter"))
    assert effects == [("fetch", "retroarch")], effects
    effects = install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
    assert effects == [("run", "check")], effects
    for event in [*FILES, *SYSTEMS, CHECK, PLAN]:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
            "free": 50 * 1024 ** 3, "writable": True, "cores": ["pcsx_rearmed"]}):
        install.tui_receive(state, ("ended", state.run_id, 1, []))
    return state


def option_focus(state: install.TuiState, action: str) -> None:
    """The focus on the Change row doing action: its rows sit under
    headings, which no index of the flat list kept."""
    state.focus["options"] = [row.action for row in install.tui_rows(state)].index(action)


def press(state: install.TuiState, *pressed) -> list:
    effects = []
    for key in pressed:
        effects += install.tui_update(state, Key("char", key) if isinstance(key, str)
                                      and len(key) == 1 else Key(key))
    return effects


def golden_states() -> dict:
    """One state per screen, filled as a run fills it."""
    states = _golden_setup_states()
    states.update(_golden_plan_states())
    states.update(_golden_run_states())
    return states


def _golden_setup_states() -> dict:
    states = {}
    states["setup"] = fresh_state()
    states["setup"].notes = ["ES-DE found: its BIOS files go to each emulator, not to "
                             "ES-DE itself."]
    platforms = fresh_state()
    platforms.stack = ["setup", "platforms"]
    platforms.focus["platforms"] = 1
    states["platforms"] = platforms
    folder = fresh_state()
    folder.platform, folder.stack = "retroarch", ["platforms", "folder"]
    folder.folder_default = SYSTEM_DIR
    states["folder"] = folder
    card = fresh_state()
    card.platform, card.stack = "nextui", ["platforms", "folder"]
    states["folder-card"] = card
    browse = fresh_state()
    browse.platform, browse.stack = "retroarch", ["folder", "browse"]
    browse.browse_dir = HOME / ".config" / "retroarch"
    browse.browse_rows = [
        install.TuiRow("use", "Use this folder"), install.TuiRow("up", "..", value=HOME),
        install.TuiRow("dir", "/media/user/SDCARD (NextUI card)",
                       value=Path("/media/user/SDCARD")),
        install.TuiRow("dir", "cores/", value=HOME / "cores"),
        install.TuiRow("dir", "system/", value=SYSTEM_DIR)]
    states["browse"] = browse
    path = fresh_state()
    path.platform, path.stack, path.path_text = "retroarch", ["folder", "path"], "~/bios"
    states["path"] = path
    create = fresh_state()
    create.platform, create.dest, create.stack = "retroarch", HOME / "bios" / "new", ["create"]
    create.facts = {"nearest": HOME}
    states["create"] = create
    checking = fresh_state()
    checking.platform, checking.dest, checking.stack = "retroarch", SYSTEM_DIR, ["checking"]
    checking.manifest, checking.started, checking.now = MANIFEST, 10.0, 14.2
    states["checking"] = checking
    return states


def _golden_plan_states() -> dict:
    states = {}
    states["plan"] = checked_state()
    done = checked_state()
    done.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0, "bytes_needed": 0,
                  "not_installable": 0}
    states["plan-in-place"] = done
    systems = checked_state()
    systems.stack.append("systems")
    systems.focus["systems"] = 3
    states["systems"] = systems
    options = checked_state()
    options.stack.append("options")
    options.focus["options"] = 1
    options.regions = ["north-america", "japan"]
    states["change"] = options
    slots = checked_state()
    slots.manifest = {**MANIFEST, "slot_fields": True}
    slots.stack.append("options")
    slots.one_per_slot = True
    option_focus(slots, "slot")
    states["change-slot"] = slots
    standalone = checked_state()
    standalone.manifest = {**MANIFEST, "standalone_builds": ["pcsx_rearmed"]}
    standalone.stack.append("options")
    standalone.emulators = ["pcsx_rearmed"]
    option_focus(standalone, "standalone")
    states["change-standalone"] = standalone
    states["device"] = device_state()
    emulators = checked_state()
    emulators.stack += ["options", "emulators"]
    emulators.emulators = ["pcsx_rearmed"]
    emulators.focus["emulators"] = 2
    states["emulators"] = emulators
    regions = checked_state()
    regions.stack += ["options", "regions"]
    regions.regions = ["north-america"]
    states["regions"] = regions
    cores = checked_state()
    cores.stack += ["options", "cores"]
    cores.cores = ["pcsx_rearmed"]
    states["cores"] = cores
    preview = checked_state()
    preview.stack += ["options", "preview"]
    preview.dry, preview.dry_files = planned(CHECK), list(FILES)
    states["preview"] = preview
    command = checked_state()
    command.stack += ["options", "command"]
    command.ticked = {"nintendo-gba"}
    states["command"] = command
    confirm = checked_state()
    confirm.stack.append("confirm")
    confirm.ticked = {"nintendo-gba"}
    confirm.dry = planned({**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                           "bytes_needed": 16384, "not_installable": 0})
    states["confirm"] = confirm
    return states


def _golden_run_states() -> dict:
    states = {}
    installing = checked_state()
    installing.stack.append("installing")
    installing.run, installing.running = "install", True
    installing.download = {"event": "download", "files": 4, "bytes": 1064964}
    installing.samples, installing.now = [(100.0, 12672), (104.0, 540672)], 104.0
    installing.network = 540672
    installing.progress = {"files_done": 2, "files_total": 4, "bytes_done": 540672,
                           "bytes_total": 1064964}
    installing.finished = [("gba_bios.bin", True, ""), ("scph5500.bin", False, "HTTP 404")]
    states["installing"] = installing
    states["result"] = golden_states_result()
    error = fresh_state()
    error.stack, error.run = ["setup", "error"], "check"
    error.error = ["  Could not fetch the file list for retroarch after 3 attempts: "
                   "[Errno -2] Name or service not known",
                   "  Address: https://raw.githubusercontent.com/Abdess/retrobios/main/"
                   "install/retroarch.json"]
    states["error"] = error
    quitting = fresh_state()
    quitting.stack = ["setup", "quit"]
    states["quit"] = quitting
    helped = checked_state()
    helped.help = True
    states["help"] = helped
    states["plan-games"] = games_state()
    listed = games_state()
    listed.stack.append("games")
    states["games"] = listed
    # What the plan and the result leave out by default, one press away.
    details = checked_state()
    details.stack.append("details")
    states["plan-details"] = details
    told = golden_states_result()
    told.stack.append("details")
    states["result-details"] = told
    states["plan-record"] = record_state()
    states["more"] = more_state("more")
    states["remove"] = more_state("more", "remove")
    states["removal"] = removal_state()
    states["removal-confirm"] = removal_state()
    install.tui_update(states["removal-confirm"], Key("enter"))
    states["removal-done"] = removal_done_state()
    states["backups"] = backups_state()
    states["pack-plan"] = pack_plan_state()
    states["pack-plan-parts"] = pack_plan_state(parts=3)
    states["pack-done"] = pack_done_state()
    return states


# What an install of the PlayStation and the Game Boy Advance recorded.
MORE_RECORD = {"written": "2026-11-03T12:00:00Z", "list": {"version": "v1", "generated": ""},
               "choice": ["--all-files"],
               "files": [{"dest": dest, "root": "", "sha1": "0" * 40, "size": size,
                          "from": "download"}
                         for dest, size in (("gba_bios.bin", 16384), ("pcsx/extra.bin", 4),
                                            ("scph5500.bin", 524288))]}


REMOVAL_PLAN = {"event": "removal_plan", "platform": "retroarch", "folder": str(SYSTEM_DIR),
                "files": 2, "bytes": 524292, "systems": ["sony-playstation"],
                "dests": ["pcsx/extra.bin", "scph5500.bin"],
                "kept": [{"dest": "scph5501.bin", "reason": "changed"}], "gone": 0,
                "backup": False, "message": ""}


BACKUPS = [{"event": "backup", "folder": str(HOME / ".config" / "retroarch" / "retrobios-backup"
                                             / name), "date": date, "files": files,
            "bytes": size, "source": source, "status": "listed", "message": ""}
           for name, date, files, size, source in (
               ("20261103-120000", "2026-11-03 12:00:00", 2, 524292, "remove"),
               ("20261020-093000", "2026-10-20 09:30:00", 1, 16384, "install"))]


def more_state(*screens: str) -> install.TuiState:
    """The plan of a folder whose record holds three files, More opened."""
    state = checked_state()
    state.record = json.loads(json.dumps(MORE_RECORD))
    for screen in screens:
        rows = install.tui_rows(state)
        state.focus[state.screen] = [row.action for row in rows].index(screen)
        assert install.tui_update(state, Key("enter")) == [], screen
    return state


def removal_state(system: bool = True) -> install.TuiState:
    """The removal plan of the PlayStation, read by its dry run."""
    state = more_state("more", "remove")
    values = [row.value for row in install.tui_rows(state)]
    state.focus["remove"] = values.index("sony-playstation") if system else 0
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("run", "removal_plan")], effects
    install.tui_receive(state, ("event", state.run_id, REMOVAL_PLAN))
    install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state


def removal_done_state() -> install.TuiState:
    state = removal_state()
    install.tui_update(state, Key("enter"))
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("run", "remove")], effects
    for dest, size in (("pcsx/extra.bin", 4), ("scph5500.bin", 524288)):
        install.tui_receive(state, ("event", state.run_id, {
            "event": "removed", "platform": "retroarch", "dest": dest, "size": size,
            "ok": True, "reason": "", "moved_to": ""}))
    install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state


def backups_state(purpose: str = "backups") -> install.TuiState:
    state = more_state("more")
    state.focus["more"] = [row.action for row in install.tui_rows(state)].index(purpose)
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("run", "backups")], effects
    for event in BACKUPS:
        install.tui_receive(state, ("event", state.run_id, event))
    install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state


PACK_PATH = HOME / "Downloads" / "RetroArch_Custom_BIOS_Pack.zip"


def pack_event(status: str, parts: int = 1, size: int = 0) -> dict:
    """The pack event of a dry run (planned) or a run (written), the pack
    whole or in parts on a FAT32 card."""
    names = ([PACK_PATH] if parts == 1 else
             [PACK_PATH.with_name(f"RetroArch_Custom_BIOS_Pack.part{n}of{parts}.zip")
              for n in range(1, parts + 1)])
    message = ("One ZIP." if parts == 1 else
               f"In {parts} parts of at most 3.9 GB, as FAT32 holds no file of 4 GB.")
    return {"event": "pack", "platform": "retroarch", "path": str(PACK_PATH), "files": 4,
            "bytes": 1049604, "size": size, "parts": [str(name) for name in names],
            "status": status, "message": message}


def pack_plan_state(parts: int = 1) -> install.TuiState:
    """More, Make a pack, its dry run read."""
    state = checked_state()
    rows = install.tui_rows(state)
    state.focus["plan"] = [row.action for row in rows].index("more")
    assert install.tui_update(state, Key("enter")) == []
    rows = install.tui_rows(state)
    state.focus["more"] = [row.action for row in rows].index("packmake")
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("run", "pack_plan")], effects
    install.tui_receive(state, ("event", state.run_id, pack_event("planned", parts)))
    install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state


def pack_done_state() -> install.TuiState:
    """The pack made, in three parts on a FAT32 card."""
    state = pack_plan_state(parts=3)
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("run", "pack")], effects
    install.tui_receive(state, ("event", state.run_id, {
        "event": "progress", "files_done": 4, "files_total": 4, "bytes_done": 1049604,
        "bytes_total": 1049604}))
    install.tui_receive(state, ("event", state.run_id,
                                pack_event("written", 3, size=1048000)))
    install.tui_receive(state, ("ended", state.run_id, 0, []))
    return state


# A board list as install/targets/ publishes it, read by Device: the boards
# by the names the list gives them, the device images each one runs.
TARGETS = {"bcm2711": {"cores": ["pcsx_rearmed"], "images": ["rpi4"]},
           "h700": {"cores": ["pcsx_rearmed", "mesen"],
                    "images": ["anbernic-rg35xx-plus", "anbernic-rg40xx-h"]},
           "x86_64": {"cores": None}}


def device_state(board: str = "h700") -> install.TuiState:
    """Device opened from Change, the board list in, the card in the reader
    naming its board (the check's board event)."""
    state = checked_state()
    if board:
        state.board_seen = ("retroarch", state.dest, board, True, False)
    state.stack.append("options")
    install.tui_update(state, Key("home"))
    rows = install.tui_rows(state)
    state.focus["options"] = [row.action for row in rows].index("device")
    effects = install.tui_update(state, Key("enter"))
    assert effects == [("targets", "retroarch")], effects
    install.tui_receive(state, ("targets", "retroarch", TARGETS, ""))
    return state


def record_setup(choice: list[str] | None = None) -> dict:
    """A record kept on 3 November of this year: the plan says 3 Nov in
    any year it runs."""
    year = time.localtime().tm_year
    return {"written": f"{year}-11-03T12:00:00Z", "list": {"version": "v1", "generated": ""},
            "choice": ["--system", "nintendo-gba"] if choice is None else choice,
            "files": [{"dest": "gba_bios.bin", "root": "", "sha1": "0" * 40, "size": 16384,
                       "from": "download"}]}


def record_state(setup: dict | None = None) -> install.TuiState:
    """The plan of a RetroArch folder whose record kept Game Boy Advance,
    its file changed by a release since, opened on the one setup found."""
    setup = record_setup() if setup is None else setup
    state = fresh_state()
    state.setups = state.setups[:1]
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["files"][2]["sha1"] = "1" * 40
    with mock.patch.object(install, "setup_record",
                           return_value=(setup, SYSTEM_DIR.parent / "x", "")), \
            mock.patch.object(install.Path, "exists", return_value=True), \
            mock.patch.object(install, "found_setups",
                              return_value=(state.setups, set())), \
            mock.patch.object(install, "detect_frontends", return_value=[]), \
            mock.patch.object(install, "_mounted_cards", return_value=[]), \
            mock.patch.object(install, "_DETECTION_REFUSED", []), \
            mock.patch.object(install.Path, "home", return_value=HOME):
        state, effects = install.tui_start(_args(), "linux")
    assert effects == [("fetch", "retroarch")], effects
    # Drawn as the other screens are, whatever the shell running the tests.
    state.home, state.pad = HOME, "both"
    effects = install.tui_receive(state, ("manifest", "retroarch", manifest))
    assert effects == [("run", "check")], effects
    gba = [event for event in FILES if event["dest"] == "gba_bios.bin"]
    systems = [event for event in SYSTEMS if event["system"] == "nintendo-gba"]
    check = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
             "bytes_needed": 16384, "not_installable": 0}
    for event in [*gba, *systems, check, plan_event(check)]:
        install.tui_receive(state, ("event", state.run_id, event))
    with mock.patch.object(install, "_tui_folder_facts", return_value={
            "free": 50 * 1024 ** 3, "writable": True, "cores": ["pcsx_rearmed"]}):
        install.tui_receive(state, ("ended", state.run_id, 1, []))
    return state


def golden_states_result() -> install.TuiState:
    """The result golden_states draws, a file failed and one kept."""
    result = checked_state()
    result.stack.append("result")
    result.code = 1
    result.log = "/tmp/retrobios-x/install.log"
    result.download = {"event": "download", "files": 4, "bytes": 1064964}
    result.summary = {
        "event": "summary", "mode": "install", "installed": 3, "up_to_date": 1, "pending": 1,
        "failed": [{"dest": "scph5500.bin", "reason": "HTTP 404"}],
        "skipped": [{"reason": "not_found", "label": "not found", "files": 2, "required": 1}],
        "left_out": [], "kept": [{"folder": str(HOME / ".config/retroarch/retrobios-backup/"
                                               "2026-10-23_1200"), "files": 1, "bytes": 4}],
        "interrupted": False}
    return result


def result_states() -> dict:
    """The result of a run that installed everything, of one with a file
    failed, of one --offline left files out of, and of one stopped."""
    def ended(code: int, **summary) -> install.TuiState:
        state = checked_state()
        state.stack.append("result")
        state.code = code
        state.download = {"event": "download", "files": 4, "bytes": 1064964}
        state.summary = {"event": "summary", "mode": "install", "installed": 4,
                         "up_to_date": 1, "pending": 0, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False, **summary}
        return state

    left = [{"dest": name, "reason": install.OFFLINE_WORDS}
            for name in ("scph5500.bin", "scph5501.bin", "pcsx/extra.bin")]
    offline = ended(1, installed=1, pending=3, failed=left)
    offline.failures = [{**failure, "kind": "offline", "url": ""} for failure in left]
    return {
        "done": ended(0),
        "partial": golden_states()["result"],
        "offline": offline,
        "stopped": ended(130, installed=2, interrupted=True),
    }


def urllib_error(reason: BaseException):
    import urllib.error

    return urllib.error.URLError(reason)


def found(dest: str, folder: str, reason: str = "") -> dict:
    return {"event": "found", "platform": "retroarch", "dest": dest, "folder": folder,
            "path": f"{folder}/{dest}", "member": "", "reason": reason}


class WindowsOs(types.ModuleType):
    """The os module with os.name "nt", everything else delegated."""

    def __init__(self) -> None:
        super().__init__("os")
        self.name = "nt"

    def __getattr__(self, attribute: str) -> object:
        return getattr(os, attribute)


class Pty:
    """install.py on a pseudo-terminal, its screen read back through pyte."""

    def __init__(self, args: list[str], env: dict, cols: int = 80, rows: int = 24,
                 program: list[str] | None = None) -> None:
        """program runs instead of this Python on install.py: the wrapper
        a user runs, install.sh."""
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.raw = b""
        with warnings.catch_warnings():
            # The child replaces itself at once: the fork-with-threads hazard
            # (a lock held by the loopback server thread) never reaches it.
            warnings.simplefilter("ignore", DeprecationWarning)
            self.pid, self.fd = pty.fork()
        if self.pid == 0:
            argv = program or [sys.executable, str(REPO_ROOT / "install.py")]
            os.execve(argv[0], [*argv, *args], env)
        self.resize(cols, rows)
        self.status: int | None = None

    def resize(self, cols: int, rows: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.screen.resize(rows, cols)

    def _pump(self, wait: float) -> bool:
        if not select.select([self.fd], [], [], wait)[0]:
            return True
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.raw += chunk
        self.stream.feed(chunk)
        return True

    def text(self) -> str:
        return "\n".join(line.rstrip() for line in self.screen.display)

    def settle(self, quiet: float = 0.3, timeout: float = 10.0) -> str:
        """The screen once nothing more arrives for `quiet` seconds.

        text() shows only what was read: a loop that sent a key and looked
        again saw the screen before the key, and on a slow runner pressed
        Enter twelve rows past the folder it was looking for.
        """
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not select.select([self.fd], [], [], quiet)[0]:
                break
            if not self._pump(0):
                break
        return self.text()

    def wait(self, needle: str, timeout: float = 20.0) -> str:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if needle in self.text():
                return self.text()
            if not self._pump(0.05):
                break
        if needle in self.text():
            return self.text()
        raise AssertionError(f"{needle!r} never shown:\n{self.text()}")

    def send(self, *keys: str) -> None:
        for key in keys:
            os.write(self.fd, key.encode())
            # The interface waits 40 ms to tell Esc from an arrow.
            time.sleep(0.15)

    def close(self, timeout: float = 30.0) -> int:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                while self._pump(0.05) and select.select([self.fd], [], [], 0)[0]:
                    pass
                # The modes the run left the terminal in: the master reads
                # the slave's.
                self.modes = termios.tcgetattr(self.fd)
                os.close(self.fd)
                self.status = os.WEXITSTATUS(status)
                return self.status
            self._pump(0.05)
        os.kill(self.pid, 9)
        raise AssertionError(f"still running:\n{self.text()}")

    def after(self) -> str:
        """What the terminal keeps once the full screen is gone."""
        return self.raw.split(b"\x1b[?1049l")[-1].decode("utf-8", "replace")


class SaveDirectoryRepository(FakeRepository):
    """The fake repository with one file read from RetroArch's save
    directory, as Azahar's keys.txt and 105 others of the real list."""

    KEYS = b"azahar keys"

    def __enter__(self) -> SaveDirectoryRepository:
        super().__enter__()
        path = self.root / "install" / "retroarch.json"
        manifest = json.loads(path.read_text())
        (self.root / "bios" / "keys.txt").write_bytes(self.KEYS)
        manifest["files"].append({
            "dest": "Azahar/Azahar/sysdata/keys.txt", "root": "save",
            "core_folder": "Azahar", "sha1": hashlib.sha1(self.KEYS).hexdigest(),
            "sha256": hashlib.sha256(self.KEYS).hexdigest(), "size": len(self.KEYS),
            "repo_path": "bios/keys.txt", "cores": ["azahar"],
            "systems": ["nintendo-3ds"]})
        manifest["save_directory"] = {"folder": "saves", "by_core": True}
        manifest["base_destination"] = "system"
        path.write_text(json.dumps(manifest))
        return self


def _app_card(test: unittest.TestCase, system: str) -> tuple[Path, Path]:
    """A card of system in the repository's tmp/, its root and BIOS folder."""
    root = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, root, True)
    return root / "card", make_card(root / "card", system)


def _installed_state(dest: Path, code: int = 0, failed: list | None = None) -> install.TuiState:
    """The result screen of an install into dest."""
    state = fresh_state()
    state.platform, state.dest, state.manifest = "retroarch", dest, MANIFEST
    state.stack, state.run, state.code = ["result"], "install", code
    state.summary = {"event": "summary", "mode": "install", "installed": 5, "up_to_date": 0,
                     "pending": 0, "failed": failed or [], "skipped": [], "left_out": [],
                     "kept": [], "interrupted": False}
    return state


def _terminfo_entry(name: str, cup: str | None, extended: bool = False,
                    colours: int | None = 8) -> bytes:
    """A compiled term(5) entry holding the strings up to cursor_address,
    only that one set, and the numbers up to max_colors when colours is
    given, columns alone when it is not."""
    def short(value: int) -> bytes:
        return value.to_bytes(2, "little", signed=True)

    width = 4 if extended else 2
    names = name.encode() + b"|test terminal\0"
    table = (cup.encode("latin-1") + b"\0") if cup is not None else b""
    offsets = [-1] * (install._TERMINFO_CUP + 1)
    if cup is not None:
        offsets[install._TERMINFO_CUP] = 0
    numbers = [80] + ([-1] * (install._TERMINFO_COLORS - 1) + [colours]
                      if colours is not None else [])
    body = names + (b"\0" if len(names) % 2 else b"")
    body += b"".join(number.to_bytes(width, "little", signed=True) for number in numbers)
    body += b"".join(short(offset) for offset in offsets) + table
    header = b"".join(short(value) for value in (
        0o1036 if extended else 0o432, len(names), 0, len(numbers), len(offsets),
        len(table)))
    return header + body


def _terminfo_folder(test: unittest.TestCase) -> Path:
    """A $TERMINFO with a glass terminal, a VT52, two ANSI terminals of 8
    colours, one in the extended format, and two ANSI terminals without
    colour: one naming 2, one naming none (vt100)."""
    folder = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, folder, True)
    ansi = "\x1b[%i%p1%d;%p2%dH"
    for name, cup, extended, colours in (
            ("rbtest-glass", None, False, None),
            ("rbtest-vt52", "\x1bY%p1%' '%+%c%p2%' '%+%c", False, None),
            ("rbtest-ansi", ansi, False, 8),
            ("rbtest-ansi2", ansi, True, 256),
            ("rbtest-two", ansi, True, 2),
            ("rbtest-mono", ansi, False, None)):
        (folder / "r").mkdir(exist_ok=True)
        (folder / "r" / name).write_bytes(_terminfo_entry(name, cup, extended, colours))
    return folder


def games_part(card: Path) -> Path:
    """An ArkOS EASYROMS (dArkOS game_systems.txt: themes, launchimages
    with loading.jpg) or an AmberELEC GAMES (autostart.sh: gamedata,
    homebrew with gamelist.xml), console folders beside them."""
    marks = (("gamedata/retroarch", "homebrew") if card.name.startswith("GAMES")
             else ("themes/es-theme-nes-box", "launchimages"))
    for folder in ("bios", "nes", "gba", "psx", *marks):
        (card / folder).mkdir(parents=True)
    if card.name.startswith("GAMES"):
        (card / "homebrew" / "gamelist.xml").write_text("<gameList/>\n")
    else:
        (card / "launchimages" / "loading.jpg").write_bytes(b"\xff\xd8")
    return card


class _Decided(Exception):
    """Raised where line mode has chosen its platforms and folders."""


def line_decision(args: argparse.Namespace, answer) -> tuple[list, str]:
    """(platforms, text) line mode reaches at a terminal for args: the run
    stops where its platforms are known, before anything is read or written.
    answer(prompt) answers each question."""
    def stop(_args, platforms):
        raise _Decided(platforms)

    # --verbose's text, which names what detection found.
    args.verbose = True
    install.LOCAL.reset()
    with mock.patch.object(install, "app_refusal", side_effect=stop), \
            mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
            mock.patch.object(install, "_is_terminal", return_value=True), \
            mock.patch.object(install, "_ask", side_effect=answer), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()) as out, \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            install._install(args, io.StringIO())
        except _Decided as decided:
            return decided.args[0], out.getvalue()
        finally:
            install.LOCAL.reset()
    raise AssertionError("line mode chose nothing:\n" + out.getvalue())


def screen_decision(args: argparse.Namespace) -> tuple[str, Path]:
    """(platform, folder) the full screen reaches for args, A pressed on
    whatever it offers first, as Enter is in line mode."""
    install.LOCAL.reset()
    with mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            state, effects = install._tui_startup(args)
            for _press in range(6):
                if any(effect[0] == "fetch" for effect in effects):
                    return state.platform, state.dest
                effects = install.tui_update(state, Key("enter"))
        finally:
            install.LOCAL.reset()
    raise AssertionError(f"the screen chose nothing: {state.stack}")


def screen_keys(args: argparse.Namespace, presses: list,
                until: tuple = ("fetch", "run")) -> install.TuiState:
    """The full screen for args once the keys are pressed, stopped as soon
    as it fetches the list or starts a run (until)."""
    install.LOCAL.reset()
    with mock.patch.object(install, "detect_os", return_value="linux"), \
            mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
            contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        try:
            state, effects = install._tui_startup(args)
            for key in presses:
                if any(effect[0] in until for effect in effects):
                    break
                effects = install.tui_update(state, key if isinstance(key, Key) else Key(key))
            return state
        finally:
            install.LOCAL.reset()


def engine_events(args: argparse.Namespace) -> tuple[list[dict], str]:
    """(events, text) of the line engine run in this process with --events,
    the run the screen starts for its check."""
    stream = io.StringIO()
    install.LOCAL.reset()
    try:
        with mock.patch.object(install.EVENTS, "stream", stream), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                contextlib.suppress(SystemExit):
            install._install(args, io.StringIO())
    finally:
        install.LOCAL.reset()
    return [json.loads(line) for line in stream.getvalue().splitlines()], out.getvalue()


class _CardFixtures:
    """Drives, lists and packs for the classes that test them on the screen and
    in line mode."""

    ABOUT = "system/configs/emulationstation/about.info"

    def drive(self, name: str, files: dict) -> Path:
        root = self.root / "media" / name
        root.mkdir(parents=True)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        return root

    def renamed(self) -> dict:
        """Renamed drives: KNULLI and Batocera each
        renamed in its own menu, with and without the file KNULLI alone
        writes, and Recalbox's share."""
        conf = "system/batocera.conf"
        return {
            "KNULLI renamed": self.drive("K1", {self.ABOUT: "KNULLI\n",
                                                conf: "system.hostname=RG40XXH\n"}),
            "KNULLI as shipped": self.drive("K2", {self.ABOUT: "KNULLI\n",
                                                   conf: "system.hostname=KNULLI\n"}),
            "renamed, no about.info": self.drive("K3", {conf: "system.hostname=RG40XXH\n"}),
            "Batocera as shipped": self.drive("B1", {conf: "system.hostname=BATOCERA\n"}),
            "Batocera, no hostname": self.drive("B2", {conf: "# system.hostname=X\n"}),
            "Recalbox": self.drive("R1", {"system/recalbox.conf": "a=1\n"}),
            "two shares": self.drive("T1", {conf: "system.hostname=BATOCERA\n",
                                            "system/recalbox.conf": ""}),
        }

    def minui(self, plat: str = "minui", systems: bool = False, cores: bool = True,
              regions: bool = True) -> tuple[Path, Path, dict]:
        """A list of plat's shape (the MinUI family records cores and regions,
        no system), the pack built from it and the files' payloads."""
        from tests.installsupport import GBA, JP, US

        payloads = {"Bios/MGBA/gba_bios.bin": (GBA, "nintendo-gba", "mgba", None),
                    "Bios/PS/scph5501.bin": (US, "sony-playstation", "pcsx_rearmed",
                                             "north-america"),
                    "Bios/PS/scph5500.bin": (JP, "sony-playstation", "pcsx_rearmed", "japan")}
        files = []
        for dest, (data, system, core, region) in payloads.items():
            entry = {"dest": dest, "sha1": hashlib.sha1(data).hexdigest(), "size": len(data),
                     "repo_path": f"bios/{dest}", "cores": [core] if cores else None}
            if systems:
                entry["systems"] = [system]
            if regions and region:
                entry.update(regions=[region], region_groups=["ps"])
            files.append(entry)
        listing = self.root / f"{plat}.json"
        install_list = {"manifest_version": 2, "platform": plat, "files": files}
        listing.write_text(json.dumps(install_list))
        if sys.version_info < BUILDER_FLOOR:
            # generate_pack.py's context managers need Python 3.9.
            return listing, None, {}
        from packs import scope

        pack_list = {"files": [{"path": dest, "sha1": entry["sha1"], "size": entry["size"]}
                               for dest, entry in zip(payloads, files)]}
        scope.annotate_pack_systems(pack_list, scope.pack_systems(install_list))
        name = {"minui": "MinUI", "misterfpga": "MiSTer_FPGA"}[plat]
        pack = self.root / f"{name}_v1_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            for dest, (data, *_rest) in payloads.items():
                archive.writestr(dest, data)
            archive.writestr("manifest.json", json.dumps(pack_list))
        return listing, pack, pack_list

    def narrowed(self, plat: str, **given) -> tuple[int, str, list]:
        """(exit code, what was said, the files kept) of a --dry-run narrowed
        as given."""
        dest = self.root / f"dest-{plat}"
        if plat == "misterfpga" and not dest.exists():
            # A MinUI card is another system's card for MiSTer's list.
            dest.mkdir()
            for marker in ("MiSTer", "menu.rbf"):
                (dest / marker).write_text("", encoding="utf-8")
        elif not dest.exists():
            make_card(dest, "MinUI")
        stream = io.StringIO()
        code = 0
        with mock.patch.object(install.EVENTS, "stream", stream), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                install._install(_args(platform=plat, dest=dest, dry_run=True, events=True,
                                       no_input=True, declared_only=False, **given),
                                 io.StringIO())
            except SystemExit as stop:
                code = stop.code
            finally:
                install.LOCAL.reset()
        kept = [json.loads(line)["dest"] for line in stream.getvalue().splitlines()
                if '"event": "file"' in line]
        return code, out.getvalue() + err.getvalue(), kept


class _OutsideTextFindings:
    """A pack's member path, a --manifest dest, the
    names a list records, a card's label and a retroarch.cfg folder reached
    line mode, the events and the disk with their control characters. Each
    source is fed escape sequences, and none comes out raw."""

    OSC = "\x1b]0;PWNED\x07"
    CSI = "\x1b[41m"

    @property
    def dest(self) -> Path:
        dest = self.root / "dest"
        dest.mkdir(exist_ok=True)
        return dest

    def assertClean(self, text: str, where: str) -> None:
        self.assertNotIn("\x1b", text, where)
        self.assertNotIn("\x07", text, where)

    def assertNothingRawOnDisk(self) -> None:
        for path in self.root.rglob("*"):
            self.assertIsNone(install._CONTROLS.search(path.name), path)

    def run_install(self, args: argparse.Namespace, mounts: list = (),
                    env: dict | None = None) -> str:
        events = io.StringIO()
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        with mock.patch.object(install, "_UNNAMEABLE", []), \
                mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "stream", events), \
                mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1", **(env or {})}), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(SystemExit):
            install._install(args, io.StringIO())
        return out.getvalue() + err.getvalue() + events.getvalue()

    def test_a_pack_member_path_is_refused(self):
        from tests.installsupport import _pack, GBA

        pack = _pack(self.root, "RetroArch_v1_BIOS_Pack.zip", {f"x{self.OSC}.bin": GBA})
        text = self.run_install(_args(platform="retroarch", dest=self.dest,
                                      from_pack=[pack], no_input=True, declared_only=False))
        self.assertClean(text, "pack")
        self.assertIn("is not valid: unsafe", text)
        self.assertEqual(list(self.dest.iterdir()), [])
        self.assertNothingRawOnDisk()

    def test_a_list_dest_and_its_names_are_refused_or_shown(self):
        files = [{"dest": f"x{self.CSI}BAD.bin", "sha1": "0" * 40, "size": 1,
                  "repo_path": "bios/x", "cores": None, "systems": ["a"]}]
        listing = self.root / "list.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                       "files": files}))
        text = self.run_install(_args(platform="retroarch", dest=self.dest, manifest=listing,
                                      no_input=True, dry_run=True, verbose=True,
                                      declared_only=False))
        self.assertClean(text, "--manifest dest")
        self.assertIn("unsafe", text)
        named = {"manifest_version": 2, "platform": "retroarch", "files": [
            {**files[0], "dest": "a.bin", "systems": [f"a{self.CSI}"],
             "cores": [f"core{self.OSC}"]}],
            "system_titles": {f"a{self.CSI}": f"Title{self.OSC}"}}
        cleaned = install._validate_manifest(named, "retroarch")
        self.assertClean(json.dumps(cleaned, ensure_ascii=False), "names")
        self.assertNothingRawOnDisk()

    def test_a_card_label_is_shown_and_never_obeyed(self):
        card = self.root / "media" / f"S{self.CSI}RED"
        (card / "system").mkdir(parents=True)
        (card / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        listing = self.root / "batocera.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                       "files": []}))
        with mock.patch.object(install, "detect_platforms", return_value=[]):
            text = self.run_install(_args(platform="batocera", manifest=listing,
                                          no_input=True, dry_run=True, events=True,
                                          declared_only=False), [card])
        self.assertIn("S?[41mRED", text)
        self.assertClean(text, "card label")
        self.assertClean(install.card_line(card), "card row")

    def test_a_folder_a_config_names_is_refused(self):
        home = self.root / "home"
        weird = home / f"sys{self.OSC}x"
        weird.mkdir(parents=True)
        cfg = home / ".config" / "retroarch" / "retroarch.cfg"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(f'system_directory = "{weird}"\n')
        listing = self.root / "retroarch.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                       "files": []}))
        text = self.run_install(
            _args(manifest=listing, no_input=True, dry_run=True, events=True,
                  declared_only=False),
            env={"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                 "RETROBIOS_OS": "linux"})
        self.assertClean(text, "retroarch.cfg")
        self.assertIn("holds a control character", text)
        self.assertNotIn("using default path", text)
        self.assertNotIn(str(home / ".config" / "retroarch" / "system"), text)

    def test_a_path_with_a_control_character_is_no_relative_path(self):
        for value in ("a\x1bb.bin", "a\x07.bin", "a\x9bb.bin", "a\nb.bin"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                install._safe_relative_path(value, "dest")
        self.assertEqual(install.shown_path(Path("/a/b\x1b[2Jc")), "/a/b?[2Jc")


class LineModeRuns:
    """Line mode and the screen run on one machine: the runs the classes that
    compare them borrow."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.dict(os.environ, {"HOME": str(self.root / "home"),
                                                     "XDG_CONFIG_HOME": str(self.root / "cfg"),
                                                     "RETROBIOS_OS": "linux"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.list = self.root / "retroarch.json"
        self.list.write_text(json.dumps({"manifest_version": 2, "platform": "retroarch",
                                         "files": []}))
        self.here = self.root / "pc" / "system"
        self.here.mkdir(parents=True)

    def both(self, mounts: list, found: list, **given) -> tuple:
        def answer(prompt: str) -> str:
            # The first entry of a numbered list, the default of a folder,
            # the first drive of a folder question that has no default.
            first = prompt.startswith(">") or ("Enter for" not in prompt and " or 1" in prompt)
            return "1" if first else ""

        extra = {"declared_only": False, "offline": False}
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=found), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            platforms, text = line_decision(_args(**extra, **given), answer)
            install._DETECTED_OS.clear()
            screen = screen_decision(_args(**extra, **given))
        return platforms[0], screen, text

    def line_run(self, args: argparse.Namespace, answers: list, mounts: list = (),
                 found: list = ()) -> tuple[str, list]:
        """(text, prompts) of line mode at a terminal for args, the answers
        given in turn: the run stops at the first question left unanswered.
        Its text is --verbose's: these findings read the lines the default
        leaves out."""
        args.verbose = True
        given, asked = iter(answers), []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            try:
                return next(given)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        # The options the run was started with, as main() records them.
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, io.StringIO())
        return out.getvalue() + err.getvalue(), asked

    def listing(self, plat: str, files: list, **extra) -> Path:
        path = self.root / f"{plat}-{len(list(self.root.glob('*.json')))}.json"
        path.write_text(json.dumps({"manifest_version": 2, "platform": plat,
                                    "files": files, **extra}))
        return path

    @staticmethod
    def entry(dest: str, payload: bytes, systems: list, **extra) -> dict:
        return {"dest": dest, "sha1": hashlib.sha1(payload).hexdigest(),
                "size": len(payload), "repo_path": f"bios/{dest}", "cores": None,
                "systems": systems, **extra}


def sgr(col: int, row: int, button: int = 0, release: bool = False) -> str:
    """An SGR mouse report, the cell counted from 1."""
    return f"\x1b[<{button};{col};{row}{'m' if release else 'M'}"


def x10(col: int, row: int, button: int = 0) -> str:
    """A legacy report: 32 plus each value."""
    return "\x1b[M" + "".join(chr(32 + value) for value in (button, col, row))


def drawn(state: install.TuiState, cols: int, rows: int) -> list:
    """The frame as the loop draws it, its targets kept as the loop keeps them."""
    state.cols, state.rows = cols, rows
    lines = install.tui_view(state, cols, rows)
    state.hits = install.tui_hits(state, lines)
    return lines


def settled(state: install.TuiState) -> None:
    """The clock moved on past TUI_TAP_SETTLE since the screen was drawn.
    A millisecond past it: shown + 0.4 - shown is 0.39999 once the clock is
    large, as a CI runner's uptime makes it, and the tap read as too early."""
    if state.hits is not None:
        state.now = max(state.now, state.hits.shown + install.TUI_TAP_SETTLE + 0.001)


def tap(state: install.TuiState, col: int, row: int, button: int = 0) -> list:
    """Press and release on one cell, columns and lines counted from 0, made
    once the screen settled (TUI_TAP_SETTLE): a reader's deliberate tap."""
    settled(state)
    effects = install.tui_update(state, install.TuiMouse(button, col + 1, row + 1))
    return effects + install.tui_update(state, install.TuiMouse(button, col + 1, row + 1,
                                                                True))


def _game_state() -> install.TuiState:
    """The plan of checked_state, its PlayStation extra marked game data and
    read from the save directory, the check's events fed in."""
    state = checked_state()
    manifest = json.loads(json.dumps(state.manifest))
    for entry in manifest["files"]:
        if entry["dest"] == "pcsx/extra.bin":
            entry.update(category="game_data", root="save")
    manifest["save_directory"] = {"folder": "saves", "by_core": True}
    state.manifest = manifest
    state.saves = {"event": "saves", "files": 1, "folder": "/home/user/.config/retroarch/saves"}
    return state


class ChoiceRuns:
    """A run's events received and a game list planned, borrowed by the classes
    that check one choice per run."""

    @staticmethod
    def receive(state: install.TuiState, events: list, facts: dict | None = None) -> None:
        """A check's events, then its end."""
        for event in events:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value=facts or {
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))

    def game_manifest(self) -> dict:
        """Three systems, each with one BIOS file and one game data file."""
        files = []
        for system in ("nintendo-ds", "sega-dreamcast", "sony-playstation"):
            files += [{"dest": f"{system}.bin", "size": 100, "systems": [system],
                       "cores": None},
                      {"dest": f"{system}/game.dat", "size": 1000, "systems": [system],
                       "cores": None, "category": install.GAME_DATA}]
        # Dreamcast holds only game data.
        files = [entry for entry in files if entry["dest"] != "sega-dreamcast.bin"]
        return {"manifest_version": 2, "platform": "retroarch", "categorized": True,
                "files": files}

    def game_events(self, manifest: dict, left_out: bool = False,
                    only: tuple = ()) -> list:
        """The events of a check over manifest, game data left out or not,
        the files of only those systems when given (--emulator)."""
        kept = [entry for entry in manifest["files"]
                if not only or entry["systems"][0] in only]
        files = [entry for entry in kept
                 if not (left_out and entry.get("category") == install.GAME_DATA)]
        events = [{"event": "file", "platform": "retroarch", "dest": entry["dest"],
                   "systems": entry["systems"], "size": entry["size"], "state": "missing"}
                  for entry in files]
        systems = sorted({entry["systems"][0] for entry in files})
        events += [{"event": "system", "platform": "retroarch", "system": system,
                    "name": system, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                    "bytes_needed": 100} for system in systems]
        games = [entry["dest"] for entry in kept if entry.get("category") == install.GAME_DATA]
        events.append({"event": "summary", "mode": "check", "installed": 0, "up_to_date": 0,
                       "pending": len(files), "failed": [], "skipped": [],
                       "left_out": [{"category": install.GAME_DATA, "label": "game data",
                                     "files": len(games), "dests": games}]
                       if left_out else [], "kept": [], "interrupted": False})
        events.append({"event": "check", "platform": "retroarch", "name": "RetroArch",
                       "bios_dir": str(SYSTEM_DIR), "files": len(files), "present": 0,
                       "missing": len(files), "wrong_hash": 0,
                       "bytes_needed": sum(entry["size"] for entry in files),
                       "data_missing": 0, "not_installable": 0})
        return events

    def game_plan(self, only: tuple = ()) -> install.TuiState:
        state = fresh_state()
        state.stack = ["setup"]
        manifest = self.game_manifest()
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", manifest))
        self.receive(state, self.game_events(manifest, only=only))
        return state


class ChoiceScreens:
    """A game list and a screen drawn as text, borrowed by the classes that check
    a choice in both modes."""

    @staticmethod
    def screen(state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
        return " ".join(" ".join(str(line).split())
                        for line in install.tui_view(state, cols, rows))

    def game_listing(self) -> Path:
        manifest = self.game_manifest()
        return self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"]], categorized=True)


class DriveRuns:
    """A drive made a card by its files, and the first screens it opens on."""

    def drive(self, name: str, folders: tuple) -> Path:
        root = self.root / "media" / name
        for folder in folders:
            (root / folder).mkdir(parents=True)
        return root

    def first_screen(self, mounts: list) -> install.TuiState:
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install.Path, "home", return_value=self.root / "home"):
            state, _effects = install.tui_start(_args(), "linux")
        return listed(state)

    def folder_screen(self, mounts: list) -> tuple[install.TuiState, str, list]:
        """RetroArch chosen on the first screen: (state, Which folder? at
        80x40, its rows)."""
        state = self.first_screen(mounts)
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            install.tui_update(state, Key("enter"))
            self.assertEqual(state.screen, "folder")
            return state, self.screen(state, 80, 40), install.tui_rows(state)


class ProvenRuns:
    """Line mode's text for a run, borrowed by the classes that count what it
    proves."""

    def line_from(self, args: argparse.Namespace, answers: list,
                  folders: list[Path] = ()) -> tuple[str, list]:
        """(text, prompts) of line mode at a terminal, the result included,
        the folders --from names read first, as main() reads them: --verbose's
        text."""
        args.verbose = True
        given, asked = iter(answers), []

        def answer(prompt: str) -> str:
            asked.append(prompt)
            try:
                return next(given)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        if folders:
            setattr(args, "from", [str(folder) for folder in folders])
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        stream = io.StringIO()
        with mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, stream)
        return out.getvalue() + err.getvalue() + stream.getvalue(), asked
