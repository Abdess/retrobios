"""One choice per run, kept the same in line mode and on the full screen, the
focus after a choice, and installing what its option installs."""

from __future__ import annotations

import tests

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PureWindowsPath
from unittest import mock

import install
from tests.netguard import module_guard
from tests.tuisupport import (
    _app_card, _args, BUILDER_FLOOR, CHECK, checked_state, ChoiceRuns, ChoiceScreens, drawn, FILES,
    found, fresh_state, _game_state, games_part, HOME, in_full, install_run, _installed_state, Key,
    LineModeRuns, listed, MANIFEST, planned, press, REPO_ROOT, SYSTEM_DIR, tap,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_choices")


class OneChoicePerRun(unittest.TestCase):
    """One choice for the run, taps that
    never commit what was not seen, and the words that fit."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    listing = LineModeRuns.listing
    entry = staticmethod(LineModeRuns.entry)

    receive = staticmethod(ChoiceRuns.receive)

    game_manifest = ChoiceRuns.game_manifest

    game_events = ChoiceRuns.game_events

    game_plan = ChoiceRuns.game_plan

    # Root cause 2: one choice for the whole run.

    def test_the_game_data_row_keeps_the_systems_ticked(self):
        """The plan's game data row set the ticks back to
        every system, and the install wrote all of them."""
        state = self.game_plan()
        state.ticked = {"nintendo-ds"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        self.assertEqual(state.ticked, {"nintendo-ds"})
        self.assertIn(("--system", "nintendo-ds"), install.tui_flags(state))
        self.assertIn(("--no-game-data", None), install.tui_flags(state))

    def test_every_check_of_the_same_list_keeps_the_choice(self):
        """A folder to copy from added, the
        save folder chosen or Check again set the ticks back to every system
        too, as the game data row did."""
        for how in ("from", "savedir", "recheck"):
            with self.subTest(how=how):
                state = self.game_plan()
                state.ticked = {"nintendo-ds"}
                if how == "from":
                    state.browse_for, state.browse_dir = "from", self.root
                    state.stack.append("browse")
                    install._activate(state, install.TuiRow("use", "Use this folder"))
                elif how == "savedir":
                    state.browse_for, state.browse_dir = "save", self.root
                    state.stack.append("browse")
                    install._activate(state, install.TuiRow("use", "Use this folder"))
                else:
                    install._activate(state, install.TuiRow("recheck", "Check again"))
                self.assertEqual(state.screen, "checking")
                self.receive(state, self.game_events(self.game_manifest()))
                self.assertEqual(state.ticked, {"nintendo-ds"})

    def test_a_choice_the_toggle_empties_says_so_and_offers_choose_systems(self):
        """Dreamcast alone, game data left out: the plan
        promised the whole list and Install refused."""
        state = self.game_plan()
        state.ticked = {"sega-dreamcast"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("sega-dreamcast holds only game data: nothing is left to install.", text)
        actions = [row.action for row in install.tui_rows(state)]
        self.assertNotIn("install", actions)
        self.assertEqual(actions[0], "systems")
        # Kept again, the same system comes back.
        state.focus["plan"] = actions.index("gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest()))
        self.assertEqual(state.ticked, {"sega-dreamcast"})

    def test_the_row_counts_the_list_the_check_read(self):
        """Under --emulator the row counted the game
        data of every system, line mode's g the emulator's alone."""
        state = self.game_plan(only=("nintendo-ds",))
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual(row.right, "1 file, 1000 B")
        # Line mode, the same list narrowed as --emulator narrows it.
        manifest = self.game_manifest()
        listing = self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"] if entry["systems"] == ["nintendo-ds"]],
            categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True), [""])
        self.assertIn("g) Game data: kept (1 file, 1000 B)", text)

    def test_line_mode_names_the_game_data_of_the_systems_chosen(self):
        """--system with --no-game-data named the game
        data of the whole list."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        listing = self.listing("retroarch", files, categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True,
                                           system=["nintendo-gba"], no_game_data=True), [])
        self.assertNotIn("doom1.wad", text)
        self.assertNotIn("game data file left out", text)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True,
                                           system=["doom"], no_game_data=True), [])
        # The choice holds no file: said, never "All files up to date", nor
        # "unknown system" for a system the list names.
        self.assertIn("doom holds only game data: nothing is left to install.", text)
        self.assertNotIn("All files up to date", text)
        self.assertNotIn("unknown system", text)

    def test_the_run_head_counts_three_kinds_and_defines_them(self):
        """A run without the menu split two kinds beside
        the plan's three, from a second counting function."""
        self.assertFalse(hasattr(install, "split_words"))
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("doom/doom1.wad", b"wad" * 10, ["doom"], category="game_data")]
        listing = self.listing("retroarch", files, categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True, no_input=True),
                                     [])
        head = text[:text.index("Checking existing files")]
        self.assertIn("1 BIOS file (3 B) and 1 game data file (30 B).", head)
        self.assertIn("Game data: files a game or a game engine reads", head)

    def test_the_cores_of_the_systems_chosen_come_first(self):
        """With --system sony-playstation, Cores opened
        on every core of the list."""
        state = checked_state()
        state.cli_systems = ["sony-playstation"]
        state.stack.append("cores")
        values = [row.value for row in install.tui_rows(state) if row.action == "core"]
        self.assertEqual(values, ["pcsx_rearmed"])
        rows = install.tui_rows(state)
        more = next(i for i, row in enumerate(rows) if row.action == "morecores")
        self.assertEqual(rows[more].label, "Cores of the other systems: 1")
        state.focus["cores"] = more
        install.tui_update(state, Key("enter"))
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["mesen", "pcsx_rearmed"])

    def test_line_mode_counts_the_systems_that_hold_a_file(self):
        """"2 of 8" in line mode, "1 of 8" on the screen."""
        files = [self.entry("ds.bin", b"ds", ["nintendo-ds"]),
                 self.entry("dc/game.dat", b"dc", ["sega-dreamcast"], category="game_data"),
                 self.entry("psx.bin", b"psx", ["sony-playstation"])]
        listing = self.listing("retroarch", files, categorized=True,
                               system_titles={"nintendo-ds": "Nintendo DS",
                                              "sega-dreamcast": "Sega Dreamcast",
                                              "sony-playstation": "Sony PlayStation"})
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "1,2", "g"])
        last = text[text.rindex("Counted again"):]
        self.assertIn("for 1 of 2 systems.", last)
        # The screen, the same choice: DS and Dreamcast ticked, game data
        # left out on the plan.
        state = self.game_plan()
        state.ticked = {"nintendo-ds", "sega-dreamcast"}
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        install.tui_update(state, Key("enter"))
        self.receive(state, self.game_events(self.game_manifest(), left_out=True))
        self.assertIn("for 1 of 2 systems", str(install.tui_view(state, 80, 24)[2]))

    # Root cause 3: copies and packs.

    def test_confirm_counts_the_copies_a_folder_holds(self):
        """Confirm called the files packx holds
        downloads, offline and online."""
        state = checked_state()
        state.found = [found(event["dest"], "/media/old") for event in FILES]
        state.stack.append("confirm")
        state.dry = planned(CHECK, files=0, bytes=0,
                            copied=[event["dest"] for event in FILES])
        state.dry_files = list(FILES)
        for env in ({install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}, {}):
            with self.subTest(offline=bool(env)), mock.patch.dict(os.environ, env):
                text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                self.assertIn("4 found in old, nothing to download", text)
                self.assertNotIn("need the internet", text)
                self.assertNotIn("to download,", text)

    def test_an_old_card_holding_every_file_in_place_is_not_called_empty(self):
        """"packx holds none of these files" when all 22
        were in place."""
        state = checked_state()
        state.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                       "bytes_needed": 0}
        state.files = []
        state.from_folders = [Path("/media/packx")]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Nothing to copy from packx: every file is in place.", text)
        self.assertNotIn("holds none of these files", text)

    def test_the_plan_says_what_the_pack_lacks_before_a_size(self):
        """"8358 files to install from the pack, 6.6 GB"
        from a pack that held none of them."""
        state = checked_state()

        class Lacking:
            name = "RetroArch_BIOS_Pack.zip"

            @staticmethod
            def find(entry: dict) -> tuple | None:
                return (None, entry) if entry["dest"] == "gba_bios.bin" else None

        dests = [event["dest"] for event in FILES]
        state.check = planned(CHECK, files=1, bytes=16384,
                              lacking=[dest for dest in dests if dest != "gba_bios.bin"])
        with mock.patch.object(install.LOCAL, "pack", Lacking()):
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
            self.assertIn("1 file to install from the pack, 16.0 KB", text)
            self.assertIn("3 of these 4 files are not in RetroArch_BIOS_Pack.zip", text)
            state.check = planned(CHECK, files=0, bytes=0, lacking=dests)
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
            self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 4 files", text)
            self.assertNotIn("install", [row.action for row in install.tui_rows(state)])

    def test_a_failed_pack_install_leaves_no_folder_behind(self):
        """405 empty folders and a saves folder."""
        pack_dir = self.root / "downloads"
        pack_dir.mkdir()
        pack = pack_dir / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
        files = [self.entry(f"deep/folder{n}/file.bin", b"x", ["nintendo-gba"])
                 for n in range(3)]
        listing = self.listing("retroarch", files)
        dest = self.root / "new" / "system"
        dest.parent.mkdir()
        text, _asked = self.line_run(_args(manifest=listing, from_pack=[pack], dest=dest,
                                           declared_only=False, yes=True, no_input=True), [])
        self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 3 files", text)
        self.assertFalse(dest.exists(), list(dest.rglob("*")) if dest.exists() else [])

    # Root cause 4: Choose another folder.

    def test_choose_another_folder_opens_the_folder_screen(self):
        """With --dest the create screen is alone on the
        stack, and Choose another folder asked Quit?."""
        state = fresh_state()
        state.platform, state.dest = "retroarch", self.root / "missing" / "bios"
        state.stack = ["create"]
        state.facts = {"nearest": self.root, "risky": False}
        state.focus["create"] = 1
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "folder")
        self.assertEqual(install.tui_view(state, 80, 24)[0].strip(),
                         "RetroBIOS: Which folder?")

    # Root cause 5: text that fits.

    def test_the_version_note_stays_on_the_40x12_plan_and_in_every_farewell(self):
        note = "This list was built for RetroBat 8.3.1, this machine runs 8.2.0.1."
        state = checked_state()
        state.version = note
        state.files = []
        state.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                       "bytes_needed": 0}
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn(note, text)
        state.exit_code = 0
        self.assertIn(note, install.tui_farewell(state))
        state.exit_code, state.quit_asked = install.QUIT_CODE, True
        self.assertIn(note, install.tui_farewell(state))

    @in_full
    def test_the_help_defines_game_data_at_40_columns(self):
        """The row was a choice nothing explained on the
        Miyoo's screen."""
        state = _game_state()
        state.mouse = True
        state.help = True
        for rows in (12, 15):
            with self.subTest(rows=rows):
                text = " ".join(" ".join(install.tui_view(state, 40, rows)).split())
                self.assertIn("Game data: files a game or a game engine reads", text)
        # Data files too, each said whole: in a few words at 40x12.
        state.check = {**state.check, "data_missing": 7, "data_bytes": 2048}
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Game data: what a game reads, of no use to other cores. Data files: "
                      "an emulator's own data folder.", text)
        text = " ".join(" ".join(install.tui_view(state, 40, 15)).split())
        self.assertIn("such as Dolphin's Sys and PPSSPP's assets.", text)

    def test_the_40_column_bar_keeps_help_and_the_help_its_tap_line(self):
        state = checked_state()
        state.mouse = True
        state.stack.append("systems")
        state.focus["systems"] = 1
        bar = str(install.tui_view(state, 40, 12)[-1])
        self.assertIn("? Help", bar)
        state.help = True
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Tap Tick or untick a row, as A", text)

    def test_one_spelling_of_a_folder_on_the_plan_and_the_result(self):
        """"/home...i_audit13/rb/bios" on the plan, the
        same folder whole and folded inside a name on the result."""
        dest = Path("/home/moi/retroarch_system/tmp/tui_audit13/rb/bios")
        for cols in (40, 80):
            with self.subTest(cols=cols):
                plan = checked_state()
                plan.dest = dest
                result = _installed_state(dest)
                spelled = []
                for state in (plan, result):
                    lines = [str(line).strip() for line in install.tui_view(state, cols, 24)]
                    at = next(i for i, line in enumerate(lines)
                              if line.startswith("BIOS folder:"))
                    pieces = [lines[at]]
                    while pieces[-1].endswith("/") and lines[at + len(pieces)]:
                        pieces.append(lines[at + len(pieces)])
                    spelled.append(pieces)
                    # A command's path may be cut to fit, said so: a folder
                    # in prose never is.
                    self.assertNotIn("...", " ".join(
                        line for line in lines if install.tui_command(state)[:10] not in line
                        and not line.startswith("--")))
                    self.assertTrue(all(len(piece) <= cols - 2 for piece in pieces), pieces)
                self.assertEqual(spelled[0], spelled[1])
                self.assertEqual("".join(spelled[0]), f"BIOS folder: {dest}")

    def test_a_long_path_fits_without_its_indent(self):
        """A pack path of 75 cells folded at 80 columns
        under an indent of 6."""
        path = "/home/moi/retroarch_system/tmp/tui_audit13/pack/MinUI_2025-11_BIOS_Pack.zip"
        self.assertEqual(len(path), 75)
        lines = install._wrap(f"    python3 install.py --from-pack {path}", 95,
                              whole="command")
        self.assertIn(f"      --from-pack {path}", lines)

    @in_full
    def test_the_definition_is_said_once_and_never_spliced(self):
        state = checked_state()
        state.systems = []
        state.manifest = {**MANIFEST, "categorized": True, "omitted_files": [
            {"dest": "jazz2/Source/Anims.j2a", "system": "jazz-jackrabbit-2",
             "required": True, "category": "game_data"}]}
        state.check = {**CHECK, "not_installable": 1}
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertEqual(text.count("files a game or a game engine reads"), 1, text)
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads.", text)

    @in_full
    def test_the_headline_counts_every_file_once(self):
        """"8358 files and 2636 data files", and the
        definition dropped at 80 columns."""
        state = _game_state()
        state.check = planned({**state.check, "data_missing": 7, "data_bytes": 2048})
        lines = [str(line).strip() for line in install.tui_view(state, 80, 24)]
        text = " ".join(" ".join(lines).split())
        self.assertIn("11 files to download, 1.0 MB", text)
        self.assertNotIn("and 7 data files", lines[2])
        self.assertIn("Data files: the files an emulator reads", text)

    @in_full
    def test_the_save_line_never_ends_on_its_colon(self):
        """"...goes to a folder per core under:" with no
        folder at 60x20."""
        state = _game_state()
        state.saves = {"event": "saves", "files": 1,
                       "folder": "/home/user/.config/retroarch/saves/<core>"}
        shown = 0
        for rows in range(12, 30):
            with self.subTest(rows=rows):
                lines = [str(line).strip() for line in install.tui_view(state, 60, rows)]
                for index, line in enumerate(lines):
                    if line.endswith("under:"):
                        shown += 1
                        self.assertTrue(lines[index + 1].startswith("~/"), lines)
        self.assertGreater(shown, 0)

    def test_the_result_says_how_to_copy_and_counts_one_kind_once(self):
        state = _installed_state(SYSTEM_DIR)
        state.manifest = {**MANIFEST, "categorized": True}
        state.mouse = True
        state.finished = [(event["dest"], True, "") for event in FILES]
        state.summary = {**state.summary, "installed": 4}
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "4 BIOS files installed.")
        self.assertFalse(any(line.startswith("Installed:") for line in lines), lines)
        self.assertEqual(lines[-1], install.TUI_RESULT_COPY)
        self.assertNotIn(install.TUI_RESULT_COPY, install.tui_farewell(state))
        state.help = True
        self.assertIn("Shift+drag", " ".join(install.tui_view(state, 80, 24)))

    def test_the_old_card_result_splits_what_is_missing(self):
        """"16 still missing" where 6 were game data."""
        state = _game_state()
        state.offline = True
        state.from_folders = [Path("/media/OLD")]
        state.local_dests = {"gba_bios.bin": ("/media/OLD", "")}
        state.finished = [("gba_bios.bin", True, "")]
        state.download = {"files": 4}
        state.stack, state.run = ["result"], "install"
        state.summary = {"event": "summary", "mode": "install", "installed": 1,
                         "up_to_date": 0, "pending": 3, "failed": [], "skipped": [],
                         "left_out": [], "kept": [], "interrupted": False}
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE:
                                          install.OFFLINE_FLAG_VALUE}):
            _title, lines = install.tui_outcome(state)
        # The wrong copy the check found is left in place: named as one,
        # never counted as missing.
        self.assertIn("1 file copied from OLD, 2 still missing, 1 wrong copy left.", lines)
        self.assertIn("Still missing: 1 BIOS file and 1 game data file.", lines)

    # Root cause 6: every other word.

    def test_drives_are_named_once_under_wsl_and_windows(self):
        """"D:: bios" and "D:\\: bios"."""
        with mock.patch.dict(install._WSL, {"active": True}):
            mount = Path(install._WSL["root"]) / "d"
            self.assertEqual(install._drive_folder(mount, "bios"), "D:\\bios")
        windows = PureWindowsPath("D:\\")
        with mock.patch.object(install, "_mount_name", return_value="D:\\"), \
                mock.patch.object(install, "shown_path", side_effect=str):
            self.assertEqual(install._drive_folder(windows, "bios"), "D:\\bios")
        stick = Path("/media/moi/USBSTICK")
        self.assertEqual(install._drive_folder(stick, "bios"), "USBSTICK: bios")

    def test_the_linux_side_is_named_by_its_side(self):
        self.assertEqual(install.side_name("wsl", "retroarch"), "Linux RetroArch")
        self.assertEqual(install.side_name("linux", "retroarch"), "RetroArch")
        state = fresh_state()
        state.os_type, state.platform = "wsl", "retroarch"
        state.stack = ["setup", "folder"]
        state.folder_default, state.folder_kind = SYSTEM_DIR, "usual"
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_is_dir", return_value=False):
            state.folder_scan = install.scan_folder(state)
        text = "\n".join(install.tui_view(state, 100, 30))
        self.assertIn("Linux RetroArch usually reads its BIOS files from:", text)
        self.assertIn("(does not exist yet)", text)

    def test_a_folder_created_where_no_setup_is_says_so(self):
        """"system is created in C:\\RetroArch-Win64, where
        RetroArch reads it" with no RetroArch there."""
        state = fresh_state()
        missing = self.root / "RetroArch-Win64" / "system"
        with mock.patch.object(install, "_start_check", return_value=[]):
            install._choose(state, "retroarch", missing, proposed=True)
        self.assertIn("a folder that does not exist yet", state.card_note)
        self.assertNotIn("reads it", state.card_note)
        here = self.root / "pc" / "bios"
        with mock.patch.object(install, "_start_check", return_value=[]):
            install._choose(state, "retroarch", here, proposed=True)
        self.assertIn("where RetroArch reads it", state.card_note)

    def test_the_needed_list_counts_one_more_system_in_words(self):
        """On the list of files an emulator needs too."""
        entries = [{"dest": f"s{n}.bin", "system": f"system-{n}", "required": True}
                   for n in range(9)]
        said = " ".join(install._needed_lines(entries, "Needed"))
        self.assertIn("... and 1 more system (--check --verbose lists them all)", said)

    @in_full
    def test_the_farewell_names_the_option_not_the_screen(self):
        state = _installed_state(SYSTEM_DIR)
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        state.summary = {**state.summary, "skipped": [
            {"reason": "no_save_directory", "label": "", "files": 1, "required": False}]}
        farewell = " ".join(install.tui_farewell(state))
        self.assertIn("Name it with --save-dir next time.", farewell)
        self.assertNotIn("Options", farewell)

    def test_more_systems_is_counted_in_words(self):
        """"... and 1 more systems"."""
        entries = [{"dest": f"s{n}.bin", "size": 10, "systems": [f"system-{n:02d}"]}
                   for n in range(install.PLAN_LARGEST_SYSTEMS + 1)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            install._print_plan(entries, SYSTEM_DIR, install.Terminal(io.StringIO()))
        self.assertIn("... and 1 more system:", out.getvalue())

    def test_the_systems_question_aligns_and_explains_after_the_list(self):
        rows = [("mattel-intellivision", []), ("nec-pc-engine", []),
                (install.OTHER_SYSTEMS, [])]
        labels = {"mattel-intellivision": "Mattel Intellivision  mattel-intellivision",
                  "nec-pc-engine": "NEC PC Engine  nec-pc-engine",
                  install.OTHER_SYSTEMS: install.OTHER_TITLE + "  " + "x" * 10}
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(install, "_ask", return_value=""):
            install._pick("Systems:", rows, labels=labels, note="A note.",
                          sizer=lambda files: "1 file")
        lines = out.getvalue().splitlines()
        listed = [line for line in lines if line.endswith("1 file")]
        self.assertEqual(len({line.index("1 file") for line in listed}), 1, listed)
        self.assertGreater(lines.index("A note."), lines.index(listed[-1]))

    def test_the_yes_stop_says_one_thing_with_a_list_or_without(self):
        """"the file list" said of a
        pack, and two wordings for one stop."""
        pack = self.root / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
        env = {"HOME": str(self.root / "home"), "XDG_CONFIG_HOME": str(self.root / "cfg"),
               "RETROBIOS_OS": "linux"}
        said = install_run("--from-pack", str(pack), "--yes", env=env)
        self.assertEqual(said.returncode, 1, said.stdout + said.stderr)
        self.assertIn("No supported platform detected: RetroArch was not found here, and "
                      "the pack does not say where it goes.", said.stderr)
        # The standalone emulators' lists come from the network: offline,
        # no request leaves the machine.
        alone = install_run("--yes", env={**env, install.OFFLINE_VARIABLE: "1"})
        self.assertIn("No supported platform detected", alone.stdout + alone.stderr)
        hint = install._manual_usage_hint("linux")
        self.assertTrue(hint[0].startswith("  Name the setup with --platform and its folder "
                                           "with --dest"), hint)
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("every run without questions stops before reading it", page)
        self.assertIn("none stops it too, with `reason` `not_found`", page)
        self.assertIn("So is a platform named by a file list or a pack", page)


class TheUsageNamesTheInstaller(unittest.TestCase):
    """The Windows one-liner's --help said "usage: retrobios-install-<guid>.py",
    the name install.ps1 gives its copy."""

    def test_a_copy_under_a_temporary_name_says_install_py(self):
        scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch, True)
        copy = scratch / "retrobios-install-33826e0b-37cc-4ad3-a6c4-6ed168e3fe9e.py"
        shutil.copyfile(REPO_ROOT / "install.py", copy)
        env = {**os.environ, "RETROBIOS_BOOTSTRAP": "ps1"}
        for option in ("--help", "--no-such-option"):
            with self.subTest(option=option):
                proc = subprocess.run([sys.executable, str(copy), option], env=env,
                                      capture_output=True, text=True, timeout=60,
                                      stdin=subprocess.DEVNULL, check=False)
                said = proc.stdout + proc.stderr
                self.assertIn("usage: install.py", said)
                self.assertNotIn("retrobios-install-", said)
        with mock.patch.object(sys, "argv", [str(copy), "--help"]):
            self.assertEqual(install.build_parser().prog, "install.py")


class ChoiceStateInBothModes(unittest.TestCase):
    """One choice state in both modes, the
    cards found first, packs that hold nothing, and words that fit."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    listing = LineModeRuns.listing
    entry = staticmethod(LineModeRuns.entry)
    receive = staticmethod(ChoiceRuns.receive)
    game_manifest = ChoiceRuns.game_manifest
    game_events = ChoiceRuns.game_events
    game_plan = ChoiceRuns.game_plan

    screen = staticmethod(ChoiceScreens.screen)

    def toggle_game_data(self, state: install.TuiState) -> None:
        rows = install.tui_rows(state)
        state.focus["plan"] = next(index for index, row in enumerate(rows)
                                   if row.action == "gamedata")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
        self.receive(state, self.game_events(self.game_manifest(),
                                             left_out=state.no_game_data))

    def test_the_game_data_toggle_never_unticks_a_system_for_good(self):
        """DS and Dreamcast ticked, game data left out
        then kept: Dreamcast was gone, and so was the row to turn it back."""
        state = self.game_plan()
        state.ticked = {"nintendo-ds", "sega-dreamcast"}
        self.toggle_game_data(state)
        self.assertEqual(state.ticked, {"nintendo-ds"})
        self.assertIn("for 1 of 2 systems", self.screen(state))
        row = next(row for row in install.tui_rows(state) if row.action == "gamedata")
        self.assertEqual((row.label, row.right), ("Game data: left out", "2 files, 2.0 KB"))
        self.toggle_game_data(state)
        self.assertEqual(state.ticked, {"nintendo-ds", "sega-dreamcast"})
        self.assertIn("for 2 of 3 systems", self.screen(state))
        # Line mode, the same choice: c, the two systems, g twice.
        manifest = self.game_manifest()
        listing = self.listing("retroarch", [
            self.entry(entry["dest"], b"x" * entry["size"], entry["systems"],
                       **({"category": entry["category"]} if "category" in entry else {}))
            for entry in manifest["files"]], categorized=True)
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "1,2", "g", "g"])
        self.assertIn("for 1 of 2 systems", text)
        self.assertIn("for 2 of 3 systems", text.rsplit("for 1 of 2 systems", 1)[1])

    game_listing = ChoiceScreens.game_listing

    def test_line_mode_offers_no_enter_for_an_emptied_choice(self):
        """Dreamcast alone, game data left out: line mode
        said "0 files, 0 B, for 0 of 2 systems", offered Enter and a command
        that installs nothing, then refused the Enter."""
        text, asked = self.line_run(_args(manifest=self.game_listing(), dest=self.here,
                                          declared_only=False),
                                    ["c", "2", "g", ""])
        menu = text.rsplit("Counted again for these choices", 1)[1]
        self.assertIn("RetroArch: sega-dreamcast holds only game data: nothing is left to "
                      "install.", menu)
        self.assertNotIn("0 files, 0 B", menu)
        self.assertNotIn("Enter)", menu)
        self.assertNotIn("Same choice without questions", menu)
        # Enter is not an answer here: asked again, never refused after.
        self.assertIn("Type c, f, g or q.", menu)
        self.assertEqual(asked[-1], "> ")

    def test_a_kept_choice_in_place_offers_no_install(self):
        """One system ticked, its files in place, the
        plan said "About 0 files" over Install, and Confirm "Everything is
        in place" over Install too."""
        state = checked_state()
        state.ticked = {"nintendo-famicom-disk"}
        text = self.screen(state)
        self.assertIn("(ファミコン) is in place: nothing is left to install.", text)
        self.assertNotIn("About 0 files", text)
        actions = [row.action for row in install.tui_rows(state)]
        self.assertNotIn("install", actions)
        self.assertEqual(actions[0], "systems")
        # Confirm counted nothing to install: Close, never Install.
        state.stack.append("confirm")
        state.dry = {**CHECK, "present": 1, "missing": 0, "wrong_hash": 0,
                     "bytes_needed": 0, "files": 1}
        state.dry_files = []
        self.assertEqual([row.action for row in install.tui_rows(state)], ["close", "back"])
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.exit_code, 0)

    def test_offline_the_plan_counts_the_systems_ticked(self):
        """Offline, one system ticked, the plan counted
        every file of the list beside "For your 1 of 3 systems"."""
        state = checked_state()
        state.offline = True
        folder = str(self.root / "from1")
        state.from_folders = [self.root / "from1"]
        state.found = [found("gba_bios.bin", folder)]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state.ticked = {"nintendo-gba"}
            text = self.screen(state, 100, 40)
            self.assertIn("About 1 file, 16.0 KB, for 1 of 3 systems ", text)
            self.assertNotIn("found in from1", text)
            self.assertNotIn("Run the installer again", text)
            state.ticked = {"sony-playstation"}
            text = self.screen(state, 100, 40)
        self.assertIn("3 files need the internet, which RETROBIOS_INSTALL_OFFLINE=1 does not "
                      "use, for 1 of 3 systems", text)
        self.assertNotIn("About 0 files", text)

    def easyroms(self, name: str = "EASYROMS") -> Path:
        """A handheld's games part as a computer mounts it, with the folders
        its system writes there (install._GAMES_PART_RULES): ArkOS's
        EASYROMS, AmberELEC's GAMES."""
        return games_part(self.root / "media" / name)

    def test_an_arkos_card_is_found_and_comes_first(self):
        """An EASYROMS partition mounted, "Nothing was
        found here", and two presses of Enter filled this computer's
        ~/.config/retroarch/system for a RetroArch that was not there. An
        AmberELEC GAMES is AmberELEC's own card."""
        for name in ("EASYROMS",):
            with self.subTest(card=name):
                card = self.easyroms(name)
                home = self.root / "home"
                with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                        mock.patch.object(install, "detect_platforms", return_value=[]), \
                        mock.patch.object(install, "detect_frontends", return_value=[]), \
                        mock.patch.object(install.Path, "home", return_value=home):
                    state, _effects = install.tui_start(_args(), "linux")
                    # Its plan first, the setups one Back away.
                    self.assertEqual(state.dest, card / "bios")
                    text = self.screen(listed(state))
                    # Named on the setups, its plan one Enter away.
                    self.assertIn(f"> dArkOS or ArkOS SD card ({name}", text)
                    self.assertNotIn("Nothing was found here", text)
                    install.tui_update(state, Key("enter"))
                    self.assertEqual(state.dest, card / "bios")
                    self.assertEqual(state.platform, "retroarch")
                    install.tui_update(state, Key("enter"))
                self.assertEqual(state.dest, card / "bios")
                shutil.rmtree(card)

    def lacking_pack(self, held: list[tuple[str, bytes]]) -> Path:
        pack_dir = self.root / "downloads"
        pack_dir.mkdir(exist_ok=True)
        pack = pack_dir / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
            for dest, payload in held:
                archive.writestr(dest, payload)
        return pack

    def test_line_mode_names_what_the_pack_lacks_before_its_plan(self):
        """--dry-run promised 23 files, --check said to
        fetch them, the install counted 23 beside the size of 20 and advised
        retrying files that always fail."""
        files = [self.entry(f"bios{n}.bin", b"x" * (n + 1), ["nintendo-gba"])
                 for n in range(4)]
        listing = self.listing("retroarch", files)
        pack = self.lacking_pack([("bios0.bin", b"x")])
        dest = self.root / "card" / "system"
        common = dict(manifest=listing, from_pack=[pack], dest=dest, declared_only=False,
                      no_input=True)
        text, _asked = self.line_run(_args(**common, dry_run=True), [])
        lacks = "3 of these 4 files are not in RetroArch_BIOS_Pack.zip"
        self.assertIn(lacks, text)
        self.assertLess(text.index(lacks), text.index("Would copy"))
        self.assertIn("Would copy 1 file (1 B) from the pack", text)
        text, _asked = self.line_run(_args(**common, check=True), [])
        self.assertIn(lacks, text)
        self.assertNotIn("to fetch them", text)
        self.assertIn("to copy 1 of them from RetroArch_BIOS_Pack.zip", text)
        options = ("--platform", "retroarch", "--manifest", str(listing), "--dest", str(dest),
                   "--yes", "--verbose")
        proc = install_run(*options, "--from-pack", str(pack))
        text = proc.stdout + proc.stderr
        self.assertIn("Copying 1 file (1 B) from RetroArch_BIOS_Pack.zip...", text)
        self.assertNotIn("retry only those", text)
        self.assertIn("RetroArch_BIOS_Pack.zip does not hold them: a newer pack", text)
        # A pack holding none: no copy, no folder.
        shutil.rmtree(dest.parent, ignore_errors=True)
        proc = install_run(*options, "--from-pack", str(self.lacking_pack([])))
        text = proc.stdout + proc.stderr
        self.assertNotIn("Copying 0 files", text)
        self.assertIn("RetroArch_BIOS_Pack.zip does not hold them", text)
        self.assertFalse(dest.exists())

    def test_a_pack_holding_none_offers_no_install_with_data_files(self):
        """Data files left, the pack holding none of the
        files nor the trees: Install was offered and failed every file, and
        the result never named the data files."""
        state = checked_state()
        # The run's plan: the pack holds none of the files nor the trees.
        state.check = planned({**state.check, "data_missing": 7, "data_bytes": 2048},
                              lacking=[event["dest"] for event in state.files],
                              data_files=0, data_bytes=0)
        state.manifest = {**MANIFEST, "data_directories": [
            {"ref": "dolphin", "dest": "dolphin-emu/Sys", "files": {}}]}

        class Empty:
            name = "RetroArch_BIOS_Pack.zip"
            members: dict = {}

            @staticmethod
            def find(entry: dict) -> None:
                return None

            @staticmethod
            def tree(prefix: str):
                return iter(())

        with mock.patch.object(install.LOCAL, "pack", Empty()):
            actions = [row.action for row in install.tui_rows(state)]
            self.assertNotIn("install", actions)
            self.assertEqual(actions[0], "fromcard")
            text = self.screen(state)
            self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 11 files", text)
            # The result of an install run anyway names them.
            state.stack = ["result"]
            state.summary = {"installed": 0, "up_to_date": 0, "pending": 4, "kept": [],
                             "failed": [{"dest": event["dest"], "reason": "not in the pack"}
                                        for event in state.files]}
            state.code = 2
            _title, lines = install.tui_outcome(state)
        self.assertIn("7 data files not installed: not in RetroArch_BIOS_Pack.zip.", lines)

    @in_full
    def test_a_command_at_40_columns_breaks_between_shell_words(self):
        """The terminal folded commands inside a word,
        "--platform" ended a line with its value on the next."""
        words = ["--platform", "retroarch", "--dest", "/a/b/c/system", "--manifest",
                 "/home/moi/x.json", "--system", "nintendo-gba"]
        text = "printf '%s\\n' " + " ".join(words)
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            lines = install._wrap(text, 38, whole="command")
        self.assertGreater(len(lines), 1)
        self.assertTrue(all(install.cell_width(line) <= 38 for line in lines), lines)
        self.assertTrue(all(line.endswith(" \\") for line in lines[:-1]), lines)
        for line in lines:
            # An option never ends a line without its value.
            self.assertFalse((line[:-2] if line.endswith(" \\") else line).rstrip().endswith(
                ("--platform", "--dest", "--manifest", "--system")), lines)
        # The shell reads the lines as the command: the same words.
        proc = subprocess.run(["sh", "-c", "\n".join(lines)], capture_output=True, text=True,
                              check=True)
        self.assertEqual(proc.stdout.split(), words)
        # A path wider than a line keeps its last folders, said so, and the
        # address of the one-liner is never cut.
        state = _installed_state(Path("/home/moi/retroarch_system/tmp/tui_audit14/sb/a/b/bios"))
        state.summary["kept"] = [{"folder": "/home/moi/retroarch_system/tmp/tui_audit14/sb/"
                                            "retrobios-backup/2026", "files": 1, "bytes": 1}]
        with mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
            screen = [str(line) for line in install.tui_view(state, 40, 40)]
        self.assertTrue(all(install.cell_width(line) <= 40 for line in screen), screen)
        self.assertIn(install.TUI_SHORTENED, " ".join(screen))
        self.assertIn(install.BOOTSTRAP_URL, " ".join(screen))
        state.exit_code = 0
        farewell = "\n".join(install.tui_farewell(state))
        self.assertIn("/home/moi/retroarch_system/tmp/tui_audit14/sb/a/b/bios", farewell)

    @in_full
    def test_a_folder_on_its_own_line_has_one_indent(self):
        """The save folder at the label's indent, the
        BIOS folder under it, a path's last piece without its indent."""
        state = checked_state()
        state.dest = Path("/home/moi/retroarch_system/tmp/tui_audit14/sb/esmiyoo/home/"
                          ".config/retroarch/system")
        state.saves = {"files": 1, "folder": "/home/moi/retroarch_system/tmp/tui_audit14/"
                                             "sb/and2/storage/RetroArch/saves/<core>"}
        for cols in (40, 80):
            with self.subTest(cols=cols):
                lines = [str(line) for line in install.tui_view(state, cols, 40)]
                folder = next(i for i, line in enumerate(lines) if "BIOS folder:" in line)
                under = next(i for i, line in enumerate(lines) if "under:" in line)
                for at in (folder, under):
                    pieces = []
                    for line in lines[at + 1:]:
                        if not line.strip() or "/" not in line or " " in line.strip():
                            break
                        pieces.append(line)
                    indents = {len(piece) - len(piece.lstrip()) for piece in pieces}
                    self.assertLessEqual(len(indents), 1, pieces)
                    if pieces:
                        self.assertEqual(indents, {3}, pieces)

    def test_no_shift_where_there_is_no_shift_key(self):
        """"Shift and a drag" on Android."""
        for os_type, said in (("linux", True), ("android", False)):
            with self.subTest(os_type=os_type):
                state = _installed_state(SYSTEM_DIR)
                state.os_type, state.mouse = os_type, True
                _title, lines = install.tui_outcome(state)
                self.assertEqual(any("Shift" in line for line in lines), said)
                self.assertIn(install.TUI_RESULT_AGAIN, lines[-1])
                state.help = True
                text = " ".join(install.tui_view(state, 80, 24))
                self.assertEqual("Shift+drag" in text, said)

    def test_the_40x12_setup_never_ends_mid_sentence(self):
        state = fresh_state()
        state.notes = [install.TUI_ESDE_NOTE]
        text = [str(line).strip() for line in install.tui_view(state, 40, 12)]
        self.assertIn(install.TUI_ESDE_SHORT, text)
        self.assertFalse(any(line.startswith("ES-DE found") for line in text), text)
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn(install.TUI_ESDE_NOTE, text)

    def test_the_40x12_plan_keeps_its_folder_and_version_note(self):
        """The plan named ~/.var/app/ as the folder, and
        the version note was absent."""
        state = checked_state()
        state.dest = HOME / ".var/app/org.libretro.RetroArch/config/retroarch/system"
        state.version = "This list was built for RetroBat 8.3.1, this machine runs 8.2.0.1."
        lines = [str(line).strip() for line in install.tui_view(state, 40, 12)]
        joined = "".join(line for line in lines if line.endswith("/") or "system" in line)
        self.assertIn("~/.var/app/org.libretro.RetroArch/config/retroarch/system", joined)
        self.assertIn(state.version, " ".join(" ".join(lines).split()))
        self.assertTrue(any(re.fullmatch(r"1-\d+ of \d+", line) for line in lines), lines)
        self.assertIn("> Install", lines)

    def test_one_count_said_once_in_both_modes(self):
        """"22 files installed." over "22 files copied
        from packx.", and line mode's Location, wrong hash and zero count."""
        state = _installed_state(SYSTEM_DIR)
        state.summary["installed"] = 5
        state.finished = [(f"f{n}.bin", True, "") for n in range(5)]
        state.local_dests = {f"f{n}.bin": ("/media/packx", "") for n in range(5)}
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "5 files copied from packx.")
        self.assertNotIn("5 files installed.", lines)
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        proc = install_run("--platform", "retroarch", "--manifest", str(listing),
                           "--dest", str(self.here), "--check", "--offline", "--verbose")
        self.assertIn("0 in place, 1 missing, 0 wrong copies", proc.stdout)
        self.assertNotIn("present (", proc.stdout)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertNotIn('say(f"Location', source)
        self.assertNotIn("already up to date.\")\n", source.split("\nDone.", 1)[-1][:300])

    def test_quit_names_stay_once(self):
        """"A/Enter Stay  B/Esc Stay"."""
        state = fresh_state()
        state.stack.append("quit")
        state.focus["quit"] = 1
        self.assertEqual(str(install.tui_view(state, 80, 24)[-1]).count("Stay"), 1)

    def test_the_yes_stop_example_keeps_yes(self):
        """A script copying the example stopped at a
        question."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"])]
        listing = self.listing("retroarch", files)
        proc = install_run("--yes", "--manifest", str(listing), "--offline",
                           env={"HOME": str(self.root / "home"), "RETROBIOS_OS": "linux"})
        example = next(line for line in proc.stderr.splitlines()
                       if "--platform retroarch --dest" in line)
        self.assertIn(" --yes", example)

    def test_the_systems_question_fits_the_terminal(self):
        """53 of 66 rows wider than 80 columns."""
        rows = [(f"system-{n}", [{"dest": f"{n}.bin", "size": 10 ** n}]) for n in range(6)]
        labels = {"system-0": "Sega Dreamcast-based arcade boards, each "
                              "them  sega-dreamcast-arcade",
                  **{f"system-{n}": f"Short {n}" for n in range(1, 6)}}
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((80, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._pick("Systems:", rows, labels=labels)
        printed = out.getvalue().splitlines()
        self.assertTrue(all(install.cell_width(line) <= 80 for line in printed), printed)
        # The long label on its own line, its size under it in the column.
        at = next(i for i, line in enumerate(printed) if "sega-dreamcast-arcade" in line)
        self.assertNotIn("B", printed[at].split("arcade", 1)[1])
        sizes = {line.index("1 file") for line in printed[at + 1:] if "1 file" in line}
        self.assertEqual(len(sizes), 1, printed)

    def test_the_save_dir_sentence_is_written_once(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('"Name it with --save-dir next time."'), 1)
        self.assertEqual(source.count("args.declared_only or len(files) + game_data_cut"), 1)

    def test_a_missing_folder_does_not_exist_yet_on_every_row(self):
        """Line mode said "(created)" of folders nobody
        created, and the screen said "does not exist yet" of the Windows row
        alone."""
        drives = [self.root / "media" / "D", self.root / "media" / "E"]
        for drive in drives:
            drive.mkdir(parents=True)
        (drives[1] / "bios").mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=drives), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install.ask_platform_folder("linux", "retroarch")
        text = out.getvalue()
        self.assertNotIn(", created)", text)
        self.assertNotIn("(created)", text)
        self.assertIn(f"D: bios (drive, {drives[0] / 'bios'}, does not exist yet)", text)
        self.assertIn(f"E: bios (drive, {drives[1] / 'bios'})\n", text)
        state = fresh_state()
        state.platform = "retroarch"
        with mock.patch.object(install, "_mounted_cards", return_value=drives):
            install._open_folder_screen(state, SYSTEM_DIR)
            labels = [row.label for row in install.tui_rows(state) if row.action == "drive"]
        self.assertEqual(labels, ["D: bios (drive, does not exist yet)", "E: bios (drive)"])

    def test_line_mode_puts_the_arkos_card_first(self):
        card = self.easyroms()
        text, asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                          declared_only=False), [""], mounts=[card])
        # Found as the screen finds it, under Enter. dArkOS writes the same
        # EASYROMS tree, so a computer cannot tell the two apart.
        self.assertIn(f"Found dArkOS or ArkOS at {card / 'bios'} (RetroArch files)", text)
        self.assertNotIn("Nothing was found here", text)
        self.assertIn("Enter for dArkOS or ArkOS SD card (EASYROMS)", asked[0])
        self.assertIn(f"BIOS folder: {card / 'bios'}", text)


class FocusAfterAnAction(unittest.TestCase):
    """One tap on the focused
    Install row armed nothing visible, the result's Put RetroBIOS on this
    card was cut at 40x12, the Game data row lost the focus once changed,
    and a choice already in place opened on Options."""

    @staticmethod
    def row_of(lines: list, action: str) -> int:
        return next(index for index, line in enumerate(lines)
                    if getattr(line, "mark", None) and line.mark[0] == "row"
                    and line.mark[2][0] == action)

    def test_one_tap_on_the_focused_install_row_arms_it_visibly(self):
        for cols, rows in ((80, 24), (40, 12)):
            with self.subTest(size=(cols, rows)):
                state = checked_state()
                state.mouse = True
                lines = drawn(state, cols, rows)
                row = self.row_of(lines, "install")
                self.assertTrue(str(lines[row]).lstrip().startswith("> Install"))
                self.assertEqual(tap(state, 4, row), [])
                armed = drawn(state, cols, rows)
                self.assertIn(install.TUI_ARMED_SHORT, str(armed[-1]))
                self.assertIn(install.TUI_ARMED_SHORT, str(armed[row]))
                self.assertEqual(armed[row].style, "focus")
                painted = install.tui_paint(str(armed[-1]), "hint", True)
                self.assertIn(f"{install.COLOUR_ROLES['accent']}m", painted)
                # The second tap, on the row or on the bar, installs.
                self.assertEqual(tap(state, 4, row), [("run", "install")])

    def test_a_row_armed_then_the_bar_installs_and_a_key_disarms(self):
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        tap(state, 4, self.row_of(lines, "install"))
        drawn(state, 80, 24)
        self.assertEqual(tap(state, 2, len(lines) - 1), [("run", "install")])
        state = checked_state()
        state.mouse = True
        lines = drawn(state, 80, 24)
        tap(state, 4, self.row_of(lines, "install"))
        install.tui_update(state, Key("down"))
        install.tui_update(state, Key("up"))
        self.assertNotIn(install.TUI_ARMED_SHORT, " ".join(map(str, drawn(state, 80, 24))))

    def test_put_retrobios_on_this_card_fits_40x12(self):
        """The result offering the app, drawn and tapped as the loop does
        (tui_view, tui_hits, tui_mouse), at 40x12 and 80x24: no line cut
        inside a word, the armed bar whole, one Exit on the bar and the
        help naming B as the bar does."""
        root, bios = _app_card(self, "muOS")
        for cols, rows in ((40, 12), (80, 24)):
            with self.subTest(size=(cols, rows)):
                state = _installed_state(bios)
                state.mouse = True
                with mock.patch.object(install, "_tui_app_ready", return_value=True):
                    lines = drawn(state, cols, rows)
                    text = [str(line).rstrip() for line in lines]
                    row = self.row_of(lines, "addapp")
                    offer = text[row].strip()
                    self.assertIn(offer, ("Put RetroBIOS on this card",
                                          install.APP_OFFER))
                    self.assertEqual(text[-1].split(), ["A/Enter", "Exit"]
                                     if cols >= install.TUI_LONG_BAR_WIDTH else ["A", "Exit"])
                    # One tap focuses the row: a second puts the app on the
                    # card, which the row and the bar say, B kept.
                    tap(state, 4, row)
                    armed = [str(line).rstrip() for line in drawn(state, cols, rows)]
                    self.assertTrue(armed[row].lstrip().startswith("> Put"))
                    self.assertIn("Exit", armed[-1])
                    self.assertIn("B/Esc" if cols >= install.TUI_LONG_BAR_WIDTH else "B",
                                  armed[-1].split())
                    self.assertIn(f"{install.TUI_ARMED_SHORT}  B", armed[-1])
                    self.assertTrue(armed[row].strip().endswith(install.TUI_ARMED_SHORT),
                                    armed[row])
                    for line in (*armed, *text):
                        self.assertLessEqual(install.cell_width(line), cols)
                        self.assertFalse(line.endswith(("aga", "fro", "(update f")), line)
                    state.tapped = None
                    install.tui_update(state, Key("f1"))
                    help_text = " ".join(" ".join(str(line).split())
                                         for line in drawn(state, cols, rows))
                    self.assertIn("Exit", help_text)
                    self.assertNotIn("Backspace Quit", help_text)
                    install.tui_update(state, Key("f1"))

    def test_the_game_data_row_keeps_the_focus_when_changed(self):
        audit = OneChoicePerRun()
        state = audit.game_plan()
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "gamedata")
        for left_out, expected in ((True, "Game data: left out"), (False, "Game data: kept")):
            self.assertEqual(install.tui_update(state, Key("enter")), [("run", "check")])
            audit.receive(state, audit.game_events(audit.game_manifest(), left_out=left_out))
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["plan"]].label, expected)

    def test_a_choice_already_in_place_opens_on_choose_systems(self):
        state = checked_state()
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.screen, "systems")
        state.ticked_before = set(state.ticked)
        state.ticked = {"nintendo-famicom-disk"}
        with mock.patch.object(install, "_choice_in_place", return_value="in place"):
            install.tui_update(state, Key("esc"))
            self.assertEqual(state.screen, "plan")
            rows = install.tui_rows(state)
            self.assertEqual(rows[state.focus["plan"]].label, "Choose systems")


class TheFromPlanSaysItsKinds(unittest.TestCase):
    """Every file found in the folder, the plan named
    the Game data row and said neither the kinds nor what game data is."""

    @in_full
    def test_the_kinds_and_the_definition_stay(self):
        audit = OneChoicePerRun()
        state = audit.game_plan()
        state.offline = True
        folder = "/media/moi/packx"
        state.from_folders = [Path(folder)]
        state.found = [found(event["dest"], folder) for event in state.files
                       if event["state"] != "present"]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = " ".join(" ".join(str(line).split())
                            for line in install.tui_view(state, 80, 24))
        self.assertIn("found in packx, nothing to download", text)
        self.assertIn("2 BIOS files", text)
        self.assertIn("3 game data files", text)
        self.assertIn("Game data: files a game or a game engine reads", text)
        self.assertNotIn("Not in packx", text)


def _parity_list(root: Path) -> tuple[Path, Path]:
    """A RetroArch list whose cores per board pick other files, a shared
    destination two cores want different bytes at, and the copies of every
    file in a folder: an install from it needs no network."""
    payloads = root / "copies"
    payloads.mkdir()
    entries = []
    alternative = {}
    for name, cores, systems in (("plat.bin", None, ["sony-playstation"]),
                                 ("pcsx/extra.bin", ["pcsx_rearmed"], ["sony-playstation"]),
                                 ("mesen/nes.bin", ["mesen"], ["nintendo-nes"]),
                                 ("nes_plat.bin", None, ["nintendo-nes"]),
                                 ("shared.bin", ["pcsx_rearmed"], ["sony-playstation"]),
                                 ("shared.bin#mesen", ["mesen"], ["nintendo-nes"])):
        payload = name.encode() * 8
        stored = name.replace("/", "_").replace("#", "_")
        (payloads / stored).write_bytes(payload)
        entry = {"dest": name.split("#")[0], "size": len(payload),
                 "sha1": hashlib.sha1(payload).hexdigest(),
                 "sha256": hashlib.sha256(payload).hexdigest(),
                 "repo_path": f"bios/{stored}", "cores": cores, "systems": systems}
        if "#" in name:
            alternative = {field: entry[field] for field in
                           ("sha1", "sha256", "size", "repo_path", "cores")}
            continue
        entries.append(entry)
    next(entry for entry in entries if entry["dest"] == "shared.bin")["alternatives"] = [
        alternative]
    listed = root / "list"
    (listed / "targets").mkdir(parents=True)
    manifest = {"manifest_version": 2, "platform": "retroarch", "files": entries,
                "omitted_files": [],
                "system_cores": {"sony-playstation": ["pcsx_rearmed"],
                                 "nintendo-nes": ["mesen"]},
                "core_names": {"pcsx_rearmed": ["pcsx_rearmed"], "mesen": ["mesen"]}}
    (listed / "retroarch.json").write_text(json.dumps(manifest))
    (listed / "targets" / "retroarch.json").write_text(json.dumps(
        {"bcm2711": {"cores": ["pcsx_rearmed"]}, "h700": {"cores": ["mesen"]}}))
    return listed / "retroarch.json", payloads


class ScreenChoicesInstallWhatTheirFlagInstalls(unittest.TestCase):
    """A board chosen on Device and an emulator ticked on Emulators install,
    file for file and byte for byte, what --target and --emulator install."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.listed, self.copies = _parity_list(self.root)
        self.manifest = json.loads(self.listed.read_text())
        self.env = {**os.environ, "RETROBIOS_OS": "linux", "HOME": str(self.root),
                    install.OFFLINE_VARIABLE: "1"}

    def run_install(self, argv: list[str]) -> dict[str, str]:
        proc = subprocess.run(argv, env=self.env, capture_output=True, text=True,
                              timeout=120, check=False, stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        dest = Path(next(arg for arg in argv if arg.startswith("--dest=")).split("=", 1)[1])
        return {path.relative_to(dest).as_posix(): hashlib.sha1(path.read_bytes()).hexdigest()
                for path in dest.rglob("*") if path.is_file()}

    def flag_run(self, name: str, *flags: str) -> dict[str, str]:
        return self.run_install([sys.executable, str(REPO_ROOT / "install.py"),
                                 "--platform=retroarch",
                                 f"--dest={self.root / name / 'system'}",
                                 f"--manifest={self.listed}", f"--from={self.copies}",
                                 *flags, "--events", "--yes"])

    def screen(self, name: str) -> install.TuiState:
        """Change, over the plan of the list as a check leaves it."""
        state = install.TuiState(os_type="linux", home=self.root)
        state.platform, state.dest = "retroarch", self.root / name / "system"
        state.manifest, state.manifest_for = self.manifest, "retroarch"
        state.manifest_path, state.manifest_given = self.listed, True
        state.from_folders = [self.copies]
        state.check = dict(CHECK)
        state.stack = ["plan", "options"]
        return state

    def screen_run(self, state: install.TuiState) -> dict[str, str]:
        return self.run_install(install.tui_argv(state, "install", sys.executable,
                                                 str(REPO_ROOT / "install.py")))

    @staticmethod
    def choose(state: install.TuiState, action: str, value: object = None) -> None:
        rows = install.tui_rows(state)
        state.focus[state.screen] = next(
            index for index, row in enumerate(rows)
            if row.action == action and (value is None or row.value == value))

    def test_a_board_chosen_on_device_installs_what_target_installs(self):
        targets = install._validate_targets(
            json.loads((self.listed.parent / "targets" / "retroarch.json").read_text()))
        everything = self.flag_run("all")
        chosen = {}
        for board in ("bcm2711", "h700"):
            with self.subTest(board=board):
                state = self.screen(f"screen-{board}")
                self.choose(state, "device")
                self.assertEqual(press(state, "enter"), [("targets", "retroarch")])
                install.tui_receive(state, ("targets", "retroarch", targets, ""))
                self.choose(state, "board", board)
                press(state, "enter")
                self.assertEqual(state.screen, "options")
                chosen[board] = self.screen_run(state)
                self.assertEqual(chosen[board],
                                 self.flag_run(f"flag-{board}", "--target", board))
                self.assertNotEqual(chosen[board], everything)
        # The two boards' cores want other bytes at one destination.
        self.assertNotEqual(chosen["bcm2711"]["shared.bin"], chosen["h700"]["shared.bin"])

    def test_every_board_installs_what_every_board_installs(self):
        targets = install._validate_targets(
            json.loads((self.listed.parent / "targets" / "retroarch.json").read_text()))
        state = self.screen("screen-every")
        state.board_seen = ("retroarch", state.dest, "h700", True, True)
        self.choose(state, "device")
        press(state, "enter")
        install.tui_receive(state, ("targets", "retroarch", targets, ""))
        self.choose(state, "board", "")
        press(state, "enter")
        self.assertEqual(self.screen_run(state),
                         self.flag_run("flag-every", "--every-board"))

    def test_an_emulator_ticked_installs_what_emulator_installs(self):
        for emulator in ("mesen", "pcsx_rearmed"):
            with self.subTest(emulator=emulator):
                state = self.screen(f"screen-{emulator}")
                self.choose(state, "emulators")
                press(state, "enter")
                self.choose(state, "emulator", emulator)
                press(state, " ", "esc")
                self.assertEqual(state.screen, "options")
                chosen = self.screen_run(state)
                self.assertEqual(chosen, self.flag_run(f"flag-{emulator}",
                                                       "--emulator", emulator))
                # The files of its systems, and its own copy of the shared one.
                shared = next(entry for entry in self.manifest["files"]
                              if entry["dest"] == "shared.bin")
                self.assertEqual(chosen["shared.bin"], shared["sha1"] if emulator ==
                                 "pcsx_rearmed" else shared["alternatives"][0]["sha1"])
                self.assertNotIn("nes_plat.bin" if emulator == "pcsx_rearmed"
                                 else "plat.bin", chosen)


class EmulatorChoiceMatchesTheEmulatorPack(unittest.TestCase):
    """An emulator ticked on Emulators against the pack generate_pack.py
    --emulator builds for it, on the real lists: every file of the pack at
    its destination with its bytes, and beside them only the files the
    platform's own list names for the systems the emulator runs."""

    CASES = (("retroarch", "handy"), ("retroarch", "beetle_psx"), ("retroarch", "mesen"),
             ("batocera", "mesen"), ("batocera", "handy"))

    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        if sys.version_info < BUILDER_FLOOR:
            # The builder's floor: install.py alone keeps 3.8.
            raise unittest.SkipTest("generate_pack.py needs Python 3.9 or newer")
        from core.ziptools import build_zip_contents_index
        from packs import archive as packs_archive
        from packs import emulatorpack
        cls.packs_archive, cls.emulatorpack = packs_archive, emulatorpack
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))
        cls.zip_contents = build_zip_contents_index(cls.db, REPO_ROOT)
        cls.by_path = {entry["path"]: sha1 for sha1, entry in cls.db["files"].items()}

    def pack(self, emulator: str) -> dict[str, str]:
        record = self.packs_archive.PackRecord()
        with contextlib.redirect_stdout(io.StringIO()):
            self.emulatorpack.generate_emulator_pack(
                [emulator], str(REPO_ROOT / "emulators"), self.db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "tmp"), zip_contents=self.zip_contents, offline=True,
                record=record)
        return {member: self.by_path[record.sources[member]] for member in record.files}

    def test_each_case(self):
        for plat, emulator in self.CASES:
            with self.subTest(platform=plat, emulator=emulator):
                manifest = json.loads((REPO_ROOT / "install" / f"{plat}.json").read_text())
                state = install.TuiState(os_type="linux")
                state.platform, state.dest = plat, Path("/x/bios")
                state.manifest, state.manifest_for = manifest, plat
                state.stack = ["plan", "options", "emulators"]
                rows = install.tui_rows(state)
                state.focus["emulators"] = next(i for i, row in enumerate(rows)
                                                if row.value == emulator)
                press(state, " ")
                argv = install.tui_argv(state, "install", "py", "install.py")
                args = install.build_parser().parse_args(argv[2:])
                self.assertEqual(args.emulator, [emulator])
                with contextlib.redirect_stdout(io.StringIO()):
                    _chosen, files, _omitted = install._narrow_to_emulators(
                        args.emulator, manifest, plat, manifest["files"],
                        manifest["omitted_files"])
                installed = {entry["dest"]: entry["sha1"] for entry in files}
                packed = self.pack(emulator)
                self.assertTrue(packed)
                self.assertEqual({dest: installed.get(dest) for dest in packed}, packed)
                for dest in set(installed) - set(packed):
                    entry = next(entry for entry in files if entry["dest"] == dest)
                    self.assertIsNone(entry.get("cores"), dest)


if __name__ == "__main__":
    unittest.main()
