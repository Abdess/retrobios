"""What each screen offers, its rows and filters, line mode decisions and the
offline setting."""

from __future__ import annotations

import tests

import contextlib
import io
import json
import os
import queue
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.test_install_app import make_card
from tests.test_install_selection import FakeRepository
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, CHECK, checked_state, _Decided, FILES, found, fresh_state, HOME, in_full,
    _installed_state, Key, MANIFEST, planned, press, Pty, pty, pyte, REPO_ROOT, ROUTES,
    SaveDirectoryRepository, SYSTEM_DIR,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_screens")


class OfflineInTheInterface(unittest.TestCase):
    """--offline in the full screen: a "No connection" error offering a Try
    again that can never work, and a plan counting downloads the run
    forbids."""

    def setUp(self):
        # The value --offline gives the variable.
        patcher = mock.patch.dict(os.environ,
                                  {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_variable_is_named_when_it_made_the_run_offline(self):
        """"(--offline)" and "without --offline" with
        RETROBIOS_INSTALL_OFFLINE=1 and no --offline: nothing to remove."""
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            inbox = queue.Queue()
            install._tui_fetch("retroarch", inbox)
            text = " ".join(inbox.get_nowait()[3])
            self.assertIn("(RETROBIOS_INSTALL_OFFLINE=1)", text)
            self.assertIn("with RETROBIOS_INSTALL_OFFLINE unset", text)
            self.assertNotIn("--offline", text)
            plan = " ".join(" ".join(install.tui_view(checked_state(), 120, 40)).split())
            self.assertIn("which RETROBIOS_INSTALL_OFFLINE=1 does not use", plan)
            self.assertNotIn("without --offline", plan)

    def test_no_list_names_the_ways_that_work(self):
        inbox = queue.Queue()
        install._tui_fetch("retroarch", inbox)
        kind, plat, title, lines, code = inbox.get_nowait()
        self.assertEqual((kind, title, code), ("manifest_failed",
                                               "No internet: offline mode", 1))
        text = " ".join(lines)
        for words in ("--manifest", "--from-pack", "without --offline"):
            self.assertIn(words, text)
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, (kind, plat, title, lines, code))
        self.assertEqual(state.screen, "error")
        self.assertNotIn("retry", [row.action for row in install.tui_rows(state)])
        view = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("No internet: offline mode", view)
        self.assertNotIn("Try again", view)

    def test_the_plan_offers_no_download(self):
        state = checked_state()
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertNotIn("to download", text)
        self.assertIn("need the internet, which --offline does not use", text)
        self.assertNotIn("install", [row.action for row in install.tui_rows(state)])
        # A file found on this machine can still be copied.
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/scph5500.bin",
                        "member": "", "reason": ""}]
        state.check = planned(CHECK, files=3, bytes=CHECK["bytes_needed"] - FILES[0]["size"],
                              copied=[FILES[0]["dest"]])
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("1 found in old,", text)
        self.assertIn("need the internet (--offline)", text)
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertIn("--offline", install.tui_command(state))


class OfflineToggleStalesTheCheck(unittest.TestCase):
    """Turning the network back on changes the run, however offline was set:
    the variable alone left the check current and Install skipped Confirm."""

    def test_each_way_offline_was_set(self):
        for value in ("1", install.OFFLINE_FLAG_VALUE):
            with self.subTest(value=value), \
                    mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: value}):
                state = install.TuiState()
                state.checked_flags = install.tui_flags(state)
                self.assertIn(("--offline", None), state.checked_flags)
                self.assertEqual(install._option_offline(state, 0), [("offline", False)])
                self.assertNotIn(("--offline", None), install.tui_flags(state))
                self.assertEqual(install._begin_install(state), [("run", "confirm")])


class LineModeOffline(unittest.TestCase):
    """The line mode under --offline asked to
    download, and said nothing of the data files."""

    @unittest.skipUnless(pyte and pty and hasattr(pty, "fork"),
                         "the line mode run needs pyte and a pty")
    def test_nothing_is_offered_that_cannot_come(self):
        with FakeRepository() as repo:
            env = {**repo.env(), "TERM": "xterm"}
            term = Pty(["--plain", "--manifest", str(repo.root / "install" / "retroarch.json"),
                        "--dest", str(repo.dest), "--offline"], env)
            term.wait("q) quit")
            term.send("\r")
            code = term.close()
            # Read as words: a terminal gets the status words painted.
            out = install.unpainted(term.raw.decode("utf-8", "replace"))
        self.assertIn("--offline: only the files found on this machine are installed, and no "
                      "--from names a folder to copy them from.", out)
        # nothing to copy from, nothing to install.
        self.assertIn("Enter) check the BIOS folder, nothing can be downloaded", out)
        self.assertIn("f) copy from a folder or an old card", out)
        self.assertIn("5 files need the internet, which --offline does not use.", out)
        self.assertNotIn("Downloading", out)
        self.assertNotIn("failed", out.lower())
        # nothing installed ended on
        # exit 0, where the screen's run gives 2.
        self.assertIn("Nothing installed: 5 files need the internet, which --offline does "
                      "not use.", out.replace("\r\n", " ").replace("\n", " "))
        self.assertNotIn("already up to date", out)
        self.assertEqual(code, 2)

    def test_the_data_files_are_counted_before_the_question(self):
        files = [{"dest": "a.bin", "size": 1024}]
        trees = [{"ref": "t", "files": {"x": {"size": 2048}, "y": {"size": 2048}}}]
        with mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._prompt_custom_selection(install.MenuContext("retroarch", files, [],
                                                                 data_trees=trees))
        # One total, the kinds under it adding up to it.
        self.assertIn("RetroArch: 3 files, 5.0 KB.\n  1 BIOS file (1.0 KB) and 2 data files "
                      "(4.0 KB).", out.getvalue())

    def test_one_save_file_goes(self):
        files = [{"dest": "keys.txt", "root": "save", "size": 1}]
        place = install.SavePlace(Path("/saves"), False)
        with mock.patch.object(install, "save_directory_for", return_value=place), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            kept, left = install.place_save_entries(files, Path("/bios"), {}, None, "RetroArch")
            install.say_saves("retroarch", kept, left, Path("/bios"), "RetroArch", False)
        self.assertIn("1 file read from RetroArch's save directory goes to /saves",
                      out.getvalue())


class NarrowSystemNames(unittest.TestCase):
    """At 40 columns the size column took half the line: Game Boy, Game Boy
    Advance and Game Boy Color all read "Nintendo Gam"."""

    def test_the_name_comes_before_the_size(self):
        state = checked_state()
        names = {"nintendo-gb": "Nintendo Game Boy", "nintendo-gba": "Nintendo Game Boy Advance",
                 "nintendo-gbc": "Nintendo Game Boy Color",
                 "videoton-tvc": "Videoton TV Computer"}
        state.manifest = {**state.manifest, "system_titles": names}
        state.systems = [
            {"event": "system", "platform": "retroarch", "system": system, "name": system,
             "files": 30, "present": 0, "missing": 30, "wrong_hash": 0,
             "bytes_needed": 30 * 1024 * 1024}
            for system in names]
        state.files = [{"event": "file", "platform": "retroarch", "dest": f"s{n}.bin",
                        "systems": list(names), "size": 1024, "state": "missing"}
                       for n in range(27)]
        state.ticked = set(names)
        state.stack.append("systems")
        for cols, rows in ((40, 15), (40, 12), (52, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                text = "\n".join(install.tui_view(state, cols, rows))
                # the size stays as the total counts it,
                # 30.0 MB, and a name too long beside it is cut where the
                # three still read apart.
                lines = [line for line in text.splitlines() if "[x]" in line]
                self.assertEqual(len(lines), 4, text)
                self.assertTrue(all(line.rstrip().endswith(("30.0 MB", "30.0 MB + 27 shared"))
                                    for line in lines), text)
                labels = [line.split("[x] ")[1].split("30.0 MB", 1)[0].strip()
                          for line in lines]
                self.assertEqual(len(set(labels)), 4, text)
                for label, name in zip(labels, names.values()):
                    stem = label[:-3] if label.endswith("...") else label
                    self.assertTrue(name.startswith(stem), (label, name))
                for line in text.splitlines():
                    self.assertLessEqual(install.cell_width(line), cols)
        # Wide, the full form stays.
        self.assertIn("3 files, 30.0 MB + 27 shared",
                      "\n".join(install.tui_view(state, 120, 40)))

    def test_one_spelling_of_shared_and_the_focused_size_below(self):
        """At 40 columns the shared part read "+ 1689 shared", "+ 28 sh.",
        ", shared" and ", all shared" on one screen, and a long name kept
        whole lost its size."""
        state = checked_state()
        names = {"epoch-scv": "Epoch Super Cassette Vision", "sega-dc": "Sega Dreamcast",
                 "snk-ng": "SNK Neo Geo"}
        state.manifest = {**state.manifest, "system_titles": names}
        state.systems = [
            {"event": "system", "platform": "retroarch", "system": system, "name": system,
             "files": count, "present": 0, "missing": count, "wrong_hash": 0,
             "bytes_needed": count * 1024}
            for system, count in (("epoch-scv", 30), ("sega-dc", 1690), ("snk-ng", 3))]
        state.files = [{"event": "file", "platform": "retroarch", "dest": f"s{n}.bin",
                        "systems": ["sega-dc", "snk-ng"], "size": 1024, "state": "missing"}
                       for n in range(3)]
        state.ticked = set(names)
        state.stack.append("systems")
        spellings = set()
        for cols in (40, 46, 52, 80):
            text = "\n".join(install.tui_view(state, cols, 15))
            spellings |= set(re.findall(r"\+ \d+ sh\w*\.?|, (?:all )?shared", text))
        self.assertLessEqual(spellings, {"+ 3 shared", ", all shared"}, spellings)
        state.focus["systems"] = next(
            index for index, row in enumerate(install.tui_rows(state))
            if row.value == "epoch-scv")
        text = " ".join(" ".join(install.tui_view(state, 40, 15)).split())
        self.assertIn("Epoch Super Cassette Vision: 30 files, 30.0 KB", text)


class TheResultGivesTheRemediesOfLineMode(unittest.TestCase):
    """The screen ended a mirror's 404 and a cut connection on "Run it again
    to retry only those", where line mode named the address, the proxy and
    that running again changes nothing: the cause did not reach it."""

    def _state(self, *failures: tuple) -> install.TuiState:
        failed = [{"dest": dest, "reason": reason} for dest, reason, _kind, _url in failures]
        state = _installed_state(SYSTEM_DIR, 1, failed)
        state.failures = [{"dest": dest, "reason": reason, "kind": kind, "url": url}
                          for dest, reason, kind, url in failures]
        return state

    def test_each_cause_gets_the_line_mode_remedy(self):
        url = "https://example.invalid/bios/a.bin"
        state = self._state(("a.bin", "HTTP 404", "http", url),
                            ("b.bin", "timed out", "network", ""))
        text = "\n".join(str(line) for line in install.tui_outcome(state)[1])
        records = install.event_records(state.failures)
        for advice in install.failure_remedies(records, "x"):
            for line in advice.split("\n"):
                self.assertIn(line.strip(), text)
        self.assertIn(f"The server answered HTTP 404 for {url}.", text)
        self.assertIn("HTTPS_PROXY", text)

    def test_the_cause_comes_from_the_event_not_the_words(self):
        state = self._state(("a.bin", "not fetched: no request", "offline", ""))
        title, _lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with files missing")

    def test_a_full_drive_offers_no_retry(self):
        state = self._state(("a.bin", install.DRIVE_FULL, "drive_full", ""))
        lines = [str(line) for line in install.tui_outcome(state)[1]]
        self.assertNotIn("Run it again to retry only those.", lines)


class TheRomMResultNamesTheScan(unittest.TestCase):
    """RomM's player sees firmware its scan recorded: the result said
    "installed" and left the scan unsaid."""

    def test_the_result_and_its_farewell_say_it(self):
        state = _installed_state(SYSTEM_DIR)
        state.platform = "romm"
        _title, lines = install.tui_outcome(state)
        self.assertIn(install.ROMM_SCAN_WORDS, lines)
        self.assertIn(install.ROMM_SCAN_WORDS, install._farewell_lines(state))
        state.platform = "retroarch"
        self.assertNotIn(install.ROMM_SCAN_WORDS, install.tui_outcome(state)[1])


class GameDataIsNoFirmwareAlarm(unittest.TestCase):
    """Every RetroArch plan named jazz2/Source/Anims.j2a (jazz-jackrabbit-2)
    as the file needed to start an emulator: a game's data, under a raw id."""

    def test_game_data_has_its_own_line(self):
        state = checked_state()
        state.systems = []
        state.manifest = {**MANIFEST, "omitted_files": [
            {"dest": "jazz2/Source/Anims.j2a", "system": "jazz-jackrabbit-2",
             "required": True, "category": "game_data"},
            {"dest": "missing.bin", "system": "sony-playstation", "required": True}]}
        lines = install._unavailable_lines(state)
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("needed to start its emulator: missing.bin", lines[0])
        self.assertNotIn("Anims.j2a", lines[0])
        # The folder it goes in, and what game data is (the Android run of
        # 2026-10-27 said neither).
        # The names first, the kind in a word, the definition on its own
        # line of the plan.
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads. Copy it", lines[1])
        self.assertNotIn("files a game or a game engine reads", lines[1])
        self.assertIn(f"into {SYSTEM_DIR / 'jazz2' / 'Source'}{os.sep}", lines[1])
        self.assertIn("Anims.j2a (Jazz Jackrabbit 2)", lines[1])


class TheHelpNamesKeysThatCome(unittest.TestCase):
    """Every route's help listed "?, F1  This help", which no pad sends, and
    a key as wide as the column touched its text."""

    def test_pad_routes_name_no_help_key(self):
        for pad in ROUTES:
            with self.subTest(route=pad):
                state = checked_state()
                state.pad = pad
                keys = [key for key, _what in install._help_lines(state)]
                self.assertEqual("?, F1" in keys, pad == "keys")

    def test_a_wide_key_keeps_two_spaces(self):
        state = checked_state()
        state.help = True
        with mock.patch.object(install, "_help_lines",
                               return_value=[("A, Start, Enter, Space, x", "Choose"),
                                             ("q", "Quit")]):
            lines = install._view_help(state, 80, 24)[1]
        self.assertTrue(any("A, Start, Enter, Space, x  Choose" in line for line in lines))


class WhatEachScreenOffers(unittest.TestCase):
    """What each screen offers and says."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def setups(self, pad: str = "keys") -> install.TuiState:
        state = install.TuiState(os_type="linux", home=HOME)
        state.pad = pad
        state.stack = ["platforms"]
        state.focus["platforms"] = 1
        return state

    def test_a_handheld_is_found_by_its_device_in_few_presses(self):
        """Onion was row 30 of 34, its row said "RetroArch files"."""
        state = self.setups("gptokeyb")
        rows = install.tui_rows(state)
        labels = [row.label for row in rows]
        self.assertEqual(labels[1], "RetroArch")
        cards = [index for index, row in enumerate(rows) if row.label.endswith(", SD card")]
        # One block, right after RetroArch.
        self.assertEqual(cards, list(range(2, 2 + len(cards))))
        onion = labels.index("Onion, SD card")
        self.assertIn("Miyoo Mini", rows[onion].right)
        # At 40x12 a page is 6 rows: L1/R1 then Down, then A.
        page = 12 - 6
        presses = (onion - 1) // page + (onion - 1) % page + 1
        self.assertLessEqual(presses, 4)
        text = " ".join(install.tui_view(state, 40, 12))
        self.assertIn("handhelds come after RetroArch", " ".join(text.split()))
        state.pad = "keys"
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("type the device's name (/)", text)
        self.assertIn("Filter by setup or device name",
                      [what for _key, what in install._help_lines(state)])
        # Something found here: the list keeps its order.
        found = fresh_state()
        found.stack = ["setup", "platforms"]
        self.assertEqual([row.label for row in install.tui_rows(found)][2], "Batocera")

    def test_line_mode_takes_a_device_name(self):
        """"miyoo" refused at the line menu."""
        with mock.patch.object(install, "_ask", side_effect=["bittboy"]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install._choose_platform("Which?"), "MiyooCFW")
        self.assertIn("the device's name", out.getvalue())
        choices = install._line_setups()
        onion = [name for name, _label in choices].index("Onion") + 1
        with mock.patch.object(install, "_ask", side_effect=["miyoo mini+", str(onion)]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install._choose_platform("Which?"), "Onion")
        self.assertIn("setups run on 'miyoo mini+'", out.getvalue())
        self.assertIn(f"{onion}) Onion, SD card (Miyoo Mini, Miyoo Mini Plus)", out.getvalue())

    def test_one_spelling_per_device_and_one_press_for_one_match(self):
        for name, devices in install._SETUP_DEVICES.items():
            with self.subTest(system=name):
                self.assertFalse(any("+" in device for device in devices))
        self.assertFalse(any(device.startswith("Anbernic RG35XX")
                             for device in install._SETUP_DEVICES["spruceOS"]))
        state = self.setups()
        state.filters["platforms"] = "mini+"
        self.assertIn("Onion, SD card", [row.label for row in install.tui_rows(state)])
        state.filters["platforms"] = "koriki"
        state.focus["platforms"] = 0
        self.assertEqual(install._primary(state), "A/Enter Choose")
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
        self.assertEqual(state.screen, "folder")
        self.assertEqual(state.card_bound[0], "Koriki")
        rows = {row.value: row for row in install.tui_rows(self.setups())}
        self.assertNotIn("PAN4ELEC", rows["amberelec"].right)

    def test_help_rows_keep_their_column_at_40(self):
        """"/ Filter (Esc clears)" ran back to the left edge."""
        for pad in ("gptokeyb", "gptokeyb_muxterm", "miyoo", "evmapy"):
            with self.subTest(pad=pad):
                state = self.setups(pad)
                state.filters["platforms"] = "x"
                state.help = True
                lines = [line[1:] for line in install.tui_view(state, 40, 12)[2:-1]
                         if line.strip()]
                column = lines[0].index("Move")
                for line in lines:
                    self.assertTrue(line[:column].strip() == "" or line[column - 2:column]
                                    == "  ", line)

    def test_copy_from_a_folder_with_none_says_so(self):
        """The plan came back the same."""
        state = checked_state()
        old = self.root / "old"
        old.mkdir()
        state.from_folders = [old]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("old holds none of these files.", text)
        state.found = [found("gba_bios.bin", str(old))]
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertNotIn("holds none", text)
        stick = self.root / "STICK"
        stick.mkdir()
        state.home = self.root
        with mock.patch.object(install, "_mounted_cards", return_value=[stick]), \
                mock.patch.object(install, "_listed", return_value=[]):
            install._open_from_browser(state)
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["browse"]].value, stick)

    @in_full
    def test_offline_plan_names_the_folder_already_copied_from(self):
        state = checked_state()
        state.offline = True
        state.from_folders = [self.root / "from1"]
        state.found = [found("gba_bios.bin", str(self.root / "from1"))]
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = " ".join(" ".join(install.tui_view(state, 100, 40)).split())
        # The rest named by kind as not in it, the remedy after.
        self.assertIn("Not in from1: ", text)
        self.assertIn("Run the installer again with a pack (--from-pack)", text)
        self.assertNotIn("They are not in", text)
        self.assertNotIn("Copy them from an old card", text)

    def test_the_card_browser_focuses_the_card_asked_for(self):
        """The muOS card, listed first, was focused for Onion."""
        muos, onion, second = self.root / "A_MUOS", self.root / "B_ONION", self.root / "C"
        make_card(muos, "muOS")
        make_card(onion, "Onion")
        make_card(second, "Onion")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(platform="onion"), "linux")
        state.home = self.root
        state.focus["folder"] = [row.action for row in install.tui_rows(state)].index(
            "browse")
        with mock.patch.object(install, "_mounted_cards",
                               return_value=[muos, onion, second]):
            press(state, "enter")
            self.assertEqual(install.tui_rows(state)[state.focus["browse"]].value, onion)
            self.assertEqual(state.status, "Choose the Onion card below.")
            for line in install.tui_view(state, 40, 12):
                self.assertNotIn("Go back", line)

    def test_confirm_offers_no_install_while_it_counts(self):
        state = checked_state()
        state.stack.append("confirm")
        state.running, state.dry = True, None
        self.assertEqual(install.tui_view(state, 80, 24)[-1].split(), ["B/Esc", "Back", "?",
                                                                      "Help"])
        self.assertNotIn("Install", [what for _key, what in install._help_lines(state)])

    def test_back_after_choosing_systems_lands_on_install(self):
        state = checked_state()
        state.focus["plan"] = [row.action for row in install.tui_rows(state)].index("systems")
        press(state, "enter")
        self.assertEqual(state.screen, "systems")
        state.focus["systems"] = next(index for index, row in
                                      enumerate(install.tui_rows(state))
                                      if row.action == "system")
        press(state, " ", "esc")
        self.assertEqual(state.screen, "plan")
        rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus["plan"]].action, "install")

    def test_a_lone_card_opens_the_first_screen_with_a_list(self):
        """With --manifest, the card's folder was the first screen."""
        onion = self.root / "ONIONB"
        make_card(onion, "Onion")
        shutil.rmtree(onion / "BIOS")
        args = _args(platform="retroarch", manifest=str(REPO_ROOT / "install" /
                                                        "retroarch.json"))
        args.platform_from_list = True
        with mock.patch.object(install, "_mounted_cards", return_value=[onion]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {}):
            state, effects = install.tui_start(args, "linux")
        self.assertEqual((state.screen, effects), ("setup", []))

    def test_a_file_left_for_its_save_directory_is_said_so(self):
        """The menu counted 23, 22 were checked, and the end blamed
        the collection for the file whose save directory is unknown."""
        menus = []

        def menu(context, **_named):
            menus.append([entry["dest"] for entry in context.files])
            return

        with SaveDirectoryRepository() as repo:
            argv = ["install.py", "--platform", "retroarch", "--dest", str(repo.dest),
                    "--manifest", str(repo.root / "install" / "retroarch.json")]
            # The files come from the repository on the loopback.
            with mock.patch.dict(os.environ, repo.env()), \
                    mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(sys.stdin, "isatty", return_value=True), \
                    mock.patch.object(install, "_is_terminal", return_value=True), \
                    mock.patch.object(install, "detect_os", return_value="linux"), \
                    mock.patch.object(install, "records_selection", return_value=True), \
                    mock.patch.object(install, "_prompt_custom_selection", menu), \
                    mock.patch.object(install, "_ask", return_value="y"), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    install.main()
                except SystemExit:
                    pass
                finally:
                    install.LOCAL.reset()
        self.assertEqual(len(menus), 1)
        self.assertNotIn("Azahar/Azahar/sysdata/keys.txt", menus[0])
        text = out.getvalue()
        self.assertIn("1 file read from RetroArch's save directory left out: its place is "
                      "not known. Name it with --save-dir next time.", text)
        self.assertNotIn("the collection does not hold", text)

    @in_full
    def test_plural_game_data_and_the_backup_line_at_40x12(self):
        state = checked_state()
        games = [{"dest": f"g{index}.dat", "system": "", "category": install.GAME_DATA}
                 for index in range(2)]
        with mock.patch.object(install, "_unavailable", return_value=(games, 0)):
            self.assertIn("Copy them from", " ".join(install._unavailable_lines(state)))
        with mock.patch.object(install, "_unavailable", return_value=(games[:1], 0)):
            self.assertIn("Copy it from", " ".join(install._unavailable_lines(state)))
        view = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("1 wrong copy: backed up, replaced.", view)


def _screen_text(state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
    return "\n".join(line.rstrip() for line in install.tui_view(state, cols, rows))


class LineModeDecisions(unittest.TestCase):
    """Line mode read other decisions than the
    screen (a drive's root for Batocera, no other setup once one was found,
    no Enter default, a folder question with no way out)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.dict(os.environ, {"HOME": str(self.root / "home"),
                                                     "XDG_CONFIG_HOME": str(self.root / "cfg"),
                                                     "RETROBIOS_OS": "linux"})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def ask(self, *answers: str):
        asked = []
        given = iter(answers)

        def answer(prompt: str) -> str:
            asked.append(prompt)
            return next(given)

        return mock.patch.object(install, "_ask", side_effect=answer), asked

    def share_drive(self, name: str = "SHARE") -> Path:
        drive = self.root / "media" / name
        (drive / "roms").mkdir(parents=True)
        return drive

    def test_a_numbered_share_drive_is_its_bios_folder(self):
        """2) SHARE gave the drive's
        root, the screen its bios folder."""
        muos = self.root / "media" / "MUOS"
        make_card(muos, "muOS")
        share = self.share_drive()
        patcher, _asked = self.ask("1")
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            folder = install.ask_platform_folder("linux", "batocera")
        self.assertEqual(folder, share / "bios")
        text = out.getvalue()
        self.assertIn(f"1) SHARE: bios ({share / 'bios'}, does not exist yet)", text)
        self.assertNotIn("MUOS", text)

    def test_the_folder_question_quits_on_q_and_says_what_to_type(self):
        """Q became the folder ./q, filled, and Enter
        with no default repeated the prompt with no word."""
        patcher, asked = self.ask("", "q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit) as stop:
            install.ask_platform_folder("linux", "batocera")
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertIn("q to quit", asked[0])
        self.assertIn("Type a folder, or q to quit.", out.getvalue())
        self.assertFalse((Path.cwd() / "q").exists())

    def test_a_relative_folder_is_named_in_full(self):
        """BIOS folder: q, Created q, Location: q."""
        here = self.root / "work"
        here.mkdir()
        patcher, _asked = self.ask("./q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                mock.patch.object(install.Path, "cwd", return_value=here), \
                mock.patch.object(install.os, "getcwd", return_value=str(here)), \
                contextlib.redirect_stdout(io.StringIO()):
            folder = install.ask_platform_folder("linux", "batocera", ask=False)
        self.assertTrue(folder.is_absolute())
        self.assertEqual(folder, here / "q")

    def test_a_card_root_question_quits_on_q(self):
        patcher, asked = self.ask("q")
        with mock.patch.object(install, "_mounted_cards", return_value=[]), patcher, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as stop:
            install.card_install_dest("rocknix", "rocknix", interactive=True)
        self.assertEqual(stop.exception.code, install.QUIT_CODE)
        self.assertEqual(asked, ["Card root, Enter to look again, q to quit: "])

    def test_install_for_takes_enter_and_offers_another_setup(self):
        """No Enter default, an All the screen does
        not have, and no other setup once one was found."""
        here = self.root / "system"
        found = [("retroarch", here)]
        patcher, asked = self.ask("")
        with patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            chosen = install._prompt_platform_choice(
                found, labels={("retroarch", here): "RetroArch"}, other=list)
        self.assertEqual(chosen, found)
        self.assertEqual(asked, ["> [Enter for RetroArch] "])
        self.assertIn("o) another setup or folder", out.getvalue())
        self.assertNotIn("All", out.getvalue())
        other = [("batocera", self.root / "bios")]
        patcher, _asked = self.ask("o")
        with patcher, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install._prompt_platform_choice(found, other=lambda: other), other)

    def test_the_setups_for_a_dest_come_in_the_screens_order(self):
        """With RetroArch found, --plain --dest put Onion
        at 19, the screen at 29."""
        dest = self.root / "blank"
        dest.mkdir()
        here = self.root / "system"
        listed = {}

        def choose(title, default="", setups=None, mounted=None):
            listed["rows"] = [name for name, _label in install._line_setups(
                setups, mounted, "linux")]
            listed["default"] = default
            raise _Decided(None)

        with mock.patch.object(install, "detect_platforms",
                               return_value=[("retroarch", here)]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_choose_platform", side_effect=choose), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(_Decided):
            install._platform_for_dest("linux", dest, True)
        with mock.patch.object(install, "detect_platforms",
                               return_value=[("retroarch", here)]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            state, _effects = install.tui_start(_args(dest=dest), "linux")
        screen = [install._row_name(row) for row in install.tui_rows(state)
                  if row.action != "filter"]
        self.assertEqual(listed["rows"], screen)
        rows = install.tui_rows(state)
        self.assertEqual(install._row_name(rows[state.focus["platforms"]]), listed["default"])

    def test_system_named_on_the_command_line_keeps_the_menu(self):
        """--system skipped the menu and its folder line."""
        files = [{"dest": "a.bin", "size": 1, "systems": ["nintendo-gba"], "cores": None},
                 {"dest": "b.bin", "size": 1, "systems": ["sega-saturn"], "cores": None}]
        given = (["nintendo-gba"], [], [])
        patcher, _asked = self.ask("")
        with patcher, contextlib.redirect_stdout(io.StringIO()) as out:
            chosen = install._prompt_custom_selection(install.MenuContext("retroarch", files, [],
                                                                          bios_path=self.root),
                                                      given=given)
        self.assertEqual(chosen, given)
        text = out.getvalue()
        self.assertIn("RetroArch: 1 file, 1 B, for 1 of 2 systems (--system).", text)
        self.assertIn("Enter) install these", text)
        self.assertIn(f"BIOS folder: {self.root}", text)

    def test_narrowing_is_said_without_an_arrow(self):
        source = Path(install.__file__).read_text(encoding="utf-8")
        self.assertNotIn("} -> {len(files)}", source)

    def test_android_typed_names_retroarch(self):
        """Android matched nothing, and nothing more."""
        patcher, _asked = self.ask("android", "q")
        with patcher, mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._choose_platform("Which setup?")
        self.assertIn("On Android, choose RetroArch", out.getvalue())

    def test_batocera_named_on_a_computer_without_questions_is_refused(self):
        """/userdata/bios taken, Cannot create, end 2
        with no error event."""
        listing = self.root / "batocera.json"
        listing.write_text(json.dumps({"manifest_version": 2, "platform": "batocera",
                                       "files": []}))
        # --manifest sets the process-wide sources: a later test fetching
        # the list must not find this one.
        self.addCleanup(install.LOCAL.reset)
        events = io.StringIO()
        with mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.EVENTS, "stream", events), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install._install(_args(platform="batocera", no_input=True, manifest=listing),
                             io.StringIO())
        self.assertEqual(stop.exception.code, 1)
        self.assertNotIn("/userdata/bios", err.getvalue())
        self.assertIn("--dest /media/$USER/SHARE/bios", err.getvalue())
        kinds = [json.loads(line)["event"] for line in events.getvalue().splitlines()]
        self.assertEqual(kinds[-1], "error")


class ScreenRowsAndFilters(unittest.TestCase):
    """Rows, filters and help as the screens draw them."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        patcher = mock.patch.dict(install._DETECTED_OS, {})
        patcher.start()
        self.addCleanup(patcher.stop)

    def start(self, mounts=(), found=(), **given) -> tuple:
        with mock.patch.object(install, "_mounted_cards", return_value=list(mounts)), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "detect_platforms", return_value=list(found)), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            return install.tui_start(_args(**given), "linux")

    def test_a_folder_holding_a_mounted_muos_card_is_no_muos_card(self):
        """/media/me held the MUOS mount point and read as
        a muOS card, and _own_card_root walked above the mount."""
        parent = self.root / "media"
        muos = parent / "MUOS"
        make_card(muos, "muOS")
        points = frozenset({str(muos)})
        with mock.patch.object(install, "_mount_points", return_value=points), \
                mock.patch.object(install, "_mounted_cards", return_value=[muos]):
            self.assertIsNone(install.card_system(parent))
            self.assertEqual(install.card_system(muos)[1], muos / "MUOS" / "bios")
            self.assertIsNone(install._own_card_root(muos / "bios"))
            self.assertEqual(install._own_card_root(muos / "MUOS" / "bios"), muos)

    def test_batocera_share_rows_leave_out_another_systems_card(self):
        """The muOS card was the first share row."""
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        share = self.root / "SHARE"
        share.mkdir()
        state, _effects = self.start([muos, share], platform="batocera")
        with mock.patch.object(install, "_mounted_cards", return_value=[muos, share]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            rows = [(row.action, row.label) for row in install.tui_rows(state)]
        self.assertIn(("share", "SHARE: bios"), rows)
        self.assertNotIn(("share", "MUOS: bios"), rows)

    def test_a_proposed_folder_is_created_without_the_guard(self):
        """Use this folder, then Create the folder? focused
        on Choose another folder, and Enter, Enter looped."""
        state = install.TuiState(os_type="linux", home=self.root)
        usual = self.root / ".config" / "retroarch" / "system"
        state.stack, state.platform = ["platforms"], "retroarch"
        install._open_folder_screen(state, usual)
        effects = install.tui_update(state, Key("enter"))
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertNotIn("create", state.stack)
        self.assertIn("system is created in", state.card_note)
        typed = self.root / "a" / "b" / "c"
        state = install.TuiState(os_type="linux", home=self.root)
        state.stack, state.platform = ["folder"], "retroarch"
        install._choose(state, "retroarch", typed)
        self.assertEqual(state.screen, "create")
        self.assertEqual(install.tui_rows(state)[state.focus["create"]].action, "other")

    def test_a_page_moves_by_the_rows_drawn(self):
        """At 40x12 PgDn moved six rows over four drawn,
        and muOS and ROCKNIX were never shown."""
        for cols, rows in ((40, 12), (40, 15), (80, 24)):
            with self.subTest(size=f"{cols}x{rows}"):
                state, _effects = self.start()
                state.cols, state.rows = cols, rows
                seen = set()
                for _press in range(40):
                    text = _screen_text(state, cols, rows)
                    seen |= {line.strip("|> ").split(",")[0].strip()
                             for line in text.splitlines()}
                    install.tui_update(state, Key("pgdn"))
                for name in ("muOS, SD card", "ROCKNIX, SD card", "JELOS, SD card",
                             "EmuELEC, SD card", "RetroOZ, SD card"):
                    self.assertTrue(any(line.startswith(name.split(",")[0]) for line in seen),
                                    name)

    def test_the_first_screen_says_quit_and_a_filter_says_clear(self):
        state, _effects = self.start(platform="onion")
        self.assertEqual(state.stack, ["folder"])
        bar = install.tui_view(state, 80, 24)[-1]
        self.assertIn("Esc Quit", bar)
        self.assertNotIn("Esc Back", bar)
        state, _effects = self.start()
        press(state, "/", "o", "n")
        self.assertIn("Esc Clear", install.tui_view(state, 80, 24)[-1])
        press(state, "enter")
        self.assertIn("Esc Clear", install.tui_view(state, 80, 24)[-1])

    def test_rows_at_40_columns_name_a_device(self):
        """"1 device" for CrossMix-OS."""
        state, _effects = self.start()
        text = _screen_text(state, 40, 60)
        self.assertNotIn("1 device", text)
        crossmix = next(line for line in text.splitlines() if "CrossMix-OS" in line)
        self.assertIn("TrimUI", crossmix)

    def test_a_model_finds_the_systems_that_list_its_family(self):
        """RG353V missed ROCKNIX, RG351P
        missed AmberELEC and ROCKNIX."""
        for system, devices in install._SETUP_DEVICES.items():
            for device in devices:
                for model in (device, *install._DEVICE_FAMILIES.get(device, ())):
                    rows = install.setup_list([], set(), model, "android")
                    names = {install._row_name(row) for row in rows}
                    with self.subTest(system=system, model=model):
                        self.assertIn(system, names)

    def test_the_filter_reads_system_names_as_line_mode_does(self):
        for typed, system in (("spruce os", "spruceOS"), ("unofficial os", "UnofficialOS"),
                              ("cross mix", "CrossMix-OS")):
            with self.subTest(typed=typed):
                rows = install.setup_list([], set(), typed, "linux")
                self.assertIn(system, {install._row_name(row) for row in rows})

    def test_android_on_the_filter_names_retroarch(self):
        state, _effects = self.start()
        state.filters["platforms"] = "android"
        self.assertIn("On Android, choose RetroArch", " ".join(_screen_text(state).split()))

    def test_a_wrapped_path_has_no_space_inserted(self):
        """Retroarch/ system."""
        path = "/home/moi/retroarch_system/tmp/tui_audit9/sb/nd/home/.config/retroarch/system"
        for width in range(30, 100):
            lines = install._wrap(f"{path} does not exist.", width)
            # Each line after the first is indented by two spaces.
            joined = lines[0] + "".join(line[2:] for line in lines[1:])
            with self.subTest(width=width):
                self.assertIn(path, joined)
                self.assertTrue(all("/ " not in line for line in lines), lines)

    def test_f1_names_what_the_card_lacks(self):
        """F1 said the refusal again."""
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        setup = install.card_setup("Onion", "retroarch")
        choice = install._not_the_card(setup, muos, muos, "muOS")
        self.assertIn(".tmp_update", choice.detail)

    def test_help_at_40x12_keeps_quit_and_this_help(self):
        """And Space for ticking on a keyboard."""
        state = checked_state()
        press(state, "down", "down", "down", "down", "enter")
        state.stack.append("systems")
        state.help = True
        text = _screen_text(state, 40, 12)
        self.assertIn("Quit", text)
        self.assertIn("This help", text)
        self.assertIn("X, Space, Right/Left", " ".join(text.split()))

    def test_the_copy_hint_fits_at_40_columns(self):
        """Cut after "copied,". On the CI runner /home
        held three folders, and the list cut the hint: it is kept whole,
        the list scrolling, from a folder of this test's own."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        for name in ("linuxbrew", "packer", "runner"):
            (home / name).mkdir()
        state = checked_state()
        state.home = home
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_listed", return_value=[]):
            install._open_from_browser(state)
        self.assertEqual(state.browse_dir, home)
        text = " ".join(_screen_text(state, 40, 12).split())
        self.assertIn("Choose the old card, a backup folder or a ZIP.", text)
        self.assertIn("> Use this folder", text)

    def test_the_miyoo_bar_says_what_a_does(self):
        """A Tick on All and None, where A unticks."""
        state = checked_state()
        state.pad = "miyoo"
        state.stack.append("systems")
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "none")
        bar = install.tui_view(state, 40, 12)[-1]
        self.assertNotIn("A Tick", bar)
        state.focus["systems"] = install._first_item(state)
        self.assertIn("A Tick", install.tui_view(state, 40, 12)[-1])

    def test_system_given_is_said_and_widened(self):
        """One system named, no word on the plan and no
        way to widen it."""
        state = checked_state()
        state.cli_systems = ["gba"]
        state.systems = [row for row in state.systems if row["system"] == "nintendo-gba"]
        state.ticked = {"nintendo-gba"}
        self.assertIn("For 1 of 3 systems (--system).", " ".join(_screen_text(state).split()))
        row = next(row for row in install.tui_rows(state) if row.action == "systems")
        effects = install._activate(state, row)
        self.assertEqual(effects, [("run", "check")])
        self.assertNotIn(("--system", "gba"), install.tui_flags(state))
        self.assertTrue(state.widen)

    def test_a_local_copy_draws_no_speed(self):
        """0 B/s 0:00 left."""
        out = io.StringIO()
        term = install.Terminal(out)
        term.live = True
        progress = install.Progress(2, 100, term)
        progress.add(50, resumed=True, network=False)
        progress._draw()
        self.assertNotIn("B/s", out.getvalue())
        self.assertNotIn("left", out.getvalue())

    def test_the_offline_remedy_follows_the_files_it_is_about(self):
        unplaced = [{"reason": "no_save_directory", "frontend": "RetroArch"}]
        with mock.patch.object(install, "_offline_only", return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install._report_outcome([self.root], 6, 0, 0, 1, False,
                                    details=install.OutcomeDetails(omitted_entries=unplaced,
                                                                   offline=16,
                                                                   sources="6 files copied from OLD, 16 still missing."))
        lines = out.getvalue().splitlines()
        remedy = next(i for i, line in enumerate(lines) if "Copy them" in line
                      or "They are not in" in line)
        missing = next(i for i, line in enumerate(lines) if "still missing" in line)
        save = next(i for i, line in enumerate(lines) if "save directory" in line)
        self.assertEqual(remedy, missing + 1)
        self.assertLess(remedy, save)

    def test_first_install_says_where_to_type(self):
        page = (REPO_ROOT / "wiki" / "first-install.md").read_text(encoding="utf-8")
        self.assertNotIn("There, type its name", page)
        self.assertIn("Press / and type the device", page)

    def test_a_folder_that_cannot_be_created_ends_on_an_error_and_a_summary(self):
        """Cannot create, then end 2 and nothing else."""
        import subprocess

        from tests.test_install_offline import PAYLOAD, _offline_env, _pack

        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("a folder that refuses writes is POSIX, and root writes anyway")
        # A file in the way is refused before the plan, as not_a_folder.
        blocker = self.root / "closed"
        blocker.mkdir()
        pack = _pack(self.root, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        os.chmod(blocker, 0o500)
        try:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
                 "--dest", str(blocker / "system"), "--from-pack", str(pack), "--events"],
                env=_offline_env(), capture_output=True, text=True, timeout=120,
                check=False, stdin=subprocess.DEVNULL)
        finally:
            os.chmod(blocker, 0o700)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        kinds = [event["event"] for event in events]
        self.assertEqual(kinds[-3:], ["error", "summary", "end"], proc.stderr)
        self.assertEqual((events[-3]["stage"], events[-3]["reason"]), ("dest", "not_writable"))
        self.assertEqual(events[-1]["code"], 2)

    def test_a_full_drive_ends_on_an_error_and_a_summary(self):
        """The space refusal ended on error then end: a script learned
        nothing of what the run installed, where a folder that could not
        be created gave it a summary."""
        import subprocess

        from tests.test_install_offline import PAYLOAD, _offline_env, _pack

        pack = _pack(self.root, "RetroArch_v1_BIOS_Pack.zip", PAYLOAD)
        argv = ["install.py", "--platform", "retroarch", "--dest", str(self.root / "system"),
                "--from-pack", str(pack), "--events"]
        program = ("import runpy, shutil, sys, types\n"
                   "shutil.disk_usage = lambda _p: types.SimpleNamespace(free=1)\n"
                   f"sys.argv = {argv!r}\n"
                   f"runpy.run_path({str(REPO_ROOT / 'install.py')!r}, run_name='__main__')\n")
        proc = subprocess.run([sys.executable, "-c", program], env=_offline_env(),
                              capture_output=True, text=True, timeout=120, check=False,
                              stdin=subprocess.DEVNULL)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        kinds = [event["event"] for event in events]
        self.assertEqual(kinds[-3:], ["error", "summary", "end"], proc.stderr)
        self.assertEqual((events[-3]["stage"], events[-3]["reason"]), ("space", "drive_full"))
        self.assertEqual(events[-2]["installed"], 0)
        self.assertGreater(events[-2]["pending"], 0)
        self.assertEqual(events[-1]["code"], 2)
        self.assertFalse((self.root / "system").exists())


class EdgesTheMutantsFound(unittest.TestCase):
    """Changes to the code that every test let through: the survivors of a
    mutmut run over the device filter, the card bounds and the WSL paths."""

    def test_a_folder_below_a_drive_is_named_with_backslashes(self):
        """Only the drive itself was ever shown: D:\\Games/bios passed."""
        for root in ("/mnt", "/mnt/", "/windows", "/drvX/"):
            with self.subTest(root=root), mock.patch.dict(install._WSL,
                                                         {"active": True, "root": root}):
                base = root.rstrip("/")
                self.assertEqual(install.shown_path(Path(f"{base}/d/Games/bios")),
                                 "D:\\Games\\bios")
                self.assertEqual(install.shown_path(Path(f"{base}/e")), "E:\\")

    def test_every_path_option_is_read_through_drvfs(self):
        """--cores-dir G:\\ under WSL stayed a relative path named G:."""
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}):
            args = _args(dest=Path("D:\\bios"), save_dir=Path("F:\\saves"),
                         cores_dir=Path("G:\\RetroArch\\cores"))
            install._wsl_dest(args)
        self.assertEqual((args.dest, args.save_dir, args.cores_dir),
                         (Path("/mnt/d/bios"), Path("/mnt/f/saves"),
                          Path("/mnt/g/RetroArch/cores")))

    def card(self, system: str) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        make_card(root / "card", system)
        return root / "card"

    def test_a_card_is_looked_for_up_to_its_mount_point_and_no_further(self):
        """Every folder up to the mount point is read:
        three at most took MUOS/a/b/c/d for a KNULLI card."""
        card = self.card("KNULLI")
        setup = install.card_setup("KNULLI", "knulli")
        deep = card / "a" / "b" / "c" / "d"
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install.os.path, "ismount", return_value=False):
            self.assertEqual(install._card_above(setup, deep), ("own", "KNULLI", card))
        mounted = frozenset({str(card / "a")})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=mounted), \
                mock.patch.object(install.os.path, "ismount", return_value=False):
            self.assertIsNone(install._card_above(setup, deep))

    def test_a_minui_root_is_looked_for_two_folders_up_and_no_further(self):
        card = self.card("MinUI")
        self.assertEqual(install.card_root_above(card / "Bios" / "GBA"), ("minui", card))
        self.assertIsNone(install.card_root_above(card / "Bios" / "GBA" / "x"))
        self.assertIsNone(install.card_root_above(card))

    def test_the_filter_compares_the_letters_alone(self):
        self.assertEqual(install._folded("Pokémon Évolution"), "pokemon evolution")
        self.assertFalse(install._matches("Odroid", "x"))

    def test_a_letter_no_name_holds_finds_nothing(self):
        with mock.patch.dict(install._SETUP_DEVICES, {"batocera": ("Odroid",),
                                                      "Onion": ("Miyoo Mini",)}):
            self.assertIsNone(install._setup_matches("batocera", ["Onion"], "x"))
            self.assertEqual(install._setup_matches("batocera", ["Onion"], "mini"),
                             ["Onion"])
            self.assertEqual(install._setup_matches("batocera", ["Onion"], "odroid"),
                             ["Odroid"])


class TheSystemsQuestionFits(unittest.TestCase):
    """The size column was placed
    for the longest size, so 60 of 66 systems took two lines and 26 still
    passed 80 columns."""

    def question(self, cols: int) -> list[str]:
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        files = manifest["files"]
        systems = install.systems_in_order(install.listed_systems(files), files, manifest,
                                           None)
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((cols, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(out):
            install._choose_narrowing(files, [], manifest, None)
        text = out.getvalue()
        # Up to the question that follows it, the cores' or none.
        ends = [at for at in (text.find("\nCores:"), text.find("\nThe platform's own"))
                if at >= 0]
        return (text[text.index("Systems:"):min(ends, default=len(text))].splitlines(),
                systems, files)

    def test_the_question_fits_80_and_40_columns(self):
        for cols in (80, 40):
            with self.subTest(cols=cols):
                lines, systems, files = self.question(cols)
                numbered = [line for line in lines if re.match(r" +\d+\) ", line)]
                self.assertEqual(len(numbered), len(systems))
                for line in lines:
                    self.assertLessEqual(install.cell_width(line), cols, line)
                shared = sum(1 for system in systems if "shared" in install._system_sized(
                    [f for f in files if install._chosen(f, {system})]))
                # One line a system, a second for its shared files: the
                # 80-column question took 127 lines for 66 systems.
                # At 40 columns a shared size takes a line more: its first
                # part alone was printed beside a long name, the shared
                # files unsaid.
                limit = (len(systems) + shared + 10 if cols == 80
                         else 2 * len(systems) + shared + 12)
                self.assertLessEqual(len(lines), limit)
                for line, after in zip(lines, lines[1:] + [""]):
                    if line.rstrip().endswith(","):
                        self.assertTrue(after.startswith(" ") and not re.match(
                            r" +\d+\) ", after), (cols, line, after))

    def test_a_row_that_fits_keeps_one_line(self):
        lines, _systems, _files = self.question(80)
        row = next(index for index, line in enumerate(lines) if "Amstrad CPC" in line)
        self.assertIn("4 files, 112.0 KB", lines[row])
        self.assertTrue(re.match(r" +\d+\) ", lines[row + 1]))


if __name__ == "__main__":
    unittest.main()
