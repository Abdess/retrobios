"""The counts the full screen gives: proven cards, card names, plan numbers and
one vocabulary."""

from __future__ import annotations

import tests

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import install
from tests.test_install_app import make_card
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, BUILDER_FLOOR, _CardFixtures, CHECK, checked_state, ChoiceRuns, ChoiceScreens, _Decided,
    drawn, DriveRuns, FILES, found, fresh_state, games_part, golden_states, HOME, in_full,
    _installed_state, Key, LineModeRuns, MANIFEST, planned, press, ProvenRuns, REPO_ROOT,
    screen_keys, SIZES, SYSTEM_DIR, SYSTEMS, tap,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_card_counts")


class DataFilesHaveASize(unittest.TestCase):
    """"8179 files to download, 6.6 GB, and 2636 data
    files", the data files with no size."""

    @in_full
    def test_the_plan_gives_the_data_files_size(self):
        state = fresh_state()
        state.stack = ["setup"]
        with mock.patch.object(install.Path, "exists", return_value=True):
            install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        check = {**CHECK, "data_missing": 2636}
        data = {"event": "data", "platform": "retroarch", "files": 2636,
                "bytes": 412 * 1024 ** 2}
        for event in [*FILES, *SYSTEMS, check, data]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("and 2636 data files (412.0 MB)", text)


class ThePagerCountsLines(unittest.TestCase):
    """At 40x12 the result read "1-2 of 5" over eight
    lines, counting paragraphs, and its last paragraph was cut."""

    def result_state(self, cols: int, rows: int) -> install.TuiState:
        state = checked_state()
        state.stack.append("result")
        state.code, state.summary = 0, {"installed": 3}
        state.dest = Path("/media/" + "long-folder-name/" * 12)
        state.cols, state.rows = cols, rows
        return state

    def test_the_last_line_is_reachable_at_every_size(self):
        for cols, rows in (*SIZES, (50, 13), (60, 14)):
            with self.subTest(size=f"{cols}x{rows}"):
                state = self.result_state(cols, rows)
                width = min(cols, install.TUI_MAX_WIDTH) - 2
                # The result keeps a path whole (whole=True): its rows after
                # it are left to the terminal's folding ("cont").
                wrapped = install._text_lines(install._pager_items(state), width, True)
                last = [line for line in wrapped if line.style != "cont"][-1]
                press(state, "end")
                screen = install.tui_view(state, cols, rows)
                body = [line.rstrip() for line in screen[2:-1]]
                self.assertIn(" " + str(last).rstrip(), body)
                if len(wrapped) > rows - 3:
                    self.assertTrue(any(re.fullmatch(rf" \d+-{len(wrapped)} of {len(wrapped)}",
                                                     line) for line in body), body)

    @in_full
    def test_the_counter_moves_one_line_per_press(self):
        state = self.result_state(40, 12)
        first = [line for line in install.tui_view(state, 40, 12) if " of " in line][-1]
        self.assertRegex(first, r"^ 1-8 of \d+")
        press(state, "down")
        second = [line for line in install.tui_view(state, 40, 12) if " of " in line][-1]
        self.assertRegex(second, r"^ 2-9 of \d+")


class ThePlanNumbersAddUp(unittest.TestCase):
    """"47 files to download" sat above "49 missing, 1 wrong copy": the 3
    found on this machine were the difference, left to the reader."""

    @in_full
    def test_the_copied_files_are_the_difference(self):
        state = checked_state()
        state.found = [found("scph5500.bin", str(SYSTEM_DIR), "one folder too deep")]
        state.check = planned(CHECK, ["scph5500.bin"])
        screen = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("3 files to download", screen)
        # The backup line under the count it explains, then the split.
        self.assertIn("1 in place, 3 missing, 1 wrong copy The 1 wrong copy is replaced, the "
                      "old one kept in a backup folder. 4 to install: 1 copied from this "
                      "machine, 3 downloaded", screen)


class CardNamesAndHelp(_CardFixtures, unittest.TestCase):
    """What the cards, the screens and the
    docs answer, line mode's parity being in LineModeAndScreenDecideAlike."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        for patcher in (mock.patch.dict(install._DETECTED_OS, {}),
                        mock.patch.object(install, "_mount_points", return_value=frozenset())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_renamed_card_is_named_by_the_file_no_menu_writes(self):
        """A KNULLI card whose hostname was changed in
        its menu was a Batocera SHARE drive, Enter filled it with Batocera's
        list and --platform knulli was refused."""
        drives = self.renamed()
        expected = {
            "KNULLI renamed": ("knulli", "bios", "KNULLI"),
            "KNULLI as shipped": ("knulli", "bios", "KNULLI"),
            "renamed, no about.info": None,
            "Batocera as shipped": ("batocera", "bios", "Batocera"),
            "Batocera, no hostname": ("batocera", "bios", "Batocera"),
            "Recalbox": ("recalbox", "bios", "Recalbox"),
            "two shares": None,
        }
        for name, drive in drives.items():
            with self.subTest(drive=name):
                found = install.card_system(drive)
                want = expected[name]
                self.assertEqual(found, want and (want[0], drive / want[1], want[2]))
                doubt, _why = install.share_doubt(drive)
                self.assertEqual(bool(doubt), want is None)
        self.assertEqual(install.share_doubt(drives["renamed, no about.info"])[0],
                         ("knulli", "batocera"))
        self.assertEqual(install.share_doubt(drives["two shares"])[0],
                         ("batocera", "recalbox"))

    def test_a_share_drive_is_never_called_a_card(self):
        """"is a Batocera card"
        and "is a Recalbox card" for their SHARE drives."""
        drives = self.renamed()
        for name in ("Batocera as shipped", "Recalbox"):
            with self.subTest(drive=name):
                choice = install.card_choice("retroarch", "retroarch", drives[name])
                self.assertIn("SHARE drive, which reads", choice.note)
                self.assertNotIn(" card, which reads", choice.note)

    def test_two_cards_of_one_system_say_what_they_hold(self):
        """An old Onion card with 6 BIOS files and a new
        empty one looked the same, and Enter took the first by name."""
        old = self.root / "media" / "OLDONION"
        make_card(old, "Onion")
        for index in range(6):
            (old / "BIOS" / f"f{index}.bin").write_bytes(b"x")
        new = self.root / "media" / "ONION"
        make_card(new, "Onion")
        shutil.rmtree(new / "BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[old, new]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            setups, _mounted = install.found_setups("linux")
        self.assertEqual([label for _plat, _path, label in setups],
                         ["Onion SD card (ONION, no BIOS folder)",
                          "Onion SD card (OLDONION, 6 BIOS files)"])

    # a list or a pack that records some axes only.

    def test_a_card_plan_offers_one_remedy_first(self):
        for facts, locked in (({"free": 50 * 1024 ** 3, "writable": False, "cores": [],
                                "on_card": True}, True),
                              ({"free": 10, "writable": True, "cores": [], "on_card": True},
                               False)):
            with self.subTest(locked=locked):
                state = checked_state(facts)
                with mock.patch.object(install, "_on_read_only_mount", return_value=locked):
                    rows = install.tui_rows(state)
                    text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
                    effects = install.tui_update(state, Key("enter"))
                self.assertEqual(rows[0].action, "recheck")
                self.assertEqual("install" in [row.action for row in rows], not locked)
                self.assertNotIn("choose another one", text)
                self.assertEqual(effects, [("run", "check")])

    def test_a_card_pulled_out_leaves_the_plan_rows_in_place(self):
        """The plan read the mounted drives on every frame: a card pulled
        out while the plan was open moved Check again from under the
        focus, and Enter chose another folder."""
        card = self.root / "media" / "ONION"
        make_card(card, "Onion")
        facts = {"free": 10, "writable": True, "cores": []}
        state = checked_state(facts)
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        state.dest = card / "BIOS"
        with mock.patch.object(install, "_mounted_cards", return_value=[card]):
            state.facts = {**install._tui_folder_facts(state), "free": 10}
        self.assertTrue(state.facts["on_card"])
        before = [row.action for row in install.tui_rows(state)]
        self.assertEqual(before[0], "recheck")
        with mock.patch.object(install, "_mounted_cards", return_value=[]) as scan, \
                mock.patch.object(install, "_on_read_only_mount", return_value=False):
            install.tui_view(state, 80, 24)
            after = [row.action for row in install.tui_rows(state)]
        self.assertEqual(scan.call_count, 0)
        self.assertEqual(after, before)

    def test_options_offer_no_downloads_when_nothing_is_downloaded(self):
        """Parallel downloads offered for an install from a pack."""
        state = checked_state()
        state.stack.append("options")
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: ""}):
            self.assertIn("jobs", [row.action for row in install.tui_rows(state)])
        state.offline = True
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            self.assertNotIn("jobs", [row.action for row in install.tui_rows(state)])

    def test_nothing_installable_focuses_the_copy(self):
        """Offline with nothing to copy, the plan focused
        Choose systems, whose systems need the internet too."""
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state = checked_state()
            rows = install.tui_rows(state)
        self.assertEqual(rows[state.focus.get("plan", 0)].action, "fromcard")

    # the screens' polish.

    def test_a_long_message_scrolls_with_its_position(self):
        """At 40x12 the offline screen dropped its remedy unsaid."""
        state = fresh_state()
        state.stack = ["error"]
        state.error_title = install.TUI_OFFLINE_TITLE
        state.error = ["This run makes no network request (--offline), and the list of BIOS "
                       "files comes from the network.",
                       "Run the installer again with the list saved as a file (--manifest "
                       "FILE, a copy of install/<platform>.json) or with a pack (--from-pack "
                       "PACK), or without --offline."]
        state.cols, state.rows = 40, 12
        view = [str(line) for line in install.tui_view(state, 40, 12)]
        self.assertTrue(any(re.fullmatch(r" 1-\d+ of \d+", line) for line in view), view)
        self.assertIn("Scroll", view[-1])
        press(state, "pgdn")
        end = " ".join(" ".join(str(line) for line in install.tui_view(state, 40, 12)).split())
        self.assertIn("--offline.", end)

    def test_a_small_window_says_why_the_questions_come_line_by_line(self):
        small = install.TuiObstacle("size", "the terminal is 39x12, smaller than 40x12",
                                    size=(39, 12))
        with mock.patch.object(install, "tui_obstacle", return_value=small), \
                mock.patch.object(install, "_run", side_effect=SystemExit(0)), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.dict(install._WSL), \
                mock.patch.object(sys, "argv", ["install.py"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                self.assertRaises(SystemExit):
            install.main()
        self.assertIn("The window is 39x12: questions come line by line (40x12 for the full "
                      "screen).", out.getvalue())

    def test_one_bar_rule_per_width(self):
        """At 40 columns the plan read "A Install", Confirm "A/Enter"."""
        states = golden_states()
        for name in ("preview", "confirm", "result", "quit"):
            with self.subTest(screen=name):
                bar = str(install.tui_view(states[name], 40, 12)[-1])
                self.assertNotIn("A/Enter", bar)
                self.assertNotIn("B/Esc", bar)

    @in_full
    def test_the_folder_its_config_named_is_said_under_it(self):
        state = checked_state()
        long_dest = Path("/home/user/" + "a-long-folder-name/" * 5 + "system")
        state.dest = long_dest
        state.facts["config"] = (HOME / ".config/retroarch/retroarch.cfg", HOME)
        lines = [str(line).strip() for line in install.tui_view(state, 80, 30)]
        at = next(index for index, line in enumerate(lines) if line.startswith("BIOS folder:"))
        tail = next(index for index, line in enumerate(lines) if line.startswith("Named by"))
        self.assertNotIn("...", " ".join(lines[at:tail]))
        self.assertIn(str(long_dest).replace("/home/user", "~")[-20:], " ".join(lines[at:tail]))
        self.assertLessEqual(tail - at, 3)

    def test_the_help_while_typing_lists_what_does_not_type(self):
        state = checked_state()
        state.stack.append("systems")
        state.editing = "systems"
        state.help = True
        help_text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Esc Clear the filter", help_text)
        self.assertIn("Ctrl-U Clear", help_text)
        self.assertNotIn("Tick, untick", help_text)

    def test_the_plan_names_core_and_region_as_line_mode(self):
        state = checked_state()
        state.cli_systems, state.cores, state.regions = ["sony-playstation"], ["x"], ["us"]
        state.cli_cores, state.cli_regions = ["x"], ["us"]
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # The flag after the words, never alone.
        self.assertIn("(--system), 0 of 1 cores (--core), regions ranked (--region).", text)

    def test_pc_and_short_prefixes_find_the_computer_setups(self):
        for typed in ("pc", "wi", "win"):
            with self.subTest(typed=typed):
                found = {row.value for row in install.setup_list([], set(), typed, "linux")
                         if row.action == "platform"}
                self.assertIn("retrobat", found)

    def test_a_partial_result_counts_once_then_says_the_remedy(self):
        state = _installed_state(Path("/x/system"))
        state.summary.update(installed=6, pending=16, failed=[])
        state.from_folders = [Path("/media/me/OLD")]
        state.offline = True
        with mock.patch.object(install, "_tui_sources",
                               return_value="6 files copied from OLD, 16 still missing."):
            _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "6 files copied from OLD, 16 still missing.")
        self.assertIn("They are not in", lines[1])

    def test_q_is_said_as_a_quit(self):
        """Q reported "stopped", the word of an interrupted run."""
        state = checked_state()
        press(state, "q")
        self.assertEqual(state.exit_code, install.QUIT_CODE)
        self.assertEqual(install._closing_lines(state),
                         ["RetroBIOS: quit. Nothing was installed."])
        other = checked_state()
        install.tui_interrupt(other)
        self.assertEqual(install._closing_lines(other),
                         ["RetroBIOS: stopped. Nothing was installed."])

    def test_wide_rows_keep_the_size_near_the_name(self):
        row = install.TuiRow("system", "[x] 3DO  3do", "2 files, 4.9 KB")
        line = str(install._row_line(row, False, 118))
        self.assertLessEqual(len(line.rstrip()), install.TUI_ROW_SPREAD)

    def test_the_wsl_browser_titles_a_drive_by_its_letter(self):
        state = fresh_state()
        state.stack = ["browse"]
        state.browse_dir = Path("/mnt/e")
        with mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}), \
                mock.patch.object(install, "_browse_rows", return_value=([], "")):
            state.browse_rows = []
            title = " ".join(str(line) for line in install.tui_view(state, 80, 24)[:4])
        self.assertIn("E:\\", title)
        self.assertNotIn("/mnt/e", title)

    @unittest.skipIf(sys.version_info < BUILDER_FLOOR,
                     "the installer doc generator needs Python 3.9")
    def test_the_card_marker_table_is_written_from_the_rules(self):
        """The table left out the
        SHARE drives. It is generated: every card rule and SHARE drive file
        is a row, about.info among them."""
        from installer_build import installerdoc

        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        block = page[page.index("<!-- generated: card-markers -->"):
                     page.index("<!-- /generated: card-markers -->")]
        for rule in install._card_rules():
            self.assertIn(f"`{rule.values[0]}", block)
        for _plat, marker in install._SHARE_DRIVES:
            self.assertIn(f"`{marker}`", block)
        self.assertIn(self.ABOUT, block)
        self.assertIn("Recalbox SHARE drive", block)
        self.assertEqual(installerdoc.render(page), page)


class OneVocabularyOneCount(unittest.TestCase):
    """Line mode said "in
    place" then "up to date", "wrong copies" then "wrong hash", counted
    twice, left the data files out of its last line, and the screen focused
    Install for a pack holding none of the files."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    listing = LineModeRuns.listing
    entry = staticmethod(LineModeRuns.entry)
    screen = staticmethod(ChoiceScreens.screen)

    def two_files(self) -> tuple[Path, Path, Path]:
        """A list of two files, the first in place, the second in an old
        folder: (list, BIOS folder, old folder)."""
        files = [self.entry("gba_bios.bin", b"gba", ["nintendo-gba"]),
                 self.entry("scph5501.bin", b"psx bytes", ["sony-playstation"])]
        listing = self.listing("retroarch", files)
        dest = self.root / "bios"
        dest.mkdir()
        (dest / "gba_bios.bin").write_bytes(b"gba")
        old = self.root / "OLD"
        old.mkdir()
        (old / "scph5501.bin").write_bytes(b"psx bytes")
        return listing, dest, old

    def run_line(self, listing: Path, dest: Path, answers: list, **given) -> str:
        # --verbose's text: the counts compared are lines the default leaves out.
        given.setdefault("verbose", True)
        from_ = given.pop("from_", None)
        args = _args(manifest=listing, dest=dest, declared_only=False, **given)
        if from_:
            given["from_"] = from_
        if "from_" in given:
            setattr(args, "from", given.pop("from_"))
        # Offline as the variable makes it: no request leaves the test. The
        # end of the run is written to the stdout the run was given.
        given_answers = iter(answers)

        def answer(prompt: str) -> str:
            try:
                return next(given_answers)
            except StopIteration:
                raise _Decided(prompt) from None

        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        invocation = install.Invocation()
        invocation.os_type = "linux"
        invocation.record(args)
        end = io.StringIO()
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}), \
                mock.patch.object(install, "_INVOCATION", invocation), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(install, "_is_terminal", return_value=True), \
                mock.patch.object(install, "_ask", side_effect=answer), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.suppress(_Decided, SystemExit):
            install._install(args, end)
        return out.getvalue() + err.getvalue() + end.getvalue()

    def test_the_line_mode_words_are_the_screens(self):
        listing, dest, old = self.two_files()
        (old / "scph5501.bin").rename(dest / "scph5501.bin")
        for given in ({"no_input": True}, {"check": True}, {"dry_run": True}):
            with self.subTest(**given):
                text = self.run_line(listing, dest, [""], offline=True, **given)
                self.assertIn("2 in place, 0 missing, 0 wrong copies", text)
                self.assertIn("Every file on the list is in place", text)
                self.assertNotIn("up to date", text)
                self.assertNotIn("0 files installed", text)
        state = checked_state()
        state.stack = ["result"]
        state.summary = {"installed": 0, "up_to_date": 2, "pending": 0, "kept": [],
                         "failed": []}
        state.code = 0
        _title, lines = install.tui_outcome(state)
        self.assertEqual(lines[0], "Every file on the list is in place.")

    def test_check_names_a_wrong_copy_as_such(self):
        listing, dest, _old = self.two_files()
        (dest / "scph5501.bin").write_bytes(b"other")
        text = self.run_line(listing, dest, [], check=True, offline=True)
        self.assertIn("1 in place, 0 missing, 1 wrong copy", text)
        self.assertIn("wrong copy: scph5501.bin", text)
        self.assertNotIn("wrong hash", text)
        self.assertNotIn("A file with a", text)

    def test_line_mode_with_from_counts_once(self):
        """No found count before Enter, the
        plan said again after it, Copying twice, the result's count twice,
        and no command on a Finished with files missing."""
        listing, dest, old = self.two_files()
        (dest / "gba_bios.bin").unlink()
        text = self.run_line(listing, dest, [""], from_=[old], offline=True)
        menu, after = text.split("\nChecking existing files...", 1)
        self.assertIn("RetroArch: 1 found in OLD, 1 needs the internet.", menu)
        self.assertNotIn("2 files (", after)
        self.assertEqual(after.count("Copying"), 1, after)
        self.assertIn(f"Finished with files missing. 1 file copied from {old}, "
                      "1 still missing.", after)
        self.assertNotIn("installed,", after)
        self.assertIn("Same choice without questions:", after)
        # Every file found: one count, as the screen's "22 files copied
        # from packx."
        (dest / "scph5501.bin").unlink()
        (old / "gba_bios.bin").write_bytes(b"gba")
        text = self.run_line(listing, dest, [""], from_=[old], offline=True)
        menu, after = text.split("\nChecking existing files...", 1)
        self.assertIn("RetroArch: 2 found in OLD, nothing to download.", menu)
        self.assertIn(f"Done. 2 files copied from {old}.", after)
        self.assertNotIn("files installed", after)

    def test_the_last_offline_line_counts_the_data_files(self):
        """"0 in place, 10994 missing", then "Nothing
        installed: 8358 files need the internet"."""
        listing, dest, _old = self.two_files()
        listed = json.loads(listing.read_text())
        listed["data_directories"] = [{
            "ref": "bluemsx", "dest": "", "type": "zip",
            "url": "https://example.invalid/blueMSX.zip", "systems": ["nintendo-gba"],
            "files": {f"Machines/{n}.txt": {"sha1": hashlib.sha1(b"%d" % n).hexdigest(),
                                            "size": 1} for n in range(2)}}]
        listing.write_text(json.dumps(listed))
        text = self.run_line(listing, dest, [""], offline=True)
        self.assertIn("1 in place, 3 missing, 0 wrong copies", text)
        self.assertIn("Nothing installed: 3 files need the internet", text)

    @in_full
    def test_a_pack_holding_none_offers_no_install(self):
        """A data tree whose folder is the BIOS folder
        itself (blueMSX) made any pack hold a data file: Install focused,
        and the result counted 8252 failed beside 10888 missing."""
        pack = self.root / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"files": []}))
            archive.writestr("other-system.bin", b"x")
        state = checked_state()
        # The run's plan: the pack holds none of the files nor the trees.
        state.check = planned({**state.check, "data_missing": 2, "data_bytes": 2},
                              lacking=[event["dest"] for event in state.files],
                              data_files=0, data_bytes=0)
        state.manifest = {**MANIFEST, "data_directories": [
            {"ref": "bluemsx", "dest": "", "files": {
                "Machines/a.txt": {"sha1": "0" * 40, "size": 1},
                "Machines/b.txt": {"sha1": "0" * 40, "size": 1}}}]}
        install.LOCAL.reset()
        self.addCleanup(install.LOCAL.reset)
        install.LOCAL.pack = install.PackSource([pack])
        rows = install.tui_rows(state)
        self.assertNotIn("install", [row.action for row in rows])
        self.assertEqual(rows[state.focus.get("plan", 0)].action, "fromcard")
        text = self.screen(state)
        self.assertIn("RetroArch_BIOS_Pack.zip holds none of these 6 files", text)
        self.assertIn("1 in place, 5 missing, 1 wrong copy", text)


class ProvenCardsAndCounts(unittest.TestCase):
    """A card its markers prove is that
    system's card everywhere, counts and states that tell the truth, one
    width for every layout, line mode's order and words as the screen's,
    and a tap that shows it was seen."""

    setUp = LineModeRuns.setUp
    line_run = LineModeRuns.line_run
    listing = LineModeRuns.listing
    entry = staticmethod(LineModeRuns.entry)
    both = LineModeRuns.both
    drive = DriveRuns.drive
    first_screen = DriveRuns.first_screen
    folder_screen = DriveRuns.folder_screen
    game_listing = ChoiceScreens.game_listing
    game_manifest = ChoiceRuns.game_manifest
    receive = staticmethod(ChoiceRuns.receive)
    screen = staticmethod(ChoiceScreens.screen)

    def amberelec(self, name: str = "GAMES") -> Path:
        return games_part(self.root / "media" / name)

    def emuelec(self, name: str = "EEROMS") -> Path:
        card = self.drive(name, ("bios", "nes", "bezels"))
        (card / "bezels" / "default.cfg").write_text("")
        return card

    line_from = ProvenRuns.line_from

    # Root cause 1: a card its markers prove is that system's card.

    def test_a_games_part_is_its_systems_card_in_both_modes(self):
        """The GAMES card AmberELEC's folders prove, and
        the EEROMS card EmuELEC's prove, read "A card is in the reader:
        choose its system" with RetroArch focused, and two presses of Enter
        put RetroArch's list on them."""
        for plat, name, make in (("amberelec", "AmberELEC", self.amberelec),
                                 ("emuelec", "EmuELEC", self.emuelec)):
            with self.subTest(system=name):
                card = make()
                state = self.first_screen([card])
                text = self.screen(state)
                self.assertIn(f"{name} SD card ({card.name})", text)
                self.assertNotIn("in the reader", text)
                self.assertIn(f"BIOSfolder:{card / 'bios'}", "".join(text.split()))
                (line, screen, said) = self.both([card], [])
                self.assertEqual(line, (plat, card))
                self.assertEqual(screen, (plat, card))
                self.assertIn(f"Found {name}", said)
                shutil.rmtree(card)

    def test_their_own_routes_take_the_card_they_prove(self):
        """--platform amberelec said it "cannot tell an
        AmberELEC card by its files" of the card holding gamedata/ and
        homebrew/, and line mode offered no Enter for it."""
        for plat, name, make in (("amberelec", "AmberELEC", self.amberelec),
                                 ("emuelec", "EmuELEC", self.emuelec)):
            with self.subTest(system=name):
                card = make()
                stick = self.drive(f"{name}STICK", ("bios",))
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    self.assertEqual(install.mounted_cards_of(name, plat), [card])
                    self.assertEqual(install.blank_cards_of(name, plat), [stick])
                    choice = install.card_choice(name, plat, card)
                    self.assertEqual((choice.refused, choice.folder), ("", card))
                    self.assertNotIn("cannot tell", choice.note)
                (line, screen, said) = self.both([card, stick], [], platform=plat)
                self.assertEqual(line, (plat, card))
                self.assertEqual(screen, (plat, card))
                self.assertIn(f"Found {name} at {card / 'bios'}", said)
                self.assertNotIn("cannot tell", said)
                # Asked for its card, the one its files prove is offered.
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    dest = install.card_install_dest(name, plat, True, False)
                self.assertEqual(dest, card)
                self.assertIn(f"{name} card found at {card.name}", out.getvalue())
                with mock.patch.object(install, "_mounted_cards", return_value=[card, stick]), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    state = screen_keys(_args(platform=plat, declared_only=False), [])
                    view = " ".join(install.tui_view(state, 80, 24))
                self.assertNotIn("cannot tell", view)
                shutil.rmtree(card)
                shutil.rmtree(stick)

    def test_an_arkos_card_from_any_year_is_a_card(self):
        """ArkOS's default trees of 2020 hold no themes/
        (9664c869 none of themes and launchimages, 495eb210 and c14afbe5
        launchimages only), and the 12262020 update skipped the themes of a
        card with under 1 GB free. Every tree holds bgmusic/. A data drive
        holding neither stays no card."""
        layouts = {
            "ARK_9664c869": ("bios", "bgmusic", "ports", "snes", "System Volume Information"),
            "ARK_495eb210": ("bios", "bgmusic", "launchimages", "ports", "snes"),
            "ARK_c14afbe5": ("bios", "bgmusic", "launchimages", "psx"),
            "ARK_f41b9485": ("bios", "bgmusic", "launchimages", "themes", "backup", "nes"),
            "ARK_FULL1226": ("bios", "launchimages", "nes"),
        }
        cards = [self.drive(name, folders) for name, folders in layouts.items()]
        data = self.drive("DATA", ("bios", "snes", "Music", "themes"))
        music = self.drive("MUSIC", ("bgmusic", "launchimages"))
        mounts = [*cards, data, music]
        with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()):
            self.assertEqual([install.card_system(card) for card in cards],
                             [("retroarch", card / "bios", "ArkOS") for card in cards])
            self.assertEqual([install.games_part(card).name for card in cards],
                             ["ArkOS"] * len(cards))
            self.assertIsNone(install.games_part(data))
            self.assertIsNone(install.games_part(music))
            self.assertEqual(install.unproven_drives(), [data])
            with mock.patch.object(install, "_drive_not_removable", return_value=True):
                self.assertEqual([install.card_system(card) for card in cards],
                                 [None] * len(cards))

    # Root cause 2: counts and states that tell the truth.

    def wrong_copy_run(self, answers: list) -> tuple[str, list, Path]:
        """An offline run whose BIOS folder holds a wrong copy of the right
        size of a.bin, a folder named with --from holding b.bin."""
        good_a, good_b = b"A" * 64, b"B" * 64
        listing = self.listing("retroarch", [self.entry("a.bin", good_a, ["nintendo-gba"]),
                                             self.entry("b.bin", good_b, ["nintendo-gba"])])
        dest = self.root / "dest"
        dest.mkdir()
        (dest / "a.bin").write_bytes(b"Z" * 64)
        old = self.root / "old"
        old.mkdir()
        (old / "b.bin").write_bytes(good_b)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, asked = self.line_from(_args(manifest=listing, dest=dest, platform="retroarch",
                                               declared_only=False), answers, [old])
        return text, asked, dest

    def test_the_head_never_calls_a_wrong_copy_in_place(self):
        """A wrong copy of the right size was in place
        for the head, which said "1 found in old, nothing to download" over
        a run that left it."""
        text, _asked, dest = self.wrong_copy_run([""])
        self.assertIn("RetroArch: 1 found in old, 1 needs the internet.", text)
        self.assertNotIn("nothing to download", text)
        self.assertEqual((dest / "a.bin").read_bytes(), b"Z" * 64)

    def test_a_wrong_copy_left_is_said_as_one(self):
        """The result said "1 still missing" of a file
        --check counts as a wrong copy."""
        text, _asked, _dest = self.wrong_copy_run([""])
        self.assertIn("Finished with files missing.", text)
        self.assertIn("1 file copied from", text)
        self.assertIn(", 1 wrong copy left.", text)
        self.assertNotIn("still missing", text.rsplit("Finished", 1)[1])

    def test_a_count_agrees_with_its_verb(self):
        """"1 need the internet" on the plan, and on
        line mode's data tree line."""
        self.assertEqual(install.agree(1, "needs", "need"), "1 needs")
        self.assertEqual(install.agree(2, "needs", "need"), "2 need")
        self.assertEqual(install._plural(2, "wrong copy"), "2 wrong copies")
        self.assertEqual(install._plural(1, "wrong copy"), "1 wrong copy")
        self.assertEqual(install._plural(2, "day"), "2 days")
        state = checked_state()
        state.offline = True
        folder = "/media/OLD"
        state.from_folders = [Path(folder)]
        copied = ("scph5500.bin", "pcsx/extra.bin", "gba_bios.bin")
        state.found = [found(dest, folder) for dest in copied]
        state.check = planned(CHECK, copied)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text = self.screen(state, 100, 30)
        self.assertIn("3 found in OLD, 1 needs the internet", text)
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\} need the internet")

    def test_line_mode_says_what_is_still_missing_before_the_remedy(self):
        """"They are not in OLD" followed "Installed: 6
        BIOS files", where the screen puts "Still missing:" between them."""
        bios, game = b"B" * 32, b"G" * 32
        listing = self.listing("retroarch", [
            self.entry("a.bin", bios, ["nintendo-gba"]),
            self.entry("b.bin", b"C" * 32, ["nintendo-gba"]),
            self.entry("g.dat", game, ["sega-dreamcast"], category="game_data")],
            categorized=True)
        dest = self.root / "dest"
        dest.mkdir()
        old = self.root / "OLD"
        old.mkdir()
        (old / "a.bin").write_bytes(bios)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            text, _asked = self.line_from(_args(manifest=listing, dest=dest,
                                                platform="retroarch", declared_only=False),
                                          [""], [old])
        end = text.rsplit("Finished with files missing", 1)[-1]
        self.assertIn("Still missing: 1 BIOS file and 1 game data file.", end)
        self.assertLess(end.index("Still missing:"), end.index(f"They are not in {old}"))
        self.assertLess(end.index("Installed:"), end.index("Still missing:"))

    def test_a_rerun_with_everything_in_place_offers_nothing(self):
        """Line mode offered "Enter) install what is
        found", then said "Everything is in place." twice."""
        data = b"A" * 64
        listing = self.listing("retroarch", [self.entry("a.bin", data, ["nintendo-gba"])])
        dest = self.root / "dest"
        dest.mkdir()
        (dest / "a.bin").write_bytes(data)
        text, asked = self.line_from(_args(manifest=listing, dest=dest, platform="retroarch",
                                           declared_only=False), [])
        self.assertEqual(asked, [])
        self.assertNotIn("Enter)", text)
        self.assertIn("RetroArch: 1 file, every one in place: nothing to install.", text)
        self.assertEqual(text.count(install.EVERYTHING_IN_PLACE), 1)

    def test_line_mode_names_the_files_it_cannot_supply(self):
        """"Not installable: 37 files (1 required, not
        found: 37)" read as a sum, and line mode never named the file the
        screen names, nor its folder."""
        listing = self.listing("retroarch", [
            self.entry("a.bin", b"A" * 8, ["nintendo-gba"])], categorized=True,
            omitted_files=[
                {"dest": "jazz2/Source/Anims.j2a", "name": "Anims.j2a",
                 "system": "jazz-jackrabbit-2", "required": True, "reason": "not_found",
                 "category": "game_data"},
                {"dest": "x.bin", "name": "x.bin", "system": "nintendo-gba",
                 "required": False, "reason": "not_found"}])
        dest = self.root / "dest"
        dest.mkdir()
        text, _asked = self.line_run(_args(manifest=listing, dest=dest, platform="retroarch",
                                           declared_only=False, dry_run=True), [])
        self.assertIn("Not available here: jazz2/Source/Anims.j2a (Jazz Jackrabbit 2), game "
                      "data its game reads. Copy it from an owned copy of the game into "
                      f"{dest / 'jazz2' / 'Source'}{os.sep}.", text)
        self.assertEqual(install.not_installable_words(37, 1, {"not_found": 37}),
                         "Not installable: 37 files are not in the collection, 1 of them "
                         "required.")
        self.assertEqual(install.not_installable_words(1, 1, {"not_found": 1}),
                         "Not installable: 1 file is not in the collection, required.")
        self.assertIn("Why: no save directory (2), not found (3).",
                      install.not_installable_words(5, 0, {"not_found": 3,
                                                           "no_save_directory": 2}))

    def test_a_system_emptied_by_no_game_data_is_named(self):
        """--system nintendo-ds,sega-dreamcast with
        --no-game-data: "For 1 of 8 systems (--system)", Dreamcast unsaid
        until after Enter."""
        manifest = self.game_manifest()
        words = (f"{install.system_title('sega-dreamcast', manifest)} holds only game data: "
                 "left out (--no-game-data).")
        listing = self.game_listing()
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True,
                                           system=["nintendo-ds", "sega-dreamcast"],
                                           no_game_data=True), [])
        head = text.split("Enter)", 1)[0]
        self.assertIn(words, head)
        state = install.TuiState(os_type="linux", home=HOME)
        state.manifest = manifest
        state.no_game_data = True
        state.cli_systems = ["nintendo-ds", "sega-dreamcast"]
        state.systems = [{"system": "nintendo-ds", "name": "Nintendo DS", "files": 1,
                          "present": 0, "missing": 1, "wrong_hash": 0, "bytes_needed": 1}]
        state.ticked = {"nintendo-ds"}
        state.dest = self.here
        state.platform = "retroarch"
        state.check = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0}
        state.stack = ["plan"]
        self.assertIn(words, self.screen(state, 100, 40))

    def test_a_run_with_failures_counts_once(self):
        """"Done. 44 files installed." then "38 files
        copied from E:\\, 4 downloaded, 2 still missing." gave two counts,
        the two that failed as missing. Each mode says one, failures named."""
        out = io.StringIO()
        sources = install.sources_line([("/media/OLD", 38)], 0, 4, 0, failed=2)
        self.assertEqual(sources, "38 files copied from /media/OLD, 4 downloaded, 2 failed.")
        with contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            install._report_outcome([self.here], 42, 0, 2, 0, False,
                                    details=install.OutcomeDetails(failures=[("x.bin", "timed out"), ("y.bin", "timed out")],
                                                                   sources=sources))
        text = out.getvalue()
        self.assertIn(f"Finished with errors. {sources}", text)
        self.assertNotIn("42 files installed", text)
        self.assertNotIn("still missing", text)
        state = checked_state()
        state.from_folders = [Path("/media/OLD")]
        state.local_dests = {"gba_bios.bin": ("/media/OLD", "")}
        state.finished = [("gba_bios.bin", True, ""), ("scph5500.bin", False, "timed out")]
        state.stack, state.run = ["result"], "install"
        state.summary = {"event": "summary", "mode": "install", "installed": 1,
                         "up_to_date": 0, "pending": 1,
                         "failed": [{"dest": "scph5500.bin", "reason": "timed out"}],
                         "skipped": [], "left_out": [], "kept": [], "interrupted": False}
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Finished with errors")
        self.assertEqual(lines[0], "1 file copied from OLD, 1 failed.")
        self.assertNotIn("1 installed, 1 failed.", lines)

    def test_check_never_says_a_missing_file_was_opened(self):
        """"missing: nintendo-ds_0.bin" then "opened at
        ..." read as a file that was opened."""
        entry = {"dest": "a.bin", "systems": ["nintendo-gba"], "cores": None}
        self.assertEqual(install.opened_line(entry, {}, self.here),
                         f"expected at {self.here / 'a.bin'}")
        named = {**entry, "cores": ["mgba"]}
        self.assertEqual(install.opened_line(named, {}, self.here),
                         f"read by mgba at {self.here / 'a.bin'}")

    # Root cause 3: one width with a floor.

    def test_a_terminal_of_no_size_has_the_fallback(self):
        """Python 3.8 gives a pty of no size as 0 and 0.
        The plan printed "0 systems, the largest first:" and the progress
        line lost every figure but its percentage."""
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((0, 0))):
            self.assertEqual(install.terminal_size(), (80, 24))
            out = io.StringIO()
            term = types.SimpleNamespace(live=True, quiet=False, stream=out,
                                         bold=str, dim=str)
            progress = install.Progress(1, 1400, term)
            progress.bytes = progress.files = 1400
            progress.files = 1
            progress._draw()
            self.assertIn("(1/1 files)", out.getvalue())
            self.assertIn("[####", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as plan:
                install._print_plan([], self.here, term, copied=["  1 file copied"])
            self.assertNotIn("the largest first", plan.getvalue())
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((8, 3))):
            self.assertEqual(install.terminal_size(), (install.LINE_MIN_COLS, 3))

    def systems_question(self, cols: int) -> list[str]:
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        out = io.StringIO()
        with mock.patch.object(install.shutil, "get_terminal_size",
                               return_value=os.terminal_size((cols, 24))), \
                mock.patch.object(install, "_ask", return_value=""), \
                contextlib.redirect_stdout(out):
            install._choose_narrowing(manifest["files"], [], manifest, None)
        text = out.getvalue()
        ends = [at for at in (text.find("\nCores:"), text.find("\nThe platform's own"))
                if at >= 0]
        return text[text.index("Systems:"):min(ends, default=len(text))].splitlines()

    def test_the_systems_question_stays_inside_the_terminal(self):
        """6 lines of 81 cells at 80 columns, 16 of 41 at
        40, "shared" and "platform" alone on a line."""
        for cols in (100, 80, 60, 40, 30):
            with self.subTest(cols=cols):
                lines = self.systems_question(cols)
                for line in lines:
                    self.assertLess(install.cell_width(line), cols, line)
                    if line.strip() and not line.endswith(":"):
                        self.assertTrue(len(install._glued_words(line)) > 1
                                        or re.match(r" *\d+\) ", line), (cols, line))
                note = " ".join(line.strip() for line in lines[lines.index(
                    next(line for line in lines if line.startswith("'Other"))):])
                self.assertIn("this platform does not list", note)

    def test_the_setup_list_never_folds_inside_a_word(self):
        """At 39 columns "Miy" / "oo Flip"."""
        for cols in (80, 39, 30):
            with self.subTest(cols=cols):
                with mock.patch.object(install.shutil, "get_terminal_size",
                                       return_value=os.terminal_size((cols, 11))), \
                        mock.patch.object(install, "_install_standalone_folders",
                                          return_value=False):
                    text, _asked = self.line_run(_args(declared_only=False), [])
                block = text.split("Which setup?", 1)[1].split("  q) quit", 1)[0]
                lines = [line for line in block.splitlines() if line.strip()]
                self.assertTrue(lines)
                for line in lines:
                    self.assertLess(install.cell_width(line), cols, line)
                self.assertIn("Miyoo Flip", " ".join(" ".join(lines).split()))

    # Root cause 4: line mode in the screen's order and words.

    def test_on_wsl_the_card_comes_first_in_both_modes(self):
        """Line mode numbered Windows RetroArch 1) and
        the card 2), where the screen put the card first. One order for
        both: the other side first, then the drives (an ArkOS card is now a
        setup found)."""
        data = self.drive("DATA", ("bios", "snes"))
        windows = Path("/mnt/c/RetroArch-Win64/system")
        side = [("Windows RetroArch: C:\\RetroArch-Win64\\system", windows)]
        with mock.patch.object(install, "_mounted_cards", return_value=[data]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "other_side", return_value=side), \
                mock.patch.object(install, "_ask", return_value="q"), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.suppress(SystemExit):
            install.ask_platform_folder("wsl", "retroarch")
        state = self.first_screen([data])
        self.assertRegex(out.getvalue(), r"\n    1\) Windows RetroArch")
        self.assertRegex(out.getvalue(), r"\n    2\) DATA: bios \(drive")
        with mock.patch.object(install, "_mounted_cards", return_value=[data]), \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "other_side", return_value=side):
            state.os_type = "wsl"
            install.tui_update(state, Key("enter"))
            rows = [row for row in install.tui_rows(state) if row.action == "drive"]
        self.assertEqual([row.value for row in rows], [windows, data / "bios"])

    def test_nothing_found_is_said_once(self):
        """"Nothing was found here." twice, and after "A
        card is in the reader"."""
        # The standalone emulators' lists come from the network: none here.
        with mock.patch.object(install, "_install_standalone_folders", return_value=False):
            text, _asked = self.line_run(_args(declared_only=False), [])
        self.assertEqual(text.count("Nothing was found here."), 1)
        card = games_part(self.root / "media" / "EASYROMS")
        text, _asked = self.line_run(_args(declared_only=False), [], mounts=[card])
        # The card its folders prove is found.
        self.assertIn("ArkOS SD card (EASYROMS)", text)
        self.assertNotIn("Nothing was found here", text)

    def test_the_bios_only_drive_note_is_one_plain_sentence(self):
        """"listed, not chosen", "(card or drive)" under
        a note saying no card, two parentheses side by side, and "keeps
        them" after a title."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        mounts = [data, stick]
        state, text, rows = self.folder_screen(mounts)
        self.assertIn("DATA and STICK have a bios folder but no folder a handheld system "
                      "writes. Pick one below if the BIOS files go there.", text)
        labels = [row.label for row in rows]
        self.assertIn("DATA: bios (drive)", labels)
        self.assertIn("STICK: bios (drive)", labels)
        line, _asked = self.line_run(_args(manifest=self.game_listing(), dry_run=True,
                                           declared_only=False), ["1", ""], mounts=mounts)
        for said in (text, line):
            self.assertNotIn("listed, not chosen", said)
            self.assertNotIn("card or drive", said)
            self.assertNotIn(") (", said)
            self.assertNotIn("keeps them", said)

    def test_the_same_choice_is_one_command_in_both_modes(self):
        """The screen wrote --manifest before --from,
        line mode after it."""
        hint = install.Invocation()
        hint.os_type = "linux"
        hint.options = [("--from", "/media/OLD"), ("--offline", None),
                        ("--manifest", "/x/list.json"), ("--system", "a")]
        self.assertEqual(hint.command("retroarch", "/dest"),
                         "python3 install.py --platform retroarch --dest /dest --manifest "
                         "/x/list.json --system a --from /media/OLD --offline")
        state = checked_state()
        state.manifest_given, state.manifest_path = True, Path("/x/list.json")
        state.from_folders = [Path("/media/OLD")]
        args = _args(manifest="/x/list.json", platform="retroarch", dest=SYSTEM_DIR,
                     declared_only=False, offline=False)
        setattr(args, "from", ["/media/OLD"])
        line = install.Invocation()
        line.os_type = "linux"
        line.record(args)
        state.offline = True
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            line.options.append(("--offline", None))
            self.assertEqual(install.tui_command(state), line.command("retroarch", SYSTEM_DIR))

    # Root cause 5: interaction.

    def test_a_tap_on_a_focused_row_shows_it_was_seen(self):
        """One tap on the focused Onion row showed
        nothing, a second continued."""
        state = fresh_state()
        state.stack = ["setup"]
        state.mouse = True
        lines = drawn(state, 80, 24)
        row = next(index for index, line in enumerate(lines)
                   if str(line).lstrip().startswith("> "))
        self.assertEqual(tap(state, 4, row), [])
        lines = drawn(state, 80, 24)
        self.assertIn(f"A/Enter Continue: {install.TUI_ARMED}", str(lines[-1]))
        self.assertIn(f"RetroArch: {install.TUI_ARMED}", str(lines[row]))
        self.assertNotEqual(tap(state, 4, row), [])

    def test_a_phone_bar_names_the_enter_key(self):
        """Termux at 40 columns said "A Continue", and
        the a key does nothing."""
        state = install.TuiState(os_type="android", home=HOME)
        state.pad = install.tui_pad_route("android", {})
        self.assertEqual(state.pad, "both")
        bar = str(install.tui_view(state, 40, 12)[-1])
        self.assertIn("Enter", bar)
        self.assertNotRegex(bar, r"(^| )A ")
        self.assertIn("A/Enter", str(install.tui_view(state, 80, 24)[-1]))
        state.pad = "gptokeyb"
        self.assertRegex(str(install.tui_view(state, 40, 12)[-1]), r"(^| )A ")

    def test_which_folder_keeps_its_folder_at_40_by_12(self):
        """With two drives holding bios, Which folder?
        at 40x12 dropped the folder "Use this folder" stands for."""
        data = self.drive("DATA", ("bios", "snes", "Music"))
        stick = self.drive("STICK", ("bios",))
        for mounts in ([data, stick], [data]):
            with self.subTest(mounts=[mount.name for mount in mounts]):
                state, _text, _rows = self.folder_screen(mounts)
                with mock.patch.object(install, "_mounted_cards", return_value=mounts), \
                        mock.patch.object(install, "_mount_points", return_value=frozenset()):
                    small = " ".join(str(line) for line in install.tui_view(state, 40, 12))
                folder = str(state.folder_default)
                self.assertIn("reads its BIOS files", small)
                # The folder wraps after a separator wherever the temporary
                # path's length puts it, and a long one keeps its last
                # folders after "...": read its tail with the breaks out.
                tail = "/".join(Path(folder).parts[-2:])
                self.assertIn(tail, "".join(small.split()))

    # The owner's note: Cores drew every box empty when no core narrows the
    # run, read as "nothing is ticked, tick them all".

    def cores_screen(self, **given) -> install.TuiState:
        state = checked_state()
        state.cores = list(given.get("cores", []))
        state.cli_cores = list(state.cores)
        press(state, "o")
        state.focus["options"] = next(index for index, row in enumerate(
            install.tui_rows(state)) if row.action == "cores")
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        return state

    @staticmethod
    def boxes(state: install.TuiState) -> dict:
        return {row.value: row.label[:3] for row in install.tui_rows(state)
                if row.action == "core"}

    def test_cores_open_every_one_ticked(self):
        state = self.cores_screen()
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_rows(state)[state.focus["cores"]].value, "mesen")
        self.assertEqual(install.tui_flags(state), [])

    def test_one_untick_narrows_to_the_others(self):
        state = self.cores_screen()
        press(state, " ")
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_flags(state), [("--core", "pcsx_rearmed")])
        press(state, " ")
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(state.cores, [])
        press(state, " ", "esc")
        self.assertEqual(state.screen, "options")
        row = next(row for row in install.tui_rows(state) if row.action == "cores")
        self.assertEqual(row.label, "Cores: 1 of 2")
        state.stack = ["setup", "plan"]
        self.assertIn("1 of 2 cores", " ".join(install.tui_view(state, 100, 30)))

    def test_none_then_all_as_the_systems_list(self):
        state = self.cores_screen()
        rows = install.tui_rows(state)
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "none")
        press(state, "enter")
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[ ]"})
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "done")
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        self.assertIn("No core is ticked", str(state.status))
        state.focus["cores"] = next(i for i, row in enumerate(rows) if row.action == "all")
        press(state, "enter")
        self.assertEqual(self.boxes(state), {"mesen": "[x]", "pcsx_rearmed": "[x]"})
        self.assertEqual(install.tui_flags(state), [])

    def test_core_ticks_only_the_cores_it_names(self):
        state = self.cores_screen(cores=["pcsx_rearmed"])
        self.assertEqual(self.boxes(state), {"mesen": "[ ]", "pcsx_rearmed": "[x]"})
        state.stack = ["setup", "plan"]
        self.assertIn("--core", " ".join(install.tui_view(state, 100, 30)))

    def test_both_modes_count_the_cores_kept_alike(self):
        listing = self.listing("retroarch", [
            self.entry("a.bin", b"A" * 8, ["nintendo-gba"]),
            self.entry("m.bin", b"M" * 8, ["nintendo-gba"], cores=["mgba"]),
            self.entry("v.bin", b"V" * 8, ["nintendo-gba"], cores=["vba_next"]),
            self.entry("p.bin", b"P" * 8, ["sony-playstation"])])
        text, _asked = self.line_run(_args(manifest=listing, dest=self.here,
                                           declared_only=False, dry_run=True),
                                     ["c", "", "2"])
        self.assertIn("Every core's extra files are kept: Enter keeps them all", text)
        head = text.rsplit("Counted again for these choices", 1)[1]
        self.assertIn("1 of 2 cores", head)
        self.assertEqual(install.cores_words(0, 2), "0 of 2 cores")
        self.assertEqual(install.cores_words(2, 2), "all cores")

    # Root cause 6: the pages say what the installer shows.

    @unittest.skipIf(sys.version_info < BUILDER_FLOOR,
                     "the site generator needs Python 3.9")
    def test_which_pack_names_the_first_screen(self):
        """Which-pack said the command opens a screen
        where Install and Choose systems are, the second screen."""
        from sitegen import guidepage

        words = " ".join(guidepage.first_screen_words())
        found, nothing = fresh_state(), install.TuiState(os_type="linux", home=HOME)
        found.stack = ["setup"]
        self.assertIn(install.tui_view(found, 80, 24)[0].split(": ", 1)[1].strip(), words)
        self.assertIn(install.tui_view(nothing, 80, 24)[0].split(": ", 1)[1].strip(), words)
        self.assertLess(words.index(install.TUI_FOUND_TITLE),
                        words.index(install.TUI_INSTALL_ROW))
        self.assertNotIn("opens a screen", words)
        # Nothing found, Which folder? comes before the plan.
        self.assertIn(f"**{install.TUI_FOLDER_TITLE}**", words)
        self.assertLess(words.index(install.TUI_FOLDER_TITLE),
                        words.index(install.TUI_INSTALL_ROW))


if __name__ == "__main__":
    unittest.main()
