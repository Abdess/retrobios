"""The screens as drawn, held against the golden text in tests/fixtures/tui/."""

from __future__ import annotations

import tests

import argparse
import contextlib
import io
import os
import re
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, BACKUPS, backups_state, CHECK, checked_state, FILES, fresh_state, GOLDEN, golden_states,
    golden_states_result, HOME, in_full, Key, MANIFEST, more_state, pack_event, pack_plan_state,
    PLAN, planned, press, record_setup, record_state, removal_done_state, REMOVAL_PLAN,
    removal_state, REPO_ROOT, result_states, ROUTES, screen_text, SIZES, SYSTEM_DIR, SYSTEMS,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_views")


class RecordedPlan(unittest.TestCase):
    """The plan of a folder with an install record: opened on the one setup
    found, on the recorded choice, one press from installing it again."""

    def row(self, state: install.TuiState, action: str) -> install.TuiRow:
        return next(row for row in install.tui_rows(state) if row.action == action)

    def test_a_part_of_the_record_that_cannot_apply_is_left_out_as_line_mode_does(self):
        """Each region tested alone, as line mode keeps them, and the systems
        and emulators the list no longer names left out and said."""
        for choice, kept, said in (
                (["--region", "us", "--region", "zz"], ["--region", "us"],
                 "--region (a region this installer does not know)"),
                (["--system", "nintendo-gba", "--system", "zz-gone"],
                 ["--system", "nintendo-gba"], "--system (zz-gone no longer on the list)"),
                (["--emulator", "nosuch"], [], "--emulator (nosuch no longer on the list)")):
            with self.subTest(choice=choice):
                state = record_state(record_setup(choice))
                self.assertEqual(state.status, f"Left out of the recorded choice: {said}.")
                self.assertEqual(state.record["choice"], kept)
        self.assertEqual(record_state(record_setup(
            ["--region", "us", "--region", "zz"])).regions, ["north-america"])

    def test_a_recorded_region_is_the_same_choice_on_screen(self):
        """The screen spells regions as the manifests do and joins them: the
        record's own words are still its choice, in their order."""
        state = record_state(record_setup(["--region", "us", "--region", "jp"]))
        self.assertTrue(install.tui_record_kept(state))
        self.assertNotEqual(install._record_key([("--region", "us,jp")]),
                            install._record_key([("--region", "jp,us")]))

    def test_opens_on_the_plan_of_the_one_setup_found(self):
        state = record_state()
        self.assertTrue(state.opened_on_plan)
        self.assertEqual(state.stack, ["setup", "plan"])
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        press(state, "end", "up", "up", "up", "up")
        self.assertEqual(install.tui_rows(state)[state.focus["plan"]].label, "Change where")
        press(state, "enter")
        self.assertEqual(state.screen, "setup")

    def test_the_notes_of_the_setups_screen_are_on_the_plan(self):
        """Opened on the plan, the ES-DE note and the setup's label, which
        only the setups screen showed, were never seen."""
        setups = fresh_state().setups[:1]
        with mock.patch.object(install, "found_setups", return_value=(setups, set())), \
                mock.patch.object(install, "detect_frontends", return_value=["esde"]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_DETECTION_REFUSED", []), \
                mock.patch.object(install.Path, "exists", return_value=True):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertTrue(state.opened_on_plan)
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        for event in [*FILES, *SYSTEMS, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        state.pad = "both"
        plan = screen_text(install.tui_view(state, 80, 24))
        self.assertIn("1 note on this machine: Details.", plan)
        self.assertNotIn(install.TUI_ESDE_NOTE, plan)
        # The plan's budget, plus the note line (6 words) and Change where (2).
        self.assertLessEqual(screen_words(install.tui_view(state, 80, 24)),
                             SCREEN_WORDS["plan"][2] + 8)
        state.focus["plan"] = [row.action for row in install.tui_rows(state)].index("details")
        press(state, "enter")
        details = screen_text(install.tui_view(state, 120, 40))
        self.assertIn(screen_text([install.TUI_ESDE_NOTE]), details)
        self.assertIn("Found here: RetroArch.", details)

    def test_several_setups_open_the_list(self):
        with mock.patch.object(install, "found_setups", return_value=(
                fresh_state().setups, set())), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_DETECTION_REFUSED", []):
            state, effects = install.tui_start(_args(), "linux")
        self.assertEqual((state.screen, effects, state.opened_on_plan), ("setup", [], False))

    def test_one_press_installs_the_recorded_choice(self):
        state = record_state()
        self.assertEqual(self.row(state, "record").label, "Same choice as on 3 Nov: yes")
        self.assertIn("For nintendo-gba.", screen_text(
            install.tui_view(state, 80, 24)))
        self.assertEqual(press(state, "enter"), [("run", "install")])
        argv = install.tui_argv(state, "install", "py", "install.py")
        self.assertIn("--system=nintendo-gba", argv)
        self.assertNotIn("--all-files", argv)

    def test_no_takes_the_whole_list_and_yes_brings_it_back(self):
        state = record_state()
        state.focus["plan"] = install.tui_rows(state).index(self.row(state, "record"))
        with mock.patch.object(install, "games_probe", return_value=None):
            effects = press(state, "enter")
        self.assertEqual(effects, [("run", "check")])
        flags = install.tui_flags(state)
        self.assertIn(("--all-files", None), flags)
        self.assertFalse([flag for flag in flags if flag[0] == "--system"])
        self.assertFalse(install.tui_record_kept(state))
        for event in [*FILES, *SYSTEMS, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.assertEqual(self.row(state, "record").label, "Same choice as on 3 Nov: no")
        self.assertEqual(install.tui_rows(state)[state.focus["plan"]].action, "record")
        self.assertEqual(press(state, "enter"), [("run", "check")])
        self.assertIn(("--system", "nintendo-gba"), install.tui_flags(state))
        self.assertTrue(install.tui_record_kept(state))

    def test_the_command_line_choice_wins(self):
        with mock.patch.object(install, "setup_record",
                               return_value=(record_setup(), SYSTEM_DIR, "")), \
                mock.patch.object(install.Path, "exists", return_value=True):
            state, _effects = install.tui_start(
                _args(platform="retroarch", dest=str(SYSTEM_DIR), system=["sony-playstation"]),
                "linux", detect=False)
        self.assertEqual(install._tui_system_flags(state), [("--system", "sony-playstation")])
        self.assertFalse(install.tui_record_kept(state))
        self.assertEqual(install._record_rows(state), [])

    def test_a_record_that_cannot_be_read_is_said_once(self):
        problem = "The install record /x/system.install.json is damaged"
        install._RECORD_SAID.discard("/x/system.install.json")
        with mock.patch.object(install, "setup_record",
                               return_value=(None, Path("/x/system.install.json"), problem)), \
                mock.patch.object(install.Path, "exists", return_value=True):
            state, _effects = install.tui_start(
                _args(platform="retroarch", dest=str(SYSTEM_DIR)), "linux", detect=False)
            self.assertEqual(str(state.status), f"{problem}, so it is ignored.")
            state.status, state.record_for = "", None
            install._tui_record_load(state)
        self.assertEqual(state.status, "")
        self.assertIsNone(state.record)
        self.assertNotIn("--all-files", str(install.tui_flags(state)))

    def test_the_install_row_says_the_size_the_headline_says(self):
        """14930 files to download, 6.8 GB stood above Install 6.6 GB: the
        data files counted in one, the copies in the other."""
        big = 2 * 1024 ** 3
        state = checked_state()
        state.files[0] = {**state.files[0], "size": big}
        state.check = planned({**state.check, "bytes_needed": state.check["bytes_needed"] + big,
                               "data_missing": 3, "data_bytes": 300 * 1024 ** 2})
        headline = str(install._plan_lines(state.check, state.dest, state)[0])
        size = headline.rsplit(", ", 1)[1]
        self.assertEqual(install.tui_rows(state)[0].label, f"Install {size}")


class Views(unittest.TestCase):
    """Every screen as text, at the sizes a handheld and a desktop show."""

    def setUp(self):
        # The card screen lists the cards mounted here: none, on every machine.
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_goldens(self):
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        GOLDEN.mkdir(parents=True, exist_ok=True)
        for name, state in golden_states().items():
            for cols, rows in SIZES:
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    lines = install.tui_view(state, cols, rows)
                    self.assertEqual(len(lines), rows)
                    for line in lines:
                        # A path or a command kept whole folds in the terminal.
                        if line.style != "long":
                            self.assertLessEqual(install.cell_width(line), cols, line)
                        self.assertTrue(all(ord(c) < 128 or c in "ファミコン" for c in line),
                                        line)
                    self.assertLess(install.cell_width(lines[-1]), cols)
                    text = "\n".join(line.rstrip() for line in lines) + "\n"
                    path = GOLDEN / f"{name}-{cols}x{rows}.txt"
                    if update:
                        path.write_text(text, encoding="utf-8")
                    self.assertEqual(text, path.read_text(encoding="utf-8"))

    def test_goldens_per_route(self):
        """Each input route at the handheld sizes and 80x24, kept only where a
        screen reads differently from the both-names form."""
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        for route in ROUTES:
            sections = []
            for name, state in golden_states().items():
                state.pad = route
                for cols, rows in SIZES[:3]:
                    with self.subTest(route=route, screen=name, size=f"{cols}x{rows}"):
                        state.cols, state.rows = cols, rows
                        lines = install.tui_view(state, cols, rows)
                        for line in lines:
                            if line.style != "long":
                                self.assertLessEqual(install.cell_width(line), cols, line)
                        self.assertLess(install.cell_width(lines[-1]), cols)
                    text = "\n".join(line.rstrip() for line in lines) + "\n"
                    both = (GOLDEN / f"{name}-{cols}x{rows}.txt").read_text(encoding="utf-8")
                    if text != both:
                        sections.append(f"=== {name} {cols}x{rows}\n{text}")
            path = GOLDEN / f"route-{route}.txt"
            if update:
                path.write_text("".join(sections), encoding="utf-8")
            with self.subTest(route=route):
                self.assertEqual("".join(sections), path.read_text(encoding="utf-8"))

    def test_colour_goldens(self):
        """Every screen as the terminal gets it with colour, the escape
        codes kept (ESC written ^[), one file per size."""
        update = os.environ.get("RETROBIOS_UPDATE_GOLDENS") == "1"
        for cols, rows in SIZES:
            sections = []
            for name, state in golden_states().items():
                state.cols, state.rows = cols, rows
                painted = [install.tui_paint(str(line), line.style, True)
                           for line in install.tui_view(state, cols, rows)]
                sections.append(f"=== {name}\n" + "\n".join(painted).replace("\x1b", "^[")
                                + "\n")
            path = GOLDEN / f"colour-{cols}x{rows}.txt"
            if update:
                path.write_text("".join(sections), encoding="utf-8")
            with self.subTest(size=f"{cols}x{rows}"):
                self.assertEqual("".join(sections), path.read_text(encoding="utf-8"))

    def test_colour_adds_codes_and_never_text(self):
        """With colour off a line is drawn as before, its style alone, and
        with colour on, stripped of its codes, it is the same text: the
        golden screen, character for character."""
        for cols, rows in SIZES:
            colour = (GOLDEN / f"colour-{cols}x{rows}.txt").read_text(encoding="utf-8")
            screens = dict(re.findall(r"=== (\S+)\n(.*?)(?=\n=== |\n\Z)", colour, re.S))
            for name, state in golden_states().items():
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    lines = install.tui_view(state, cols, rows)
                    for line in lines:
                        # The bar's key names faint, its actions not:
                        # the rest as before.
                        self.assertEqual(install.tui_paint(str(line), line.style, False),
                                         install.painted(line, install._bar_spans(
                                             line, "strong")) if line.style == "hint"
                                         else install._STYLES.get(line.style, "") + line)
                    stripped = [install.unpainted(painted.replace("^[", "\x1b")).rstrip()
                                for painted in screens[name].split("\n")]
                    golden = (GOLDEN / f"{name}-{cols}x{rows}.txt").read_text(encoding="utf-8")
                    self.assertEqual("\n".join(stripped) + "\n", golden)

    def test_each_role_paints_a_status_word_on_the_result_screens(self):
        """Done, a part done, files left offline, a stop: between them the
        result screens use every role, each on a word that says it."""
        # The failed files are listed on the result's Details.
        told = result_states()["partial"]
        told.stack.append("details")
        drawn = "\n".join(install.tui_paint(str(line), line.style, True)
                          for state in [*result_states().values(), told]
                          for line in install.tui_view(state, 80, 24))
        for role, word in (("accent", "RetroBIOS"), ("strong+success", "4 files installed"),
                           ("strong+success", "Done"), ("failure", "1 failed"),
                           ("failure", "failed:"), ("strong+warning", "3 not fetched"),
                           ("strong+warning", "Stopped"),
                           ("strong", "/home/user/.config/retroarch/system")):
            with self.subTest(role=role, word=word):
                self.assertIn(install._sgr(role) + word, drawn)
        # "2 of 4 installed" is no count of files installed.
        self.assertNotIn(install._sgr("strong+success") + "4 installed", drawn)

    def test_the_status_words_take_their_role_and_a_zero_none(self):
        spans = install.status_spans("1 in place, 0 missing, 3 missing, 1 wrong copy, 2 failed")
        self.assertEqual([("1 in place", "success"), ("3 missing", "warning"),
                          ("1 wrong copy", "warning"), ("2 failed", "failure")],
                         [("1 in place, 0 missing, 3 missing, 1 wrong copy, 2 failed"[a:b], r)
                          for a, b, r in spans])
        self.assertEqual(install.status_spans("0 wrong copies, 0 missing"), [])
        self.assertEqual(install.status_spans("python3 install.py --platform retroarch"), [])

    def test_the_bar_paints_a_key_only(self):
        """The first entry's key in the accent, never a word: "Writing to the
        card..." and "Any key closes this help" name no key."""
        for text in (" Writing to the card...", " Any key closes this help"):
            self.assertEqual(install.tui_paint(text, "hint", True), text)
        painted = install.tui_paint(" A/Enter Exit  B/Esc Back", "hint", True)
        # The actions plain, the other keys faint.
        self.assertEqual(painted, " " + install._sgr("accent") + "A/Enter\x1b[0m Exit  "
                         + install._sgr("muted") + "B/Esc\x1b[0m Back")

    def test_the_hint_bar_names_the_primary_action_first(self):
        for name, state in golden_states().items():
            with self.subTest(screen=name):
                hint = install.tui_view(state, 40, 15)[-1].strip()
                # Checking has no A: Back comes first, Quit never in the
                # cell the screen before had Continue in.
                self.assertTrue(hint.startswith(("A/Enter", "A ", "Enter", "Ctrl-C", "Any key",
                                                 "B/Esc Stop", "B Stop")
                                                + (("B ",) if name == "checking" else ())),
                                hint)

    def test_focus_is_marked_without_colour(self):
        lines = install.tui_view(fresh_state(), 80, 24)
        focused = [line for line in lines if getattr(line, "style", "") == "focus"]
        self.assertEqual(len(focused), 1)
        self.assertTrue(focused[0].lstrip().startswith("> RetroArch"))


class Rendering(unittest.TestCase):
    def test_only_changed_lines_are_written(self):
        out = io.StringIO()
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.stdout, terminal.encoding, terminal.frame = out, "ascii", []
        state = fresh_state()
        terminal.draw(install.tui_view(state, 40, 12), 40)
        first = out.getvalue()
        self.assertTrue(first.startswith("\x1b[H\x1b[2J"))
        press(state, "down")
        out.seek(0)
        out.truncate()
        terminal.draw(install.tui_view(state, 40, 12), 40)
        changed = out.getvalue()
        self.assertEqual(changed.count("\x1b[7m"), 1)
        before = install.tui_view(fresh_state(), 40, 12)
        after = install.tui_view(state, 40, 12)
        moved = [f"\x1b[{i + 1};1H" for i, (a, b) in enumerate(zip(before, after)) if a != b]
        self.assertEqual(changed.count(";1H"), len(moved))
        for move in moved:
            self.assertIn(move, changed)

    def test_text_the_terminal_cannot_encode_is_replaced(self):
        out = io.StringIO()
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.stdout, terminal.encoding, terminal.frame = out, "ascii", []
        terminal.write("ファ")
        self.assertEqual(out.getvalue(), "??")


class TheSectionStandsApart(unittest.TestCase):
    def test_no_name_of_the_installer_is_defined_again(self):
        """_run and _system_label were defined twice: the later one won, and
        the installer's listing called the interface's. The interface is
        modules of installer/ now, joined into one namespace with the rest,
        so no name is defined twice anywhere in the file."""
        import ast

        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        seen: dict = {}
        for node in ast.parse(source).body:
            names = [node.name] if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else [
                target.id for target in getattr(node, "targets", [])
                if isinstance(target, ast.Name)]
            for name in names:
                seen.setdefault(name, []).append(node.lineno)
        twice = {name: lines for name, lines in seen.items()
                 if len(lines) > 1}
        self.assertEqual(twice, {})


class SmallFixes(unittest.TestCase):
    def test_a_system_name_is_said_once_with_a_pack(self):
        """"Onion gets the RetroArch file list" was
        printed by the pack check, then again where the platform is read."""
        pack = mock.Mock(files=[Path("RetroArch_BIOS_Pack.zip")])
        pack.name = "RetroArch_BIOS_Pack.zip"
        pack.platforms.return_value = ["retroarch"]
        args = argparse.Namespace(manifest=None, from_pack=Path("p.zip"), platform="onion",
                                  **{"from": None})
        with mock.patch.object(install, "PackSource", return_value=pack), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install._open_local_sources(args)
        self.assertNotIn("Onion gets", out.getvalue())
        install.LOCAL.reset()

    def test_a_command_line_region_the_list_lacks(self):
        state = checked_state()
        state.cli_regions = ["europe"]
        state.regions = list(state.cli_regions)
        state.stack += ["options", "regions"]
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "region"], ["europe", "japan", "north-america"])
        press(state, "enter")
        self.assertEqual(state.regions, [])
        self.assertIn("europe", [row.value for row in install.tui_rows(state)])
        press(state, "enter")
        self.assertEqual(state.regions, ["europe"])

    def test_stay_after_esc_on_a_direct_check_checks_again(self):
        state = fresh_state()
        state.stack = []
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._choose(state, "retroarch", Path(REPO_ROOT))
        self.assertEqual(state.screen, "checking")
        self.assertEqual(press(state, "esc"), [("kill",)])
        self.assertEqual(state.screen, "quit")
        self.assertEqual(press(state, "down", "enter"), [("run", "check")])
        self.assertEqual((state.stack, state.running), (["checking"], True))
        press(state, "esc")
        self.assertEqual(press(state, "esc"), [("run", "check")])

    def test_speed_ignores_a_resumed_partial(self):
        state = checked_state()
        press(state, "enter")
        mega = 1024 * 1024
        state.now = 9.0
        install.tui_receive(state, ("event", state.run_id, {
            "event": "download", "platform": "retroarch", "files": 2, "bytes": 1000 * mega}))
        # The first event carries the 500 MB already on disk.
        for when, done in ((10.0, 500 * mega), (11.0, 501 * mega), (12.0, 502 * mega)):
            state.now = when
            install.tui_receive(state, ("event", state.run_id, {
                "event": "progress", "files_done": 0, "files_total": 2,
                "bytes_done": done, "bytes_total": 1000 * mega}))
            # The partial copy resumed is counted local by the engine.
            install.tui_receive(state, ("event", state.run_id, {
                "event": "transfer", "bytes_local": 500 * mega,
                "bytes_network": done - 500 * mega}))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("1.0 MB/s, 8:18 left", text)

    def test_numbers_from_before_the_options_say_so(self):
        state = checked_state()
        state.stack.append("systems")
        self.assertNotIn("before the options", "\n".join(install.tui_view(state, 80, 24)))
        state.regions = ["japan"]
        footer = "\n".join(install.tui_view(state, 80, 24)[-3:])
        self.assertIn("before the options", footer)

    def test_a_cores_folder_implies_the_installed_cores(self):
        state = checked_state()
        state.passthrough = [("--cores-dir", "/opt/cores")]
        state.installed_only = True
        state.stack.append("options")
        row = next(r for r in install.tui_rows(state) if r.action == "installed")
        self.assertEqual(row.label, "Installed cores only: yes, implied by --cores-dir")
        state.focus["options"] = install.tui_rows(state).index(row)
        press(state, "enter", "left")
        self.assertTrue(state.installed_only)
        self.assertNotIn("--installed-cores", [f for f, _v in install.tui_flags(state)])

    @in_full
    def test_the_end_of_a_wrapped_pager_is_reachable(self):
        state = checked_state()
        state.stack.append("result")
        state.code, state.summary = 0, {"installed": 3}
        state.dest = Path("/media/" + "long-folder-name/" * 8)
        state.cols, state.rows = 40, 12
        press(state, "end")
        lines = install.tui_view(state, 40, 12)
        self.assertIn("python3 install.py", "\n".join(lines))
        top = state.focus["result"]
        press(state, "up")
        self.assertEqual(state.focus["result"], top - 1)

    def test_end_then_up_in_a_pager(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry, state.dry_files = dict(CHECK), list(FILES) * 10
        state.cols, state.rows = 40, 15
        press(state, "end")
        last = install.tui_view(state, 40, 15)
        press(state, "up")
        self.assertNotEqual(install.tui_view(state, 40, 15), last)

    def test_a_paste_slower_than_the_escape_wait_stays_one_piece(self):
        decoder = install.KeyDecoder()
        self.assertEqual(decoder.feed("\x1b[200~/media/"), [])
        self.assertEqual(decoder.flush(), [])
        self.assertTrue(decoder.waiting)
        self.assertEqual(decoder.feed("sd\x1b[201~"), [Key("paste", "/media/sd")])

    def test_values_cannot_be_read_as_options(self):
        state = checked_state()
        state.dest = Path("-rf")
        state.cores = ["-x"]
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertIn("--dest=-rf", argv)
        self.assertIn("--core=-x", argv)
        self.assertIn("--platform=retroarch", argv)

    def test_the_second_ctrl_c_is_announced_and_the_result_stays_honest(self):
        state = checked_state()
        press(state, "enter")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "download", "platform": "retroarch", "files": 4, "bytes": 100}))
        install.tui_receive(state, ("event", state.run_id, {
            "event": "downloaded", "dest": "a.bin", "ok": True, "reason": "", "size": 1,
            "files_done": 1, "files_total": 4, "bytes_done": 1, "bytes_total": 100}))
        press(state, "ctrl-c")
        self.assertIn("Press B or Ctrl-C again to stop now.",
                      " ".join(install.tui_view(state, 120, 40)))
        self.assertEqual(press(state, "ctrl-c"), [("kill",)])
        install.tui_receive(state, ("ended", state.run_id, -9, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual((title, state.code), ("Stopped", 130))
        self.assertEqual(lines[0], "Stopped: 1 of 4 installed, run again to finish.")

    def test_systems_show_the_platform_names(self):
        state = checked_state()
        state.systems.append({"event": "system", "system": "sega-saturn",
                              "name": "Sega - Saturn", "files": 1, "present": 0,
                              "missing": 1, "wrong_hash": 0, "bytes_needed": 5})
        state.ticked.add("sega-saturn")
        state.stack.append("systems")
        wide = "\n".join(install.tui_view(state, 120, 40))
        self.assertIn("[x] Sega - Saturn", wide)
        self.assertIn("sega-saturn", wide)
        narrow = "\n".join(install.tui_view(state, 40, 15))
        self.assertIn("[x] Sega - Saturn", narrow)
        self.assertNotIn("sega-saturn", narrow)
        press(state, "/", "s", "a", "t", "u")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "system"], ["sega-saturn"])


# The most words each screen may show by default, one count per size of
# SIZES (owner, 2026-11-09: a beginner lost the important line in text). A
# path is no word. The plan, Confirm and the result say what happens, where
# and what next, and their counts, notes and commands wait on Details. A list
# shows more rows on a taller window. A change that adds words to a screen
# raises its numbers here and says why: the result names its failed files
# (review of 2026-11-10), what the user acts on.
SCREEN_WORDS = {
    "setup": (29, 36, 34, 34), "platforms": (23, 27, 89, 225), "folder": (27, 27, 25, 25),
    "folder-card": (52, 52, 50, 50), "browse": (17, 17, 15, 15), "path": (23, 23, 25, 25),
    "create": (23, 23, 21, 21), "checking": (18, 18, 17, 17), "plan": (32, 32, 32, 32),
    "plan-in-place": (23, 23, 20, 20), "systems": (36, 37, 36, 36),
    "regions": (45, 44, 42, 42), "cores": (47, 47, 45, 45),
    "preview": (29, 29, 28, 28), "command": (22, 22, 16, 16), "confirm": (22, 22, 20, 20),
    "installing": (32, 32, 31, 31), "result": (33, 33, 31, 31), "error": (37, 34, 32, 31),
    "quit": (14, 14, 12, 12), "help": (24, 26, 26, 26), "plan-games": (36, 47, 55, 55),
    "games": (36, 45, 44, 44), "plan-details": (30, 30, 29, 29),
    "result-details": (30, 30, 19, 19),
    # The plan's words, plus the recorded choice by name, its row (the one
    # press back to the whole list) and Change where (back to the setups,
    # the plan having opened on the one found), and More, the record being
    # what a removal reads.
    "plan-record": (38, 42, 43, 43),
    # Change holds every option one level below the plan (design 4.4): the
    # rows for Emulators, a pack, the device and the internet, and the five
    # headings that group them, the intro sentence they replace dropped.
    "change": (32, 42, 72, 72),
    # Change with an expert row: one BIOS per console and region on a list
    # that records its slots, or the standalone build of the emulator chosen.
    "change-slot": (34, 44, 78, 78), "change-standalone": (32, 42, 76, 76),
    # A list of boards and one of emulators, each with the line that says
    # what the choice does and the gloss of "board".
    "device": (35, 35, 33, 33), "emulators": (29, 29, 27, 27),
    # Every plan names More (one word, counted in the plan budgets above):
    # a pack can always be made. More's four rows where the folder has a
    # record or a backup, then Make a pack (three words), Remove files with each system the record holds and its
    # size and the row for the misplaced copies (two words), the removal plan (what goes, the space freed, the folder, what
    # stays and why), its confirm and result, and the backups newest first.
    "more": (20, 20, 18, 18), "remove": (33, 33, 31, 31), "removal": (34, 34, 32, 32),
    "removal-confirm": (18, 18, 16, 16), "removal-done": (18, 18, 16, 16),
    "backups": (24, 24, 22, 22),
    # Make a pack: what goes in, its size and setup, where it goes, how it
    # is written (one ZIP, or the parts and why), then the result.
    "pack-plan": (27, 27, 24, 24), "pack-plan-parts": (39, 39, 35, 35),
    "pack-done": (29, 29, 25, 25),
}


def screen_words(lines: list) -> int:
    """Words of a drawn screen, its title and bar included, a path left out."""
    return sum(1 for line in lines for token in str(line).split()
               if re.search(r"[A-Za-z0-9]", token) and "/" not in token)


class MoreScreens(unittest.TestCase):
    """More: removal, the backups, putting one back and deleting one, each
    a child run with its own options and none of the plan's."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_plan_names_more_where_it_has_something_to_act_on(self):
        self.assertEqual([row.action for row in install.tui_rows(more_state())][-2:],
                         ["more", "quit"])
        done = golden_states()["plan-in-place"]
        self.assertEqual(install.tui_rows(done)[-1].action, "more")
        self.assertEqual([row.action for row in install.tui_rows(more_state("more"))],
                         ["remove", "backups", "putback", "dropbackup", "packmake"])

    def test_the_removal_plan_asks_its_own_child(self):
        state = removal_state()
        state.regions = ["japan"]
        argv = install.tui_argv(state, "removal_plan", "python", "install.py")
        self.assertEqual(argv[-4:], ["--remove", "--system=sony-playstation", "--dry-run",
                                     "--events"])
        self.assertNotIn("--region=japan", argv)
        self.assertIn(f"--dest={SYSTEM_DIR}", argv)
        self.assertEqual(state.screen, "removal")
        self.assertEqual(install.tui_rows(state)[0].label, "Remove 512.0 KB")

    def test_everything_removes_with_no_system(self):
        state = removal_state(system=False)
        argv = install.tui_argv(state, "removal_plan", "python", "install.py")
        self.assertEqual(argv[-3:], ["--remove", "--dry-run", "--events"])

    def test_the_misplaced_copies_are_deleted_never_moved_to_a_backup(self):
        state = more_state("more", "remove")
        actions = [row.action for row in install.tui_rows(state)]
        state.focus["remove"] = actions.index("rmmisplaced")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "removal_plan")])
        argv = install.tui_argv(state, "removal_plan", "python", "install.py")
        self.assertEqual(argv[-4:], ["--remove", "--misplaced", "--dry-run", "--events"])
        install.tui_receive(state, ("event", state.run_id, REMOVAL_PLAN))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        state.removal_backup = True
        self.assertNotIn("rmbackup", [row.action for row in install.tui_rows(state)])
        self.assertIn("in the wrong place go", screen_text(install.tui_view(state, 80, 24)))
        state.focus["removal"] = 0
        press(state, "enter")
        self.assertIn("The files where the cores read them stay.",
                      screen_text(install.tui_view(state, 80, 24)))
        press(state, "enter")
        argv = install.tui_argv(state, "remove", "python", "install.py")
        self.assertEqual(argv[-4:], ["--remove", "--misplaced", "--events", "--yes"])

    def test_a_backup_is_one_row_away_and_the_removal_says_so(self):
        state = removal_state()
        state.focus["removal"] = 1
        press(state, "enter")
        self.assertTrue(state.removal_backup)
        self.assertEqual(install.tui_rows(state)[0].label, "Move 512.0 KB to a backup")
        state.focus["removal"] = 0
        press(state, "enter")
        self.assertEqual(state.screen, "actconfirm")
        effects = press(state, "enter")
        self.assertEqual(effects, [("run", "remove")])
        argv = install.tui_argv(state, "remove", "python", "install.py")
        self.assertEqual(argv[-4:], ["--system=sony-playstation", "--backup", "--events",
                                     "--yes"])

    def test_close_ends_with_the_removal_s_code_and_back_counts_again(self):
        state = removal_done_state()
        self.assertEqual(state.screen, "actdone")
        self.assertIn("Removed 2 files, 512.0 KB freed.",
                      screen_text(install.tui_view(state, 80, 24)))
        press(state, "enter")
        self.assertEqual(state.exit_code, 0)
        state = removal_done_state()
        with mock.patch.object(install, "setup_record", return_value=(None, None, "")):
            effects = press(state, "esc")
        self.assertEqual(effects, [("run", "check")])
        self.assertEqual(state.screen, "checking")
        # The record is read again: the removal changed it.
        self.assertIsNone(state.record)

    def test_a_failure_is_said_and_ends_on_one(self):
        state = removal_state()
        press(state, "enter", "enter")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "removed", "platform": "retroarch", "dest": "scph5500.bin",
            "size": 524288, "ok": False, "reason": "Permission denied", "moved_to": ""}))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        self.assertIn("1 file failed.", screen_text(install.tui_view(state, 80, 24)))
        press(state, "enter")
        self.assertEqual(state.exit_code, 1)

    def test_a_put_back_says_why_it_is_not_done_and_where_files_were_kept(self):
        folder = str(BACKUPS[0]["folder"])
        state = backups_state("putback")
        press(state, "enter", "enter")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "restored", "folder": folder, "path": "/bios/scph5500.bin",
            "size": 524288, "ok": True, "reason": ""}))
        install.tui_receive(state, ("event", state.run_id, {
            "event": "restore", "folder": folder, "status": "not_done", "files": 1,
            "bytes": 524288, "kept": [{"folder": "/kept/20261122-101010", "files": 1,
                                       "bytes": 4}],
            "problem": "it is for /bios, which does not hold the files put back",
            "message": ""}))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = screen_text(install.tui_view(state, 100, 30))
        self.assertIn("Put back 1 file, 512.0 KB.", text)
        self.assertIn("Kept 1 file that were in their place (4 B) in /kept/20261122-101010",
                      text)
        self.assertIn("The install record could not be updated (it is for /bios", text)

    def test_put_back_and_delete_name_the_backup_alone(self):
        folder = BACKUPS[0]["folder"]
        for purpose, run, argv in (
                ("putback", "restore", [f"--restore={folder}", "--events"]),
                ("dropbackup", "delete_backup",
                 [f"--delete-backup={folder}", "--events", "--yes"])):
            with self.subTest(purpose=purpose):
                state = backups_state(purpose)
                press(state, "enter")
                self.assertEqual(state.screen, "actconfirm")
                self.assertEqual(press(state, "enter"), [("run", run)])
                self.assertEqual(install.tui_argv(state, run, "python", "install.py"),
                                 ["python", "install.py", *argv])

    def test_a_backup_looked_at_offers_both(self):
        state = backups_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "backup")
        self.assertEqual(state.backup_chosen["date"], BACKUPS[1]["date"])
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["bkrestore", "bkdelete", "back"])
        argv = install.tui_argv(state, "backups", "python", "install.py")
        self.assertEqual(argv[-2:], ["--backups", "--events"])

    def test_without_a_record_nothing_is_offered_to_remove(self):
        state = checked_state()
        state.record = None
        state.stack += ["more", "remove"]
        self.assertEqual([row.action for row in install.tui_rows(state)], ["back"])
        self.assertIn("No install record here", screen_text(install.tui_view(state, 80, 24)))

    def test_the_files_and_what_stays_are_on_details(self):
        state = removal_state()
        state.focus["removal"] = [row.action for row in install.tui_rows(state)].index(
            "details")
        press(state, "enter")
        text = screen_text(install.tui_view(state, 80, 24))
        self.assertIn("pcsx/extra.bin", text)
        self.assertIn("scph5501.bin: changed since it was installed", text)


class PackScreens(unittest.TestCase):
    """More, Make a pack: a dry run says what goes in, the run makes it,
    each a child given the plan's choice and none of the folder's options."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_more_is_on_every_plan_with_make_a_pack(self):
        state = checked_state()
        self.assertEqual([row.action for row in install.tui_rows(state)][-2:],
                         ["more", "quit"])
        state.stack.append("more")
        self.assertEqual([row.action for row in install.tui_rows(state)], ["packmake"])
        self.assertEqual([row.action for row in install.tui_rows(more_state("more"))][-1],
                         "packmake")

    def test_the_dry_run_takes_the_choice_and_not_the_folder(self):
        state = pack_plan_state()
        state.regions = ["japan"]
        state.passthrough = [("--save-dir", "/saves")]
        argv = install.tui_argv(state, "pack_plan", "python", "install.py")
        self.assertIn("--region=japan", argv)
        self.assertFalse([arg for arg in argv if arg.startswith(("--dest", "--save-dir"))])
        # No Downloads folder here: the home folder.
        self.assertEqual(argv[-3:], [f"--pack={HOME}{os.sep}", "--dry-run", "--events"])
        with mock.patch.object(install, "_is_dir", return_value=True):
            self.assertEqual(install.tui_pack_dir(state), HOME / "Downloads")
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["packgo", "packwhere"])

    def test_make_the_pack_runs_it_and_close_ends_on_its_code(self):
        state = pack_plan_state()
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "pack")])
        self.assertEqual(install.tui_argv(state, "pack", "python", "install.py")[-2:],
                         ["--events", "--yes"])
        self.assertIn("Making the pack...", screen_text(install.tui_view(state, 80, 24)))
        install.tui_receive(state, ("event", state.run_id, pack_event("written", size=900)))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertIn("Pack made: 4 files, 900 B.", screen_text(install.tui_view(state, 80, 24)))
        install.tui_update(state, Key("enter"))
        self.assertEqual(state.exit_code, 0)

    def test_a_pack_not_made_says_so_and_back_returns_to_more(self):
        state = pack_plan_state()
        install.tui_update(state, Key("enter"))
        failed = {**pack_event("failed"), "parts": [],
                  "message": "1 file could not be had: no pack was written."}
        install.tui_receive(state, ("event", state.run_id, failed))
        install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = screen_text(install.tui_view(state, 80, 24))
        self.assertIn("No pack was made.", text)
        self.assertIn("1 file could not be had", text)
        install.tui_update(state, Key("esc"))
        self.assertEqual(state.screen, "more")

    def test_change_where_browses_and_reads_the_plan_again(self):
        state = pack_plan_state()
        state.focus["packplan"] = 1
        with mock.patch.object(install, "_browse_rows", return_value=(
                [install.TuiRow("use", "Use this folder")], "")):
            install.tui_update(state, Key("enter"))
        self.assertEqual((state.screen, state.browse_for), ("browse", "packto"))
        state.browse_dir = Path("/media/card")
        self.assertEqual(install.tui_update(state, Key("enter")), [("run", "pack_plan")])
        self.assertEqual(state.screen, "packplan")
        self.assertEqual(install.tui_argv(state, "pack_plan", "python", "install.py")[-3],
                         f"--pack={Path('/media/card')}{os.sep}")

    def test_a_dry_run_that_ends_without_its_event_is_an_error(self):
        state = checked_state()
        state.stack += ["more"]
        state.focus["more"] = 0
        install.tui_update(state, Key("enter"))
        install.tui_receive(state, ("ended", state.run_id, 2, ["install.py: error: no"]))
        self.assertEqual(state.screen, "error")


class ScreenWordBudgets(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_every_screen_keeps_to_its_budget(self):
        states = golden_states()
        self.assertEqual(sorted(states), sorted(SCREEN_WORDS),
                         "a screen without a word budget, or a budget without its screen")
        for name, state in states.items():
            for (cols, rows), budget in zip(SIZES, SCREEN_WORDS[name]):
                with self.subTest(screen=name, size=f"{cols}x{rows}"):
                    state.cols, state.rows = cols, rows
                    words = screen_words(install.tui_view(state, cols, rows))
                    self.assertLessEqual(words, budget)

    def test_the_default_path_says_what_where_and_next_first(self):
        """The plan opens on what it installs and where, the result on what
        happened, where and the next step: nothing between them."""
        plan = [str(line).strip() for line in install.tui_view(checked_state(), 80, 24)]
        self.assertEqual(plan[2:4], ["4 files to download, 1.0 MB",
                                     "BIOS folder: ~/.config/retroarch/system"])
        self.assertEqual(plan[4], "")
        done = result_states()["done"]
        lines = [str(line).strip() for line in install.tui_view(done, 80, 24)]
        self.assertEqual(lines[2:5], ["4 files installed. 1 file already in place.",
                                      f"BIOS folder: {SYSTEM_DIR}",
                                      "Next: start RetroArch and play."])


class DetailsScreen(unittest.TestCase):
    """What the plan, Confirm and the result leave out by default, one key
    or one row away, and every line of --verbose in one place or the other."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def text(self, state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
        return "\n".join(str(line) for line in install.tui_view(state, cols, rows))

    def test_d_opens_the_plans_details_and_b_comes_back(self):
        state = checked_state()
        self.assertNotIn("Free space", self.text(state))
        press(state, "d")
        self.assertEqual(state.screen, "details")
        shown = self.text(state)
        for line in ("1 in place, 3 missing, 1 wrong copy", "Free space: 50.0 GB",
                     "The 1 wrong copy is replaced"):
            self.assertIn(line, shown)
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_a_controller_reaches_them_by_the_row(self):
        state = checked_state()
        rows = install.tui_rows(state)
        state.focus["plan"] = [row.action for row in rows].index("details")
        self.assertIn("A/Enter Show", self.text(state))
        press(state, "enter")
        self.assertEqual(state.screen, "details")
        press(state, "enter")
        self.assertEqual(state.screen, "plan")

    def test_the_results_details_are_said_after_exit_once_opened(self):
        state = golden_states_result()
        self.assertIn("Y/o Details", self.text(state))
        self.assertNotIn("Same choice without questions", "\n".join(install.tui_farewell(state)))
        press(state, "o")
        self.assertEqual(state.screen, "details")
        self.assertIn("Same choice without questions:", self.text(state))
        press(state, "esc")
        self.assertEqual(state.screen, "result")
        press(state, "enter")
        farewell = "\n".join(install.tui_farewell(state))
        self.assertIn("Same choice without questions:", farewell)
        self.assertIn("failed: scph5500.bin (HTTP 404)", farewell)

    def test_confirm_has_its_details_too(self):
        state = golden_states()["confirm"]
        self.assertNotIn("Free space", self.text(state))
        press(state, "d")
        self.assertEqual(state.screen, "details")
        self.assertIn("Nothing is written before Install.", self.text(state))
        self.assertIn("Free space: 50.0 GB", self.text(state))

    def test_every_line_is_on_the_screen_or_its_details(self):
        """The screen and its Details together say what --verbose says on
        the screen alone: no line is lost."""
        for name in ("plan", "plan-games", "plan-in-place", "confirm", "result"):
            with self.subTest(screen=name):
                state = golden_states()[name]
                whole = (install._plan_text(state) if state.screen == "plan"
                         else install._confirm_text(state) if state.screen == "confirm"
                         else install.tui_outcome(state)[1])
                shown = install._shown(state, whole)
                state.stack.append("details")
                told = install.details_lines(state)
                self.assertEqual(sorted(map(str, whole)),
                                 sorted(map(str, [*shown, *[line for line in told
                                                           if install._is_detail(line)]])))

    def test_verbose_draws_them_in_place_and_offers_no_row(self):
        state = checked_state()
        state.passthrough = [("--verbose", None)]
        text = self.text(state)
        self.assertIn("Free space: 50.0 GB", text)
        self.assertNotIn("details", [row.action for row in install.tui_rows(state)])

    def test_installing_lists_the_files_that_went_well_with_verbose(self):
        state = golden_states()["installing"]
        self.assertNotIn("gba_bios.bin", self.text(state))
        self.assertIn("FAILED scph5500.bin (HTTP 404)", self.text(state))
        state.passthrough = [("--verbose", None)]
        self.assertIn("ok     gba_bios.bin", self.text(state))


if __name__ == "__main__":
    unittest.main()
