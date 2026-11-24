"""The full screen's model: how it moves from screen to screen, its widgets, the
warnings of a plan and the text that fits."""

from __future__ import annotations

import tests

import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import install
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, CHECK, checked_state, FILES, fresh_state, HOME, Key, listed, MANIFEST, option_focus,
    PLAN, press, REPO_ROOT, SYSTEM_DIR,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_flow")


class Flow(unittest.TestCase):
    """update() on keys and events: what each choice starts and passes on."""

    def test_three_presses_install_everything(self):
        state = checked_state()
        self.assertEqual(state.screen, "plan")
        self.assertEqual(press(state, "enter"), [("run", "install")])
        self.assertEqual(state.screen, "installing")
        argv = install.tui_argv(state, "install", "py", "install.py")
        self.assertEqual(argv, ["py", "install.py", "--platform=retroarch",
                                f"--dest={SYSTEM_DIR}", "--events", "--yes"])
        for event in ({"event": "download", "platform": "retroarch", "files": 4,
                       "bytes": 1064964},
                      {"event": "downloaded", "dest": "gba_bios.bin", "ok": True, "reason": "",
                       "size": 16384, "files_done": 1, "files_total": 4,
                       "bytes_done": 16384, "bytes_total": 1064964},
                      {"event": "summary", "mode": "install", "installed": 4, "up_to_date": 1,
                       "pending": 0, "failed": [], "skipped": [], "left_out": [],
                       "kept": [], "interrupted": False}):
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(state.screen, "result")
        press(state, "enter")
        self.assertEqual(state.exit_code, 0)

    def test_every_run_reads_the_folders_given_with_from(self):
        """--tui --from OLD: the check and the install both copy from OLD,
        each folder named once."""
        args = _args(**{"from": [Path("old-card"), Path("backup.zip")],
                        "from_pack": [Path("pack.zip")]})
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            started, _effects = install.tui_start(args, "linux")
        state = checked_state()
        state.passthrough = started.passthrough
        state.from_folders = started.from_folders
        state.packs = started.packs
        for run in ("check", "install"):
            argv = install.tui_argv(state, run, "py", "i.py")
            for folder in ("old-card", "backup.zip"):
                self.assertEqual(argv.count(f"--from={Path(folder).absolute()}"), 1, argv)
            self.assertIn(f"--from-pack={Path('pack.zip').absolute()}", argv)

    def test_the_check_runs_with_the_command_line_choices(self):
        state = fresh_state()
        state.passthrough = [("--target", "switch")]
        state.cli_systems = ["psx"]
        state.regions = ["north-america"]
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        self.assertEqual(install._start_check(state), [("run", "check")])
        self.assertEqual(install.tui_argv(state, "check", "py", "i.py")[4:], [
            "--target=switch", "--system=psx", "--region=north-america",
            "--check", "--events"])

    def test_one_system_goes_through_the_dry_run(self):
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        self.assertEqual(state.ticked, {"nintendo-gba", "sony-playstation"})
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        press(state, "n")
        self.assertEqual(state.ticked, set())
        focus = next(i for i, row in enumerate(install.tui_rows(state))
                     if row.value == "nintendo-gba")
        state.focus["systems"] = focus
        # A ticks the system in focus, B goes back to the plan, and Install
        # there counts the choice first.
        self.assertEqual(press(state, "enter", "esc"), [])
        self.assertEqual(state.ticked, {"nintendo-gba"})
        self.assertEqual(state.screen, "plan")
        self.assertEqual(press(state, "enter"), [("run", "confirm")])
        self.assertEqual(state.screen, "confirm")
        self.assertIn("--system=nintendo-gba", install.tui_argv(state, "confirm", "py", "i.py"))
        self.assertIn("--dry-run", install.tui_argv(state, "confirm", "py", "i.py"))
        dry = {**CHECK, "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
               "bytes_needed": 16384}
        install.tui_receive(state, ("event", state.run_id, dry))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(press(state, "enter"), [("run", "install")])
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertEqual(argv[4:], ["--system=nintendo-gba", "--events", "--yes"])

    def test_a_choice_that_changes_nothing_skips_the_confirmation(self):
        state = checked_state()
        state.jobs = 4
        self.assertEqual(press(state, "enter"), [("run", "confirm")])
        install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
        effects = install.tui_receive(state, ("ended", state.run_id, 0, []))
        self.assertEqual(effects, [("run", "install")])
        self.assertEqual(state.screen, "installing")

    def test_options_set_the_flags_they_name(self):
        state = checked_state()
        press(state, "o")
        self.assertEqual(state.screen, "options")
        rows = install.tui_rows(state)
        # Grouped by what each decides, a heading above each group.
        self.assertEqual([row.right or row.label for row in rows], [
            "What to install", "--region", "--core", "--emulator", "--no-game-data",
            "Where", "--dest", "--from", "--from-pack",
            "For which device", "--target", "--installed-cores",
            "How", "--offline", "--jobs", "See", "--dry-run", "Show the command line"])
        press(state, "enter")
        self.assertEqual(state.screen, "regions")
        # Ticked in the order of preference, then moved up.
        regions = [row.value for row in install.tui_rows(state) if row.action == "region"]
        self.assertEqual(regions, ["japan", "north-america"])
        press(state, "enter", "down", "enter")
        self.assertEqual(state.regions, ["japan", "north-america"])
        press(state, "left")
        self.assertEqual(state.regions, ["north-america", "japan"])
        # The rank moves, the row stays where it is, under the focus.
        self.assertEqual(state.focus["regions"], 1)
        self.assertEqual([row.label for row in install.tui_rows(state)],
                         ["[2] Japan", "[1] North America", "None", "Done"])
        press(state, "shift-down")
        self.assertEqual(state.regions, ["japan", "north-america"])
        # Down passes the headings: Game data, Installed cores only, then
        # Parallel downloads.
        press(state, "esc", "down", "down", "down", "enter", *["down"] * 5, "right",
              "down", "down", "right", "right")
        self.assertTrue(state.no_game_data)
        self.assertTrue(state.installed_only)
        self.assertEqual(state.jobs, 10)
        argv = install.tui_argv(state, "install", "py", "i.py")
        self.assertEqual(argv[4:], ["--region=japan,north-america", "--no-game-data",
                                    "--installed-cores", "--jobs=10", "--events", "--yes"])
        self.assertIn("--region japan,north-america --no-game-data", install.tui_command(state))

    def test_cores_checklist(self):
        state = checked_state()
        press(state, "o")
        option_focus(state, "cores")
        press(state, "enter")
        self.assertEqual(state.screen, "cores")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["mesen", "pcsx_rearmed"])
        self.assertEqual(install.tui_rows(state)[state.focus["cores"]].value, "mesen")
        # Every core ticked while none narrows the run: one untick keeps
        # the others, ticked back it is every core again.
        press(state, " ")
        self.assertEqual(state.cores, ["pcsx_rearmed"])
        press(state, "right")
        self.assertEqual(state.cores, [])
        press(state, "/", "p", "c")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "core"], ["pcsx_rearmed"])
        # Enter ends the typing on the first match, Left unticks it, and B
        # clears the filter, then leaves.
        press(state, "enter", "left", "esc", "esc")
        self.assertEqual(state.screen, "options")
        self.assertEqual(install.tui_flags(state), [("--core", "mesen")])

    def test_preview_is_a_dry_run(self):
        state = checked_state()
        press(state, "o")
        option_focus(state, "preview")
        self.assertEqual(press(state, "enter"), [("run", "preview")])
        self.assertEqual(install.tui_argv(state, "preview", "py", "i.py")[-2:],
                         ["--dry-run", "--events"])
        for event in [*FILES, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        install.tui_receive(state, ("ended", state.run_id, 0, []))
        text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("4 files to download, 1.0 MB. Nothing is written.", text)
        self.assertIn("wrong copy", text)
        press(state, "esc")
        self.assertEqual(state.screen, "options")

    def test_back_and_quit(self):
        state = fresh_state()
        press(state, "esc")
        self.assertEqual(state.screen, "quit")
        press(state, "esc")
        self.assertEqual(state.screen, "setup")
        press(state, "esc", "enter")
        self.assertEqual(state.exit_code, install.QUIT_CODE)
        state = checked_state()
        self.assertEqual(press(state, "q"), [])
        self.assertEqual(state.exit_code, install.QUIT_CODE)

    def test_ctrl_c_stops_an_install_once_then_kills(self):
        state = checked_state()
        press(state, "enter")
        self.assertEqual(press(state, "ctrl-c"), [("stop",)])
        self.assertTrue(state.stopping)
        self.assertEqual(press(state, "ctrl-c"), [("kill",)])
        summary = {"event": "summary", "mode": "install", "installed": 1, "up_to_date": 1,
                   "pending": 3, "failed": [], "skipped": [], "left_out": [], "kept": [],
                   "interrupted": True}
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "download", "platform": "retroarch",
                                     "files": 4, "bytes": 1064964}))
        install.tui_receive(state, ("event", state.run_id, summary))
        install.tui_receive(state, ("ended", state.run_id, 130, []))
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Stopped")
        self.assertEqual(lines[0], "Stopped: 1 of 4 installed, run again to finish.")
        press(state, "enter")
        self.assertEqual(state.exit_code, 130)

    def test_back_from_the_check_stops_it(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, ("manifest", "retroarch", MANIFEST))
        self.assertTrue(state.running)
        self.assertEqual(press(state, "esc"), [("kill",)])
        self.assertEqual(state.screen, "setup")
        install.tui_receive(state, ("ended", state.run_id - 1, 1, []))
        self.assertEqual(state.screen, "setup")

    def test_ctrl_c_elsewhere_ends_at_once(self):
        state = fresh_state()
        self.assertEqual(press(state, "ctrl-c"), [])
        self.assertEqual(state.exit_code, 130)
        state = checked_state()
        state.running = True
        self.assertEqual(press(state, "ctrl-d"), [("kill",)])

    def test_the_folder_path(self):
        state = fresh_state()
        press(state, "down", "down", "enter")
        self.assertEqual(state.screen, "platforms")
        self.assertEqual(install.tui_rows(state)[state.focus["platforms"]].value, "retroarch")
        press(state, "/", "b", "a", "t", "o")
        self.assertEqual([row.value for row in install.tui_rows(state)][1:], ["batocera"])
        # the one match is chosen with the first Enter.
        press(state, "enter")
        self.assertEqual(state.screen, "folder")
        self.assertEqual(state.platform, "batocera")
        state.focus["folder"] = 2
        press(state, "enter")
        self.assertEqual(state.screen, "path")
        state.path_text = ""
        press(state, "paste")
        install.tui_update(state, Key("paste", '"~/my bios"'))
        # Two missing levels are asked, Choose another folder in focus.
        with mock.patch.object(install, "missing_folder",
                               return_value=install.MissingFolder(HOME, 2, "ask")):
            press(state, "enter")
        self.assertEqual(state.screen, "create")
        self.assertEqual(state.dest, Path(os.path.expanduser("~/my bios")))
        press(state, "enter")
        self.assertEqual(state.screen, "folder")

    def test_typed_paths(self):
        with mock.patch.dict(os.environ, {"CARD": "/media/sd"}):
            self.assertEqual(install.typed_path(' "$CARD/Bios" '), Path("/media/sd/Bios"))
        self.assertEqual(install.typed_path("'C:\\RetroBat\\bios'"), Path("C:\\RetroBat\\bios"))
        self.assertIsNone(install.typed_path('""'))

    def test_the_browser_lists_folders_and_goes_up(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for name in ("system", ".config", "Bios"):
            (root / name).mkdir()
        (root / "file.bin").write_bytes(b"")
        state = fresh_state()
        state.platform = "retroarch"
        state.stack = ["folder"]
        state.folder_default = root / "system"
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "down", "enter")
            self.assertEqual(state.screen, "browse")
            self.assertEqual(state.browse_dir, root / "system")
            self.assertEqual([row.label for row in install.tui_rows(state)],
                             ["Use this folder", ".."])
            press(state, "down", "enter")
            self.assertEqual(state.browse_dir, root)
            labels = [row.label for row in install.tui_rows(state)]
            self.assertEqual(labels, ["Use this folder", "..", "Bios/", "system/", ".config/"])
            self.assertEqual(install.tui_rows(state)[state.focus["browse"]].label, "system/")
            effects = press(state, "home", "enter")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, root)

    def test_a_holds_no_bios_folder_root_never_takes_a(self):
        """With no usual folder the browser opens at HOME, on Use this
        folder: A five times installed the BIOS files into ~. At HOME or a
        drive's root, A goes into the first folder instead."""
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        (home / "Games").mkdir()
        state = install.TuiState(os_type="linux", home=home)
        state.platform = "retroarch"
        state.stack = ["folder"]
        state.folder_default = None
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._browse_to(state, home)
            self.assertEqual(state.browse_rows[state.focus["browse"]].label, "Games/")
            install._browse_to(state, home / "Games")
            self.assertEqual(state.browse_rows[state.focus["browse"]].label,
                             "Use this folder")
            install._browse_to(state, Path(home.anchor))
            self.assertNotEqual(state.browse_rows[state.focus["browse"]].action, "use")

    def test_cards_are_listed_first(self):
        card = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("NextUI-20250101\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]):
            rows, error = install._browse_rows(REPO_ROOT / "tests")
        self.assertEqual(error, "")
        self.assertEqual(rows[2].label, f"{card} (NextUI card)")

    def test_a_mounted_card_is_a_setup_of_its_own(self):
        card = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, card, True)
        (card / ".system").mkdir()
        (card / ".system" / "version.txt").write_text("MinUI-20250101\n")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(), "linux")
        # The one setup found: its plan first, the list one Back away.
        self.assertEqual((state.screen, effects), ("checking", [("fetch", "minui")]))
        self.assertEqual(listed(state).screen, "setup")
        label = f"MinUI SD card ({card.name})"
        self.assertEqual(state.setups, [("minui", card, label)])
        self.assertEqual([row.label for row in install.tui_rows(state)],
                         [label, "Another setup or folder"])

    def test_an_error_offers_another_try(self):
        state = fresh_state()
        with mock.patch.object(install.Path, "exists", return_value=True):
            press(state, "enter")
        install.tui_receive(state, ("manifest_failed", "retroarch", "No connection",
                                    ["  Could not fetch the file list for retroarch", ""], 1))
        self.assertIn("RetroBIOS: No connection", install.tui_view(state, 80, 24)[0])
        self.assertEqual(state.screen, "error")
        self.assertEqual([row.action for row in install.tui_rows(state)],
                         ["retry", "elsewhere", "quit"])
        self.assertEqual(press(state, "enter"), [("fetch", "retroarch")])
        install.tui_receive(state, ("manifest_failed", "retroarch", "No connection", ["no"], 1))
        press(state, "down", "down", "enter")
        self.assertEqual(state.exit_code, 1)

    def test_a_check_that_writes_no_check_event_is_an_error(self):
        state = fresh_state()
        state.platform, state.dest = "retroarch", SYSTEM_DIR
        state.manifest, state.manifest_for = MANIFEST, "retroarch"
        install._start_check(state)
        install.tui_receive(state, ("ended", state.run_id, 1,
                                    ["Error: /x is inside a NextUI card."]))
        self.assertEqual(state.screen, "error")
        self.assertEqual(state.error, ["Error: /x is inside a NextUI card."])

    def test_events_of_an_abandoned_run_are_ignored(self):
        state = checked_state()
        press(state, "o")
        option_focus(state, "preview")
        press(state, "enter")
        old = state.run_id
        self.assertEqual(press(state, "esc"), [("kill",)])
        install.tui_receive(state, ("event", old, dict(CHECK)))
        install.tui_receive(state, ("ended", old, 0, []))
        self.assertIsNone(state.dry)
        self.assertEqual(state.screen, "options")

    def test_help_and_a_small_window(self):
        state = fresh_state()
        press(state, "?")
        self.assertTrue(state.help)
        self.assertIn("Any key closes", install.tui_view(state, 80, 24)[-1])
        press(state, "down")
        self.assertFalse(state.help)
        self.assertEqual(state.focus.get("setup", 0), 0)
        state.cols, state.rows = 30, 10
        press(state, "enter")
        self.assertEqual(state.screen, "setup")
        lines = install.tui_view(state, 30, 10)
        self.assertEqual([line.strip() for line in lines if line.strip()],
                         ["Make the window larger:", "40x12 or more, now 30x10"])
        self.assertEqual(len(install.tui_view(state, 39, 1)), 1)
        self.assertEqual(install.tui_view(state, 30, 0), [])


class PlanWarnings(unittest.TestCase):
    def test_a_folder_that_cannot_take_the_files_says_so_first(self):
        state = checked_state({"free": 1024, "writable": False, "cores": []})
        text = " ".join(install.tui_view(state, 120, 40))
        self.assertIn("Not enough free space: 1.0 MB needed.", text)
        self.assertIn("This folder cannot be written to: choose another one.", text)
        # sudo changes the home folder: the advice names this one.
        self.assertIn("Or run it as root, this folder named: sudo python3 install.py "
                      f"--platform retroarch --dest {SYSTEM_DIR}",
                      " ".join(text.replace(" \\", "").split()))
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows[:2]], ["folder", "install"])
        self.assertEqual(state.focus.get("plan", 0), 0)
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "folder")
        self.assertNotIn("--installed-cores", [row.right for row in install._option_rows(state)])


class Widgets(unittest.TestCase):
    def systems_state(self, count: int) -> install.TuiState:
        state = checked_state()
        state.systems = [{"event": "system", "system": f"system-{n:03d}", "name": f"s{n}",
                          "files": 1, "present": 0, "missing": 1, "wrong_hash": 0,
                          "bytes_needed": 10} for n in range(count)]
        state.ticked = {row["system"] for row in state.systems}
        state.stack.append("systems")
        return state

    def test_a_long_list_scrolls_and_says_where(self):
        state = self.systems_state(112)
        press(state, "end")
        lines = install.tui_view(state, 40, 15)
        self.assertIn("> Done", "\n".join(lines))
        self.assertIn("[x] system-111", "\n".join(lines))
        # The Filter, All, None and Done rows are not counted among the systems.
        self.assertTrue(any(re.fullmatch(r" \d+-112 of 112", line) for line in lines), lines)
        press(state, "pgup")
        self.assertLess(state.focus["systems"], 114)
        press(state, "home")
        self.assertEqual(state.focus["systems"], 0)

    def test_up_wraps_only_in_short_menus(self):
        state = fresh_state()
        press(state, "up")
        self.assertEqual(state.focus["setup"], 2)
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        press(state, "up")
        self.assertEqual(state.focus["platforms"], 0)
        # A list of ticks wraps at any length: None and Done, at its end,
        # are a few presses up from its first item.
        state = self.systems_state(20)
        state.focus["systems"] = 0
        press(state, "up")
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "done")

    def test_filter_ignores_case_and_accents(self):
        state = self.systems_state(3)
        state.systems.append({"system": "sega-genesis", "name": "Mégadrive", "files": 1,
                              "present": 0, "missing": 1, "wrong_hash": 0,
                              "bytes_needed": 3})
        press(state, "/", "M", "E", "G")
        self.assertEqual([row.value for row in install.tui_rows(state)
                          if row.action == "system"], ["sega-genesis"])
        press(state, "esc")
        self.assertEqual(state.filters["systems"], "")
        self.assertEqual(state.screen, "systems")
        press(state, "/", "z", "z", "enter")
        self.assertIn("No system matches 'zz'.", "\n".join(install.tui_view(state, 80, 24)))
        # Esc clears a kept filter first, and goes back only then.
        press(state, "esc")
        self.assertEqual((state.screen, state.filters["systems"]), ("systems", ""))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_all_and_none(self):
        state = self.systems_state(5)
        press(state, "n")
        self.assertEqual(state.ticked, set())
        press(state, "a")
        self.assertEqual(len(state.ticked), 5)
        state.focus["systems"] = next(i for i, row in enumerate(install.tui_rows(state))
                                      if row.action == "none")
        # X on None does nothing: only A, an explicit choice, unticks all.
        press(state, " ")
        self.assertEqual(len(state.ticked), 5)
        press(state, "enter")
        self.assertEqual(state.ticked, set())

    def test_running_total_counts_each_file_once(self):
        state = checked_state()
        state.stack.append("systems")
        state.files.append({"event": "file", "dest": "shared.bin", "size": 1024 * 1024,
                            "systems": ["nintendo-gba", "sony-playstation"],
                            "state": "missing"})
        footer = install.tui_view(state, 80, 24)[-2]
        self.assertEqual(footer.strip(), "2 of 3 systems: 5 files, 2.0 MB")
        state.ticked = {"nintendo-gba"}
        footer = install.tui_view(state, 80, 24)[-2]
        self.assertEqual(footer.strip(), "1 of 3 systems: 2 files, 1.0 MB")


class TextThatFits(unittest.TestCase):
    """A pack's name cut in a
    command, folder lines at two indents, the 40x12 plan dropping the
    version note, and the --from plan without its kinds."""

    def test_a_pack_path_keeps_its_name_whole(self):
        pack = "/home/user/Downloads/RetroArch_BIOS_Pack.zip"
        text = ("curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform "
                f"retroarch --dest /media/moi/ONION/BIOS --from-pack {pack} --offline")
        for width in (38, 50, 78):
            with self.subTest(width=width), \
                    mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "sh"}):
                lines = install._command_wrap(text, width)
                joined = " ".join(lines)
                self.assertIn("RetroArch_BIOS_Pack.zip", joined)
                self.assertNotRegex(joined, r"\.\.\.[^/ ]*Pack\.zip")
                for line in lines:
                    self.assertLessEqual(install.cell_width(line), width, line)

    def test_a_folder_on_its_own_line_keeps_one_indent(self):
        base = "/home/me/very/long/folder/names/for/an/android/storage/RetroArch"
        items = [f"BIOS folder: {base}/system",
                 "1 file read from RetroArch's save directory goes to a folder per core:",
                 f"  {base}/saves"]
        for width in (38, 70, 78):
            for whole in (False, True):
                with self.subTest(width=width, whole=whole):
                    lines = [str(line) for line in install._text_lines(items, width, whole)]
                    folders = [line for line in lines if "/" in line
                               and not line.startswith("BIOS folder:")]
                    self.assertTrue(folders)
                    for line in folders:
                        self.assertEqual(len(line) - len(line.lstrip(" ")), 2, lines)

    def test_the_40x12_plan_keeps_the_version_note(self):
        state = checked_state()
        state.dest = Path("/home/moi/retroarch_system/tmp/tui_audit15/rb2/bios")
        install.tui_receive(state, ("event", state.run_id, {
            "event": "version", "platform": "retroarch", "list_version": "1.22.2",
            "installed_version": "1.21.0",
            "message": "This list was built for RetroArch 1.22.2, this machine runs 1.21.0. "
                       "Some files may differ from what this version reads."}))
        state.run = "check"
        narrow = " ".join(" ".join(str(line).split())
                          for line in install.tui_view(state, 40, 12))
        self.assertIn("List for RetroArch 1.22.2, this is 1.21.0.", narrow)
        self.assertIn("BIOS folder:", narrow)
        wide = " ".join(" ".join(str(line).split()) for line in install.tui_view(state, 80, 24))
        self.assertIn("This list was built for RetroArch 1.22.2, this machine runs 1.21.0.", wide)


if __name__ == "__main__":
    unittest.main()
