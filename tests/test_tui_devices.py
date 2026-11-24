"""The device and emulator screens, the board registry and the app on a card."""

from __future__ import annotations

import tests

import contextlib
import io
import json
import os
import queue
import re
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import install
from tests.netguard import module_guard
from tests.tuisupport import (
    _app_card, _args, CHECK, checked_state, device_state, fresh_state, golden_states_result,
    in_full, _installed_state, MANIFEST, press, REPO_ROOT, result_states, SYSTEM_DIR, TARGETS,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_devices")


class TheSetupFilterKnowsDevices(unittest.TestCase):
    """The filter found nothing for steam deck, r36s,
    trimui or retroid, and miyoo found RetroArch with muOS, JELOS... beside it."""

    TYPED = {
        "steam deck": {"retroarch", "batocera", "emudeck", "retrodeck"},
        # MinUI and MyMinUI list their devices, and on
        # a computer an Android device is no RetroArch of this machine's.
        "r36s": {"retroarch", "rocknix", "myminui"},
        "rg35xx": {"retroarch", "rocknix", "knulli", "minui", "myminui"},
        "trimui": {"retroarch", "knulli", "minui", "nextui"},
        "retroid": {"rocknix", "knulli"},
        "miyoo": {"retroarch", "knulli", "minui", "myminui"},
        "anbernic": {"retroarch", "rocknix", "amberelec", "knulli", "minui", "myminui"},
        "odin": {"rocknix"},
        "ayn": {"retroarch", "rocknix"},
        "rp5": {"rocknix", "knulli"},
        "rog ally": {"retroarch", "emudeck", "retrobat", "bizhawk"},
        "onion": {"retroarch"},
    }

    def rows(self, needle: str) -> list:
        state = fresh_state()
        state.stack = ["platforms"]
        state.filters["platforms"] = needle
        return [row for row in install.tui_rows(state)
                if row.action in ("platform", "cardsystem")]

    def test_each_device_finds_every_setup_it_runs(self):
        for needle, setups in self.TYPED.items():
            with self.subTest(needle=needle):
                self.assertEqual({row.value[0] if row.action == "cardsystem" else row.value
                                  for row in self.rows(needle)}, setups)

    def test_the_right_column_names_what_matched(self):
        rows = self.rows("miyoo")
        # MiyooCFW stayed on the
        # RetroArch row, which opened this computer's folder.
        self.assertNotIn("retroarch", [row.value for row in rows if row.action == "platform"])
        self.assertEqual([row.label for row in rows if row.action == "cardsystem"],
                         ["Allium, SD card", "Koriki, SD card", "MiyooCFW, SD card",
                          "Onion, SD card", "spruceOS, SD card"])
        spruce = {row.label: row for row in rows}["spruceOS, SD card"]
        self.assertEqual(spruce.right, "Miyoo A30, Miyoo Flip, Miyoo Mini, Miyoo Mini Plus, "
                         "Miyoo Mini Flip")
        # Cut at a comma, never inside a name ("Miyoo ...s").
        self.assertIn("Miyoo A30, Miyoo Flip, +3", spruce.narrow)
        line = str(install._row_line(spruce, False, 60))
        self.assertTrue(line.rstrip().endswith(("+1", "+2", "+3", "+4")), line)
        deck = {row.value: row for row in self.rows("steam deck")}
        self.assertEqual(deck["retroarch"].right, "Steam Deck")
        self.assertEqual({row.value: row for row in self.rows("")}["retroarch"].right, "")

    def test_the_handheld_lists_are_the_guides(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("pyyaml is not installed")

        guides = yaml.safe_load((REPO_ROOT / "platforms" / "_guides.yml").read_text())
        for system in guides["handheld_guide"]["systems"]:
            if system.get("devices"):
                with self.subTest(system=system["name"]):
                    self.assertEqual(install._SETUP_DEVICES[system["name"]],
                                     tuple(str(name) for name in system["devices"]))


class AppOnTheCard(unittest.TestCase):
    """The RetroBIOS app offered on the result screen and in the options."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(install.OFFLINE_VARIABLE, None)

    def fields(self, card_root: Path, ok: bool = True) -> dict:
        return {"event": "app", "system": "muOS", "folder": str(card_root), "ok": ok,
                "reason": "" if ok else "it could not be downloaded: no connection",
                "dests": ["ARCHIVE/RetroBIOS.muxapp"],
                "written": ["ARCHIVE/RetroBIOS.muxapp"] if ok else [], "kept": []}

    def test_the_result_offers_it_and_exit_stays_the_default(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        rows = install.tui_rows(state)
        self.assertEqual([row.action for row in rows], ["exit", "addapp"])
        self.assertEqual(rows[1].label, install.APP_OFFER)
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn(install.APP_OFFER, screen)
        self.assertIn("A/Enter Exit", screen)
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.exit_code, 0)

    def test_choosing_it_puts_it_then_says_what_it_did(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        effects = press(state, "down", "enter")
        self.assertEqual(effects, [("app", install.card_app(bios))])
        self.assertTrue(state.app_running)
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("Putting RetroBIOS on the card...", screen)
        # Nothing ends the screen while the card is written.
        self.assertEqual(press(state, "enter", "esc"), [])
        self.assertIsNone(state.exit_code)
        install.tui_receive(state, ("app", self.fields(root)))
        self.assertEqual(install.tui_rows(state), [])
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("RetroBIOS is on the muOS card: 1 file written", screen)
        self.assertIn("Archive Manager", screen)
        self.assertIn("--add-app", install.tui_command(state))
        press(state, "enter")
        self.assertEqual(state.exit_code, 0)

    def test_a_failure_is_said_and_ends_on_1(self):
        root, bios = _app_card(self, "KNULLI")
        state = _installed_state(bios)
        press(state, "down", "enter")
        install.tui_receive(state, ("app", {**self.fields(root, ok=False), "system": "KNULLI"}))
        _title, lines = install.tui_outcome(state)
        self.assertTrue(any("could not be put on the KNULLI card" in line for line in lines))
        press(state, "enter")
        self.assertEqual(state.exit_code, 1)

    def test_space_and_b_never_put_it(self):
        _root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        self.assertEqual(press(state, "down", " "), [])
        self.assertFalse(state.app_running)
        press(state, "esc")
        self.assertEqual(state.exit_code, 0)

    def test_no_offer_where_it_cannot_go(self):
        _root, muos = _app_card(self, "muOS")
        _root, onion = _app_card(self, "Onion")
        cases = {
            "failed install": _installed_state(muos, 1, [{"dest": "a", "reason": "x"}]),
            "plain folder": _installed_state(SYSTEM_DIR),
            "no launcher": _installed_state(onion),
        }
        offline = _installed_state(muos)
        for name, state in cases.items():
            with self.subTest(case=name):
                self.assertEqual(install.tui_rows(state), [])
        offline.offline = True
        self.assertEqual(install.tui_rows(offline), [])
        _title, lines = install.tui_outcome(cases["no launcher"])
        self.assertIn(install.no_python_words("Onion"), lines)

    def test_put_by_the_install_itself_no_second_offer(self):
        root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        install._take_event(state, self.fields(root))
        self.assertEqual(install.tui_rows(state), [])
        self.assertIn("RetroBIOS is on the muOS card", "\n".join(install.tui_outcome(state)[1]))

    def test_the_options_row_sets_the_flag_of_the_install_only(self):
        _root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        state.stack = ["plan", "options"]
        rows = install.tui_rows(state)
        row = next(row for row in rows if row.action == "addapp")
        self.assertEqual((row.label, row.right), ("Put RetroBIOS on this card: no", "--add-app"))
        state.focus["options"] = rows.index(row)
        press(state, "enter")
        self.assertTrue(state.add_app)
        self.assertIn("--add-app", install.tui_argv(state, "install", "py", "install.py"))
        for run in ("check", "confirm", "preview"):
            self.assertNotIn("--add-app", install.tui_argv(state, run, "py", "install.py"))
        self.assertIn("--add-app", install.tui_command(state))
        press(state, "left")
        self.assertFalse(state.add_app)
        plain = _installed_state(SYSTEM_DIR)
        plain.stack = ["plan", "options"]
        self.assertFalse(any(row.action == "addapp" for row in install.tui_rows(plain)))

    def test_offline_on_the_screen_drops_the_flag_before_its_effect(self):
        _root, bios = _app_card(self, "muOS")
        state = _installed_state(bios)
        state.add_app = True
        with mock.patch.dict(os.environ):
            os.environ.pop(install.OFFLINE_VARIABLE, None)
            state.offline = True
            argv = install.tui_argv(state, "install", "py", "install.py")
        self.assertIn("--offline", argv)
        self.assertNotIn("--add-app", argv)

    def test_the_command_line_flag_ticks_the_row(self):
        _root, bios = _app_card(self, "ROCKNIX")
        state, _effects = install.tui_start(_args(add_app=True, platform="rocknix",
                                                  dest=bios), "linux", detect=False)
        self.assertTrue(state.add_app)


class OneDeviceRegistry(unittest.TestCase):
    """One device spelled
    several ways found one system, one press took it, MinUI listed brands."""

    def found(self, typed: str, os_type: str = "linux") -> set:
        return {row.value[1] if row.action == "cardsystem" else row.value
                for row in install.setup_list([], set(), typed, os_type)}

    def test_one_spelling_per_device(self):
        keys = {}
        for name in install._DEVICES:
            keys.setdefault(install._device_key(name), []).append(name)
        self.assertEqual({key: names for key, names in keys.items() if len(names) > 1}, {})
        for system, devices in install._SETUP_DEVICES.items():
            with self.subTest(system=system):
                self.assertEqual([name for name in devices if name not in install._DEVICES], [])

    def test_every_spelling_finds_every_system_that_runs_it(self):
        rk2023 = {"dArkOS", "ArkOS", "KOLOS", "JELOS", "rocknix"}
        cubexx = {"muOS", "knulli", "rocknix", "minui"}
        flip2 = {"knulli", "rocknix"}
        for typed, systems in (("Powkiddy RK2023", rk2023), ("RK2023", rk2023),
                               ("rk-2023", rk2023), ("RG CubeXX", cubexx),
                               ("RGCUBEXX", cubexx), ("Anbernic RG CubeXX", cubexx),
                               ("Retroid Pocket Flip 2", flip2), ("flip2", flip2)):
            with self.subTest(typed=typed):
                self.assertEqual(self.found(typed), systems)
        self.assertIn("ArkOS", self.found("Anbernic RG353V"))
        self.assertTrue({"Onion", "minui", "myminui", "Allium"} <= self.found("Miyoo Mini"))
        self.assertTrue({"Onion", "minui"} <= self.found("Miyoo Mini+"))
        self.assertIn("minui", self.found("TrimUI Brick"))
        self.assertIn("Anbernic stock firmware", self.found("rg35xx"))
        self.assertIn("JELOS", self.found("rgb10 max 3"))

    def test_android_is_this_machine_only_on_android(self):
        self.assertNotIn("retroarch", self.found("android"))
        self.assertNotIn("retroarch", self.found("retroid pocket 5"))
        self.assertIn("retroarch", self.found("android", "android"))

    def test_a_device_several_systems_run_is_never_taken_in_one_press(self):
        out = io.StringIO()
        with mock.patch.object(install, "_ask",
                               side_effect=["Powkiddy RK2023", "", "0", "35", "q"]), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            install._choose_platform("Which?", "retroarch")
        text = out.getvalue()
        self.assertIn("5 setups run on 'Powkiddy RK2023':", text)
        # Enter after the matches takes none, and 0 and 35 are numbers.
        self.assertEqual(text.count("Type a number from 1 to 34"), 3)
        self.assertNotIn("run on '0'", text)
        self.assertNotIn("run on '35'", text)

    def test_the_line_menu_is_the_screen_list_numbered(self):
        for setups in ([], [("retroarch", SYSTEM_DIR, "RetroArch")]):
            with self.subTest(found=bool(setups)):
                rows = install.setup_list(setups, set(), "", "linux")
                self.assertEqual([name for name, _label in install._line_setups(setups, None,
                                                                                 "linux")],
                                 [install._row_name(row) for row in rows])
        labels = dict(install._line_setups())
        self.assertIn("RG28XX", labels["minui"])
        self.assertNotIn("(Anbernic, Miyoo", labels["minui"])
        self.assertIn("RG35XX Plus", labels["Anbernic stock firmware"])
        self.assertNotIn("RetroArch files", labels["JELOS"])

    def test_forty_columns_keep_the_name_whole_and_a_device_count(self):
        rows = {row.label: row for row in install.setup_list([], set(), "", "linux")}
        for label in ("KNULLI, SD card", "ROCKNIX, SD card", "CrossMix-OS, SD card",
                      "AmberELEC, SD card", "JELOS, SD card"):
            with self.subTest(row=label):
                line = str(install._row_line(rows[label], False, 38))
                self.assertIn(label, line)
                self.assertTrue(line.rstrip() != ("  " + label).rstrip(), line)
        # its one device, cut, where "1 device" named none.
        self.assertTrue(str(install._row_line(rows["CrossMix-OS, SD card"], False, 38))
                        .rstrip().endswith("TrimUI Smar..."))


class TheAndroidResultReadsWhole(unittest.TestCase):
    """A run on Android 17 under Termux: the result named /sdcard and
    /storage/emulated/0 for one storage, saves/<core> read as a folder named
    <core>, a backup path and the restore command were split inside a word,
    and the game data line named no folder."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        for patcher in (mock.patch.dict(install._SPELLED, {}, clear=True),):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_one_storage_is_named_one_way(self):
        real = self.root / "storage" / "emulated" / "0"
        (real / "RetroArch" / "system").mkdir(parents=True)
        link = self.root / "sdcard"
        link.symlink_to(real)
        bios = link / "RetroArch" / "system"
        self.assertEqual(install._destination_path(bios, "a.bin"),
                         real.resolve() / "RetroArch" / "system" / "a.bin")
        kept = install.KeptFiles()
        run = kept.plan(install._kept_slot(bios, "a.bin")[0], 3)
        folder = kept.summary()[0]["folder"]
        self.assertTrue(folder.startswith(str(link / "RetroArch" / "retrobios-backup")),
                        folder)
        self.assertEqual(install.shown_path(run), folder)
        self.assertNotIn(str(real), install.shown_path(real.resolve() / "RetroArch" / "saves"))

    def test_a_folder_per_core_is_said_in_words(self):
        where = "/sdcard/RetroArch/saves/<core>"
        line = install.saves_line("RetroArch", 106, where)
        self.assertEqual(line, "106 files read from RetroArch's save directory go to a "
                               "folder per core under /sdcard/RetroArch/saves")
        self.assertEqual(install.save_where_words("/s/saves/<system>"),
                         ("a folder per system under", "/s/saves"))
        state = checked_state()
        screen = install._saves_lines(state, {"files": 106, "folder": where})
        self.assertNotIn("<core>", " ".join(screen))
        self.assertIn("a folder per core under:", screen[0])

    def result(self, cols: int) -> list:
        state = _installed_state(Path("/sdcard/RetroArch/system"))
        state.summary["kept"] = [{"folder": "/sdcard/RetroArch/retrobios-backup/"
                                            "20261027-223524", "files": 3, "bytes": 10}]
        state.cols, state.rows = cols, 40
        return install.tui_view(state, cols, 40)

    @in_full
    def test_a_path_or_a_command_is_never_split_inside_a_word(self):
        full = "/sdcard/RetroArch/retrobios-backup/20261027-223524"
        for cols in (40, 50, 80):
            with self.subTest(cols=cols):
                lines = [str(line).strip() for line in self.result(cols)]
                words = [word for line in lines for word in line.split()]
                self.assertIn("--restore", words)
                # The command keeps it whole where its line holds it, cut to
                # its last folders and said so where not.
                if cols >= 60:
                    self.assertIn(full, words)
                else:
                    self.assertIn(install.TUI_SHORTENED, lines)
                # Prose breaks it after a separator only, never inside a name:
                # glued again, it is whole.
                self.assertIn(full, re.sub(r"/ ", "/", " ".join(lines)))
                self.assertFalse(any(line.endswith(("retrobios-ba", "20261027-"))
                                     for line in lines), lines)
        state = _installed_state(Path("/sdcard/RetroArch/system"))
        command = install._styled(f"curl -fsSL {install.BOOTSTRAP_URL} | sh -s -- --restore "
                                  "'/storage/emulated/0/a b/20261027-223524'", "command")
        state.stack.append("result")
        pieces = install._text_lines([command], 38, whole=True)
        joined = [str(piece).strip() for piece in pieces if piece.style != "cont"]
        # The address never cut, the option with its value, each line but
        # the last ending with the shell's continuation.
        self.assertIn(f"{install.BOOTSTRAP_URL} \\", joined)
        self.assertTrue(any(line.startswith("--restore '") for line in joined), joined)
        self.assertTrue(all(len(str(piece)) <= 38 for piece in pieces), pieces)

    def test_a_long_line_folds_in_the_terminal(self):
        terminal = install._TuiTerminal.__new__(install._TuiTerminal)
        terminal.frame, written = [], []
        terminal.write = written.append
        long = install._styled("x" * 50, "long")
        terminal.draw([long, install._styled("", "cont"), install._styled("next")], 40)
        out = "".join(written)
        self.assertIn("x" * 50, out)
        self.assertNotIn("\x1b[2;1H", out)
        self.assertIn("\x1b[3;1H", out)

    def test_game_data_names_the_folder_it_goes_in(self):
        entry = {"dest": "jazz2/Source/Anims.j2a", "required": True, "category": "game_data",
                 "system": "jazz-jackrabbit-2"}
        bios = Path("/sdcard/RetroArch/system")
        lines = install._omission_lines(1, [entry], bios)
        said = " ".join(lines)
        self.assertIn(f"into {bios / 'jazz2' / 'Source'}{os.sep}", said)
        # Defined on its own line, never spliced into the sentence naming
        # the file.
        self.assertIn("files a game or a game engine reads", said)
        self.assertEqual([line for line in lines if "game engine reads" in line],
                         ["  Game data: files a game or a game engine reads, of no use to "
                          "the other cores."])
        self.assertNotIn("Needed to start an emulator", said)


class WhatToActOnStaysOnTheScreen(unittest.TestCase):
    """A failure, a file an emulator needs that the collection lacks, a
    remedy to choose: on the screen by default, never only on Details
    (review of 2026-11-10)."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def text(self, state: install.TuiState) -> str:
        return " ".join(" ".join(install.tui_view(state, 80, 24)).split())

    def test_a_failed_file_is_named_on_the_result_and_after_exit(self):
        state = golden_states_result()
        self.assertIn("failed: scph5500.bin (HTTP 404)", self.text(state))
        press(state, "enter")
        self.assertIn("failed: scph5500.bin (HTTP 404)", "\n".join(install.tui_farewell(state)))

    def needs(self, state: install.TuiState) -> install.TuiState:
        state.manifest = {**MANIFEST, "omitted_files": [
            {"dest": "lost.bin", "system": "sony-playstation", "required": True},
            {"dest": "spare.bin", "system": "sony-playstation", "required": False}]}
        return state

    def test_a_file_an_emulator_needs_is_counted_on_the_plan(self):
        state = self.needs(checked_state())
        said = "1 file an emulator needs is not available here (Details names it)."
        self.assertIn(said, self.text(state))
        press(state, "d")
        self.assertIn("lost.bin", self.text(state))
        # With --verbose the names are on the plan, and the count not again.
        state = self.needs(checked_state())
        state.passthrough = [("--verbose", None)]
        self.assertNotIn(said, self.text(state))
        self.assertIn("lost.bin", self.text(state))

    def test_a_file_an_emulator_needs_is_counted_on_the_result(self):
        state = self.needs(result_states()["done"])
        self.assertIn("1 file an emulator needs is not available here (Details names it).",
                      self.text(state))

    def test_the_save_folder_remedy_is_on_the_result(self):
        state = result_states()["done"]
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        state.summary["skipped"] = [{"reason": "no_save_directory", "files": 2}]
        text = self.text(state)
        self.assertIn("2 files read from RetroArch's save directory left out. "
                      f"{install.TUI_SAVE_REMEDY}", text)
        self.assertNotIn("Its place is not known.", text)
        press(state, "o")
        self.assertIn("Its place is not known.", self.text(state))

    def test_the_save_folder_remedy_is_on_the_plan(self):
        state = checked_state()
        state.manifest = {**MANIFEST, "save_directory": {"folder": "saves", "by_core": True}}
        state.check_summary = {"skipped": [{"reason": "no_save_directory", "files": 2}]}
        self.assertIn("Choose it in Change, Save folder (--save-dir).", self.text(state))

    def test_files_that_could_not_be_read_are_counted_where_no_row_says_so(self):
        unread = [{"event": "unreadable", "platform": "retroarch", "folder": "/media/OLD",
                   "path": "/media/OLD/scph5501.bin", "member": "",
                   "reason": "Permission denied"}]
        state = checked_state()
        state.unreadable = list(unread)
        # The plan's row names them: the count waits on Details.
        self.assertIn("Show the files that could not be read", self.text(state))
        # Everything in place: no row, the count on the plan.
        done = checked_state()
        done.check = {**CHECK, "present": 5, "missing": 0, "wrong_hash": 0,
                      "bytes_needed": 0, "not_installable": 0}
        done.unreadable = list(unread)
        self.assertNotIn("unreadable", [row.action for row in install.tui_rows(done)])
        self.assertIn("1 file in OLD could not be read.", self.text(done))

    def test_another_drive_to_add_is_said_on_the_plan(self):
        state = checked_state()
        state.scanned = [{"event": "scanned", "folder": "E:\\", "files": 200000,
                          "truncated": True, "other_drives": ["E:\\D"]}]
        text = self.text(state)
        self.assertIn("E:\\D is another drive: add it to copy from it too.", text)
        self.assertNotIn("Read the first", text)


class DeviceAndEmulatorScreens(unittest.TestCase):
    """Device chooses --target and --every-board, Emulators --emulator, and
    Change keeps every option one level below the plan, grouped by intent."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def text(self, state: install.TuiState, cols: int = 80, rows: int = 24) -> str:
        return "\n".join(str(line) for line in install.tui_view(state, cols, rows))

    def focus(self, state: install.TuiState, action: str, value: object = None) -> None:
        rows = install.tui_rows(state)
        state.focus[state.screen] = next(
            index for index, row in enumerate(rows)
            if row.action == action and (value is None or row.value == value))

    def test_change_groups_every_option_under_headings_focus_skips(self):
        state = checked_state()
        press(state, "o")
        rows = install.tui_rows(state)
        headings = [row.label for row in rows if row.action == "heading"]
        self.assertEqual(headings, list(install.TUI_CHANGE_GROUPS))
        self.assertNotEqual(rows[state.focus["options"]].action, "heading")
        flags = {row.right for row in rows if row.action != "heading"}
        for flag in ("--region", "--core", "--emulator", "--no-game-data", "--dest", "--from",
                     "--from-pack", "--target", "--installed-cores", "--jobs", "--offline",
                     "--dry-run"):
            self.assertIn(flag, flags)
        # Down and Up never stop on a heading, Home neither.
        for key in ("down",) * len(rows) + ("up",) * len(rows) + ("home", "end", "home"):
            press(state, key)
            self.assertNotEqual(install.tui_rows(state)[state.focus["options"]].action,
                                "heading", key)
        # Up on the first row stays: the list does not wrap past its heading.
        press(state, "home", "up")
        self.assertEqual(state.focus["options"], 1)
        # The plan's row and bar name the screen.
        plan = checked_state()
        self.assertIn("Change", [row.label for row in install.tui_rows(plan)])
        self.assertIn("Y/o Change", self.text(plan))

    def test_a_tap_on_a_heading_does_nothing(self):
        state = checked_state()
        press(state, "o")
        before = dict(state.focus)
        rows = install.tui_rows(state)
        index = next(i for i, row in enumerate(rows) if row.action == "heading")
        state.cols, state.rows = 80, 24
        state.hits = install.tui_hits(state, install.tui_view(state, 80, 24))
        number = next(target[0] for target in state.hits.targets
                      if target[3][:2] == ("row", index))
        state.now = state.hits.shown + 1
        install.tui_mouse(state, install.TuiMouse(0, 3, number + 1, False))
        self.assertEqual(install.tui_mouse(state, install.TuiMouse(0, 3, number + 1, True)), [])
        self.assertEqual(state.focus, before)

    def test_device_lists_the_card_board_first_and_chosen(self):
        state = device_state()
        self.assertEqual(state.screen, "device")
        rows = install.tui_rows(state)
        self.assertEqual([row.label for row in rows],
                         ["(x) h700", "( ) bcm2711", "( ) x86_64", "( ) Every board"])
        self.assertEqual(rows[0].right, "named by the card")
        self.assertEqual(rows[1].right, "rpi4")
        self.assertEqual(state.focus["device"], 0)
        # Chosen as it is: nothing to say on the command line.
        press(state, "enter")
        self.assertEqual(state.screen, "options")
        self.assertEqual([flag for flag in install.tui_flags(state)
                          if flag[0] in ("--target", "--every-board")], [])
        self.assertIn("Device: h700, named by the card", self.text(state))

    def test_on_the_device_itself_it_says_this_device(self):
        state = checked_state()
        state.board_seen = ("retroarch", state.dest, "bcm2711", True, True)
        state.stack.append("options")
        self.assertIn("Device: bcm2711, this device", self.text(state))

    def test_the_board_event_is_kept_across_checks(self):
        state = checked_state()
        state.run, state.running = "check", True
        install.tui_receive(state, ("event", state.run_id, {
            "event": "board", "platform": "retroarch", "board": "h700", "applied": True,
            "message": "Board h700 found on the card (--every-board installs all boards)"}))
        with mock.patch.object(install, "detect_board", return_value=None):
            self.assertEqual(install._board_seen(state)[:2], ("h700", True))
        install._start_run(state, "check")
        self.assertEqual(install._board_seen(state)[:2], ("h700", True))

    def test_another_board_and_every_board_set_their_flag(self):
        state = device_state()
        self.focus(state, "board", "bcm2711")
        press(state, "enter")
        self.assertIn(("--target", "bcm2711"), install.tui_flags(state))
        self.assertIn("--target=bcm2711", install.tui_argv(state, "install", "py", "i.py"))
        self.assertIn("Device: bcm2711", self.text(state))
        # Back on the plan, counted again for the board.
        self.assertEqual(press(state, "esc"), [("run", "check")])
        state = device_state()
        self.focus(state, "board", "")
        press(state, "enter")
        self.assertEqual([flag for flag in install.tui_flags(state)
                          if flag[0] in ("--target", "--every-board")],
                         [("--every-board", None)])
        self.assertIn("Device: every board", self.text(state))

    def test_with_no_board_read_every_board_is_the_choice(self):
        state = device_state(board="")
        self.assertEqual(install.tui_rows(state)[-1].label, "(x) Every board")
        self.assertEqual(state.focus["device"], 3)
        self.assertEqual([flag for flag in install.tui_flags(state)
                          if flag[0] in ("--target", "--every-board")], [])
        # Chosen, it is said: a card put in the reader later names none.
        press(state, "enter")
        self.assertEqual([flag for flag in install.tui_flags(state)
                          if flag[0] in ("--target", "--every-board")],
                         [("--every-board", None)])

    def test_a_board_list_that_cannot_be_read_is_said(self):
        state = checked_state()
        state.stack.append("options")
        self.focus(state, "device")
        press(state, "enter")
        self.assertIn("Reading the board list...", self.text(state))
        install.tui_receive(state, ("targets", "retroarch", None,
                                    "The board list could not be read."))
        self.assertIn("The board list could not be read.", self.text(state))
        self.assertEqual(press(state, "esc"), [])
        self.assertEqual(state.screen, "options")

    def test_the_command_line_choice_is_the_one_shown(self):
        args = _args(platform="retroarch", dest=SYSTEM_DIR, target="bcm2711",
                     emulator=["mesen"])
        state, _effects = install.tui_start(args, "linux", detect=False)
        self.assertEqual((state.target, state.emulators), ("bcm2711", ["mesen"]))
        self.assertNotIn("--target", [flag for flag, _value in state.passthrough])
        flags = install.tui_flags(state)
        self.assertIn(("--target", "bcm2711"), flags)
        self.assertIn(("--emulator", "mesen"), flags)

    def test_emulators_ticked_are_the_emulator_flags(self):
        state = checked_state()
        state.stack.append("options")
        self.focus(state, "emulators")
        press(state, "enter")
        self.assertEqual(state.screen, "emulators")
        rows = install.tui_rows(state)
        self.assertEqual([row.label for row in rows if row.action == "emulator"],
                         ["[ ] mesen", "[ ] pcsx_rearmed"])
        self.assertEqual(rows[state.focus["emulators"]].value, "mesen")
        press(state, " ")
        self.assertEqual(state.emulators, ["mesen"])
        self.assertIn(("--emulator", "mesen"), install.tui_flags(state))
        press(state, "n")
        self.assertEqual(state.emulators, [])
        press(state, " ", "esc")
        self.assertEqual(state.screen, "options")
        self.assertIn("Emulators: mesen", self.text(state))

    def test_without_the_internet_sets_offline_for_the_runs(self):
        state = checked_state()
        state.stack.append("options")
        self.focus(state, "offline")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(install.OFFLINE_VARIABLE, None)
            self.assertIn("Without the internet: no", self.text(state))
            self.assertEqual(press(state, "enter"), [("offline", True)])
            install.set_offline(True)
            self.assertIn("Without the internet: yes", self.text(state))
            self.assertIn(("--offline", None), install.tui_flags(state))
            self.assertEqual(press(state, "left"), [("offline", False)])
            install.set_offline(False)
            self.assertNotIn(("--offline", None), install.tui_flags(state))

    def test_from_a_pack_opens_the_browser_on_zips_and_reads_the_pack(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "Downloads").mkdir()
        pack = root / "Downloads" / "RetroArch_BIOS_Pack.zip"
        pack.write_bytes(b"PK")
        (root / "Downloads" / "notes.txt").write_text("x")
        state = checked_state()
        state.home = root
        state.stack.append("options")
        self.focus(state, "pack")
        press(state, "enter")
        self.assertEqual((state.screen, state.browse_for), ("browse", "pack"))
        rows = install.tui_rows(state)
        self.assertNotIn("use", [row.action for row in rows])
        self.assertEqual([row.label for row in rows if row.action == "zip"],
                         ["RetroArch_BIOS_Pack.zip"])
        self.focus(state, "zip")
        self.assertIn("A/Enter Use this pack", self.text(state))
        self.assertEqual(press(state, "enter"), [("pack", pack)])
        # Refused: said, the browser stays.
        install.tui_receive(state, ("pack_opened", pack, None, "Not a pack."))
        self.assertEqual(state.screen, "browse")
        self.assertIn("Not a pack.", self.text(state))
        opened = mock.Mock()
        effects = install.tui_receive(state, ("pack_opened", pack, opened, ""))
        self.assertEqual(effects, [("use_pack", opened), ("fetch", "retroarch")])
        self.assertEqual(state.packs, [pack])
        self.assertIn(("--from-pack", str(pack)), install.tui_flags(state))

    def test_open_tui_pack_refuses_another_platforms_pack(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        pack = root / "Batocera_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"platform": "batocera",
                                                          "files": []}))
        previous = install.LOCAL.pack
        opened, problem = install.open_tui_pack(pack, "retroarch")
        self.assertIs(install.LOCAL.pack, previous)
        self.assertIsNone(opened)
        self.assertTrue(problem)


class DeviceAndEmulatorReview(unittest.TestCase):
    """The review of 2026-11-11: each finding, held."""

    def setUp(self):
        patcher = mock.patch.object(install, "_mounted_cards", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def focus(state: install.TuiState, action: str, value: object = None) -> None:
        rows = install.tui_rows(state)
        state.focus[state.screen] = next(
            index for index, row in enumerate(rows)
            if row.action == action and (value is None or row.value == value))

    def text(self, state: install.TuiState) -> str:
        return "\n".join(str(line) for line in install.tui_view(state, 80, 24))

    def test_every_board_is_said_whatever_the_run_started_with(self):
        for start in ({"target": "bcm2711"}, {"every_board": True}, {}):
            with self.subTest(start=start):
                state = device_state(board="")
                state.target = start.get("target", "")
                state.every_board = start.get("every_board", False)
                self.focus(state, "board", "")
                press(state, "enter")
                self.assertEqual([flag for flag in install.tui_flags(state)
                                  if flag[0] in ("--target", "--every-board")],
                                 [("--every-board", None)])
        # The board the run reads itself clears both.
        state = device_state()
        state.every_board = True
        self.focus(state, "board", "h700")
        press(state, "enter")
        self.assertEqual((state.target, state.every_board), ("", False))

    def test_a_board_list_that_failed_is_fetched_again(self):
        state = checked_state()
        state.stack.append("options")
        self.focus(state, "device")
        self.assertEqual(press(state, "enter"), [("targets", "retroarch")])
        install.tui_receive(state, ("targets", "retroarch", None,
                                    "The board list could not be read."))
        self.assertIn("The board list could not be read.", self.text(state))
        press(state, "esc")
        self.assertEqual(press(state, "enter"), [("targets", "retroarch")])
        self.assertIn("Reading the board list...", self.text(state))

    def test_a_pack_is_read_only_once_the_screen_takes_it(self):
        state = checked_state()
        state.stack += ["options", "browse"]
        state.browse_for = "pack"
        pack = mock.Mock()
        effects = install.tui_receive(state, ("pack_opened", Path("p.zip"), pack, ""))
        self.assertEqual(effects[0], ("use_pack", pack))
        # Left before it opened: closed, never read.
        state = checked_state()
        effects = install.tui_receive(state, ("pack_opened", Path("p.zip"), pack, ""))
        self.assertEqual(effects, [("close_pack", pack)])
        self.assertEqual(state.packs, [])

    def test_open_tui_pack_leaves_the_run_s_pack_alone(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        pack = root / "RetroArch_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "platform": "retroarch", "files": [
                    {"dest": "a.bin", "path": "a.bin", "sha1": "0" * 40, "size": 1}]}))
            archive.writestr("a.bin", b"a")
        previous = install.LOCAL.pack
        opened, problem = install.open_tui_pack(pack, "retroarch")
        self.addCleanup(lambda: opened is not None and opened.close())
        self.assertEqual(problem, "", problem)
        self.assertIsNotNone(opened)
        self.assertIs(install.LOCAL.pack, previous)

    def test_a_zip_that_is_no_pack_is_closed(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        notpack = root / "photos.zip"
        with zipfile.ZipFile(notpack, "w") as archive:
            archive.writestr("a.jpg", b"x")
        opened = []
        real = zipfile.ZipFile

        def tracked(*args, **kwargs):
            archive = real(*args, **kwargs)
            opened.append(archive)
            return archive

        with mock.patch.object(install.zipfile, "ZipFile", side_effect=tracked), self.assertRaises(ValueError):
            install.PackSource([notpack])
        self.assertTrue(opened)
        self.assertTrue(all(archive.fp is None for archive in opened))

    def test_another_setup_drops_the_board_and_emulators(self):
        state = checked_state()
        state.target, state.every_board, state.emulators = "bcm2711", False, ["mesen"]
        install._set_platform(state, "batocera")
        self.assertEqual((state.target, state.every_board, state.emulators),
                         ("", False, []))
        state = checked_state()
        state.target, state.emulators = "bcm2711", ["mesen"]
        install._set_platform(state, "retroarch")
        self.assertEqual((state.target, state.emulators), ("bcm2711", ["mesen"]))

    def test_names_the_new_list_lacks_are_left_out_and_said(self):
        state = checked_state()
        state.emulators, state.target = ["mesen", "gone_core"], "nowhere"
        state.targets, state.targets_for = dict(TARGETS), "retroarch"
        install._known_choice(state, "retroarch", MANIFEST)
        self.assertEqual((state.emulators, state.target), (["mesen"], ""))
        self.assertEqual(state.status, "Left out, not in this list: --emulator gone_core, "
                                       "--target nowhere.")

    def test_page_up_and_home_never_rest_on_a_heading(self):
        state = checked_state()
        press(state, "o")
        rows = install.tui_rows(state)
        for start in (1, 6, len(rows) - 1):
            for key in ("pgup", "home"):
                with self.subTest(start=start, key=key):
                    state.focus["options"] = start
                    press(state, key)
                    self.assertEqual(state.focus["options"], 1)

    def test_offline_is_refused_for_a_target_with_no_board_list_held(self):
        state = checked_state()
        state.target = "bcm2711"
        state.stack.append("options")
        self.focus(state, "offline")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(install.OFFLINE_VARIABLE, None)
            self.assertEqual(press(state, "enter"), [])
            self.assertIn("Open Device once first", self.text(state))
            state.targets, state.targets_for = dict(TARGETS), "retroarch"
            self.assertEqual(press(state, "enter"), [("offline", True)])

    def test_the_board_list_is_fetched_once_with_the_list_s_timeout(self):
        inbox: queue.Queue = queue.Queue()
        with mock.patch.object(install, "_fetch_json", return_value={}) as fetched, \
                mock.patch.object(install, "held_targets", return_value=None):
            install._tui_fetch_targets("retroarch", inbox)
        self.assertEqual(fetched.call_args.kwargs["attempts"], 1)
        self.assertEqual(fetched.call_args.kwargs["timeout"], install.TUI_FETCH_TIMEOUT)
        self.assertEqual(inbox.get_nowait(), ("targets", "retroarch", {}, ""))

    def test_a_board_list_refused_is_said_in_the_screen_s_words(self):
        """The screen showed the terminal line, "Error:" prefix and urllib
        text included: "...: Error: failed to fetch targets for batocera:
        HTTP Error 500: Internal Server Error"."""
        inbox: queue.Queue = queue.Queue()
        refused = install.urllib.error.HTTPError("u", 500, "Internal Server Error", {}, None)
        with mock.patch.object(install, "_fetch_json", side_effect=refused), \
                mock.patch.object(install, "held_targets", return_value=None), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            install._tui_fetch_targets("batocera", inbox)
        self.assertEqual(inbox.get_nowait(), (
            "targets", "batocera", None,
            "The board list could not be read: the server answered HTTP 500."))
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
