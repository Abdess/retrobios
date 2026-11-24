"""A card's space, the confirmation before writing, the card rows and a long
system list walked with a pad."""

from __future__ import annotations

import tests

import contextlib
import io
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

import install
from tests.installsupport import FakeRepository, make_card
from tests.netguard import module_guard
from tests.tuisupport import (
    _args, CHECK, checked_state, FILES, found, fresh_state, HOME, in_full, install_run, Key, listed,
    MANIFEST, PLAN, planned, press, REPO_ROOT, reported, screen_text, SYSTEM_DIR, SYSTEMS,
    urllib_error,
)


# No connection off the loopback and no card of the host reaches a test,
# in this process or one it starts: the module fails at its end when one is tried.
setUpModule, tearDownModule = module_guard("test_tui_card_space")


class HoldingPack:
    """A pack given to the run that holds every file asked of it."""

    name = "RetroArch_BIOS_Pack.zip"

    @staticmethod
    def find(entry: dict) -> tuple:
        return (None, entry)


class CardsSpaceAndConfirm(unittest.TestCase):
    """Each card by its own files, Space on install, and a short card."""

    CARDS = {
        "muOS": ({"MUOS/": ""}, "retroarch", "MUOS/bios"),
        "Onion": ({".tmp_update/onionVersion/version.txt": "4.3.1\n"}, "retroarch", "BIOS"),
        "spruceOS": ({"spruce/": ""}, "retroarch", "BIOS"),
        "KNULLI": ({"system/batocera.conf": "a=1\nsystem.hostname=KNULLI\n"}, "knulli",
                   "bios"),
        "ROCKNIX": ({".config/system/configs/system.cfg": "root.password=rocknix\n"},
                    "rocknix", "roms/bios"),
        # Lakka's STORAGE partition, once RetroArch has written its config.
        "Lakka": ({".config/retroarch/retroarch.cfg":
                   'menu_driver = "xmb"\nsystem_directory = "/tmp/system"\n'},
                  "lakka", "system"),
    }

    def card(self, files: dict) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for name, text in files.items():
            path = root / name
            if name.endswith("/"):
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
        return root

    # a handheld's card mounted on a computer.

    def test_each_card_by_its_own_files(self):
        for name, (files, plat, folder) in self.CARDS.items():
            with self.subTest(card=name):
                root = self.card(files)
                self.assertEqual(install.card_system(root), (plat, root / folder, name))

    def test_card_nothing_names_is_left_alone(self):
        self.assertIsNone(install.card_system(self.card({"roms/": "", "BIOS/": ""})))
        # Batocera's own share is its SHARE drive, read
        # by a batocera.conf that names no KNULLI.
        share = self.card({"system/batocera.conf": "system.hostname=BATOCERA\n"})
        self.assertEqual(install.card_system(share), ("batocera", share / "bios", "Batocera"))

    def test_the_card_rules_are_the_device_rules(self):
        # The folder and the marker come from the rule the device reads, so
        # they are never written twice.
        rules = {rule.name: rule for rule in install._card_rules()}
        self.assertLessEqual({"muOS", "Onion", "spruceOS", "CrossMix-OS", "Allium", "Koriki",
                              "KNULLI", "ROCKNIX"}, set(rules))
        # Only a marker on the part its BIOS folder is on names the card:
        # plumOS's and the Anbernic firmware's are on another part.
        for setup in install.card_setups():
            for rule in setup.rules:
                with self.subTest(system=setup.name, rule=rule.values):
                    self.assertEqual(rule.bios, setup.below)
        self.assertIn("ArkOS", rules)
        self.assertEqual(install.DEFAULT_DESTS["knulli"], Path("/userdata") / "bios")
        self.assertEqual(install.DEFAULT_DESTS["rocknix"], Path("/storage") / "roms/bios")

    def test_the_first_screen_offers_the_card_folder(self):
        root = self.card(self.CARDS["muOS"][0])
        with mock.patch.object(install, "_mounted_cards", return_value=[root]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, effects = install.tui_start(_args(), "linux")
        self.assertEqual(effects, [("fetch", "retroarch")])
        self.assertEqual(state.dest, root / "MUOS" / "bios")
        listed(state)
        label = f"muOS SD card ({root.name})"
        self.assertEqual(state.setups, [("retroarch", root / "MUOS" / "bios", label)])
        text = screen_text(install.tui_view(state, 120, 40))
        self.assertIn(f"> {label}", text)
        self.assertIn(f"BIOS folder: {root / 'MUOS' / 'bios'}", text)
        (root / "MUOS" / "bios").mkdir()
        self.assertEqual(press(state, "enter"), [("fetch", "retroarch")])
        self.assertEqual(state.dest, root / "MUOS" / "bios")

    def test_drive_letter_names_the_card(self):
        self.assertEqual(install._mount_name(PureWindowsPath("E:\\")), "E:\\")
        self.assertEqual(install._mount_name(Path("/media/me/MUOS")), "MUOS")
        # under WSL the card screen listed "d (card or drive)".
        with mock.patch.dict(install._WSL, {"active": True}):
            self.assertEqual(install._mount_name(Path("/mnt/d")), "D:")
            self.assertEqual(install._mount_name(Path("/mnt/wslg")), "wslg")
        self.assertEqual(install._mount_name(Path("/mnt/d")), "d")

    def test_on_the_device_its_card_is_not_offered_twice(self):
        root = self.card(self.CARDS["muOS"][0])
        bound = Path("/run/muos/storage/bios")
        with mock.patch.object(install, "_mounted_cards", return_value=[root]), \
                mock.patch.object(install, "detect_platforms", return_value=[("retroarch",
                                                                              bound)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.dict(install._DETECTED_OS, {("retroarch", bound): "muOS"}):
            state, _effects = install.tui_start(_args(), "linux")
        self.assertEqual([setup[1] for setup in state.setups], [bound])

    def test_browsing_to_the_card_root_uses_its_folder(self):
        root = self.card(self.CARDS["KNULLI"][0])
        with mock.patch.object(install, "_mounted_cards", return_value=[root]):
            rows, _error = install._browse_rows(REPO_ROOT / "tests")
        self.assertEqual(rows[2].label, f"{root} (KNULLI card)")
        state = fresh_state()
        install._choose(state, "knulli", root)
        self.assertEqual(state.dest, root / "bios")
        # Another platform's list keeps the folder it was given.
        install._choose(state, "batocera", root)
        self.assertEqual(state.dest, root)

    def test_the_command_line_writes_where_muos_reads(self):
        root = self.card(self.CARDS["muOS"][0])
        with FakeRepository() as repo:
            proc = install_run("--platform", "muos", "--dest", str(root), "--yes",
                               env=repo.env())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"muOS card: RetroArch files, in {root / 'MUOS' / 'bios'}", proc.stdout)
        self.assertEqual(sorted(path.name for path in root.iterdir()), ["MUOS"])
        self.assertTrue((root / "MUOS" / "bios" / "scph5501.bin").is_file())

    def test_folder_that_is_no_muos_card_is_refused(self):
        root = self.card({"roms/": ""})
        proc = install_run("--platform", "muos", "--dest", str(root), "--yes")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"{root} is not a muOS SD card: no muOS files on it. muOS keeps "
                      "MUOS at the root of its card.", proc.stderr)
        # muOS always names its card: <card>/MUOS/bios would be refused the
        # same, the card's top folder is the remedy.
        self.assertIn("Name the top folder of the muOS card with --dest", proc.stderr)
        self.assertNotIn("<card>/", proc.stderr)
        self.assertEqual(list(root.iterdir()), [root / "roms"])
        # Its BIOS folder named outright is its card's, checked as the card
        # is: on a folder with no MUOS it is refused, as typed it was.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            install.card_dest("muos", "retroarch", root / "MUOS" / "bios")
        card = self.card({"MUOS/bios/": ""})
        self.assertEqual(install.card_dest("muos", "retroarch", card / "MUOS" / "bios"),
                         ("retroarch", card / "MUOS" / "bios"))
        # On the device, the folder muOS binds it to.
        bound = Path("/run/muos/storage/bios")
        self.assertEqual(install.card_dest("muos", "retroarch", bound), ("retroarch", bound))
        # A list named by its own name says which list, not which card.
        self.assertEqual(install.card_dest("retroarch", "retroarch", root),
                         ("retroarch", root))

    def test_the_folder_named_is_compared_by_folders(self):
        """NOTMUOS/bios ended with MUOS/bios as text and was taken for a
        muOS card's folder."""
        root = self.card({"roms/": ""})
        stray = root / "NOTMUOS" / "bios"
        with self.assertRaises(SystemExit), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            reported(install.card_dest, "muos", "retroarch", stray)
        self.assertIn("does not exist", err.getvalue())
        card = self.card({"MUOS/bios/": ""})
        self.assertEqual(install.card_dest("muos", "retroarch", card / "muos" / "BIOS"),
                         ("retroarch", card / "muos" / "BIOS"))

    def test_card_two_systems_claim_says_so(self):
        root = self.card({"MUOS/": "", "spruce/": ""})
        self.assertIsNone(install.card_system(root))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install.card_dest("retroarch", "retroarch", root),
                             ("retroarch", root))
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("holds the files of muOS and spruceOS", lines[0])
        # The system named among them decides.
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(install.card_dest("muos", "retroarch", root),
                             ("retroarch", root / "MUOS/bios"))
        self.assertIn("muOS card", out.getvalue())

    # Space is X on PortMaster and Y on muxterm.

    def test_space_on_install_opens_the_confirm_screen(self):
        state = checked_state()
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertEqual(press(state, " "), [("run", "confirm")])
        self.assertEqual(state.screen, "confirm")
        # The same plan comes back: the screen still waits for A.
        install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
        self.assertEqual(install.tui_receive(state, ("ended", state.run_id, 0, [])), [])
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(install.tui_rows(state)[0].action, "install")
        self.assertEqual(press(state, " "), [])
        self.assertEqual(state.screen, "confirm")
        self.assertEqual(press(state, "enter"), [("run", "install")])

    def test_space_never_closes_or_quits(self):
        for action in ("quit", "close"):
            with self.subTest(row=action):
                state = checked_state()
                if action == "close":
                    state.check = {**CHECK, "missing": 0, "wrong_hash": 0, "bytes_needed": 0}
                rows = install.tui_rows(state)
                state.focus["plan"] = next(i for i, r in enumerate(rows) if r.action == action)
                self.assertEqual(press(state, " "), [])
                self.assertIsNone(state.exit_code)
        state = checked_state()
        state.focus["plan"] = next(i for i, r in enumerate(install.tui_rows(state))
                                   if r.action == "options")
        press(state, " ")
        self.assertEqual(state.screen, "options")

    def test_enter_still_installs_in_three_presses(self):
        state = checked_state()
        self.assertEqual(press(state, "enter"), [("run", "install")])
        self.assertEqual(state.screen, "installing")

    # a card too small for the download.

    def test_a_stop_asked_for_says_only_the_outcome(self):
        """Start+Select (SIGTERM) or SIGHUP stops the child before it writes
        a summary: the farewell then listed the log's last lines."""
        state = checked_state()
        state.download = {"files": 50}
        state.finished = [("scph5501.bin", True, "")]
        state.tail = ["    [2/50] scph5501.bin ok",
                      "    Stopping. Files already installed are kept."]
        for code, shown in ((130, False), (1, True)):
            with self.subTest(code=code):
                state.code = code
                _title, lines = install.tui_outcome(state)
                self.assertEqual(any("[2/50]" in line for line in lines), shown, lines)

    def test_a_pack_installs_from_the_pack_not_the_network(self):
        """With --from-pack and no Wi-Fi, the plan said "to download", which
        on a handheld with no network read as a failure on its way."""
        state = checked_state()
        with mock.patch.object(install.LOCAL, "pack", HoldingPack()):
            headline = str(install.tui_view(state, 80, 24)[0])
            plan = "\n".join(str(line) for line in install.tui_view(state, 80, 24))
            state.summary = {"installed": 3, "failed": [], "up_to_date": 0}
            title, lines = install.tui_outcome(state)
        self.assertIn("to install from the pack", plan, headline)
        self.assertNotIn("to download", plan)
        self.assertEqual(lines[0], "3 files installed from the pack.")

    def test_another_folder_comes_first_when_space_is_short(self):
        state = checked_state({"free": 1024, "writable": True, "cores": []})
        self.assertEqual([row.label for row in install.tui_rows(state)[:2]],
                         ["Choose another folder", "Install anyway"])
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "folder")

    def test_offline_with_nothing_to_copy_offers_no_install_anyway(self):
        """Offline with nothing here to copy, Install is removed: a folder
        short of space then put "Install anyway" back, a run that could
        only fail every file."""
        state = checked_state({"free": 1024, "writable": False, "cores": []})
        state.offline = True
        labels = [row.label for row in install.tui_rows(state)]
        self.assertEqual(labels[0], "Choose another folder")
        self.assertNotIn("Install anyway", labels)
        self.assertFalse(any(label.startswith("Install") for label in labels), labels)

    FULL_TAIL = [
        "  Checking existing files...",
        "    0/50 present (0 verified, 0 wrong hash)",
        "  Downloading 50 files (845.7 KB)...",
        "Not enough space on the drive holding /media/me/MUOS/MUOS/bios.",
        "  Needed: 1.2 GB. Free: 300.0 MB.",
        "  Free up 920.0 MB, or install to another drive:",
        "    python3 install.py --platform retroarch --dest '<folder on another drive>'",
    ]

    def test_full_card_is_said_in_words(self):
        root = self.card(self.CARDS["muOS"][0])
        state = checked_state()
        state.dest, state.log = root / "MUOS" / "bios", "/tmp/retrobios-tui-x/install.log"
        state.stack.append("result")
        state.code, state.tail = 2, list(self.FULL_TAIL)
        install._take_event(state, {"event": "no_space", "platform": "retroarch",
                                    "folder": str(state.dest),
                                    "bytes_needed": 1200 * 1024 * 1024,
                                    "bytes_free": 300 * 1024 * 1024})
        with mock.patch.object(install, "_mounted_cards", return_value=[root]):
            state.full_drive = install.full_drive_words(state)
        title, lines = install.tui_outcome(state)
        self.assertEqual(title, "Not enough space")
        self.assertEqual(lines[0], "The card is full: 1.2 GB needed, 300.0 MB free.")
        self.assertIn("Free some space, or run again and choose another folder.", lines)
        text = "\n".join(lines)
        for raw in ("Checking existing files", "Downloading", "stopped with code", "Details:"):
            self.assertNotIn(raw, text)
        self.assertFalse(install.tui_keeps_log(state))

    def test_a_reworded_space_line_leaves_the_stop_unchanged(self):
        """The result read "Needed: X. Free: Y." from the run's stderr: the
        numbers come from the no_space event, whatever the line says."""
        state = checked_state()
        state.dest = self.card({}) / "bios"
        install._take_event(state, {"event": "no_space", "platform": "retroarch",
                                    "folder": str(state.dest), "bytes_needed": 90010,
                                    "bytes_free": 36 * 1024})
        state.tail = ["Not enough room."]
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            words = install.full_drive_words(state)
        self.assertEqual(words, "The drive is full: 87.9 KB needed, 36.0 KB free.")
        state.no_space, state.tail = None, list(self.FULL_TAIL)
        self.assertEqual(install.full_drive_words(state), "")

    def test_advice_never_names_the_interface_list(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root writes to a read-only folder")
        folder = self.card({})
        folder.chmod(0o555)
        self.addCleanup(folder.chmod, 0o755)
        with FakeRepository() as repo:
            listed = repo.root / "install" / "retroarch.json"
            proc = install_run("--platform", "retroarch", "--dest", str(folder),
                               f"--manifest={listed}", "--yes",
                               env={**repo.env(), install.TUI_LIST_ENV: "1"})
        self.assertIn("sudo", proc.stdout + proc.stderr)
        self.assertNotIn("--manifest", proc.stdout + proc.stderr)

    # the BIOS folder line on a handheld screen.

    def test_the_plan_keeps_the_folder_at_handheld_sizes(self):
        zipped = "/home/me/a/long/path/to/the/Downloads/PSX BIOS.zip"
        for cols, rows in ((40, 12), (40, 15)):
            with self.subTest(size=f"{cols}x{rows}"):
                state = checked_state()
                state.dest = Path("/home/someone/with/a/long/path/.config/retroarch/system")
                state.found = [found("scph5500.bin", zipped)]
                state.cols, state.rows = cols, rows
                lines = [line.strip() for line in install.tui_view(state, cols, rows)]
                at = next(index for index, line in enumerate(lines)
                          if line.startswith("BIOS folder: "))
                # Whole, broken after a separator: cut in its middle at 40
                # columns, it was spelled one way on the plan and another on
                # the result.
                self.assertEqual(lines[at] + lines[at + 1], "BIOS folder: /home/someone/with/"
                                 "a/long/path/.config/retroarch/system")
                self.assertIn("1 found in PSX BIOS.zip,", " ".join(lines))
                self.assertNotIn("/home/me/a/long", " ".join(lines))

    # where the files came from.

    def test_the_result_says_what_came_from_the_card(self):
        state = checked_state()
        state.stack.append("result")
        state.code, state.download = 0, {"files": 5, "bytes": 10}
        state.local_dests = {"scph5500.bin": ("/media/me/OLD", ""),
                             "scph5501.bin": ("/media/me/OLD", ""),
                             "gba_bios.bin": (str(SYSTEM_DIR), "one folder too deep")}
        state.finished = [("scph5500.bin", True, ""), ("scph5501.bin", True, ""),
                          ("gba_bios.bin", True, ""), ("pcsx/extra.bin", True, ""),
                          ("fc/disksys.rom", False, "HTTP 404")]
        state.summary = {"installed": 4, "up_to_date": 0, "failed": [
            {"dest": "fc/disksys.rom", "reason": "HTTP 404"}]}
        _title, lines = install.tui_outcome(state)
        # One count, the failed file said as failed.
        self.assertEqual(lines[0], "2 files copied from OLD, 1 copied from the wrong place "
                                   "in the BIOS folder, 1 downloaded, 1 failed.")
        # The line mode's own sentence, from the same counts.
        self.assertEqual(lines[0], install.sources_line([("OLD", 2)], 1, 1, 0, failed=1))

    def test_run_that_copied_nothing_adds_no_line(self):
        state = install.TuiState()
        state.summary, state.finished = {"installed": 2, "failed": []}, [("a", True, "")]
        self.assertEqual(install._tui_sources(state, 2, 0), "")

    # the systems list.

    def systems_state(self) -> install.TuiState:
        state = checked_state()
        state.systems = [*state.systems,
                         {"system": "other", "name": "other", "files": 2, "present": 0,
                          "missing": 2, "wrong_hash": 0, "bytes_needed": 300},
                         {"system": "3do", "name": "3do", "files": 3, "present": 0,
                          "missing": 3, "wrong_hash": 0, "bytes_needed": 600}]
        state.files = [*state.files,
                       {"event": "file", "dest": "panafz1.bin", "systems": ["3do"],
                        "size": 100, "state": "missing"},
                       {"event": "file", "dest": "mame/hash/a.xml", "systems": ["3do", "mac"],
                        "size": 200, "state": "missing"},
                       {"event": "file", "dest": "mame/hash/b.xml", "systems": ["3do", "mac"],
                        "size": 300, "state": "missing"}]
        state.ticked |= {"other", "3do"}
        state.stack.append("systems")
        return state

    def test_the_other_row_is_named_and_explained(self):
        state = self.systems_state()
        rows = install.tui_rows(state)
        other = next(i for i, row in enumerate(rows) if row.value == "other")
        self.assertEqual(rows[other].label, "[x] Other systems and game engines")
        state.focus["systems"] = other
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("Other systems and game engines: what cores load for systems this "
                      "setup does not list", text)

    def test_shared_files_are_counted_apart(self):
        state = self.systems_state()
        rows = install.tui_rows(state)
        three = next(i for i, row in enumerate(rows) if row.value == "3do")
        self.assertEqual(rows[three].right, "1 file, 100 B + 2 shared")
        state.focus["systems"] = three
        text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("+2 shared: counted once", text)
        # The line mode counts the same files apart.
        self.assertIn("and 2 files, 500 B shared with other systems", install._system_sized([
            {"dest": "panafz1.bin", "size": 100, "systems": ["3do"]},
            {"dest": "a.xml", "size": 200, "systems": ["3do", "mac"]},
            {"dest": "b.xml", "size": 300, "systems": ["3do", "mac"]}]))
        narrow = install.tui_view(state, 40, 15)
        self.assertTrue(any("100 B + 2 shared" in line for line in narrow), narrow)

    # a file that cannot be supplied, by name, where it matters.

    def unavailable_state(self) -> install.TuiState:
        state = checked_state()
        state.manifest = {**MANIFEST, "system_titles": {"nintendo-gba": "Game Boy Advance"},
                          "omitted_files": [
                              {"dest": "gba_extra.bin", "system": "nintendo-gba",
                               "required": True, "reason": "not_found"},
                              {"dest": "optional.bin", "system": "nintendo-gba",
                               "required": False, "reason": "not_found"}]}
        state.stack.append("result")
        state.code, state.download = 0, {"files": 1, "bytes": 1}
        state.summary = {"installed": 1, "up_to_date": 0, "failed": []}
        return state

    def test_the_missing_file_is_named_with_its_system(self):
        state = self.unavailable_state()
        _title, lines = install.tui_outcome(state)
        self.assertIn("Not available here, and needed to start its emulator: gba_extra.bin "
                      "(Game Boy Advance). An owned copy goes in the BIOS folder.", lines)
        self.assertNotIn("collection", " ".join(lines))

    def test_it_is_left_out_when_it_does_not_concern_the_run(self):
        state = self.unavailable_state()
        state.ticked = {"sony-playstation"}
        self.assertEqual(install._unavailable_lines(state), [])
        state = self.unavailable_state()
        state.summary = {"installed": 1, "failed": [], "interrupted": True}
        self.assertFalse(any("Not available" in line for line in install.tui_outcome(state)[1]))

    # small fixes the audit listed.

    def fetch_failure(self, error: BaseException, env: dict | None = None) -> tuple:
        inbox = __import__("queue").Queue()
        with mock.patch.object(install, "_fetch_json", side_effect=error), \
                mock.patch.dict(os.environ, env or {}):
            for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                         "NO_PROXY", "no_proxy"):
                if name not in (env or {}):
                    os.environ.pop(name, None)
            install._tui_fetch("retroarch", inbox)
        _kind, _plat, title, lines, _code = inbox.get_nowait()
        return title, lines

    def test_the_clock_names_the_row_to_choose(self):
        import ssl

        error = urllib_error(ssl.SSLCertVerificationError("certificate is not yet valid"))
        words = install.network_words(error, today=install.datetime.date(1980, 1, 1))
        with mock.patch.object(install, "network_words", return_value=words):
            _title, lines = self.fetch_failure(error)
        self.assertTrue(lines[0].endswith("then choose Try again."), lines[0])

    def test_proxy_in_the_way_is_named_not_shown(self):
        error = urllib_error(ConnectionRefusedError(111, "Connection refused"))
        _title, lines = self.fetch_failure(
            error, {"HTTPS_PROXY": "http://me:secret@10.0.0.1:3128"})
        self.assertIn("HTTPS_PROXY is set, so the connection goes through a proxy: check "
                      "that it answers.", lines)
        self.assertNotIn("secret", " ".join(lines))
        _title, lines = self.fetch_failure(error)
        self.assertFalse(any("PROXY" in line for line in lines))

    def test_a_proxy_urllib_does_not_use_is_not_named(self):
        """NO_PROXY sends the host direct, and urllib reads no ALL_PROXY
        for HTTPS: the screen blamed a proxy the request never went through."""
        error = urllib_error(ConnectionRefusedError(111, "Connection refused"))
        for env in ({"HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "raw.githubusercontent.com"},
                    {"ALL_PROXY": "http://127.0.0.1:9"}):
            with self.subTest(env=env):
                _title, lines = self.fetch_failure(error, env)
                self.assertFalse(any("proxy" in line.lower() for line in lines), lines)

    def test_a_system_proxy_is_named(self):
        """A Windows or macOS proxy set in the settings, no variable."""
        error = urllib_error(ConnectionRefusedError(111, "Connection refused"))
        with mock.patch.object(install.urllib.request, "getproxies",
                               return_value={"https": "http://10.0.0.1:3128"}), \
                mock.patch.object(install.urllib.request, "proxy_bypass", return_value=False):
            _title, lines = self.fetch_failure(error)
        self.assertIn("The system settings set a proxy, so the connection goes through "
                      "it: check that it answers.", lines)

    def test_list_that_is_no_json_is_said_in_words(self):
        try:
            install.json.loads("<html>")
        except install.json.JSONDecodeError as cause:
            error = ValueError(f"invalid file list: {cause}")
            error.__cause__ = cause
        title, lines = self.fetch_failure(error)
        self.assertEqual(title, "The file list is not valid")
        self.assertNotIn("Expecting value", " ".join(lines))
        self.assertIn("a Wi-Fi sign-in page or a cut download looks like this.", lines[0])

    def test_the_preview_counts_its_files_only(self):
        state = checked_state()
        state.stack += ["options", "preview"]
        state.dry = dict(CHECK)
        state.dry_files = [{**FILES[0], "dest": f"f{n}.bin"} for n in range(40)]
        state.rows = 24
        lines = [line.strip() for line in install.tui_view(state, 80, 24)]
        self.assertIn("1-18 of 40", lines)

    def test_game_data_reads_without_a_double_negative(self):
        state = checked_state()
        label = next(row.label for row in install._option_rows(state)
                     if row.action == "game_data")
        self.assertEqual(label, "Game data: kept")
        state.no_game_data = True
        label = next(row.label for row in install._option_rows(state)
                     if row.action == "game_data")
        self.assertEqual(label, "Game data: left out")

    @in_full
    def test_the_plan_says_which_config_named_the_folder(self):
        config = HOME / ".config/retroarch/retroarch.cfg"
        state = checked_state()
        with mock.patch.dict(install._RETROARCH_CONFIGS, {state.dest: (config, config.parent)}):
            state.facts = install._tui_folder_facts(state)
        # Read with the folder's facts, never by a frame.
        with mock.patch.object(install, "_retroarch_config_at", side_effect=AssertionError):
            text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("Named by ~/.config/retroarch/retroarch.cfg", text)

    def test_the_setup_screen_probes_no_card_per_frame(self):
        """The view drew about ten frames a second and asked the card for
        its games part on each, in the thread that reads the keys."""
        state = fresh_state()
        games = Path("/media/x/GAMES")
        state.setups = [("amberelec", games, "AmberELEC")]
        with mock.patch.object(install, "games_part", return_value=None):
            state.setup_folders = install.setup_folders(state.setups)
        with mock.patch.object(install, "games_part", side_effect=AssertionError):
            for _frame in range(3):
                text = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn(f"BIOS folder: {games}", text)

    # The engine's own events (main, after the second audit).

    def test_the_speed_is_the_network_bytes(self):
        state = checked_state()
        state.stack.append("installing")
        state.run, state.running = "install", True
        install.tui_receive(state, ("event", state.run_id,
                                    {"event": "download", "files": 4, "bytes": 4 << 20}))
        for now, done, network in ((100.0, 1 << 20, 0), (102.0, 3 << 20, 1 << 20)):
            state.now = now
            install.tui_receive(state, ("event", state.run_id, {
                "event": "progress", "files_done": 1, "files_total": 4, "bytes_done": done,
                "bytes_total": 4 << 20}))
            install.tui_receive(state, ("event", state.run_id, {
                "event": "transfer", "bytes_local": done - network, "bytes_network": network}))
        text = "\n".join(install.tui_view(state, 80, 24))
        # 1 MB from the network in 2 s, whatever came from the old card.
        self.assertIn("512.0 KB/s, 0:02 left", text)

    @in_full
    def test_the_plan_says_what_the_scan_left_out(self):
        state = checked_state()
        state.from_folders = [Path("E:\\")]
        install._start_check(state)
        events = [{"event": "scanned", "folder": "E:\\", "files": 200000, "truncated": True,
                   "other_drives": ["E:\\D"]},
                  {"event": "unreadable", "platform": "retroarch", "folder": "E:\\",
                   "path": "E:\\bios\\scph5501.bin", "member": "", "reason": "Permission denied"},
                  {"event": "unreadable", "platform": "retroarch", "folder": "E:\\",
                   "path": "E:\\backup.zip", "member": "gba_bios.bin",
                   "reason": "it is encrypted, a password is needed"}]
        for event in [*FILES, *SYSTEMS, *events, CHECK, PLAN]:
            install.tui_receive(state, ("event", state.run_id, event))
        with mock.patch.object(install, "_tui_folder_facts", return_value={
                "free": 50 * 1024 ** 3, "writable": True, "cores": []}):
            install.tui_receive(state, ("ended", state.run_id, 1, []))
        text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        self.assertIn("Read the first 200,000 files of E:\\.", text)
        self.assertIn("E:\\D is another drive: add it to copy from it too.", text)
        # The folder by its name: "your old card" was said of any folder.
        self.assertIn("2 files in E:\\ could not be read.", text)
        rows = install.tui_rows(state)
        state.focus["plan"] = next(i for i, row in enumerate(rows) if row.action == "unreadable")
        press(state, "enter")
        self.assertEqual(state.screen, "unreadable")
        self.assertEqual(install._pager_items(state), [
            "E:\\bios\\scph5501.bin: Permission denied",
            "E:\\backup.zip, gba_bios.bin: it is encrypted, a password is needed"])

    def test_the_interface_does_not_index_the_folders_itself(self):
        missing = REPO_ROOT / "tmp" / "no-such-old-card"
        err = io.StringIO()
        with mock.patch.object(install, "FolderIndex", side_effect=AssertionError("indexed")), \
                mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install, "tui_start", side_effect=AssertionError("opened")), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(install.run_tui(_args(**{"from": [missing]})), 1)
        self.assertIn(f"Error: {missing} does not exist: --from names the folder", err.getvalue())

    def test_a_games_folder_that_does_not_exist_closes_before_the_first_frame(self):
        missing = REPO_ROOT / "tmp" / "no-such-games-folder"
        err = io.StringIO()
        with mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install, "tui_start", side_effect=AssertionError("opened")), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(install.run_tui(_args(for_games=missing)), 1)
        self.assertIn(f"Error: the games folder {missing} does not exist or cannot be opened.",
                      err.getvalue())

    # Work folders: only a kill no handler sees leaves one, and the next
    # run takes it away.

    def test_work_folders_left_behind_are_pruned(self):
        import subprocess

        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        now = time.time()
        week = install.TUI_KEEP_SECONDS

        def folder(name: str, pid: int | None, kept: bool, age: float) -> Path:
            path = root / f"{install.TUI_WORK_PREFIX}{name}"
            path.mkdir()
            if pid is not None:
                (path / install.TUI_OWNER).write_text(str(pid))
            if kept:
                (path / install.TUI_KEPT).write_text("")
            os.utime(path, (now - age, now - age))
            return path

        killed = folder("killed", gone.pid, False, 60)
        running = folder("running", os.getpid(), False, 2 * week)
        failed = folder("failed", gone.pid, True, 60)
        failed_old = folder("failed-old", gone.pid, True, 2 * week)
        unknown = folder("unknown", None, False, 60)
        unknown_old = folder("unknown-old", None, False, 2 * week)
        other = root / "something-else"
        other.mkdir()
        # A stray or hostile owner file is an unknown owner: a number past
        # what a pid holds raised OverflowError, and 0 or -1 name a group.
        hostile = [folder(f"hostile{index}", None, False, 60)
                   for index in range(3)]
        for path, text in zip(hostile, ("9" * 40, "0", "-1")):
            (path / install.TUI_OWNER).write_text(text)
            self.assertIsNone(install._owner_alive(path))
        removed = install._prune_work_folders(root, now)
        self.assertEqual(sorted(removed), sorted([killed, failed_old, unknown_old]))
        for path in hostile:
            shutil.rmtree(path)
        self.assertEqual(sorted(path.name for path in root.iterdir()),
                         sorted(path.name for path in (running, failed, unknown, other)))


class OneSystemInFewPresses(unittest.TestCase):
    """One system with a controller took 15 presses on
    the fixture list, about 60 on muxterm, which has no page key."""

    # The buttons each route sends, as the keys the interface reads.
    PADS = {
        "gptokeyb": {"A": "enter", "B": "esc", "X": " ", "Start": "enter", "R1": "pgdn",
                     "L1": "pgup"},
        "muxterm": {"A": "enter", "B": "esc", "X": " ", "Start": "enter", "R1": "right",
                    "L1": "left"},
    }

    def long_list(self, pad: str) -> install.TuiState:
        state = checked_state()
        state.pad = pad
        state.cols, state.rows = 40, 15
        state.systems = [{"event": "system", "platform": "retroarch", "system": f"sys-{n:02d}",
                          "name": f"System {n:02d}", "files": 1, "present": 0, "missing": 1,
                          "wrong_hash": 0, "bytes_needed": 10} for n in range(66)]
        state.ticked = {row["system"] for row in state.systems}
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "install")
        return state

    def press_button(self, state, pad: str, button: str) -> list:
        name = self.PADS[pad].get(button, button)
        return install.tui_update(state, Key("char", name) if len(name) == 1 else Key(name))

    def go_to(self, state, pad: str, target: str, paging: bool) -> int:
        """Presses from the focus to the target system, or to the row of that
        action (none), as a person does."""
        count = 0
        while True:
            rows = install.tui_rows(state)
            focus = state.focus.get("systems", 0)
            index = next(i for i, row in enumerate(rows)
                         if target in (row.value, row.action))
            if index == focus:
                return count
            # A page is the rows drawn.
            page = install._page_step(state)
            if index > focus:
                button = "R1" if paging and index - focus >= page else "down"
            else:
                button = "L1" if paging and focus - index >= page else "up"
            self.press_button(state, pad, button)
            count += 1

    def presses(self, pad: str, fast: bool) -> int:
        """From the plan to the run that installs sys-45 alone, with the
        setup's A before it."""
        state = self.long_list(pad)
        count = 1
        for button in ("down", "A"):
            self.press_button(state, pad, button)
            count += 1
        self.assertEqual(state.screen, "systems")
        # On its first system, None at the list's end.
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        paging = pad != "muxterm" or fast
        # Up from the first item wraps to the list's end: Done, then None.
        while install.tui_rows(state)[state.focus["systems"]].action != "none":
            self.press_button(state, pad, "up")
            count += 1
        self.press_button(state, pad, "A")
        count += 1
        count += self.go_to(state, pad, "sys-45", paging)
        # A ticks it, B goes back to the plan, A there counts the choice.
        self.press_button(state, pad, "A")
        self.press_button(state, pad, "B")
        effects = self.press_button(state, pad, "A")
        count += 3
        self.assertEqual(state.ticked, {"sys-45"})
        self.assertEqual(effects, [("run", "confirm")])
        # Install on the confirm screen, then Exit on the result.
        return count + 2

    def test_presses_before_and_after(self):
        # The audit's path, A Down A Up Up A R1 x5 X Start A A. Before the
        # fast path it took 17 presses here, 57 on muxterm (None kept the
        # focus, and muxterm had no page key).
        # A page is the rows drawn, ten here where it
        # was nine: sys-45 is four pages and five Downs away, not five pages.
        # None now at the list's end, three presses up
        # from the first system: the list wraps. fast pages down to sys-45.
        self.assertEqual(self.presses("gptokeyb", fast=True), 21)
        self.assertEqual(self.presses("muxterm", fast=False), 57)
        self.assertEqual(self.presses("muxterm", fast=True), 21)

    def test_a_on_a_system_with_none_ticked_takes_it_alone(self):
        state = self.long_list("keys")
        state.stack.append("systems")
        state.ticked = set()
        state.focus["systems"] = 5
        text = install.tui_view(state, 80, 24)[-1]
        self.assertIn("Enter Tick", text)
        focused = install.tui_rows(state)[5].value
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.ticked, {focused})

    def test_enter_still_continues_with_the_ticks_as_they_are(self):
        state = self.long_list("keys")
        state.stack.append("systems")
        state.focus["systems"] = 5
        # nothing runs from the list. A unticks the system
        # in focus, B goes back to the plan.
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual((state.screen, len(state.ticked)), ("systems", 65))
        press(state, "esc")
        self.assertEqual(state.screen, "plan")

    def test_left_and_right_page_inside_muxterm_only(self):
        for pad in ("muxterm", "gptokeyb_muxterm", "gptokeyb"):
            with self.subTest(pad=pad):
                state = self.long_list(pad)
                state.stack.append("systems")
                state.focus["systems"] = 3
                press(state, "right")
                paged = pad != "gptokeyb"
                self.assertEqual(state.focus["systems"] > 4, paged)
                self.assertEqual(len(state.ticked), 66)
                state.help = True
                help_text = " ".join(install.tui_view(state, 80, 24))
                self.assertEqual("D-pad Left/Right" in help_text, paged)

    def test_a_short_list_opens_on_its_first_system(self):
        state = checked_state()
        state.focus["plan"] = next(i for i, row in enumerate(install.tui_rows(state))
                                   if row.action == "systems")
        press(state, "enter")
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")


class BackTicksAndSaveFolder(unittest.TestCase):
    """Going back keeps the ticks, and the save folder is said once."""

    def long_list(self) -> install.TuiState:
        state = OneSystemInFewPresses().long_list("keys")
        state.cols, state.rows = 80, 24
        return state

    def test_back_from_none_keeps_the_ticks_it_opened_with(self):
        state = self.long_list()
        everything = set(state.ticked)
        press(state, "down", "enter")
        # The list opens on its first system, None at its end.
        self.assertEqual(install.tui_rows(state)[state.focus["systems"]].action, "system")
        press(state, "n")
        self.assertEqual(state.ticked, set())
        self.assertEqual(install._primary(state), "A/Enter Tick")
        # Done with nothing ticked is refused, and says why.
        press(state, "esc")
        self.assertEqual(state.screen, "systems")
        self.assertIn("No system is ticked", " ".join(install.tui_view(state, 80, 24)))
        press(state, "a", "esc")
        self.assertEqual(state.screen, "plan")
        self.assertEqual(state.ticked, everything)
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertNotIn("No system is ticked", text)

    def test_the_page_says_where_the_list_opens(self):
        """wiki/installer.md said a long list opens on None, where A
        unticked every system as the first press: the focus moved to the
        first system, and the page kept the old words."""
        state = self.long_list()
        self.assertGreater(len(state.systems), install.TUI_LONG_LIST)
        press(state, "down", "enter")
        rows = install.tui_rows(state)
        self.assertEqual(state.focus["systems"],
                         next(i for i, row in enumerate(rows) if row.action == "system"))
        self.assertEqual([row.action for row in rows][-3:], ["all", "none", "done"])
        page = " ".join((REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8").split())
        self.assertNotIn("opens on **None**", page)
        self.assertIn("It opens on its first system, every system ticked", page)
        self.assertIn("**None** (`a` and `n`) sit at the end of the list", page)

    def test_back_after_a_choice_keeps_the_choice(self):
        state = self.long_list()
        press(state, "down", "enter", "enter")
        press(state, " ")
        chosen = set(state.ticked)
        press(state, "esc")
        self.assertEqual((state.screen, state.ticked), ("plan", chosen))

    def test_confirm_offline_with_nothing_on_hand_has_no_install(self):
        state = checked_state()
        state.stack.append("confirm")
        state.dry = planned(CHECK)
        state.dry_files = [dict(event, state="missing") for event in FILES]
        state.offline = True
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            rows = [row.action for row in install.tui_rows(state)]
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertEqual(rows, ["back"])
            self.assertIn("Copy them from an old card or a folder", text)
            state.found = [{"event": "found", "platform": "retroarch",
                            "dest": FILES[0]["dest"], "folder": "/media/old",
                            "path": "/media/old/x", "member": "", "reason": ""}]
            state.dry = planned(CHECK, [FILES[0]["dest"]])
            self.assertEqual(install.tui_rows(state)[0].action, "install")

    def test_the_checking_clock_starts_at_zero(self):
        state = install.TuiState()
        self.assertLess(abs(state.now - time.monotonic()), 5)

    @in_full
    def test_a_pack_installs_from_the_pack(self):
        state = checked_state()
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/x", "member": "",
                        "reason": "misplaced"}]
        state.check = planned(CHECK, [FILES[0]["dest"]])
        with mock.patch.object(install.LOCAL, "pack", mock.Mock()):
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            # one count, "4 files to install" above "3 from
            # the pack", where "3 to install from the pack" sat over "4".
            self.assertIn("4 files to install, 1.0 MB", text)
            self.assertIn("3 from the pack, 1 copied from this machine", text)
            self.assertNotIn("downloaded", text)
            self.assertNotIn("of them", text)
            state.finished = [(FILES[0]["dest"], True, ""), (FILES[1]["dest"], True, "")]
            state.local_dests = {FILES[0]["dest"]: ("/media/old", "misplaced")}
            self.assertIn("1 from the pack", install._tui_sources(state, 2, 0))

    def test_the_wrong_place_screen_says_the_copies_stay(self):
        state = checked_state()
        state.stack.append("misplaced")
        self.assertEqual(install._pager_items(state)[0],
                         "They are copied where the emulators read them. The copies found stay "
                         "where they are.")

    def test_the_save_folder_is_a_line_of_its_own(self):
        state = checked_state()
        saves = {"files": 1, "folder": str(HOME / ".config" / "retroarch" / "saves" / "<core>")}
        lines = install._saves_lines(state, saves)
        # In words: "saves/<core>" read as a folder named <core>.
        # The folder at the BIOS folder's indent.
        self.assertEqual(lines, ["1 file read from RetroArch's save directory goes to a "
                                 "folder per core under:", "  ~/.config/retroarch/saves"])

    def test_the_shared_note_is_one_line(self):
        state = self.long_list()
        state.cols, state.rows = 40, 12
        state.files = [{"event": "file", "dest": "mame.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]}]
        state.stack.append("systems")
        state.focus["systems"] = install._first_item(state)
        lines = install.tui_view(state, 40, 12)
        self.assertIn(" Shared, counted once", lines)

    def test_a_folder_left_out_gives_the_cause_line_mode_gives(self):
        """A RetroArch keeping saves beside each game read on the screen as
        "Its place is not known", and the roms folder had no line at all."""
        files = [{"dest": "keys.txt", "root": "save", "size": 1}]
        why = install.SaveUnknown("RetroArch keeps saves beside each game "
                                  "(savefiles_in_content_dir in /c/retroarch.cfg)",
                                  ": name the folder with --save-dir")
        with mock.patch.object(install, "save_directory_for", return_value=why):
            kept, left = install.place_save_entries(files, Path("/bios"), {}, None, "RetroArch")
        roms = [{"dest": "pico-8/pico8_64", "root": "roms", "cores": ["x"]}]
        _kept, beyond = install.place_relative_entries(roms, Path("/card/notbios"), {})
        self.assertIn(f"left out: {why.words}.",
                      " ".join(install.save_lines(kept, left, Path("/bios"), "RetroArch")))
        state = checked_state()
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        state.unplaced_why = install.unplaced_whys(left + beyond)
        summary = {"skipped": [{"reason": "no_save_directory", "files": 1},
                               {"reason": "no_roms_directory", "files": 1}]}
        lines = install._unplaced_lines(summary, state)
        self.assertIn(f"{why.cause}.", screen_text(lines))
        self.assertIn("1 file read from RetroArch's roms folder left out: /card/notbios is "
                      "not its BIOS folder.", lines)
        self.assertEqual(install._save_folder_words(state), why.cause)

    def test_the_save_folder_remedy_is_the_same_on_both_screens(self):
        summary = {"skipped": [{"reason": "no_save_directory", "files": 1}]}
        state = checked_state()
        state.manifest = {**state.manifest, "save_directory": {"folder": "saves",
                                                               "by_core": True}}
        lines = install._unplaced_lines(summary, state)
        self.assertIn("Change, Save folder (--save-dir)", lines[0])

    def test_a_size_keeps_its_unit(self):
        for width in range(20, 45):
            for line in install._wrap("2 files to install from the pack, 5.1 KB", width):
                self.assertNotEqual(line.strip(), "KB")

    def test_the_miyoo_bar_names_the_tick(self):
        state = self.long_list()
        state.pad = "miyoo"
        press(state, "down", "enter")
        state.ticked = set()
        state.focus["systems"] = install._first_item(state)
        bar = install.tui_view(state, 40, 15)[-1]
        # A is Space on a Miyoo, and ticks as Start does.
        self.assertTrue(bar.strip().startswith("A Tick"))
        # the way out was the entry given up at 40 columns.
        self.assertIn("R2 Done", bar)

    def test_muxterm_help_names_no_home_key(self):
        state = self.long_list()
        state.pad = "muxterm"
        press(state, "down", "enter")
        keys = [key for key, _what in install._help_lines(state)]
        self.assertNotIn("Home/End, g/G", keys)
        state.pad = "keys"
        self.assertIn("Home/End, g/G", [key for key, _what in install._help_lines(state)])


class ConfirmRefusalsAndCardRows(unittest.TestCase):
    """Confirm before an install, refusals said in full, and card rows."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def onion(self, name: str = "ONION") -> Path:
        card = self.root / name
        make_card(card, "Onion")
        return card

    def test_continue_never_installs_without_confirm(self):
        """A on a system, the ticks unchanged, installed at once,
        offline too where the plan had no Install."""
        state = checked_state()
        press(state, "down", "enter")
        self.assertEqual(state.screen, "systems")
        # A ticks there, and Done goes back to the plan: nothing runs from
        # the list.
        self.assertEqual(install._primary(state), "A/Enter Tick")
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "systems")
        self.assertEqual(press(state, "enter"), [])
        self.assertEqual(press(state, "esc"), [])
        self.assertEqual(state.screen, "plan")

    def test_offline_with_nothing_on_hand_runs_nothing_from_the_list(self):
        state = checked_state()
        # Checked offline: the counts read are those of an offline run.
        state.offline = True
        state.checked_flags = install.tui_flags(state)
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: "1"}):
            state.focus["plan"] = [row.action for row in install.tui_rows(state)].index(
                "systems")
            press(state, "enter")
            # A ticks: the list runs nothing. The way to
            # Confirm is Space on the plan's Install.
            self.assertEqual(press(state, "enter", "esc"), [])
            state.focus["plan"] = 0
            state.must_confirm = True
            install._push(state, "confirm")
            install._start_run(state, "confirm")
            install.tui_receive(state, ("event", state.run_id, dict(CHECK)))
            for event in FILES:
                install.tui_receive(state, ("event", state.run_id, dict(event)))
            install.tui_receive(state, ("ended", state.run_id, 0, []))
            self.assertEqual([row.action for row in install.tui_rows(state)], ["back"])
            view = install.tui_view(state, 40, 12)
            text = " ".join(" ".join(view).split())
        self.assertEqual(state.screen, "confirm")
        # Back alone, no word of an Install.
        self.assertNotIn("before Install", text)
        self.assertNotIn("backup folder", text)
        self.assertIn("Copy them from an old card", text)
        # The short names at 40 columns, as every screen of that width.
        self.assertEqual(view[-1].strip(), "A Back  ? Help")

    def test_a_refusal_shows_at_40x12_on_type_a_path(self):
        """Enter seemed to do nothing, the refusal drawn below the
        last line."""
        blank = self.root / "USBSTICK"
        blank.mkdir()
        state = fresh_state()
        state.stack = ["setup", "folder", "path"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        state.path_text = str(blank)
        press(state, "enter")
        self.assertEqual(state.screen, "path")
        text = " ".join(" ".join(install.tui_view(state, 40, 12)).split())
        self.assertIn("Not an Onion SD card: no Onion files on it.", text)
        self.assertNotIn("Ctrl-U clears", text)
        # no hidden folder named in the short form, the detail after.
        self.assertNotIn(".tmp_update", state.status)
        self.assertIn(".tmp_update", state.status_more)
        # the prompt asks for the card.
        self.assertIn("The top folder of the Onion SD card:", text)

    def test_the_help_says_the_refusal_in_full(self):
        state = fresh_state()
        state.stack = ["setup", "folder"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        blank = self.root / "STICK"
        blank.mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._choose_card(state, blank)
            press(state, "?")
            text = " ".join(" ".join(install.tui_view(state, 80, 24)).split())
        self.assertIn("STICK is not an Onion SD card: no Onion files on it. Onion keeps "
                      ".tmp_update at the root of its card.", text)

    def test_wsl_drive_letters_are_taken_as_typed(self):
        """The screen says D:, and D: typed was refused."""
        with mock.patch.dict(install._WSL, {"active": True}):
            for typed in ("D:", "D:\\", "d:\\", "\"D:\\\""):
                with self.subTest(typed=typed):
                    self.assertEqual(install._typed_folder(typed), Path("/mnt/d"))
                    self.assertEqual(install.typed_path(typed), Path("/mnt/d"))
            self.assertEqual(install._typed_folder("E:\\bios"), Path("/mnt/e/bios"))
            args = _args(dest=Path("D:\\"))
            install._wsl_dest(args)
            self.assertEqual(args.dest, Path("/mnt/d"))
            card = Path("/mnt/d")
            with mock.patch.object(install, "_card_what", return_value="Onion card"):
                self.assertEqual(install.card_line(card), "D: (Onion card)")
        self.assertEqual(install._typed_folder("D:"), Path("D:"))

    def test_a_dest_refused_on_the_setup_list_names_dest(self):
        """"Choose the root of the Onion card", where
        --dest fixes the folder, and the refused system stayed chosen."""
        blank = self.root / "USBSTICK"
        blank.mkdir()
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=[]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(dest=str(blank)), "linux")
            state.filters["platforms"] = "onion"
            state.focus["platforms"] = 1
            self.assertEqual(install.tui_rows(state)[1].label, "Onion, SD card")
            self.assertEqual(press(state, "enter"), [])
        self.assertEqual(state.screen, "platforms")
        # --dest is fixed: a stick that is no card is named again in the
        # command, another setup would not help.
        self.assertIn("Run it again with the card's top folder.", state.status)
        self.assertNotIn("choose another setup", state.status)
        self.assertEqual((state.platform, state.card_bound), ("", None))

    def test_on_the_device_a_folder_typed_is_taken_as_typed(self):
        """A KNULLI got bios added to what was typed."""
        share = self.root / "userdata" / "share"
        share.mkdir(parents=True)
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.platform, state.card_bound = "knulli", ("KNULLI", "bios")
        install._open_folder_screen(state, Path("/userdata/bios"), "found")
        state.stack.append("path")
        state.path_text = str(share)
        text = " ".join(install.tui_view(state, 80, 24))
        self.assertIn("The folder for KNULLI:", text)
        with mock.patch.object(install, "_mounted_cards", return_value=[]):
            press(state, "enter")
        self.assertEqual(state.dest, share)

    def test_a_card_in_a_reader_asks_for_its_card_once(self):
        """"Which folder? Onion reads
        its BIOS files from" on a computer, the same card listed twice."""
        first, second = self.onion("D"), self.onion("E")
        with mock.patch.object(install, "_mounted_cards", return_value=[first, second]), \
                mock.patch.object(install, "detect_platforms",
                                  return_value=[("retroarch", SYSTEM_DIR)]), \
                mock.patch.object(install, "detect_frontends", return_value=[]):
            state, _effects = install.tui_start(_args(), "linux")
            self.assertEqual(len(state.setups), 3)
            state.focus["setup"] = len(state.setups)
            press(state, "enter")
            state.filters["platforms"] = "onion"
            state.focus["platforms"] = 1
            press(state, "enter")
            rows = install.tui_rows(state)
            title = install.tui_view(state, 80, 24)[0]
        self.assertIn("Where is the SD card?", title)
        self.assertEqual([(row.action, row.value) for row in rows][:2],
                         [("card", first), ("card", second)])
        self.assertNotIn("default", [row.action for row in rows])
        # The RetroArch row stays this computer's, never the card's folder.
        state.stack = ["setup", "platforms"]
        state.filters["platforms"] = ""
        state.focus["platforms"] = install._platform_focus(state, "retroarch")
        with mock.patch.object(install, "_mounted_cards", return_value=[first, second]):
            press(state, "enter")
        self.assertEqual(state.folder_default, SYSTEM_DIR)

    def test_browsing_for_a_card_starts_on_the_drives(self):
        """The browser opened on the home folder, Use this
        folder focused, saying to go back, the cards listed under it."""
        card = self.onion()
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        state.platform, state.card_bound = "retroarch", ("Onion", "BIOS")
        with mock.patch.object(install, "_mounted_cards", return_value=[card]):
            install._open_folder_screen(state, None)
            state.focus["folder"] = [row.action for row in install.tui_rows(state)].index(
                "browse")
            press(state, "enter")
            rows = install.tui_rows(state)
        self.assertEqual(state.screen, "browse")
        self.assertEqual(rows[state.focus["browse"]].value, card)
        self.assertEqual(state.status, "Choose the Onion card below.")

    def test_a_number_outside_the_list_is_said(self):
        """9 was read as a folder."""
        card, other = self.onion(), self.onion("SECOND")
        answers = iter(["9", "0", "2"])
        with mock.patch.object(install, "_mounted_cards", return_value=[card, other]), \
                mock.patch.object(install, "_ask", side_effect=lambda _p: next(answers)), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            dest = install.card_install_dest("onion", "retroarch", True)
        self.assertEqual(dest, other / "BIOS")
        self.assertEqual(out.getvalue().count(
            "Type a number from 1 to 2, a folder, Enter to look again, or q to quit."), 2)

    def test_the_articles_read(self):
        self.assertEqual([install._a(name) for name in ("Onion", "Allium", "ArkOS", "muOS",
                                                        "KNULLI")],
                         ["an Onion", "an Allium", "an ArkOS", "a muOS", "a KNULLI"])

    def test_every_card_row_reads_the_same(self):
        """KNULLI, ROCKNIX and the MinUI family asked for
        their card without saying so."""
        state = fresh_state()
        state.stack = ["setup", "platforms"]
        labels = {row.value: row.label for row in install.tui_rows(state)
                  if row.action == "platform"}
        for plat in ("knulli", "rocknix", "minui", "nextui", "myminui"):
            self.assertEqual(labels[plat], f"{install.display_name(plat)}, SD card")
        self.assertEqual(labels["retroarch"], "RetroArch")
        # On the device itself it is that device's setup, not a card.
        share = Path("/userdata/bios")
        state.setups.append(("knulli", share, "KNULLI"))
        with mock.patch.dict(install._DETECTED_OS, {("knulli", share): "KNULLI"}):
            labels = {row.value: row.label for row in install.tui_rows(state)
                      if row.action == "platform"}
        self.assertEqual(labels["knulli"], "KNULLI")

    @in_full
    def test_offline_plan_counts_agree(self):
        """"3 downloaded" under "3 need the internet";
        the data files read as if on hand."""
        state = checked_state()
        state.offline = True
        state.found = [{"event": "found", "platform": "retroarch", "dest": FILES[0]["dest"],
                        "folder": "/media/old", "path": "/media/old/x", "member": "",
                        "reason": ""}]
        state.check = planned(CHECK, [FILES[0]["dest"]])
        with mock.patch.dict(os.environ, {install.OFFLINE_VARIABLE: install.OFFLINE_FLAG_VALUE}):
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
            self.assertNotIn("downloaded", text)
            state.found = []
            state.check = planned(dict(CHECK, data_missing=2636, data_bytes=40 * 1024 * 1024))
            text = " ".join(" ".join(install.tui_view(state, 120, 40)).split())
        # One count of files, the kinds apart under the folder: "4 files and
        # 2636 data files" read as two kinds of one.
        self.assertIn("2640 files need the internet, which --offline does not use", text)
        self.assertIn("2636 data files (40.0 MB).", text)

    def test_the_error_row_and_the_bar_agree(self):
        """"Choose another setup or folder" over
        "A/Enter Back"."""
        state = checked_state()
        state.run = "check"
        install._fail(state, ["went wrong"], 1)
        state.focus["error"] = 0
        self.assertEqual(install.tui_rows(state)[0].label, "Choose another setup or folder")
        self.assertEqual(install._primary(state), "A/Enter Choose")
        press(state, "enter")
        self.assertNotEqual(state.screen, "error")

    def test_a_long_name_keeps_a_size_at_40_columns(self):
        """Nintendo Game Boy Advance lost its size.
        It also kept it rounded, 3 KB beside a total of
        2.7 KB. The size stays whole, the name is cut."""
        row = install.TuiRow("system", "[x] Nintendo Game Boy Advance", "1 file, 16.0 KB",
                             "nintendo-gba", narrow=("16.0 KB",), keep_right=True)
        line = str(install._row_line(row, False, 38)).rstrip()
        self.assertTrue(line.endswith("16.0 KB"), line)
        self.assertRegex(line, r"Nintendo Game Boy A?d?\.\.\.")

    def test_the_shared_note_keeps_its_line(self):
        """The page held 4, 3 and 5 systems as the note
        came and went, and "+19" read as 19 more."""
        state = OneSystemInFewPresses().long_list("keys")
        state.files = [{"event": "file", "dest": "mame.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]},
                       {"event": "file", "dest": "two.zip", "size": 10,
                        "systems": ["sys-00", "sys-01"]}]
        state.stack.append("systems")
        footers = set()
        for focus in range(1, 10):
            state.focus["systems"] = focus
            lines = install.tui_view(state, 40, 12)
            footers.add(next(i for i, line in enumerate(lines) if "of 66 systems:" in line))
        self.assertEqual(len(footers), 1, footers)
        state.focus["systems"] = 1
        self.assertIn(" +2 shared: counted once", install.tui_view(state, 40, 12))


class CardBoundaries(unittest.TestCase):
    """Three folders at most, a bind mount not
    seen, a folder named MUOS taken for a card, ismount unprobed."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def choice(self, folder: Path, points=frozenset()) -> install.CardChoice:
        with mock.patch.object(install, "_mounted_cards", return_value=[]), \
                mock.patch.object(install, "_mount_points", return_value=points):
            return install.card_choice("knulli", "knulli", folder)

    def test_every_folder_up_to_the_mount_is_read(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        deep = muos / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        self.assertIn("muOS", self.choice(deep).refused)

    def test_a_bind_mount_inside_a_card_is_its_own_drive(self):
        muos = self.root / "MUOS"
        make_card(muos, "muOS")
        stick = muos / "x"
        stick.mkdir()
        self.assertTrue(self.choice(stick).refused)
        choice = self.choice(stick, frozenset({str(stick)}))
        self.assertEqual((choice.refused, choice.folder), ("", stick / "bios"))

    def test_a_folder_named_muos_beside_it_is_no_card(self):
        backups = self.root / "stage" / "backups"
        (backups / "MUOS").mkdir(parents=True)
        (backups / "knulli-new").mkdir()
        choice = self.choice(backups / "knulli-new")
        self.assertEqual(choice.refused, "")
        self.assertEqual(choice.folder, backups / "knulli-new" / "bios")

    def test_mount_points_are_probed(self):
        with mock.patch.object(install, "_probed", wraps=install._probed) as probed, \
                mock.patch.object(install, "_mount_points", return_value=frozenset()), \
                mock.patch.object(install, "_mounted_cards", return_value=[]):
            install._card_boundary(self.root)
        self.assertTrue(probed.called)
        points = install._mount_points()
        if Path("/proc/self/mountinfo").exists():
            self.assertIn("/", points)


if __name__ == "__main__":
    unittest.main()
