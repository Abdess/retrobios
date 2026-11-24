"""install.py finds each platform where its own code puts it, on a desktop, under WSL or from the registry."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import io
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, reported


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_detection")


class DetectionFollowsTheRegistry(unittest.TestCase):
    """The registry declared RetroPie at ~/RetroPie/BIOS and BizHawk at
    ~/.config/BizHawk/Firmware, every manifest published it, and the
    installer never read it: such a home detected nothing."""

    def test_the_table_is_the_registry(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = {
            (rule["os"], name, rule["path"], rule.get("bios_path"))
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "path_exists"
        }
        self.assertEqual(set(install._PATH_RULES), rules)

    def test_the_embedded_table_is_the_registry(self):
        """Only the path rules were compared: Knulli, muOS, ArkOS and the
        Recalbox version file were detected by the installer and absent
        from every manifest's `detect`, and ROCKNIX was declared another
        way. A changed bios_path in the registry reached no installer."""
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = []
        for name, entry in registry["platforms"].items():
            for rule in (entry.get("install") or {}).get("detect", []):
                if rule["method"] == "os_release":
                    values = tuple(rule["match"])
                elif rule["method"] == "file_exists":
                    files = rule["file"]
                    values = tuple(files if isinstance(files, list) else [files])
                elif rule["method"] == "file_matches":
                    values = (rule["file"], rule["pattern"])
                else:
                    continue
                rules.append(install._OsRule(
                    "" if rule.get("installs") is False else name, rule["name"],
                    rule["method"], values, rule.get("bios_path"),
                    tuple(rule.get("config", ())), rule.get("home", ""),
                    rule.get("derives_from", ""),
                ))
        self.assertEqual(sorted(install._EMBEDDED_RULES, key=repr), sorted(rules, key=repr))

    def test_every_config_file_read_is_published(self):
        """The registry published five RetroArch config files and the fixed
        RetroDECK folder, but the installer also read Snap, the older macOS file,
        C:\\RetroArch, Program Files, ES-DE, Steam and RetroDECK's own
        config. A manifest reader saw a subset of what the installer does."""
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {
                "HOME": str(root / "home"), "APPDATA": str(root / "appdata"),
                "ProgramFiles": str(root / "pf"), "ProgramFiles(x86)": str(root / "pf86"),
                # Not the host's: a WSL session can hold them.
                "USERPROFILE": "", "LOCALAPPDATA": "", "ProgramData": "",
                "SCOOP": "", "SCOOP_GLOBAL": "",
            }

            def expand(text: str) -> str:
                text = text.replace("$HOME", env["HOME"])
                for var in ("ProgramFiles(x86)", "ProgramFiles", "APPDATA"):
                    text = text.replace(f"%{var}%", env[var])
                return str(Path(text.replace("\\", "/")))

            published = {
                (rule["os"], expand(rule["config"]))
                for entry in registry["platforms"].values()
                for rule in (entry.get("install") or {}).get("detect", [])
                if rule["method"] == "config_file"
            }
            read: set[tuple[str, str]] = set()

            def record(os_type: str):
                def probe(path, *_args, **_kwargs):
                    read.add((os_type, str(Path(str(path).replace("\\", "/")))))
                    return
                return probe

            with unittest.mock.patch.dict(os.environ, env), \
                    unittest.mock.patch.object(install, "_detect_embedded", list), \
                    unittest.mock.patch.object(install, "_detect_android", list):
                for os_type in ("linux", "darwin", "windows"):
                    with unittest.mock.patch.object(
                        install, "_parse_retroarch_system_dir", record(os_type)
                    ):
                        install.detect_platforms(os_type)
                with unittest.mock.patch.object(Path, "is_file", lambda _self: True):
                    for folder in install._windows_retroarch_dirs():
                        read.add(("windows", str(folder / "retroarch.cfg")))
            retrodeck = root / "home/.var/app/net.retrodeck.retrodeck/config/retrodeck"
            read |= {("linux", str(retrodeck / "retrodeck.json")),
                     ("linux", str(retrodeck / "retrodeck.cfg"))}
            # The default Steam library is the Program Files one, already read.
            self.assertEqual(sorted(read - published), [])

    def test_the_first_embedded_match_wins(self):
        with unittest.mock.patch.object(install, "_parse_os_release", return_value={}), \
                unittest.mock.patch.object(
                    Path, "exists",
                    lambda p: str(p) in ("/usr/share/knulli/knulli.version",
                                       "/usr/share/batocera/batocera.version"),
                ):
            self.assertEqual(install._detect_embedded(), [("knulli", Path("/userdata/bios"))])
        # What ROCKNIX writes since 2025: OS_NAME and HW_DEVICE, no ID.
        with unittest.mock.patch.object(install, "_parse_os_release",
                                        return_value={"OS_NAME": "ROCKNIX", "HW_DEVICE": "RK3566"}):
            self.assertEqual(
                install._detect_embedded(), [("rocknix", Path("/storage/roms/bios"))]
            )

    def _home(self) -> Path:
        home = scratch_dir(self)
        patcher = unittest.mock.patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return home

    def test_a_home_layout_is_detected(self):
        home = self._home()
        (home / "RetroPie" / "BIOS").mkdir(parents=True)
        found: list = []
        install._detect_by_path("linux", found)
        self.assertIn(("retropie", home / "RetroPie" / "BIOS"), found)

    def test_bizhawk_is_found_by_its_executable(self):
        """~/.config/BizHawk/Firmware is a folder no build reads: the
        archive extracted to ~/Games/BizHawk-2.11.1 reads the Firmware folder
        beside EmuHawkMono.sh."""
        home = self._home()
        extracted = home / "Games" / "BizHawk-2.11.1"
        extracted.mkdir(parents=True)
        (extracted / "EmuHawkMono.sh").write_text("#!/bin/sh\n")
        found: list = []
        install._detect_by_executable("linux", found)
        self.assertEqual(found, [("bizhawk", extracted / "Firmware")])
        self.assertNotIn("bizhawk", install._os_default_dests("linux"))
        self.assertNotIn("bizhawk", install._os_default_dests("windows"))

    def test_a_portable_platform_is_not_guessed(self):
        """--platform bizhawk with no install found wrote 924 files into
        ~/.config/BizHawk/Firmware, then detected that folder next time."""
        home = self._home()
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--platform", "bizhawk"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install.main()
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("--dest", err.getvalue())
        self.assertFalse((home / ".config" / "BizHawk").exists())

    def test_the_executable_table_is_the_registry(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        rules = {
            (rule["os"], name, tuple(rule["file"]), rule["bios_subdir"])
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "executable"
        }
        self.assertEqual(set(install._EXE_RULES), rules)

    def test_a_windows_profile_path_is_detected(self):
        home = self._home()
        (home / "BizHawk" / "Firmware").mkdir(parents=True)
        found: list = []
        install._detect_by_path("windows", found)
        self.assertEqual(found, [("bizhawk", home / "BizHawk" / "Firmware")])

    def test_a_platform_already_found_is_not_added_again(self):
        home = self._home()
        (home / "Emulation" / "bios").mkdir(parents=True)
        found = [("emudeck", home / "elsewhere" / "bios")]
        install._detect_by_path("linux", found)
        self.assertEqual(found, [("emudeck", home / "elsewhere" / "bios")])

    def test_emudeck_on_macos_is_found_by_its_settings(self):
        """EmuDeck's macOS build reads ~/.config/EmuDeck/settings.sh as the
        Linux one does (functions/all.sh:3-4,24, vars.sh:2): a Mac with
        EmuDeck detected nothing and was offered RetroArch's folder."""
        home = self._home()
        settings = home / ".config" / "EmuDeck" / "settings.sh"
        settings.parent.mkdir(parents=True)
        settings.write_text(f"emulationPath={home / 'Games' / 'Emulation'}\n")
        self.assertIn(("emudeck", home / "Games" / "Emulation" / "bios"),
                      install.detect_platforms("darwin"))
        settings.unlink()
        (home / "Emulation" / "bios").mkdir(parents=True)
        self.assertIn(("emudeck", home / "Emulation" / "bios"),
                      install.detect_platforms("darwin"))


class TestDetectedPlatformPrompt(unittest.TestCase):
    """With two platforms detected the menu had no quit entry, and q or any
    wrong answer brought back a bare prompt."""

    PLATFORMS = [("emudeck", Path("/e")), ("retroarch", Path("/r"))]

    def _answer(self, *answers: str):
        replies = iter(answers)
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(replies)), \
                contextlib.redirect_stdout(out):
            try:
                result = install._prompt_platform_choice(self.PLATFORMS)
            except SystemExit as exc:
                result = exc
        return result, out.getvalue()

    def test_q_quits_and_the_menu_says_so(self):
        result, out = self._answer("q")
        self.assertIsInstance(result, SystemExit)
        self.assertEqual(result.code, install.QUIT_CODE)
        self.assertIn("q) quit", out)

    def test_a_wrong_answer_names_the_choices(self):
        result, out = self._answer("x", "2")
        self.assertEqual(result, [self.PLATFORMS[1]])
        self.assertIn("Type a number from 1 to 2, or q to quit.", out)

    def test_enter_takes_the_first_and_there_is_no_all(self):
        """The screen focuses the first and has no All."""
        result, out = self._answer("")
        self.assertEqual(result, [self.PLATFORMS[0]])
        self.assertNotIn("All", out)


class TestManualPlatformPrompt(unittest.TestCase):
    """With nothing detected, an interactive run asks instead of exiting.

    Every test runs on no drive and a home of its own: two read the host's
    drives and home, and failed with a card in the reader."""

    def setUp(self):
        home = scratch_dir(self)
        for patcher in (unittest.mock.patch.object(install, "_mounted_cards", return_value=[]),
                        unittest.mock.patch.object(install, "_mount_points",
                                                   return_value=frozenset()),
                        unittest.mock.patch.object(install.Path, "home", return_value=home),
                        unittest.mock.patch.dict(os.environ, {"HOME": str(home)}),
                        unittest.mock.patch("sys.stdout", io.StringIO())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_host_is_not_read(self):
        self.assertEqual(install._mounted_cards(), [])
        self.assertEqual(install._default_dest("linux", "retroarch"),
                         Path.home() / ".config" / "retroarch" / "system")

    def test_number_picks_the_platform_and_default_directory(self):
        answers = iter(["1", ""])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(
            chosen, [("retroarch", Path.home() / ".config" / "retroarch" / "system")]
        )

    def test_enter_takes_retroarch_as_the_dest_menu_does(self):
        """The --dest menu offered `[Enter for RetroArch]` and this one, the
        same list, had no default."""
        answers = iter(["", ""])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen[0][0], "retroarch")

    def test_name_and_explicit_directory(self):
        answers = iter(["batocera", "~/my bios"])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("batocera", Path("~/my bios").expanduser())])

    def test_default_directory_comes_from_the_table(self):
        answers = iter(["retropie", ""])
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("retropie", install.DEFAULT_DESTS["retropie"])])

    def test_lakka_on_a_computer_asks_for_its_card(self):
        """/storage/system, a folder only the Lakka machine has, was taken
        on a computer: Lakka keeps its BIOS on its card's STORAGE part."""
        card = scratch_dir(self)
        (card / ".config" / "retroarch").mkdir(parents=True)
        (card / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "/tmp/system"\n')
        answers = iter(["lakka"])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[card]), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("lakka", card / "system")])
        self.assertIn("Lakka card found", out.getvalue())

    def test_batocera_on_a_computer_gets_no_default(self):
        """/userdata/bios, a folder only the Batocera
        machine has, was offered on a computer, and Enter took it."""
        answers = iter(["batocera", "", "~/share/bios"])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                unittest.mock.patch.object(install, "_mounted_cards", return_value=[]), \
                contextlib.redirect_stdout(out):
            chosen = install._prompt_manual_platform("linux")
        self.assertEqual(chosen, [("batocera", Path("~/share/bios").expanduser())])
        self.assertIn("SHARE drive", out.getvalue())
        self.assertNotIn("/userdata/bios", out.getvalue())

    def test_quit_stops_like_ctrl_c(self):
        """`install.sh && retroarch` went on to start RetroArch with no BIOS
        after a q, which left with 0 where Ctrl+C leaves with 130."""
        with unittest.mock.patch("builtins.input", lambda _prompt="": "q"), \
                self.assertRaises(SystemExit) as raised:
            install._prompt_manual_platform("linux")
        self.assertEqual(raised.exception.code, install.QUIT_CODE)

    def test_quotes_around_a_typed_folder_are_dropped(self):
        """Explorer's "Copy as path" quotes the folder: the files went into a
        folder named `"` under the current directory, and the run said Done."""
        root = scratch_dir(self)
        for typed in (f'"{root}/My Card/bios"', f"'{root}/My Card/bios'",
                      f'  "{root}/My Card/bios"  ',
                      # A half-selected copy: line mode kept the quote.
                      f'"{root}/My Card/bios'):
            answers = iter(["1", typed])
            with self.subTest(typed=typed), \
                    unittest.mock.patch("builtins.input",
                                        lambda _prompt="", answers=answers: next(answers)), \
                    contextlib.redirect_stdout(io.StringIO()):
                chosen = install._prompt_manual_platform("linux")
            self.assertEqual(chosen, [("retroarch", root / "My Card" / "bios")])

    def test_home_and_variables_are_expanded_on_every_system(self):
        for os_type in ("linux", "windows", "darwin"):
            answers = iter(["1", '"~/$RB_TEST_DIR/bios"'])
            with self.subTest(os_type=os_type), \
                    unittest.mock.patch.dict(os.environ, {"RB_TEST_DIR": "cards"}), \
                    unittest.mock.patch("builtins.input",
                                        lambda _prompt="", answers=answers: next(answers)), \
                    contextlib.redirect_stdout(io.StringIO()):
                chosen = install._prompt_manual_platform(os_type)
            self.assertEqual(chosen[0][1], Path.home() / "cards" / "bios")

    def test_a_default_folder_not_there_is_not_found(self):
        """With nothing installed, Enter printed "Found RetroArch at" a
        folder that did not exist."""
        root = scratch_dir(self)
        answers = iter(["1", ""])
        out = io.StringIO()
        with unittest.mock.patch.object(install, "_default_dest",
                                        return_value=root / "retroarch" / "system"), \
                unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_manual_platform("linux")
        self.assertIn("default BIOS folder", out.getvalue())
        self.assertIn("will be created", out.getvalue())
        self.assertNotIn("Found", out.getvalue())

    def test_a_wrong_answer_says_what_to_type(self):
        answers = iter(["99", "1", ""])
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            install._prompt_manual_platform("linux")
        self.assertIn("or q to quit", out.getvalue())

    def test_windows_hint_shows_the_one_liner_with_arguments(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "ps1"}):
            hint = "\n".join(install._manual_usage_hint("windows"))
        self.assertIn("--platform retroarch --dest", hint)
        self.assertIn("/i.ps1", hint)


class AnUnreadableRetroDeckConfigIsSaid(unittest.TestCase):
    """retrodeck.json present but unreadable: the installer wrote to
    ~/retrodeck without a word, where a home moved to an SD card is not."""

    def test_the_fallback_is_announced(self):
        import contextlib

        home = scratch_dir(self)
        conf = home / ".var" / "app" / "net.retrodeck.retrodeck" / "config" / "retrodeck"
        conf.mkdir(parents=True)
        (conf / "retrodeck.json").write_text("{truncated")
        err = io.StringIO()
        with unittest.mock.patch.object(install.Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_detect_embedded", return_value=[]), \
                contextlib.redirect_stderr(err):
            found = install.detect_platforms("linux")
        self.assertIn(("retrodeck", home / "retrodeck"), found)
        self.assertIn("could not read paths.rd_home_path", err.getvalue())


class RetroDeckFoldersMovedOneByOne(unittest.TestCase):
    """RetroDECK moves its bios folder on its own and records the new place
    in retrodeck.json paths.bios_path, but only rd_home_path was read: the
    files went to <home>/bios, a folder RetroDECK no longer reads."""

    def _detect(self, paths: dict) -> tuple[Path, list]:
        home = scratch_dir(self)
        conf = home / ".var/app/net.retrodeck.retrodeck/config/retrodeck"
        conf.mkdir(parents=True)
        (conf / "retrodeck.json").write_text(json.dumps({"paths": paths}))
        with unittest.mock.patch.object(install.Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_detect_embedded", return_value=[]), \
                unittest.mock.patch.object(install.MOVED, "_by_root", {}), \
                contextlib.redirect_stderr(io.StringIO()):
            found = install.detect_platforms("linux")
            dests = {name: install._destination_path(home / "retrodeck", f"{name}/a.bin")
                     for name in ("bios", "roms", "saves")}
            label = install.found_label("retrodeck", home / "retrodeck")
        return home, [found, dests, label]

    def test_a_moved_bios_folder_is_followed(self):
        home = scratch_dir(self)
        sd = home / "sd"
        root, (found, dests, label) = self._detect({
            "rd_home_path": "", "bios_path": str(sd / "bios"), "roms_path": str(sd / "roms"),
        })
        rd_home = root / "retrodeck"
        self.assertIn(("retrodeck", rd_home), found)
        self.assertEqual(dests["bios"], (sd / "bios").resolve() / "a.bin")
        self.assertEqual(dests["roms"], (sd / "roms").resolve() / "a.bin")
        self.assertEqual(dests["saves"], rd_home.resolve() / "saves" / "a.bin")
        self.assertIn(f"bios/ at {sd / 'bios'}", label)

    def test_folders_in_place_change_nothing(self):
        home = scratch_dir(self)
        rd_home = home / "rd"
        _root, (found, dests, label) = self._detect({
            "rd_home_path": str(rd_home), "bios_path": str(rd_home / "bios"),
        })
        self.assertIn(("retrodeck", rd_home), found)
        self.assertNotIn("bios/ at", label)

    def test_a_run_that_never_detects_follows_the_move(self):
        """--platform retrodeck --dest D never detects, and the full-screen
        interface passes --dest to every child run: the files went to
        <home>/bios before a detection had filled the moved folders."""
        home = scratch_dir(self)
        sd = home / "sd"
        conf = home / ".var/app/net.retrodeck.retrodeck/config/retrodeck"
        conf.mkdir(parents=True)
        (conf / "retrodeck.json").write_text(json.dumps({"paths": {
            "rd_home_path": "", "bios_path": str(sd / "bios")}}))
        with unittest.mock.patch.object(install.Path, "home", return_value=home), \
                unittest.mock.patch.object(install.MOVED, "_by_root", {}):
            dest = install._destination_path(home / "retrodeck", "bios/a.bin")
            other = install._destination_path(home / "elsewhere", "bios/a.bin")
        self.assertEqual(dest, (sd / "bios").resolve() / "a.bin")
        self.assertEqual(other, (home / "elsewhere").resolve() / "bios" / "a.bin")


class TheInstallerPageNamesEveryEvidence(unittest.TestCase):
    """The page said BizHawk, RetroBat, RomM and RetroPie had no detection
    and fell back to ~/bios, while install.py found each by its directory."""

    def test_every_rule_is_on_the_page(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        page = page.replace("\\\\", "\\")
        expected = [path for rule in install._EMBEDDED_RULES
                    if rule.method == "file_exists" for path in rule.values]
        expected += [rule.name for rule in install._EMBEDDED_RULES]
        expected += [path.replace("$HOME", "~").rstrip("/")
                     for _os, _p, path, _b in install._PATH_RULES]
        missing = [path for path in expected if path not in page]
        self.assertEqual(missing, [])
        self.assertNotIn("have no detection", page)


class BizHawkIsFoundWhereItReads(unittest.TestCase):
    """BizHawk reads <data dir>/Firmware: $BIZHAWK_DATA_HOME on Unix (the
    Nix package sets $XDG_DATA_HOME/emuhawk-monort-<version>), else the
    EmuHawk folder. Only two conventional folders were looked at, and a
    forced --platform bizhawk wrote where EmuHawk never reads."""

    def test_the_data_home_variable(self):
        home = scratch_dir(self)
        with unittest.mock.patch.dict(os.environ, {"BIZHAWK_DATA_HOME": str(home)}):
            self.assertEqual(install._bizhawk_unix_firmware(), home / "Firmware")

    def test_the_nix_data_home(self):
        xdg = scratch_dir(self)
        (xdg / "emuhawk-monort-2.11.1").mkdir()
        env = {"XDG_DATA_HOME": str(xdg), "BIZHAWK_DATA_HOME": ""}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(
                install._bizhawk_unix_firmware(), xdg / "emuhawk-monort-2.11.1" / "Firmware"
            )

    def test_launchbox_names_emuhawk(self):
        source = " ".join((REPO_ROOT / "install.py").read_text(encoding="utf-8").split())
        self.assertIn('.get("emuhawk.exe")', source)


class QuitMeansNoAtTheLastQuestion(unittest.TestCase):
    """Every menu taught q as quit, yet at "Download 3.2 GB ...? [Y/n]" a q
    started the download."""

    def test_quit_words_refuse(self):
        for answer, expected in (("q", False), ("quit", False), ("exit", False),
                                 ("n", False), ("No", False), ("", True), ("y", True)):
            with self.subTest(answer=answer), \
                    unittest.mock.patch.object(install, "_ask", return_value=answer):
                self.assertIs(install._confirm("? "), expected)


class WindowsSeenFromWsl(unittest.TestCase):
    """Under WSL, C:\\RetroBat\\bios was a relative path, %APPDATA% and
    %USERPROFILE% were unset, and --platform retrobat wrote 7 753 files into
    ~/bios inside the distribution, where RetroBat reads nothing."""

    def setUp(self):
        self.root = scratch_dir(self)
        patcher = unittest.mock.patch.dict(install._WSL, {"active": True, "root": str(self.root)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_drive_path_is_its_mount(self):
        self.assertEqual(install._host_path("C:\\RetroBat\\bios"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._rule_path("C:\\RetroBat\\bios"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._default_dest("wsl", "retrobat"), self.root / "c" / "RetroBat" / "bios")
        self.assertEqual(install._host_path("relative/path"), Path("relative/path"))

    def test_retrobat_on_the_windows_side_is_detected(self):
        (self.root / "c" / "RetroBat" / "bios").mkdir(parents=True)
        found: list = []
        install._detect_by_path("wsl", found)
        self.assertIn(("retrobat", self.root / "c" / "RetroBat" / "bios"), found)

    def test_retroarch_beside_its_exe_on_the_windows_side_is_detected(self):
        """The installer page said both sides are searched under WSL, and
        RetroArch's install folders were looked in on Windows only: a
        C:\\RetroArch-Win64 was never found from WSL."""
        exe_dir = self.root / "c" / "RetroArch-Win64"
        exe_dir.mkdir(parents=True)
        (exe_dir / "retroarch.exe").write_bytes(b"MZ")
        home = scratch_dir(self)
        cleared = {name: "" for name in (*install._WINDOWS_VARIABLES, "SCOOP", "SCOOP_GLOBAL",
                                         "ProgramData")}
        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home)}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            found = install.detect_platforms("wsl")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_the_windows_variables_are_read_through_cmd(self):
        answers = {"USERPROFILE": "C:\\Users\\me", "APPDATA": "C:\\Users\\me\\AppData\\Roaming"}

        def cmd(argv, **kwargs):
            # cmd.exe must not read the terminal: it swallowed the answer
            # typed at the first prompt.
            self.assertIs(kwargs.get("stdin"), subprocess.DEVNULL)
            name = argv[-1].split("%")[1]
            return subprocess.CompletedProcess(argv, 0, answers.get(name, f"%{name}%") + "\r\n", "")

        cleared = {name: "" for name in install._WINDOWS_VARIABLES}
        with unittest.mock.patch.dict(os.environ, cleared), \
                unittest.mock.patch.object(install.subprocess, "run", cmd):
            install._enter_wsl()
            self.assertEqual(os.environ["USERPROFILE"], str(self.root / "c" / "Users" / "me"))
            self.assertEqual(os.environ["APPDATA"],
                             str(self.root / "c" / "Users" / "me" / "AppData" / "Roaming"))
            # ProgramFiles among them: cmd answered %ProgramFiles% unexpanded.
            for name in sorted(set(install._WINDOWS_VARIABLES) - answers.keys()):
                with self.subTest(variable=name):
                    self.assertEqual(os.environ[name], "")


    def test_a_steam_client_outside_program_files_is_found(self):
        """A Steam client in D:\\Steam hid every library: only Program Files
        was searched, and Steam's RetroArch was not detected."""
        empty = self.root / "c" / "Program Files (x86)"
        empty.mkdir(parents=True)
        common = self.root / "d" / "steam" / "steamapps" / "common" / "RetroArch"
        common.mkdir(parents=True)
        (common / "retroarch.exe").write_bytes(b"MZ")
        (common / "retroarch.cfg").write_text('system_directory = "default"\n')
        home = scratch_dir(self)
        cleared = {name: "" for name in (*install._WINDOWS_VARIABLES, "SCOOP", "SCOOP_GLOBAL",
                                         "ProgramData")}
        asked: list = []

        def registry(key, value):
            asked.append((key, value))
            return "d:/steam" if (key, value) == ("HKCU\\Software\\Valve\\Steam",
                                                  "SteamPath") else None

        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home),
                                                   "ProgramFiles(x86)": str(empty)}), \
                unittest.mock.patch.object(Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_read_registry", registry):
            self.assertEqual(install._steam_libraries(), [self.root / "d" / "steam"])
            found = install.detect_platforms("wsl")
        self.assertIn(("retroarch", common / "system"), found)

    def test_windows_not_answering_is_said_not_taken_for_nothing(self):
        """cmd.exe timing out on the first variable ended the import without
        a word, and detection said no setup was installed."""
        calls: list = []

        def slow(argv, **kwargs):
            calls.append(argv)
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 10))

        cleared = {name: "" for name in install._WINDOWS_VARIABLES}
        home = scratch_dir(self)
        err = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {**cleared, "HOME": str(home)}), \
                unittest.mock.patch.object(install.subprocess, "run", slow), \
                unittest.mock.patch.object(Path, "home", return_value=home), \
                unittest.mock.patch.object(install, "_DETECTION_REFUSED", []), \
                unittest.mock.patch.object(install.EVENTS, "emit") as emit, \
                contextlib.redirect_stderr(err):
            install._enter_wsl()
            self.assertEqual(len(calls), 1)
            install.detect_platforms("wsl")
            install.detect_platforms("wsl")
        said = err.getvalue()
        self.assertEqual(said.count("on the Windows side"), 1, said)
        self.assertIn("cmd.exe did not answer in 10 s", said)
        kinds = [c.args[0] for c in emit.call_args_list]
        self.assertEqual(kinds.count("unsearched"), 1)
        self.assertEqual(emit.call_args_list[kinds.index("unsearched")].kwargs["folder"],
                         str(self.root))


class NoFallbackOutsideWhatAPlatformReads(unittest.TestCase):
    """A forced platform not found here fell back to ~/bios for RetroBat on
    Linux and for BizHawk from the menu, and on Windows to /userdata/bios,
    which resolves to the root of the current drive. Each run reported done."""

    def test_the_fallback_is_none_where_nothing_is_read(self):
        self.assertIsNone(install._default_dest("linux", "retrobat"))
        self.assertIsNone(install._default_dest("linux", "bizhawk"))
        self.assertIsNone(install._default_dest("windows", "batocera"))
        self.assertIsNone(install._default_dest("windows", "retropie"))
        self.assertEqual(install._default_dest("linux", "batocera"), Path("/userdata/bios"))
        # emudeck-we functions/all.ps1:12-14, not the profile folder.
        self.assertEqual(
            install._default_dest("windows", "emudeck"), install._host_path("C:/Emulation/bios")
        )

    def test_a_forced_platform_without_a_folder_is_refused(self):
        with unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch("sys.argv", ["install.py", "--platform", "retrobat",
                                                 "--no-input"]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as caught:
            install.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("--dest", err.getvalue())


class AQuestionLeftWithCtrlDOrCtrlCIsAStop(unittest.TestCase):
    """Ctrl+C or Ctrl+D at a question left with 0, so `install.sh && retroarch`
    carried on with no BIOS, while the page documents 130."""

    def test_eof_raises_the_stop(self):
        def closed(_prompt=""):
            raise EOFError

        with unittest.mock.patch("builtins.input", closed), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(KeyboardInterrupt):
            install._ask("> ")

    @unittest.skipIf(os.name == "nt", "needs a pseudo-terminal")
    def test_ctrl_d_at_the_platform_question_exits_130(self):
        import pty
        import time

        home = scratch_dir(self)
        master, slave = pty.openpty()
        # Its output on the terminal too: piped, nothing is asked, and the
        # test skipped on every machine.
        proc = subprocess.Popen(
            [sys.executable, "install.py", "--plain"], cwd=REPO_ROOT, stdin=slave,
            stdout=slave, stderr=slave,
            # No request leaves the machine: the standalone emulators' lists
            # come from the network.
            env={**os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
                 "RETROBIOS_INSTALL_OFFLINE": "1"},
        )
        os.close(slave)
        self.addCleanup(os.close, master)
        out = ""
        deadline = time.monotonic() + 60
        while "Which setup?" not in out and proc.poll() is None \
                and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                out += os.read(master, 65536).decode("utf-8", "replace")
        os.write(master, b"\x04")
        proc.wait(timeout=60)
        while select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk.decode("utf-8", "replace")
        if "Which setup?" not in out:
            self.skipTest("a platform was detected on this machine")
        self.assertEqual(proc.returncode, 130, out)
        self.assertIn("Stopped", out)


class DestAloneFollowsWhatIsFoundHere(unittest.TestCase):
    """--dest without --platform always meant RetroArch's list, even on a
    machine where Batocera was found, and nothing said so."""

    def _pick(self, found, interactive=False, answer=""):
        out = io.StringIO()
        with unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch("builtins.input", lambda _prompt="": answer), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                plat, folder = reported(install._platform_for_dest, "linux",
                                        Path("/media/card"), interactive)
                self.assertEqual(folder, Path("/media/card"))
                return plat, out.getvalue()
            except SystemExit as exc:
                return exc, out.getvalue()

    def test_a_card_system_chosen_checks_the_folder(self):
        """The menu offered no card system, and one
        chosen now reads --dest as --platform does."""
        root = scratch_dir(self)
        answers = iter(["Onion", "retroarch"])
        out = io.StringIO()
        with unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                unittest.mock.patch("builtins.input", lambda _prompt="": next(answers)), \
                contextlib.redirect_stdout(out):
            plat, folder = install._platform_for_dest("linux", root, True)
        self.assertEqual((plat, folder), ("retroarch", root))
        self.assertIn(f"{root} is not an Onion SD card", out.getvalue())
        self.assertIn("Onion, SD card (Miyoo Mini, Miyoo Mini Plus)", out.getvalue())

    def test_nothing_found_is_retroarch_said_aloud(self):
        plat, out = self._pick([])
        self.assertEqual(plat, "retroarch")
        self.assertIn("File list: RetroArch (nothing was detected here)", out)

    def test_the_one_platform_found_is_used(self):
        plat, out = self._pick([("batocera", Path("/userdata/bios"))])
        self.assertEqual(plat, "batocera")
        self.assertIn("File list: Batocera", out)

    def test_several_found_without_a_terminal_is_refused(self):
        result, out = self._pick([("emudeck", Path("/e")), ("retroarch", Path("/r"))])
        self.assertIsInstance(result, SystemExit)
        self.assertEqual(result.code, 1)
        self.assertIn("--platform", out)

    def test_a_terminal_asks_and_enter_keeps_the_one_found(self):
        plat, out = self._pick([("batocera", Path("/userdata/bios"))], interactive=True)
        self.assertEqual(plat, "batocera")
        self.assertIn("Which platform's files go to /media/card?", out)


class RetroBatIsFoundWhereItSaysItIs(unittest.TestCase):
    """RetroBat on D:\\RetroBat was not detected, and --platform retrobat
    wrote 7.6 GB into C:\\RetroBat\\bios, a folder it does not read.
    RetroBat.exe writes its folder to the registry on every start."""

    def test_the_table_is_the_registry(self):
        import yaml

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        rules = {
            (rule["os"], name, rule["key"], rule["value"], rule["bios_subdir"])
            for name, entry in registry["platforms"].items()
            for rule in (entry.get("install") or {}).get("detect", [])
            if rule["method"] == "registry"
        }
        self.assertEqual(set(install._REGISTRY_RULES), rules)

    def test_the_registry_folder_wins_over_the_default(self):
        folder = scratch_dir(self)
        with unittest.mock.patch.object(install, "_read_registry",
                                        return_value=str(folder) + "\\"):
            found: list = []
            install._detect_by_registry("windows", found)
        self.assertEqual(found, [("retrobat", folder / "bios")])

    def test_a_folder_since_removed_is_passed_over(self):
        gone = scratch_dir(self) / "moved"
        with unittest.mock.patch.object(install, "_read_registry", return_value=str(gone)):
            found: list = []
            install._detect_by_registry("windows", found)
        self.assertEqual(found, [])

    def test_wsl_reads_it_through_reg_exe(self):
        output = ("\nHKEY_CURRENT_USER\\SOFTWARE\\RetroBat\n"
                  "    LatestKnownInstallPath    REG_SZ    D:\\Games\\RetroBat\\\n\n")
        with unittest.mock.patch.dict(install._WSL, {"active": True, "root": "/mnt"}), \
                unittest.mock.patch.object(install.os, "name", "posix"), \
                unittest.mock.patch.object(
                    install.subprocess, "run",
                    return_value=SimpleNamespace(stdout=output, returncode=0)) as run:
            value = install._read_registry("HKCU\\SOFTWARE\\RetroBat", "LatestKnownInstallPath")
            self.assertEqual(value, "D:\\Games\\RetroBat\\")
            self.assertEqual(install._host_path(value.rstrip("\\")),
                             Path("/mnt/d/Games/RetroBat"))
        self.assertEqual(run.call_args[0][0][:2], ["reg.exe", "query"])


class EmuDeckWindowsIsFoundAsItsScriptsFindIt(unittest.TestCase):
    """EmuDeck's Windows scripts read %APPDATA%\\EmuDeck\\settings.ps1, else
    %USERPROFILE%\\EmuDeck\\settings.ps1, and take C:\\Emulation when neither
    names a folder (functions/all.ps1:4-14). Only the first was read, and a
    forced --platform emudeck wrote into %USERPROFILE%\\Emulation\\bios."""

    def _env(self) -> tuple[Path, Path]:
        root = scratch_dir(self)
        appdata, profile = root / "appdata", root / "profile"
        patcher = unittest.mock.patch.dict(
            os.environ, {"APPDATA": str(appdata), "USERPROFILE": str(profile)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return appdata, profile

    @staticmethod
    def _settings(folder: Path, text: str, encoding: str = "utf-8-sig") -> None:
        (folder / "EmuDeck").mkdir(parents=True, exist_ok=True)
        (folder / "EmuDeck" / "settings.ps1").write_bytes(text.encode(encoding))

    def test_the_profile_settings_are_read_when_appdata_has_none(self):
        _appdata, profile = self._env()
        self._settings(profile, '\n$emulationPath="/games/Emulation"\n')
        self.assertEqual(install._emudeck_windows_bios(), Path("/games/Emulation/bios"))

    def test_appdata_comes_first(self):
        appdata, profile = self._env()
        self._settings(profile, '$emulationPath="/b/Emulation"\n')
        self._settings(appdata, '$emulationPath="/a/Emulation"\n', "utf-16")
        self.assertEqual(install._emudeck_windows_bios(), Path("/a/Emulation/bios"))

    def test_settings_naming_no_folder_mean_c_emulation(self):
        appdata, _profile = self._env()
        self._settings(appdata, '$device="Windows"\n')
        self.assertEqual(install._emudeck_windows_bios(),
                         install._host_path("C:\\Emulation") / "bios")

    def test_a_network_install_is_its_share(self):
        appdata, _profile = self._env()
        self._settings(appdata, '$networkInstallation="true"\n'
                       '$VolName="/nas/games"\n'
                       '$emulationPath=$testdrive.ToString() + ":\\Emulation"\n')
        self.assertEqual(install._emudeck_windows_bios(),
                         Path("/nas/games\\Emulation") / "bios")

    def test_no_settings_detects_nothing(self):
        self._env()
        self.assertIsNone(install._emudeck_windows_bios())

    def test_a_forced_platform_falls_back_to_c_emulation(self):
        self.assertEqual(install._default_dest("windows", "emudeck"),
                         install._host_path("C:/Emulation/bios"))


if __name__ == "__main__":
    unittest.main()
