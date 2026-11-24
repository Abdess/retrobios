"""install.py reads each setup's config files and finds RetroArch and LaunchBox where they keep their BIOS."""
from __future__ import annotations

import tests
from tests import scratch_dir

import functools
import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_config")


class TestShellUnquote(unittest.TestCase):
    def test_plain_value(self):
        self.assertEqual(install._shell_unquote("/userdata/bios"), "/userdata/bios")

    def test_double_quoted(self):
        self.assertEqual(install._shell_unquote('"/home/deck/Emulation"'), "/home/deck/Emulation")

    def test_single_quoted(self):
        self.assertEqual(install._shell_unquote("'/home/deck/Emulation'"), "/home/deck/Emulation")

    def test_concatenated_quoted_unquoted(self):
        # EmuDeck SD card layout (issue: quote left in the middle of the path)
        self.assertEqual(
            install._shell_unquote('"/run/media/deck/EmuSD"/Emulation'),
            "/run/media/deck/EmuSD/Emulation",
        )

    def test_concatenated_preserves_spaces_in_quotes(self):
        self.assertEqual(
            install._shell_unquote('"/run/media/deck/My Card"/Emulation'),
            "/run/media/deck/My Card/Emulation",
        )

    def test_home_variable_expansion(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            self.assertEqual(
                install._shell_unquote('"$HOME"/Emulation'),
                "/home/deck/Emulation",
            )
            self.assertEqual(
                install._shell_unquote('"${HOME}/Emulation"'),
                "/home/deck/Emulation",
            )
        finally:
            if old is not None:
                os.environ["HOME"] = old

    def test_single_quotes_do_not_expand(self):
        self.assertEqual(install._shell_unquote("'$HOME/x'"), "$HOME/x")

    def test_trailing_comment(self):
        self.assertEqual(install._shell_unquote("/data/bios # main dir"), "/data/bios")

    def test_unquoted_stops_at_whitespace(self):
        self.assertEqual(install._shell_unquote("/data/bios extra"), "/data/bios")

    def test_tilde_expansion(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            self.assertEqual(install._shell_unquote("~/Emulation"), "/home/deck/Emulation")
        finally:
            if old is not None:
                os.environ["HOME"] = old


class TestParseBashVar(unittest.TestCase):
    def _write(self, content: str) -> Path:
        fd, path = tempfile.mkstemp(suffix=".sh")
        os.close(fd)
        Path(path).write_text(content, encoding="utf-8")
        self.addCleanup(os.unlink, path)
        return Path(path)

    def test_emudeck_sd_card_concatenation(self):
        path = self._write(
            'emulationPath="/run/media/deck/EmuSD"/Emulation\n'
            'biosPath="/run/media/deck/EmuSD"/Emulation/bios\n'
        )
        self.assertEqual(
            install._parse_bash_var(path, "emulationPath"),
            "/run/media/deck/EmuSD/Emulation",
        )
        self.assertEqual(
            install._parse_bash_var(path, "biosPath"),
            "/run/media/deck/EmuSD/Emulation/bios",
        )

    def test_emudeck_home_variable(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = "/home/deck"
        try:
            path = self._write('emulationPath="$HOME"/Emulation\n')
            self.assertEqual(
                install._parse_bash_var(path, "emulationPath"),
                "/home/deck/Emulation",
            )
        finally:
            if old is not None:
                os.environ["HOME"] = old

    def test_missing_key(self):
        path = self._write("other=1\n")
        self.assertIsNone(install._parse_bash_var(path, "emulationPath"))

    def test_missing_file(self):
        self.assertIsNone(
            install._parse_bash_var(Path("/nonexistent/settings.sh"), "emulationPath")
        )


class TestParseJsonPath(unittest.TestCase):
    def _write(self, data) -> Path:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        Path(path).write_text(
            data if isinstance(data, str) else json.dumps(data), encoding="utf-8"
        )
        self.addCleanup(os.unlink, path)
        return Path(path)

    def test_retrodeck_rd_home_path(self):
        path = self._write(
            {"version": "1.0", "paths": {"rd_home_path": "/home/deck/retrodeck"}}
        )
        self.assertEqual(
            install._parse_json_path(path, "paths", "rd_home_path"),
            "/home/deck/retrodeck",
        )

    def test_missing_key_returns_none(self):
        path = self._write({"paths": {}})
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_invalid_json_returns_none(self):
        path = self._write("{not json")
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_empty_value_returns_none(self):
        path = self._write({"paths": {"rd_home_path": ""}})
        self.assertIsNone(install._parse_json_path(path, "paths", "rd_home_path"))

    def test_missing_file(self):
        self.assertIsNone(
            install._parse_json_path(Path("/nonexistent/rd.json"), "paths", "rd_home_path")
        )


class TestDefaultDests(unittest.TestCase):
    def test_retrodeck_defaults_to_rdhome(self):
        self.assertEqual(
            install.DEFAULT_DESTS["retrodeck"], Path.home() / "retrodeck"
        )

    def test_known_fixed_paths(self):
        self.assertEqual(install.DEFAULT_DESTS["batocera"], Path("/userdata/bios"))
        self.assertEqual(
            install.DEFAULT_DESTS["recalbox"], Path("/recalbox/share/bios")
        )

    def test_mister_defaults_to_games_on_the_sd_card(self):
        self.assertEqual(
            install.DEFAULT_DESTS["misterfpga"], Path("/media/fat/games")
        )


class TestDefaultsFollowTheRegistry(unittest.TestCase):
    """A platform named but not detected fell back to ~/bios on every OS for
    RetroArch, RetroBat, BizHawk and RomM, a folder none of them reads."""

    ENV = {"USERPROFILE": "/u", "APPDATA": "/u/AppData/Roaming"}

    def _expand(self, raw: str) -> Path:
        text = raw.replace("$HOME", str(Path.home()))
        for name, value in self.ENV.items():
            text = text.replace(f"%{name}%", value)
        return Path(text.replace("\\", "/"))

    def test_the_default_is_a_folder_detection_looks_for(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parent.parent / "platforms" / "_registry.yml")
            .read_text(encoding="utf-8")
        )["platforms"]
        checked = 0
        with unittest.mock.patch.dict(os.environ, self.ENV):
            for name, entry in registry.items():
                by_os: dict[str, set[Path]] = {}
                for rule in (entry.get("install") or {}).get("detect", []):
                    if rule.get("bios_path"):
                        by_os.setdefault(rule["os"], set()).add(self._expand(rule["bios_path"]))
                    elif rule.get("method") == "path_exists":
                        by_os.setdefault(rule["os"], set()).add(self._expand(rule["path"]))
                    elif rule.get("parse_key") == "system_directory":
                        config = self._expand(rule["config"])
                        by_os.setdefault(rule["os"], set()).add(config.parent / "system")
                if name in install.PORTABLE_ONLY:
                    # No folder of its own to fall back on: the run stops
                    # and asks for --dest (test_a_portable_platform_is_not_guessed).
                    continue
                for os_type, candidates in by_os.items():
                    with self.subTest(platform=name, os=os_type):
                        self.assertIn(install._default_dest(os_type, name), candidates)
                        checked += 1
                # The installer's own default comes first in the registry and
                # is the one the pack guide and the installer name.
                first = next(
                    (self._expand(rule["path"]) for rule in (entry.get("install") or {}).get("detect", [])
                     if rule.get("os") == "windows" and rule.get("method") == "path_exists"),
                    None,
                )
                if name == "retrobat":
                    self.assertEqual(install._default_dest("windows", name), first)
        self.assertGreater(checked, 10)


class TestLaunchboxDetection(unittest.TestCase):
    """LaunchBox references its emulators in Data/Emulators.xml."""

    def _make_launchbox(self, app_path: str, title: str = "Retroarch"):
        root = scratch_dir(self)
        data = root / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        xml = data / "Emulators.xml"
        xml.write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            "  <Emulator>\n"
            "    <ID>x</ID>\n"
            f"    <Title>{title}</Title>\n"
            f"    <ApplicationPath>{app_path}</ApplicationPath>\n"
            "  </Emulator>\n"
            "</LaunchBox>\n"
        )
        return root, xml

    def test_relative_application_path(self):
        root, xml = self._make_launchbox("Emulators\\RetroArch\\retroarch.exe")
        ra_dir = root / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), ra_dir / "system"
        )

    def test_absolute_application_path(self):
        emu_dir = scratch_dir(self) / "RetroArch"
        emu_dir.mkdir(parents=True)
        root, xml = self._make_launchbox(str(emu_dir / "retroarch.exe"))
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), emu_dir / "system"
        )

    def test_no_retroarch_entry(self):
        root, xml = self._make_launchbox("Emulators\\PCSX2\\pcsx2.exe", "PCSX2")
        self.assertIsNone(install._launchbox_retroarch_system_dir(xml))

    def test_missing_emulator_directory(self):
        root, xml = self._make_launchbox("Emulators\\RetroArch\\retroarch.exe")
        self.assertIsNone(install._launchbox_retroarch_system_dir(xml))

    def test_stale_entry_before_installed_one(self):
        root = scratch_dir(self)
        data = root / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        ra_dir = root / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        xml = data / "Emulators.xml"
        xml.write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch (old)</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch-old\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "</LaunchBox>\n"
        )
        self.assertEqual(
            install._launchbox_retroarch_system_dir(xml), ra_dir / "system"
        )

    def test_missing_or_malformed_xml(self):
        self.assertIsNone(
            install._launchbox_retroarch_system_dir(Path("/nonexistent/Emulators.xml"))
        )
        root = scratch_dir(self)
        bad = root / "Emulators.xml"
        bad.write_text("not xml at all <<<")
        self.assertIsNone(install._launchbox_retroarch_system_dir(bad))


class TestRetroarchPathExpansion(unittest.TestCase):
    """RetroArch abbreviates paths with '~' and ':' in its config."""

    def _cfg(self, value: str) -> Path:
        app_dir = scratch_dir(self)
        (app_dir / "retroarch.cfg").write_text(f'system_directory = "{value}"\n')
        return app_dir

    def test_application_dir_prefix(self):
        app_dir = self._cfg(":\\system")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            app_dir / "system",
        )

    def test_application_dir_prefix_forward_slash(self):
        app_dir = self._cfg(":/system")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            app_dir / "system",
        )

    def test_home_prefix(self):
        app_dir = self._cfg("~/bios")
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"),
            Path.home() / "bios",
        )

    def test_application_dir_overrides_config_dir(self):
        app_dir = self._cfg(":\\system")
        elsewhere = scratch_dir(self)
        self.assertEqual(
            install._parse_retroarch_system_dir(
                app_dir / "retroarch.cfg", elsewhere
            ),
            elsewhere / "system",
        )

    def test_absolute_path_untouched(self):
        target = scratch_dir(self) / "bios"
        app_dir = self._cfg(str(target))
        self.assertEqual(
            install._parse_retroarch_system_dir(app_dir / "retroarch.cfg"), target
        )


class TestLaunchboxRoot(unittest.TestCase):
    """LaunchBox installs where the user chooses and keeps no registry key."""

    def _make_root(self, root: Path) -> Path:
        (root / "Data").mkdir(parents=True)
        (root / "Data" / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n<LaunchBox></LaunchBox>\n"
        )
        return root

    def test_shortcut_target_is_read(self):
        # Byte layout of the shortcut a real install writes
        lnk = scratch_dir(self) / "LaunchBox.lnk"
        lnk.write_bytes(
            b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
            b"\x00\x00\x00\x46" + b"\x00" * 8
            + b"C:\\Games\\LaunchBox\\Core\\LaunchBox.exe\x00"
            b"\x1c\x00\x00\x00LaunchBox\x00"
        )
        self.assertEqual(
            install._lnk_target(lnk, "LaunchBox.exe"),
            Path("C:/Games/LaunchBox/Core/LaunchBox.exe"),
        )

    def test_shortcut_without_target_is_ignored(self):
        lnk = scratch_dir(self) / "LaunchBox.lnk"
        lnk.write_bytes(b"L\x00\x00\x00 no target here ")
        self.assertIsNone(install._lnk_target(lnk, "LaunchBox.exe"))

    def test_shortcut_pointing_elsewhere_falls_back(self):
        # A stale shortcut must not win over a real installation
        userprofile = scratch_dir(self)
        root = self._make_root(userprofile / "LaunchBox")
        appdata = scratch_dir(self)
        lnk_dir = (
            appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "LaunchBox"
        )
        lnk_dir.mkdir(parents=True)
        (lnk_dir / "LaunchBox.lnk").write_bytes(
            b"L\x00\x00\x00D:\\Gone\\LaunchBox\\Core\\LaunchBox.exe\x00"
        )
        env = {"APPDATA": str(appdata), "USERPROFILE": str(userprofile)}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(install.launchbox_root("windows"), root)

    def test_falls_back_to_userprofile(self):
        userprofile = scratch_dir(self)
        root = self._make_root(userprofile / "LaunchBox")
        env = {"APPDATA": str(scratch_dir(self)), "USERPROFILE": str(userprofile)}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(install.launchbox_root("windows"), root)

    def test_absent_on_linux(self):
        self.assertIsNone(install.launchbox_root("linux"))

    def test_nothing_installed(self):
        env = {
            "APPDATA": str(scratch_dir(self)),
            "USERPROFILE": str(scratch_dir(self)),
        }
        with unittest.mock.patch.dict(os.environ, env):
            self.assertIsNone(install.launchbox_root("windows"))


class TestLaunchboxBiosDirs(unittest.TestCase):
    """LaunchBox computes where each emulator it manages keeps its BIOS."""

    def _make(self, entries: list[tuple[str, str]]) -> Path:
        root = scratch_dir(self) / "LaunchBox"
        (root / "Data").mkdir(parents=True)
        body = "".join(
            "  <Emulator>\n"
            f"    <Title>{title}</Title>\n"
            f"    <ApplicationPath>{app}</ApplicationPath>\n"
            "  </Emulator>\n"
            for title, app in entries
        )
        (root / "Data" / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            f"<LaunchBox>\n{body}</LaunchBox>\n"
        )
        for _, app in entries:
            (root / Path(app.replace("\\", "/")).parent).mkdir(parents=True, exist_ok=True)
        return root

    def test_pcsx2_portable_default_bios(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.ini").write_text("")
        (emu / "inis").mkdir()
        (emu / "inis" / "PCSX2.ini").write_text("[Folders]\nBios = bios\n")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], emu / "bios")

    def test_pcsx2_portable_absolute_bios(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        elsewhere = scratch_dir(self) / "ps2bios"
        (emu / "portable.ini").write_text("")
        (emu / "inis").mkdir()
        (emu / "inis" / "PCSX2.ini").write_text(f"Bios = {elsewhere}\n")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], elsewhere)

    def test_pcsx2_portable_txt_also_triggers_portable_mode(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.txt").write_text("")
        self.assertEqual(install.launchbox_bios_dirs(root)["pcsx2"], emu / "bios")

    def test_pcsx2_portable_txt_names_a_data_root(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        emu = root / "Emulators" / "PCSX2"
        (emu / "portable.txt").write_text("mydata\n")
        self.assertEqual(
            install.launchbox_bios_dirs(root)["pcsx2"], emu / "mydata" / "bios"
        )

    def test_pcsx2_without_config_uses_documents(self):
        root = self._make([("PCSX2", "Emulators\\PCSX2\\pcsx2.exe")])
        userprofile = scratch_dir(self)
        with unittest.mock.patch.dict(os.environ, {"USERPROFILE": str(userprofile)}):
            self.assertEqual(
                install.launchbox_bios_dirs(root)["pcsx2"],
                userprofile / "Documents" / "PCSX2" / "bios",
            )

    def test_xemu_defaults_to_bios_folder(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        with unittest.mock.patch.dict(os.environ, {"APPDATA": str(scratch_dir(self))}):
            self.assertEqual(install.launchbox_bios_dirs(root)["xemu"], emu / "bios")

    def test_xemu_honours_configured_bootrom(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        configured = scratch_dir(self) / "xbox"
        configured.mkdir()
        (configured / "mcpx_1.0.bin").write_text("x")
        (emu / "xemu.toml").write_text(
            "[sys.files]\n"
            f"bootrom_path = '{configured / 'mcpx_1.0.bin'}'\n"
        )
        self.assertEqual(install.launchbox_bios_dirs(root)["xemu"], configured)

    def test_dolphin_portable_user_folder(self):
        root = self._make([("Dolphin", "Emulators\\Dolphin\\Dolphin.exe")])
        emu = root / "Emulators" / "Dolphin"
        (emu / "portable.txt").write_text("")
        self.assertEqual(install.launchbox_bios_dirs(root)["dolphin"], emu / "User")

    def test_dolphin_without_portable_marker_is_absent(self):
        root = self._make([("Dolphin", "Emulators\\Dolphin\\Dolphin.exe")])
        (root / "Emulators" / "Dolphin" / "User").mkdir()
        self.assertNotIn("dolphin", install.launchbox_bios_dirs(root))

    def test_unknown_emulators_are_ignored(self):
        root = self._make([("Cemu", "Emulators\\Cemu\\Cemu.exe")])
        self.assertEqual(install.launchbox_bios_dirs(root), {})

    def test_doctype_is_rejected(self):
        root = scratch_dir(self) / "LaunchBox"
        (root / "Data").mkdir(parents=True)
        (root / "Data" / "Emulators.xml").write_text(
            "<!DOCTYPE LaunchBox [<!ENTITY a 'x'>]>\n<LaunchBox></LaunchBox>\n"
        )
        self.assertEqual(install.launchbox_emulators(root / "Data" / "Emulators.xml"), {})


class RetroArchIsFoundWhereWindowsInstallsPutIt(unittest.TestCase):
    """Program Files\\RetroArch-Win64, a Steam library on another drive and
    an installed ES-DE's Emulators folder all held a RetroArch the one-liner
    reported as "no supported platform detected"."""

    def _env(self, program_files: Path) -> None:
        patcher = unittest.mock.patch.dict(
            os.environ, {"ProgramFiles": str(program_files), "ProgramFiles(x86)": ""}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _exe(folder: Path) -> Path:
        folder.mkdir(parents=True)
        (folder / "retroarch.exe").write_bytes(b"MZ")
        return folder

    def test_program_files_win64(self):
        program_files = scratch_dir(self)
        self._env(program_files)
        found = self._exe(program_files / "RetroArch-Win64")
        self.assertIn(found, install._windows_retroarch_dirs())

    def test_a_scoop_install(self):
        # `scoop install retroarch` puts it under ~/scoop/apps/retroarch/current,
        # which none of the searched folders covered.
        program_files = scratch_dir(self)
        self._env(program_files)
        home = scratch_dir(self)
        found = self._exe(home / "scoop" / "apps" / "retroarch" / "current")
        with unittest.mock.patch.dict(os.environ, {"USERPROFILE": str(home)}):
            os.environ.pop("SCOOP", None)
            self.assertIn(found, install._windows_retroarch_dirs())

    def test_a_steam_library_on_another_drive(self):
        program_files = scratch_dir(self)
        library = scratch_dir(self)
        steamapps = program_files / "Steam" / "steamapps"
        steamapps.mkdir(parents=True)
        (steamapps / "libraryfolders.vdf").write_text(
            '"libraryfolders"\n{\n\t"1"\n\t{\n\t\t"path"\t\t"' + str(library) + '"\n\t}\n}\n'
        )
        self._env(program_files)
        found = self._exe(library / "steamapps" / "common" / "RetroArch")
        self.assertIn(found, install._windows_retroarch_dirs())

    def test_an_installed_es_de(self):
        program_files = scratch_dir(self)
        self._env(program_files)
        found = self._exe(program_files / "ES-DE" / "Emulators" / "RetroArch-Win64")
        self.assertIn(found, install._windows_retroarch_dirs())


class TestSteamRetroarchDetection(unittest.TestCase):
    """The Steam build is a portable install under the default library."""

    def test_steam_library_is_found_on_windows(self):
        program_files = scratch_dir(self)
        ra_dir = program_files / "Steam" / "steamapps" / "common" / "RetroArch"
        ra_dir.mkdir(parents=True)
        (ra_dir / "retroarch.cfg").write_text('system_directory = ":\\system"\n')
        env = {"ProgramFiles(x86)": str(program_files)}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", ra_dir / "system"), found)


class TestLaunchboxDetectionPowershell(unittest.TestCase):
    """install.ps1 must resolve LaunchBox's portable RetroArch on its own."""

    def _run(self, entries: str, seed=None, manifest: dict | None = None):
        userprofile = scratch_dir(self)
        ra_dir = userprofile / "LaunchBox" / "Emulators" / "RetroArch"
        ra_dir.mkdir(parents=True)
        data = userprofile / "LaunchBox" / "Data"
        data.mkdir(parents=True)
        (data / "Emulators.xml").write_text(
            "<?xml version=\"1.0\" standalone=\"yes\"?>\n"
            "<LaunchBox>\n"
            f"{entries}"
            "</LaunchBox>\n"
        )
        if seed is not None:
            seed(userprofile)
        serve_root = scratch_dir(self)
        (serve_root / "install").mkdir()
        payload = dict(manifest if manifest is not None else {"files": []})
        payload.setdefault("manifest_version", 2)
        payload.setdefault("platform", "retroarch")
        payload.setdefault("files", [])
        (serve_root / "install" / "retroarch.json").write_text(json.dumps(payload))
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(serve_root)
        )
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            env = dict(os.environ)
            env.update(
                USERPROFILE=str(userprofile),
                APPDATA=str(scratch_dir(self)),
                RETROBIOS_BASE_URL=f"http://127.0.0.1:{httpd.server_address[1]}",
                # A LaunchBox layout is a Windows layout: the runner is Linux.
                RETROBIOS_OS="wsl",
            )
            proc = subprocess.run(
                [
                    "pwsh", "-NoProfile", "-File",
                    str(REPO_ROOT / "install.ps1"), "--standalone-copies", "--verbose",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()
        return proc, ra_dir

    def _assert_resolved(self, proc, ra_dir):
        self.assertIn("Found LaunchBox", proc.stdout)
        self.assertIn("Found RetroArch at", proc.stdout)
        self.assertIn(str(ra_dir), proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Done.", proc.stdout)

    def test_detects_launchbox_retroarch(self):
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>Retroarch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
        )
        self._assert_resolved(proc, ra_dir)

    def test_stale_entry_before_installed_one(self):
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch (old)</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch-old\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
        )
        self._assert_resolved(proc, ra_dir)

    def test_system_directory_from_config(self):
        def seed(root: Path) -> None:
            ra = root / "LaunchBox" / "Emulators" / "RetroArch"
            (ra / "bios").mkdir(parents=True)
            (ra / "retroarch.cfg").write_text('system_directory = ":\\bios"\n')

        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n",
            seed=seed,
        )
        self.assertIn("Found LaunchBox", proc.stdout)
        self.assertIn("Found RetroArch at", proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(str(ra_dir / "bios"), proc.stdout)

    def test_standalone_copy_reaches_launchbox_emulator(self):
        def seed(root: Path) -> None:
            system = root / "LaunchBox" / "Emulators" / "RetroArch" / "system"
            system.mkdir(parents=True)
            (system / "ps2-0230a.bin").write_text("rom")
            pcsx2 = root / "LaunchBox" / "Emulators" / "PCSX2"
            (pcsx2 / "bios").mkdir(parents=True)
            (pcsx2 / "portable.ini").write_text("")
            (pcsx2 / "inis").mkdir()
            (pcsx2 / "inis" / "PCSX2.ini").write_text("[Folders]\nBios = bios\n")

        # In place with its hash: only a file the run verified is copied.
        manifest = {
            "files": [{"dest": "ps2-0230a.bin", "size": 3, "repo_path": "bios/ps2-0230a.bin",
                       "sha1": "a1e17a20e93e5da710685444df3ad038ac66e2c9"}],
            "standalone_copies": [
                {
                    "pattern": "ps2-*.bin",
                    "emulator": "pcsx2",
                    "targets": {"windows": []},
                }
            ],
        }
        proc, ra_dir = self._run(
            "  <Emulator>\n"
            "    <Title>RetroArch</Title>\n"
            "    <ApplicationPath>Emulators\\RetroArch\\retroarch.exe</ApplicationPath>\n"
            "  </Emulator>\n"
            "  <Emulator>\n"
            "    <Title>PCSX2</Title>\n"
            "    <ApplicationPath>Emulators\\PCSX2\\pcsx2.exe</ApplicationPath>\n"
            "  </Emulator>\n",
            seed=seed,
            manifest=manifest,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        landed = ra_dir.parent / "PCSX2" / "bios" / "ps2-0230a.bin"
        self.assertTrue(landed.exists(), proc.stdout)


class TestForcedOs(unittest.TestCase):
    """RETROBIOS_OS overrides detection with a known name only."""

    def test_known_name_wins(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_OS": "Windows"}):
            self.assertEqual(install.detect_os(), "windows")

    def test_unknown_name_is_ignored(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_OS": "amiga"}):
            self.assertIn(install.detect_os(), ("linux", "wsl", "windows", "darwin"))


class TestDetectFrontends(unittest.TestCase):
    """Frontends have no BIOS directory of their own but hint at the setup."""

    def test_esde_from_home_directory(self):
        home = scratch_dir(self)
        (home / "ES-DE").mkdir()
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old

    def test_esde_from_env_dir(self):
        home = scratch_dir(self)
        appdata = scratch_dir(self)
        os.environ["ESDE_APPDATA_DIR"] = str(appdata)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            del os.environ["ESDE_APPDATA_DIR"]

    def test_nothing_detected(self):
        home = scratch_dir(self)
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertEqual(install.detect_frontends("linux", home=home), [])
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old


class RetroArchWhereItReallyLives(unittest.TestCase):
    """Windows: retroarch.cfg sits beside retroarch.exe and system defaults
    to <exe folder>\\system. Only %APPDATA% was read, and the fallback was a
    folder RetroArch never reads. macOS: the config is under
    Application Support/RetroArch/config, the system folder in Documents."""

    def _exe_dir(self) -> tuple[Path, dict]:
        program_files = scratch_dir(self)
        exe_dir = program_files / "RetroArch"
        exe_dir.mkdir()
        (exe_dir / "retroarch.exe").write_bytes(b"MZ")
        return exe_dir, {"ProgramFiles": str(program_files)}

    def test_windows_install_folder_without_a_config(self):
        exe_dir, env = self._exe_dir()
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_windows_appdata_config_at_default_names_the_exe_folder(self):
        exe_dir, env = self._exe_dir()
        appdata = scratch_dir(self)
        (appdata / "RetroArch").mkdir()
        (appdata / "RetroArch" / "retroarch.cfg").write_text('system_directory = "default"\n')
        env["APPDATA"] = str(appdata)
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", exe_dir / "system"), found)

    def test_windows_config_beside_the_exe_wins(self):
        exe_dir, env = self._exe_dir()
        (exe_dir / "retroarch.cfg").write_text('system_directory = "D:\\bios"\n')
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            found = install.detect_platforms("windows")
        self.assertIn(("retroarch", Path("D:\\bios")), found)

    def test_macos_config_folder_and_documents_default(self):
        home = scratch_dir(self)
        support = home / "Library" / "Application Support" / "RetroArch"
        (support / "config").mkdir(parents=True)
        (support / "config" / "retroarch.cfg").write_text('system_directory = "default"\n')
        with unittest.mock.patch.object(install.Path, "home", return_value=home):
            found = install.detect_platforms("darwin")
            self.assertIn(("retroarch", home / "Documents" / "RetroArch" / "system"), found)
            (support / "portable.txt").write_text("")
            found = install.detect_platforms("darwin")
            self.assertIn(("retroarch", support / "system"), found)


class LinuxRetroArchFollowsXdgConfigHome(unittest.TestCase):
    """RetroArch on Linux keeps its config under $XDG_CONFIG_HOME/retroarch
    when the variable is set, then falls back to ~/.retroarch.cfg
    (file_path_special.c fill_pathname_application_data, configuration.c
    open_default_config_file). Only ~/.config/retroarch was read: a home
    with its own XDG layout detected nothing."""

    def _env(self) -> tuple[Path, Path]:
        home = scratch_dir(self)
        xdg = scratch_dir(self)
        patcher = unittest.mock.patch.dict(os.environ, {"HOME": str(home)}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        return home, xdg

    def test_the_config_under_xdg_config_home_is_read(self):
        home, xdg = self._env()
        (xdg / "retroarch").mkdir()
        (xdg / "retroarch" / "retroarch.cfg").write_text('system_directory = "/srv/bios"\n')
        # A config under ~/.config is not the one this RetroArch opens.
        (home / ".config" / "retroarch").mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "/elsewhere"\n')
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", Path("/srv/bios")), found)
        self.assertNotIn(("retroarch", Path("/elsewhere")), found)
        self.assertEqual(install._os_default_dests("linux")["retroarch"],
                         xdg / "retroarch" / "system")

    def test_home_retroarch_cfg_is_the_fallback(self):
        home, xdg = self._env()
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
        (home / ".retroarch.cfg").write_text('system_directory = "default"\n')
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", xdg / "retroarch" / "system"), found)

    def test_without_the_variable_the_folder_is_under_dot_config(self):
        home, _ = self._env()
        (home / ".config" / "retroarch").mkdir(parents=True)
        (home / ".config" / "retroarch" / "retroarch.cfg").write_text(
            'system_directory = "default"\n')
        found = install.detect_platforms("linux")
        self.assertIn(("retroarch", home / ".config" / "retroarch" / "system"), found)


class RetroArchUwpIsFound(unittest.TestCase):
    """The UWP/MSIX RetroArch keeps retroarch.cfg and system/ in its
    package's LocalState, but no rule looked under %LOCALAPPDATA%\\Packages."""

    def _state(self) -> Path:
        local = scratch_dir(self)
        state = local / "Packages" / f"{install.RETROARCH_UWP_ID}_abc123" / "LocalState"
        state.mkdir(parents=True)
        patcher = unittest.mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)})
        patcher.start()
        self.addCleanup(patcher.stop)
        return state

    def test_the_default_is_local_state_system(self):
        state = self._state()
        self.assertEqual(install._retroarch_uwp_system_dir(), state / "system")

    def test_a_tilde_is_local_state(self):
        state = self._state()
        (state / "retroarch.cfg").write_text('system_directory = "~\\bios"\n')
        self.assertEqual(install._retroarch_uwp_system_dir(), state / "bios")

    def test_nothing_installed(self):
        with unittest.mock.patch.dict(os.environ, {"LOCALAPPDATA": str(scratch_dir(self))}):
            self.assertIsNone(install._retroarch_uwp_system_dir())


class RetroArchAppImageIsPortable(unittest.TestCase):
    """The buildbot's Linux RetroArch is an AppImage beside a .home folder
    the AppImage runtime makes its HOME: the run found nothing and offered
    ~/.config/retroarch/system, a folder this RetroArch never reads."""

    def _detect(self, home: Path, env: dict | None = None) -> list:
        cleared = {"HOME": str(home), "XDG_CONFIG_HOME": ""}
        with unittest.mock.patch.dict(os.environ, {**cleared, **(env or {})}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            os.environ.pop("XDG_CONFIG_HOME")
            return install.detect_platforms("linux")

    def _unpack(self, home: Path) -> Path:
        folder = home / "Downloads" / "RetroArch-Linux-x86_64"
        base = folder / "RetroArch-Linux-x86_64.AppImage.home" / ".config" / "retroarch"
        (base / "system").mkdir(parents=True)
        (folder / "RetroArch-Linux-x86_64.AppImage").write_bytes(b"\x7fELF")
        return base

    def test_the_unpacked_archive_is_found(self):
        home = scratch_dir(self)
        base = self._unpack(home)
        self.assertIn(("retroarch", base / "system"), self._detect(home))

    def test_its_config_is_read_with_its_own_home(self):
        home = scratch_dir(self)
        base = self._unpack(home)
        (base / "retroarch.cfg").write_text('system_directory = "~/bios"\n')
        portable = base.parent.parent
        self.assertIn(("retroarch", portable / "bios"), self._detect(home))

    def test_a_config_folder_beside_it_wins(self):
        home = scratch_dir(self)
        base = self._unpack(home)
        config = base.parent.parent.with_name("RetroArch-Linux-x86_64.AppImage.config")
        (config / "retroarch").mkdir(parents=True)
        found = self._detect(home)
        self.assertIn(("retroarch", config / "retroarch" / "system"), found)
        self.assertNotIn(("retroarch", base / "system"), found)

    def test_a_folder_without_its_appimage_is_left(self):
        home = scratch_dir(self)
        base = self._unpack(home)
        (base.parent.parent.with_name("RetroArch-Linux-x86_64.AppImage")).unlink()
        self.assertNotIn(("retroarch", base / "system"), self._detect(home))


class SteamRetroArchOnMacIsPortable(unittest.TestCase):
    """platform_darwin.m makes the Steam build portable (HAVE_STEAM) with no
    portable.txt: a default system_directory is Application Support's, and
    the installer took ~/Documents/RetroArch/system."""

    def test_the_steam_bundle_moves_the_base(self):
        home = scratch_dir(self)
        support = home / "Library" / "Application Support"
        with unittest.mock.patch.dict(os.environ, {"HOME": str(home)}), \
                unittest.mock.patch.object(Path, "home", return_value=home):
            self.assertEqual(install._macos_retroarch_base(), home / "Documents" / "RetroArch")
            (support / "Steam/steamapps/common/RetroArch/RetroArch.app").mkdir(parents=True)
            self.assertEqual(install._macos_retroarch_base(), support / "RetroArch")


if __name__ == "__main__":
    unittest.main()
