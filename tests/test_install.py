"""Tests for install.py platform detection and config parsing."""
from __future__ import annotations

import functools
import http.server
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


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


class TestEmbeddedDetection(unittest.TestCase):
    """MiSTer is identified by the main binary at the SD card root."""

    def _detect_with(self, existing: set[str], os_id: str = ""):
        real_exists = install.Path.exists
        real_parse = install._parse_os_release

        def fake_exists(self):
            return str(self) in existing

        install.Path.exists = fake_exists
        install._parse_os_release = lambda: {"ID": os_id} if os_id else {}
        try:
            return install._detect_embedded()
        finally:
            install.Path.exists = real_exists
            install._parse_os_release = real_parse

    def test_mister_detected_from_main_binary(self):
        self.assertEqual(
            self._detect_with({"/media/fat/MiSTer"}),
            [("misterfpga", Path("/media/fat/games"))],
        )

    def test_rocknix_wins_over_path_probes(self):
        self.assertEqual(
            self._detect_with({"/media/fat/MiSTer"}, os_id="rocknix"),
            [("rocknix", Path("/storage/roms/bios"))],
        )

    def test_no_embedded_os_detected(self):
        self.assertEqual(self._detect_with(set()), [])


class TestLaunchboxDetection(unittest.TestCase):
    """LaunchBox references its emulators in Data/Emulators.xml."""

    def _make_launchbox(self, app_path: str, title: str = "Retroarch"):
        root = Path(tempfile.mkdtemp())
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
        emu_dir = Path(tempfile.mkdtemp()) / "RetroArch"
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
        root = Path(tempfile.mkdtemp())
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
        root = Path(tempfile.mkdtemp())
        bad = root / "Emulators.xml"
        bad.write_text("not xml at all <<<")
        self.assertIsNone(install._launchbox_retroarch_system_dir(bad))


class TestRetroarchPathExpansion(unittest.TestCase):
    """RetroArch abbreviates paths with '~' and ':' in its config."""

    def _cfg(self, value: str) -> Path:
        app_dir = Path(tempfile.mkdtemp())
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
        elsewhere = Path(tempfile.mkdtemp())
        self.assertEqual(
            install._parse_retroarch_system_dir(
                app_dir / "retroarch.cfg", elsewhere
            ),
            elsewhere / "system",
        )

    def test_absolute_path_untouched(self):
        target = Path(tempfile.mkdtemp()) / "bios"
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
        lnk = Path(tempfile.mkdtemp()) / "LaunchBox.lnk"
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
        lnk = Path(tempfile.mkdtemp()) / "LaunchBox.lnk"
        lnk.write_bytes(b"L\x00\x00\x00 no target here ")
        self.assertIsNone(install._lnk_target(lnk, "LaunchBox.exe"))

    def test_shortcut_pointing_elsewhere_falls_back(self):
        # A stale shortcut must not win over a real installation
        userprofile = Path(tempfile.mkdtemp())
        root = self._make_root(userprofile / "LaunchBox")
        appdata = Path(tempfile.mkdtemp())
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
        userprofile = Path(tempfile.mkdtemp())
        root = self._make_root(userprofile / "LaunchBox")
        env = {"APPDATA": str(Path(tempfile.mkdtemp())), "USERPROFILE": str(userprofile)}
        with unittest.mock.patch.dict(os.environ, env):
            self.assertEqual(install.launchbox_root("windows"), root)

    def test_absent_on_linux(self):
        self.assertIsNone(install.launchbox_root("linux"))

    def test_nothing_installed(self):
        env = {
            "APPDATA": str(Path(tempfile.mkdtemp())),
            "USERPROFILE": str(Path(tempfile.mkdtemp())),
        }
        with unittest.mock.patch.dict(os.environ, env):
            self.assertIsNone(install.launchbox_root("windows"))


class TestLaunchboxBiosDirs(unittest.TestCase):
    """LaunchBox computes where each emulator it manages keeps its BIOS."""

    def _make(self, entries: list[tuple[str, str]]) -> Path:
        root = Path(tempfile.mkdtemp()) / "LaunchBox"
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
        elsewhere = Path(tempfile.mkdtemp()) / "ps2bios"
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
        userprofile = Path(tempfile.mkdtemp())
        with unittest.mock.patch.dict(os.environ, {"USERPROFILE": str(userprofile)}):
            self.assertEqual(
                install.launchbox_bios_dirs(root)["pcsx2"],
                userprofile / "Documents" / "PCSX2" / "bios",
            )

    def test_xemu_defaults_to_bios_folder(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        with unittest.mock.patch.dict(os.environ, {"APPDATA": str(Path(tempfile.mkdtemp()))}):
            self.assertEqual(install.launchbox_bios_dirs(root)["xemu"], emu / "bios")

    def test_xemu_honours_configured_bootrom(self):
        root = self._make([("Xemu", "Emulators\\Xemu\\xemu.exe")])
        emu = root / "Emulators" / "Xemu"
        configured = Path(tempfile.mkdtemp()) / "xbox"
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
        root = Path(tempfile.mkdtemp()) / "LaunchBox"
        (root / "Data").mkdir(parents=True)
        (root / "Data" / "Emulators.xml").write_text(
            "<!DOCTYPE LaunchBox [<!ENTITY a 'x'>]>\n<LaunchBox></LaunchBox>\n"
        )
        self.assertEqual(install.launchbox_emulators(root / "Data" / "Emulators.xml"), {})


class TestStandaloneCopiesExtraDirs(unittest.TestCase):
    """Setups that keep emulators outside the default locations."""

    def _manifest(self) -> dict:
        return {
            "standalone_copies": [
                {
                    "pattern": "ps2-*.bin",
                    "emulator": "pcsx2",
                    "targets": {"windows": []},
                },
                {
                    "file": "GC/USA/IPL.bin",
                    "emulator": "dolphin",
                    "targets": {"windows": []},
                },
            ]
        }

    def test_pattern_entry_copies_into_extra_dir(self):
        bios = Path(tempfile.mkdtemp())
        (bios / "ps2-0230a.bin").write_text("rom")
        extra = Path(tempfile.mkdtemp()) / "bios"
        extra.mkdir()
        copied, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"pcsx2": extra}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((extra / "ps2-0230a.bin").exists())

    def test_file_entry_keeps_its_subdirectory(self):
        bios = Path(tempfile.mkdtemp())
        (bios / "GC" / "USA").mkdir(parents=True)
        (bios / "GC" / "USA" / "IPL.bin").write_text("ipl")
        user = Path(tempfile.mkdtemp()) / "User"
        (user / "GC" / "USA").mkdir(parents=True)
        copied, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"dolphin": user}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((user / "GC" / "USA" / "IPL.bin").exists())

    def test_no_extra_dirs_is_unchanged(self):
        bios = Path(tempfile.mkdtemp())
        (bios / "ps2-0230a.bin").write_text("rom")
        self.assertEqual(
            install.do_standalone_copies(self._manifest(), bios, "windows"), (0, 0)
        )


@unittest.skipUnless(shutil.which("pwsh"), "pwsh not available")
class TestLaunchboxDetectionPowershell(unittest.TestCase):
    """install.ps1 must resolve LaunchBox's portable RetroArch on its own."""

    def _run(self, entries: str, seed=None, manifest: dict | None = None):
        userprofile = Path(tempfile.mkdtemp())
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
        serve_root = Path(tempfile.mkdtemp())
        (serve_root / "install").mkdir()
        (serve_root / "install" / "retroarch.json").write_text(
            json.dumps(manifest if manifest is not None else {"files": []})
        )
        handler = functools.partial(
            http.server.SimpleHTTPRequestHandler, directory=str(serve_root)
        )
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            env = dict(os.environ)
            env.update(
                USERPROFILE=str(userprofile),
                APPDATA=str(tempfile.mkdtemp()),
                RETROBIOS_BASE_URL=f"http://127.0.0.1:{httpd.server_address[1]}",
            )
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(REPO_ROOT / "install.ps1")],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            httpd.shutdown()
        return proc, ra_dir

    def _assert_resolved(self, proc, ra_dir):
        self.assertIn("Found LaunchBox with RetroArch at", proc.stdout)
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
        self.assertIn("Found LaunchBox with RetroArch at", proc.stdout)
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

        manifest = {
            "files": [],
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


class TestDetectFrontends(unittest.TestCase):
    """Frontends have no BIOS directory of their own but hint at the setup."""

    def test_esde_from_home_directory(self):
        home = Path(tempfile.mkdtemp())
        (home / "ES-DE").mkdir()
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old

    def test_esde_from_env_dir(self):
        home = Path(tempfile.mkdtemp())
        appdata = Path(tempfile.mkdtemp())
        os.environ["ESDE_APPDATA_DIR"] = str(appdata)
        try:
            self.assertIn("esde", install.detect_frontends("linux", home=home))
        finally:
            del os.environ["ESDE_APPDATA_DIR"]

    def test_nothing_detected(self):
        home = Path(tempfile.mkdtemp())
        old = os.environ.pop("ESDE_APPDATA_DIR", None)
        try:
            self.assertEqual(install.detect_frontends("linux", home=home), [])
        finally:
            if old is not None:
                os.environ["ESDE_APPDATA_DIR"] = old


class TestNormalizePlatform(unittest.TestCase):
    """Manifest URLs are case sensitive: user input must be normalized."""

    def test_lowercases_input(self):
        self.assertEqual(install.normalize_platform("Batocera"), "batocera")

    def test_strips_whitespace(self):
        self.assertEqual(install.normalize_platform(" retroarch "), "retroarch")

    def test_unknown_platform_exits(self):
        with self.assertRaises(SystemExit):
            install.normalize_platform("launchbox")

    def test_all_available_platforms_accepted(self):
        for plat in install.AVAILABLE_PLATFORMS:
            self.assertEqual(install.normalize_platform(plat), plat)


class TestAvailablePlatforms(unittest.TestCase):
    """The platform list must match the generated manifests."""

    def test_matches_install_manifests(self):
        manifests = {p.stem for p in (REPO_ROOT / "install").glob("*.json")}
        self.assertEqual(set(install.AVAILABLE_PLATFORMS), manifests)

    def test_powershell_installer_same_list(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        match = re.search(r"\$available = @\(([^)]*)\)", content)
        self.assertIsNotNone(match, "install.ps1 must define $available")
        ps_list = set(re.findall(r'"([^"]+)"', match.group(1)))
        self.assertEqual(ps_list, set(install.AVAILABLE_PLATFORMS))

    def test_powershell_normalizes_input(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        self.assertIn(".Trim().ToLower()", content)


if __name__ == "__main__":
    unittest.main()
