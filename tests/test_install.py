"""Tests for install.py platform detection and config parsing."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import tempfile
import unittest
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
