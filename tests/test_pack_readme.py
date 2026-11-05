"""The README inside a pack sends files where the platform reads them.

RetroDECK's pack holds bios/ and roms/ at its root, and its guide said to
extract into ~/retrodeck/bios/, giving ~/retrodeck/bios/bios/. MiSTer and
ROCKNIX had no guide and were told "your BIOS directory", a folder MiSTer
does not have, while the registry names the path.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from packreadme import _build_readme  # noqa: E402


def _extract_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if "Extract all files" in line]


class GuidesPointAtTheReadPath(unittest.TestCase):
    def test_retrodeck_is_extracted_at_its_root(self):
        text = _build_readme("retrodeck", "RetroDECK", "", 1, 1)
        for line in _extract_lines(text):
            self.assertNotIn("retrodeck/bios", line)

    def test_unguided_platforms_name_the_registry_path(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name, data in registry["platforms"].items():
            detect = (data.get("install", {}) or {}).get("detect", [])
            if not any(d.get("bios_path") for d in detect):
                continue
            text = _build_readme(name, name, "", 1, 1, detect=detect)
            with self.subTest(platform=name):
                self.assertFalse(
                    any("your BIOS directory" in line for line in _extract_lines(text))
                )


class ACardOpenedOnAComputerShowsItsShareDrive(unittest.TestCase):
    """The SD card steps said /userdata/bios/ and /recalbox/share/bios/,
    paths of the running system. On a computer the SHARE drive opens at its
    root, bios/ beside roms/ and system/, and no such folder exists."""

    def test_the_card_steps_name_the_drive_folder(self):
        for name in ("batocera", "recalbox"):
            text = _build_readme(name, name, "", 1, 1)
            card = text[text.index("Manual (SD card)"):]
            card = card[:card.index("\n\n", card.index("1."))]
            with self.subTest(platform=name):
                self.assertIn("bios folder at the root of the SHARE drive", card)
                self.assertNotIn("/userdata/bios/ on", card)
                self.assertNotIn("Navigate to /recalbox", card)


class GuidesNameShippedInstallers(unittest.TestCase):
    def test_every_installer_named_exists(self):
        """RetroBat's guide sent users to an install.bat no release carries."""
        source = (REPO_ROOT / "scripts" / "packreadme.py").read_text(encoding="utf-8")
        for name in set(re.findall(r"install\.(?:bat|ps1|sh|py)", source)):
            with self.subTest(installer=name):
                self.assertTrue((REPO_ROOT / name).is_file())

def _registry() -> dict:
    return yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())


def _guide(name: str) -> str:
    install = _registry()["platforms"][name].get("install") or {}
    return _build_readme(name, name, "", 1, 1, detect=install.get("detect", []),
                         standalone_copies=install.get("standalone_copies", []))


class TheOneLinerFollowsTheRegistry(unittest.TestCase):
    """The guides were written per platform by hand: ROCKNIX and MiSTer,
    which the installer detects, had no one-line install, EmuDeck's
    Windows edition was told to open Konsole, and every RomM user was sent
    to library/bios/ whatever its firmware template."""

    def test_every_detected_system_gets_its_command(self):
        for name, data in _registry()["platforms"].items():
            systems = {rule["os"] for rule in (data.get("install") or {}).get("detect", [])}
            if not systems:
                continue
            text = _guide(name)
            with self.subTest(platform=name):
                self.assertEqual("/i | sh" in text, bool(systems - {"windows"}))
                self.assertEqual("/i.ps1 | iex" in text, "windows" in systems)

    def test_rocknix_and_mister_run_it_on_the_device(self):
        for name in ("rocknix", "misterfpga"):
            with self.subTest(platform=name):
                self.assertIn(f"On the machine running {name}", _guide(name))

    def test_emudeck_is_not_steam_deck_only(self):
        text = _guide("emudeck")
        self.assertNotIn("Steam Deck / Linux", text)
        self.assertNotIn("Konsole", text)
        self.assertIn("/i.ps1 | iex", text)
        self.assertIn("C:\\Emulation\\bios", text)
        self.assertIn("--standalone-copies", text)

    def test_romm_names_both_firmware_layouts(self):
        text = _guide("romm")
        self.assertIn("library/bios/", text)
        self.assertIn("library/psx/bios/", text)
        self.assertIn("--romm-firmware", text)

    def test_the_commands_are_written_once(self):
        """The address comes from install_base in platforms/_guides.yml, the
        one the site's commands use."""
        import packreadme
        import sitebootstrap
        from siteguides import INSTALL_BASE

        source = (REPO_ROOT / "scripts" / "packreadme.py").read_text(encoding="utf-8")
        self.assertNotIn("raw.githubusercontent.com", source)
        self.assertNotIn("abdess.github.io", source)
        self.assertEqual(packreadme.INSTALL_SH, f"{INSTALL_BASE}/{sitebootstrap.SH_NAME}")
        self.assertEqual(packreadme.INSTALL_PS1, f"{INSTALL_BASE}/{sitebootstrap.PS1_NAME}")


if __name__ == "__main__":
    unittest.main()
