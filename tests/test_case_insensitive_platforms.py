"""A platform the installer targets on Windows or macOS packs case-insensitively.

RetroBat shipped quasi88/N88.ROM (the md5 it pins) beside quasi88/n88.rom;
extracted on NTFS the second overwrote the first and RetroBat's own check
went red. The flag lived in retrobat.yml and vanished at the next scrape.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from common import load_platform_config  # noqa: E402


class CaseInsensitiveWhereTheFilesystemIs(unittest.TestCase):
    def test_windows_and_macos_platforms_carry_the_flag(self):
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        for name, data in registry["platforms"].items():
            systems = {str(d.get("os")) for d in (data.get("install") or {}).get("detect", [])}
            if systems & {"windows", "darwin"}:
                with self.subTest(platform=name):
                    config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                    self.assertTrue(config.get("case_insensitive_fs"))


class ThePackReadmeNamesTheSpellingsItLeavesOut(unittest.TestCase):
    """The EmuDeck pack is folded for Windows and extracted on a Steam Deck,
    where the core asking for bios.col finds only BIOS.col. Only the
    installer adds that spelling (case_variants), and the pack's README said
    nothing about it."""

    def setUp(self):
        import common
        import generate_db
        import generate_pack

        self.gp = generate_pack
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        Path("bios/Coleco").mkdir(parents=True)
        payload = b"coleco bios"
        Path("bios/Coleco/BIOS.col").write_bytes(payload)
        sha1 = hashlib.sha1(payload).hexdigest()
        files = {sha1: {"path": "bios/Coleco/BIOS.col", "name": "BIOS.col",
                        "size": len(payload), "sha1": sha1,
                        "md5": hashlib.md5(payload).hexdigest(),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "crc32": "00000001"}}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        Path("platforms").mkdir()
        Path("emulators").mkdir()
        self.config = {
            "platform": "P", "verification_mode": "existence",
            "case_insensitive_fs": True, "cores": ["mesence"],
            "systems": {"coleco": {"files": [{"name": "BIOS.col"}]}},
        }
        Path("emulators/mesence.yml").write_text(yaml.dump({
            "emulator": "mesence", "type": "libretro", "systems": ["coleco"],
            "files": [{"name": "bios.col", "required": True}],
        }))
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._emulator_profiles_cache.clear)

    def _readme(self, systems: list[str]) -> str:
        import common

        Path("platforms/p.yml").write_text(yaml.dump(self.config))
        Path("platforms/_registry.yml").write_text(yaml.dump({"platforms": {"p": {
            "install": {"detect": [{"os": os_name} for os_name in systems]},
        }}}))
        common._platform_config_cache.clear()
        texts: dict[str, str] = {}
        real = self.gp._write_generated_member

        def capture(zf, arcname, text):
            texts[arcname] = text
            return real(zf, arcname, text)

        self.gp._write_generated_member = capture
        self.addCleanup(setattr, self.gp, "_write_generated_member", real)
        with contextlib.redirect_stdout(io.StringIO()):
            self.gp.generate_pack(
                "p", "platforms", self.db, "bios", "", emulators_dir="emulators",
                offline=True, record=self.gp.PackRecord(),
            )
        return texts["README.txt"]

    def test_a_platform_also_on_linux_names_them(self):
        readme = self._readme(["windows", "linux"])
        self.assertIn("NAMES THAT DIFFER ONLY BY CASE", readme)
        self.assertIn("    bios.col  (the pack has BIOS.col)", readme)

    def test_a_platform_only_on_windows_does_not(self):
        self.assertNotIn("DIFFER ONLY BY CASE", self._readme(["windows"]))


if __name__ == "__main__":
    unittest.main()
