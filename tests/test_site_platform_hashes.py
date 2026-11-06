"""A platform page shows each row the hash its own declaration carries.

The page joined verify's details to the platform YAML by file name alone,
the last declaration winning: MiSTer declares boot.rom 23 times with 21
distinct MD5s, and every boot.rom row showed the same one, so a user
checking a dump against the page was told the wrong hash.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import siterender  # noqa: E402
from generate_site import _render_platform_systems  # noqa: E402

A, B, C = "a" * 32, "b" * 32, "c" * 32


class EachRowItsDeclaration(unittest.TestCase):
    def test_same_name_in_two_systems_and_twice_in_one(self):
        config_files = {
            ("psx", "boot.rom"): [{"name": "boot.rom", "md5": A}],
            ("saturn", "boot.rom"): [
                {"name": "boot.rom", "md5": B},
                {"name": "boot.rom", "md5": C},
            ],
        }
        by_system = {
            "psx": [{"name": "boot.rom", "status": "ok", "system": "psx"}],
            "saturn": [
                {"name": "boot.rom", "status": "ok", "system": "saturn"},
                {"name": "boot.rom", "status": "ok", "system": "saturn"},
            ],
        }
        names = {"psx": "Sony PlayStation", "saturn": "Sega Saturn"}
        with mock.patch.dict(siterender.SYSTEM_NAMES, names):
            text = "\n".join(_render_platform_systems(by_system, config_files, {}))
        psx, saturn = text.split("saturn", 1)[0], text.split("saturn", 1)[1]
        self.assertIn(A, psx)
        self.assertNotIn(B, psx)
        self.assertLess(saturn.index(B), saturn.index(C))
        self.assertNotIn(A, saturn)


class AnUntestedRowNamesBothHashes(unittest.TestCase):
    """The gaps page said "declared hash contradicted by the local file" for
    RetroDECK's dsifirmware.bin and named neither the dump RetroDECK asks for
    nor the one the collection holds."""

    def test_declared_and_held(self):
        import generate_site as gs

        path = "bios/Nintendo/Nintendo DS/dsifirmware.bin"
        declared, held = "1" * 64, "2" * 64
        config = {"systems": {"nintendo-ds": {"files": [
            {"name": "dsifirmware.bin", "sha256": declared}]}}}
        detail = {"name": "dsifirmware.bin", "system": "nintendo-ds"}
        problem = {
            "platform": "RetroDECK", "name": "dsifirmware.bin", "status": "untested",
            "required": True, "reason": "declared hash contradicted by the local file",
            "declared": gs._declared_hashes(config, detail), "path": path,
        }
        db = {"files": {"f" * 40: {"path": path, "sha256": held}}}
        table = "\n".join(gs._render_problem_files([problem], db=db))
        row = next(line for line in table.splitlines() if "dsifirmware" in line)
        # Cut to 12 characters in the cell, the whole value in its title.
        self.assertIn(f'sha256 <code title="{declared}">{declared[:12]}</code>', row)
        self.assertIn(f'sha256 <code title="{held}">{held[:12]}</code>', row)
        self.assertIn(f"`{path}`", row)


if __name__ == "__main__":
    unittest.main()
