"""A core extra keeps every field that identifies its content.

Each hop kept its own subset: min_size and validation were lost, so
np2kai's bios.rom (98304 bytes minimum, size checked) resolved by name to an
IBM PCjr ROM and shipped in four packs, and dosbox's SC-55 ROMs to a
Galaksija ROM and a PS2 ROM2.BIN.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import PROFILE_IDENTITY_FIELDS  # noqa: E402

ENTRY = {
    "name": "bios.rom",
    "path": "np2kai/bios.rom",
    "min_size": 98304,
    "validation": ["size"],
    "aliases": ["BIOS.ROM"],
    "crc32": "12345678",
}


class IdentityTravels(unittest.TestCase):
    def test_report_and_extra_keep_every_identity_field(self):
        from packextras import _collect_emulator_extras
        from verify import find_undeclared_files

        profile = {
            "emulator": "NP2kai",
            "type": "libretro",
            "systems": ["nec-pc-98"],
            "files": [dict(ENTRY)],
        }
        config = {"cores": ["np2kai"], "systems": {}}
        db = {
            "files": {"s1": {"name": "bios.rom", "path": "bios/NEC/PC-98/bios.rom",
                             "size": 100000, "sha1": "s1", "md5": "m1", "crc32": "12345678"}},
            "indexes": {"by_name": {"bios.rom": ["s1"]}, "by_md5": {"m1": "s1"},
                        "by_crc32": {"12345678": "s1"}},
        }
        report = find_undeclared_files(config, "emulators", db, emu_profiles={"np2kai": profile})
        extras = _collect_emulator_extras(
            config, "emulators", db, set(), "", {"np2kai": profile}, include_all=True
        )
        for label, item in (("report", report[0]), ("extra", extras[0])):
            for field in ("min_size", "validation", "aliases", "crc32"):
                with self.subTest(where=label, field=field):
                    self.assertEqual(item.get(field), ENTRY[field])

    def test_every_hop_reads_the_shared_list(self):
        for name in ("packextras.py", "verify.py"):
            source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertIn("PROFILE_IDENTITY_FIELDS", source)
                self.assertNotIn('("sha1", "md5", "sha256", "crc32", "size"', source)
        self.assertIn("validation", PROFILE_IDENTITY_FIELDS)


if __name__ == "__main__":
    unittest.main()
