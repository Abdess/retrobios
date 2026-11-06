"""A core extra keeps every field that identifies its content.

Each hop kept its own subset: min_size and validation were lost, so
np2kai's bios.rom (98304 bytes minimum, size checked) resolved by name to an
IBM PCjr ROM and shipped in four packs, and dosbox's SC-55 ROMs to a
Galaksija ROM and a PS2 ROM2.BIN.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import PROFILE_IDENTITY_FIELDS  # noqa: E402
from packextras import _collect_emulator_extras  # noqa: E402
from verify import find_undeclared_files  # noqa: E402

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


class UnsourceableIsNoCopy(unittest.TestCase):
    """The second pass copies a covered file to another core's path by name.

    zc210 ships its own default.sf2, while dosbox-staging reads a default.sf2 that
    the operating system links to its SoundFont, which no collection holds.
    The name was enough to give dosbox-staging a slot, recorded as missing
    while zc210 was in the pack and absent once it was not, so a pack built
    for a target disagreed with the installer narrowing the full list.
    """

    def test_an_unsourceable_entry_gets_no_copy(self):
        profiles = {
            "zc210": {"emulator": "ZC", "type": "libretro", "systems": ["zc"],
                      "files": [{"name": "default.sf2", "path": "zc210/sf2/default.sf2"}]},
            "dosbox-staging": {
                "emulator": "DOSBox Staging", "type": "libretro", "systems": ["dos"],
                "files": [{"name": "default.sf2", "path": "soundfonts/default.sf2",
                           "required": False, "unsourceable": "the system's own link"}],
            },
        }
        config = {"cores": ["zc210", "dosbox-staging"], "systems": {}}
        db = {
            "files": {"s1": {"name": "default.sf2", "path": "bios/ZC/default.sf2",
                             "size": 10, "sha1": "s1", "md5": "m1", "crc32": "c1"}},
            "indexes": {"by_name": {"default.sf2": ["s1"]}, "by_md5": {"m1": "s1"},
                        "by_crc32": {"c1": "s1"},
                        "by_path_suffix": {"zc210/sf2/default.sf2": ["s1"]}},
        }
        extras = _collect_emulator_extras(config, "emulators", db, set(), "", profiles)
        self.assertEqual(
            [(e["source_profile"], e["destination"]) for e in extras],
            [("zc210", "zc210/sf2/default.sf2")],
        )


class BareNameIsADestination(unittest.TestCase):
    """geargrafx reads syscard1.pce at the root of the system directory,
    but Recalbox declares it only under pcenginecd/. The declaration settles the
    core's need on the promise that the builder copies the file to the
    core's path, and the second pass skipped every entry with no path."""

    def test_a_root_copy_of_a_file_declared_in_a_subdirectory(self):
        profiles = {"geargrafx": {
            "emulator": "Geargrafx", "type": "libretro", "systems": ["pce"],
            "files": [{"name": "syscard1.pce"}],
        }}
        config = {"cores": ["geargrafx"], "systems": {"pcenginecd": {"files": [
            {"name": "syscard1.pce", "destination": "pcenginecd/syscard1.pce"}]}}}
        db = {
            "files": {"s1": {"name": "syscard1.pce", "path": "bios/NEC/syscard1.pce",
                             "size": 10, "sha1": "s1", "md5": "m1", "crc32": "c1"}},
            "indexes": {"by_name": {"syscard1.pce": ["s1"]}, "by_md5": {"m1": "s1"},
                        "by_crc32": {"c1": "s1"}, "by_path_suffix": {}},
        }
        extras = _collect_emulator_extras(
            config, "emulators", db, {"pcenginecd/syscard1.pce"}, "", profiles
        )
        self.assertIn("syscard1.pce", [e["destination"] for e in extras])


class ArchiveMembersStayInside(unittest.TestCase):
    """fbneo reads msx.rom inside msx.zip. Once the second pass copied bare
    names, it wrote that member loose at the root as soon as another core's
    msx.rom covered the name, and 000-lo.lo landed beside neogeo.zip."""

    def test_no_loose_copy_of_a_member(self):
        profiles = {
            "zesarux": {"emulator": "ZEsarUX", "type": "libretro", "systems": ["msx"],
                        "files": [{"name": "msx.rom"}]},
            "fbneo": {"emulator": "FBNeo", "type": "libretro", "systems": ["msx"],
                      "files": [{"name": "msx.rom", "archive": "msx.zip"}]},
        }
        config = {"cores": ["zesarux", "fbneo"], "systems": {}}
        db = {
            "files": {"s1": {"name": "msx.rom", "path": "bios/MSX/msx.rom",
                             "size": 10, "sha1": "s1", "md5": "m1", "crc32": "c1"}},
            "indexes": {"by_name": {"msx.rom": ["s1"]}, "by_md5": {"m1": "s1"},
                        "by_crc32": {"c1": "s1"}, "by_path_suffix": {}},
        }
        extras = _collect_emulator_extras(config, "emulators", db, set(), "", profiles)
        loose = [e for e in extras if e["destination"] == "msx.rom"]
        self.assertEqual([e["source_profile"] for e in loose], ["zesarux"])


if __name__ == "__main__":
    unittest.main()
