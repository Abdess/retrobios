"""A shared group adds files, never a second name for a native one.

The quasi88 group declared N88SUB.ROM beside the disk.rom System.dat
already names for nec-pc-88, same bytes: the RetroArch pack carried the
2 KB ROM twice under quasi88/, and the group read as twelve required files
where four did the work. Alternative names are aliases in the profile.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import list_registered_platforms, load_platform_config  # noqa: E402

PLATFORMS = str(REPO_ROOT / "platforms")


def _md5s(entry: dict) -> set[str]:
    raw = entry.get("md5") or ""
    values = raw if isinstance(raw, list) else str(raw).split(",")
    return {v.strip().lower() for v in values if v and v.strip()}


class SharedGroupsAddOnly(unittest.TestCase):
    def test_no_shared_file_repeats_a_native_file_of_the_same_directory(self):
        shared = yaml.safe_load((REPO_ROOT / "platforms" / "_shared.yml").read_text())
        groups = shared.get("shared_groups") or {}
        repeated = []
        for platform in list_registered_platforms(PLATFORMS, include_archived=True):
            config = load_platform_config(platform, PLATFORMS)
            for system in config.get("systems", {}).values():
                included = [
                    fe for group in system.get("includes", []) for fe in groups.get(group, [])
                ]
                if not included:
                    continue
                group_keys = {
                    (fe.get("name"), fe.get("destination", fe.get("name"))) for fe in included
                }
                native: dict[tuple[str, str], str] = {}
                for fe in system.get("files", []):
                    if (fe.get("name"), fe.get("destination", fe.get("name"))) in group_keys:
                        continue
                    dest = fe.get("destination") or fe.get("name", "")
                    directory = dest.rsplit("/", 1)[0] if "/" in dest else ""
                    for md5 in _md5s(fe):
                        native.setdefault((directory, md5), fe.get("name", ""))
                for fe in included:
                    dest = fe.get("destination") or fe.get("name", "")
                    directory = dest.rsplit("/", 1)[0] if "/" in dest else ""
                    for md5 in _md5s(fe):
                        other = native.get((directory, md5))
                        if other and other.lower() != fe.get("name", "").lower():
                            repeated.append(f"{platform}:{fe['name']} = {other}")
        self.assertEqual(repeated, [])

class ADeclaredAliasSettlesTheRequirement(unittest.TestCase):
    """quasi88 reads n88sub.rom or disk.rom; System.dat names disk.rom. The
    gap pass compared the entry's name alone and the pack carried the same
    2 KB ROM a second time as quasi88/n88sub.rom."""

    def test_a_platform_naming_an_alias_has_met_the_entry(self):
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from common import _emulator_profiles_cache  # noqa: PLC0415
        from verify import find_undeclared_files  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "emulators").mkdir()
            Path(tmp, "emulators", "quasi88.yml").write_text(
                "emulator: QUASI88\ntype: libretro\nsystems: [nec-pc-88]\ncores: [quasi88]\n"
                "files:\n  - name: n88sub.rom\n    path: quasi88/n88sub.rom\n"
                "    aliases: [N88SUB.ROM, disk.rom]\n    required: true\n"
            )
            _emulator_profiles_cache.clear()
            self.addCleanup(_emulator_profiles_cache.clear)
            config = {"platform": "P", "verification_mode": "existence", "cores": "all_libretro",
                      "base_destination": "system",
                      "systems": {"nec-pc-88": {"files": [{"name": "disk.rom", "destination": "quasi88/disk.rom"}]}}}
            db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {}, "by_path_suffix": {}}}
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            undeclared = find_undeclared_files(config, "emulators", db, data_names=set())
        self.assertEqual([u["name"] for u in undeclared], [])


class ASameNamedFileOfAnotherSizeSettlesNothing(unittest.TestCase):
    """RetroArch declares Galaksija's ROM1.BIN, a 4 KiB ROM; DOSBox reads a
    32 KiB SC-55 ROM1.BIN and checks its size. The gap pass settled DOSBox's
    entry on the name alone: the report never listed SC-55/ROM1.BIN, and a
    missing dump would have shown no gap."""

    PROFILE = (
        "emulator: DOSBox\ntype: libretro\nsystems: [dos]\ncores: [dosbox]\n"
        "files:\n  - name: ROM1.BIN\n    path: SC-55/ROM1.BIN\n"
        "    size: 32768\n    validation: [size]\n"
    )

    def undeclared(self, declared_size, destination="galaksija/ROM1.BIN", md5=None, db_size=None):
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from common import _emulator_profiles_cache  # noqa: PLC0415
        from verify import find_undeclared_files  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "emulators").mkdir()
            Path(tmp, "emulators", "dosbox.yml").write_text(self.PROFILE)
            _emulator_profiles_cache.clear()
            self.addCleanup(_emulator_profiles_cache.clear)
            config = {"platform": "P", "verification_mode": "existence", "cores": "all_libretro",
                      "base_destination": "system",
                      "systems": {"galaksija": {"files": [
                          {"name": "ROM1.BIN", "destination": destination,
                           "size": declared_size, "md5": md5}]}}}
            db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {}, "by_path_suffix": {}}}
            if md5:
                db["files"]["a" * 40] = {"name": "ROM1.BIN", "size": db_size}
                db["indexes"]["by_md5"][md5] = "a" * 40
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            return [u["path"] for u in find_undeclared_files(config, "emulators", db, data_names=set())]

    def test_a_declaration_at_a_size_the_core_rejects_leaves_the_gap_open(self):
        self.assertEqual(self.undeclared(4096), ["SC-55/ROM1.BIN"])

    def test_a_declaration_at_an_accepted_size_settles_it(self):
        self.assertEqual(self.undeclared(32768), [])

    def test_a_declaration_without_a_size_still_settles_it(self):
        self.assertEqual(self.undeclared(None), [])

    def test_the_size_of_the_file_its_hash_names_stands_in(self):
        """Batocera writes no size: its md5 names the file, and the file's size
        decides. MT32_CONTROL.ROM at 64 KiB covered DOSBox's 128 KiB entries."""
        self.assertEqual(
            self.undeclared(None, md5="b" * 32, db_size=4096), ["SC-55/ROM1.BIN"]
        )

    def test_a_declaration_filling_the_entry_slot_settles_it(self):
        """Same destination, other size: which bytes fill the slot is the slot
        arbitration's call, and the builder leaves a taken slot alone."""
        self.assertEqual(self.undeclared(4096, destination="SC-55/ROM1.BIN"), [])


class AnAliasAnswersOnlyWhereTheCoreReadsIt(unittest.TestCase):
    """CLK reads MSX/MSX.ROM and answers to MSX.ROM; RetroDECK declares
    bios/MSX.ROM at the root for fMSX. The alias settled CLK's entry and the
    pack left CLK without an MSX BIOS: the builder copies a file declared
    elsewhere to a core's path under the core's own name, never an alias."""

    PROFILE = (
        "emulator: CLK\ntype: libretro\nsystems: [msx]\ncores: [clk]\n"
        "files:\n  - name: msx.rom\n    aliases: [MSX.ROM]\n    path: MSX/MSX.ROM\n"
        "    required: true\n"
    )

    def undeclared(self, destination, base_destination="", size=None):
        import os  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        from common import _emulator_profiles_cache  # noqa: PLC0415
        from verify import find_undeclared_files  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "emulators").mkdir()
            Path(tmp, "emulators", "clk.yml").write_text(self.PROFILE)
            _emulator_profiles_cache.clear()
            self.addCleanup(_emulator_profiles_cache.clear)
            config = {"platform": "P", "verification_mode": "md5", "cores": ["clk"],
                      "base_destination": base_destination,
                      "systems": {"msx": {"files": [
                          {"name": "MSX.ROM", "destination": destination, "size": size},
                          {"name": "other.rom", "destination": "bios/other.rom"}]}}}
            db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {}, "by_path_suffix": {}}}
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                return [u["path"] for u in find_undeclared_files(config, "emulators", db, data_names=set())]
            finally:
                os.chdir(previous)

    def test_an_alias_declared_at_another_path_leaves_the_entry_open(self):
        self.assertEqual(self.undeclared("bios/MSX.ROM"), ["MSX/MSX.ROM"])

    def test_an_alias_declared_where_the_core_reads_settles_it(self):
        """RetroDECK writes bios/ into every destination; core paths start below it."""
        self.assertEqual(self.undeclared("bios/MSX/MSX.ROM"), [])

    def test_an_alias_in_place_at_a_rejected_size_leaves_it_open(self):
        """RetroBat's root DISK.ROM is the 16 KiB MSX disk ROM; gsplus reads a
        256-byte DISK.ROM or c600.rom there and checks the size."""
        self.PROFILE = (
            "emulator: GSplus\ntype: libretro\nsystems: [msx]\ncores: [clk]\n"
            "files:\n  - name: c600.rom\n    aliases: [MSX.ROM]\n"
            "    size: 256\n    validation: [size]\n"
        )
        self.assertEqual(self.undeclared("MSX.ROM", "bios", size=16384), ["c600.rom"])
        self.assertEqual(self.undeclared("MSX.ROM", "bios", size=256), [])


if __name__ == "__main__":
    unittest.main()
