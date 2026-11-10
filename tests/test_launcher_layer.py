"""The launcher layer read by verify and by the pack builder.

A platform's launcher decides which name a file is read under. The fixtures
give a synthetic platform three launcher records: a region list tried in
order (Batocera's DuckStation shape), a second list no declared file fills,
and a fixed path the launcher passes (Batocera's x16emu shape).
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import inspect
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import yaml  # noqa: E402

from common import _emulator_profiles_cache, load_emulator_profiles, load_platform_config  # noqa: E402
from launchers import LauncherLayer, launcher_places, suffixed_stem  # noqa: E402
from verify import find_undeclared_files, verify_platform  # noqa: E402

CONTENT = {
    "b.bin": b"REGION_B_IMAGE",
    "e.bin": b"IMAGE_KNOWN_AS_E",
    "core.bin": b"CORE_DEFAULT_ROM",
    "plain.bin": b"PLAIN_CORE_FILE",
}


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


class LauncherLayerTest(unittest.TestCase):
    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        self.root = tempfile.mkdtemp()
        self.bios_dir = os.path.join(self.root, "bios")
        self.platforms_dir = os.path.join(self.root, "platforms")
        self.emulators_dir = os.path.join(self.root, "emulators")
        for d in (self.bios_dir, self.platforms_dir, self.emulators_dir):
            os.makedirs(d)
        files: dict[str, dict] = {}
        by_md5: dict[str, str] = {}
        by_name: dict[str, list[str]] = {}
        for name, data in CONTENT.items():
            path = os.path.join(self.bios_dir, name)
            with open(path, "wb") as fh:
                fh.write(data)
            sha1 = hashlib.sha1(data).hexdigest()
            files[sha1] = {
                "path": path, "name": name, "md5": _md5(data), "sha1": sha1,
                "size": len(data), "crc32": "",
            }
            by_md5[_md5(data)] = sha1
            by_name.setdefault(name, []).append(sha1)
        self.db = {
            "files": files,
            "indexes": {
                "by_md5": by_md5, "by_name": by_name, "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        platform = {
            "platform": "LauncherTest",
            "verification_mode": "md5",
            "base_destination": "bios",
            "standalone_cores": ["psxemu", "fixemu"],
            "systems": {
                "test-sys": {
                    "files": [
                        {"name": "plain.bin", "destination": "plain.bin",
                         "md5": _md5(CONTENT["plain.bin"]), "required": True},
                    ],
                },
            },
            "launchers": [
                {
                    "emulator": "psxemu", "build": "standalone",
                    "kind": "names_searched", "slot": "NTSCU",
                    "names": ["a.bin", "b.bin", "c.bin"],
                    "case_insensitive": True, "search_dir": "/userdata/bios",
                    "source_ref": "gen/psx.py:10-20",
                },
                {
                    "emulator": "psxemu", "build": "standalone",
                    "kind": "names_searched", "slot": "PAL",
                    "names": ["d.bin", "e.bin"],
                    "case_insensitive": True, "search_dir": "/userdata/bios",
                    "source_ref": "gen/psx.py:21-30",
                },
                {
                    "emulator": "fixemu", "build": "standalone",
                    "kind": "fixed_name", "names": ["sub/fix.bin"],
                    "search_dir": "/userdata/bios",
                    "source_ref": "gen/fix.py:5",
                },
            ],
        }
        with open(os.path.join(self.platforms_dir, "launchertest.yml"), "w") as fh:
            yaml.dump(platform, fh)
        profiles = {
            "psxemu": {
                "emulator": "PsxEmu", "type": "standalone", "found_by": "content",
                "systems": ["test-sys"],
                "files": [
                    {"name": "a.bin", "required": True,
                     "md5": "0" * 32, "validation": ["md5"]},
                    {"name": "b.bin", "required": True,
                     "md5": _md5(CONTENT["b.bin"]), "validation": ["md5"]},
                    {"name": "label_pal.bin", "required": True,
                     "md5": _md5(CONTENT["e.bin"]), "validation": ["md5"]},
                ],
            },
            "fixemu": {
                "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
                "files": [
                    {"name": "core.bin", "aliases": ["fix.bin"], "required": True},
                ],
            },
        }
        for key, profile in profiles.items():
            with open(os.path.join(self.emulators_dir, f"{key}.yml"), "w") as fh:
                yaml.dump(profile, fh)
        self.config = load_platform_config("launchertest", self.platforms_dir)
        self.profiles = load_emulator_profiles(self.emulators_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def _report(self) -> list[dict]:
        return find_undeclared_files(
            self.config, self.emulators_dir, self.db, self.profiles,
        )

    def _pack_names(self) -> set[str]:
        from generate_pack import generate_pack

        output = os.path.join(self.root, "dist")
        os.makedirs(output)
        zip_path = generate_pack(
            "launchertest", self.platforms_dir, self.db, self.bios_dir, output,
            emulators_dir=self.emulators_dir, emu_profiles=self.profiles,
            offline=True,
        )
        self.assertIsNotNone(zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            return set(zf.namelist())

    def test_places_follow_the_launcher_order(self) -> None:
        places = launcher_places(self.config)
        self.assertEqual(places[0].paths, ("a.bin", "b.bin", "c.bin"))
        self.assertEqual(places[2].paths, ("sub/fix.bin",))
        self.assertTrue(places[0].stands_for_default)

    def test_held_alternative_settles_the_others(self) -> None:
        """b.bin fills the NTSCU list, so a.bin is not missing there."""
        report = self._report()
        names = {u["name"]: u for u in report}
        self.assertNotIn("a.bin", names)
        self.assertTrue(names["b.bin"]["in_repo"])

    def test_without_the_layer_the_alternative_is_missing(self) -> None:
        config = {**self.config, "launchers": []}
        names = {
            u["name"]: u
            for u in find_undeclared_files(config, self.emulators_dir, self.db, self.profiles)
        }
        self.assertFalse(names["a.bin"]["in_repo"])

    def test_accepted_content_lands_under_the_launcher_name(self) -> None:
        """No declared file fills PAL: the image the core accepts goes in as e.bin."""
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertIn("e.bin", added)
        self.assertEqual(added["e.bin"]["md5"], _md5(CONTENT["e.bin"]))
        self.assertEqual(added["e.bin"]["launcher_of"], "label_pal.bin")

    def test_fixed_name_receives_the_held_file(self) -> None:
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertIn("sub/fix.bin", added)
        self.assertEqual(added["sub/fix.bin"]["md5"], _md5(CONTENT["core.bin"]))

    def test_a_file_the_emulator_installs_is_not_brought(self) -> None:
        """ROCKNIX installs xemu's xbox_hdd.qcow2 (installed_on), and the
        layer packed one under the launcher's hdd/ path all the same."""
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "core.bin", "aliases": ["fix.bin"], "required": True,
                       "installed_on": ["launchertest"]}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        added = [u["path"] for u in self._report() if u.get("launcher")]
        self.assertNotIn("sub/fix.bin", added)

    def test_a_hashless_entry_takes_a_launcher_file_of_a_size_it_checks(self) -> None:
        """EmuDeck passes Complex_4627v1.03.bin as xemu's flash ROM
        (emuDeckXemu.sh:60-61), and xemu's Complex_4627.bin entry checks only
        a size: matched neither by name nor by content, the default name was
        still asked for."""
        data = b"F" * 64
        self.db["files"]["f" * 40] = {"path": os.path.join(self.bios_dir, "v103.bin"),
                                      "name": "v103.bin", "md5": _md5(data), "sha1": "f" * 40,
                                      "size": len(data), "crc32": ""}
        with open(os.path.join(self.bios_dir, "v103.bin"), "wb") as fh:
            fh.write(data)
        self.db["indexes"]["by_name"]["v103.bin"] = ["f" * 40]
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "flash.bin", "required": True, "size": [32, 64],
                       "validation": ["size"]},
                      {"name": "boot.bin", "required": True, "size": 8,
                       "validation": ["size"]}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"][2]["names"] = ["v103.bin"]
        self.config["launchers"][2]["search_dir"] = "/userdata/bios"
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        report = {u["path"]: u for u in self._report()}
        self.assertNotIn("flash.bin", report)
        self.assertIn("v103.bin", report)
        self.assertIn("boot.bin", report)

    def test_a_name_whose_copies_fail_the_size_is_not_held(self) -> None:
        """NanoBoyAdvance reads a 16 KB bios.bin, and the collection's
        bios.bin files are PCem's and QEMU's PC BIOS images. Counted held by
        name, the entry escaped the launcher layer, which settles only what
        the collection lacks, and the ROCKNIX pack carried PCem's 64 KB image
        beside the gba_bios.bin its launcher passes."""
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "core.bin", "required": True,
                       "size": len(CONTENT["plain.bin"]), "validation": ["size"]}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"][2]["names"] = ["plain.bin"]
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        self.assertNotIn("core.bin", {u["name"] for u in self._report()})
        self.assertNotIn("core.bin", self._pack_names())

    def test_a_file_handed_to_an_entry_setting_takes_the_entry_content(self) -> None:
        """RetroPie runs sdl2trs with `-romfile4p $biosdir/level4p.rom` and
        EmuDeck writes a No-Intro name into ares's NeoGeoPocket firmware
        setting: neither name is the core's, and the held file of the entry
        that setting reads went in under no name at all."""
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "core.bin", "required": True, "config_key": "romslot"},
                      {"name": "other.bin", "required": True, "config_key": "otherslot"}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"][2]["names"] = ["launcher.rom"]
        self.config["launchers"][2]["passes_to"] = "command line -romslot"
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertEqual(added["launcher.rom"]["launcher_of"], "core.bin")
        self.assertEqual(added["launcher.rom"]["md5"], _md5(CONTENT["core.bin"]))
        self.assertIn("launcher.rom", self._pack_names())

    def test_a_fixed_name_with_an_appended_extension_takes_the_entry(self) -> None:
        """ROCKNIX passes kick34005.A500.rom to Amiberry, which names
        Kickstart 1.3 kick34005.A500: the pack shipped nothing under it."""
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "core.bin", "aliases": ["kick.A500"], "required": True}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"][2]["names"] = ["kick.A500.rom"]
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertEqual(added["kick.A500.rom"]["md5"], _md5(CONTENT["core.bin"]))
        self.assertIsNone(suffixed_stem("scph1001.bin"))

    def test_an_entry_the_platform_declares_still_fills_the_launcher_name(self) -> None:
        """AmberELEC declares kick34005.A500, so the report never offers
        Amiberry's entry, and its config still passes kick34005.A500.rom."""
        profile = {
            "emulator": "FixEmu", "type": "standalone", "systems": ["test-sys"],
            "files": [{"name": "core.bin", "aliases": ["kick.A500"], "required": True}],
        }
        with open(os.path.join(self.emulators_dir, "fixemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"][2]["names"] = ["kick.A500.rom"]
        self.config["systems"]["test-sys"]["files"].append(
            {"name": "core.bin", "destination": "core.bin", "required": True}
        )
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertEqual(added["kick.A500.rom"]["md5"], _md5(CONTENT["core.bin"]))

    def test_each_name_of_a_config_takes_its_own_key(self) -> None:
        """AmberELEC's atari800.cfg names eight ROMs under eight keys, and
        one record describes them in order: 5200a.rom is ROM_5200_A's file,
        not every key's."""
        config = {"base_destination": "bios", "launchers": [{
            "emulator": "e", "build": "libretro", "kind": "fixed_name",
            "names": ["a.rom", "b.rom"], "search_dir": "/storage/roms/bios",
            "passes_to": "e.cfg ROM_A, ROM_B", "source_ref": "e.cfg:1",
        }]}
        places = {p.paths[0]: p.passes_to for p in launcher_places(config)}
        self.assertEqual(places, {"a.rom": "e.cfg ROM_A", "b.rom": "e.cfg ROM_B"})

    def test_a_core_option_names_the_dump_of_a_model(self) -> None:
        """RetroDECK sets LRPS2's pcsx2_bios to scph10000.bin. LRPS2's entry
        is a placeholder for every BIOS its scan finds, and the catalogues
        name two revisions of the SCPH-10000: the earlier goes in."""
        older, newer = b"S" * 64, b"T" * 64
        for data, catalogue in ((newer, "ps2-0101j-20000217.bin"),
                                (older, "ps2-0100j-20000117.bin")):
            sha1 = hashlib.sha1(data).hexdigest()
            path = os.path.join(self.bios_dir, catalogue)
            with open(path, "wb") as fh:
                fh.write(data)
            self.db["files"][sha1] = {
                "path": path, "name": catalogue, "md5": _md5(data), "sha1": sha1,
                "size": len(data), "crc32": "",
                "provenance": {"redump": {"name": catalogue,
                                          "description": "SCPH-10000 (Version 5.0)"}},
            }
        profile = {
            "emulator": "OptEmu", "type": "libretro", "systems": ["test-sys"],
            "files": [{"name": "<bios>.bin", "path": "ps2/bios/<bios>.bin", "required": True,
                       "min_size": 32, "max_size": 64, "validation": ["size"],
                       "config_key": "emu_bios"}],
        }
        with open(os.path.join(self.emulators_dir, "optemu.yml"), "w") as fh:
            yaml.dump(profile, fh)
        self.config["launchers"].append({
            "emulator": "retroarch", "build": "libretro", "kind": "core_option",
            "names": ["scph10000.bin"], "passes_to": "core option emu_bios",
            "source_ref": "core-options.cfg:515",
        })
        _emulator_profiles_cache.clear()
        self.profiles = load_emulator_profiles(self.emulators_dir)
        added = {u["path"]: u for u in self._report() if u.get("launcher")}
        self.assertEqual(added["ps2/bios/scph10000.bin"]["md5"], _md5(older))

    def test_the_default_name_a_launcher_replaces_is_not_packed(self) -> None:
        """EmuDeck passes Complex_4627v1.03.bin to xemu, which then never
        opens Complex_4627.bin: the pack carried both, one read by nobody."""
        report = {u["path"]: u for u in self._report()}
        self.assertIn("sub/fix.bin", report)
        self.assertNotIn("core.bin", report)
        self.assertNotIn("core.bin", self._pack_names())

    def test_a_link_of_a_named_file_is_a_place(self) -> None:
        """ROCKNIX links /storage/roms/bios/nds_bios_arm9.bin into DraStic's
        system folder (start_drastic.sh:37-41): the file goes where the
        link reads it, not under the emulator's own folder."""
        self.config["launchers"][2].update(
            kind="links", names=["fix.bin"], search_dir="/storage/roms/bios",
        )
        places = [p for p in launcher_places(self.config) if p.kind == "links"]
        self.assertEqual([p.paths for p in places], [("fix.bin",)])
        self.assertTrue(places[0].stands_for_default)
        report = {u["path"]: u for u in self._report()}
        self.assertIn("fix.bin", report)
        self.assertNotIn("core.bin", report)

    def test_a_link_of_a_directory_is_no_place(self) -> None:
        self.config["launchers"][2].update(
            kind="links", names=[], search_dir="/userdata/bios/sub",
        )
        self.assertFalse([p for p in launcher_places(self.config) if p.kind == "links"])

    def test_the_platform_spelling_of_the_bios_folder_is_a_root(self) -> None:
        """RetroPie names $biosdir, EmuDeck ${biosPath}, RetroDECK $bios_path:
        read as no folder at all, every place of those platforms was dropped."""
        for spelling in ("$biosdir", "${biosPath}", "$bios_path", "$HOME/RetroPie/bios"):
            self.config["launchers"][2]["search_dir"] = f"{spelling}/sub"
            with self.subTest(spelling=spelling):
                self.assertEqual(launcher_places(self.config)[2].paths, ("sub/sub/fix.bin",))

    def test_every_extractor_spelling_of_the_bios_folder_is_known(self) -> None:
        import launchers
        from scraper import emudeck_launchers, retrodeck_launchers, retropie_launchers

        for token in (emudeck_launchers.BIOS, retrodeck_launchers.BIOS,
                      retropie_launchers.BIOSDIR):
            self.assertIn(token, launchers.BIOS_ROOT_TOKENS)

    def test_no_place_is_filled_twice(self) -> None:
        added = [u["path"] for u in self._report() if u.get("launcher")]
        self.assertEqual(sorted(added), ["e.bin", "sub/fix.bin"])

    def test_a_declared_name_fills_the_place(self) -> None:
        layer = LauncherLayer(
            self.config, self.profiles, self.profiles, self.db, {"B.BIN"},
        )
        self.assertTrue(layer.platform_holds(layer.places[0]))
        self.assertFalse(layer.platform_holds(layer.places[1]))

    def test_verify_and_pack_agree(self) -> None:
        result = verify_platform(self.config, self.db, self.emulators_dir, self.profiles)
        missing = [
            u["name"] for u in result["undeclared_files"]
            if not u["in_repo"] and u.get("category", "bios") != "game_data"
        ]
        self.assertEqual(missing, [])
        names = self._pack_names() - {"README.txt"}
        for expected in ("e.bin", "sub/fix.bin", "b.bin"):
            self.assertIn(expected, names)
        self.assertNotIn("a.bin", names)
        self.assertEqual(result["packed_extras"]["bios"], len(names - {"plain.bin"}))

    def test_the_gap_report_reads_the_launcher_too(self) -> None:
        """cross_reference --platform batocera listed duckstation's
        scph1002a.bin as packed while the PAL slot was filled by the
        launcher's scph5502.bin, which verify and the builder both knew."""
        from cross_reference import cross_reference, declared_names, load_platform_files
        from launchers import declared_destinations

        selected = ["launchertest"]
        declared, data_dirs = load_platform_files(self.platforms_dir, selected)
        layer = LauncherLayer(
            self.config, self.profiles, self.profiles, self.db,
            declared_destinations(self.config),
        )
        report = cross_reference(
            self.profiles, declared, self.db, data_dirs, set(),
            all_declared=declared_names(self.platforms_dir, selected, self.db),
            standalone_cores={"psxemu", "fixemu"},
            platform="launchertest", launcher_layer=layer,
        )
        gaps = sorted(
            g["path"] for data in report.values() for g in data["gap_details"]
        )
        self.assertEqual(gaps, sorted(u["path"] for u in self._report()))
        self.assertNotIn("core.bin", gaps)
        self.assertEqual(report["fixemu"]["set_aside"]["launcher"], 1)

    def test_one_decision_for_verify_and_pack(self) -> None:
        """The layer is applied once, in the report both sides read."""
        import generate_pack
        import packextras
        import verify

        self.assertIn("LauncherLayer(", inspect.getsource(verify.find_undeclared_files))
        self.assertIn(".settle(", inspect.getsource(verify.find_undeclared_files))
        self.assertIn(
            "undeclared_report(", inspect.getsource(packextras._collect_emulator_extras)
        )
        self.assertIn(
            "find_undeclared_files(", inspect.getsource(packextras.undeclared_report)
        )
        for module in (generate_pack, packextras, verify):
            source = inspect.getsource(module)
            with self.subTest(module=module.__name__):
                self.assertNotIn("launcher_places(", source)
            if module is not verify:
                self.assertNotIn("LauncherLayer(", source)


if __name__ == "__main__":
    unittest.main()
