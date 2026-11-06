"""Files a libretro core reads below the frontend's save directory.

Azahar's libretro core moves its user folder to <save_dir>/Azahar/
(src/citra_libretro/core_settings.cpp:1048-1080), so keys.txt, the shared
font and the NAND files are read there and not below the system directory.
The profile says so with ``load_from: save_dir``. The pack places these
files in the platform's save folder, the manifest marks them ``root: save``,
verify credits the same paths, and the installer writes them below the save
directory the frontend's config names.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import functools
import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import yaml  # noqa: E402

from packpaths import (  # noqa: E402
    EMULATOR_PACK_SAVE_FOLDER,
    SaveLayout,
    _resolve_destination,
    save_destination,
    save_layout,
)
from validation import (  # noqa: E402
    entry_root,
    outside_gap_scope,
    read_from_save_dir,
    read_from_system_dir,
)

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)


def _scratch(test: unittest.TestCase) -> Path:
    """A folder under the repository's tmp/, removed after the test."""
    base = REPO_ROOT / "tmp"
    base.mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=str(base)))
    test.addCleanup(shutil.rmtree, path, True)
    return path


class TheEntryNamesItsRoot(unittest.TestCase):
    ENTRY = {"name": "keys.txt", "path": "CoreX/sysdata/keys.txt",
             "standalone_path": "sysdata/keys.txt",
             "load_from": {"libretro": "save_dir"}}

    def test_the_libretro_build_reads_below_the_save_directory(self):
        self.assertTrue(read_from_save_dir(self.ENTRY))
        self.assertEqual(entry_root(self.ENTRY), "save")
        self.assertFalse(read_from_system_dir(self.ENTRY))

    def test_the_standalone_build_has_no_frontend_save_directory(self):
        self.assertFalse(read_from_save_dir(self.ENTRY, standalone=True))
        self.assertEqual(entry_root(self.ENTRY, standalone=True), "system")
        plain = {"name": "a.bin", "path": "a.bin", "load_from": "save_dir"}
        self.assertTrue(read_from_save_dir(plain))
        self.assertFalse(read_from_save_dir(plain, standalone=True))

    def test_save_entries_are_in_the_pack_scope(self):
        self.assertFalse(outside_gap_scope(self.ENTRY, False))
        for other in ("content_dir", "working_directory", "internal_storage"):
            with self.subTest(load_from=other):
                self.assertTrue(outside_gap_scope({**self.ENTRY, "load_from": other}, False))

    def test_an_emulator_pack_keeps_them_in_their_own_folder(self):
        self.assertEqual(
            _resolve_destination(self.ENTRY, False),
            f"{EMULATOR_PACK_SAVE_FOLDER}/CoreX/sysdata/keys.txt",
        )
        self.assertEqual(_resolve_destination(self.ENTRY, True), "sysdata/keys.txt")


class ThePlatformNamesItsSaveDirectory(unittest.TestCase):
    def test_the_registry_block(self):
        self.assertEqual(
            save_layout({"save_directory": {"folder": "saves", "by_core": True}}),
            SaveLayout("saves", True),
        )
        for block in (None, {}, {"folder": ""}, {"folder": "../b", "by_core": True},
                      {"folder": "a/../b", "by_core": True}):
            with self.subTest(block=block):
                self.assertIsNone(save_layout({"save_directory": block}))
        self.assertIsNone(save_layout({}))

    def test_a_frontend_sorting_by_core_inserts_the_library_name(self):
        layout = SaveLayout("saves", True)
        self.assertEqual(save_destination("Azahar/sysdata/keys.txt", "Azahar", layout),
                         "saves/Azahar/Azahar/sysdata/keys.txt")
        # Unknown: nowhere to put it. Empty: the core reads the same place
        # sorted or not (an empty library_name, Cemu's own folder).
        self.assertIsNone(save_destination("Azahar/sysdata/keys.txt", None, layout))
        self.assertEqual(save_destination("Cemu/mlc01/x.ttf", "", layout),
                         "saves/Cemu/mlc01/x.ttf")
        self.assertEqual(
            save_destination("Azahar/sysdata/keys.txt", "", SaveLayout("savefiles", False)),
            "savefiles/Azahar/sysdata/keys.txt",
        )

    def test_retroarch_and_lakka_have_one_retropie_none(self):
        from common import load_platform_config

        platforms = str(REPO_ROOT / "platforms")
        self.assertEqual(save_layout(load_platform_config("retroarch", platforms)),
                         SaveLayout("saves", True))
        self.assertEqual(save_layout(load_platform_config("lakka", platforms)),
                         SaveLayout("savefiles", True))
        # RetroPie inherits RetroArch but keeps saves beside each game.
        self.assertIsNone(save_layout(load_platform_config("retropie", platforms)))

    def test_each_platform_running_these_cores_says_where(self):
        """The layout read from each platform's launch code, or none where
        saves sit beside each game or in a browser."""
        from common import load_platform_config

        platforms = str(REPO_ROOT / "platforms")
        expected = {
            "batocera": SaveLayout("saves", False, True, pack_folder="userdata-saves"),
            "knulli": SaveLayout("saves", False, True),
            "recalbox": SaveLayout("saves", False, True),
            "retrodeck": SaveLayout("saves", False, True),
            "retrobat": SaveLayout("saves", False, True, frozenset({"dolphin"})),
            "emudeck": SaveLayout("saves/retroarch/saves", False),
            "rocknix": None, "amberelec": None, "emuelec": None, "romm": None,
            "retropie": None,
        }
        for name, layout in expected.items():
            with self.subTest(platform=name):
                config = load_platform_config(name, platforms)
                self.assertEqual(save_layout(config), layout)
                if layout is not None and layout.by_system:
                    self.assertTrue(config.get("libretro_systems"))

    def test_a_save_folder_per_system(self):
        layout = SaveLayout("saves", False, True)
        self.assertEqual(save_destination("User/GBA/gba_bios.bin", "dolphin-emu", layout,
                                          "gamecube"),
                         "saves/gamecube/User/GBA/gba_bios.bin")
        # The system folder is required, and one folder name.
        self.assertIsNone(save_destination("a.bin", "X", layout))
        self.assertIsNone(save_destination("a.bin", "X", layout, "a/b"))
        # A launcher sorting one core by core (RetroBat's dolphin).
        sorted_one = SaveLayout("saves", False, True, frozenset({"dolphin"}))
        self.assertTrue(sorted_one.sorts({"dolphin", "dolphin-gui"}))
        self.assertFalse(sorted_one.sorts({"stella"}))
        self.assertEqual(
            save_destination("User/GBA/gba_bios.bin", "dolphin-emu", sorted_one, "wii",
                             sorted_one.sorts({"dolphin"})),
            "saves/wii/dolphin-emu/User/GBA/gba_bios.bin",
        )

    def test_a_pack_folder_apart_from_the_bios_tree(self):
        """Batocera's BIOS tree has a saves/ of its own: the pack keeps the
        save directory's files in another folder, the installer still
        writes them to /userdata/saves."""
        layout = save_layout({"save_directory": {
            "folder": "saves", "by_core": False, "by_system": True,
            "pack_folder": "userdata-saves"}})
        self.assertEqual(layout.in_pack, "userdata-saves")
        self.assertEqual(save_destination("stella/KVS1.WAV", None, layout, "atari2600"),
                         "userdata-saves/atari2600/stella/KVS1.WAV")
        self.assertEqual(SaveLayout("saves", True).in_pack, "saves")
        try:
            from validate_schemas import _bios_tree_below
        except ImportError:
            self.skipTest("validate_schemas needs jsonschema")
        self.assertEqual(_bios_tree_below("batocera", "saves"),
                         "saves/dolphin-emu/Triforce/segaboot.gcm")
        self.assertEqual(_bios_tree_below("batocera", "userdata-saves"), "")

    def test_the_systems_a_core_runs_for(self):
        from packpaths import libretro_systems

        config = {"libretro_systems": {"dolphin": ["wii", "gamecube"], "fbalpha": ["fbneo"],
                                       "fbalpha2012": ["cps3", "fbneo"]}}
        self.assertEqual(libretro_systems(config, ["dolphin"]), ["gamecube", "wii"])
        self.assertEqual(libretro_systems(config, ["fbalpha2012", "fbalpha"]),
                         ["cps3", "fbneo"])
        self.assertEqual(libretro_systems(config, ["stella"]), [])


class _Fixture(unittest.TestCase):
    """A RetroArch-like platform with a save directory, one without, and a
    core reading one file below the system directory and one below the save
    directory. The platform declares a keys.txt of its own in the BIOS tree:
    it does not answer for the one the core reads below the save directory."""

    SYS = b"SYSTEM FILE"
    KEYS = b"SAVE DIR KEYS"
    OTHER_KEYS = b"PLATFORM KEYS"

    def setUp(self) -> None:
        from common import _emulator_profiles_cache, _platform_config_cache

        _emulator_profiles_cache.clear()
        _platform_config_cache.clear()
        self.addCleanup(_platform_config_cache.clear)
        self.addCleanup(_emulator_profiles_cache.clear)
        self.root = _scratch(self)
        self.bios = self.root / "bios"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        for folder in (self.bios / "X", self.bios / "Y", self.platforms, self.emulators):
            folder.mkdir(parents=True)
        files: dict[str, dict] = {}
        by_name: dict[str, list[str]] = {}
        by_md5: dict[str, str] = {}
        for rel, data in (("X/sys.bin", self.SYS), ("X/keys.txt", self.KEYS),
                          ("Y/keys.txt", self.OTHER_KEYS)):
            path = self.bios / rel
            path.write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(path), "name": path.name, "md5": md5,
                           "size": len(data), "crc32": ""}
            by_name.setdefault(path.name, []).append(sha1)
            by_md5[md5] = sha1
        self.db = {"files": files, "indexes": {
            "by_md5": by_md5, "by_name": by_name, "by_crc32": {}, "by_path_suffix": {},
        }}
        system = {"files": [{"name": "keys.txt", "destination": "keys.txt",
                             "sha1": hashlib.sha1(self.OTHER_KEYS).hexdigest(),
                             "required": False}]}
        for name in ("testra", "testnosave"):
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "2.1", "verification_mode": "existence",
                "base_destination": "system", "cores": ["corex"],
                "systems": {"test-console": system},
            }))
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump({"platforms": {
            "testra": {"save_directory": {"folder": "saves", "by_core": True}},
            "testnosave": {"save_directory": None},
        }}))
        (self.emulators / "corex.yml").write_text(yaml.safe_dump({
            "emulator": "CoreX", "type": "libretro", "library_name": "CoreX",
            "systems": ["test-console"],
            "files": [
                {"name": "sys.bin", "path": "sys.bin", "required": True,
                 "sha1": hashlib.sha1(self.SYS).hexdigest()},
                {"name": "keys.txt", "path": "CoreX/sysdata/keys.txt",
                 "load_from": "save_dir", "required": False,
                 "sha1": hashlib.sha1(self.KEYS).hexdigest()},
            ],
        }))

    def config(self, name: str) -> dict:
        from common import load_platform_config

        return load_platform_config(name, str(self.platforms))

    def profiles(self) -> dict:
        from common import load_emulator_profiles

        return load_emulator_profiles(str(self.emulators))

    def pack(self, name: str) -> list[str]:
        from generate_pack import generate_pack

        out = self.root / f"out-{name}"
        out.mkdir()
        zip_path = generate_pack(
            name, str(self.platforms), self.db, str(self.bios), str(out),
            emulators_dir=str(self.emulators), offline=True,
        )
        with zipfile.ZipFile(zip_path) as zf:
            self.readme = zf.read("README.txt").decode()
            return sorted(zf.namelist())

    def manifest(self, name: str) -> dict:
        from generate_pack import generate_manifest

        return generate_manifest(
            name, str(self.platforms), self.db, str(self.bios),
            str(self.platforms / "_registry.yml"),
            emulators_dir=str(self.emulators), offline=True,
        )

    def verify(self, name: str) -> dict:
        from verify import verify_platform

        return verify_platform(self.config(name), self.db, str(self.emulators))


class ThePackPlacesThemInTheSaveFolder(_Fixture):
    SAVED = "saves/CoreX/CoreX/sysdata/keys.txt"

    def test_the_report_marks_the_entry(self):
        from verify import find_undeclared_files

        report = find_undeclared_files(
            self.config("testra"), str(self.emulators), self.db, self.profiles()
        )
        saved = [u for u in report if u["name"] == "keys.txt"]
        self.assertEqual(len(saved), 1, "the platform's keys.txt answers nothing here")
        self.assertEqual(
            {k: saved[0].get(k) for k in ("root", "core_folder", "path", "in_repo")},
            {"root": "save", "core_folder": "CoreX",
             "path": "CoreX/sysdata/keys.txt", "in_repo": True},
        )

    def test_pack_manifest_and_verify_agree(self):
        names = self.pack("testra")
        self.assertIn(self.SAVED, names)
        self.assertIn("keys.txt", names, "the platform's own keys.txt stays")
        self.assertIn("Files read from the save directory", self.readme)
        report = self.verify("testra")
        written = {n for n in names if n != "README.txt" and not n.endswith("/")}
        self.assertEqual(set(report["pack_destinations"]), written)

        manifest = self.manifest("testra")
        saved = [e for e in manifest["files"] if e.get("root") == "save"]
        self.assertEqual(len(saved), 1)
        self.assertEqual(
            {k: saved[0][k] for k in ("dest", "root", "core_folder", "sha1")},
            {"dest": "CoreX/CoreX/sysdata/keys.txt", "root": "save", "core_folder": "CoreX",
             "sha1": hashlib.sha1(self.KEYS).hexdigest()},
        )
        self.assertEqual(manifest["save_directory"], {"folder": "saves", "by_core": True})
        # The fixture's copies live outside a repository checkout: give them
        # the repository path the installer downloads from.
        for entry in manifest["files"]:
            entry["repo_path"] = f"bios/{Path(entry['repo_path']).name}"
        install._validate_manifest(manifest, "testra")

    def test_a_platform_without_a_save_directory_says_so(self):
        names = self.pack("testnosave")
        self.assertFalse(any(n.startswith("saves/") for n in names))
        self.assertNotIn("Files read from the save directory", self.readme)
        manifest = self.manifest("testnosave")
        self.assertNotIn("save_directory", manifest)
        omitted = [e for e in manifest["omitted_files"] if e.get("root") == "save"]
        self.assertEqual([(e["dest"], e["reason"]) for e in omitted],
                         [("CoreX/CoreX/sysdata/keys.txt", "no_save_directory")])
        report = self.verify("testnosave")
        entry = next(u for u in report["undeclared_files"] if u.get("root") == "save")
        self.assertFalse(entry["in_pack"])
        self.assertIn("no fixed place", entry["omitted"])
        self.assertFalse(any(p.startswith("saves/") for p in report["pack_destinations"]))

    def test_the_emulator_pack_and_verify_emulator_agree(self):
        from generate_pack import PackRecord, generate_emulator_pack
        from verify import verify_emulator

        record = PackRecord()
        generate_emulator_pack(
            ["corex"], str(self.emulators), self.db, str(self.bios), str(self.root),
            offline=True, platforms_dir=str(self.platforms), record=record,
        )
        self.assertIn("saves/CoreX/sysdata/keys.txt", record.files)
        report = verify_emulator(["corex"], str(self.emulators), self.db,
                                 platforms_dir=str(self.platforms))
        self.assertEqual(set(report["pack_destinations"]), set(record.files))


class AFolderPerSystem(_Fixture):
    """Batocera's launcher hands a core /userdata/saves/<system>, RetroBat's
    saves\\<system> with dolphin alone sorted by core: one copy of the file
    below each system the platform runs the core for."""

    OWN = b"COREY OWN FILE"

    def setUp(self) -> None:
        super().setUp()
        (self.bios / "X" / "own.bin").write_bytes(self.OWN)
        sha1 = hashlib.sha1(self.OWN).hexdigest()
        self.db["files"][sha1] = {
            "path": str(self.bios / "X" / "own.bin"), "name": "own.bin",
            "md5": hashlib.md5(self.OWN).hexdigest(), "size": len(self.OWN), "crc32": "",
        }
        self.db["indexes"]["by_name"]["own.bin"] = [sha1]
        (self.emulators / "corey.yml").write_text(yaml.safe_dump({
            "emulator": "CoreY", "type": "libretro", "library_name": "CoreY",
            "systems": ["test-console"],
            "files": [{"name": "own.bin", "path": "own.bin", "load_from": "save_dir",
                       "required": False, "sha1": sha1}],
        }))
        system = {"files": [{"name": "keys.txt", "destination": "keys.txt",
                             "sha1": hashlib.sha1(self.OTHER_KEYS).hexdigest(),
                             "required": False}]}
        for name in ("testbato", "testrb"):
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "2.1", "verification_mode": "existence",
                "base_destination": "bios", "cores": ["corex", "corey"],
                "systems": {"test-console": system},
                # Two systems run CoreX, none runs CoreY.
                "libretro_systems": {"corex": ["sysb", "sysa"], "other": ["sysc"]},
            }))
        registry = yaml.safe_load((self.platforms / "_registry.yml").read_text())
        registry["platforms"]["testbato"] = {"save_directory": {
            "folder": "saves", "by_core": False, "by_system": True}}
        registry["platforms"]["testrb"] = {"save_directory": {
            "folder": "saves", "by_core": False, "by_system": True, "by_core_for": ["corex"]}}
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump(registry))

    def test_one_copy_below_each_system(self):
        names = self.pack("testbato")
        saved = sorted(n for n in names if n.startswith("saves/"))
        self.assertEqual(saved, ["saves/sysa/CoreX/sysdata/keys.txt",
                                 "saves/sysb/CoreX/sysdata/keys.txt"])
        self.assertIn("the folder of each system", self.readme)
        report = self.verify("testbato")
        written = {n for n in names if n != "README.txt" and not n.endswith("/")}
        self.assertEqual(set(report["pack_destinations"]), written)

    def test_the_manifest_lists_each_copy(self):
        manifest = self.manifest("testbato")
        saved = sorted((e["dest"], e.get("core_folder")) for e in manifest["files"]
                       if e.get("root") == "save")
        # The launcher fixes the path: no core folder for the installer to undo.
        self.assertEqual(saved, [("sysa/CoreX/sysdata/keys.txt", None),
                                 ("sysb/CoreX/sysdata/keys.txt", None)])
        self.assertEqual(manifest["save_directory"],
                         {"folder": "saves", "by_core": False, "by_system": True})
        omitted = [(e["dest"], e["reason"]) for e in manifest["omitted_files"]
                   if e.get("root") == "save"]
        self.assertEqual(omitted, [("CoreY/own.bin", "no_save_system")])
        for entry in manifest["files"]:
            entry["repo_path"] = f"bios/{Path(entry['repo_path']).name}"
        install._validate_manifest(manifest, "testbato")

    def test_verify_says_why_a_core_without_a_system_is_left_out(self):
        report = self.verify("testbato")
        entry = next(u for u in report["undeclared_files"] if u["name"] == "own.bin")
        self.assertFalse(entry["in_pack"])
        self.assertIn("no system runs the core", entry["omitted"])

    def test_a_core_the_launcher_sorts(self):
        names = self.pack("testrb")
        self.assertEqual(sorted(n for n in names if n.startswith("saves/")),
                         ["saves/sysa/CoreX/CoreX/sysdata/keys.txt",
                          "saves/sysb/CoreX/CoreX/sysdata/keys.txt"])
        manifest = self.manifest("testrb")
        self.assertEqual(sorted(e["dest"] for e in manifest["files"] if e.get("root") == "save"),
                         ["sysa/CoreX/CoreX/sysdata/keys.txt",
                          "sysb/CoreX/CoreX/sysdata/keys.txt"])

    def test_two_cores_reading_one_path_in_one_folder_share_it(self):
        (self.emulators / "corez.yml").write_text(yaml.safe_dump({
            "emulator": "CoreZ", "type": "libretro", "library_name": "CoreZ",
            "systems": ["test-console"],
            "files": [{"name": "keys.txt", "path": "CoreX/sysdata/keys.txt",
                       "load_from": "save_dir", "required": False,
                       "sha1": hashlib.sha1(self.KEYS).hexdigest()}],
        }))
        config = yaml.safe_load((self.platforms / "testbato.yml").read_text())
        config["cores"].append("corez")
        config["libretro_systems"]["corez"] = ["sysa"]
        (self.platforms / "testbato.yml").write_text(yaml.safe_dump(config))
        names = self.pack("testbato")
        self.assertEqual(names.count("saves/sysa/CoreX/sysdata/keys.txt"), 1)
        manifest = self.manifest("testbato")
        shared = next(e for e in manifest["files"]
                      if e["dest"] == "sysa/CoreX/sysdata/keys.txt")
        self.assertEqual(sorted(shared["cores"]), ["corex", "corez"])


class TheInstallerFindsTheSaveDirectory(unittest.TestCase):
    MANIFEST = {"base_destination": "system",
                "save_directory": {"folder": "saves", "by_core": True}}

    def setUp(self) -> None:
        self.root = _scratch(self)
        self.app = self.root / "RetroArch"
        self.bios = self.app / "system"
        self.cfg = self.app / "retroarch.cfg"
        self.bios.mkdir(parents=True)
        self.addCleanup(install._RETROARCH_CONFIGS.pop, self.bios, None)
        self.addCleanup(install._SAVE_DIRS.pop, self.bios, None)

    def place(self, cfg: str | None, override: Path | None = None):
        if cfg is not None:
            self.cfg.write_text(cfg)
            install._RETROARCH_CONFIGS[self.bios] = (self.cfg, self.app)
        return install.save_directory_for(self.bios, self.MANIFEST, override)

    def test_a_config_left_at_its_defaults(self):
        self.assertEqual(self.place('system_directory = ":\\\\system"\n'),
                         install.SavePlace(self.app / "saves", True))

    def test_a_configured_folder_and_sorting(self):
        saves = self.root / "elsewhere"
        saves.mkdir()
        cfg = f'savefile_directory = "{saves}"\nsort_savefiles_enable = "false"\n'
        self.assertEqual(self.place(cfg), install.SavePlace(saves, False))

    def test_a_configured_folder_that_does_not_exist_is_ignored(self):
        cfg = f'savefile_directory = "{self.root / "gone"}"\n'
        self.assertEqual(self.place(cfg), install.SavePlace(self.app / "saves", True))

    def test_saves_beside_each_game_have_no_single_place(self):
        for key in ("savefiles_in_content_dir", "sort_savefiles_by_content_enable"):
            with self.subTest(key=key):
                found = self.place(f'{key} = "true"\n')
                self.assertIsInstance(found, str)
                self.assertIn(key, found)

    def test_without_a_config(self):
        self.assertEqual(self.place(None), install.SavePlace(self.app / "saves", True))
        other = self.root / "BIOS"
        found = install.save_directory_for(other, self.MANIFEST)
        self.assertIsInstance(found, str)
        self.assertIn("--save-dir", found)
        self.assertEqual(install.save_directory_for(other, self.MANIFEST, self.root / "s"),
                         install.SavePlace(self.root / "s", True))

    def test_a_launcher_writing_it_per_system_is_not_read_from_a_config(self):
        """Batocera and RetroBat write retroarch.cfg at each launch: the one
        on disk names the last system played."""
        manifest = {"base_destination": "system",
                    "save_directory": {"folder": "saves", "by_core": False, "by_system": True}}
        other = self.root / "elsewhere"
        other.mkdir()
        self.cfg.write_text(f'savefile_directory = "{other}"\nsort_savefiles_enable = "true"\n')
        install._RETROARCH_CONFIGS[self.bios] = (self.cfg, self.app)
        self.assertEqual(install.save_directory_for(self.bios, manifest),
                         install.SavePlace(self.app / "saves", False, False))

    def test_a_list_rooted_above_the_bios_folder(self):
        """RetroDECK's dests start at ~/retrodeck, which holds bios/ and saves/."""
        manifest = {"base_destination": "",
                    "save_directory": {"folder": "saves", "by_core": False, "by_system": True}}
        root = self.root / "retrodeck"
        self.assertEqual(install.save_directory_for(root, manifest),
                         install.SavePlace(root / "saves", False, False))

    def test_a_save_folder_several_levels_down(self):
        """EmuDeck: ~/Emulation/bios and ~/Emulation/saves/retroarch/saves."""
        manifest = {"base_destination": "bios",
                    "save_directory": {"folder": "saves/retroarch/saves", "by_core": False}}
        bios = self.root / "Emulation" / "bios"
        self.assertEqual(install.save_directory_for(bios, manifest),
                         install.SavePlace(self.root / "Emulation" / "saves/retroarch/saves",
                                           False, False))
        install._check_save_directory(manifest)

    def other_spelling(self, spelled: Path) -> install.SavePlace | str:
        """save_directory_for the BIOS folder written another way, the config
        keyed as detection writes it, with savefile_directory set."""
        saves = self.root / "MySaves"
        saves.mkdir(exist_ok=True)
        self.cfg.write_text(f'savefile_directory = "{saves}"\n')
        install._RETROARCH_CONFIGS[self.bios] = (self.cfg, self.app)
        self.addCleanup(install._SAVE_DIRS.pop, spelled, None)
        with mock.patch.object(install, "_CONFIGS_READ", [True]):
            return install.save_directory_for(spelled, self.MANIFEST)

    def test_a_relative_bios_folder_finds_its_config(self):
        """cd ~/.config/retroarch && install.py --dest system: the save files
        went to a guessed saves/ beside it."""
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.app)
        self.assertEqual(self.other_spelling(Path("system")),
                         install.SavePlace(self.root / "MySaves", True))

    def test_a_bios_folder_through_a_link_finds_its_config(self):
        """EmuDeck links RetroArch's system folder to ~/Emulation/bios."""
        link = self.root / "bios-link"
        link.symlink_to(self.bios, target_is_directory=True)
        self.assertEqual(self.other_spelling(link),
                         install.SavePlace(self.root / "MySaves", True))
        linked_app = self.root / "RA-link"
        linked_app.symlink_to(self.app, target_is_directory=True)
        self.assertEqual(self.other_spelling(linked_app / "system"),
                         install.SavePlace(self.root / "MySaves", True))

    def test_case_only_differs_where_the_system_folds_it(self):
        spelled = Path(str(self.bios).upper())
        with mock.patch.object(install.sys, "platform", "linux"):
            self.assertNotEqual(self.other_spelling(spelled),
                                install.SavePlace(self.root / "MySaves", True))
        install._SAVE_DIRS.pop(spelled, None)
        with mock.patch.object(install.sys, "platform", "darwin"):
            self.assertEqual(self.other_spelling(spelled),
                             install.SavePlace(self.root / "MySaves", True))

    def test_the_cores_folder_through_another_spelling(self):
        cores = self.root / "MyCores"
        cores.mkdir()
        self.cfg.write_text(f'libretro_directory = "{cores}"\n')
        install._RETROARCH_CONFIGS[self.bios] = (self.cfg, self.app)
        link = self.root / "bios-link"
        link.symlink_to(self.bios, target_is_directory=True)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.app)
        with mock.patch.object(install, "_CONFIGS_READ", [True]):
            for spelled in (Path("system"), link, Path("./system/")):
                with self.subTest(spelled=str(spelled)):
                    self.assertEqual(install.core_dirs("retroarch", spelled), [cores])

    def test_the_entry_path(self):
        saves = (self.app / "saves").resolve()
        install._SAVE_DIRS[self.bios] = install.SavePlace(self.app / "saves", True)
        entry = {"dest": "Azahar/Azahar/sysdata/keys.txt", "root": "save",
                 "core_folder": "Azahar"}
        self.assertEqual(install._entry_path(self.bios, entry),
                         saves / "Azahar/Azahar/sysdata/keys.txt")
        # sort_savefiles_enable off: the core is handed the save directory.
        install._SAVE_DIRS[self.bios] = install.SavePlace(self.app / "saves", False)
        self.assertEqual(install._entry_path(self.bios, entry),
                         saves / "Azahar/sysdata/keys.txt")
        # A list laid out unsorted, a frontend sorting: the folder goes in.
        install._SAVE_DIRS[self.bios] = install.SavePlace(self.app / "saves", True, False)
        self.assertEqual(
            install._entry_path(self.bios, {**entry, "dest": "Azahar/sysdata/keys.txt"}),
            saves / "Azahar/Azahar/sysdata/keys.txt",
        )
        # Cemu adds its folder once: no core_folder, the same place either way.
        cemu = {"dest": "Cemu/mlc01/a.ttf", "root": "save"}
        for by_core in (True, False):
            install._SAVE_DIRS[self.bios] = install.SavePlace(self.app / "saves", by_core)
            self.assertEqual(install._entry_path(self.bios, cemu), saves / "Cemu/mlc01/a.ttf")
        plain = {"dest": "Azahar/sysdata/keys.txt"}
        self.assertEqual(install._entry_path(self.bios, plain),
                         self.bios.resolve() / "Azahar/sysdata/keys.txt")


class TheManifestBoundary(unittest.TestCase):
    ENTRY = {"dest": "Azahar/Azahar/sysdata/keys.txt", "sha1": "a" * 40, "sha256": "b" * 64,
             "size": 1, "repo_path": "bios/x/keys.txt", "cores": ["azahar"],
             "root": "save", "core_folder": "Azahar"}

    def manifest(self, entry: dict, layout: object = ...) -> dict:
        data = {"manifest_version": 2, "platform": "retroarch", "files": [entry],
                "total_files": 1, "total_size": 1}
        if layout is not ...:
            data["save_directory"] = layout
        return data

    def test_a_save_entry_crosses_it(self):
        install._validate_manifest(
            self.manifest(self.ENTRY, {"folder": "saves", "by_core": True}), "retroarch"
        )

    def test_what_is_refused(self):
        layout = {"folder": "saves", "by_core": True}
        for label, data in (
            ("no save_directory", self.manifest(self.ENTRY)),
            ("other root", self.manifest({**self.ENTRY, "root": "content"}, layout)),
            ("climbing core folder", self.manifest({**self.ENTRY, "core_folder": ".."}, layout)),
            ("nested core folder", self.manifest({**self.ENTRY, "core_folder": "a/b"}, layout)),
            ("core folder on a BIOS file", self.manifest(
                {k: v for k, v in self.ENTRY.items() if k != "root"}, layout)),
            ("climbing save folder", self.manifest(self.ENTRY, {"folder": "..", "by_core": True})),
            ("save folder climbing inside", self.manifest(
                self.ENTRY, {"folder": "a/../b", "by_core": True})),
            ("by_system not true", self.manifest(
                self.ENTRY, {"folder": "saves", "by_core": True, "by_system": False})),
            ("unknown save_directory key", self.manifest(
                self.ENTRY, {"folder": "saves", "by_core": True, "by_game": True})),
            ("by_core not a flag", self.manifest(self.ENTRY, {"folder": "saves", "by_core": 1})),
            ("dest without its core folder", self.manifest(
                {**self.ENTRY, "dest": "sysdata/keys.txt"}, layout)),
        ):
            with self.subTest(label), self.assertRaises(ValueError):
                install._validate_manifest(data, "retroarch")


class _Repository:
    """A loopback copy of the repository serving one manifest and its files."""

    def __init__(self, test: unittest.TestCase, files: dict[str, tuple[bytes, dict]]):
        self.root = _scratch(test)
        (self.root / "install").mkdir()
        (self.root / "bios").mkdir()
        entries = []
        for dest, (payload, extra) in files.items():
            stored = dest.replace("/", "_")
            (self.root / "bios" / stored).write_bytes(payload)
            entries.append({
                "dest": dest, "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                "repo_path": f"bios/{stored}", "cores": None, **extra,
            })
        manifest = {"manifest_version": 2, "platform": "retroarch",
                    "base_destination": "system", "files": entries,
                    "save_directory": {"folder": "saves", "by_core": True}}
        (self.root / "install" / "retroarch.json").write_text(json.dumps(manifest))
        handler = functools.partial(_Quiet, directory=str(self.root))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        test.addCleanup(self.httpd.server_close)
        test.addCleanup(self.httpd.shutdown)

    def run(self, *options: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["RETROBIOS_BASE_URL"] = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
             "--yes", *options],
            env=env, capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL,
        )


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: D102
        pass


class TheInstallerWritesThem(unittest.TestCase):
    FILES = {
        "sys.bin": (b"system file", {}),
        "Azahar/Azahar/sysdata/keys.txt": (
            b"keys below the save directory", {"root": "save", "core_folder": "Azahar"},
        ),
    }

    def test_beside_the_default_bios_folder(self):
        repo = _Repository(self, self.FILES)
        app = _scratch(self)
        proc = repo.run("--dest", str(app / "system"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((app / "system" / "sys.bin").read_bytes(), b"system file")
        self.assertEqual(
            (app / "saves" / "Azahar" / "Azahar" / "sysdata" / "keys.txt").read_bytes(),
            b"keys below the save directory",
        )
        self.assertFalse((app / "system" / "Azahar").exists())
        self.assertIn("read from RetroArch's save directory goes to", proc.stdout)

    def test_where_save_dir_points(self):
        repo = _Repository(self, self.FILES)
        app = _scratch(self)
        saves = app / "my saves"
        proc = repo.run("--dest", str(app / "BIOS"), "--save-dir", str(saves))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((saves / "Azahar" / "Azahar" / "sysdata" / "keys.txt").is_file())

    def test_left_out_and_said_when_the_save_directory_is_unknown(self):
        repo = _Repository(self, self.FILES)
        app = _scratch(self)
        proc = repo.run("--dest", str(app / "BIOS"))
        self.assertTrue((app / "BIOS" / "sys.bin").is_file(), proc.stdout + proc.stderr)
        self.assertFalse(any(app.rglob("keys.txt")))
        self.assertIn("--save-dir", proc.stdout)


class TheProfilesFollowTheContract(unittest.TestCase):
    def test_every_save_dir_entry_has_a_library_name(self):
        try:
            from validate_schemas import _save_dir_without_library_name
        except ImportError:
            self.skipTest("validate_schemas needs jsonschema")

        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            with self.subTest(profile=path.name):
                self.assertEqual(_save_dir_without_library_name(path, document), [])

    def test_azahar_reads_its_user_folder_below_the_save_directory(self):
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "azahar.yml").read_text())
        self.assertEqual(profile["library_name"], "Azahar")
        for entry in profile["files"]:
            with self.subTest(entry=entry["name"]):
                self.assertTrue(read_from_save_dir(entry))
                self.assertTrue(entry["path"].startswith("Azahar/"))

    def test_the_registry_blocks(self):
        try:
            from validate_schemas import _save_directory_blocks
        except ImportError:
            self.skipTest("validate_schemas needs jsonschema")

        self.assertEqual(_save_directory_blocks(), [])

    def test_the_published_retroarch_list_places_azahar(self):
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        self.assertEqual(manifest.get("save_directory"), {"folder": "saves", "by_core": True})
        azahar = {e["dest"]: e for e in manifest["files"] if e.get("core_folder") == "Azahar"}
        self.assertIn("Azahar/Azahar/sysdata/keys.txt", azahar)
        self.assertTrue(all(e["root"] == "save" for e in azahar.values()))


class TheScrapersReadTheSystemLists(unittest.TestCase):
    """libretro_systems, read from each platform's own system list."""

    def setUp(self) -> None:
        sys.path.insert(0, str(REPO_ROOT))
        self.addCleanup(sys.path.remove, str(REPO_ROOT))

    def test_batocera_and_knulli_es_systems_yml(self):
        from scripts.scraper.batocera_scraper import es_systems_libretro_systems

        text = (
            "gamecube:\n  emulators:\n    dolphin:\n      dolphin: { requireAnyOf: [A] }\n"
            "    libretro:\n      dolphin: { requireAnyOf: [B] }\n"
            "wii:\n  emulators:\n    libretro:\n      dolphin: { requireAnyOf: [B] }\n"
            "      plugin: { requireAnyOf: [C] }\n"
            "atari2600:\n  emulators:\n    libretro:\n      stella: { requireAnyOf: [D] }\n"
        )
        self.assertEqual(es_systems_libretro_systems(text, {"plugin"}),
                         {"dolphin": ["gamecube", "wii"], "stella": ["atari2600"]})

    def test_retrobat_es_systems_cfg(self):
        from scripts.scraper.retrobat_scraper import es_systems_libretro_systems

        text = (
            "<systemList><system><name>3ds</name><emulators>"
            "<emulator name=\"libretro\"><cores><core>azahar</core>"
            "<!-- <core>citra</core> --></cores></emulator>"
            "<emulator name=\"citra-qt\"><cores><core>citra-qt</core></cores></emulator>"
            "</emulators></system></systemList>"
        )
        self.assertEqual(es_systems_libretro_systems(text), {"azahar": ["3ds"]})

    def test_recalbox_system_ini(self):
        from scripts.scraper.recalbox_scraper import libretro_systems

        wii = ("[system]\nname = \"wii\"\n[core.0]\nemulator = \"dolphin-gui\"\n"
               "core = \"dolphin-gui\"\n[core.2]\nemulator = \"libretro\"\ncore = \"dolphin\"\n")
        nameless = "[core.0]\nemulator = \"libretro\"\ncore = \"stella\"\n"
        self.assertEqual(libretro_systems({"wii": wii, "atari2600": nameless}),
                         {"dolphin": ["wii"], "stella": ["atari2600"]})

    def test_retrodeck_es_de_commands(self):
        from scripts.scraper.retrodeck_scraper import es_systems_libretro_systems

        text = (
            "<systemList><system><name>n3ds</name><path>%ROMPATH%/n3ds</path>"
            "<command label=\"Azahar (Standalone)\">%EMULATOR_AZAHAR% %ROM%</command>"
            "<command label=\"Citra\">%EMULATOR_RETROARCH% -L "
            "%CORE_RETROARCH%/citra_libretro.so %ROM%</command>"
            "<!-- <command>%EMULATOR_RETROARCH% -L %CORE_RETROARCH%/x_libretro.so</command> -->"
            "</system></systemList>"
        )
        self.assertEqual(es_systems_libretro_systems(text), {"citra": ["n3ds"]})

    def test_the_published_platform_files(self):
        expected = {
            "batocera": {"dolphin": ["gamecube", "wii"], "stella": ["atari2600"]},
            "knulli": {"dolphin": ["gamecube", "wii"], "citra": ["3ds"]},
            "retrobat": {"azahar": ["3ds"], "dolphin": ["gamecube", "triforce", "wii"]},
            "recalbox": {"dolphin": ["gamecube", "wii"], "stella": ["atari2600"]},
            "retrodeck": {"citra": ["n3ds"], "stella": ["atari2600"]},
        }
        for name, cores in expected.items():
            table = yaml.safe_load(
                (REPO_ROOT / "platforms" / f"{name}.yml").read_text(encoding="utf-8")
            )["libretro_systems"]
            for core, systems in cores.items():
                with self.subTest(platform=name, core=core):
                    self.assertEqual(table[core], systems)

    def test_the_published_batocera_list_places_dolphin_per_system(self):
        manifest = json.loads((REPO_ROOT / "install" / "batocera.json").read_text())
        self.assertEqual(manifest.get("save_directory"),
                         {"folder": "saves", "by_core": False, "by_system": True})
        dests = {e["dest"] for e in manifest["files"] if e.get("root") == "save"}
        for system in ("gamecube", "wii"):
            self.assertIn(f"{system}/User/GBA/gba_bios.bin", dests)
        self.assertIn("atari2600/stella/KVS1.WAV", dests)


class TheSchemasCarryTheFields(unittest.TestCase):
    def test_install_manifest_and_profile_schemas(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())
        validator = Draft202012Validator(schema)
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        self.assertEqual(list(validator.iter_errors(manifest)), [])
        bad = {**manifest, "files": [{**manifest["files"][0], "root": "content"}]}
        self.assertTrue(list(validator.iter_errors(bad)))

        emulator = json.loads((REPO_ROOT / "schemas" / "emulator.schema.json").read_text())
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "azahar.yml").read_text())
        self.assertEqual(list(Draft202012Validator(emulator).iter_errors(profile)), [])
        self.assertTrue(list(Draft202012Validator(emulator).iter_errors(
            {**profile, "library_name": "a/b"}
        )))


if __name__ == "__main__":
    unittest.main()
