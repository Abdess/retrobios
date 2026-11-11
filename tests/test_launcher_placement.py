"""A platform's launcher moves where an emulator's file lands.

A profile's ``path`` is where the emulator's code reads a file. UAE4All2
reads kickstarts/<name> below its working directory, and RetroPie starts it
in its install directory, whose kickstarts/ it links to BIOS/amiga. The
pack, the manifest and verify all put the file in amiga/ on that platform,
and a platform with no such record keeps the profile's layout.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    _emulator_profiles_cache,
    load_emulator_profiles,
    load_platform_config,
    platform_layouts,
    standalone_set,
)
from generate_pack import generate_manifest, generate_pack  # noqa: E402
from verify import verify_platform  # noqa: E402

WORKING_DIRECTORY = {
    "emulator": "kick", "build": "standalone", "kind": "passes_path", "names": [],
    "search_dir": "$md_inst", "passes_to": "working directory of $romdir/amiga/+Start.sh",
    "source_ref": "kick.sh:90",
}
LINK = {
    "emulator": "kick", "build": "standalone", "kind": "links", "names": [],
    "search_dir": "$biosdir/amiga", "passes_to": "$md_inst/kickstarts is a symlink to it",
    "source_ref": "kick.sh:79",
}


class ALinkMovesTheDestination(unittest.TestCase):
    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        bios = self.root / "bios" / "Commodore" / "Amiga"
        bios.mkdir(parents=True)
        files, by_md5, by_name = {}, {}, {}
        for name, data in (("kick13.rom", b"KICKSTART 1.3"), ("kick.rom", b"CUSTOM KICKSTART")):
            (bios / name).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(bios / name), "name": name, "sha1": sha1,
                           "md5": md5, "crc32": "", "size": len(data)}
            by_md5[md5] = sha1
            by_name[name] = [sha1]
        self.db = {
            "files": files,
            "indexes": {"by_md5": by_md5, "by_name": by_name, "by_crc32": {},
                        "by_path_suffix": {}},
        }
        kick13 = by_name["kick13.rom"][0]
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        self.platforms.mkdir()
        self.emulators.mkdir()
        for name, launchers in (("linkplat", [WORKING_DIRECTORY, LINK]), ("plainplat", [])):
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "1", "verification_mode": "existence",
                "base_destination": "BIOS", "cores": ["kick"], "standalone_cores": ["kick"],
                "launchers": launchers,
                "systems": {"commodore-amiga": {"files": []}},
            }))
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump({"platforms": {
            "linkplat": {"config": "linkplat.yml"}, "plainplat": {"config": "plainplat.yml"},
        }}))
        (self.emulators / "kick.yml").write_text(yaml.safe_dump({
            "emulator": "Kick", "type": "standalone", "cores": ["kick"],
            "systems": ["commodore-amiga"],
            "standalone_directories": ["getcwd"],
            "files": [
                {"name": "kick13.rom", "path": "kickstarts/kick13.rom",
                 "sha1": kick13, "required": False},
                # Read in the working directory itself, which the platform
                # links nowhere in the BIOS tree.
                {"name": "kick.rom", "path": "kick.rom", "required": False},
            ],
        }))

    def pack_names(self, platform: str, name: str = "kick13.rom") -> list[str]:
        with redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.root / "out" / platform), emulators_dir=str(self.emulators),
                offline=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            return [n for n in zf.namelist() if n.rsplit("/", 1)[-1] == name]

    def manifest(self, platform: str) -> dict:
        with redirect_stdout(io.StringIO()):
            return generate_manifest(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.platforms / "_registry.yml"),
                emulators_dir=str(self.emulators), offline=True,
            )

    def manifest_dests(self, platform: str, name: str = "kick13.rom") -> list[str]:
        return [f["dest"] for f in self.manifest(platform)["files"]
                if f["dest"].rsplit("/", 1)[-1] == name]

    def verify_entries(self, platform: str, name: str = "kick13.rom") -> list[dict]:
        config = load_platform_config(platform, str(self.platforms))
        result = verify_platform(config, self.db, str(self.emulators))
        return [u for u in result["undeclared_files"] if u["name"] == name]

    def verify_paths(self, platform: str) -> list[str]:
        return [u["path"] for u in self.verify_entries(platform)]

    def test_the_link_moves_it_in_pack_manifest_and_verify(self) -> None:
        self.assertEqual(self.pack_names("linkplat"), ["amiga/kick13.rom"])
        self.assertEqual(self.manifest_dests("linkplat"), ["amiga/kick13.rom"])
        self.assertEqual(self.verify_paths("linkplat"), ["amiga/kick13.rom"])

    def test_a_platform_without_the_record_is_unchanged(self) -> None:
        self.assertEqual(self.pack_names("plainplat"), ["kickstarts/kick13.rom"])
        self.assertEqual(self.manifest_dests("plainplat"), ["kickstarts/kick13.rom"])
        self.assertEqual(self.verify_paths("plainplat"), ["kickstarts/kick13.rom"])

    def test_a_file_outside_every_binding_is_named_never_placed(self) -> None:
        self.assertEqual(self.pack_names("linkplat", "kick.rom"), [])
        manifest = self.manifest("linkplat")
        self.assertEqual(self.manifest_dests("linkplat", "kick.rom"), [])
        omitted = [o for o in manifest["omitted_files"] if o["name"] == "kick.rom"]
        self.assertEqual(len(omitted), 1)
        self.assertEqual(
            (omitted[0]["dest"], omitted[0]["root"], omitted[0]["reason"], omitted[0]["cores"]),
            ("kick.rom", "emulator", "outside_bios_folder", ["kick"]),
        )
        (entry,) = self.verify_entries("linkplat", "kick.rom")
        self.assertFalse(entry["in_pack"])
        self.assertIn("outside the BIOS tree", entry["omitted"])

    def test_a_root_file_of_another_core_is_not_claimed_by_it(self) -> None:
        # Another core reads kick.rom at the BIOS root: kick's own kick.rom,
        # in its working directory, is a different place.
        for name in ("linkplat", "plainplat"):
            path = self.platforms / f"{name}.yml"
            data = yaml.safe_load(path.read_text())
            data["cores"] = ["kick", "other"]
            path.write_text(yaml.safe_dump(data))
        (self.emulators / "other.yml").write_text(yaml.safe_dump({
            "emulator": "Other", "type": "libretro", "cores": ["other"],
            "systems": ["commodore-amiga"],
            "files": [{"name": "kick.rom", "path": "kick.rom", "required": False}],
        }))
        _emulator_profiles_cache.clear()
        manifest = self.manifest("linkplat")
        (held,) = [f for f in manifest["files"] if f["dest"] == "kick.rom"]
        self.assertEqual(held["cores"], ["other"])
        omitted = [o for o in manifest["omitted_files"] if o["name"] == "kick.rom"]
        self.assertEqual([(o["root"], o["cores"]) for o in omitted], [("emulator", ["kick"])])

    def test_two_builds_in_one_folder_are_one_omission(self) -> None:
        # RetroPie builds amiberry 5.7.2 and 6.3.3, one per board, both in
        # $md_inst of its amiberry package: one place, read by both.
        data = yaml.safe_load((self.emulators / "kick.yml").read_text())
        for key in ("kick-1", "kick-2"):
            (self.emulators / f"{key}.yml").write_text(
                yaml.safe_dump({**data, "built_by": ["linkplat"]}))
        _emulator_profiles_cache.clear()
        omitted = [o for o in self.manifest("linkplat")["omitted_files"]
                   if o["name"] == "kick.rom"]
        self.assertEqual([(o["root"], o["cores"]) for o in omitted],
                         [("emulator", ["kick-1", "kick-2"])])

    def test_the_installer_accepts_the_omission(self) -> None:
        import install

        manifest = self.manifest("linkplat")
        omitted = next(o for o in manifest["omitted_files"] if o["name"] == "kick.rom")
        install._check_omission(omitted, omitted["dest"])
        # Two emulators reading kick.rom in their own folders read two files.
        self.assertNotEqual(
            install._entry_key(omitted), install._entry_key({**omitted, "cores": ["other"]})
        )
        self.assertNotEqual(install._entry_key(omitted), install._entry_key({"dest": "kick.rom"}))
        self.assertEqual(install.OMISSION_REASONS[omitted["reason"]], "read outside the BIOS folder")
        with self.assertRaises(ValueError):
            install._check_root({"root": "emulator"}, "kick.rom")
        install._check_root(omitted, "kick.rom", omitted=True)

    def test_without_relocation_the_root_file_stays_at_the_root(self) -> None:
        self.assertEqual(self.pack_names("plainplat", "kick.rom"), ["kick.rom"])

    def test_the_link_alone_binds_nothing(self) -> None:
        # Without the working directory the link's $md_inst is not the
        # directory the profile's paths are relative to.
        config = {"standalone_cores": ["kick"], "launchers": [LINK]}
        profile = load_emulator_profiles(str(self.emulators))["kick"]
        (view, standalone), = platform_layouts("kick", profile, standalone_set(config))
        self.assertTrue(standalone)
        self.assertNotIn("standalone_path", view["files"][0])


class UAE4AllOnRetroPie(unittest.TestCase):
    """The real profile against the real launcher records."""

    def test_kickstarts_land_in_amiga(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["uae4all"]
        config = load_platform_config("retropie", str(REPO_ROOT / "platforms"))
        (view, standalone), = platform_layouts("uae4all", profile, standalone_set(config))
        self.assertTrue(standalone)
        for entry in view["files"]:
            if entry["path"].startswith("kickstarts/"):
                self.assertEqual(
                    entry["standalone_path"], "amiga/" + entry["path"].removeprefix("kickstarts/")
                )
            else:
                # kick.rom and rom.key in the working directory, $md_inst
                self.assertEqual(entry.get("unplaced"), "outside_bios_folder", entry["path"])



class FsUaeOnRetroPie(unittest.TestCase):
    """RetroPie lists KS 1.3 as kick34005.A500, and its fs-uae launcher
    passes $biosdir/kick13.rom (fs-uae.sh:23-26). The listed copy settles
    fs-uae's entry by content, and the launcher's name was filled only as
    a copy of UAE4All2's amiga/kick13.rom: a board without UAE4All2 lost it."""

    def test_the_launcher_name_is_filled_without_another_core(self) -> None:
        import json

        from common import load_target_config

        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        db = json.loads(db_path.read_text(encoding="utf-8"))
        cores = load_target_config("retropie", "x86", str(REPO_ROOT / "platforms"))
        self.assertNotIn("uae4all", cores)
        with redirect_stdout(io.StringIO()):
            manifest = generate_manifest(
                "retropie", str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "platforms" / "_registry.yml"),
                emulators_dir=str(REPO_ROOT / "emulators"), offline=True,
                target_cores=set(cores), target_name="x86",
            )
        held = [(f["dest"], f["cores"]) for f in manifest["files"]
                if f["dest"].rsplit("/", 1)[-1] == "kick13.rom"]
        self.assertEqual(held, [("kick13.rom", ["fs-uae"])])


class XboxOnRetroBat(unittest.TestCase):
    """RetroBat's launcher writes xemu's eeprom.bin and disk image into
    saves/<system> and cxbx-reloaded's EEPROM.bin into its emulator folder,
    and each Cxbx build reads its data from the folder it runs from
    (Xemu.Generator.cs:82-113, Cxbx.Generator.cs:99-115, 158, 216-223)."""

    def test_nothing_lands_at_the_bios_root(self) -> None:
        import json

        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        db = json.loads(db_path.read_text(encoding="utf-8"))
        with redirect_stdout(io.StringIO()):
            manifest = generate_manifest(
                "retrobat", str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "platforms" / "_registry.yml"),
                emulators_dir=str(REPO_ROOT / "emulators"), offline=True,
            )
        at_root = {f["dest"].lower() for f in manifest["files"] if not f.get("root")}
        # The launcher writes the two EEPROMs and the disk image, mounts an
        # .iso with its own tool, and each Cxbx build reads keys.bin from
        # its own folder. wpcap.dll comes with the Npcap driver.
        self.assertFalse(at_root & {
            "eeprom.bin", "xbox_hdd.qcow2", "dokan2.dll", "keys.bin", "wpcap.dll",
        })
        placed = {(f.get("root"), f["dest"]) for f in manifest["files"]}
        self.assertIn(("emulators", "cxbx-reloaded/keys.bin"), placed)
        self.assertIn(("emulators", "chihiro/EEPROM.bin"), placed)
        self.assertNotIn(("emulators", "cxbx-reloaded/EEPROM.bin"), placed)


PROGRAM = b"PROGRAM BINARY"
PROGRAM_DATA = b"PROGRAM DATA"


class AProgramRunFromItsFolder(unittest.TestCase):
    """A program that reads its files beside its executable.

    The profile gives the layout of the program's archive (prog/prog,
    prog/prog.dat) and declares the executable directory. A platform that
    runs prog/prog from its BIOS folder keeps that layout, one that runs it
    from roms/prog places the program folder below its roms folder, and one
    that runs it from an emulator folder names its files as not placeable.
    """

    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        bios = self.root / "bios" / "Maker" / "Prog"
        bios.mkdir(parents=True)
        files, by_md5, by_name = {}, {}, {}
        for name, data in (("prog", PROGRAM), ("prog.dat", PROGRAM_DATA)):
            (bios / name).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(bios / name), "name": name, "sha1": sha1,
                           "md5": md5, "crc32": "", "size": len(data)}
            by_md5[md5] = sha1
            by_name[name] = [sha1]
        self.db = {"files": files, "indexes": {
            "by_md5": by_md5, "by_name": by_name, "by_crc32": {}, "by_path_suffix": {}}}
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        self.platforms.mkdir()
        self.emulators.mkdir()
        run = {"emulator": "prog", "build": "standalone", "kind": "fixed_name",
               "passes_to": "exec", "source_ref": "start_prog.sh:9"}
        launchers = {
            "biosplat": [{**run, "names": ["prog/prog"], "search_dir": "/userdata/bios"}],
            "romsplat": [{**run, "names": ["prog"], "search_dir": "/storage/roms/prog"}],
            "exeplat": [{**run, "names": ["prog"], "search_dir": "<emulator folder>"}],
            "emuplat": [{**run, "names": ["prog"], "search_dir": '<GetPath("prog")>'}],
            "plainplat": [],
        }
        for name, records in launchers.items():
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "1", "verification_mode": "existence",
                "base_destination": "bios", "cores": ["prog"], "standalone_cores": ["prog"],
                "launchers": records,
                "systems": {"prog-system": {"files": []}},
            }))
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump({"platforms": {
            **{name: {"config": f"{name}.yml"} for name in launchers},
            "emuplat": {"config": "emuplat.yml", "emulators_directory": {
                "launcher_spelling": '<GetPath("{key}")>', "bios_folder": "bios",
                "searched": ["frontend/{key}", "emulators/{key}"],
                "default": "emulators/{key}", "config": "frontend/launcher.cfg"}},
        }}))
        # The roms root as the OS's own source records it (romfolders).
        (self.platforms / "romfolders").mkdir()
        (self.platforms / "romfolders" / "romsplat.yml").write_text(yaml.safe_dump({
            "setup": "romsplat", "platform": "romsplat",
            "roms_root": {"path": "/storage/roms", "from_bios": "..", "source_ref": "os x.mk:1"},
            "folders": [],
        }))
        # A list that installs into the roms root itself, its BIOS folder
        # one of the folders there (AmberELEC's /storage/roms).
        (self.platforms / "rootplat.yml").write_text(yaml.safe_dump({
            "platform": "rootplat", "version": "1", "verification_mode": "existence",
            "base_destination": "", "cores": ["prog"], "standalone_cores": ["prog"],
            "launchers": [{**run, "names": ["prog"], "search_dir": "/storage/roms/prog"}],
            "systems": {"prog-system": {"files": [
                {"name": "own.bin", "destination": "bios/own.bin", "required": False},
            ]}},
        }))
        registry = yaml.safe_load((self.platforms / "_registry.yml").read_text())
        registry["platforms"]["rootplat"] = {"config": "rootplat.yml"}
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump(registry))
        (self.platforms / "romfolders" / "rootplat.yml").write_text(yaml.safe_dump({
            "setup": "rootplat", "platform": "rootplat",
            "roms_root": {"path": "/storage/roms", "from_bios": "..", "source_ref": "os x.mk:1"},
            "folders": [],
        }))
        (self.emulators / "prog.yml").write_text(yaml.safe_dump({
            "emulator": "Prog", "type": "standalone", "cores": ["prog"],
            "systems": ["prog-system"],
            "standalone_directories": ["executable directory"],
            "files": [
                {"name": "prog", "path": "prog/prog", "sha1": by_name["prog"][0],
                 "required": True},
                {"name": "prog.dat", "path": "prog/prog.dat",
                 "sha1": by_name["prog.dat"][0], "required": True},
            ],
        }))

    def pack(self, platform: str) -> list[str]:
        with redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.root / "out" / platform), emulators_dir=str(self.emulators),
                offline=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            return sorted(n for n in zf.namelist() if n.split("/")[-1].startswith("prog"))

    def manifest(self, platform: str) -> dict:
        with redirect_stdout(io.StringIO()):
            return generate_manifest(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.platforms / "_registry.yml"),
                emulators_dir=str(self.emulators), offline=True,
            )

    def verify(self, platform: str) -> list[dict]:
        config = load_platform_config(platform, str(self.platforms))
        result = verify_platform(config, self.db, str(self.emulators))
        return [u for u in result["undeclared_files"] if u["name"].startswith("prog")]

    def test_run_from_the_bios_folder_keeps_the_layout(self) -> None:
        for platform in ("biosplat", "plainplat"):
            with self.subTest(platform=platform):
                self.assertEqual(self.pack(platform), ["prog/prog", "prog/prog.dat"])
                self.assertEqual(
                    sorted(f["dest"] for f in self.manifest(platform)["files"]),
                    ["prog/prog", "prog/prog.dat"],
                )

    def test_run_from_the_roms_folder_is_installed_there(self) -> None:
        self.assertEqual(self.pack("romsplat"), [])
        manifest = self.manifest("romsplat")
        self.assertEqual(
            sorted((f["dest"], f.get("root")) for f in manifest["files"]),
            [("prog/prog", "roms"), ("prog/prog.dat", "roms")],
        )
        self.assertEqual(manifest["roms_directory"], {"bios_folder": "bios", "from_bios": ".."})
        entries = self.verify("romsplat")
        self.assertEqual(sorted(u["path"] for u in entries), ["prog/prog", "prog/prog.dat"])
        self.assertTrue(all(u["in_pack"] is False for u in entries))

    def test_a_roms_root_inside_the_install_tree_is_a_plain_dest(self) -> None:
        self.assertEqual(self.pack("rootplat"), ["prog/prog", "prog/prog.dat"])
        manifest = self.manifest("rootplat")
        self.assertEqual(
            sorted((f["dest"], f.get("root")) for f in manifest["files"] if "prog" in f["dest"]),
            [("prog/prog", None), ("prog/prog.dat", None)],
        )
        self.assertNotIn("roms_directory", manifest)

    def test_run_from_an_emulator_folder_is_named(self) -> None:
        self.assertEqual(self.pack("exeplat"), [])
        manifest = self.manifest("exeplat")
        self.assertEqual([f["dest"] for f in manifest["files"]], [])
        self.assertEqual(
            sorted((o["dest"], o["root"], o["reason"]) for o in manifest["omitted_files"]),
            [("prog/prog", "emulator", "outside_bios_folder"),
             ("prog/prog.dat", "emulator", "outside_bios_folder")],
        )

    def test_the_installer_finds_the_roms_folder_above_the_bios_folder(self) -> None:
        import install

        manifest = self.manifest("romsplat")
        install._check_relative_directories(manifest)
        files = list(manifest["files"])
        card = self.root / "card" / "roms" / "bios"
        kept, left = install.place_relative_entries(files, card, manifest, "romsplat", say=False)
        self.assertEqual((len(kept), left), (2, []))
        self.assertEqual(
            install._entry_path(card, kept[0]),
            (card.parent / kept[0]["dest"]).resolve()
            if install._entry_path(card, kept[0]).is_absolute() else card.parent / kept[0]["dest"],
        )
        other = self.root / "elsewhere"
        kept, left = install.place_relative_entries(files, other, manifest, "romsplat", say=False)
        self.assertEqual(kept, [])
        self.assertEqual({o["reason"] for o in left}, {"no_roms_directory"})
        with self.assertRaises(ValueError):
            install._check_relative_directories({"files": files})
        # A roms root beside the BIOS folder (Batocera's ../roms).
        beside = {**manifest, "roms_directory": {"bios_folder": "bios", "from_bios": "../roms"}}
        install._check_relative_directories(beside)
        disk = self.root / "userdata" / "bios"
        install.place_relative_entries(files, disk, beside, "romsplat", say=False)
        self.assertEqual(install._entry_place(disk, kept_entry := files[0])[0],
                         self.root / "userdata" / "roms")
        self.assertEqual(kept_entry["root"], "roms")
        for climbing in ("roms", "../roms/..", "/storage/roms"):
            with self.subTest(from_bios=climbing), self.assertRaises(ValueError):
                install._check_relative_directories(
                    {**manifest, "roms_directory": {"bios_folder": "bios", "from_bios": climbing}}
                )

    def test_run_from_an_emulator_folder_the_registry_describes(self) -> None:
        self.assertEqual(self.pack("emuplat"), [])
        manifest = self.manifest("emuplat")
        self.assertEqual(
            sorted((f["dest"], f.get("root")) for f in manifest["files"]),
            [("prog/prog", "emulators"), ("prog/prog.dat", "emulators")],
        )
        self.assertEqual(manifest["emulators_directory"]["default"], "emulators/{key}")
        self.assertTrue(all(u["in_pack"] is False for u in self.verify("emuplat")))

    def test_the_installer_follows_the_launcher_search(self) -> None:
        import install

        manifest = self.manifest("emuplat")
        install._check_emulators_directory(manifest)
        files = list(manifest["files"])
        home = self.root / "Frontend"
        bios = home / "bios"
        bios.mkdir(parents=True)
        # Not the platform's folder: no launcher config beside it.
        kept, left = install.place_emulator_entries(files, bios, manifest, "emuplat", say=False)
        self.assertEqual((kept, {o["reason"] for o in left}), ([], {"no_emulators_directory"}))
        (home / "frontend").mkdir()
        (home / "frontend" / "launcher.cfg").write_text("other=x\n")
        kept, left = install.place_emulator_entries(files, bios, manifest, "emuplat", say=False)
        self.assertEqual((len(kept), left), (2, []))
        entry = next(f for f in kept if f["dest"] == "prog/prog")
        self.assertEqual(install._entry_place(bios, entry), (home / "emulators" / "prog", "prog"))
        # The first searched place that exists wins.
        (home / "frontend" / "prog").mkdir()
        install.place_emulator_entries(files, bios, manifest, "emuplat", say=False)
        self.assertEqual(install._entry_place(bios, entry)[0], home / "frontend" / "prog")
        # A key the launcher config sets moves the folder: left out.
        (home / "frontend" / "launcher.cfg").write_text("prog=D:\\Prog\n")
        kept, left = install.place_emulator_entries(files, bios, manifest, "emuplat", say=False)
        self.assertEqual((kept, len(left)), ([], 2))


class EachProgramItsOwnProfile(unittest.TestCase):
    """PICO-8 and Voxatron are two programs: a platform running one gets its files only."""

    def test_only_the_platforms_that_run_voxatron_get_it(self) -> None:
        from common import list_registered_platforms, resolve_platform_cores

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        runs = {
            name: {k for k in ("lexaloffle", "voxatron")
                   if k in resolve_platform_cores(
                       load_platform_config(name, str(REPO_ROOT / "platforms")), profiles)}
            for name in list_registered_platforms(str(REPO_ROOT / "platforms"))
        }
        self.assertEqual(
            {name for name, found in runs.items() if "voxatron" in found}, {"batocera", "knulli"}
        )
        self.assertTrue(all("lexaloffle" in runs[name] for name in (
            "batocera", "knulli", "rocknix", "retrodeck", "retrobat", "recalbox")))

    def test_a_standalone_emulator_is_run(self) -> None:
        from common import resolve_platform_cores

        profiles = {"emu": {"emulator": "Emu", "type": "standalone", "cores": ["emu"],
                            "systems": ["sys"], "files": []}}
        config = {"cores": ["other"], "standalone_cores": ["emu"], "systems": {}}
        self.assertEqual(resolve_platform_cores(config, profiles), {"emu"})


BIOS_SETTING = {
    "emulator": "ps2emu", "build": "standalone", "kind": "passes_path", "names": [],
    "search_dir": "/userdata/bios/ps2",
    "passes_to": "inis/PCSX2.ini [Folders] Bios = ../../../bios/ps2, relative to the data root",
    "source_ref": "ps2emuGenerator.py:219",
}
# The same folder through a scans_dir record, and a record setting the image
# name alone, which hands no folder.
BIOS_SCAN = {**BIOS_SETTING, "kind": "scans_dir", "passes_to": "PCSX2.ini [Folders] Bios"}
BIOS_NAME = {**BIOS_SETTING, "passes_to": "PCSX2.ini [Filenames] BIOS"}


class ASettingSetsTheBiosFolder(unittest.TestCase):
    """KNULLI sets AetherSX2's [Folders] Bios to bios/ps2.

    The profile reads its BIOS images by content from bios/ under its data
    root, and names that setting in standalone_directories. Every image the
    scan finds goes to ps2/ in the pack, the manifest and verify, and a file
    the layout keeps outside its bios/ folder is named, never packed.
    """

    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        files, by_md5, by_name = {}, {}, {}
        for folder, name, data in (
            ("Sony/PlayStation 2", "img-a.bin", b"PS2 IMAGE A....."),
            ("Sony/PlayStation 2", "img-b.bin", b"PS2 IMAGE B....."),
            ("Other/ps2emu/arcade", "boot.zip", b"BOOT PROGRAMS"),
        ):
            where = self.root / "bios" / folder
            where.mkdir(parents=True, exist_ok=True)
            (where / name).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(where / name), "name": name, "sha1": sha1,
                           "md5": md5, "crc32": "", "size": len(data)}
            by_md5[md5] = sha1
            by_name[name] = [sha1]
        self.db = {
            "files": files,
            "indexes": {"by_md5": by_md5, "by_name": by_name, "by_crc32": {},
                        "by_path_suffix": {}},
        }
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        self.platforms.mkdir()
        self.emulators.mkdir()
        platforms = {"setplat": [BIOS_SETTING], "scanplat": [BIOS_SCAN],
                     "nameplat": [BIOS_NAME], "plainplat": []}
        for name, launchers in platforms.items():
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "1", "verification_mode": "existence",
                "base_destination": "bios", "cores": ["ps2emu"],
                "standalone_cores": ["ps2emu"], "launchers": launchers,
                "systems": {"sony-playstation-2": {"files": []}},
            }))
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump({"platforms": {
            name: {"config": f"{name}.yml"} for name in platforms
        }}))
        (self.emulators / "ps2emu.yml").write_text(yaml.safe_dump({
            "emulator": "PS2Emu", "type": "standalone", "bios_mode": "agnostic",
            "cores": ["ps2emu"], "systems": ["sony-playstation-2"],
            "bios_directory": "bios/",
            "standalone_directories": ["[Folders] Bios = bios"],
            "files": [
                {"name": "img-a.bin", "path": "bios/img-a.bin", "required": True,
                 "min_size": 16, "max_size": 16, "validation": ["size"]},
                # Read below the data root, never below its bios/ folder.
                {"name": "boot.zip", "standalone_path": "arcade/boot.zip",
                 "mode": "standalone", "required": False},
            ],
        }))

    def pack_names(self, platform: str) -> list[str]:
        with redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.root / "out" / platform), emulators_dir=str(self.emulators),
                offline=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            return sorted(n for n in zf.namelist() if n.endswith((".bin", ".zip")))

    def manifest(self, platform: str) -> dict:
        with redirect_stdout(io.StringIO()):
            return generate_manifest(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.platforms / "_registry.yml"),
                emulators_dir=str(self.emulators), offline=True,
            )

    def verify_dests(self, platform: str) -> list[str]:
        config = load_platform_config(platform, str(self.platforms))
        result = verify_platform(config, self.db, str(self.emulators))
        return sorted(d for d in result["pack_destinations"] if d.endswith((".bin", ".zip")))

    def assert_placed(self, platform: str, expected: list[str]) -> None:
        self.assertEqual(self.pack_names(platform), expected)
        self.assertEqual(
            sorted(f["dest"] for f in self.manifest(platform)["files"]), expected
        )
        self.assertEqual(self.verify_dests(platform), expected)

    def test_every_scanned_image_lands_in_the_folder_set(self) -> None:
        self.assert_placed("setplat", ["ps2/img-a.bin", "ps2/img-b.bin"])

    def test_a_scans_dir_record_sets_it_too(self) -> None:
        self.assert_placed("scanplat", ["ps2/img-a.bin", "ps2/img-b.bin"])

    def test_the_image_name_setting_hands_no_folder(self) -> None:
        self.assert_placed("nameplat", ["img-a.bin", "img-b.bin"])

    def test_a_platform_without_the_record_keeps_the_layout(self) -> None:
        self.assert_placed("plainplat", ["img-a.bin", "img-b.bin"])

    def test_a_file_outside_the_bios_folder_is_named(self) -> None:
        omitted = [o for o in self.manifest("setplat")["omitted_files"]
                   if o["name"] == "boot.zip"]
        self.assertEqual(
            [(o["dest"], o["root"], o["reason"], o["cores"]) for o in omitted],
            [("arcade/boot.zip", "emulator", "outside_bios_folder", ["ps2emu"])],
        )

    def test_the_ini_key_carries_its_section(self) -> None:
        from launchers import ini_keys

        self.assertEqual(
            ini_keys("PCSX2.ini [Folders] Bios = /storage/roms/bios/armsx2, [Filenames] BIOS"),
            {"[Folders] Bios", "[Filenames] BIOS"},
        )
        self.assertEqual(ini_keys("command line -rompath"), frozenset())


class AetherSX2OnKnulli(unittest.TestCase):
    """The real profile against KNULLI's aethersx2Generator.py:219 record."""

    def test_the_bios_images_land_in_ps2(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["aethersx2"]
        config = load_platform_config("knulli", str(REPO_ROOT / "platforms"))
        (view, standalone), = platform_layouts("aethersx2", profile, standalone_set(config))
        self.assertTrue(standalone)
        for entry in view["files"]:
            path = entry.get("path") or ""
            if path.startswith("bios/"):
                self.assertEqual(entry["standalone_path"], "ps2/" + path.removeprefix("bios/"))
            elif path:
                self.assertEqual(entry.get("unplaced"), "outside_bios_folder", path)


class Quasi88OnRetroPie(unittest.TestCase):
    """RetroPie writes -romdir $biosdir/pc88 into quasi88.ini (quasi88.sh:67)."""

    def test_the_roms_land_in_pc88(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["quasi88kai"]
        config = load_platform_config("retropie", str(REPO_ROOT / "platforms"))
        (view, standalone), = platform_layouts("quasi88kai", profile, standalone_set(config))
        self.assertTrue(standalone)
        paths = [e["path"] for e in view["files"]]
        self.assertTrue(paths and all(p.startswith("rom/") for p in paths))
        self.assertEqual(
            [e["standalone_path"] for e in view["files"]],
            ["pc88/" + p.removeprefix("rom/") for p in paths],
        )


class FlycastOnEmuELEC(unittest.TestCase):
    """EmuELEC links /storage/.local/share/flycast to bios/dc (flycast.sh:11-14),
    and root's home is /storage (busybox profile.d/98-busybox.conf:4)."""

    def test_the_home_directory_is_spelled_as_home(self) -> None:
        from launchers import normalize_handle

        self.assertEqual(
            normalize_handle("/storage/.local/share/flycast", "/storage"), "~/.local/share/flycast"
        )
        self.assertEqual(normalize_handle("/storage", "/storage/"), "~")
        self.assertEqual(normalize_handle("/storagex/a", "/storage"), "/storagex/a")
        self.assertEqual(
            normalize_handle("/storage/.local/share/flycast"), "/storage/.local/share/flycast"
        )

    def test_the_bios_lands_in_dc(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["flycast"]
        config = load_platform_config("emuelec", str(REPO_ROOT / "platforms"))
        layouts = platform_layouts("flycast", profile, standalone_set(config))
        (view,) = [v for v, standalone in layouts if standalone]
        self.assertTrue(view["files"])
        for entry in view["files"]:
            self.assertEqual(entry["standalone_path"], "dc/" + entry["layout_path"])


def standalone_view(emulator: str, platform: str) -> dict:
    profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))[emulator]
    config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
    (view,) = [v for v, standalone in platform_layouts(emulator, profile, standalone_set(config))
               if standalone]
    return view


class Eka2l1OnRetroBat(unittest.TestCase):
    """RetroBat writes data-storage = bios/eka2l1/data (Eka2l1.Generator.cs:153, 156)."""

    def test_the_device_rom_lands_in_eka2l1_data(self) -> None:
        view = standalone_view("eka2l1", "retrobat")
        (rom,) = [e for e in view["files"] if e["name"] == "SYM.ROM"]
        self.assertEqual(rom["standalone_path"], "eka2l1/data/roms/nem-4/SYM.ROM")
        # Shipped beside the executable, in RetroBat's emulator folder.
        for entry in view["files"]:
            if entry.get("mode") == "standalone":
                self.assertEqual(entry.get("unplaced"), "outside_bios_folder", entry["name"])


class CemuOnRetroDECK(unittest.TestCase):
    """RetroDECK sets mlc_path to $bios_path/cemu (cemu/component_prepare.sh:14, 29)
    and keeps Cemu's user data in its Flatpak's $XDG_DATA_HOME/Cemu."""

    def test_the_mlc_lands_in_cemu(self) -> None:
        view = standalone_view("cemu", "retrodeck")
        mlc = [e for e in view["files"] if (e.get("layout_path") or "").startswith("mlc01/")]
        self.assertTrue(mlc)
        for entry in mlc:
            self.assertEqual(
                entry["standalone_path"], "cemu/" + entry["layout_path"].removeprefix("mlc01/")
            )
        (otp,) = [e for e in view["files"] if e["name"] == "otp.bin"]
        self.assertEqual(otp.get("unplaced"), "outside_bios_folder")


class DolphinUserDirectory(unittest.TestCase):
    """EmuELEC runs Dolphin with XDG_DATA_HOME=/storage/roms/dolphin (dolphin.sh:28),
    RetroDECK links $XDG_DATA_HOME/dolphin-emu/Triforce to bios/Triforce
    (dolphin/component_prepare.sh:30, 49)."""

    def test_emuelec_installs_the_user_directory_below_its_roms(self) -> None:
        view = standalone_view("dolphin", "emuelec")
        placed = {e["name"]: e["standalone_path"] for e in view["files"] if e.get("layout_path")}
        self.assertEqual(placed["segaboot.gcm"], "dolphin/dolphin-emu/Triforce/segaboot.gcm")
        # A standalone-only entry's path is its place in the User directory.
        self.assertEqual(
            placed["rtl8723a_fw.bin"], "dolphin/dolphin-emu/Load/Firmware/rtl_bt/rtl8723a_fw.bin"
        )
        self.assertTrue(all(e.get("unprefixed") for e in view["files"] if e.get("layout_path")))

    def test_retrodeck_places_triforce_alone(self) -> None:
        view = standalone_view("dolphin", "retrodeck")
        placed = {e["name"]: e["standalone_path"] for e in view["files"] if e.get("layout_path")}
        self.assertEqual(placed, {"segaboot.gcm": "Triforce/segaboot.gcm"})
        (ipl, *_) = [e for e in view["files"] if e["name"] == "IPL.bin"]
        self.assertEqual(ipl.get("unplaced"), "outside_bios_folder")


class MameSearchPaths(unittest.TestCase):
    """MAME reads each semicolon-separated search path in turn
    (src/emu/fileio.cpp:53-58, 330-392)."""

    def sets(self, view: dict) -> list[dict]:
        return [e for e in view["files"] if e.get("category") == "bios_zip"]

    def test_retrobat_keeps_the_sets_at_the_bios_root(self) -> None:
        # -rp bios;<rom directory> (Mame64.Generator.cs:93-96).
        view = standalone_view("mame", "retrobat")
        sets = self.sets(view)
        self.assertGreater(len(sets), 1000)
        for entry in sets:
            self.assertEqual(entry["standalone_path"], entry["name"])
            self.assertNotIn("unplaced", entry)
        (bbc,) = [e for e in view["files"] if e["name"] == "bbc.zip"]
        # -sp bios/mame/samples, hbmame's folder being another record
        # (Mame64.Generator.cs:30, 101, 106-107).
        self.assertEqual(bbc["standalone_path"], "mame/samples/bbc.zip")

    def test_knulli_keeps_the_root_listed_after_bios_mame(self) -> None:
        # -rompath <romDirname>;/userdata/bios/mame;/userdata/bios (mameGenerator.py:116-122).
        view = standalone_view("mame", "knulli")
        self.assertTrue(all(e["standalone_path"] == e["name"] for e in self.sets(view)))
        (bbc,) = [e for e in view["files"] if e["name"] == "bbc.zip"]
        self.assertEqual(bbc["standalone_path"], "mame/samples/bbc.zip")

    def test_retropie_moves_the_sets_to_bios_mame(self) -> None:
        # rompath $romdir/mame;$romdir/arcade;$biosdir/mame (mame.sh:133).
        view = standalone_view("mame", "retropie")
        self.assertTrue(all(
            e["standalone_path"] == "mame/" + e["name"] for e in self.sets(view)
        ))

    def test_retrodeck_reads_samples_in_mame_sa(self) -> None:
        # samplepath $bios_path/mame-sa/samples (mame/component_prepare.sh:94, 117).
        view = standalone_view("mame", "retrodeck")
        (bbc,) = [e for e in view["files"] if e["name"] == "bbc.zip"]
        self.assertEqual(bbc["standalone_path"], "mame-sa/samples/bbc.zip")
        # ES-DE hands -rompath %GAMEDIR%;%ROMPATH%/<system>: no BIOS folder.
        self.assertTrue(all(
            e.get("unplaced") == "outside_bios_folder"
            or str(e.get("standalone_path")).startswith("roms/")
            for e in self.sets(view)
        ))

    def test_a_passed_search_setting_leaves_the_bundled_tree_unread(self) -> None:
        # RetroBat passes -hash bios/mame/hash and -sp bios/mame/samples
        # (Mame64.Generator.cs:30, 101, 106-107, 172, 177-178), RetroDECK
        # writes samplepath $bios_path/mame-sa/samples (component_prepare.sh:94):
        # the trees beside the executable are not read, the pack brings them.
        for platform, tree, place in (
            ("retrobat", "hash/", "mame/hash/"),
            ("retrobat", "floppy/", "mame/samples/floppy/"),
            ("knulli", "floppy/", "mame/samples/floppy/"),
            ("retrodeck", "floppy/", "mame-sa/samples/floppy/"),
        ):
            view = standalone_view("mame", platform)
            (entry,) = [e for e in view["files"]
                        if e["name"] == tree and e.get("mode") == "standalone"]
            self.assertEqual(entry["standalone_path"], place, platform)
            self.assertNotIn("bundled", entry, platform)
        # Where no launcher passes the setting, the bundled copy is read.
        view = standalone_view("mame", "emudeck")
        (entry,) = [e for e in view["files"]
                    if e["name"] == "hash/" and e.get("mode") == "standalone"]
        self.assertTrue(entry.get("bundled"))

    def test_retropie_reads_samples_below_its_roms(self) -> None:
        # samplepath $romdir/mame/samples;$romdir/arcade/samples (mame.sh:135).
        view = standalone_view("mame", "retropie")
        (bbc,) = [e for e in view["files"] if e["name"] == "bbc.zip"]
        self.assertEqual((bbc["standalone_path"], bbc.get("root")),
                         ("mame/samples/bbc.zip", "roms"))
        (tree,) = [e for e in view["files"]
                   if e["name"] == "floppy/" and e.get("mode") == "standalone"]
        self.assertEqual((tree["standalone_path"], tree.get("root")),
                         ("mame/samples/floppy/", "roms"))
        self.assertNotIn("bundled", tree)

    def test_batocera_keeps_the_sets_at_the_root_and_samples_in_bios_mame(self) -> None:
        # -rompath <romDirname>;/userdata/bios/mame;/userdata/bios and
        # -samplepath /userdata/bios/mame/samples (mameGenerator.py:129-142).
        view = standalone_view("mame", "batocera")
        self.assertTrue(all(e["standalone_path"] == e["name"] for e in self.sets(view)))
        (bbc,) = [e for e in view["files"] if e["name"] == "bbc.zip"]
        self.assertEqual(bbc["standalone_path"], "mame/samples/bbc.zip")

    def test_a_moved_tree_is_found_by_its_layout_path(self) -> None:
        from common import expand_directory_entries, load_database

        db = load_database(str(REPO_ROOT / "database.json"))
        view = standalone_view("mame", "retrodeck")
        (tree,) = [e for e in view["files"]
                   if e["name"] == "floppy/" and e.get("mode") == "standalone"]
        members = expand_directory_entries([tree], db, standalone=True)
        self.assertEqual(len(members), 19)
        for member in members:
            self.assertTrue(member["path"].startswith("mame-sa/samples/floppy/"))

    def test_psxmame_reads_bios_psxmame_bios(self) -> None:
        # -rompath bios/psxmame/bios;<rom directory> (PSXMame.Generator.cs:38-48).
        view = standalone_view("psxmame", "retrobat")
        self.assertTrue(view["files"])
        for entry in view["files"]:
            self.assertEqual(entry["standalone_path"], "psxmame/bios/" + entry["name"])


class LibretroMameSetsInMameBios(unittest.TestCase):
    """libretro/mame searches the content folder, then <system>/mame/bios and
    <system>/mame/roms, never the system folder itself
    (src/osd/libretro/libretro-internal/retro_init.cpp:580-597)."""

    def test_every_libretro_mame_set_is_read_in_mame_bios(self) -> None:
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for key in ("mame", "mame0258", "mame0278", "mamearcade", "mamemess"):
            sets = [f for f in profiles[key]["files"] if f.get("category") == "bios_zip"
                    and f.get("mode") != "standalone" and f["name"] != "bbc.zip"]
            self.assertTrue(sets, key)
            for entry in sets:
                self.assertEqual(entry.get("path"), "mame/bios/" + entry["name"], key)

    def test_the_standalone_build_keeps_its_rompath_layout(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["mame"]
        for entry in profile["files"]:
            if str(entry.get("path", "")).startswith("mame/bios/"):
                self.assertEqual(entry.get("standalone_path"), entry["name"])

    def test_retrobat_lays_out_both_builds(self) -> None:
        # es_systems.cfg offers the libretro core mame and the standalone
        # mame64, two names of one profile.
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["mame"]
        config = load_platform_config("retrobat", str(REPO_ROOT / "platforms"))
        builds = sorted(s for _v, s in platform_layouts("mame", profile, standalone_set(config)))
        self.assertEqual(builds, [False, True])


class GzdoomOnRetroDECK(unittest.TestCase):
    """RetroDECK writes RETRODECKROMSDIR/doom into [IWADSearch.Directories]
    (gzdoom.ini:9, component_prepare.sh:27)."""

    def test_the_iwads_land_in_roms_doom(self) -> None:
        view = standalone_view("gzdoom", "retrodeck")
        iwads = [e for e in view["files"] if e.get("system")]
        self.assertEqual(len(iwads), 43)
        for entry in iwads:
            self.assertEqual(entry["standalone_path"], "roms/doom/" + entry["name"])
            self.assertTrue(entry.get("unprefixed"))
        # The engine pk3s are read beside the executable first.
        (pk3,) = [e for e in view["files"] if e["name"] == "gzdoom.pk3"]
        self.assertNotIn("standalone_path", pk3)

    def test_another_platform_keeps_them(self) -> None:
        view = standalone_view("gzdoom", "batocera")
        self.assertFalse(any(e.get("standalone_path") for e in view["files"]))


def _reads_configs(profile: str) -> bool:
    """Whether a repository profile carries config_reads."""
    path = REPO_ROOT / "emulators" / f"{profile}.yml"
    return bool((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("config_reads"))


# EmuELEC hands AdvanceMAME its folders through advmame.rc: the chain binds
# once the profile says where the build reads them (config_reads).
@unittest.skipUnless(
    _reads_configs("advancemame"), "advancemame.yml carries no config_reads, dir_rom is unproven"
)
class AdvanceMameOnEmuELEC(unittest.TestCase):
    """advmame.rc sets dir_rom /storage/roms/mame, /storage/roms/arcade for
    the arcade system (advmame.rc:11, advmame.sh:26-30)."""

    def test_the_sets_land_in_roms_mame_and_roms_arcade(self) -> None:
        # Started for arcade it reads roms/arcade, for mame and cps1-3
        # roms/mame (es_systems.json, advmame.sh:26-30): an arcade set is
        # read in both.
        view = standalone_view("advancemame", "emuelec")
        sets = [e for e in view["files"] if e.get("category") == "bios_zip"]
        self.assertEqual(len(sets), 52)
        places: dict[str, set[str]] = {}
        for entry in sets:
            self.assertTrue(entry.get("unprefixed"))
            places.setdefault(entry["name"], set()).add(entry["standalone_path"])
        self.assertEqual(len(places), 26)
        for name, paths in places.items():
            self.assertEqual(paths, {"mame/" + name, "arcade/" + name})

    def test_both_copies_are_one_file(self) -> None:
        # Outside the BIOS tree the folder is no proof of content: each copy
        # resolves by its layout path, so both folders hold the same file.
        from common import load_database

        db = load_database(str(REPO_ROOT / "database.json"))
        with redirect_stdout(io.StringIO()):
            manifest = generate_manifest(
                "emuelec", str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "platforms" / "_registry.yml"),
                emulators_dir=str(REPO_ROOT / "emulators"), offline=True,
            )
        # mame2003_plus reads its own sets in arcade/ too (es_systems.cfg):
        # the copy AdvanceMAME reads there is the one its claim names.
        def advancemame_copy(entry: dict) -> str | None:
            for copy in (entry, *(entry.get("alternatives") or [])):
                if "advancemame" in (copy.get("cores") or []):
                    return copy["sha1"]
            return None

        by_dest = {f["dest"]: advancemame_copy(f) for f in manifest["files"]}
        sets = [d.removeprefix("arcade/") for d, sha1 in by_dest.items()
                if d.startswith("arcade/") and sha1]
        self.assertEqual(len(sets), 26)
        for name in sets:
            self.assertEqual(by_dest["arcade/" + name], by_dest["mame/" + name], name)

    def test_the_roms_folder_is_no_proof_of_content(self) -> None:
        # bios/Arcade/MAME/konamigv.zip is MAME 0.289's set, not AdvanceMAME's.
        from common import load_database, resolve_local_file

        db = load_database(str(REPO_ROOT / "database.json"))
        view = standalone_view("advancemame", "emuelec")
        entry = next(e for e in view["files"]
                     if e["name"] == "konamigv.zip" and e["standalone_path"].startswith("mame/"))
        moved, _status = resolve_local_file(entry, db, dest_hint=entry["standalone_path"])
        plain = {k: v for k, v in entry.items()
                 if k not in ("layout_path", "standalone_path", "unprefixed")}
        root, _status = resolve_local_file(plain, db, dest_hint=entry["name"])
        self.assertEqual(moved, root)
        self.assertNotIn("/MAME/", moved)


def libretro_view(emulator: str, platform: str) -> dict:
    profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))[emulator]
    config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
    (view,) = [v for v, standalone in platform_layouts(emulator, profile, standalone_set(config))
               if not standalone]
    return view


class SetsReadBesideTheGame(unittest.TestCase):
    """MAME 2016 and older search the folder of the loaded game for their
    sets and never the system folder (mame2003 src/fileio.c:217-220,
    mame2010 src/emu/romload.c:667-685, mame2016
    src/osd/retro/retromain.cpp:1364-1402)."""

    CORES = ("mame2000", "mame2003", "mame2003_plus", "mame2009", "mame2010",
             "mame2014", "mame2015", "mame2016", "ume2015")

    def test_each_set_is_read_beside_the_game(self) -> None:
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for key in self.CORES:
            sets = [f for f in profiles[key]["files"] if f.get("category") == "bios_zip"]
            self.assertTrue(sets, key)
            for entry in sets:
                self.assertEqual(entry.get("load_from"), "content_dir", (key, entry["name"]))

    def test_batocera_places_them_in_the_folders_it_launches_the_core_for(self) -> None:
        # es_systems.yml offers mame078plus under mame and neogeo.
        view = libretro_view("mame2003_plus", "batocera")
        neogeo = [e for e in view["files"] if e["name"] == "neogeo.zip"]
        self.assertEqual(sorted(e["path"] for e in neogeo), ["mame/neogeo.zip", "neogeo/neogeo.zip"])
        self.assertTrue(all(e["root"] == "roms" and "load_from" not in e for e in neogeo))

    def test_retroarch_names_them_outside_the_bios_folder(self) -> None:
        # RetroArch keeps no folder per system: the game's folder is the user's.
        view = libretro_view("mame2003", "retroarch")
        sets = [e for e in view["files"] if e.get("category") == "bios_zip"]
        self.assertTrue(sets)
        self.assertTrue(all(e.get("unplaced") == "outside_bios_folder" for e in sets))

    def test_game_data_beside_the_content_is_left_to_the_game(self) -> None:
        view = libretro_view("mame2000", "retroarch")
        (hiscore,) = [e for e in view["files"] if e["name"] == "hiscore.dat"]
        self.assertEqual(hiscore.get("load_from"), "content_dir")
        self.assertNotIn("unplaced", hiscore)

    def test_a_mess_build_takes_no_arcade_set(self) -> None:
        # lr-mess2016 builds mame2016 with SUBTARGET=mess (lr-mess2016.sh:31).
        view = libretro_view("mame2016", "retropie")
        folders = {e["path"].split("/")[0] for e in view["files"] if e.get("root") == "roms"}
        self.assertEqual(folders, {"arcade", "mame-libretro"})

    def test_emulatorjs_writes_the_bios_beside_the_game(self) -> None:
        # data/src/emulator.js:845, 990, 1054: one filesystem root for both.
        view = libretro_view("mame2003_plus", "romm")
        sets = [e for e in view["files"] if e.get("category") == "bios_zip"]
        self.assertTrue(all("load_from" not in e and "root" not in e for e in sets))

    def test_the_manifest_drops_the_root_copy_no_core_reads(self) -> None:
        from common import load_database

        db = load_database(str(REPO_ROOT / "database.json"))
        with redirect_stdout(io.StringIO()):
            manifest = generate_manifest(
                "rocknix", str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "platforms" / "_registry.yml"),
                emulators_dir=str(REPO_ROOT / "emulators"), offline=True,
            )
        dests = {(f.get("root") or "", f["dest"]) for f in manifest["files"]}
        # ROCKNIX starts mame2003_plus for arcade and mame (arcade.conf, mame.conf),
        # and no core it runs reads coh1000c.zip at the BIOS root.
        self.assertIn(("roms", "arcade/coh1000c.zip"), dests)
        self.assertIn(("roms", "mame/coh1000c.zip"), dests)
        self.assertNotIn(("", "coh1000c.zip"), dests)


class MameOnRetroDeckRomPaths(unittest.TestCase):
    """ES-DE starts standalone MAME with -rompath %GAMEDIR%;%ROMPATH%/<system>
    (resources/systems/linux/es_systems.xml), which outranks mame.ini."""

    def test_the_rom_folders_file_records_each_search_path(self) -> None:
        with (REPO_ROOT / "platforms" / "romfolders" / "retrodeck.yml").open() as f:
            rows = yaml.safe_load(f)["folders"]
        found = {r["folder"]: s for r in rows for s in r.get("searched_by") or []}
        self.assertEqual(len(found), 54)
        self.assertEqual(found["tanodragon"]["reads"], ["dragon32"])
        self.assertEqual(found["adam"]["machines"], ["adam"])
        self.assertTrue(found["neogeo"]["any_machine"])

    def test_a_machine_reads_its_own_set_and_its_devices(self) -> None:
        from common import rom_search_sets

        self.assertIn("adam", rom_search_sets("mame", "adam", ["adam"], False))
        neogeo = rom_search_sets("mame", "neogeo", [], True)
        self.assertIn("neogeo", neogeo)
        self.assertNotIn("stvbios", neogeo)
        # A folder that holds any machine reads every BIOS set.
        self.assertIn("stvbios", rom_search_sets("mame", "mame", [], True))

    def test_sets_land_in_the_folders_that_read_them(self) -> None:
        # RetroDECK's roms/ sits beside bios/ in the install tree.
        view = standalone_view("mame", "retrodeck")
        places = {}
        for e in view["files"]:
            if e.get("unprefixed") and e["standalone_path"].startswith("roms/"):
                places.setdefault(e["name"], set()).add(e["standalone_path"].split("/")[1])
        self.assertEqual(places["adam.zip"], {"adam"})
        self.assertIn("neogeo", places["neogeo.zip"])
        self.assertNotIn("adam", places["neogeo.zip"])
        self.assertEqual(places["stvbios.zip"] - {"arcade", "mame", "consolearcade"}, {"stv"})


class LibretroMameOnEsdeRomPaths(unittest.TestCase):
    """ES-DE hands the libretro MAME core a command line as its content,
    with -rompath "%GAMEDIRRAW%;%ROMPATH%/<system>" after the machine. The
    core passes it to MAME after its own <system>/mame/bios, and the later
    value wins (retro_init.cpp:580-597, 902-940, options.cpp:260-276)."""

    def test_the_rom_folders_file_records_the_core(self) -> None:
        with (REPO_ROOT / "platforms" / "romfolders" / "retrodeck.yml").open() as f:
            rows = yaml.safe_load(f)["folders"]
        found = {r["folder"]: s for r in rows for s in r.get("searched_by") or []
                 if s.get("core") == "mame"}
        self.assertEqual(len(found), 21)
        self.assertEqual(found["apple2"]["machines"], ["apple2e"])
        self.assertEqual(found["atari7800"]["reads"], ["atari7800"])
        self.assertEqual(found["atari7800"]["emulator"], "retroarch")

    def test_sets_also_land_in_the_folder_the_command_names(self) -> None:
        # RetroDECK's roms/ sits beside bios/ in the install tree.
        for platform, read in (("retrodeck", ("", "roms/gamate/gamate.zip")),
                               ("emudeck", ("roms", "gamate/gamate.zip"))):
            view = libretro_view("mame", platform)
            places = {(e.get("root") or "", e["path"]) for e in view["files"]
                      if e["name"] == "gamate.zip"}
            self.assertEqual(places, {("", "mame/bios/gamate.zip"), read}, platform)


class StandaloneMameOnEmuDeck(unittest.TestCase):
    """EmuDeck writes mame.ini rompath roms/arcade;bios;bios/mame
    (emuDeckMAME.sh:66-68), read when Steam ROM Manager starts MAME with no
    -rompath (tools/launchers/mame.sh). ES-DE's commands pass their own."""

    def test_a_set_keeps_its_ini_place_and_gains_the_command_folder(self) -> None:
        view = standalone_view("mame", "emudeck")
        places = {(e.get("root") or "", e["standalone_path"]) for e in view["files"]
                  if e["name"] == "adam.zip"}
        self.assertIn(("", "adam.zip"), places)
        self.assertIn(("roms", "adam/adam.zip"), places)


class EveryCoreAFolderOffers(unittest.TestCase):
    """AmberELEC's es_systems.cfg, EmuELEC's es_systems.json and ROCKNIX's
    add_emu_core calls offer several cores per folder, the user's choice
    starting any of them."""

    def test_the_rom_folders_files_record_the_offers(self) -> None:
        for setup, folder, core in (("amberelec", "arcade", "mame2010"),
                                    ("emuelec", "arcade", "mame2010"),
                                    ("rocknix", "arcade", "mame2010")):
            with (REPO_ROOT / "platforms" / "romfolders" / f"{setup}.yml").open() as f:
                rows = {r["folder"]: r for r in yaml.safe_load(f)["folders"]}
            self.assertIn(core, {o["core"] for o in rows[folder].get("offers") or []}, setup)

    def test_an_offered_core_reads_its_sets_in_that_folder(self) -> None:
        for platform in ("amberelec", "rocknix"):
            view = libretro_view("mame2010", platform)
            folders = {e["path"].split("/")[0] for e in view["files"]
                       if e.get("category") == "bios_zip" and e.get("layout_path")}
            self.assertIn("arcade", folders, platform)


class CloneReadsItsParent(unittest.TestCase):
    """ES-DE starts odyssey2 with -rompath on roms/odyssey2 alone, and MAME
    finds o2bios.rom in the parent's videopac.zip (src/emu/driver.cpp:31-38)."""

    def test_the_parent_set_goes_to_the_clone_folder(self) -> None:
        from common import rom_search_sets

        self.assertIn("videopac", rom_search_sets("mame", "odyssey2", ["odyssey2"], False))
        for platform, dest in (("emudeck", "odyssey2/videopac.zip"),
                               ("retrodeck", "roms/odyssey2/videopac.zip")):
            with self.subTest(platform=platform):
                dests = {f["dest"] for f in platform_manifest(platform)["files"]}
                self.assertIn(dest, dests)


class AdvanceMameOnRetroPie(unittest.TestCase):
    """RetroPie writes dir_rom $romdir/mame-advmame:$romdir/arcade into each
    AdvanceMAME build's rc (advmame.sh:100), the list the code splits on ':'
    (advance/linux/file.c:138-141)."""

    def test_the_sets_go_to_the_first_folder_searched(self) -> None:
        config = load_platform_config("retropie", str(REPO_ROOT / "platforms"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        tags = standalone_set(config)
        for emu in ("advmame", "advmame-1.4", "advmame-0.94"):
            with self.subTest(emu=emu):
                placed = [
                    (f.get("root"), f.get("standalone_path"))
                    for view, standalone in platform_layouts(emu, profiles[emu], tags)
                    if standalone
                    for f in view["files"] if isinstance(f, dict) and f["name"] == "neogeo.zip"
                ]
                self.assertEqual(placed, [("roms", "mame-advmame/neogeo.zip")])


class CoreOfferedOnSomeBoards(unittest.TestCase):
    """ROCKNIX writes some add_emu_core calls under a `case "${DEVICE}"`
    branch (emulators/package.mk:188 offers uae4arm for amiga on the devices
    it builds it for). A board's pack places such a core in that folder only
    when the branch names the board, and a manifest for every board says
    where it does."""

    ROW = {
        "folder": "amiga", "core": "puae", "emulator": "retroarch",
        "offers": [
            {"emulator": "retroarch", "core": "puae"},
            {"emulator": "retroarch", "core": "uae4arm", "when": "DEVICE H700|RK3326"},
            {"emulator": "retroarch", "core": "puae2021",
             "when": 'if [ "${PREFER_GLES}" = "yes" ]; then'},
        ],
    }

    def config(self, **extra) -> dict:
        base = load_platform_config("rocknix", str(REPO_ROOT / "platforms"))
        return {**base, "_rom_folders": [self.ROW], **extra}

    def test_a_branch_names_the_boards(self) -> None:
        from common import when_admits

        self.assertTrue(when_admits("DEVICE H700|RK3326", "rk3326"))
        self.assertFalse(when_admits("DEVICE H700|RK3326", "s922x"))
        self.assertTrue(when_admits("DEVICE AMD64; DEVICE RK3588*", "rk3588"))
        self.assertTrue(when_admits('if [ "${PREFER_GLES}" = "yes" ]; then', "h700"))

    def test_an_offer_carries_the_boards_its_branch_names(self) -> None:
        from common import offer_boards

        boards = offer_boards(self.config())
        self.assertEqual(boards[("uae4arm", "amiga")], frozenset({"h700", "rk3326"}))
        self.assertIsNone(boards[("puae", "amiga")])
        self.assertIsNone(boards[("puae2021", "amiga")])

    def test_a_board_pack_places_the_core_where_the_board_offers_it(self) -> None:
        from common import CONTENT_FOLDER_PREFIX, TARGET_KEY, content_folder_tags

        def placed(config: dict) -> dict:
            rows = [json.loads(t[len(CONTENT_FOLDER_PREFIX):]) for t in content_folder_tags(config)
                    if t.startswith(CONTENT_FOLDER_PREFIX)]
            return {core: on for core, _folder, _where, on in rows}

        every = placed(self.config())
        self.assertEqual(every["uae4arm"], ["h700", "rk3326"])
        self.assertIsNone(every["puae"])
        self.assertIn("uae4arm", placed(self.config(**{TARGET_KEY: "rk3326"})))
        self.assertNotIn("uae4arm", placed(self.config(**{TARGET_KEY: "s922x"})))
        self.assertIn("puae", placed(self.config(**{TARGET_KEY: "s922x"})))


def platform_manifest(platform: str) -> dict:
    from common import load_database

    db = load_database(str(REPO_ROOT / "database.json"))
    with redirect_stdout(io.StringIO()):
        return generate_manifest(
            platform, str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
            str(REPO_ROOT / "platforms" / "_registry.yml"),
            emulators_dir=str(REPO_ROOT / "emulators"), offline=True,
        )


class ArchiveSharedByOfferedCores(unittest.TestCase):
    """One path holds one file: several cores reading an archive in one roms
    folder get the copy of the core the folder starts by default, then the
    copy serving the most of them."""

    def test_the_default_core_copy_takes_the_folder(self) -> None:
        # EmuELEC's arcade folder starts MAME 2003-Plus by default
        # (es_systems.json:82), AdvanceMAME reads its sets there too.
        (entry,) = [f for f in platform_manifest("emuelec")["files"]
                    if f["dest"] == "arcade/neogeo.zip"]
        self.assertEqual(entry["cores"], ["mame2003_plus"])
        self.assertTrue(entry["repo_path"].endswith("neogeo.zip.74df3258"))
        others = {c for a in entry.get("alternatives", []) for c in a["cores"]}
        self.assertIn("advancemame", others)

    def test_offered_cores_join_the_default_one(self) -> None:
        # AmberELEC's arcade folder starts MAME 2003-Plus and offers MAME
        # 2000, 2010, 2015 and 2016 (es_systems.cfg:116-150).
        (entry,) = [f for f in platform_manifest("amberelec")["files"]
                    if f["dest"] == "arcade/neogeo.zip"]
        self.assertEqual(entry["cores"], ["mame2003_plus"])
        self.assertTrue(entry["repo_path"].endswith("neogeo.zip.74df3258"))
        others = {c for a in entry.get("alternatives", []) for c in a["cores"]}
        self.assertLessEqual({"mame2000", "mame2010", "mame2015", "mame2016"}, others)

    def test_the_copy_serving_most_cores_wins_without_a_default(self) -> None:
        # RetroDECK's cps folders start the libretro MAME core, whose sets are
        # in mame/bios. Of the cores reading nss.zip in cps1, MAME 2003-Plus
        # alone lists members, and only its copy holds them.
        (entry,) = [f for f in platform_manifest("retrodeck")["files"]
                    if f["dest"] == "roms/cps1/nss.zip"]
        self.assertEqual(entry["cores"], ["mame2003_plus"])
        self.assertTrue(entry["repo_path"].endswith("nss.zip.cba0bd8c"))


class MacBootDisksOnKnulli(unittest.TestCase):
    def test_the_hard_records_bind(self) -> None:
        # mameGenerator.py and libretroMAMEConfig.py pass the boot disk as
        # -hard, the brief name of the LC III's one hard disk image
        # (harddriv.h:43, diimage.cpp:1131-1165, maclc3.cpp:266).
        from launchers import bound_launchers

        config = load_platform_config("knulli", str(REPO_ROOT / "platforms"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        bound = [r for r in bound_launchers(config, profiles)
                 if r.get("emulator") == "mame" and "-hard" in str(r.get("passes_to"))]
        self.assertEqual(sorted(r["build"] for r in bound), ["libretro", "standalone"])


class ArcadeParentSources(unittest.TestCase):
    def test_the_index_names_each_driver_source(self) -> None:
        import json

        with (REPO_ROOT / "games" / "arcade" / "mame.json").open() as f:
            index = json.load(f)
        self.assertIn("sf2", index["sources"]["capcom/cps1.cpp"])
        self.assertIn("qsound_hle", {d for sets in index["sources"].values() for d in sets})


if __name__ == "__main__":
    unittest.main()
