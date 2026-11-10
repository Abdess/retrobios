"""--no-game-data: the firmware without the files a game reads.

A platform list can name a game's data beside the firmware (EmuELEC lists the
Doom WADs), and a core profile marks its game data `category: game_data`. The
manifest marks both, the builder leaves both out under --no-game-data, verify
reports on the same file set, and the installer makes the same cut from the
full manifest.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import functools
import hashlib
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
import install  # noqa: E402
import packverify  # noqa: E402
import verify  # noqa: E402

PAYLOADS = {
    "System/firmware.rom": b"firmware of the console",
    "System/corefw.bin": b"firmware the core loads",
    "Doom/doom1.wad": b"shareware episode",
    "Doom/engine.pk3": b"engine resources",
}

PROFILES = {
    "emu": {
        "emulator": "Emu", "type": "libretro", "cores": ["emu"],
        "systems": ["console"],
        "files": [
            {"name": "firmware.rom", "required": True},
            {"name": "corefw.bin", "required": True},
        ],
    },
    "doomcore": {
        "emulator": "DoomCore", "type": "libretro", "cores": ["doomcore"],
        "systems": ["doom"],
        "files": [
            {"name": "doom1.wad", "path": "doom/doom1.wad", "category": "game_data",
             "required": False},
            {"name": "engine.pk3", "category": "game_data", "required": True},
        ],
    },
}

FIRMWARE = {"firmware.rom", "corefw.bin"}
GAME = {"doom/doom1.wad", "engine.pk3"}


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bios = self.root / "bios"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        files = {}
        for rel, data in PAYLOADS.items():
            path = self.bios / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            files[sha1] = {
                "path": str(path), "name": path.name, "size": len(data), "sha1": sha1,
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(), "crc32": "00000000",
            }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        self.platforms.mkdir()
        self.emulators.mkdir()
        for key, profile in PROFILES.items():
            (self.emulators / f"{key}.yml").write_text(yaml.dump(profile))
        platform = {
            "platform": "Handheld", "version": "2.1", "verification_mode": "existence",
            "cores": ["emu", "doomcore"],
            "systems": {
                "console": {"files": [{"name": "firmware.rom", "destination": "firmware.rom"}]},
                "doom": {"files": [{"name": "doom1.wad", "destination": "doom/doom1.wad"}]},
            },
        }
        (self.platforms / "handheld.yml").write_text(yaml.dump(platform))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"handheld": {"config": "handheld.yml"}}})
        )
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.out = self.root / "dist"
        self.out.mkdir()

    def tearDown(self):
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def pack(self, no_game_data: bool) -> tuple[str, set[str], str]:
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            zip_path = builder.generate_pack(
                "handheld", str(self.platforms), self.db, str(self.bios), str(self.out),
                emulators_dir=str(self.emulators), emu_profiles=PROFILES,
                offline=True, no_game_data=no_game_data,
            )
        with zipfile.ZipFile(zip_path) as archive:
            members = set(archive.namelist()) - set(builder.PACK_DOCUMENTS)
        return zip_path, members, printed.getvalue()

    def manifest(self, no_game_data: bool = False) -> dict:
        return builder.generate_manifest(
            "handheld", str(self.platforms), self.db, str(self.bios),
            str(self.platforms / "_registry.yml"), emulators_dir=str(self.emulators),
            emu_profiles=PROFILES, offline=True, no_game_data=no_game_data,
        )


class ManifestCategory(_Fixture):
    def test_game_data_is_marked_and_firmware_is_not(self):
        manifest = self.manifest()
        self.assertIs(manifest["categorized"], True)
        category = {entry["dest"]: entry.get("category") for entry in manifest["files"]}
        self.assertEqual(set(category), FIRMWARE | GAME)
        # A platform entry only game data reads, and a core's game data file.
        self.assertEqual(category["doom/doom1.wad"], "game_data")
        self.assertEqual(category["engine.pk3"], "game_data")
        # Firmware carries no field at all.
        for entry in manifest["files"]:
            if entry["dest"] in FIRMWARE:
                self.assertNotIn("category", entry)

    def test_a_narrowed_manifest_is_the_full_one_without_game_data(self):
        full = self.manifest()
        narrowed = self.manifest(no_game_data=True)
        self.assertIs(narrowed["no_game_data"], True)
        self.assertEqual(
            {(e["dest"], e["sha1"]) for e in narrowed["files"]},
            {(e["dest"], e["sha1"]) for e in full["files"] if e.get("category") != "game_data"},
        )

    def test_an_omitted_game_data_file_is_marked(self):
        (self.bios / "Doom" / "engine.pk3").unlink()
        files = {sha1: e for sha1, e in self.db["files"].items() if e["name"] != "engine.pk3"}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        manifest = self.manifest()
        omitted = {e["dest"]: e.get("category") for e in manifest["omitted_files"]}
        self.assertEqual(omitted.get("engine.pk3"), "game_data")


class PackNarrowing(_Fixture):
    def test_the_pack_leaves_game_data_out_and_names_it(self):
        _full_path, full, _ = self.pack(no_game_data=False)
        zip_path, narrowed, printed = self.pack(no_game_data=True)
        self.assertEqual(full, FIRMWARE | GAME)
        self.assertEqual(narrowed, FIRMWARE)
        self.assertIn("_NoGameData_BIOS_Pack.zip", os.path.basename(zip_path))
        with zipfile.ZipFile(zip_path) as archive:
            readme = archive.read("README.txt").decode()
        self.assertIn("PACK TYPE: Narrowed", readme)
        self.assertIn("firmware only, game data left out", readme)
        # Named, with the reason, never only counted.
        self.assertIn("doom/doom1.wad (game data of doomcore)", printed)
        self.assertIn("doomcore: doom1.wad, engine.pk3", printed)

    def test_verify_reports_the_pack_the_builder_wrote(self):
        zip_path, members, _ = self.pack(no_game_data=True)
        config = common.load_platform_config("handheld", str(self.platforms))
        result = verify.verify_platform(
            config, self.db, str(self.emulators), PROFILES, no_game_data=True,
        )
        self.assertEqual(set(result["pack_destinations"]), members)
        self.assertTrue(any("doom/doom1.wad" in line for line in result["left_out"]))
        checked = packverify.verify_pack_against_platform(
            zip_path, "handheld", str(self.platforms), db=self.db,
            emulators_dir=str(self.emulators), emu_profiles=PROFILES,
            no_game_data=True,
        )
        self.assertTrue(checked[0], checked[3])
        # Held to the full list, the narrowed pack is short of the game data.
        full = packverify.verify_pack_against_platform(
            zip_path, "handheld", str(self.platforms), db=self.db,
            emulators_dir=str(self.emulators), emu_profiles=PROFILES,
        )
        self.assertFalse(full[0])

    def test_the_full_report_is_unchanged(self):
        config = common.load_platform_config("handheld", str(self.platforms))
        result = verify.verify_platform(config, self.db, str(self.emulators), PROFILES)
        self.assertNotIn("left_out", result)
        self.assertEqual(set(result["pack_destinations"]), FIRMWARE | GAME)

    def test_split_parts_add_up_to_the_narrowed_pack(self):
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            parts = builder.generate_split_packs(
                "handheld", str(self.platforms), self.db, str(self.bios), str(self.out),
                emulators_dir=str(self.emulators), emu_profiles=PROFILES,
                offline=True, no_game_data=True,
            )
        held: set[str] = set()
        for part in parts:
            self.assertIn("_NoGameData", part)
            with zipfile.ZipFile(part) as archive:
                held |= set(archive.namelist()) - set(builder.PACK_DOCUMENTS)
        self.assertEqual(held, FIRMWARE)


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args) -> None:
        return


class InstallerLeavesGameDataOut(unittest.TestCase):
    """The installer cut, in each mode, from a manifest served over loopback."""

    FILES = {
        "bios/a.bin": (b"alpha" * 20, None),
        "bios/game.wad": (b"wad" * 10, "game_data"),
    }

    def _tempdir(self) -> Path:
        handle = tempfile.TemporaryDirectory()
        self.addCleanup(handle.cleanup)
        return Path(handle.name)

    def serve(self, categorized: bool = True) -> None:
        root = self._tempdir()
        files = []
        for path, (data, category) in self.FILES.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(data)
            entry = {"dest": Path(path).name, "repo_path": path, "size": len(data),
                     "sha1": hashlib.sha1(data).hexdigest(), "cores": None,
                     "systems": ["sys-a"]}
            if category:
                entry["category"] = category
            files.append(entry)
        manifest = {
            "manifest_version": 2, "platform": "retroarch", "display_name": "RetroArch",
            "files": files,
            "omitted_files": [{"dest": "level.dat", "name": "level.dat", "system": "sys-a",
                               "required": True, "reason": "not_found",
                               "systems": ["sys-a"], "category": "game_data"}],
        }
        if categorized:
            manifest["categorized"] = True
        (root / "install").mkdir()
        (root / "install" / "retroarch.json").write_text(json.dumps(manifest))
        handler = functools.partial(_Quiet, directory=str(root))
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        home = self._tempdir()
        self.bios = home / "bios"
        self.bios.mkdir()
        self.env = {**os.environ, "HOME": str(home), "RETROBIOS_OS": "linux",
                    "RETROBIOS_BASE_URL": f"http://127.0.0.1:{httpd.server_address[1]}"}

    def run_installer(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "install.py", "--platform", "retroarch", "--dest",
             str(self.bios), "--no-input", "--jobs", "1", *argv],
            cwd=REPO_ROOT, env=self.env, capture_output=True, text=True, timeout=120,
            check=False,
        )

    def test_install_leaves_it_out_and_names_it(self):
        self.serve()
        proc = self.run_installer("--no-game-data", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((self.bios / "a.bin").exists())
        self.assertFalse((self.bios / "game.wad").exists())
        self.assertIn("2 game data files left out (--no-game-data), 1 of them not installable: "
                      "game.wad, level.dat",
                      proc.stdout)

    def test_check_and_dry_run_leave_it_out(self):
        self.serve()
        for mode, listed in (("--check", "1 file to download."),
                             ("--dry-run", "Would download 1 file")):
            with self.subTest(mode=mode):
                proc = self.run_installer("--no-game-data", mode, "--verbose")
                self.assertIn(
                    "2 game data files left out (--no-game-data), 1 of them not installable: "
                    "game.wad, level.dat",
                    proc.stdout,
                )
                self.assertIn(listed, proc.stdout)
                self.assertNotIn("missing: game.wad", proc.stdout)
                self.assertFalse((self.bios / "a.bin").exists())

    def test_the_default_installs_everything(self):
        self.serve()
        proc = self.run_installer()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((self.bios / "game.wad").exists())
        self.assertNotIn("game data files left out", proc.stdout)

    def test_events_name_what_was_left_out(self):
        self.serve()
        proc = self.run_installer("--no-game-data", "--check", "--events")
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        summary = next(e for e in events if e["event"] == "summary")
        self.assertEqual(list(summary), ["event", *install.EVENT_KEYS["summary"]])
        self.assertEqual(summary["left_out"], [{
            "category": "game_data", "label": "game data", "files": 2,
            "dests": ["game.wad", "level.dat"],
        }])
        # The omission is left out, not counted as a file the collection lacks.
        self.assertEqual(summary["skipped"], [])
        check = next(e for e in events if e["event"] == "check")
        self.assertEqual(check["files"], 1)

    def test_a_list_without_categories_is_refused(self):
        self.serve(categorized=False)
        proc = self.run_installer("--no-game-data", "--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("records no file category", proc.stderr)

    def test_listings_that_read_no_file_list_refuse_it(self):
        proc = subprocess.run(
            [sys.executable, "install.py", "--list-platforms", "--no-game-data"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--no-game-data", proc.stderr)

    def test_the_cut_function(self):
        files = [{"dest": "a"}, {"dest": "b", "category": "game_data"}]
        omitted = [{"dest": "c", "category": "game_data"}, {"dest": "d"}]
        kept, kept_omitted, left = install.leave_out_game_data(files, omitted)
        self.assertEqual([e["dest"] for e in kept], ["a"])
        self.assertEqual([e["dest"] for e in kept_omitted], ["d"])
        self.assertEqual([e["dest"] for e in left], ["b", "c"])


if __name__ == "__main__":
    unittest.main()
