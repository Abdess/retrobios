"""verify and the pack name the same paths, not only the same number of them.

The pipeline compared counts. RetroArch declares SGB1.sfc and, below it,
SGB1.sfc/program.rom: the pack writes the file and skips the path it blocks,
verify credited both, and both sides still read 526/526. A user_provided
declaration keeps its slot in the pack, while verify let a core file take
it and counted one more file from the cores.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class _Fixture(unittest.TestCase):
    def setUp(self) -> None:
        from common import _emulator_profiles_cache

        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.bios = self.root / "bios"
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        for directory in (self.bios, self.platforms, self.emulators):
            directory.mkdir()
        files, by_name, by_md5 = {}, {}, {}
        for name, data in (("sgb.sfc", b"SGB" * 8), ("program.rom", b"PRG" * 8),
                           ("core.bin", b"CORE" * 8)):
            path = self.bios / name
            path.write_bytes(data)
            sha1, md5 = hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest()
            files[sha1] = {"path": str(path), "name": name, "md5": md5, "size": len(data)}
            by_name[name] = [sha1]
            by_md5[md5] = sha1
        self.db = {"files": files, "indexes": {"by_name": by_name, "by_md5": by_md5,
                                               "by_crc32": {}, "by_path_suffix": {}}}

    def _platform(self, files: list[dict], cores: list[str] | None = None) -> dict:
        config = {"platform": "Paths", "verification_mode": "existence",
                  "base_destination": "system", "systems": {"sys": {"files": files}}}
        if cores is not None:
            config["cores"] = cores
        (self.platforms / "paths.yml").write_text(yaml.safe_dump(config))
        return config

    def _both(self) -> tuple[dict, set[str]]:
        from common import load_emulator_profiles, load_platform_config
        from generate_pack import generate_pack
        from verify import verify_platform

        profiles = load_emulator_profiles(str(self.emulators))
        report = verify_platform(
            load_platform_config("paths", str(self.platforms)), self.db,
            str(self.emulators), profiles,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                "paths", str(self.platforms), self.db, str(self.bios),
                str(self.root / "out"), emulators_dir=str(self.emulators),
                emu_profiles=profiles, offline=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            members = {n for n in zf.namelist() if n != "README.txt"}
        return report, members


class APathBlockedByAFile(_Fixture):
    def test_verify_credits_only_the_file_the_pack_writes(self):
        self._platform([
            {"name": "sgb.sfc", "destination": "SGB1.sfc"},
            {"name": "program.rom", "destination": "SGB1.sfc/program.rom"},
        ])
        report, members = self._both()
        self.assertEqual(members, {"SGB1.sfc"})
        self.assertEqual(set(report["pack_destinations"]), members)


class AUserProvidedSlot(_Fixture):
    def test_no_core_file_takes_it_on_either_side(self):
        (self.emulators / "coreemu.yml").write_text(yaml.safe_dump({
            "emulator": "CoreEmu", "type": "libretro", "systems": ["sys"],
            "files": [{"name": "core.bin", "required": True}],
        }))
        self._platform(
            [{"name": "manual.bin", "destination": "core.bin", "storage": "user_provided"}],
            cores=["coreemu"],
        )
        report, members = self._both()
        self.assertEqual(members, {"INSTRUCTIONS_manual.bin.txt"})
        self.assertEqual(report["packed_extras"], {"bios": 0, "game_data": 0})
        self.assertEqual(report["pack_destinations"], [])


class AnEntryWithoutAFileTakesNoPath(unittest.TestCase):
    """EmuDeck's system:md5 entries name no file. verify credited the bare
    base destination as a pack path, and the comparison failed on ''."""

    def test_it_is_left_out(self):
        from verify import _builder_placement

        shipped, occupied = _builder_placement(
            [("s", "bios/", None), ("s", "", "x"), ("s", "bios/a.bin", "bios/a.bin")], False
        )
        self.assertEqual(shipped, {"bios/a.bin": "bios/a.bin"})
        self.assertEqual(set(occupied), {"bios/a.bin"})


class ThePipelineComparesPaths(unittest.TestCase):
    """Equal counts, other paths: the comparison fails and names both sides."""

    def test_a_swap_at_equal_counts_fails(self):
        import pipeline

        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        zip_path = root / "Plat_BIOS_Pack.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for name in ("a.bin", "b.bin", "README.txt", "INSTRUCTIONS_x.bin.txt"):
                zf.writestr(name, name)
        output = f"Generating pack for plat [source=full]...\n  {zip_path}: 2 files packed\n"
        for credited, expected in ((["a.bin", "b.bin"], True), (["a.bin", "c.bin"], False)):
            with self.subTest(credited=credited):
                destinations = root / "d.json"
                destinations.write_text(json.dumps(
                    {"Plat": {"platform": "plat", "pack_destinations": credited}}
                ))
                previous = os.getcwd()
                os.chdir(REPO_ROOT)
                try:
                    with mock_tree_members(), contextlib.redirect_stdout(io.StringIO()) as out:
                        ok = pipeline.check_pack_destinations(str(destinations), output)
                finally:
                    os.chdir(previous)
                self.assertIs(ok, expected, out.getvalue())
                if not expected:
                    self.assertIn("verify only 1: c.bin", out.getvalue())
                    self.assertIn("pack only 1: b.bin", out.getvalue())

    def test_the_run_compares_every_emulator_pack(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn("ok = check_pack_destinations(destinations_file, pack_output) and ok", source)
        self.assertIn("ok = check_emulator_packs() and ok", source)
        self.assertIn('"--destinations", destinations_file', source)


@contextlib.contextmanager
def mock_tree_members():
    import pipeline

    original = pipeline._tree_members
    pipeline._tree_members = lambda *_args: {}
    try:
        yield
    finally:
        pipeline._tree_members = original


class EveryEmulatorPackMatchesItsReport(unittest.TestCase):
    """Reads the repository: every profile, both builds, built in memory."""

    def test_the_paths_agree(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json is not built")
        import pipeline

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                ok = pipeline.check_emulator_packs()
        finally:
            os.chdir(previous)
        self.assertTrue(ok, out.getvalue())
        # Packs of several profiles too: a placement rule that only goes
        # wrong when two profiles share a path never meets in one profile.
        self.assertIn("system packs compared, all equal", out.getvalue())


if __name__ == "__main__":
    unittest.main()
