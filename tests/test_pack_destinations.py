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


class ARequiredOnlyPack(_Fixture):
    """verify had no --required-only: nothing compared the pack to a report."""

    def test_verify_credits_what_the_pack_writes(self):
        from common import load_emulator_profiles, load_platform_config
        from generate_pack import PackRecord, generate_pack
        from verify import verify_platform

        (self.emulators / "coreemu.yml").write_text(yaml.safe_dump({
            "emulator": "CoreEmu", "type": "libretro", "systems": ["sys"],
            "files": [{"name": "core.bin", "required": False}],
        }))
        self._platform(
            [{"name": "sgb.sfc", "destination": "SGB1.sfc"},
             {"name": "program.rom", "destination": "program.rom", "required": False}],
            cores=["coreemu"],
        )
        profiles = load_emulator_profiles(str(self.emulators))
        record = PackRecord()
        with contextlib.redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                "paths", str(self.platforms), self.db, str(self.bios),
                str(self.root / "out"), emulators_dir=str(self.emulators),
                emu_profiles=profiles, offline=True, required_only=True,
            )
            generate_pack(
                "paths", str(self.platforms), self.db, str(self.bios), "",
                emulators_dir=str(self.emulators), emu_profiles=profiles,
                offline=True, required_only=True, record=record,
            )
        with zipfile.ZipFile(zip_path) as zf:
            members = set(zf.namelist())
        # The record names what the archive holds, nothing more or less.
        self.assertEqual(set(record.members), members)
        report = verify_platform(
            load_platform_config("paths", str(self.platforms)), self.db,
            str(self.emulators), profiles, required_only=True,
        )
        self.assertEqual(set(report["pack_destinations"]), {"SGB1.sfc"})
        self.assertEqual(members - {"README.txt"}, {"SGB1.sfc"})


class EveryNarrowingIsCompared(unittest.TestCase):
    """A way to narrow a pack that step 5 does not build is a way for the pack
    and verify to drift with nothing to say so."""

    def test_each_dimension_of_the_name_builder_is_accounted_for(self):
        import inspect

        import pipeline
        from generate_pack import _narrowings

        dimensions = set(inspect.signature(_narrowings).parameters)
        compared = set(pipeline.NARROWINGS_COMPARED)
        exempt = set(pipeline.NARROWINGS_NOT_COMPARED)
        self.assertFalse(compared & exempt)
        self.assertEqual(dimensions, compared | exempt,
                         "compare the new narrowing in check_narrowed_packs, "
                         "or write in NARROWINGS_NOT_COMPARED why it is not")

    def test_each_emulator_pack_narrowing_is_compared(self):
        """check_emulator_packs built every pack without --region or
        --required-only, while the table above counted both as compared:
        it describes the platform packs only."""
        import inspect

        import pipeline
        from generate_pack import _narrowings, generate_emulator_pack

        taken = (set(inspect.signature(_narrowings).parameters)
                 & set(inspect.signature(generate_emulator_pack).parameters))
        self.assertEqual(taken, set(pipeline.EMULATOR_NARROWINGS_COMPARED))
        profile = {"files": [{"name": "a.bin", "region": "japan"},
                             {"name": "b.bin", "region": ["north-america", "europe"]}]}
        used = {key for _label, narrowing in pipeline.emulator_variants([profile], False)
                for key in narrowing}
        # standalone is the loop around the variants, both builds of each profile.
        self.assertEqual(used, pipeline.EMULATOR_NARROWINGS_COMPARED - {"standalone"})
        regions = [n["regions"] for _l, n in pipeline.emulator_variants([profile], True)
                   if "regions" in n]
        self.assertEqual(len(regions), 3)

    def test_the_variants_reach_every_compared_dimension(self):
        import pipeline
        from common import load_emulator_profiles, load_platform_config

        platforms = str(REPO_ROOT / "platforms")
        config = load_platform_config("retroarch", platforms)
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for full in (False, True):
            with self.subTest(full=full):
                variants = pipeline.narrowed_variants(
                    "retroarch", config, profiles, platforms, full,
                )
                used = {key for _label, narrowing in variants for key in narrowing}
                self.assertEqual(used, pipeline.NARROWINGS_COMPARED | {"system_filter"})
        systems = [n for _l, n in variants if "system_filter" in n]
        self.assertEqual(len(systems), len(config["systems"]))

    def test_the_sample_takes_both_ends_and_the_middle(self):
        import pipeline

        self.assertEqual(list(pipeline._matrix_coverage(False, 2)), [0, 1])
        self.assertEqual(pipeline._matrix_coverage(False, 11), [0, 5, 10])
        self.assertEqual(list(pipeline._matrix_coverage(True, 11)), list(range(11)))

    def test_the_run_compares_them(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn("ok = check_narrowed_packs(", source)


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
        self.assertIn("ok = check_emulator_packs(full=args.full_narrowings) and ok", source)
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
