"""Arcade parent index: game set to BIOS sets and device sets, per core."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
FIXTURES = ROOT / "tests" / "fixtures" / "arcade_parents"
COMMITTED = ROOT / "games" / "arcade"

from scripts.scraper import arcade_parent_importer as api  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # validate_schemas.py is the only tool that needs it
    Draft202012Validator = None

COMMIT = "a" * 40


def _sets(name: str, chunk: int | None = None) -> dict:
    data = (FIXTURES / name).read_bytes()
    saved = api.LISTXML_CHUNK
    if chunk:
        api.LISTXML_CHUNK = chunk
    try:
        return api.read_sets([lambda: io.BytesIO(data)])
    finally:
        api.LISTXML_CHUNK = saved


class ListxmlIndex(unittest.TestCase):
    def setUp(self) -> None:
        self.index = api.build_index(_sets("listxml.xml"), "isbios")

    def test_clone_reaches_bios_through_its_parent(self) -> None:
        self.assertEqual(self.index["bios"]["neogeo"], ["mslug", "mslugh"])

    def test_every_bios_on_the_chain_is_listed(self) -> None:
        self.assertIn("ikaruga", self.index["bios"]["naomigd"])
        self.assertIn("ikaruga", self.index["bios"]["naomi"])

    def test_device_with_roms_only(self) -> None:
        self.assertEqual(self.index["devices"], {"m68705p3": ["mslug"]})

    def test_chd_and_missing_parent(self) -> None:
        self.assertEqual(self.index["chd"], ["ikaruga"])
        self.assertEqual(self.index["missing_parents"], {"orphan": "gonebios"})

    def test_sets_without_a_dump_are_not_games(self) -> None:
        counts = self.index["counts"]
        # mslug, mslugh, ikaruga, orphan, pacman
        self.assertEqual(counts["games"], 5)
        self.assertEqual(counts["games_with_bios"], 3)
        self.assertEqual(counts["bios_sets"], 3)

    def test_games_without_a_bios_and_the_bios_sets_are_named(self) -> None:
        # A set on a card is then a game that needs nothing, a BIOS set,
        # or a name the DAT does not hold: only the last falls back.
        self.assertEqual(self.index["no_bios"], ["pacman"])
        self.assertEqual(len(self.index["bios_sets"]), self.index["counts"]["bios_sets"])
        self.assertIn("neogeo", self.index["bios_sets"])
        self.assertNotIn("orphan", self.index["no_bios"])

    def test_small_window_reads_the_same(self) -> None:
        small = api.build_index(_sets("listxml.xml", chunk=64), "isbios")
        self.assertEqual(api.dump(small), api.dump(self.index))


class RunnableMarker(unittest.TestCase):
    def test_runnable_no_marks_the_bios(self) -> None:
        index = api.build_index(_sets("runnable_no.dat"), "runnable")
        self.assertEqual(index["bios"], {"neogeo": ["kof98"]})
        self.assertEqual(index["missing_parents"], {"brvblade": "psarc95"})
        self.assertEqual(index["counts"]["bios_sets"], 2)

    def test_isbios_marker_ignores_runnable(self) -> None:
        index = api.build_index(_sets("runnable_no.dat"), "isbios")
        self.assertEqual(index["bios"], {})


class FlycastTable(unittest.TestCase):
    def setUp(self) -> None:
        self.index = api.flycast_index((FIXTURES / "naomi_roms.cpp").read_text())

    def test_null_bios_is_naomi_and_filename_names_the_archive(self) -> None:
        self.assertEqual(self.index["bios"]["naomi"], ["gram2000", "ikaruga", "jpgame"])
        self.assertEqual(self.index["bios"]["awbios"], ["kofnw"])
        self.assertNotIn("naomi-jp-d", self.index["bios"])

    def test_gdrom_game_needs_a_chd(self) -> None:
        self.assertEqual(self.index["chd"], ["ikaruga"])

    def test_unknown_bios_is_reported(self) -> None:
        self.assertEqual(self.index["missing_parents"], {"bad": "nosuchbios"})


class OfflineImport(unittest.TestCase):
    """import_profile reads the cache only, and two runs write the same bytes."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.cache = Path(self.temp.name)
        dat = self.cache / "repo" / "libretro" / "mame2003-libretro" / COMMIT / "metadata"
        dat.mkdir(parents=True)
        (dat / "mame2003.xml").write_bytes((FIXTURES / "runnable_no.dat").read_bytes())
        with zipfile.ZipFile(self.cache / "mame0000lx.zip", "w") as archive:
            archive.write(FIXTURES / "listxml.xml", "mame0000.xml")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_repo_profile_is_deterministic(self) -> None:
        profile = {
            "source": "https://github.com/libretro/mame2003-libretro",
            "source_commit": COMMIT,
            "core_version": "0.78",
        }
        first = api.dump(api.import_profile("mame2003", profile, self.cache, offline=True))
        second = api.dump(api.import_profile("mame2003", profile, self.cache, offline=True))
        self.assertEqual(first, second)
        doc = json.loads(first)
        self.assertEqual(doc["bios"], {"neogeo": ["kof98"]})
        self.assertEqual(list(doc["source"]["files"]), ["metadata/mame2003.xml"])

    def test_listxml_release_from_the_cache(self) -> None:
        doc = api.import_profile("mame", {"core_version": "0.000"}, self.cache, offline=True)
        self.assertEqual(doc["source"]["release"], "mamedev/mame mame0000")
        self.assertEqual(doc["devices"], {"m68705p3": ["mslug"]})

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_fixture_output_matches_the_schema(self) -> None:
        profile = {
            "source": "https://github.com/libretro/mame2003-libretro",
            "source_commit": COMMIT,
            "core_version": "0.78",
        }
        doc = api.import_profile("mame2003", profile, self.cache, offline=True)
        schema = json.loads((ROOT / "schemas" / "arcade-parents.schema.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(doc)), [])


class DeclaredArchives(unittest.TestCase):
    def test_names_aliases_and_archives(self) -> None:
        profile = {"files": [
            {"name": "neogeo.zip"},
            {"name": "sp-s2.sp1", "archive": "neogeo.zip"},
            {"name": "pgm.zip", "aliases": ["PGMBIOS.zip"]},
        ]}
        self.assertEqual(api.declared_archives(profile), {"neogeo.zip", "sp-s2.sp1", "pgm.zip", "pgmbios.zip"})


class CommittedIndex(unittest.TestCase):
    def test_every_profile_has_its_file_above_the_floor(self) -> None:
        for profile in api.PROFILES:
            with self.subTest(profile=profile):
                path = COMMITTED / f"{profile}.json"
                self.assertTrue(path.is_file(), path)
                doc = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(doc["profile"], profile)
                self.assertGreaterEqual(doc["counts"]["games_with_bios"], api.FLOORS[profile])

    def test_committed_files_are_written_canonically(self) -> None:
        for path in sorted(COMMITTED.glob("*.json")):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(api.dump(json.loads(text)), text)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_committed_files_match_the_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "arcade-parents.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for path in sorted(COMMITTED.glob("*.json")):
            with self.subTest(path=path.name):
                errors = list(validator.iter_errors(json.loads(path.read_text(encoding="utf-8"))))
                self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
