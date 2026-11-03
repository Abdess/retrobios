"""Game catalogs: DAT import, region tags, determinism, floors, schema."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
FIXTURES = ROOT / "tests" / "fixtures" / "game_dats"
sys.path.insert(0, str(ROOT / "scripts"))

from region import REGIONS  # noqa: E402
from scripts.scraper import game_dat_importer as importer  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - CI installs it
    Draft202012Validator = None


def run_import(source: str, output: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "scripts.scraper.game_dat_importer", "--source", source,
         "--pack", str(FIXTURES), "--output-dir", str(output), *extra],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )


class RegionTags(unittest.TestCase):
    def test_first_territory_group_wins(self) -> None:
        self.assertEqual(importer.name_regions("Game (USA) (Rev 1)"), ["north-america"])
        self.assertEqual(importer.name_regions("Game (USA, Europe)"), ["europe", "north-america"])
        self.assertEqual(importer.name_regions("Game (En,Fr) (Japan)"), ["japan"])

    def test_world_absorbs(self) -> None:
        self.assertEqual(importer.name_regions("Game (World)"), ["world"])

    def test_untagged_and_unmapped(self) -> None:
        self.assertIsNone(importer.name_regions("Game (Rev 1)"))
        self.assertIsNone(importer.name_regions("Game (South Africa)"))

    def test_extra_words_fall_under_their_super_region(self) -> None:
        self.assertEqual(importer.name_regions("Game (Scandinavia)"), ["europe"])

    def test_every_mapping_is_vocabulary(self) -> None:
        targets = set(importer._TERRITORY.values())
        self.assertLessEqual(targets, set(REGIONS))


class FixtureImport(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.out = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_nointro_rows(self) -> None:
        result = run_import("no-intro", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        files = sorted(p.relative_to(self.out).as_posix() for p in self.out.rglob("*.json"))
        self.assertEqual(files, ["no-intro/nintendo-snes.json"])
        doc = json.loads((self.out / files[0]).read_text())
        self.assertEqual(doc["fields"], ["crc32", "size", "sha1", "region", "title"])
        self.assertEqual(len(doc["games"]), 5)
        rows = {row[4]: row for row in doc["games"]}
        self.assertEqual(rows["Zeta Quest (USA)"][:3],
                         ["0000beef", 1048576, "1" * 40])
        self.assertEqual(doc["regions"][rows["Both Worlds (USA, Europe) (Rev 1)"][3]],
                         ["europe", "north-america"])
        self.assertIsNone(rows["Untagged Demo"][3])
        self.assertEqual([r[0] for r in doc["games"]], sorted(r[0] for r in doc["games"]))
        self.assertIn("freely used", doc["licence"]["quote"])
        self.assertEqual(doc["licence"]["mirror"]["licence"], "MIT")

    def test_redump_first_data_track_and_serials(self) -> None:
        result = run_import("redump", self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads((self.out / "redump" / "sega-megacd.json").read_text())
        rows = {row[4]: row for row in doc["games"]}
        self.assertEqual(rows["Sonic CD (Europe)"][:2], ["0060ac74", 129590496])
        self.assertEqual(rows["Sonic CD (USA)"][5], ["4407", "T-0000"])
        self.assertEqual(doc["archive"]["dat_date"], "2026-10-23")
        self.assertIn("public domain", doc["licence"]["quote"])
        self.assertIn("serial_note", doc)
        coverage = importer.coverage(doc)
        self.assertEqual(coverage["serials"], 3)
        self.assertEqual(coverage["multi_region_serials"], 1)

    def test_two_imports_are_byte_identical(self) -> None:
        first, second = self.out / "a", self.out / "b"
        for out in (first, second):
            for source in ("no-intro", "redump"):
                self.assertEqual(run_import(source, out).returncode, 0)
        for path in first.rglob("*.json"):
            twin = second / path.relative_to(first)
            self.assertEqual(path.read_bytes(), twin.read_bytes(), path.name)

    def test_floor_refuses_a_short_dat(self) -> None:
        result = run_import("no-intro", self.out, "--floor", "--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("floor 3920", result.stderr)
        self.assertEqual(list(self.out.rglob("*.json")), [])

    def test_offline_without_cache_names_the_remedy(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "scripts.scraper.game_dat_importer", "--source", "redump",
             "--cache-dir", str(self.out / "empty"), "--output-dir", str(self.out)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--fetch", result.stderr)


class Selection(unittest.TestCase):
    def test_every_system_is_a_repository_system(self) -> None:
        from romfolders import SystemResolver

        ids = SystemResolver.from_repo().ids
        wanted = [s for s, _ in importer.NOINTRO_DATS.values()]
        wanted += [s for _, s, _ in importer.REDUMP_DATS.values()]
        self.assertEqual(len(wanted), len(set(wanted)))
        self.assertEqual([s for s in wanted if s not in ids], [])
        self.assertEqual(len(importer.NOINTRO_DATS), 29)
        self.assertEqual(len(importer.REDUMP_DATS), 9)


@unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
class CommittedCatalogs(unittest.TestCase):
    def setUp(self) -> None:
        schema = json.loads((ROOT / "schemas" / "game-catalog.schema.json").read_text())
        self.validator = Draft202012Validator(schema)
        self.paths = sorted((ROOT / "games" / "catalogs").glob("*/*.json"))

    def test_every_catalog_matches_the_schema(self) -> None:
        self.assertEqual(len(self.paths), 38)
        for path in self.paths:
            doc = json.loads(path.read_text())
            errors = [e.message for e in self.validator.iter_errors(doc)]
            self.assertEqual(errors, [], path.name)

    def test_committed_catalogs_meet_their_floor(self) -> None:
        for path in self.paths:
            doc = json.loads(path.read_text())
            self.assertEqual(path.stem, doc["system"])
            self.assertGreaterEqual(importer.coverage(doc)["games"], importer.floor_of(doc),
                                    path.name)

    def test_region_slugs_are_vocabulary(self) -> None:
        for path in self.paths:
            doc = json.loads(path.read_text())
            for regions in doc["regions"]:
                self.assertLessEqual(set(regions), set(REGIONS), path.name)

    def test_rewrite_is_a_no_op(self) -> None:
        for path in self.paths[:3]:
            doc = json.loads(path.read_text())
            self.assertEqual(importer.dump_catalog(doc), path.read_text())

    def test_fixture_output_matches_the_schema(self) -> None:
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            out = Path(directory)
            for source in ("no-intro", "redump"):
                self.assertEqual(run_import(source, out).returncode, 0)
            for path in out.rglob("*.json"):
                errors = [e.message for e in self.validator.iter_errors(json.loads(path.read_text()))]
                self.assertEqual(errors, [], path.name)


if __name__ == "__main__":
    unittest.main()
