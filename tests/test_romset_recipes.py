"""Tests for romset identification and reconstruction from recipes."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts"))

from romset_recipes import (  # noqa: E402
    AtomPool,
    collect_recipes,
    identify_archive,
    identify_report,
    load_dat_recipes,
    merge_recipes,
    missing_report,
    reconstruct,
    write_reconstructions,
)
from scripts.scraper.romset_dat_importer import (  # noqa: E402
    compact_entries,
    listxml_entries,
    merge_snapshot,
    recipe_entries,
)
from scripts.scraper.logiqx_parser import parse_logiqx  # noqa: E402
from torrentzip import build_torrentzip, is_torrentzip  # noqa: E402

ROM_A = b"first rom payload"
ROM_B = b"second rom payload"


def _crc(data: bytes) -> str:
    import zlib

    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


class RecipeCollection(unittest.TestCase):
    def test_only_recipes_with_every_crc_are_usable(self):
        profiles = {
            "complete": {
                "files": [
                    {
                        "name": "set.zip",
                        "contents": [
                            {"name": "a.rom", "crc32": "11111111"},
                            {"name": "b.rom", "crc32": "22222222"},
                        ],
                    }
                ]
            },
            "partial": {
                "files": [
                    {
                        "name": "set.zip",
                        "contents": [
                            {"name": "a.rom", "crc32": "11111111"},
                            {"name": "b.rom"},
                        ],
                    }
                ]
            },
        }
        recipes = collect_recipes(profiles)
        self.assertEqual(sorted(recipes["set.zip"]), ["complete"])

    def test_an_archive_without_contents_has_no_recipe(self):
        recipes = collect_recipes({"p": {"files": [{"name": "set.zip"}]}})
        self.assertEqual(recipes, {})


class PoolAndBuild(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.bios = Path(self.temp.name)
        with zipfile.ZipFile(self.bios / "source.zip", "w") as archive:
            archive.writestr("a.rom", ROM_A)
            archive.writestr("b.rom", ROM_B)
        self.pool = AtomPool(self.bios)

    def tearDown(self):
        self.temp.cleanup()

    def test_atoms_are_addressed_by_crc32(self):
        self.assertIn(_crc(ROM_A), self.pool)
        self.assertEqual(self.pool.read(_crc(ROM_A)), ROM_A)

    def test_a_recipe_missing_an_atom_builds_nothing(self):
        self.assertIsNone(self.pool.build([("x.rom", "deadbeef")]))

    def test_build_is_torrentzip_and_reproducible(self):
        recipe = [("a.rom", _crc(ROM_A)), ("b.rom", _crc(ROM_B))]
        first = self.pool.build(recipe)
        self.assertEqual(first, build_torrentzip([("a.rom", ROM_A), ("b.rom", ROM_B)]))
        target = self.bios / "built.zip"
        target.write_bytes(first)
        self.assertTrue(is_torrentzip(target))

    def test_identify_names_the_recipe_that_rebuilds_the_archive(self):
        recipe = [("a.rom", _crc(ROM_A)), ("b.rom", _crc(ROM_B))]
        built = self.bios / "built.zip"
        built.write_bytes(self.pool.build(recipe))
        label = identify_archive(
            built,
            {"v2": recipe, "v1": [("a.rom", _crc(ROM_A))]},
            self.pool,
        )
        self.assertEqual(label, "v2")

    def test_identify_returns_nothing_when_no_recipe_matches(self):
        other = self.bios / "other.zip"
        other.write_bytes(build_torrentzip([("z.rom", b"unrelated")]))
        self.assertIsNone(
            identify_archive(other, {"v1": [("a.rom", _crc(ROM_A))]}, self.pool)
        )

    def test_reconstruct_finds_the_recipe_behind_a_pinned_md5(self):
        recipe = [("a.rom", _crc(ROM_A))]
        target = hashlib.md5(self.pool.build(recipe)).hexdigest()
        found = reconstruct(target, {"v1": recipe}, self.pool)
        self.assertIsNotNone(found)
        self.assertEqual(found[0], "v1")
        self.assertEqual(hashlib.md5(found[1]).hexdigest(), target)


class ReportsOverAFixture(unittest.TestCase):
    """A whole run over a synthetic collection, database and platform."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.root = Path(self.temp.name)
        self.bios = self.root / "bios"
        self.bios.mkdir()
        self.pool_source = self.bios / "source.zip"
        with zipfile.ZipFile(self.pool_source, "w") as archive:
            archive.writestr("a.rom", ROM_A)
            archive.writestr("b.rom", ROM_B)
        self.pool = AtomPool(self.bios)
        self.recipe = [("a.rom", _crc(ROM_A)), ("b.rom", _crc(ROM_B))]
        self.set_path = self.bios / "set.zip"
        self.set_path.write_bytes(self.pool.build(self.recipe))
        # The pool must see the archive it will be asked to identify.
        self.pool = AtomPool(self.bios)

        blob = self.set_path.read_bytes()
        self.db = {
            "files": {
                hashlib.sha1(blob).hexdigest(): {
                    "path": str(self.set_path),
                    "name": "set.zip",
                    "md5": hashlib.md5(blob).hexdigest(),
                }
            },
            "indexes": {
                "by_name": {"set.zip": [hashlib.sha1(blob).hexdigest()]},
                "by_md5": {hashlib.md5(blob).hexdigest(): hashlib.sha1(blob).hexdigest()},
            },
        }
        self.recipes = {"set.zip": {"v1": self.recipe}}

    def tearDown(self):
        self.temp.cleanup()

    def test_identify_report_labels_the_local_archive(self):
        report = identify_report(self.recipes, self.pool, self.db)
        self.assertEqual(len(report["identified"]), 1)
        self.assertEqual(report["identified"][0]["recipe"], "v1")
        self.assertTrue(report["identified"][0]["torrentzip"])
        self.assertEqual(report["unidentified"], [])

    def test_an_aliased_non_archive_is_not_treated_as_a_romset(self):
        loose = self.bios / "state-machine.rom"
        loose.write_bytes(b"not an archive")
        sha1 = hashlib.sha1(loose.read_bytes()).hexdigest()
        self.db["files"][sha1] = {"path": str(loose), "name": "state-machine.rom"}
        self.db["indexes"]["by_name"]["set.zip"].append(sha1)

        report = identify_report(self.recipes, self.pool, self.db)
        paths = {r["path"] for r in report["identified"] + report["unidentified"]}
        self.assertNotIn(str(loose), paths)

    def test_missing_report_reconstructs_a_pinned_archive(self):
        platforms = self.root / "platforms"
        platforms.mkdir()
        pinned = hashlib.md5(self.pool.build(self.recipe)).hexdigest()
        (platforms / "_registry.yml").write_text(
            "platforms:\n  demo:\n    config: demo.yml\n    status: active\n",
            encoding="utf-8",
        )
        (platforms / "demo.yml").write_text(
            "platform: Demo\nsystems:\n  arcade:\n    files:\n"
            "      - name: set.zip\n        destination: set.zip\n"
            f"        md5: {pinned}\n",
            encoding="utf-8",
        )
        # The collection does not hold the pinned archive yet.
        self.db["indexes"]["by_md5"] = {}

        report = missing_report(self.recipes, self.pool, self.db, str(platforms))
        self.assertEqual(len(report["constructible"]), 1)
        entry = report["constructible"][0]
        self.assertEqual(entry["recipe"], "v1")
        self.assertEqual(entry["md5"], pinned)

        written = write_reconstructions(
            report["constructible"], self.recipes, self.pool, self.bios, self.db
        )
        self.assertEqual(len(written), 1)
        produced = Path(written[0])
        self.assertEqual(hashlib.md5(produced.read_bytes()).hexdigest(), pinned)
        self.assertTrue(is_torrentzip(produced))

    def test_an_unreproducible_pin_is_reported_not_guessed(self):
        platforms = self.root / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            "platforms:\n  demo:\n    config: demo.yml\n    status: active\n",
            encoding="utf-8",
        )
        (platforms / "demo.yml").write_text(
            "platform: Demo\nsystems:\n  arcade:\n    files:\n"
            "      - name: set.zip\n        destination: set.zip\n"
            f"        md5: {'f' * 32}\n",
            encoding="utf-8",
        )
        self.db["indexes"]["by_md5"] = {}

        report = missing_report(self.recipes, self.pool, self.db, str(platforms))
        self.assertEqual(report["constructible"], [])
        self.assertEqual(len(report["unreproducible"]), 1)
        self.assertEqual(report["unreproducible"][0]["recipes_tried"], ["v1"])


DAT = """<?xml version="1.0"?>
<datafile>
  <header><name>MAME</name><version>0.289</version></header>
  <machine name="manager">
    <description>Salora Manager</description>
    <rom name="01" size="17" crc="{crc_a}" sha1=""/>
    <rom name="23" size="18" crc="{crc_b}" sha1=""/>
  </machine>
  <machine name="undumped">
    <description>Nothing dumped yet</description>
    <rom name="x.rom" size="0" status="nodump"/>
  </machine>
</datafile>
"""


class DatRecipes(unittest.TestCase):
    """A DAT states, per set, the members one emulator version expects."""

    def _dat(self) -> str:
        return DAT.format(crc_a=_crc(ROM_A), crc_b=_crc(ROM_B))

    def test_a_set_becomes_one_recipe_named_after_its_archive(self):
        entries = recipe_entries(parse_logiqx(self._dat()))
        self.assertEqual([e["name"] for e in entries], ["manager.zip"])
        self.assertEqual(
            [m["name"] for m in entries[0]["members"]], ["01", "23"]
        )

    def test_an_undumped_member_is_dropped_not_the_whole_set(self):
        """A real romset does not carry a ROM nobody has dumped."""
        entries = recipe_entries(parse_logiqx(self._dat()))
        self.assertNotIn("undumped.zip", [e["name"] for e in entries])

    def test_only_referenced_archives_are_kept(self):
        entries = recipe_entries(parse_logiqx(self._dat()), keep={"other.zip"})
        self.assertEqual(entries, [])

    def test_snapshot_round_trips_into_usable_recipes(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            snapshot = root / "romset-recipes.json"
            entries = recipe_entries(parse_logiqx(self._dat()))
            snapshot.write_text(
                json.dumps(
                    {
                        "source": "mame",
                        "imported_at": "2026-08-10",
                        "dats": {"MAME": "0.289"},
                        "entries": entries,
                    }
                ),
                encoding="utf-8",
            )
            recipes = load_dat_recipes(snapshot)
            self.assertEqual(sorted(recipes), ["manager.zip"])
            self.assertEqual(sorted(recipes["manager.zip"]), ["mame:MAME"])

            bios = root / "bios"
            bios.mkdir()
            with zipfile.ZipFile(bios / "source.zip", "w") as archive:
                archive.writestr("01", ROM_A)
                archive.writestr("23", ROM_B)
            pool = AtomPool(bios)
            built = bios / "manager.zip"
            built.write_bytes(pool.build(recipes["manager.zip"]["mame:MAME"]))
            self.assertTrue(is_torrentzip(built))
            self.assertEqual(
                identify_archive(built, recipes["manager.zip"], AtomPool(bios)),
                "mame:MAME",
            )

    def test_a_missing_snapshot_is_simply_no_recipes(self):
        self.assertEqual(load_dat_recipes(TMP_ROOT / "absent.json"), {})

    def test_merge_keeps_profile_and_dat_labels_side_by_side(self):
        merged = merge_recipes(
            {"set.zip": {"mame": [("a", "1")]}},
            {"set.zip": {"mame:MAME": [("a", "1")]}},
        )
        self.assertEqual(sorted(merged["set.zip"]), ["mame", "mame:MAME"])


LISTXML = """<?xml version="1.0"?>
<!DOCTYPE mame [<!ELEMENT mame (machine+)>]>
<mame build="0.289">
  <machine name="parentset" isbios="yes">
    <description>Parent</description>
    <rom name="shared.rom" size="17" crc="{crc_a}" sha1=""/>
  </machine>
  <machine name="childset" romof="parentset">
    <description>Child</description>
    <rom name="own.rom" size="18" crc="{crc_b}" sha1=""/>
  </machine>
  <machine name="undumped">
    <description>Nothing dumped</description>
    <rom name="x.rom" size="0" status="nodump"/>
  </machine>
</mame>
"""


class ListXmlRecipes(unittest.TestCase):
    """MAME ships its -listxml output as a release asset."""

    def _opener(self, text: str):
        import io

        return lambda: io.BytesIO(text.encode("utf-8"))

    def _document(self) -> str:
        return LISTXML.format(crc_a=_crc(ROM_A), crc_b=_crc(ROM_B))

    def test_a_child_inherits_its_parent_members(self):
        """A non-merged archive carries the parent set's ROMs as well."""
        entries = listxml_entries(self._opener(self._document()), "MAME 0.289", None)
        by_name = {entry["name"]: entry for entry in entries}
        self.assertEqual(
            [m["name"] for m in by_name["childset.zip"]["members"]],
            ["own.rom", "shared.rom"],
        )

    def test_a_set_without_a_parent_keeps_its_own_members(self):
        entries = listxml_entries(self._opener(self._document()), "MAME 0.289", None)
        by_name = {entry["name"]: entry for entry in entries}
        self.assertEqual(
            [m["name"] for m in by_name["parentset.zip"]["members"]], ["shared.rom"]
        )

    def test_an_undumped_only_set_is_dropped(self):
        entries = listxml_entries(self._opener(self._document()), "MAME 0.289", None)
        self.assertNotIn("undumped.zip", {entry["name"] for entry in entries})

    def test_a_parent_outside_the_keep_set_is_still_resolved(self):
        """The child is wanted, its parent is not, and the union still holds."""
        entries = listxml_entries(
            self._opener(self._document()), "MAME 0.289", {"childset.zip"}
        )
        self.assertEqual([entry["name"] for entry in entries], ["childset.zip"])
        self.assertEqual(
            [m["name"] for m in entries[0]["members"]], ["own.rom", "shared.rom"]
        )

    def test_versions_accumulate_instead_of_replacing_each_other(self):
        """A platform pins the archive of whichever version it was built on."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            output = str(Path(directory) / "romset-recipes.json")
            merge_snapshot(
                output,
                "mame",
                {"MAME 0.288": "mame0288"},
                [
                    {
                        "dat": "MAME 0.288",
                        "name": "set.zip",
                        "set": "set",
                        "description": "",
                        "members": [{"name": "a", "crc32": "1"}],
                    }
                ],
            )
            merge_snapshot(
                output,
                "mame",
                {"MAME 0.289": "mame0289"},
                [
                    {
                        "dat": "MAME 0.289",
                        "name": "set.zip",
                        "set": "set",
                        "description": "",
                        "members": [{"name": "b", "crc32": "2"}],
                    }
                ],
            )
            recipes = load_dat_recipes(output)
            self.assertEqual(
                sorted(recipes["set.zip"]), ["mame:MAME 0.288", "mame:MAME 0.289"]
            )


class SnapshotCompaction(unittest.TestCase):
    """Most sets do not change between MAME releases."""

    def _entry(self, dat: str, members: list[dict]) -> dict:
        return {
            "dat": dat,
            "name": "set.zip",
            "set": "set",
            "description": "",
            "members": members,
        }

    def test_identical_recipes_collapse_to_one_entry(self):
        members = [{"name": "a", "crc32": "1"}]
        compact = compact_entries(
            [
                self._entry("MAME 0.200", members),
                self._entry("MAME 0.190", members),
                self._entry("MAME 0.210", members),
            ]
        )
        self.assertEqual(len(compact), 1)
        self.assertEqual(
            compact[0]["dats"], ["MAME 0.190", "MAME 0.200", "MAME 0.210"]
        )

    def test_the_representative_label_is_the_earliest_version(self):
        """A match reads as 'unchanged since', not 'is this version'."""
        members = [{"name": "a", "crc32": "1"}]
        compact = compact_entries(
            [self._entry("MAME 0.280", members), self._entry("MAME 0.190", members)]
        )
        self.assertEqual(compact[0]["dat"], "MAME 0.190")

    def test_a_changed_recipe_stays_a_separate_entry(self):
        compact = compact_entries(
            [
                self._entry("MAME 0.190", [{"name": "a", "crc32": "1"}]),
                self._entry("MAME 0.280", [{"name": "a", "crc32": "2"}]),
            ]
        )
        self.assertEqual(len(compact), 2)

    def test_compaction_is_idempotent(self):
        members = [{"name": "a", "crc32": "1"}]
        once = compact_entries(
            [self._entry("MAME 0.190", members), self._entry("MAME 0.200", members)]
        )
        self.assertEqual(compact_entries(once), once)


class RepositoryRun(unittest.TestCase):
    """The real collection, skipped when its data is not present."""

    def test_identification_covers_the_documented_archives(self):
        database = ROOT / "database.json"
        bios = ROOT / "bios"
        if not database.is_file() or not bios.is_dir():
            self.skipTest("collection not present in this checkout")

        from common import load_database, load_emulator_profiles

        db = load_database(str(database))
        recipes = collect_recipes(
            load_emulator_profiles(str(ROOT / "emulators"), skip_aliases=False)
        )
        self.assertGreater(len(recipes), 0)
        pool = AtomPool(bios)
        self.assertGreater(len(pool), 0)
        self.assertEqual(pool.unreadable, [])

        report = identify_report(recipes, pool, db)
        self.assertGreater(len(report["identified"]), 0)
        for record in report["identified"]:
            self.assertIn(record["recipe"], recipes[record["archive"]])


if __name__ == "__main__":
    unittest.main()
