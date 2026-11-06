"""Tests for romset identification and reconstruction from recipes."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
import zlib
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
    catalog_targets,
    compact_entries,
    holds_target,
    listxml_entries,
    git_blob_sha,
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
            "platforms:\n  demo:\n    config: demo.yml\n",
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
            "platforms:\n  demo:\n    config: demo.yml\n",
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

    def test_a_machine_larger_than_the_window_is_kept(self):
        """Each machine here spans several reads: the window grows until the
        element closes instead of cutting its start tag away."""
        from scripts.scraper import romset_dat_importer

        expected = listxml_entries(self._opener(self._document()), "MAME 0.289", None)
        saved = romset_dat_importer.LISTXML_CHUNK
        try:
            for window in (1, 7, 16, 64):
                romset_dat_importer.LISTXML_CHUNK = window
                entries = listxml_entries(
                    self._opener(self._document()), "MAME 0.289", None
                )
                self.assertEqual(entries, expected, window)
        finally:
            romset_dat_importer.LISTXML_CHUNK = saved
        self.assertEqual(
            [entry["name"] for entry in entries], ["childset.zip", "parentset.zip"]
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

    def test_a_set_holding_a_missing_catalog_dump_is_kept(self):
        """fm7740sx carries three No-Intro dumps the collection lacks. No
        profile names it, so the missing report named no place to find them."""
        targets = {(_crc(ROM_B), len(ROM_B)): {""}}
        entries = listxml_entries(
            self._opener(self._document()), "MAME 0.289", {"other.zip"}, targets
        )
        self.assertEqual([entry["name"] for entry in entries], ["childset.zip"])

    def test_a_catalog_sha1_must_agree(self):
        member = {"crc32": _crc(ROM_B), "size": len(ROM_B), "sha1": "a" * 40}
        self.assertFalse(holds_target([member], {(_crc(ROM_B), len(ROM_B)): {"b" * 40}}))
        self.assertTrue(holds_target([member], {(_crc(ROM_B), len(ROM_B)): {"a" * 40}}))

    def test_catalog_targets_leave_out_what_the_collection_holds(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            (root / "prov").mkdir()
            (root / "prov" / "tosec.json").write_text(json.dumps({"source": "tosec", "entries": [
                {"name": "held.rom", "crc32": "1", "size": 4, "sha1": "a" * 40},
                {"name": "lacked.rom", "crc32": "2", "size": 4, "sha1": "b" * 40},
            ]}))
            (root / "db.json").write_text(json.dumps({"files": {"a" * 40: {}}}))
            targets = catalog_targets(str(root / "prov"), str(root / "db.json"))
        self.assertEqual(targets, {("00000002", 4): {"b" * 40}})

    def test_upstream_blobs_are_recorded_and_replaced(self):
        """The snapshot names the DAT blobs it was read from, so a later
        check can tell whether upstream moved without importing again."""
        entry = {
            "dat": "FBNeo - X",
            "name": "set.zip",
            "set": "set",
            "description": "",
            "members": [{"name": "a", "crc32": "1"}],
        }
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            output = str(Path(directory) / "fbneo.json")
            merge_snapshot(output, "fbneo", {"FBNeo - X": "1.0"}, [entry], {"X.dat": "aaa"})
            with open(output, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["upstream"], {"blobs": {"X.dat": "aaa"}})
            merge_snapshot(output, "fbneo", {"FBNeo - X": "1.0"}, [entry], {"X.dat": "bbb"})
            with open(output, encoding="utf-8") as handle:
                snapshot = json.load(handle)
            self.assertEqual(snapshot["upstream"], {"blobs": {"X.dat": "bbb"}})
            self.assertEqual(len(snapshot["entries"]), 1)
            # An import that names no blobs (a local --pack) keeps the last ones.
            merge_snapshot(output, "fbneo", {"FBNeo - X": "1.0"}, [entry])
            with open(output, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["upstream"], {"blobs": {"X.dat": "bbb"}})

    def test_git_blob_sha_matches_git(self):
        # The values git hash-object gives for the empty blob and for "hi".
        self.assertEqual(git_blob_sha(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
        self.assertEqual(git_blob_sha(b"hi"), "32f95c0d1244a78b2be1bab8de17906fabb2c4a8")

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



class TheMissingReportNamesItsTargets(unittest.TestCase):
    """--missing printed three counters. The archives to go and find were
    only in --json."""

    def test_every_target_is_named(self):
        import contextlib  # noqa: PLC0415
        import io  # noqa: PLC0415

        import romset_recipes  # noqa: PLC0415

        gap = {
            "constructible": [],
            "unreproducible": [{"archive": "neogeo.zip", "md5": "a" * 32},
                               {"archive": "neogeo.zip", "md5": "b" * 32},
                               {"archive": "aes.zip", "md5": "c" * 32}],
            "no_recipe": [{"archive": "scummclassic.zip", "md5": "d" * 32}],
        }
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            romset_recipes.print_missing(gap)
        text = out.getvalue()
        self.assertIn("NOT REPRODUCIBLE: neogeo.zip (2 pinned: aaaaaaaa, bbbbbbbb)", text)
        self.assertIn("NOT REPRODUCIBLE: aes.zip (1 pinned: cccccccc)", text)
        self.assertIn("NO RECIPE: scummclassic.zip md5=dddddddd", text)
        self.assertLess(text.index("neogeo.zip"), text.index("aes.zip"))


class IdentificationReadsTheDirectoryFirst(unittest.TestCase):
    """identify_archive built every recipe at DEFLATE level 9 before
    comparing bytes: 94 s and 1 GB at pipeline step 1c, mostly for recipes
    whose members could never match."""

    def test_a_recipe_with_other_members_is_never_built(self):
        from torrentzip import build_torrentzip  # noqa: PLC0415

        import romset_recipes  # noqa: PLC0415

        rom = b"rom bytes"
        crc = format(zlib.crc32(rom), "08x")
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            archive = Path(tmp) / "set.zip"
            archive.write_bytes(build_torrentzip([("a.rom", rom)]))

            class Pool:
                built: list = []

                def build(self, recipe):
                    self.built.append(recipe)
                    return build_torrentzip([(name, rom) for name, _crc in recipe])

                def digest(self, recipe):
                    import hashlib  # noqa: PLC0415

                    blob = self.build(recipe)
                    return hashlib.md5(blob).hexdigest(), len(blob)

            pool = Pool()
            label = romset_recipes.identify_archive(
                archive, {"other": [("b.rom", crc)], "match": [("a.rom", crc)]}, pool)
        self.assertEqual(label, "match")
        self.assertEqual(pool.built, [[("a.rom", crc)]])


class BuildDigestsOutliveTheRun(unittest.TestCase):
    """Step 1c rebuilt every recipe at DEFLATE 9 on each pipeline run (70 s)
    for bytes that depend only on the members."""

    def test_a_second_pool_reads_the_digest_without_building(self):
        import hashlib

        from unittest import mock

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            bios = Path(tmp) / "bios"
            bios.mkdir()
            with zipfile.ZipFile(bios / "source.zip", "w") as archive:
                archive.writestr("a.rom", ROM_A)
            cache = Path(tmp) / "digests.json"
            recipe = [("a.rom", _crc(ROM_A))]
            first = AtomPool(bios, cache)
            digest = first.digest(recipe)
            blob = first.build(recipe)
            self.assertEqual(digest, (hashlib.md5(blob).hexdigest(), len(blob)))
            first.save_digests()
            second = AtomPool(bios, cache)
            with mock.patch.object(second, "build", side_effect=AssertionError("rebuilt")):
                self.assertEqual(second.digest(recipe), digest)
            self.assertIsNone(second.digest([("x.rom", "deadbeef")]))

class WriteRunsTheReportItWrites(unittest.TestCase):
    """--identify --write ran the identification only: the reconstructions
    --write saves come from the missing-pins report, which did not run."""

    def test_write_implies_missing(self):
        import argparse  # noqa: PLC0415

        import romset_recipes  # noqa: PLC0415

        args = argparse.Namespace(identify=True, missing=False, write=True)
        romset_recipes._resolve_modes(args)
        self.assertEqual((args.identify, args.missing), (True, True))
        default = argparse.Namespace(identify=False, missing=False, write=False)
        romset_recipes._resolve_modes(default)
        self.assertEqual((default.identify, default.missing), (True, True))
        alone = argparse.Namespace(identify=True, missing=False, write=False)
        romset_recipes._resolve_modes(alone)
        self.assertEqual((alone.identify, alone.missing), (True, False))



class AnOversizedDatIsNamed(unittest.TestCase):
    """The romset importer skipped a DAT over its size cap without a word,
    and the run ended on "Unchanged" with a version missing."""

    def test_the_skip_is_reported(self):
        import contextlib
        import io
        import zipfile
        from unittest import mock

        from scripts.scraper import romset_dat_importer as importer

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            pack = Path(directory) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as archive:
                archive.writestr("big.dat", b"x" * 64)
            err = io.StringIO()
            with mock.patch.object(importer, "MAX_MEMBER_SIZE", 16), \
                    contextlib.redirect_stderr(err):
                self.assertEqual(list(importer._iter_dat_contents(pack)), [])
            self.assertIn("Skipping big.dat", err.getvalue())



FBNEO_DAT = (
    b'<?xml version="1.0"?>\n<datafile><header><name>FinalBurn Neo - Demo</name>'
    b"<version>1.0.0.03</version></header>"
    b'<game name="demobios"><description>Demo BIOS</description>'
    b'<rom name="a.bin" size="17" crc="' + _crc(ROM_A).encode() + b'"/></game>'
    b"</datafile>\n"
)


class FbneoFetchReadsOneRevision(unittest.TestCase):
    """The FBNeo import listed blobs at the tip but downloaded branch URLs a
    CDN caches, and --fetch <revision> read the tip whatever was named."""

    def setUp(self):
        from scripts.scraper import romset_dat_importer as importer

        self.importer = importer
        self._tmp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.dir = Path(self._tmp.name)
        self.calls: list[str] = []
        self.served = FBNEO_DAT

    def tearDown(self):
        self._tmp.cleanup()

    def _api(self, url: str) -> object:
        self.calls.append(url)
        if "/commits/" in url:
            return {"sha": "c0ffee"}
        return [{
            "type": "file", "name": "Demo.dat",
            "sha": self.importer.git_blob_sha(FBNEO_DAT),
            "download_url": "https://raw.githubusercontent.com/libretro/FBNeo/c0ffee/dats/Demo.dat",
        }]

    def _download(self, url: str, destination: Path) -> Path:
        destination.write_bytes(self.served)
        return destination

    def _patched(self):
        from unittest import mock

        return mock.patch.multiple(
            self.importer, _api_json=self._api, _download=self._download
        )

    def test_bytes_that_are_not_the_listed_blob_are_refused(self):
        self.served = FBNEO_DAT.replace(b"1.0.0.03", b"1.0.0.02")
        with self._patched(), self.assertRaises(self.importer.BlobMismatchError):
            self.importer.fetch_pack("fbneo", "latest", self.dir)
        self.assertFalse((self.dir / "fbneo-dats" / "Demo.dat").exists())

    def test_the_named_revision_is_the_one_listed(self):
        with self._patched():
            target, blobs = self.importer.fetch_pack("fbneo", "v1.0.0.02", self.dir)
        self.assertEqual(
            self.calls,
            [f"{self.importer.FBNEO_API}/commits/v1.0.0.02",
             f"{self.importer.FBNEO_API}/contents/dats?ref=c0ffee"],
        )
        self.assertEqual(list(blobs), ["Demo.dat"])

    def test_a_revision_import_is_labelled_and_leaves_the_tip_blobs(self):
        import contextlib
        import io
        from unittest import mock

        output = self.dir / "fbneo.json"
        output.write_text(json.dumps({"upstream": {"blobs": {"Demo.dat": "tip"}}}))
        argv = ["romset_dat_importer", "--source", "fbneo", "--fetch", "v1.0.0.02",
                "--all", "--cache-dir", str(self.dir), "--output", str(output)]
        with self._patched(), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.importer.main(), 0)
        snapshot = json.loads(output.read_text())
        self.assertEqual(snapshot["upstream"]["blobs"], {"Demo.dat": "tip"})
        self.assertEqual(
            [entry["dat"] for entry in snapshot["entries"]],
            ["FinalBurn Neo - Demo @ v1.0.0.02"],
        )


class LooseRomsAreAtoms(unittest.TestCase):
    """AtomPool read only ZIP members: nmk004.zip stayed unidentified while
    its one ROM sat loose in bios/Arcade/FBNeo/nmk004.bin."""

    def test_a_loose_file_completes_a_recipe(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            bios = Path(directory) / "bios"
            bios.mkdir()
            loose = bios / "nmk004.bin"
            loose.write_bytes(ROM_A)
            db = {"files": {"x": {"path": str(loose), "crc32": _crc(ROM_A)}}}
            self.assertNotIn(_crc(ROM_A), AtomPool(bios))
            pool = AtomPool(bios, None, db)
            self.assertIn(_crc(ROM_A), pool)
            self.assertEqual(pool.read(_crc(ROM_A)), ROM_A)
            self.assertIsNotNone(pool.build([("nmk004.bin", _crc(ROM_A))]))


if __name__ == "__main__":
    unittest.main()
