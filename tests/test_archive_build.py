"""Every archive has a recipe, every member is held, and the build reproduces it.

The collection must regenerate each archive it serves from the ROMs it holds
plus recipes/archives.json, without a copy of that archive from elsewhere.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts"))

import archive_build  # noqa: E402
from torrentzip import build_torrentzip  # noqa: E402

ROM_A = b"first rom payload" * 50
ROM_B = b"second rom payload" * 40
ROM_C = b"third rom, held only inside its own archive" * 30


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


class TheLedgerCoversTheCollection(unittest.TestCase):
    """Read from the committed files: database.json and recipes/archives.json."""

    @classmethod
    def setUpClass(cls):
        with (ROOT / "database.json").open(encoding="utf-8") as handle:
            cls.db = json.load(handle)
        cls.ledger = archive_build.load_ledger()
        cls.archives = archive_build.database_archives(cls.db)

    def test_every_database_archive_has_a_recipe(self):
        absent = sorted(set(self.archives) - set(self.ledger))
        self.assertEqual(
            absent, [],
            f"{len(absent)} archives without a recipe; run "
            "`python scripts/romset_recipes.py --capture`",
        )

    def test_no_recipe_outlives_its_archive(self):
        self.assertEqual(sorted(set(self.ledger) - set(self.archives)), [])

    def test_each_recipe_names_the_container_the_database_holds(self):
        wrong = [
            path for path, record in self.ledger.items()
            if path in self.archives and any(
                record[key] != self.archives[path][key] for key in ("sha1", "md5", "size")
            )
        ]
        self.assertEqual(wrong, [], "recaptured archives keep a stale recipe")

    def test_each_recipe_is_complete(self):
        for path, record in self.ledger.items():
            self.assertIn(record["rebuild"], ("exact", "canonical"), path)
            self.assertEqual(record["sources"][-1], "collection", path)
            self.assertTrue(record["members"], path)
            for member in record["members"]:
                self.assertEqual(set(member), {"name", "size", "crc32", "sha1"}, path)
            if record.get("bytes_pinned"):
                self.assertTrue(record["pins"], path)

    def test_every_member_is_held_in_the_collection(self):
        """The list printed here is the acquisition list: a member neither held
        as a loose file nor inside any archive the database lists."""
        missing = archive_build.missing_members(self.ledger, self.db)
        listing = "\n".join(
            f"  {m['archive']}: {m['member']} ({m['sha1']})" for m in missing
        )
        self.assertEqual(missing, [], f"members held nowhere:\n{listing}")

    def test_the_file_is_written_the_one_way(self):
        text = archive_build.ARCHIVES_FILE.read_text(encoding="utf-8")
        self.assertEqual(text, archive_build.ledger_text(self.ledger))

    def test_recipes_describe_the_archives_on_disk(self):
        """Names in order, sizes and crc32 against each central directory."""
        checked = 0
        for path, record in sorted(self.ledger.items()):
            archive = ROOT / path
            if not archive.is_file():
                continue  # a release asset not restored in this checkout
            with zipfile.ZipFile(archive) as handle:
                held = [
                    (info.filename, info.file_size, f"{info.CRC:08x}")
                    for info in handle.infolist() if not info.is_dir()
                ]
            recorded = [(m["name"], m["size"], m["crc32"]) for m in record["members"]]
            self.assertEqual(held, recorded, path)
            checked += 1
        if not checked:
            self.skipTest("bios/ is not present")


class Fixture(unittest.TestCase):
    """A small collection: a loose ROM, a TorrentZip set, a plain ZIP."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.root = Path(self.temp.name)
        bios = self.root / "bios"
        bios.mkdir()
        (bios / "a.rom").write_bytes(ROM_A)
        self.exact_path = bios / "set.zip"
        self.exact_path.write_bytes(
            build_torrentzip([("a.rom", ROM_A), ("b.rom", ROM_B), ("c.rom", ROM_C)])
        )
        self.other_path = bios / "other.zip"
        with zipfile.ZipFile(self.other_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("dir/", b"")
            archive.writestr("second.rom", ROM_B)
            archive.writestr("first.rom", ROM_A)
        self.db = {"files": {}}
        for path in (bios / "a.rom", self.exact_path, self.other_path):
            data = path.read_bytes()
            self.db["files"][_sha1(data)] = {
                "path": path.relative_to(self.root).as_posix(),
                "name": path.name,
                "sha1": _sha1(data),
                "md5": hashlib.md5(data).hexdigest(),
                "size": len(data),
            }

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, **kwargs) -> dict[str, dict]:
        records, failed = archive_build.capture(
            self.db, kwargs.get("previous", {}), kwargs.get("index", {}),
            kwargs.get("pins", {}), workers=1, log=lambda _line: None,
        )
        self.assertEqual(failed, {})
        return records


class Capture(Fixture):
    def setUp(self):
        super().setUp()
        self._cwd = Path.cwd()
        import os

        os.chdir(self.root)

    def tearDown(self):
        import os

        os.chdir(self._cwd)
        super().tearDown()

    def test_a_torrentzip_archive_is_exact_and_another_canonical(self):
        records = self.capture()
        exact, other = records["bios/set.zip"], records["bios/other.zip"]
        self.assertEqual(exact["rebuild"], "exact")
        self.assertEqual(other["rebuild"], "canonical")
        self.assertEqual(
            [m["name"] for m in other["members"]], ["second.rom", "first.rom"],
            "members keep the archive's own order",
        )
        self.assertEqual(other["directories"], ["dir/"])
        self.assertEqual(other["members"][0]["sha1"], _sha1(ROM_B))
        self.assertEqual(exact["sources"], ["collection"])

    def test_dat_agreement_and_pins_are_recorded(self):
        key = archive_build.member_key(
            [{"name": n, "crc32": c} for n, c in (
                ("a.rom", self._crc(ROM_A)), ("b.rom", self._crc(ROM_B)),
                ("c.rom", self._crc(ROM_C)),
            )]
        )
        md5 = hashlib.md5(self.exact_path.read_bytes()).hexdigest()
        records = self.capture(
            index={key: {"mame:MAME mame0289"}}, pins={md5: {"platform:demo"}}
        )
        record = records["bios/set.zip"]
        self.assertEqual(record["sources"], ["mame:MAME mame0289", "collection"])
        self.assertEqual((record["bytes_pinned"], record["pins"]), (True, ["platform:demo"]))
        self.assertNotIn("bytes_pinned", records["bios/other.zip"])

    def test_an_unchanged_archive_is_not_read_again(self):
        previous = self.capture()
        previous["bios/set.zip"]["members"][0]["sha1"] = "kept"
        records = self.capture(previous=previous)
        self.assertEqual(records["bios/set.zip"]["members"][0]["sha1"], "kept")

    def test_zlib_ng_refuses_to_capture(self):
        with mock.patch.object(archive_build, "zlib_ng_version", lambda: "2.2.4"):
            with self.assertRaises(archive_build.ZlibNgError):
                self.capture()

    def test_composite_and_zipped_pins_name_no_container(self):
        platforms = self.root / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            "platforms:\n"
            "  plain:\n    config: plain.yml\n"
            "  composite:\n    config: composite.yml\n    zip_digest: composite\n",
            encoding="utf-8",
        )
        entry = "      - name: set.zip\n        destination: set.zip\n"
        (platforms / "plain.yml").write_text(
            "platform: Plain\nsystems:\n  arcade:\n    files:\n"
            f"{entry}        md5: {'a' * 32}\n"
            f"{entry}        md5: {'b' * 32}\n        zipped_file: a.rom\n",
            encoding="utf-8",
        )
        (platforms / "composite.yml").write_text(
            "platform: Composite\nsystems:\n  arcade:\n    files:\n"
            f"{entry}        md5: {'c' * 32}\n",
            encoding="utf-8",
        )
        emulators = self.root / "emulators"
        emulators.mkdir()
        (emulators / "core.yml").write_text(
            "emulator: Core\ntype: libretro\nfiles:\n"
            f"  - name: set.zip\n    sha1: {'d' * 40}\n",
            encoding="utf-8",
        )
        pins = archive_build.container_pins(str(platforms), str(emulators))
        self.assertEqual(pins, {"a" * 32: {"platform:plain"}, "d" * 40: {"profile:core"}})

    @staticmethod
    def _crc(data: bytes) -> str:
        import zlib

        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


class Build(Fixture):
    def setUp(self):
        super().setUp()
        import os

        self._cwd = Path.cwd()
        os.chdir(self.root)
        self.ledger = self.capture()
        os.chdir(self._cwd)
        self.atoms = archive_build.AtomIndex.from_collection(self.ledger, self.db, self.root)
        self.out = self.root / "out"

    def build(self, path: str):
        return archive_build.build_archive(self.ledger[path], self.atoms, self.out, self.root)

    def test_an_exact_recipe_rebuilds_the_bytes(self):
        result = self.build("bios/set.zip")
        self.assertEqual(result.status, "exact")
        built = self.out / "set.zip"
        self.assertEqual(built.read_bytes(), self.exact_path.read_bytes())
        self.assertEqual(result.own_members, 1, "c.rom is held only in set.zip")

    def test_members_come_from_a_loose_file_then_another_archive(self):
        own = self.root / "bios" / "set.zip"
        self.assertEqual(self.atoms.find(_sha1(ROM_A), own).member, None)
        self.assertEqual(self.atoms.find(_sha1(ROM_B), own).path.name, "other.zip")
        self.assertEqual(self.atoms.find(_sha1(ROM_C), own).path, own)

    def test_a_canonical_recipe_is_checked_by_its_members(self):
        result = self.build("bios/other.zip")
        self.assertEqual(result.status, "canonical")
        with zipfile.ZipFile(self.out / "other.zip") as archive:
            self.assertEqual(sorted(archive.namelist()), ["first.rom", "second.rom"])
            self.assertTrue(archive.comment.startswith(b"TORRENTZIPPED-"))

    def test_a_member_held_nowhere_makes_it_impossible(self):
        record = dict(self.ledger["bios/set.zip"])
        record["members"] = record["members"] + [
            {"name": "gone.rom", "size": 1, "crc32": "00000000", "sha1": "f" * 40}
        ]
        result = archive_build.build_archive(record, self.atoms, self.out, self.root)
        self.assertEqual(result.status, "impossible")
        self.assertEqual([m["name"] for m in result.missing], ["gone.rom"])
        self.assertFalse(self.out.exists())

    def test_a_mismatch_is_never_promoted(self):
        record = dict(self.ledger["bios/set.zip"], sha1="0" * 40)
        result = archive_build.build_archive(record, self.atoms, self.out, self.root)
        self.assertEqual(result.status, "failed")
        self.assertIn("is not the recorded", result.detail)
        self.assertEqual(list(self.out.rglob("*")), [], "no file, no scratch left")

    def test_a_canonical_mismatch_is_never_promoted(self):
        record = dict(self.ledger["bios/other.zip"])
        record["members"] = [dict(m) for m in record["members"]]
        record["members"][0]["crc32"] = "00000000"
        result = archive_build.build_archive(record, self.atoms, self.out, self.root)
        self.assertEqual(result.status, "failed")
        self.assertEqual(list(self.out.rglob("*")), [])

    def test_zlib_ng_never_claims_exact(self):
        with mock.patch.object(archive_build, "zlib_ng_version", lambda: "2.2.4"):
            result = self.build("bios/set.zip")
        self.assertEqual(result.status, "canonical")
        self.assertIn("zlib-ng 2.2.4", result.detail)

    def test_an_archive_is_named_by_path_or_by_name(self):
        self.assertEqual(
            [r["path"] for r in archive_build.select(self.ledger, "set.zip", self.root)],
            ["bios/set.zip"],
        )
        self.assertEqual(
            len(archive_build.select(self.ledger, str(self.exact_path), self.root)), 1
        )
        self.assertEqual(archive_build.select(self.ledger, "none.zip", self.root), [])

    def test_missing_members_reads_the_committed_data(self):
        self.assertEqual(archive_build.missing_members(self.ledger, self.db), [])
        del self.db["files"][_sha1(self.exact_path.read_bytes())]
        missing = archive_build.missing_members(self.ledger, self.db)
        self.assertEqual(
            [(m["archive"], m["member"]) for m in missing], [("bios/set.zip", "c.rom")]
        )

    def test_the_command_reports_each_archive(self):
        archives = self.root / "archives.json"
        archives.write_text(archive_build.ledger_text(self.ledger), encoding="utf-8")
        db = self.root / "database.json"
        db.write_text(json.dumps(self.db), encoding="utf-8")
        run = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "romset_recipes.py"),
                "--build-all", "--output-dir", str(self.out), "--discard",
                "--bios-dir", str(self.root / "bios"), "--db", str(db),
                "--archives", str(archives),
            ],
            capture_output=True, text=True, check=False, timeout=120,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("EXACT: bios/set.zip", run.stdout)
        self.assertIn("CANONICAL: bios/other.zip", run.stdout)
        self.assertIn("2 archives: 1 rebuilt exact, 1 canonical, 0 impossible", run.stdout)
        self.assertEqual(list(self.out.rglob("*.zip")), [], "--discard keeps nothing")


if __name__ == "__main__":
    unittest.main()
