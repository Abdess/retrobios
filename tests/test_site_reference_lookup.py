"""The published lookup and folder check.

A lookup record answers every hash a setup lists and counts emulators like
the card, its URLs resolve, and the folder check gives verify.py's verdicts
and exit code. Tests reading the generated site skip when it has not been
generated.
"""

from __future__ import annotations

import tests

import csv
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock
import hashlib
import os
import shutil
import tempfile
import urllib.parse
import zipfile
import runpy
import urllib.error

from sitegen import cards
from sitegen import datapage
from sitegen import lookup
import check_platform_folder
from tests.sitereferencesupport import API, PUBLIC, REPO_ROOT, SITE, _built


def _verify_status(entry: dict, path: Path, mode: str) -> str:
    """What verify.py says of one entry, the platform's native logic."""
    from packs.verdicts import verify_entry_existence, verify_entry_md5, verify_entry_sha1

    local = str(path) if path.is_file() else None
    if mode == "existence":
        return verify_entry_existence(entry, local)["status"]
    if mode == "sha1":
        return verify_entry_sha1(entry, local)["status"]
    return verify_entry_md5(entry, local)["status"]


def _as_snippet(status: str) -> str:
    return {"ok": "ok", "untested": "wrong", "missing": "missing"}[status]


class AFolderCheckAgreesWithTheVerifier(unittest.TestCase):
    """8.1 and 8.3: the published example gives verify.py's verdicts."""

    def _folder(self, tmp: Path) -> tuple[dict, Path]:
        member = b"basic rom bytes"
        root = tmp / "bios"
        root.mkdir()
        with zipfile.ZipFile(root / "bbcb.zip", "w") as archive:
            archive.writestr("BASIC1.ROM", member)
        (root / "plain.bin").write_bytes(b"plain")
        (root / "wrong.bin").write_bytes(b"not it")
        (root / "nohash.bin").write_bytes(b"x")
        def md5(data: bytes) -> str:
            return hashlib.md5(data).hexdigest()

        contract = {"verification_mode": "md5", "systems": {"s": {"files": [
            {"name": "bbcb.zip", "destination": "bbcb.zip", "md5": md5(member),
             "zipped_file": "basic1.rom"},
            {"name": "bbcb.zip", "destination": "bbcb.zip", "md5": "0" * 32,
             "zipped_file": "basic1.rom"},
            {"name": "plain.bin", "destination": "plain.bin", "md5": md5(b"plain")[:29]},
            {"name": "wrong.bin", "destination": "wrong.bin", "md5": md5(b"plain")},
            {"name": "nohash.bin", "destination": "nohash.bin"},
            {"name": "gone.bin", "destination": "gone.bin", "md5": "1" * 32},
        ]}}}
        return contract, root

    def test_each_rule_on_a_sample_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            contract, root = self._folder(Path(tmp))
            platforms = Path(tmp) / "platforms"
            platforms.mkdir()
            (platforms / "sample.json").write_text(
                json.dumps({"items": [{"contract": contract}]}), encoding="utf-8")
            found = check_platform_folder.check("sample", root, platforms.as_uri() + "/")
            expected = [
                (entry["destination"], _as_snippet(_verify_status(entry, root / entry["destination"], "md5")))
                for entry in contract["systems"]["s"]["files"]
            ]
        self.assertEqual(found, expected)
        # plain.bin declares a cut md5: Batocera compares the whole string.
        self.assertEqual([v for _d, v in found], ["ok", "wrong", "wrong", "wrong", "ok", "missing"])

    def test_batocera_from_the_csv_matches_the_verifier(self):
        """A check driven by platform-files.csv, with zipped_file, gives the
        verifier's verdict on every Batocera entry of a folder filled from
        the collection."""
        text = _built(PUBLIC / "downloads" / "platform-files.csv").read_text(encoding="utf-8")
        rows = [row for row in csv.DictReader(io.StringIO(text)) if row["platform_id"] == "batocera"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for row in rows:
                source = REPO_ROOT / row["collection_path"] if row["collection_path"] else None
                target = root / row["destination"]
                if source and source.is_file() and not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        os.link(source, target)
                    except OSError:
                        shutil.copyfile(source, target)
            held = [row for row in rows if (root / row["destination"]).is_file()]
            if len(held) < 100:
                raise unittest.SkipTest("the collection files are not in this checkout")
            # The verifier reads the platform's own entries, the check the CSV.
            contract = json.loads(_built(API / "platforms" / "batocera.json").read_text())[
                "items"][0]["contract"]
            declared = [entry for _sys, system in sorted(contract["systems"].items())
                        for entry in system.get("files") or []]
            self.assertEqual([e["name"] for e in declared], [row["name"] for row in rows])
            mismatched = []
            zipped_ok = 0
            for row, platform_entry in zip(rows, declared):
                entry = {key: value for key, value in row.items() if value}
                path = root / row["destination"]
                ours = "ok" if check_platform_folder.accepts(entry, path, "md5") else (
                    "wrong" if path.is_file() else "missing")
                theirs = _as_snippet(_verify_status(platform_entry, path, "md5"))
                if ours != theirs:
                    mismatched.append((row["destination"], row.get("zipped_file"), ours, theirs))
                zipped_ok += ours == "ok" and bool(row["zipped_file"])
        self.assertEqual(mismatched, [])
        self.assertGreater(zipped_ok, 100)

    def test_the_data_page_shows_the_script_itself(self):
        script = (REPO_ROOT / "scripts" / "check_platform_folder.py").read_text(encoding="utf-8")
        page = datapage.generate_data_page([])
        self.assertIn("```python\n" + script.rstrip("\n") + "\n```", page)
        self.assertLess(len(script.splitlines()), 70)
        self.assertIn("## Check a folder for one platform", page)


class TheLookupRecipeSaysWhatASha1Misses(unittest.TestCase):
    """The page said a SHA1 lookup was enough, "a setup that lists a file
    by MD5 or CRC32 is filed under the SHA1 of the collection file it names
    too". A record whose value no collection file answers has no SHA1: 702
    platform MD5s were out of the recipe's reach."""

    def test_the_page_and_the_records_agree(self):
        record = {"layer": "platform", "algorithm": "md5", "value": "0" * 32,
                  "name": "dmg_boot.bin", "owner": "recalbox"}
        self.assertEqual(lookup._held_under_every_hash([record], {}), [])
        self.assertNotIn("sha1", record)
        page = " ".join(datapage.generate_data_page([]).split())
        self.assertNotIn("none is needed", page)
        self.assertIn("A list naming a file the collection lacks is filed under its MD5 "
                      "or CRC32 alone", page)


class LookupUrlsResolve(unittest.TestCase):
    """8.7: a record's url, joined to the shard holding it, is a page."""

    def test_site_absolute(self):
        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin"}}}
        [item] = lookup.file_location_items(db)
        self.assertTrue(item["url"].startswith("/retrobios/systems/"), item["url"])
        shard = SITE + "api/v1/lookup/ab.json"
        self.assertTrue(urllib.parse.urljoin(shard, item["url"]).startswith(SITE + "systems/"))

    def test_each_record_names_its_system_as_the_pages_do(self):
        """Find a file opens on "a BIOS file for Sony PlayStation": the name
        comes from system_name, never built in the browser."""
        from sitegen.runsections import system_name

        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin",
                                    "name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}}}
        coverages = {"batocera": {"platform": "Batocera", "config": {"systems": {
            "sony-playstation": {"files": [{"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}}}}
        profiles = {"duckstation": {"systems": ["sony-playstation"], "files": [
            {"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}
        records = lookup.file_lookup_records(
            db, coverages, profiles, lookup.file_location_items(db))
        expected = system_name("sony-playstation")
        by_layer = {r["layer"]: r for r in records if r["algorithm"] == "md5"}
        for layer in ("collection", "platform", "emulator"):
            with self.subTest(layer=layer):
                self.assertEqual(by_layer[layer]["system_name"], expected)

    def test_built_shards_carry_the_name(self):
        shard = json.loads(_built(API / "lookup" / "05.json").read_text())
        record = next(r for r in shard["items"] if r["value"].startswith("0555c6fae890"))
        self.assertEqual(record["system_name"], "Sony PlayStation")

    def test_built_records_land_on_built_pages(self):
        shard = json.loads(_built(API / "lookup" / "05.json").read_text())
        dist = REPO_ROOT / "website" / "dist"
        for record in shard["items"][:200]:
            with self.subTest(url=record["url"]):
                self.assertTrue(record["url"].startswith("/retrobios/"))
                if dist.is_dir():
                    page = urllib.parse.unquote(record["url"].split("#")[0].removeprefix("/retrobios/"))
                    self.assertTrue((dist / page / "index.html").is_file(), page)


class LookupRecordsUnderEveryHash(unittest.TestCase):
    """8.1: a platform listing a file by MD5 is found by its SHA1 too."""

    SHA1 = "a" * 40
    FILE = {"name": "bios.bin", "path": "bios/Sony/PlayStation/bios.bin", "sha1": SHA1,
            "md5": "b" * 32, "crc32": "c" * 8, "sha256": "d" * 64}

    def records(self) -> list[dict]:
        db = {"files": {self.SHA1: self.FILE}, "indexes": {
            "by_md5": {"b" * 32: self.SHA1}, "by_crc32": {"c" * 8: self.SHA1},
            "by_sha256": {"d" * 64: self.SHA1}}}
        coverages = {"setup": {"config": {"systems": {"sony-playstation": {"files": [
            {"name": "bios.bin", "md5": "b" * 32}]}}}}}
        profiles = {"core": {"type": "libretro", "systems": ["sony-playstation"],
                             "files": [{"name": "bios.bin", "crc32": "c" * 8}]}}
        with mock.patch.object(lookup, "_console_system_names", return_value={}), \
                mock.patch.object(lookup, "_lookup_system_name", return_value=None), \
                mock.patch.object(lookup, "emulator_card_page", side_effect=lambda k, a: k), \
                mock.patch.object(cards, "emulator_card_page", side_effect=lambda k, a: k):
            return lookup.file_lookup_records(
                db, coverages, profiles, [{"sha1": self.SHA1, "url": "/x"}])

    def test_each_hash_names_the_setup_and_the_emulator(self):
        records = self.records()
        for value in (self.SHA1, "b" * 32, "c" * 8, "d" * 64):
            owners = {(r["layer"], r.get("owner")) for r in records if r["value"] == value}
            self.assertIn(("platform", "setup"), owners, value)
            self.assertIn(("emulator", "core"), owners, value)

    def test_records_carry_the_sha1_and_say_what_was_declared(self):
        for record in self.records():
            if record["layer"] in ("platform", "emulator"):
                self.assertEqual(record["sha1"], self.SHA1)
        copy = next(r for r in self.records()
                    if r["layer"] == "platform" and r["value"] == self.SHA1)
        self.assertEqual(copy["declared"], "md5")

    def test_scph5501_gives_one_answer_for_its_four_hashes(self):
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        sha1 = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
        entry = db["files"][sha1]
        _built(API / "lookup")
        answers = []
        for algorithm in ("sha1", "md5", "crc32", "sha256"):
            value = str(entry[algorithm]).lower()
            shard = json.loads((API / "lookup" / f"{value[:2]}.json").read_text())
            found = [r for r in shard["items"] if r["value"] == value]
            answers.append(tuple(sorted({(r["layer"], r.get("owner", "")) for r in found})))
        self.assertEqual(len(set(answers)), 1, answers)
        setups = {owner for layer, owner in answers[0] if layer == "platform"}
        emulators = {owner for layer, owner in answers[0] if layer == "emulator"}
        self.assertGreaterEqual(len(setups), 10)
        self.assertGreaterEqual(len(emulators), 8)


class TheFolderCheckReadsEmuDecksWhitelist(unittest.TestCase):
    """8.2: an entry with no destination names no file. EmuDeck's check
    passes the system when any top-level file of the folder has its md5."""

    def check(self, files: dict[str, bytes]) -> list[tuple[str, str]]:
        good = b"ps1 bios bytes"
        contract = {"verification_mode": "md5", "systems": {"sony-playstation": {"files": [
            {"name": f"sony-playstation:{hashlib.md5(good).hexdigest()}", "destination": "",
             "md5": hashlib.md5(good).hexdigest()},
            {"name": "sony-playstation:" + "0" * 32, "destination": "", "md5": "0" * 32},
        ]}}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bios"
            (root / "sub").mkdir(parents=True)
            for name, data in files.items():
                (root / name).write_bytes(data)
            api = Path(tmp) / "api"
            api.mkdir()
            (api / "emudeck.json").write_text(json.dumps({"items": [{"contract": contract}]}))
            found = check_platform_folder.check("emudeck", root, api.as_uri() + "/")
            # The verifier's verdict on the matching entry, file by file.
            from packs.verdicts import verify_entry_md5

            verdicts = {name: verify_entry_md5(contract["systems"]["sony-playstation"]["files"][0],
                                               str(root / name))["status"]
                        for name in files if (root / name).is_file()}
        return found, verdicts

    def test_any_name_passes(self):
        found, verdicts = self.check({"my-ps1-dump.bin": b"ps1 bios bytes"})
        self.assertEqual(found, [("sony-playstation: any file", "ok")])
        self.assertEqual(verdicts, {"my-ps1-dump.bin": "ok"})

    def test_a_folder_without_it_is_missing(self):
        found, _verdicts = self.check({"other.bin": b"x", "sub/deep.bin": b"ps1 bios bytes"})
        self.assertEqual(found, [("sony-playstation: any file", "missing")])

    def test_the_data_page_states_the_rule(self):
        page = datapage.generate_data_page([])
        self.assertIn("An entry with no `destination` (EmuDeck) names no file", page)
        self.assertLess(len((REPO_ROOT / "scripts" / "check_platform_folder.py")
                            .read_text().splitlines()), 70)


class FakeConsumers:
    def __init__(self, sha1: str) -> None:
        self.emulators = {sha1: {"byname"}}
        self.emulator_entries = {sha1: {"byname": 0}}
        self.emulator_files = {"byname": [{"name": "bios.bin"}]}


class LookupCountsEmulatorsLikeTheCard(unittest.TestCase):
    """8.3: an emulator reading the file by name is in the verdict."""

    SHA1 = "a" * 40

    def records(self) -> list[dict]:
        db = {"files": {self.SHA1: {"name": "bios.bin", "path": "bios/Sony/PlayStation/bios.bin",
                                    "sha1": self.SHA1, "md5": "b" * 32}},
              "indexes": {"by_md5": {"b" * 32: self.SHA1}}}
        coverages = {"setup": {"config": {"systems": {"sony-playstation": {"files": [
            {"name": "bios.bin", "md5": "b" * 32}]}}}}}
        with mock.patch.object(lookup, "_console_system_names", return_value={}), \
                mock.patch.object(lookup, "_lookup_system_name", return_value=None), \
                mock.patch.object(lookup, "emulator_card_page", side_effect=lambda k, a: k), \
                mock.patch.object(cards, "emulator_card_page", side_effect=lambda k, a: k):
            return lookup.file_lookup_records(
                db, coverages, {}, [{"sha1": self.SHA1, "url": "/x"}], None,
                FakeConsumers(self.SHA1))

    def test_by_name_under_every_hash(self):
        records = self.records()
        for value in (self.SHA1, "b" * 32):
            named = [r for r in records if r["value"] == value and r.get("owner") == "byname"]
            self.assertEqual(len(named), 1, value)
            self.assertEqual(named[0]["declared"], "name")

    def test_every_setup_and_emulator_record_says_what_was_declared(self):
        for record in self.records():
            if record["layer"] in ("platform", "emulator"):
                self.assertIn("declared", record)
        own = next(r for r in self.records()
                   if r["layer"] == "platform" and r["value"] == "b" * 32)
        self.assertEqual(own["declared"], "md5")

    def test_scph5501_names_the_cards_eleven(self):
        sha1 = "0555c6fae8906f3f09baf5988f00e55f88e9f30b"
        shard = json.loads(_built(API / "lookup" / f"{sha1[:2]}.json").read_text())
        owners = {r["owner"] for r in shard["items"]
                  if r["value"] == sha1 and r["layer"] == "emulator"}
        self.assertGreaterEqual(len(owners), 11)
        self.assertLessEqual({"pcsx_rearmed", "pcsx1"}, owners)


def _respond(routes: dict):
    def urlopen(url: str, *args, **kwargs):
        for suffix, body in routes.items():
            if url.endswith(suffix):
                if body is None:
                    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
                return io.BytesIO(json.dumps(body).encode())
        raise AssertionError(url)
    return urlopen


class TheFolderCheckExitCode(unittest.TestCase):
    """8.5: exit 1 on a file wrong or missing, a word for an unknown platform."""

    SCRIPT = str(REPO_ROOT / "scripts" / "check_platform_folder.py")
    CONTRACT = {"items": [{"contract": {"verification_mode": "existence", "systems": {
        "x": {"files": [{"name": "a.bin", "destination": "a.bin"}]}}}}]}

    def run_script(self, platform: str, folder: Path, routes: dict) -> tuple[object, str]:
        err = io.StringIO()
        with mock.patch("urllib.request.urlopen", _respond(routes)), \
                mock.patch.object(sys, "argv", ["check", platform, str(folder)]), \
                mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", err), \
                self.assertRaises(SystemExit) as raised:
            runpy.run_path(self.SCRIPT, run_name="__main__")
        return raised.exception.code, err.getvalue()

    def test_missing_exits_one_and_complete_exits_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            code, _err = self.run_script("p", Path(folder), {"/p.json": self.CONTRACT})
            self.assertEqual(code, 1)
            (Path(folder) / "a.bin").write_bytes(b"x")
            code, _err = self.run_script("p", Path(folder), {"/p.json": self.CONTRACT})
            self.assertEqual(code, 0)

    def test_an_unknown_platform_names_the_known_ones(self):
        catalog = {"items": [{"url": "manifests/batocera.json"}, {"url": "stats.json"}]}
        with tempfile.TemporaryDirectory() as folder:
            code, _err = self.run_script(
                "nosuch", Path(folder), {"/nosuch.json": None, "/catalog.json": catalog})
        self.assertEqual(code, "unknown platform: nosuch. Known: batocera")

    def test_a_folder_that_is_not_there_is_named(self):
        """A mistyped folder read as every file missing, exit 1."""
        with tempfile.TemporaryDirectory() as folder:
            code, _err = self.run_script("p", Path(folder) / "bois", {"/p.json": self.CONTRACT})
        self.assertIsInstance(code, str)
        self.assertIn("bois", code)
        self.assertIn("No such file or directory", code)

    def test_a_missing_argument_prints_the_usage(self):
        err = io.StringIO()
        with mock.patch.object(sys, "argv", ["check", "batocera"]), \
                mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as raised:
            runpy.run_path(self.SCRIPT, run_name="__main__")
        self.assertTrue(str(raised.exception.code).startswith("Usage: "))

    def test_no_network_is_a_message(self):
        def offline(url: str, *args, **kwargs):
            raise urllib.error.URLError("Name or service not known")
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("urllib.request.urlopen", offline), \
                mock.patch.object(sys, "argv", ["check", "p", folder]), \
                self.assertRaises(SystemExit) as raised:
            runpy.run_path(self.SCRIPT, run_name="__main__")
        self.assertEqual(raised.exception.code, "error: <urlopen error Name or service not known>")

    def test_the_page_shows_the_script(self):
        script = Path(self.SCRIPT).read_text(encoding="utf-8")
        self.assertIn("```python\n" + script.rstrip("\n") + "\n```",
                      datapage.generate_data_page([]))


if __name__ == "__main__":
    unittest.main()
