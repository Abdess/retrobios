"""The wanted page's list: what the collection lacks, by hash, and where
each file goes.

A visitor drops a file on wanted/ and the page says whether the collection
wants it. The list is built from the gaps page's own report, so a file the
collection holds must never be on it, and its folder must be the one the
review of the pull request asks for (validate_pr.placement): a page that
sent a file elsewhere would have its upload flagged by the same project.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitewanted  # noqa: E402
import validate_pr  # noqa: E402
from common import load_database  # noqa: E402

WEBSITE = REPO_ROOT / "website"
WANTED_TS = WEBSITE / "src" / "scripts" / "wanted.ts"
PUBLISHED = WEBSITE / "public" / sitewanted.DATA_FILE

HELD = b"held rom"
WANTED = b"wanted rom"
VARIANT = b"another revision"
MEMBER = b"rom inside an archive"
CRC_ONLY = b"crc only rom"
CUT = b"cut md5 rom"
RECALBOX = [b"revision one", b"revision two"]


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def crc(data: bytes) -> str:
    return f"{zlib.crc32(data):08x}"


class _World(unittest.TestCase):
    """One held file of system x in bios/Maker/Console/, a profile and a
    platform that ask for files around it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self._cwd)
        self.addCleanup(self._tmp.cleanup)
        self.db = {
            "files": {sha1(HELD): {"path": "bios/Maker/Console/a.bin", "name": "a.bin",
                                   "size": len(HELD), "sha1": sha1(HELD), "md5": md5(HELD),
                                   "crc32": crc(HELD)},
                      sha1(b"named"): {"path": "bios/Maker/Console/v.bin", "name": "v.bin",
                                       "size": 5, "sha1": sha1(b"named"), "md5": md5(b"named"),
                                       "crc32": crc(b"named")}},
            "indexes": {"by_md5": {md5(HELD): sha1(HELD), md5(b"named"): sha1(b"named")},
                        "by_sha256": {}, "by_name": {"v.bin": [sha1(b"named")],
                                                     "a.bin": [sha1(HELD)]}},
        }
        (self.tmp / "bios" / "Maker" / "Console").mkdir(parents=True)
        (self.tmp / "bios" / "Maker" / "Console" / "a.bin").write_bytes(HELD)
        (self.tmp / "bios" / "Maker" / "Console" / "v.bin").write_bytes(b"named")
        emulators = self.tmp / "emulators"
        emulators.mkdir()
        (emulators / "engine.yml").write_text(
            "emulator: Engine\ntype: standalone\nsystems: [x]\nfiles:\n"
            f"  - name: a.bin\n    system: x\n    sha1: \"{sha1(HELD)}\"\n"
            f"  - name: b.bin\n    system: x\n    sha1: \"{sha1(WANTED)}\"\n    required: true\n"
            f"  - name: m.bin\n    system: x\n    sha1: \"{sha1(MEMBER)}\"\n"
            f"  - name: c.bin\n    system: x\n    crc32: \"{crc(CRC_ONLY)}\"\n    size: {len(CRC_ONLY)}\n"
            "  - name: nohash.bin\n    system: x\n"
            "  - name: later.bin\n    system: x\n    unsourceable: not dumped yet\n"
            f"    md5: \"{md5(b'later')}\"\n"
        )
        self.profiles = {"engine": {
            "emulator": "Engine", "type": "standalone", "systems": ["x"],
            "files": [
                {"name": "a.bin", "system": "x", "sha1": sha1(HELD)},
                {"name": "b.bin", "system": "x", "sha1": sha1(WANTED), "required": True},
                {"name": "m.bin", "system": "x", "sha1": sha1(MEMBER)},
                {"name": "c.bin", "system": "x", "crc32": crc(CRC_ONLY), "size": len(CRC_ONLY)},
                {"name": "nohash.bin", "system": "x"},
                {"name": "later.bin", "system": "x", "unsourceable": "not dumped yet",
                 "md5": md5(b"later")},
            ],
        }}
        self.gap_report = {"engine": {
            "emulator": "Engine", "systems": ["x"],
            "gap_details": [
                {"name": name, "source": "missing", "identity": "", "required": name == "b.bin"}
                for name in ("a.bin", "b.bin", "m.bin", "c.bin", "nohash.bin")
            ] + [{"name": "pkg.bin", "source": "missing", "bundled": True, "identity": ""}],
            "unsourceable": [{"name": "later.bin", "required": False, "reason": "not dumped yet"}],
        }}
        platform = {
            "x": {"files": [
                {"name": "v.bin", "md5": md5(VARIANT)},
                {"name": "cut.bin", "md5": md5(CUT)[:29]},
                {"name": "z.zip", "md5": md5(b"inner rom"), "zipped_file": "inner.rom"},
                {"name": "r.bin", "md5": ",".join(md5(r) for r in RECALBOX)},
            ]},
        }
        self.coverages = {"plat": {
            "platform": "Plat", "config": {"systems": platform},
            "details": [
                {"name": "v.bin", "status": "untested", "system": "x", "required": True},
                {"name": "cut.bin", "status": "missing", "system": "x", "required": False},
                {"name": "z.zip", "status": "missing", "system": "x", "required": True},
                {"name": "r.bin", "status": "missing", "system": "x", "required": True},
                {"name": "a.bin", "status": "ok", "system": "x"},
            ],
        }}
        self.ledger = [{"path": "bios/Maker/Console/set.zip", "members": [
            {"name": "m.bin", "size": len(MEMBER), "crc32": crc(MEMBER), "sha1": sha1(MEMBER)},
        ]}]
        self.platform_hashes = {"sha1": set(), "md5": set(), "names": set(), "folders": {},
                                "named": {}}
        self.profile_hashes = validate_pr.load_profile_hashes(str(emulators), self.db)
        self.placer = sitewanted.Placer(self.db, self.platform_hashes, self.profile_hashes)
        self.data = sitewanted.build_wanted(
            self.profiles, self.coverages, self.gap_report, self.db, self.placer,
            lambda system: f"System {system.upper()}", self.ledger,
        )

    def entry(self, name: str) -> dict:
        found = [e for e in self.data["entries"] if e["n"] == name]
        self.assertEqual(len(found), 1, name)
        return found[0]


class TheListHoldsWhatTheGapsReportLacks(_World):
    def test_names(self):
        names = sorted(e["n"] for e in self.data["entries"])
        # a.bin is held, m.bin is held inside set.zip, nohash.bin and z.zip
        # (a zipped_file md5 names a ROM inside the archive) declare nothing
        # a dropped file can be compared with, pkg.bin comes with its
        # emulator: none is wanted. r.bin is one entry per revision.
        self.assertEqual(names, ["b.bin", "c.bin", "cut.bin", "later.bin", "r.bin", "r.bin", "v.bin"])

    def test_an_entry_carries_its_readers_system_and_need(self):
        entry = self.entry("b.bin")
        self.assertEqual(entry["h"], {"sha1": [sha1(WANTED)]})
        self.assertEqual(entry["s"], "System X")
        self.assertEqual(entry["r"], 1)
        self.assertEqual([self.data["readers"][i] for i in entry["w"]], [["e", "engine", "Engine"]])
        self.assertEqual([self.data["readers"][i] for i in self.entry("v.bin")["w"]],
                         [["p", "plat", "Plat"]])

    def test_hashes_as_the_resolver_reads_them(self):
        self.assertEqual(self.entry("c.bin")["h"], {"crc32": [crc(CRC_ONLY)]})
        self.assertEqual(self.entry("c.bin")["z"], [len(CRC_ONLY)])
        self.assertEqual(self.entry("cut.bin")["h"], {"md5": [md5(CUT)[:29]]})
        revisions = sorted(e["h"]["md5"][0] for e in self.data["entries"] if e["n"] == "r.bin")
        self.assertEqual(revisions, sorted(md5(r) for r in RECALBOX))

    def test_a_cut_md5_another_wanted_md5_starts_is_that_md5(self):
        records = [{"hashes": {"md5": [md5(CUT)[:29]]}}, {"hashes": {"md5": [md5(CUT)]}}]
        sitewanted._settle_cut(records)
        self.assertEqual(records[0]["hashes"], {"md5": [md5(CUT)]})
        both = [{"hashes": {"md5": ["ab" * 14 + "a"]}},
                {"hashes": {"md5": ["ab" * 14 + "a" + "000"]}},
                {"hashes": {"md5": ["ab" * 14 + "a" + "111"]}}]
        sitewanted._settle_cut(both)
        self.assertEqual(both[0]["hashes"], {})

    def test_a_cut_md5_a_held_md5_starts_is_held(self):
        held = sitewanted.Held(self.db)
        self.assertTrue(held.holds({"md5": [md5(HELD)[:29]]}, []))
        self.assertFalse(held.holds({"md5": [md5(CUT)[:29]]}, []))

    def test_a_crc32_counts_at_its_declared_size(self):
        held = sitewanted.Held(self.db)
        self.assertTrue(held.holds({"crc32": [crc(HELD)]}, [len(HELD)]))
        self.assertTrue(held.holds({"crc32": [crc(HELD)]}, []))
        self.assertFalse(held.holds({"crc32": [crc(HELD)]}, [len(HELD) + 1]))


class EveryFolderIsTheReviewsFolder(_World):
    """The folder and name of each entry, against what validate_pr says for
    the same bytes dropped outside bios/: the destination --place copies to."""

    def test_the_review_places_each_file_where_the_page_sends_it(self):
        platform_hashes = {**self.platform_hashes, "md5": {md5(VARIANT)}, "names": {"v.bin"}}
        for data, name in ((WANTED, "b.bin"), (VARIANT, "v.bin")):
            with self.subTest(name=name):
                path = self.tmp / "card" / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(data)
                result = validate_pr.validate_file(
                    f"card/{name}", self.db, platform_hashes, self.profile_hashes)
                entry = self.entry(name)
                folder = self.data["folders"][entry["f"]]
                expected = (f"{folder}.variants/{entry['t']}.{sha1(data)[:8]}" if entry.get("v")
                            else folder + entry["t"])
                self.assertEqual(result.destination, expected)
        self.assertEqual(self.data["folders"][self.entry("b.bin")["f"]], "bios/Maker/Console/")
        self.assertEqual(self.entry("v.bin").get("v"), 1)

    def test_each_entry_is_placed_by_validate_pr(self):
        for entry in self.data["entries"]:
            values = [v for algo in ("sha1", "md5", "sha256") for v in entry["h"].get(algo, [])
                      if len(v) == sitewanted.FULL_LENGTH[algo]]
            spot = validate_pr.placement(values, entry["n"], self.db, self.platform_hashes,
                                         self.profile_hashes, declared=True,
                                         exists=self.placer.paths.__contains__)
            with self.subTest(entry=entry["n"]):
                self.assertEqual(self.data["folders"][entry["f"]] if "f" in entry else "",
                                 spot.folder)
                self.assertEqual(entry.get("t", ""), spot.name)
                self.assertEqual(bool(entry.get("v")), spot.variant)

    def test_the_gaps_page_upload_link_reads_the_same_rule(self):
        source = (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")
        self.assertIn("folder = placer.folder(declared[0]) if placer and declared else \"\"", source)
        self.assertNotIn("def _upload_folder", source)
        self.assertEqual(self.placer.folder(self.profiles["engine"]["files"][1]),
                         "bios/Maker/Console/")
        self.assertEqual(sitewanted.upload_href(sitewanted.UPLOAD_ROOT, "bios/Maker/Sub Dir/"),
                         "https://github.com/Abdess/retrobios/upload/main/bios/Maker/Sub%20Dir")
        self.assertEqual(sitewanted.upload_href(sitewanted.UPLOAD_ROOT, ""),
                         generate_site.UPLOAD_URL)


def _node(script: str) -> str:
    node = shutil.which("node")
    if not node:
        raise unittest.SkipTest("node is missing")
    return subprocess.run([node, "--input-type=module-typescript", "-e", script],
                          capture_output=True, text=True, check=True, cwd=WEBSITE).stdout


class ThePageReadsTheListAsTheResolverDoes(_World):
    """wanted.ts against the list built above: a dropped file matches by
    every hash its entry declares, and its upload goes where the review
    places it."""

    def _page(self, data: bytes, own_name: str) -> dict:
        hashes = {"sha1": sha1(data), "md5": md5(data), "crc32": crc(data),
                  "sha256": hashlib.sha256(data).hexdigest()}
        return json.loads(_node(
            f"import {{ matches, target, uploadUrl, issueUrl }} from {json.dumps(WANTED_TS.as_uri())};"
            f"const data = {json.dumps(self.data)}; const file = {json.dumps(hashes)};"
            f"const found = matches(data, file, {len(data)});"
            f"const place = found.length ? target(data, found[0], file, {json.dumps(own_name)}) : null;"
            "console.log(JSON.stringify({names: found.map((e) => e.n), place,"
            " upload: place && uploadUrl(data, place.folder),"
            f" issue: found.length && issueUrl(data, found[0].n, file, {len(data)})}}));"
        ))

    def test_matches(self):
        self.assertEqual(self._page(WANTED, "x.bin")["names"], ["b.bin"])
        self.assertEqual(self._page(CRC_ONLY, "x.bin")["names"], ["c.bin"])
        self.assertEqual(self._page(CUT, "x.bin")["names"], ["cut.bin"])
        self.assertEqual(self._page(RECALBOX[1], "x.bin")["names"], ["r.bin"])
        self.assertEqual(self._page(HELD, "a.bin")["names"], [])
        self.assertEqual(self._page(b"unknown", "u.bin")["names"], [])

    def test_a_crc32_at_another_size_is_not_the_file(self):
        entry = {"n": "c.bin", "h": {"crc32": [crc(CRC_ONLY)]}, "w": [], "z": [len(CRC_ONLY) + 1]}
        out = _node(
            f"import {{ satisfies }} from {json.dumps(WANTED_TS.as_uri())};"
            f"console.log(JSON.stringify(satisfies({json.dumps(entry)}, "
            f"{{sha1: '', md5: '', sha256: '', crc32: {json.dumps(crc(CRC_ONLY))}}}, {len(CRC_ONLY)})));"
        )
        self.assertFalse(json.loads(out))

    def test_the_upload_goes_where_the_review_places_it(self):
        page = self._page(WANTED, "dump.rom")
        self.assertEqual(page["place"], {"folder": "bios/Maker/Console/", "name": "b.bin"})
        self.assertEqual(page["upload"],
                         "https://github.com/Abdess/retrobios/upload/main/bios/Maker/Console")
        variant = self._page(VARIANT, "v.bin")["place"]
        self.assertEqual(variant, {"folder": "bios/Maker/Console/.variants/",
                                   "name": f"v.bin.{sha1(VARIANT)[:8]}"})

    def test_the_issue_form_is_filled_as_the_review_fills_it(self):
        result = validate_pr.ValidationResult("b.bin")
        result.sha1, result.md5, result.size = sha1(WANTED), md5(WANTED), len(WANTED)
        self.assertEqual(self._page(WANTED, "b.bin")["issue"], validate_pr.large_file_issue_url(result))


class TheTwoPagesLinkEachOther(unittest.TestCase):
    """files/ checks any file, wanted/ the ones the collection lacks: each
    sends a reader to the other in one line."""

    def test_links(self):
        self.assertIn("[See if it is wanted](../wanted.md)", generate_site.generate_files_page())
        self.assertIn("[Find or check a file](files/index.md)", sitewanted.page(1))


class ThePublishedList(unittest.TestCase):
    """The list generate_site.py wrote, against the collection: nothing it
    holds, every folder by validate_pr, and light enough for a phone."""

    @classmethod
    def setUpClass(cls) -> None:
        if not PUBLISHED.is_file():
            raise unittest.SkipTest("no generated site data")
        cls.data = json.loads(PUBLISHED.read_text(encoding="utf-8"))
        cls.db = load_database(str(REPO_ROOT / "database.json"))

    def test_nothing_held_is_wanted(self):
        held = sitewanted.Held(self.db, sitewanted.load_ledger(REPO_ROOT / "recipes" / "archives.json"))
        for entry in self.data["entries"]:
            with self.subTest(entry=entry["n"]):
                self.assertFalse(held.holds(entry["h"], entry.get("z", [])))

    def test_every_folder_is_the_reviews(self):
        placer = sitewanted.Placer(
            self.db, validate_pr.load_platform_hashes(str(REPO_ROOT / "platforms"), self.db),
            validate_pr.load_profile_hashes(str(REPO_ROOT / "emulators"), self.db))
        for entry in self.data["entries"]:
            spot = placer.place(entry["h"], entry["n"])
            with self.subTest(entry=entry["n"]):
                self.assertEqual(self.data["folders"][entry["f"]] if "f" in entry else "", spot.folder)
                self.assertEqual(entry.get("t", ""), spot.name)

    def test_weight(self):
        self.assertLess(PUBLISHED.stat().st_size, 200_000)


if __name__ == "__main__":
    unittest.main()
