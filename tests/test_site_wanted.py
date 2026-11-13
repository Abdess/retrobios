"""The wanted page's list: what the collection lacks, by hash, and where
each file goes.

A visitor drops a file on wanted/ and the page says whether the collection
wants it, then lists every wanted file with its own upload button. The list
is built from the gaps page's own report, so a file the collection holds
must never be on it, and its folder must be the one the review of the pull
request asks for (validate_pr.placement): a page that sent a file elsewhere
would have its upload flagged by the same project.
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
import re
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitewanted  # noqa: E402
import validate_pr  # noqa: E402
import yaml  # noqa: E402
from common import load_database  # noqa: E402
from tests.test_site_pronouns import pronouns  # noqa: E402

WEBSITE = REPO_ROOT / "website"
WANTED_TS = WEBSITE / "src" / "scripts" / "wanted.ts"
COMPONENTS = WEBSITE / "src" / "components"
PUBLISHED = WEBSITE / "public" / sitewanted.DATA_FILE

HELD = b"held rom"
WANTED = b"wanted rom"
VARIANT = b"another revision"
MEMBER = b"rom inside an archive"
CRC_ONLY = b"crc only rom"
CUT = b"cut md5 rom"
RECALBOX = [b"revision one", b"revision two"]
GAME = b"game data file"
HOMONYM = b"another machine's nohash.bin"


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
                                       "crc32": crc(b"named")},
                      # A file of the same name held for another machine.
                      sha1(HOMONYM): {"path": "bios/Other/Elsewhere/nohash.bin",
                                      "name": "nohash.bin", "size": len(HOMONYM),
                                      "sha1": sha1(HOMONYM), "md5": md5(HOMONYM),
                                      "crc32": crc(HOMONYM)}},
            "indexes": {"by_md5": {md5(HELD): sha1(HELD), md5(b"named"): sha1(b"named")},
                        "by_sha256": {}, "by_name": {"v.bin": [sha1(b"named")],
                                                     "a.bin": [sha1(HELD)],
                                                     "nohash.bin": [sha1(HOMONYM)]}},
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
            "  - name: nohash.bin\n    system: x\n    description: A boot ROM. Read at start.\n"
            "  - name: later.bin\n    system: x\n    unsourceable: not dumped yet\n"
            f"    md5: \"{md5(b'later')}\"\n"
            f"  - name: g.bin\n    system: x\n    category: game_data\n    required: true\n"
            f"    sha1: \"{sha1(GAME)}\"\n"
            "  - name: own.cfg\n    system: x\n    unsourceable: settings the user writes\n"
        )
        self.profiles = {"engine": {
            "emulator": "Engine", "type": "standalone", "systems": ["x"],
            "files": [
                {"name": "a.bin", "system": "x", "sha1": sha1(HELD)},
                {"name": "b.bin", "system": "x", "sha1": sha1(WANTED), "required": True},
                {"name": "m.bin", "system": "x", "sha1": sha1(MEMBER)},
                {"name": "c.bin", "system": "x", "crc32": crc(CRC_ONLY), "size": len(CRC_ONLY)},
                {"name": "nohash.bin", "system": "x", "description": "A boot ROM. Read at start."},
                {"name": "later.bin", "system": "x", "unsourceable": "not dumped yet",
                 "md5": md5(b"later")},
                {"name": "g.bin", "system": "x", "category": "game_data", "required": True,
                 "sha1": sha1(GAME)},
                {"name": "own.cfg", "system": "x", "unsourceable": "settings the user writes"},
            ],
        }}
        self.gap_report = {"engine": {
            "emulator": "Engine", "systems": ["x"],
            "gap_details": [
                {"name": name, "source": "missing", "identity": "",
                 "required": name in ("b.bin", "g.bin")}
                for name in ("a.bin", "b.bin", "m.bin", "c.bin", "nohash.bin", "g.bin")
            ] + [{"name": "pkg.bin", "source": "missing", "bundled": True, "identity": ""}],
            "unsourceable": [{"name": "later.bin", "required": False, "reason": "not dumped yet"},
                             {"name": "own.cfg", "required": True,
                              "reason": "settings the user writes"}],
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
                {"name": "cut.bin", "status": "missing", "system": "x", "required": False,
                 "category": "unread"},
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
        # a.bin is held, m.bin is held inside set.zip, pkg.bin comes with
        # its emulator, own.cfg is the user's own: none is wanted. r.bin is
        # one entry per revision.
        self.assertEqual(names, ["b.bin", "c.bin", "cut.bin", "g.bin", "later.bin", "nohash.bin",
                                 "r.bin", "r.bin", "v.bin", "z.zip"])

    def test_an_entry_with_no_hash_is_kept_and_marked(self):
        """nohash.bin declares no hash and z.zip only the md5 of a ROM
        inside it: a dropped file cannot be compared with either, but a
        person who has it can still upload it from the list."""
        for name in ("nohash.bin", "z.zip"):
            with self.subTest(name=name):
                self.assertNotIn("h", self.entry(name))
        self.assertIn("h", self.entry("b.bin"))

    # The world's categories: g.bin is game data, cut.bin a file a
    # platform lists and no core reads, the others firmware.
    KIND = {"g.bin": 2, "cut.bin": 1}

    def test_required_entries_come_first(self):
        firmware = [e for e in self.data["entries"] if e["n"] not in self.KIND]
        needs = [bool(e.get("r")) for e in firmware]
        self.assertEqual(needs, sorted(needs, reverse=True))
        self.assertTrue(any(needs) and not all(needs))

    def test_firmware_comes_before_game_data(self):
        kinds = [self.KIND.get(e["n"], 0) for e in self.data["entries"]]
        self.assertEqual(kinds, sorted(kinds))
        # g.bin is required, and still after every optional firmware file.
        self.assertEqual(self.data["entries"][-1]["n"], "g.bin")
        self.assertEqual(self.entry("g.bin").get("r"), 1)

    def test_a_file_nobody_can_share_is_left_out(self):
        """The reason a profile gives decides, read from the profiles
        themselves: emucorev's config.txt and puae's WHDLoad.key leave,
        a ROM no one has dumped yet stays."""
        reasons = {}
        for key, name in (("emucorev", "config.txt"), ("puae", "WHDLoad.key")):
            profile = yaml.safe_load((REPO_ROOT / "emulators" / f"{key}.yml").read_text(encoding="utf-8"))
            found = [f for f in profile["files"] if isinstance(f, dict) and f.get("name") == name
                     and f.get("unsourceable")]
            self.assertTrue(found, (key, name))
            reasons[name] = str(found[0]["unsourceable"])
        for name, reason in reasons.items():
            with self.subTest(name=name):
                self.assertFalse(sitewanted.shareable(reason), reason)
        for reason in ("no public dump located (2026-10-04), and a same-named ROM of another set "
                       "must not stand in",
                       "retail data the collection does not hold, and a same-named file of another "
                       "game must not stand in",
                       "ships inside the Ghostship release, and the collection does not hold it"):
            with self.subTest(reason=reason):
                self.assertTrue(sitewanted.shareable(reason))

    def test_more_readers_come_first(self):
        records = [{"name": "a", "required": False, "readers": {("emulator", "e", "E")}},
                   {"name": "b", "required": False,
                    "readers": {("emulator", "e", "E"), ("platform", "p", "P")}},
                   {"name": "c", "required": True, "readers": {("emulator", "e", "E")}},
                   {"name": "d", "required": True, "readers": {("emulator", "e", "E")},
                    "category": sitewanted.GAME_DATA},
                   {"name": "u", "required": True, "readers": {("platform", "p", "P")},
                    "category": sitewanted.UNREAD}]
        for record in records:
            record.setdefault("category", sitewanted.BIOS)
        self.assertEqual([r["name"] for r in sorted(records, key=sitewanted._order)],
                         ["c", "b", "a", "u", "d"])

    def test_a_name_with_no_hash_joins_the_hashed_entry_of_its_name(self):
        reader = ("emulator", "other", "Other")
        records = {
            ("b.bin", (("sha1", ("x",)),), ()): {
                "name": "b.bin", "hashes": {"sha1": ["x"]}, "systems": {"x"}, "required": False,
                "readers": {("emulator", "engine", "Engine")}, "description": "",
                "category": sitewanted.GAME_DATA, "crc": set(), "links": {(False, "engine"): "e"}},
            ("b.bin", "x", ""): {
                "name": "b.bin", "hashes": {}, "systems": {"x"}, "required": True,
                "readers": {reader}, "crc": {"1234abcd"}, "links": {(False, "other"): "o"},
                "category": sitewanted.BIOS},
        }
        sitewanted._merge_named(records)
        self.assertEqual(len(records), 1)
        merged = next(iter(records.values()))
        self.assertIn(reader, merged["readers"])
        self.assertTrue(merged["required"])
        self.assertEqual(merged["category"], sitewanted.BIOS)

    def test_a_pattern_is_not_a_file(self):
        profiles = {"engine": {**self.profiles["engine"], "files": [
            *self.profiles["engine"]["files"], {"name": "<serial>.txt", "system": "x"}]}}
        report = {"engine": {**self.gap_report["engine"], "gap_details": [
            *self.gap_report["engine"]["gap_details"],
            {"name": "<serial>.txt", "source": "missing", "identity": ""}]}}
        data = sitewanted.build_wanted(profiles, self.coverages, report, self.db, self.placer,
                                       str, self.ledger)
        self.assertNotIn("<serial>.txt", [e["n"] for e in data["entries"]])

    def test_every_name_links_its_details(self):
        """An emulator's entry links its card, a file only a setup lists
        links that setup's page."""
        seen = []

        def link(kind: str, key: str, entry: dict) -> str:
            seen.append((kind, key, entry["name"]))
            return f"{kind}/{key}/#{entry['name']}"

        data = sitewanted.build_wanted(self.profiles, self.coverages, self.gap_report, self.db,
                                       self.placer, str, self.ledger, link)
        links = {e["n"]: e["a"] for e in data["entries"]}
        self.assertEqual(links["b.bin"], "emulator/engine/#b.bin")
        self.assertEqual(links["v.bin"], "platform/plat/#v.bin")
        self.assertTrue(all(e["a"] for e in data["entries"]))
        self.assertEqual(sitewanted.reader_page("platform", "plat", {}), "platforms/plat/")

    def test_a_crc32_beside_a_stronger_hash_is_shown_not_matched(self):
        profiles = {"engine": {**self.profiles["engine"], "files": [
            {**f, "crc32": crc(WANTED)} if f["name"] == "b.bin" else f
            for f in self.profiles["engine"]["files"]]}}
        data = sitewanted.build_wanted(profiles, self.coverages, self.gap_report, self.db,
                                       self.placer, str, self.ledger)
        entry = next(e for e in data["entries"] if e["n"] == "b.bin")
        self.assertEqual(entry["h"], {"sha1": [sha1(WANTED)]})
        self.assertEqual(entry["c"], [crc(WANTED)])

    def test_the_list_carries_only_what_the_table_and_the_drop_box_read(self):
        allowed = {"n", "h", "c", "w", "s", "r", "z", "a", "f", "t", "v"}
        for entry in self.data["entries"]:
            with self.subTest(entry=entry["n"]):
                self.assertLessEqual(set(entry), allowed)

    def test_an_entry_carries_its_readers_system_and_need(self):
        entry = self.entry("b.bin")
        self.assertEqual(entry["h"], {"sha1": [sha1(WANTED)]})
        self.assertEqual([self.data["systems"][i] for i in entry["s"]], ["System X"])
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
            values = [v for algo in ("sha1", "md5", "sha256") for v in entry.get("h", {}).get(algo, [])
                      if len(v) == sitewanted.FULL_LENGTH[algo]]
            spot = validate_pr.placement(values, entry["n"], self.db, self.platform_hashes,
                                         self.profile_hashes, declared="h" in entry,
                                         exists=self.placer.paths.__contains__,
                                         systems=["x"])
            with self.subTest(entry=entry["n"]):
                self.assertEqual(self.data["folders"][entry["f"]] if "f" in entry else "",
                                 spot.folder)
                self.assertEqual(entry.get("t", ""), spot.name)
                self.assertEqual(bool(entry.get("v")), spot.variant)

    def test_a_name_held_for_another_machine_is_no_folder(self):
        """nohash.bin is held only in bios/Other/Elsewhere/, a folder no
        file of system x is in: the folder comes from system x."""
        self.assertEqual(self.data["folders"][self.entry("nohash.bin")["f"]], "bios/Maker/Console/")
        spot = validate_pr.placement([], "nohash.bin", self.db, self.platform_hashes,
                                     self.profile_hashes, declared=False, systems=["x"])
        self.assertEqual(spot.folder, "bios/Maker/Console/")
        # The review, given the name alone, reads the systems that declare it.
        self.assertEqual(validate_pr.placement([], "nohash.bin", self.db, self.platform_hashes,
                                               self.profile_hashes, declared=False).folder,
                         "bios/Maker/Console/")

    def test_the_review_accepts_the_folder_the_page_gives(self):
        folder = self.data["folders"][self.entry("nohash.bin")["f"]]
        path = self.tmp / folder / "nohash.bin"
        path.write_bytes(b"a copy of the wanted file")
        result = validate_pr.validate_file(f"{folder}nohash.bin", self.db, self.platform_hashes,
                                           self.profile_hashes)
        self.assertFalse([m for kind, m in result.checks if kind == "WARN" and m.startswith("Placed under")])
        self.assertIn(("PASS", "Correct placement: bios/Maker/Console/"), result.checks)

    def test_a_declared_directory_names_its_folder(self):
        spot = validate_pr.placement([], "v.bin", self.db, self.platform_hashes, self.profile_hashes,
                                     declared=False, directory="system/Maker/Console/")
        self.assertEqual(spot.folder, "bios/Maker/Console/")

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

    def test_a_dropped_file_meets_a_name_only_entry_by_its_name(self):
        out = json.loads(_node(
            f"import {{ byName, matches }} from {json.dumps(WANTED_TS.as_uri())};"
            f"const data = {json.dumps(self.data)};"
            "const file = {sha1: 'x', md5: 'x', crc32: 'x', sha256: 'x'};"
            "console.log(JSON.stringify([byName(data, 'NOHASH.BIN').map((e) => e.n),"
            " byName(data, 'b.bin').map((e) => e.n), matches(data, file, 1).map((e) => e.n)]));"
        ))
        self.assertEqual(out, [["nohash.bin"], [], []])

    def test_the_issue_form_is_filled_as_the_review_fills_it(self):
        result = validate_pr.ValidationResult("b.bin")
        result.sha1, result.md5, result.size = sha1(WANTED), md5(WANTED), len(WANTED)
        self.assertEqual(self._page(WANTED, "b.bin")["issue"], validate_pr.large_file_issue_url(result))


class TheTwoPagesLinkEachOther(unittest.TestCase):
    """files/ checks any file, wanted/ the ones the collection lacks: each
    sends a reader to the other in one line."""

    def test_links(self):
        self.assertIn("[See if it is wanted](../wanted.md)", generate_site.generate_files_page())
        self.assertIn("[Find or check a file](files/index.md)", sitewanted.page(2, 1))


class ThePageSpeaksWithoutPronouns(unittest.TestCase):
    """The generated page is held by test_site_pronouns. The words the
    components write at run time are held here."""

    STRING = re.compile(r"'((?:[^'\\\n]|\\.)*)'|`([^`]*)`")
    MARKUP_TEXT = re.compile(r">([^<>{}]+)<")

    def test_page(self):
        self.assertEqual(pronouns(sitewanted.page(1_165, 199)), [])

    def test_components(self):
        for name in ("WantedFiles.astro", "WantedList.astro"):
            source = (COMPONENTS / name).read_text(encoding="utf-8")
            script = source[source.index("<script>"):source.index("</script>")]
            texts = [a or b for a, b in self.STRING.findall(script)]
            texts += self.MARKUP_TEXT.findall(source[:source.index("<script>")])
            with self.subTest(component=name):
                self.assertTrue(texts)
                self.assertEqual([t for t in texts if pronouns(t)], [])

    def test_a_simple_table(self):
        """File name, size and the three hashes, a name linked to its
        details: nothing else on a row."""
        source = (COMPONENTS / "WantedList.astro").read_text(encoding="utf-8")
        head = re.search(r"<thead>(.*?)</thead>", source, re.S)[1]
        self.assertEqual(re.findall(r"<th[^>]*>([^<]*)</th>", head),
                         ["File name", "Size", "CRC32", "MD5", "SHA1"])
        script = source[source.index("<script>"):source.index("</script>")]
        self.assertIn("name.href = `${base}${entry.a}`;", script)
        for gone in ("entry.d", "entry.u", "entry.l", "entry.r", "entry.w", "Upload", "rb-badge",
                     "Copy"):
            self.assertNotIn(gone, script)

    def test_the_page_lists_the_steps(self):
        text = sitewanted.page(1_165, 199)
        for step in ("<WantedFiles />", "<WantedList />", "https://github.com/signup",
                     "pull request", "issue form", "Drop them all", "1,165 files"):
            self.assertIn(step, text)
        self.assertLess(text.index("<WantedFiles />"), text.index("<WantedList />"))


class AFolderComesFromTheSystem(unittest.TestCase):
    """AmberELEC declares config.ini once per blueMSX machine, with no
    hash. The only config.ini files the collection holds are msx.emu's,
    one of them under its ColecoVision machine: a match by name alone sent
    the MSX ones there."""

    @classmethod
    def setUpClass(cls) -> None:
        if not (REPO_ROOT / "database.json").is_file():
            raise unittest.SkipTest("no database")
        cls.db = load_database(str(REPO_ROOT / "database.json"))
        cls.platform_hashes = validate_pr.load_platform_hashes(str(REPO_ROOT / "platforms"), cls.db)
        cls.profile_hashes = validate_pr.load_profile_hashes(str(REPO_ROOT / "emulators"), cls.db)

    def place(self, systems: list[str], directory: str) -> validate_pr.Placement:
        return validate_pr.placement([], "config.ini", self.db, self.platform_hashes,
                                     self.profile_hashes, declared=False,
                                     systems=systems, directory=directory)

    def test_an_msx_machine_config_stays_with_msx(self):
        spot = self.place(["microsoft-msx"], "bios/Machines/MSX2 - Arabic/")
        self.assertNotIn("ColecoVision", spot.folder)
        self.assertTrue(spot.folder.startswith("bios/Microsoft/MSX/"), spot)

    def test_the_name_alone_names_no_machine(self):
        """The review of an upload outside bios/ knows the name only: eight
        systems declare config.ini, so no copy of one of them answers."""
        spot = self.place([], "")
        self.assertEqual(spot.home, "")
        self.assertIn("bios/Microsoft/MSX/", spot.folders)

    def test_a_colecovision_config_keeps_its_machine(self):
        spot = self.place(["coleco-colecovision"], "bios/Machines/COL - ColecoVision/")
        self.assertTrue(spot.folder.endswith("/Machines/COL - ColecoVision/"), spot)


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
            if "h" not in entry:
                continue
            with self.subTest(entry=entry["n"]):
                self.assertFalse(held.holds(entry["h"], entry.get("z", [])))

    def test_name_only_entries_are_kept(self):
        self.assertTrue(any("h" not in e for e in self.data["entries"]))

    def test_every_folder_is_the_reviews(self):
        placer = sitewanted.Placer(
            self.db, validate_pr.load_platform_hashes(str(REPO_ROOT / "platforms"), self.db),
            validate_pr.load_profile_hashes(str(REPO_ROOT / "emulators"), self.db))
        # An entry placed by its hashes. The others take their folder from
        # their system and directory, which the list does not carry: the
        # synthetic world above holds them to the rule.
        for entry in self.data["entries"]:
            values = [v for algo in ("sha1", "md5", "sha256") for v in entry.get("h", {}).get(algo, [])
                      if len(v) == sitewanted.FULL_LENGTH[algo]]
            if not validate_pr.expected_folders(values, placer.platform_hashes, placer.profile_hashes):
                continue
            spot = placer.place(entry.get("h", {}), entry["n"])
            with self.subTest(entry=entry["n"]):
                self.assertEqual(self.data["folders"][entry["f"]] if "f" in entry else "", spot.folder)
                self.assertEqual(entry.get("t", ""), spot.name)

    def test_weight(self):
        self.assertLess(PUBLISHED.stat().st_size, 200_000)

    def test_every_link_lands_on_its_details(self):
        """Each name's link is a built page, and a card anchor is on it."""
        dist = WEBSITE / "dist"
        if not dist.is_dir():
            self.skipTest("no built site")
        pages: dict[str, str] = {}
        for entry in self.data["entries"]:
            path, _, anchor = entry["a"].partition("#")
            html = pages.get(path)
            if html is None:
                built = dist / path / "index.html"
                html = pages[path] = built.read_text(encoding="utf-8") if built.is_file() else ""
            with self.subTest(entry=entry["n"], link=entry["a"]):
                self.assertTrue(html)
                if anchor:
                    self.assertIn(f'id="{anchor}"', html)

    def test_the_built_page_asks_for_this_list(self):
        """The list's address carries its version: a browser that cached an
        older list (another shape) fetches this one."""
        built = WEBSITE / "dist" / "wanted" / "index.html"
        if not built.is_file():
            self.skipTest("no built site")
        html = built.read_text(encoding="utf-8")
        version = hashlib.sha1(PUBLISHED.read_bytes()).hexdigest()[:12]
        self.assertEqual(html.count(f'data-version="{version}"'), 2)
        self.assertNotIn("data/wanted.json", html)


if __name__ == "__main__":
    unittest.main()
