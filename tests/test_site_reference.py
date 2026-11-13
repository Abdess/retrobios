"""Reference pages and data.

A reference page cites a hash, a source line or a count, and each citation
has to hold when an expert checks it: the reader of a pinned dump is the
profile entry accepting its hash, a source line is a pinned link, an entry
names the file that serves it, and the exports carry what the page shows.

The CSV and SQLite dropped zipped_file, so a check built from them judged
106 good Batocera files wrong. The manifest a pack installs was nowhere on
the site. Contracts failed their own schema, 716 documents lacked `commit`,
no endpoint answered a system id or a buildbot core name, lookup URLs
resolved to 404s, the data's licence went unstated, platform overviews
named emulators as unlinked ids, gaps tables overflowed with full hashes
and a source link went into a repository that does not hold the file.
Tests that read the built site skip when it has not been generated.

The lookup answered a SHA1 without the setups that list the same file by
MD5, the published folder check failed 134 EmuDeck entries a folder EmuDeck
accepts, the manifest table printed `&lt;ref>` behind a dead link and showed
17 of 48 fields, 28 system ids held files and no page, and source links went
to 404s on the deploy, which has no tree cache. Tests that read the built
site skip when it has not been generated.

The API said Lakka and RetroPie had a release pack while their pages said
none, 50 nested manifest fields and the nine omission codes had no
description, the lookup named 9 emulators where the card named 11, four
served schemas and the target lists appeared nowhere on the Data page, the
folder check exited 0 on a folder missing every file, and a system id did
not lead to its JSON document. Tests reading the generated site skip when
it has not been generated.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import csv
import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock
import hashlib
import os
import shutil
import sqlite3
import tempfile
import urllib.parse
import zipfile
import runpy
import urllib.error

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitewanted  # noqa: E402
import siterender  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
    list_release_pack_platforms,
)
from exporter.baseline import HASH_FIELDS, _hash_values  # noqa: E402
from exporter.candidates import EntryCategories  # noqa: E402
from sitesources import launcher_ref_markdown, list_source  # noqa: E402
import check_platform_folder  # noqa: E402
import sitesources  # noqa: E402
import release_record  # noqa: E402
import upstream  # noqa: E402


PLATFORMS = str(REPO_ROOT / "platforms")
DIST = REPO_ROOT / "website" / "dist"


def _accepted(profile_entry: dict) -> set[str]:
    values = {v for f in HASH_FIELDS for v in _hash_values(profile_entry, f)}
    for member in profile_entry.get("contents") or []:
        if isinstance(member, dict):
            values |= {v for f in HASH_FIELDS for v in _hash_values(member, f)}
    return values


class ReaderMatchedByHash(unittest.TestCase):
    """Batocera's scph1001.bin (md5 dc2b9bf8, SCPH-1001 v2.0) cited
    DuckStation's bios.cpp:36, the line of the v2.2 dump: the reader was
    matched by name."""

    @classmethod
    def setUpClass(cls):
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def test_batocera_scph1001_cites_the_v20_line(self):
        config = load_platform_config("batocera", PLATFORMS)
        cats = EntryCategories(config, self.profiles)
        entry = next(e for e in config["systems"]["sony-playstation"]["files"]
                     if e["name"] == "scph1001.bin")
        found = cats.explain(entry, entry.get("destination") or entry["name"],
                             "sony-playstation")
        duck = next(r for r in found["read_by"] if r["emulator"] == "duckstation")
        self.assertEqual(duck["entries"], [
            {"name": "scph1001_v20.bin", "source_ref": "src/core/bios.cpp:42"}])

    def test_every_cited_entry_accepts_the_md5_or_says_by_name(self):
        by_name = 0
        for platform in list_registered_platforms(PLATFORMS):
            config = load_platform_config(platform, PLATFORMS)
            cats = EntryCategories(config, self.profiles)
            for sys_id, system in (config.get("systems") or {}).items():
                for entry in system.get("files") or []:
                    md5s = set(_hash_values(entry, "md5")) | set(_hash_values(entry, "alt_md5"))
                    if not md5s:
                        continue
                    # The same dump, named by whichever hash both sides state.
                    declared = md5s | {v for f in HASH_FIELDS for v in _hash_values(entry, f)}
                    found = cats.explain(entry, entry.get("destination") or entry["name"], sys_id)
                    for reader in found.get("read_by", []):
                        if reader["emulator"] == "launcher":
                            continue
                        files = self.profiles[reader["emulator"]].get("files") or []
                        for cited in reader["entries"]:
                            if cited.get("by") == "name":
                                by_name += 1
                                continue
                            accepted = set().union(*(
                                _accepted(f) for f in files
                                if isinstance(f, dict) and f.get("name") == cited["name"]))
                            with self.subTest(platform=platform, entry=entry["name"],
                                              emulator=reader["emulator"]):
                                self.assertTrue(any(
                                    a == m or (29 <= len(m) < 32 and a.startswith(m))
                                    for m in declared for a in accepted))
        self.assertGreater(by_name, 0)

    def test_a_contradicting_homonym_is_not_cited(self):
        profiles = {"core": {"type": "libretro", "systems": ["s"], "files": [
            {"name": "bios.bin", "md5": "1" * 32, "source_ref": "a.c:1"},
            {"name": "bios_v2.bin", "md5": "2" * 32, "source_ref": "a.c:2"},
        ]}}
        config = {"cores": ["core"], "systems": {"s": {"files": []}}}
        cats = EntryCategories(config, profiles)
        found = cats.explain({"name": "bios.bin", "md5": "2" * 32}, "bios.bin", "s")
        self.assertEqual(found["read_by"][0]["entries"],
                         [{"name": "bios_v2.bin", "source_ref": "a.c:2"}])
        found = cats.explain({"name": "bios.bin", "md5": "3" * 32}, "bios.bin", "s")
        self.assertEqual(found["read_by"][0]["entries"], [])


class EvidenceLinksItsSource(unittest.TestCase):
    """Platform pages printed refs as code with the role word in front:
    `source frontend/libretro.c:3864-3867`."""

    def test_pinned_link_and_by_name(self):
        evidence = {"read_by": [{
            "emulator": "pcsx_rearmed", "proof": "name", "runs_system": True,
            "entries": [{"name": "scph1001.bin", "by": "name",
                         "source_ref": "source frontend/libretro.c:3864-3867 (listed_bios[6])"}],
        }]}
        text = generate_site._category_evidence_md(evidence)
        self.assertRegex(text, r"\[`frontend/libretro\.c:3864-3867`\]\(https://github\.com/"
                               r"libretro/pcsx_rearmed/blob/[0-9a-f]{40}/frontend/libretro\.c"
                               r"#L3864-L3867\)")
        self.assertIn("(by name)", text)
        self.assertNotIn("`source ", text)

    def test_launcher_record_named_with_its_lines(self):
        evidence = {"read_by": [{"emulator": "launcher", "proof": "launcher",
                                 "entries": [], "runs_system": True}]}
        config = load_platform_config("batocera", PLATFORMS)
        launched = generate_site._launcher_refs(config)["scph1001.bin"]
        text = generate_site._category_evidence_md(evidence, launched)
        self.assertNotIn("(by launcher)", text)
        self.assertIn("https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/"
                      "package/batocera/core/batocera-configgen/", text)
        self.assertIn("duckstationGenerator.py:115-136", text)

    def test_every_platform_links_its_launchers(self):
        """Only Batocera and RetroBat were linked: Recalbox, ROCKNIX, EmuDeck,
        RetroPie and RetroDECK read their launchers in the list's repository
        too, and their citations came out as plain code."""
        checked = 0
        for path in sorted(Path(PLATFORMS).glob("*.yml")):
            if not path.stem[0].isalpha():
                continue
            config = load_platform_config(path.stem, PLATFORMS)
            if not config.get("launchers"):
                continue
            with self.subTest(platform=path.stem):
                rendered = [text for texts in generate_site._launcher_refs(config).values()
                            for text in texts]
                self.assertTrue(rendered)
                self.assertFalse([t for t in rendered if " at `" in t])
            checked += 1
        self.assertGreaterEqual(checked, 7)

    def test_a_launcher_in_another_repository_is_not_linked(self):
        source = list_source("https://gitlab.com/recalbox/recalbox/-/raw/10.1.1/x/es_bios.xml")
        self.assertEqual(launcher_ref_markdown(None, "a/b.py:3"), "`b.py:3`")
        self.assertIn("gitlab.com/recalbox/recalbox/-/blob/10.1.1/a/b.py#L3",
                      launcher_ref_markdown(source, "a/b.py:3"))


class EachEntryNamesItsFile(unittest.TestCase):
    def test_served_held_and_missing(self):
        path, digest = next(
            (p, d) for p, d in generate_site._collection_sha1_by_path().items()
            if p.startswith("bios/") and p.count("/") >= 3)
        served = generate_site._served_line({"status": "ok", "path": path})
        self.assertRegex(served, rf"\]\(\.\./systems/[^)]+\.md#sha1-{digest[:12]}\)")
        self.assertTrue(served.startswith("Served by: "))
        self.assertIn(f"`{digest[:8]}`", served)
        # The row already shows the declared sha1: repeating it said nothing.
        quiet = generate_site._served_line({"status": "ok", "path": path}, f"aaaa, {digest.upper()}")
        self.assertNotIn(digest[:8], quiet.split(")", 1)[1])
        self.assertIn(f"`{digest[:8]}`", generate_site._served_line(
            {"status": "ok", "path": path}, "a" * 40))
        self.assertEqual(generate_site._served_line({"status": "missing"}), "Not held")
        self.assertTrue(generate_site._served_line(
            {"status": "untested", "path": path}).startswith("Held, not the declared hash"))
        # Existence mode reports no path: nothing is claimed, held or not.
        self.assertEqual(generate_site._served_line({"status": "ok"}), "")

    def test_a_long_system_list_is_cut_between_rows_by_elements(self):
        rows = [[f'<details class="rb-file"><summary>f{n}.bin</summary>x<br>y</details>']
                for n in range(4)]
        # Three elements a row: two rows fit in a budget of seven.
        runs = generate_site._blocks_in_runs(rows, 7, generate_site._element_weight)
        self.assertEqual([len(run) for run in runs], [2, 2])
        self.assertEqual(sum(runs, []), sum(rows, []))


class AlsoNamedIsNotCited(unittest.TestCase):
    def test_other_system_cores_are_named_only(self):
        evidence = {"read_by": [
            {"emulator": "duckstation", "proof": "name", "runs_system": True,
             "entries": [{"name": "scph1001_v20.bin", "source_ref": "src/core/bios.cpp:42"}]},
            {"emulator": "mame", "proof": "name", "runs_system": False,
             "entries": [{"name": "x.zip", "source_ref": "src/mame/x.cpp:1", "by": "name"}]},
        ]}
        text = generate_site._category_evidence_md(evidence)
        also = text.split(", also named by ", 1)[1]
        self.assertNotIn("x.cpp", also)
        self.assertIn("mame", also)


class PlatformReferenceInWords(unittest.TestCase):
    def _page(self, mode: str, hash_type: str, systems: dict | None = None,
              registry: dict | None = None) -> str:
        details = [{"name": "f.bin", "status": "ok", "system": s} for s in (systems or {})]
        cov = {"platform": "P", "details": details, "total": 1, "verified": 1,
               "present": 1, "missing": 0, "untested": 0, "mode": mode,
               "config": {"hash_type": hash_type, "systems": systems or {},
                          "source": "https://github.com/o/r/tree/" + "a" * 40}}
        return generate_site.generate_platform_page("p", cov, registry or {})

    def test_hash_type_only_when_it_differs(self):
        self.assertNotIn("Hash type", self._page("md5", "md5"))
        self.assertNotIn("Hashes in the list", self._page("md5", "md5"))
        page = self._page("existence", "sha1")
        self.assertIn("| Hashes in the list | SHA-1 |", page)
        self.assertIn(">name only</span>", page)
        self.assertIn(">MD5</span>", self._page("md5", "md5"))
        self.assertIn("[r repository at commit aaaaaaaaaaaa](https://github.com/o/r/tree/"
                      + "a" * 40 + ")", page)

    def test_every_check_label_reads_the_hash_rule(self):
        """RomM's badge and table rows said MD5 beside a sentence saying it
        accepts the size and any one hash."""
        details = [{"name": "f.bin", "status": "ok", "system": "sony-playstation"}]
        cov = {"platform": "RomM", "details": details, "total": 1, "verified": 1,
               "present": 1, "missing": 0, "untested": 0, "mode": "md5",
               "core_present": 0, "core_missing": 0, "core_unsourceable": 0,
               "config": {"hash_type": "md5", "hash_rule": "size_and_any_hash",
                          "systems": {"sony-playstation": {"files": [{"name": "f.bin"}]}},
                          "source": "https://github.com/o/r/tree/" + "a" * 40}}
        page = generate_site.generate_platform_page("romm", cov, {})
        self.assertIn(">size, then any hash</span>", page)
        self.assertNotIn(">MD5</span>", page)
        table = "\n".join(generate_site.setup_table({"romm": cov}))
        self.assertIn("| size, then any hash |", table)

    def test_systems_by_name_with_the_id_in_small_text(self):
        systems = {"sony-playstation": {"files": [{"name": "f.bin"}]}}
        page = self._page("md5", "md5", systems)
        name = siterender.system_name("sony-playstation")
        self.assertIn(f"| [{name}](#sony-playstation) <small data-pagefind-ignore>sony-playstation</small> |", page)
        heading = next(line for line in page.splitlines() if line.startswith("### ")
                       and "sony-playstation" in line)
        self.assertIn(name, heading)
        self.assertTrue(heading.endswith("<small>sony-playstation</small> { #sony-playstation }"))

    def test_logo_in_front_matter_not_floated(self):
        page = self._page("md5", "md5", registry={"p": {"logo": "https://x.test/l.png"}})
        self.assertTrue(page.startswith('---\nlogo: "https://x.test/l.png"\n---\n'))
        self.assertNotIn('align="right"', page)


class GapsPageNumbers(unittest.TestCase):
    def test_badge_only_for_missing_required_firmware(self):
        self.assertNotIn("rb-badge", generate_site._ratio_cell(99, 100))
        self.assertIn('class="rb-bar"', generate_site._ratio_cell(99, 100))
        self.assertIn("rb-badge-danger", generate_site._ratio_cell(99, 100, 1))
        cov = {"details": [
            {"name": "a", "system": "s", "status": "missing", "required": True, "category": "bios"},
            {"name": "b", "system": "s", "status": "missing", "required": True,
             "category": "game_data"},
            {"name": "c", "system": "s", "status": "missing", "required": False},
        ]}
        self.assertEqual(generate_site._missing_required_firmware(cov), 1)

    def test_headings_and_header(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        body = source[source.index("def generate_gap_analysis("):]
        body = body[:body.index("\ndef ", 10)]
        self.assertIn('"# What the packs do not hold"', body)
        self.assertIn("On its BIOS list (destinations)", body)
        self.assertIn('"### Files to source"', body)
        self.assertNotIn("### Files to source (", body)


class UpstreamsGrouped(unittest.TestCase):
    def test_mame_trees_are_one_project(self):
        keys = {generate_site.upstream_project(u)[0] for u in (
            "https://github.com/mamedev/mame",
            "https://github.com/mamedev/mame/tree/mame0289",
            "https://github.com/mamedev/mame/tree/mame0135u4",
        )}
        self.assertEqual(keys, {"github.com/mamedev/mame"})
        self.assertEqual(generate_site.upstream_project(
            "https://github.com/mamedev/mame/tree/mame0289")[1], "mame0289")

    def test_nested_groups_notes_and_archives(self):
        project = generate_site.upstream_project
        self.assertEqual(
            project("https://gitlab.com/recalbox/packages/recalbox-cores/libretro-exel-hence"),
            ("gitlab.com/recalbox/packages/recalbox-cores/libretro-exel-hence", ""))
        self.assertEqual(project("https://gitlab.com/jgemu/geolith/-/tree/v1"),
                         ("gitlab.com/jgemu/geolith", "v1"))
        self.assertEqual(
            project("https://git.9front.org/plan9front/plan9front (sys/src/games/nes/)"),
            ("git.9front.org/plan9front/plan9front", "sys/src/games/nes/"))
        key, _ = project("https://archive.softwareheritage.org/browse/revision/"
                         "dc20a615275f66bee20a4fd851ef0231daca4f14/")
        self.assertEqual(generate_site._upstream_label(key),
                         "Software Heritage revision dc20a615275f")

    def test_overview_and_a_page_per_platform(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        coverages = {}
        for name in ("batocera", "retroarch"):
            config = load_platform_config(name, PLATFORMS)
            coverages[name] = {"platform": config.get("platform", name), "config": config}
        moved: dict[str, str] = {}
        page = generate_site.generate_cross_reference(coverages, profiles, moved)
        self.assertEqual(set(moved), {"cross-reference-batocera", "cross-reference-retroarch"})
        self.assertNotIn("<details", page)
        upstream = page[page.index("## By upstream emulator"):]
        self.assertEqual(len(re.findall(r"\| \[mamedev/<wbr>mame\]\(", upstream)), 1)
        header = next(line for line in upstream.splitlines() if line.startswith("| Cores"))
        self.assertTrue(header.startswith("| Cores | Upstream |"))


class ExportsComplete(unittest.TestCase):
    def test_gap_rows_once_with_their_outcome(self):
        path = next(iter(generate_site._collection_sha1_by_path()))
        detail = {"name": "x.bin", "system": "s", "status": "untested", "path": path,
                  "category": "bios"}
        coverages = {"p": {"platform": "P", "details": [
            {"name": "h.xml", "system": "s", "status": "missing"},
            {"name": "h.xml", "system": "s", "status": "missing"}, detail]}}
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        rows = generate_site._gap_export_rows(coverages, {}, db)
        self.assertEqual([r["name"] for r in rows], ["h.xml", "x.bin"])
        held = rows[1]
        self.assertEqual(held["collection_path"], path)
        self.assertEqual(held["resolved_sha1"], generate_site._collection_sha1_by_path()[path])
        self.assertEqual(held["category"], "bios")

    def test_platform_rows_carry_status_and_file(self):
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        sha1, entry = next(iter(db["files"].items()))
        coverages = {"p": {"platform": "P", "config": {"systems": {"s": {"files": [
            {"name": "a.bin"}, {"name": "b.bin"}]}}}, "details": [
            {"name": "a.bin", "system": "s", "status": "ok", "path": entry["path"],
             "category": "bios"},
            {"name": "b.bin", "system": "s", "status": "missing", "category": "game_data"}]}}
        _items, rows = generate_site._platform_export_rows(coverages, db)
        self.assertEqual((rows[0]["status"], rows[0]["resolved_sha1"]), ("ok", sha1))
        self.assertEqual(rows[0]["collection_path"], entry["path"])
        self.assertEqual((rows[1]["status"], rows[1]["category"], rows[1]["collection_path"]),
                         ("missing", "game_data", ""))

    def test_commit_and_wanted_list(self):
        commit = generate_site._source_commit()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        schema = json.loads((REPO_ROOT / "schemas" / "site-api-envelope.schema.json")
                            .read_text(encoding="utf-8"))
        self.assertIn("commit", schema["properties"])
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        rows = generate_site._provenance_wanted_rows(db)
        self.assertTrue(rows)
        self.assertTrue(all(r["catalog"] and r["name"] for r in rows))
        text = generate_site._csv_document(list(generate_site.WANTED_FIELDS), rows)
        self.assertEqual(next(csv.reader(io.StringIO(text))), list(generate_site.WANTED_FIELDS))


class DatesAndNames(unittest.TestCase):
    def test_snapshot_date_in_words(self):
        self.assertEqual(generate_site._date_in_words("2026-08-07T10:00:00Z"),
                         '<time datetime="2026-08-07">7 August 2026</time>')

    def test_data_page_title(self):
        self.assertIn("\n---\n\n# Data and API\n", generate_site.generate_data_page([]))


@unittest.skipUnless((DIST / "platforms" / "batocera" / "index.html").is_file(),
                     "site not built")
class BuiltBatoceraPage(unittest.TestCase):
    def test_served_by_and_pinned_links(self):
        main = (DIST / "platforms" / "batocera" / "index.html").read_text(encoding="utf-8")
        self.assertTrue("batocera-systems at tag batocera-43.1" in main)
        # PlayStation's list is long enough to sit on a page of its own.
        pages = [main] + [p.read_text(encoding="utf-8") for p in
                          (DIST / "platforms").glob("batocera-sony-playstation*/index.html")]
        # Read as a browser shows it: a page with no tab bar is plain
        # Markdown, which keeps the entity a name's underscore is written as.
        import html as _html

        html = _html.unescape("".join(pages))
        for text in ("Served by:", "scph1001_v20.bin", "https://github.com/stenzek/duckstation/blob/"):
            with self.subTest(text=text):
                self.assertTrue(text in html)
        self.assertFalse("(by launcher)" in html)


PUBLIC = REPO_ROOT / "website" / "public"
API = PUBLIC / "api" / "v1"
SITE = "https://abdess.github.io/retrobios/"
TMP = REPO_ROOT / "tmp"


def _built(path: Path) -> Path:
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path


def _verify_status(entry: dict, path: Path, mode: str) -> str:
    """What verify.py says of one entry, the platform's native logic."""
    from verify import verify_entry_existence, verify_entry_md5, verify_entry_sha1

    local = str(path) if path.is_file() else None
    if mode == "existence":
        return verify_entry_existence(entry, local)["status"]
    if mode == "sha1":
        return verify_entry_sha1(entry, local)["status"]
    return verify_entry_md5(entry, local)["status"]


def _as_snippet(status: str) -> str:
    return {"ok": "ok", "untested": "wrong", "missing": "missing"}[status]


class TheExportsKeepWhatACheckNeeds(unittest.TestCase):
    """8.1: zipped_file and the Recalbox flags reach the CSV and SQLite."""

    COVERAGE = {"batocera": {
        "platform": "Batocera", "details": [],
        "config": {"platform": "Batocera", "verification_mode": "md5",
                   "install": {"detect": []}, "logo": "x.svg", "_key": "batocera",
                   "systems": {"bbc": {"files": [
                       {"name": "bbcb.zip", "destination": "bbcb.zip",
                        "md5": "521a197d", "zipped_file": "basic1.rom"},
                       {"name": "n.rom", "destination": "n.rom", "md5": "ab",
                        "hash_match_mandatory": True, "mandatory_declared": False,
                        "shared_group": "group-x"},
                   ]}}},
    }}

    def test_rows_carry_the_member_and_the_flags(self):
        _items, rows = generate_site._platform_export_rows(self.COVERAGE)
        zipped, flagged = rows
        self.assertEqual(zipped["zipped_file"], "basic1.rom")
        self.assertIs(flagged["hash_match_mandatory"], True)
        self.assertIs(flagged["mandatory_declared"], False)
        self.assertEqual(flagged["shared_group"], "group-x")
        self.assertEqual(flagged["zipped_file"], "")

    def test_the_csv_header_and_the_table_name_them(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('"collection_path", "resolved_sha1", *ENTRY_EXPORT_FIELDS,', source)
        for field in generate_site.ENTRY_EXPORT_FIELDS:
            self.assertIn(f":{field}", source)
        for field in ("zipped_file", "hash_match_mandatory", "mandatory_declared", "curated"):
            self.assertIn(field, generate_site.ENTRY_EXPORT_FIELDS)

    def test_the_built_csv_has_the_column(self):
        text = _built(PUBLIC / "downloads" / "platform-files.csv").read_text(encoding="utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
        batocera = [row for row in rows if row["platform_id"] == "batocera"]
        self.assertGreater(sum(1 for row in batocera if row["zipped_file"]), 300)
        with sqlite3.connect(_built(PUBLIC / "downloads" / "retrobios.sqlite")) as db:
            count = db.execute("SELECT count(*) FROM platform_files "
                               "WHERE platform_id = 'batocera' AND zipped_file != ''").fetchone()[0]
            license_row = db.execute("SELECT value FROM metadata WHERE key = 'license'").fetchone()
        self.assertGreater(count, 300)
        self.assertEqual(license_row[0], generate_site.DATA_LICENSE)


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
        md5 = lambda data: hashlib.md5(data).hexdigest()  # noqa: E731
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
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
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
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
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
        page = generate_site.generate_data_page([])
        self.assertIn("```python\n" + script.rstrip("\n") + "\n```", page)
        self.assertLess(len(script.splitlines()), 70)
        self.assertIn("## Check a folder for one platform", page)


class TheContractsValidate(unittest.TestCase):
    """8.4: registry keys leave the contract, every $id is its served URL."""

    def test_every_contract_validates_against_the_platform_schema(self):
        try:
            from jsonschema import Draft202012Validator  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        from common import list_registered_platforms, load_platform_config  # noqa: PLC0415

        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text())
        validator = Draft202012Validator(schema)
        platforms = str(REPO_ROOT / "platforms")
        for name in list_registered_platforms(platforms):
            config = load_platform_config(name, platforms)
            contract, registry = generate_site._split_contract(config)
            with self.subTest(platform=name):
                errors = [error.message for error in validator.iter_errors(contract)]
                self.assertEqual(errors, [])
                self.assertIn("install", registry)
                self.assertNotIn("_key", registry)
                self.assertEqual(set(contract) | set(registry) | {"_key"}, set(config) | {"_key"})

    def test_every_schema_id_is_the_address_it_is_served_at(self):
        for path in sorted((REPO_ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text())
            with self.subTest(schema=path.name):
                self.assertEqual(schema.get("$id"), f"{SITE}api/v1/schemas/{path.name}")

    def test_every_schema_is_published(self):
        published = {p.name for p in _built(API / "schemas").glob("*.json")}
        self.assertEqual(published, {p.name for p in (REPO_ROOT / "schemas").glob("*.schema.json")})

    def test_the_built_api_validates(self):
        try:
            from jsonschema import Draft202012Validator  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is a tooling dependency")

        schemas = {p.name: json.loads(p.read_text()) for p in (REPO_ROOT / "schemas").glob("*.json")}
        envelope = Draft202012Validator(schemas["site-api-envelope.schema.json"])
        platform = Draft202012Validator(schemas["platform.schema.json"])
        document = json.loads(_built(API / "platforms.json").read_text())
        self.assertEqual(list(envelope.iter_errors(document)), [])
        for item in document["items"]:
            with self.subTest(platform=item["id"]):
                self.assertEqual([e.message for e in platform.iter_errors(item["contract"])], [])
        for name in ("systems.json", "cores.json", "index.json", "catalog.json"):
            with self.subTest(document=name):
                self.assertEqual(
                    [e.message for e in envelope.iter_errors(json.loads((API / name).read_text()))], [])


class TheIndexSaysWhatTheCatalogLists(unittest.TestCase):
    """index.json called catalog.json every published file, while the 990
    one-item documents of emulators/, platforms/, systems/ and lookup/ are
    in none of its 80 items."""

    def test_the_description_matches_the_items(self):
        index = json.loads(_built(API / "index.json").read_text())
        catalog = json.loads(_built(API / "catalog.json").read_text())
        described = next(i["description"] for i in index["items"] if i["url"] == "catalog.json")
        self.assertNotIn("Every published file", described)
        listed = {item["url"].split("/", 1)[0] for item in catalog["items"]}
        for folder in ("emulators", "platforms", "systems", "lookup"):
            with self.subTest(folder=folder):
                self.assertIn(f"{folder}/", described)
                self.assertNotIn(folder, listed)
                self.assertTrue(any((API / folder).glob("*.json")))


class EveryEnvelopeCarriesTheCommit(unittest.TestCase):
    """8.5: emulators/ and systems/ lacked `commit` (716 documents)."""

    def test_the_writers_pass_it(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('str(db.get("generated_at") or _timestamp()), _source_commit(),\n        )\n'
                      "    clash", source)
        block = source[source.index("public_profiles = {"):source.index("pages = emulator_pages(")]
        self.assertIn("write_single_item(", block)
        self.assertIn("_source_commit()", block)

    def test_every_built_envelope_has_it(self):
        _built(API / "catalog.json")
        if not generate_site._source_commit():
            raise unittest.SkipTest("not a git checkout")
        lacking = [
            path.relative_to(API).as_posix() for path in sorted(API.rglob("*.json"))
            if path.parent.name not in ("schemas", "manifests", "targets", "exports")
            and path.name not in ("database.json", "stats.json", "release.json")
            and "commit" not in json.loads(path.read_text())
        ]
        self.assertEqual(lacking, [])


class ManifestsArePublished(unittest.TestCase):
    """8.2: the manifest a pack installs, byte for byte, in the catalog."""

    def test_each_manifest_is_the_repository_file(self):
        catalog = json.loads(_built(API / "catalog.json").read_text())
        listed = {item["url"]: item for item in catalog["items"]}
        for source in sorted((REPO_ROOT / "install").glob("*.json")):
            with self.subTest(manifest=source.name):
                item = listed[f"manifests/{source.name}"]
                self.assertEqual(item["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertEqual(item["schema"], "schemas/install-manifest.schema.json")
        self.assertIn("release.json", listed)
        self.assertEqual(catalog["license"], generate_site.DATA_LICENSE)

    def test_the_data_page_explains_the_fields_from_the_schema(self):
        page = generate_site.generate_data_page([])
        schema = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())
        for field in ("dest", "repo_path", "release_asset", "cores"):
            description = schema["$defs"]["file"]["properties"][field]["description"]
            self.assertIn(f"| `{field}` | {generate_site._escape_tags(description)} |", page)
        self.assertIn("## Platform manifests", page)
        self.assertIn("**Licence:**", page)
        self.assertIn("## Hosting, rate limits and caching", page)
        # The endpoints first, the DAT below them.
        self.assertLess(page.index("## Stable JSON endpoints"), page.index("The DAT is Logiqx XML"))


class TheLookupRecipeSaysWhatASha1Misses(unittest.TestCase):
    """The page said a SHA1 lookup was enough, "a setup that lists a file
    by MD5 or CRC32 is filed under the SHA1 of the collection file it names
    too". A record whose value no collection file answers has no SHA1: 702
    platform MD5s were out of the recipe's reach."""

    def test_the_page_and_the_records_agree(self):
        record = {"layer": "platform", "algorithm": "md5", "value": "0" * 32,
                  "name": "dmg_boot.bin", "owner": "recalbox"}
        self.assertEqual(generate_site._held_under_every_hash([record], {}, {}), [])
        self.assertNotIn("sha1", record)
        page = " ".join(generate_site.generate_data_page([]).split())
        self.assertNotIn("none is needed", page)
        self.assertIn("A list naming a file the collection lacks is filed under its MD5 "
                      "or CRC32 alone", page)


class AnIdLeadsToItsData(unittest.TestCase):
    """8.6: a system by its id, a core by the name the buildbot gives it."""

    def test_a_buildbot_name_designates_its_profile(self):
        profiles = {
            "beetle_psx": {"type": "libretro", "cores": ["mednafen_psx", "mednafen_psx_hw"]},
            "pcsx2": {"type": "standalone"},
            "lrps2": {"type": "libretro", "cores": ["pcsx2"]},
            "mednafen_psx_alias": {"type": "alias", "alias_of": "beetle_psx"},
            "probe": {"type": "libretro", "role": "test", "cores": ["probe_core"]},
        }
        items = generate_site.core_index_items(profiles)
        by_name: dict[str, list[tuple[str, bool]]] = {}
        for item in items:
            by_name.setdefault(item["name"], []).append((item["profile"], item["preferred"]))
        self.assertEqual(by_name["mednafen_psx"], [("beetle_psx", True)])
        self.assertEqual(by_name["pcsx2"], [("pcsx2", True), ("lrps2", False)])
        self.assertEqual(by_name["mednafen_psx_alias"], [("beetle_psx", True)])
        self.assertNotIn("probe_core", by_name)

    def test_the_built_index_resolves_ids_to_sections(self):
        items = {item["id"]: item for item in
                 json.loads(_built(API / "systems.json").read_text())["items"]}
        color = items["wonderswan-color"]
        self.assertEqual(color["name"], "Bandai WonderSwan Color")
        self.assertTrue(color["url"].startswith("/retrobios/systems/bandai/"), color["url"])
        self.assertTrue(items["sony-playstation"]["sha1"])
        cores = json.loads((API / "cores.json").read_text())["items"]
        self.assertIn({"name": "mednafen_psx", "profile": "beetle_psx", "preferred": True}, cores)


class LookupUrlsResolve(unittest.TestCase):
    """8.7: a record's url, joined to the shard holding it, is a page."""

    def test_site_absolute(self):
        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin"}}}
        [item] = generate_site.file_location_items(db)
        self.assertTrue(item["url"].startswith("/retrobios/systems/"), item["url"])
        shard = SITE + "api/v1/lookup/ab.json"
        self.assertTrue(urllib.parse.urljoin(shard, item["url"]).startswith(SITE + "systems/"))

    def test_each_record_names_its_system_as_the_pages_do(self):
        """Find a file opens on "a BIOS file for Sony PlayStation": the name
        comes from system_name, never built in the browser."""
        from siterender import system_name  # noqa: PLC0415

        db = {"files": {"ab" * 20: {"path": "bios/Sony/PlayStation/scph5501.bin",
                                    "name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}}}
        coverages = {"batocera": {"platform": "Batocera", "config": {"systems": {
            "sony-playstation": {"files": [{"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}}}}
        profiles = {"duckstation": {"systems": ["sony-playstation"], "files": [
            {"name": "scph5501.bin", "md5": "490f666e1afb15b7362b406ed1cea246"}]}}
        records = generate_site.file_lookup_records(
            db, coverages, profiles, generate_site.file_location_items(db))
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


class PlatformPagesLinkTheirSystemsAndEmulators(unittest.TestCase):
    """8.9: the overview named emulators as ids, none of 1,463 linked."""

    def test_an_emulator_is_named_and_linked(self):
        link = generate_site._emulator_named_link("beetle_psx", "../")
        self.assertRegex(link, r"^\[[^\]]+\]\(\.\./emulators/beetle_psx\.md\)$")
        self.assertNotEqual(link, "[beetle_psx](../emulators/beetle_psx.md)")

    def test_the_overview_column_uses_it(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        block = source[source.index("### Systems overview"):source.index("_render_platform_systems(by_system")]
        self.assertIn("_emulator_named_link(e, \"../\")", block)
        self.assertNotIn('", ".join(sys_emus[:3])', block)

    def test_a_moved_list_opens_on_its_console_and_names_its_parent(self):
        # Past PLATFORM_SECTION_BUDGET, so the list leaves for a page of its own.
        files = [{"name": f"{'f' * 200}{i}.bin", "status": "ok"} for i in range(2000)]
        moved: dict[str, str] = {}
        generate_site._render_platform_systems(
            {"sony-playstation": files}, {}, {}, ("retroarch", "RetroArch"), moved, {})
        self.assertTrue(moved)
        page = next(iter(moved.values()))
        self.assertTrue(page.startswith('---\nparent:\n  label: "RetroArch"\n'
                                        '  link: "/platforms/retroarch/"\n---\n'), page[:120])
        self.assertRegex(page, r"RetroArch's list for \[Sony PlayStation\]\(\.\./systems/")

    def test_part_pages_of_gaps_and_cross_reference_name_their_parent(self):
        moved: dict[str, str] = {}
        generate_site._list_pages("gaps-x", "T", "intro", [], [["| a |"]], moved,
                                  parent=("What the packs do not hold", "/gaps/"))
        self.assertIn('parent:\n  label: "What the packs do not hold"\n  link: "/gaps/"', moved["gaps-x"])
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('_parent_front_matter(("Cores by platform", "/cross-reference/"))', source)
        self.assertIn('parent=("Dump provenance", "/provenance/")', source)


class TablesFitTheirColumn(unittest.TestCase):
    """8.12 and 8.13: a hash in a cell is 12 characters, the rest in its title."""

    def test_the_downloads_table(self):
        item = {"title": "SQLite snapshot", "url": "downloads/retrobios.sqlite",
                "media_type": "application/vnd.sqlite3", "bytes": 10, "sha256": "a" * 64}
        page = generate_site.generate_data_page([item])
        row = next(line for line in page.splitlines() if "SQLite snapshot" in line and "|" in line)
        self.assertIn(f'<code title="{"a" * 64}">{"a" * 12}</code>', row)
        self.assertNotIn("a" * 13, row.replace(f'title="{"a" * 64}"', ""))

    def test_the_gaps_tables(self):
        problem = {"platform": "Batocera", "name": "x.bin", "status": "untested", "required": True,
                   "reason": "expected md5 differs", "declared": {"md5": ["b" * 32]}, "path": ""}
        table = "\n".join(generate_site._render_problem_files([problem], db={"files": {}}))
        row = next(line for line in table.splitlines() if "x.bin" in line)
        self.assertIn(f'<code title="{"b" * 32}">{"b" * 12}</code>', row)
        self.assertIn('<span class="rb-reason">expected md5 differs</span>', row)
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertIn('expected = f"{algorithm} {short_hash(value)}"', source)
        self.assertIn("{_reason_cell(u['reason'])}", source)


class SourceLinksGoWhereTheFileIs(unittest.TestCase):
    """8.14: trident cited a Panda3DS path and linked it into 3dsTrident."""

    PROFILE = {
        "emulator": "trident", "type": "libretro",
        "source": "https://github.com/DanAlexMorton/3dsTrident",
        "upstream": "https://github.com/wheremyfoodat/Panda3DS",
        "source_commit": "b" * 40,
    }

    def tearDown(self):
        sitesources._tree_paths.cache_clear()

    def _render(self, tree: frozenset[str]) -> str:
        original = sitesources._tree_paths
        sitesources._tree_paths = lambda repo, pin: tree  # type: ignore[assignment]
        try:
            return sitesources._source_ref_markdown(
                self.PROFILE, "src/emulator.cpp:234; src/core/loader/ncch.cpp:151-164")
        finally:
            sitesources._tree_paths = original

    def test_a_path_the_tree_lacks_is_not_linked(self):
        text = self._render(frozenset({"src/emulator.cpp"}))
        self.assertIn("[`src/emulator.cpp:234`](https://github.com/DanAlexMorton/3dsTrident/", text)
        self.assertIn("`src/core/loader/ncch.cpp:151-164`", text)
        self.assertNotIn("3dsTrident/blob/" + "b" * 40 + "/src/core/loader", text)

    def test_a_path_no_tree_confirmed_is_not_linked(self):
        """Without a tree the declared repository took the path,
        and the deploy, which has no tree cache, linked 30 paths to a 404."""
        text = self._render(frozenset())
        self.assertNotIn("](https://", text)
        self.assertIn("`src/core/loader/ncch.cpp:151-164`", text)

    def test_every_rendered_link_is_in_its_cached_tree(self):
        """Offline: each link the pages render points at a path the cached
        tree of its repository holds."""
        if not sitesources.TREE_CACHE.is_dir():
            raise unittest.SkipTest("no cached tree listings")
        from common import load_emulator_profiles  # noqa: PLC0415

        link = re.compile(r"\(https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/([^#)]+)")
        checked, wrong = 0, []
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        for key, profile in sorted(profiles.items()):
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict) or not entry.get("source_ref"):
                    continue
                for slug, pin, path in link.findall(
                        sitesources._source_ref_markdown(profile, entry["source_ref"])):
                    import upstream  # noqa: PLC0415

                    repo = upstream.parse_repo(f"https://github.com/{slug}")
                    held = sitesources.tree_holds(repo, pin, urllib.parse.unquote(path))
                    if held is None:
                        continue
                    checked += 1
                    if not held:
                        wrong.append((key, slug, path))
        if not checked:
            raise unittest.SkipTest("no rendered link has a cached tree")
        self.assertEqual(wrong, [])


DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"


def _page(stem: str) -> str:
    for suffix in (".md", ".mdx"):
        path = DOCS / f"{stem}{suffix}"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise unittest.SkipTest(f"{stem} not generated")


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
        with mock.patch.object(generate_site, "_console_system_names", return_value={}), \
                mock.patch.object(generate_site, "_lookup_system_name", return_value=None), \
                mock.patch.object(generate_site, "emulator_card_page", side_effect=lambda k, a: k):
            return generate_site.file_lookup_records(
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
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            root = Path(tmp) / "bios"
            (root / "sub").mkdir(parents=True)
            for name, data in files.items():
                (root / name).write_bytes(data)
            api = Path(tmp) / "api"
            api.mkdir()
            (api / "emudeck.json").write_text(json.dumps({"items": [{"contract": contract}]}))
            found = check_platform_folder.check("emudeck", root, api.as_uri() + "/")
            # The verifier's verdict on the matching entry, file by file.
            from verify import verify_entry_md5  # noqa: PLC0415

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
        page = generate_site.generate_data_page([])
        self.assertIn("An entry with no `destination` (EmuDeck) names no file", page)
        self.assertLess(len((REPO_ROOT / "scripts" / "check_platform_folder.py")
                            .read_text().splitlines()), 70)


class ManifestFieldsAreComplete(unittest.TestCase):
    """8.3 and 8.4."""

    SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())

    def test_a_url_template_is_code(self):
        rows = generate_site._schema_field_rows(self.SCHEMA["$defs"]["file"], ("repo_path",))
        self.assertIn("`https://raw.githubusercontent.com/Abdess/retrobios/<ref>/<repo_path>`",
                      rows[0])
        rows = generate_site._schema_field_rows(
            {"properties": {"a": {"description": "From https://x.test/<asset>, then."}}}, ("a",))
        self.assertEqual(rows, ["| `a` | From `https://x.test/<asset>`, then. |"])

    def test_every_field_is_described_and_shown(self):
        page = generate_site.generate_data_page([])
        for schema in (self.SCHEMA, self.SCHEMA["$defs"]["file"]):
            for key, spec in schema["properties"].items():
                self.assertTrue(spec.get("description"), key)
                self.assertIn(f"| `{key}` |", page)

    def test_no_link_carries_an_escaped_bracket(self):
        html = _built(DIST / "data" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r'href="[^"]*&amp;lt;')
        self.assertNotRegex(html, r'href="[^"]*&lt;')


class EverySystemIdWithFilesHasAPage(unittest.TestCase):
    """8.5: tyrian, scummvm, dos and 25 more had files and a null url."""

    def test_built_index(self):
        items = json.loads(_built(API / "systems.json").read_text())["items"]
        orphans = [item["id"] for item in items if item["sha1"] and not item["url"]]
        self.assertEqual(orphans, [])

    def test_first_file_then_emulator(self):
        files = {"f" * 40: {"path": "bios/DOS/DOS/a.bin"}}
        with mock.patch("siterender._card_pages", {}):
            place = generate_site._first_file_place(
                "dos", ["f" * 40], files, {}, lambda path, sha1: "dos")
        self.assertEqual(place, ("DOS", "/retrobios/systems/dos/#sha1-ffffffffffff"))
        place = generate_site._first_file_place(
            "tyrian", [], files, {"opentyrian": {"systems": ["tyrian"]}}, None)
        self.assertEqual(place, ("", "/retrobios/emulators/opentyrian/"))


# A source permalink of each forge family the pages write.
_PERMALINK = re.compile(
    r"\]\(https://(?P<host>[^/]+)/(?P<slug>[^/]+/[^/]+)/"
    r"(?:blob/|-/blob/|src/commit/)(?P<pin>[0-9a-f]{40})/(?P<path>[^#)]+)")


class SourceLinksOnlyWhereTheFileIs(unittest.TestCase):
    """8.6: the deploy reads the committed record, never a tree cache."""

    def test_an_address_in_a_binary_reads_as_one(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        text = sitesources._source_ref_markdown(
            profile, "Nesoid 2.5.0 libnes.so 0x455a4-0x45694 (setter), 0x8094-0x80ac")
        self.assertEqual(text, "offset `0x455a4-0x45694` in `Nesoid 2.5.0 libnes.so` (setter), "
                               "offset `0x8094-0x80ac` in `Nesoid 2.5.0 libnes.so`")

    def test_only_a_recorded_path_links(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        repo = upstream.parse_repo("https://github.com/o/r")
        record = {sitesources.tree_key(repo, "e" * 40): frozenset({"src/a.c"})}
        with mock.patch.object(sitesources, "_verified", return_value=record):
            sitesources._tree_paths.cache_clear()
            try:
                text = sitesources._source_ref_markdown(profile, "src/a.c:5, src/b.c:7")
            finally:
                sitesources._tree_paths.cache_clear()
        self.assertIn("[`src/a.c:5`](https://github.com/o/r/blob/" + "e" * 40 + "/src/a.c#L5)", text)
        self.assertIn("`src/b.c:7`", text)
        self.assertNotIn("src/b.c#", text)

    def test_the_writer_keeps_held_paths_only(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "notes": "see src/c.c:3", "files": [{"source_ref": "src/a.c:5, gone.c:1"}]}
        with mock.patch.object(sitesources, "_cached_tree",
                               return_value=frozenset({"src/a.c", "src/c.c", "x.c"})):
            held, unread = sitesources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {"github.com/o/r@" + "e" * 40: ["src/a.c", "src/c.c"]})
        self.assertEqual(unread, [])

    def test_a_tree_no_directory_answers_for_stays_unread(self):
        # TeknoParrotUI answers 404: listed folder by folder, every listing
        # failed and the tree read as holding nothing, so a fetch without its
        # cached tree dropped its four recorded paths.
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "files": [{"source_ref": "src/a.c:5"}]}
        with mock.patch.object(sitesources, "_cached_tree", return_value=None), \
                mock.patch.object(sitesources.upstream, "list_directory",
                                  side_effect=upstream.UpstreamError("HTTP 404")):
            held, unread = sitesources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {})
        self.assertEqual(unread, ["github.com/o/r@" + "e" * 40])

    def test_every_rendered_link_is_recorded(self):
        record = json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8"))
        pages = sorted(_built(DOCS / "emulators").rglob("*.md*")) + sorted(DOCS.glob("gaps*.md*"))
        import measurement_records  # noqa: PLC0415

        # A Tested block links a record line and its data file in this
        # repository. The records are append-only, so a file a permalink
        # names is still in the tree.
        records = set(measurement_records.tree_files(REPO_ROOT))
        checked, stray = 0, []
        for page in pages:
            for found in _PERMALINK.finditer(page.read_text(encoding="utf-8")):
                key = f"{found['host']}/{found['slug']}@{found['pin']}"
                path = urllib.parse.unquote(found["path"])
                if "/Abdess/retrobios/" in found[0]:
                    if path.startswith(f"{measurement_records.RECORDS_DIR}/") and path not in records:
                        stray.append((page.name, key, path))
                    continue
                checked += 1
                if path not in record.get(key, ()):
                    stray.append((page.name, key, path))
        self.assertGreater(checked, 1000)
        self.assertEqual(stray[:20], [])

    def test_the_record_is_read_by_the_deploy(self):
        """The record is committed where the build reads it, sorted."""
        record = json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8"))
        self.assertGreater(len(record), 300)
        for key, paths in record.items():
            self.assertRegex(key, r"^[a-z0-9.-]+/.+@[0-9a-f]{40}$")
            self.assertEqual(paths, sorted(set(paths)), key)


class TheReferencePagesAnswerTheirWords(unittest.TestCase):
    """8.7, 8.8, 8.10 and 8.13."""

    def test_find_or_check_a_file(self):
        page = generate_site.generate_files_page()
        self.assertTrue(page.startswith(
            "---\nterms: check my dump, md5 check, verify bios file, check hash, "
            "is my bios correct, is my bios right\n---\n"))
        self.assertIn("\n# Find or check a file\n\nCheck a BIOS dump: paste its hash "
                      "or choose the file.\n", page)

    def test_the_data_page(self):
        page = generate_site.generate_data_page([])
        self.assertTrue(page.startswith(
            "---\nterms: manifest, schema, json schema, license, check a folder, "
            "check bios folder script, rate limit, api\n---\n"))
        self.assertIn("## Hosting, rate limits and caching", page)
        self.assertIn("HTTP 429", page)
        self.assertIn("crypto.subtle.digest(\"SHA-1\"", page)
        self.assertIn("api/v1/lookup/", page)
        self.assertIn("`preferred: true`", page)
        self.assertIn("`database.json`, `stats.json`, `release.json` and the manifests are not "
                      "envelopes", page)
        self.assertIn("- MinUI, MyMinUI and NextUI have no list of their own "
                      "(`native_list: none`). An empty list does not mean nothing is needed.", page)

    def test_overview_ids_and_counts_are_not_indexed(self):
        html = _built(DIST / "platforms" / "batocera" / "index.html").read_text(encoding="utf-8")
        self.assertRegex(html, r"<small data-pagefind-ignore(=\"true\")?>sony-playstation</small>")
        self.assertRegex(html, r"<span data-pagefind-ignore(=\"true\")?>\d+/\d+</span>")


class TheReleaseRecordHasAVersion(unittest.TestCase):
    """8.9."""

    def test_the_writer_and_the_committed_record(self):
        self.assertEqual(release_record.SCHEMA_VERSION, 1)
        source = (REPO_ROOT / "scripts" / "release_record.py").read_text(encoding="utf-8")
        self.assertIn('{"schema_version": SCHEMA_VERSION, "tag": tag, "packs": packs}', source)
        schema = json.loads((REPO_ROOT / "schemas" / "release.schema.json").read_text())
        self.assertIn("schema_version", schema["required"])
        record = json.loads((REPO_ROOT / "release.json").read_text())
        self.assertEqual(record["schema_version"], 1)


class NoEmptyCoreTable(unittest.TestCase):
    """8.11: MiSTer and BizHawk declare cores: [] and had a page of nothing."""

    def test_own_list_platforms_get_a_sentence(self):
        coverages = {"misterfpga": {"platform": "MiSTer FPGA", "config": {"cores": [], "systems": {}}}}
        moved: dict[str, str] = {}
        page = generate_site.generate_cross_reference(coverages, {}, moved)
        self.assertEqual(moved, {})
        self.assertIn(generate_site.OWN_LIST_ONLY, page)

    def test_built_pages(self):
        _built(DOCS / "cross-reference.md")
        for name in ("misterfpga", "bizhawk"):
            self.assertFalse((DOCS / f"cross-reference-{name}.md").exists())
            self.assertIn(generate_site.OWN_LIST_ONLY, _page(f"platforms/{name}"))
        redirects = json.loads((REPO_ROOT / "website" / "src" / "generated" /
                                "redirects.json").read_text())
        self.assertEqual(redirects.get("/cross-reference-misterfpga/"), "/platforms/misterfpga/")


class FilesToSourceOnAPhone(unittest.TestCase):
    """8.12: 601 rows on one page, no way to give a file."""

    def test_parts_of_a_hundred_rows_each_with_an_upload(self):
        _built(DOCS / "gaps-files-to-source.md")
        parts = sorted(DOCS.glob("gaps-files-to-source*.md"))
        self.assertGreater(len(parts), 1)
        for part in parts:
            rows = [line for line in part.read_text(encoding="utf-8").splitlines()
                    if line.startswith("| `")]
            self.assertLessEqual(len(rows), generate_site.FILES_TO_SOURCE_PART, part.name)
            for row in rows:
                self.assertIn(f"[Have it? Upload]({generate_site.UPLOAD_URL}", row)

    def test_the_upload_lands_in_the_folder_the_review_asks_for(self):
        """The link read the profile's first system: Raze's Duke Nukem 3D
        files were sent to bios/Monolith/Blood/. It reads validate_pr's
        placement now (tests/test_site_wanted.py)."""
        held = "a" * 40
        db = {"files": {held: {"path": "bios/Sony/PlayStation/scph1001.bin"}},
              "indexes": {"by_md5": {}, "by_sha256": {}, "by_name": {}}}
        profile_hashes = {"folders": {"b" * 40: {"bios/Sony/PlayStation/"}}, "named": {}}
        placer = sitewanted.Placer(db, {}, profile_hashes)
        self.assertEqual(placer.folder({"name": "scph5501.bin", "sha1": "b" * 40}),
                         "bios/Sony/PlayStation/")
        self.assertEqual(placer.folder({"name": "x.bin"}), "")


GENERATED = REPO_ROOT / "website" / "src" / "generated"
SCHEMA = json.loads((REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text())


def _released() -> set[str]:
    return set(list_release_pack_platforms(str(REPO_ROOT / "platforms")))


class OneAnswerOnReleasePacks(unittest.TestCase):
    """8.1: the API, the picker's data and the pages read the registry."""

    def test_a_child_does_not_inherit_its_parents_pack(self):
        _contract, registry = generate_site._split_contract(
            {"_key": "lakka", "inherits": "retroarch", "release_pack": True})
        self.assertIs(registry["release_pack"], "lakka" in _released())
        _contract, registry = generate_site._split_contract({"_key": "minui"})
        self.assertNotIn("release_pack", registry)
        _contract, registry = generate_site._split_contract({"_key": "retroarch"})
        self.assertIs(registry["release_pack"], "retroarch" in _released())

    def test_api_release_pack_set_equals_the_registry(self):
        found = set()
        for path in _built(API / "platforms").glob("*.json"):
            item = json.loads(path.read_text())["items"][0]
            if item["registry"].get("release_pack"):
                found.add(item["id"])
        self.assertEqual(found, _released())

    def test_the_picker_file_is_the_advertised_record(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir()
                                         else None) as folder:
            generate_site.write_release_advertised(Path(folder))
            written = json.loads((Path(folder) / "release-advertised.json").read_text())
        self.assertEqual(written, release_record.load_advertised())
        served = {p for pack in written.get("packs", {}).values() for p in pack["platforms"]}
        self.assertLessEqual(served, _released())

    def test_the_built_picker_file(self):
        written = json.loads(_built(GENERATED / "release-advertised.json").read_text())
        self.assertEqual(written, release_record.load_advertised())


def _properties(node: object, path: str = ""):
    """(path, spec) of every property at any depth, $defs included."""
    if not isinstance(node, dict):
        return
    for key, spec in (node.get("properties") or {}).items():
        yield f"{path}{key}", spec
        yield from _properties(spec, f"{path}{key}.")
    for key in ("items", "additionalProperties"):
        yield from _properties(node.get(key), path)
    for name, spec in (node.get("$defs") or {}).items():
        yield from _properties(spec, f"#{name}.")
    for key in ("oneOf", "anyOf", "allOf"):
        for spec in node.get(key) or []:
            yield from _properties(spec, path)


class EveryManifestFieldIsDescribed(unittest.TestCase):
    """8.2: every property at any depth, and each omission code."""

    def test_every_property_has_a_description(self):
        missing = [path for path, spec in _properties(SCHEMA)
                   if isinstance(spec, dict) and not spec.get("description")]
        self.assertEqual(missing, [])

    def test_each_reason_code_has_a_line(self):
        page = generate_site.generate_data_page([])
        for path, spec in _properties(SCHEMA):
            if path.endswith(".reason"):
                self.assertEqual(len(spec["enumDescriptions"]), len(spec["enum"]), path)
                for code in spec["enum"]:
                    self.assertRegex(page, rf"\n- `{code}`: \S")

    def test_nested_tables_are_on_the_page(self):
        page = generate_site.generate_data_page([])
        for label in ("Each entry of `omitted_files`:", "Each entry of `data_directories`:",
                      "Each value of `data_directories[].files`:", "Fields of `save_directory`:",
                      "Each entry of `files[].alternatives`:",
                      "Each entry of `files[].slot_choices`:",
                      "Each entry of `files[].declared_choices`:",
                      "Each entry of `files[].absent_claims`:"):
            self.assertIn(label, page)
        for key in ("below_platform_folder", "strip_components", "by_core"):
            self.assertIn(f"`{key}`", page)


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
        with mock.patch.object(generate_site, "_console_system_names", return_value={}), \
                mock.patch.object(generate_site, "_lookup_system_name", return_value=None), \
                mock.patch.object(generate_site, "emulator_card_page", side_effect=lambda k, a: k):
            return generate_site.file_lookup_records(
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


class TheDataPageListsWhatIsServed(unittest.TestCase):
    """8.4 and 8.6."""

    def test_every_schema_is_listed(self):
        page = generate_site.generate_data_page([])
        for path in (REPO_ROOT / "schemas").glob("*.schema.json"):
            self.assertIn(f"- [`{path.name}`](api/v1/schemas/{path.name}): ", page)

    def test_target_lists_are_published_and_catalogued(self):
        catalog = json.loads(_built(API / "catalog.json").read_text())
        listed = {item["url"] for item in catalog["items"]}
        for source in (REPO_ROOT / "install" / "targets").glob("*.json"):
            self.assertIn(f"targets/{source.name}", listed)
            self.assertEqual((API / "targets" / source.name).read_bytes(), source.read_bytes())

    def test_declared_only_and_search_words(self):
        page = generate_site.generate_data_page([])
        self.assertIn("With `--declared-only`, or from the `declared` event, "
                      "`install.py --check` answers it too.", page)
        terms = page.split("\n", 2)[1]
        for word in ("json schema", "license", "check bios folder script"):
            self.assertIn(word, terms)
        files_terms = generate_site.generate_files_page().split("---\n", 2)[1]
        for word in ("is my bios correct", "is my bios right"):
            self.assertIn(word, files_terms)


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
                      generate_site.generate_data_page([]))


class SystemItemsCarryTheirApi(unittest.TestCase):
    """8.7."""

    def test_each_api_address_is_served(self):
        items = json.loads(_built(API / "systems.json").read_text())["items"]
        playstation = next(i for i in items if i["id"] == "sony-playstation")
        self.assertEqual(playstation["api"], "/retrobios/api/v1/systems/sony.json")
        for item in items:
            if item["url"] is not None:
                self.assertIsNotNone(item["api"], item["id"])
            if item["api"]:
                self.assertTrue((PUBLIC / item["api"].removeprefix("/retrobios/")).is_file(),
                                item["api"])


if __name__ == "__main__":
    unittest.main()
