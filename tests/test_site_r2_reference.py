"""Reference pages (round 2, package 8).

A reference page cites a hash, a source line or a count, and each citation
has to hold when an expert checks it: the reader of a pinned dump is the
profile entry accepting its hash, a source line is a pinned link, an entry
names the file that serves it, and the exports carry what the page shows.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import siterender  # noqa: E402
from common import (  # noqa: E402
    list_registered_platforms,
    load_emulator_profiles,
    load_platform_config,
)
from exporter.baseline import HASH_FIELDS, _hash_values  # noqa: E402
from exporter.candidates import EntryCategories  # noqa: E402
from sitesources import launcher_ref_markdown, list_source  # noqa: E402

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
        for platform in list_registered_platforms(PLATFORMS, include_archived=True):
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
        launched = generate_site._launcher_refs("batocera", config)["scph1001.bin"]
        text = generate_site._category_evidence_md(evidence, launched)
        self.assertNotIn("(by launcher)", text)
        self.assertIn("https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/"
                      "package/batocera/core/batocera-configgen/", text)
        self.assertIn("duckstationGenerator.py:115-136", text)

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
        table = "\n".join(generate_site.setup_table({"romm": cov}, {}))
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
        html = "".join(pages)
        for text in ("Served by:", "scph1001_v20.bin", "https://github.com/stenzek/duckstation/blob/"):
            with self.subTest(text=text):
                self.assertTrue(text in html)
        self.assertFalse("(by launcher)" in html)

if __name__ == "__main__":
    unittest.main()
