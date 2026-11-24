"""Reference pages: citations, source links, tables.

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
"""

from __future__ import annotations

import tests
from tests import sitepages
from tests.sources import script_source

import json
import re
import unittest
from pathlib import Path
from unittest import mock
import tempfile
import urllib.parse
import urllib.error

from model import siteinputs
from sitegen import crossref
from sitegen import datapage
from sitegen import gaps
from sitegen import gapproblems
from sitegen import gapsources
from sitegen import lookup
from sitegen import parts as sitegen_parts
from sitegen import platformfiles
from sitegen import platformindex
from sitegen import platformpage
from sitegen import provenance
from sitegen import wanted as sitewanted
from sitegen import runsections
from model.registry import list_registered_platforms
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from core.hashing import HASH_FIELDS, parse_hash_list
from resolve.categories import EntryCategories
from sitegen.sources import launcher_ref_markdown, list_source
import core
from sitegen import sources
from core import upstream
from core import forgehttp
from packs.verdicts import Severity, blocking_missing, compute_severity
from tests.sitepages import DIST, REPO_ROOT, built


PLATFORMS = str(REPO_ROOT / "platforms")


def _accepted(profile_entry: dict) -> set[str]:
    values = {v for f in HASH_FIELDS for v in parse_hash_list(profile_entry.get(f))}
    for member in profile_entry.get("contents") or []:
        if isinstance(member, dict):
            values |= {v for f in HASH_FIELDS for v in parse_hash_list(member.get(f))}
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
                    md5s = set(parse_hash_list(entry.get("md5"))) | set(parse_hash_list(entry.get("alt_md5")))
                    if not md5s:
                        continue
                    # The same dump, named by whichever hash both sides state.
                    declared = md5s | {v for f in HASH_FIELDS for v in parse_hash_list(entry.get(f))}
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
        text = platformfiles._category_evidence_md(evidence)
        self.assertRegex(text, r"\[`frontend/libretro\.c:3864-3867`\]\(https://github\.com/"
                               r"libretro/pcsx_rearmed/blob/[0-9a-f]{40}/frontend/libretro\.c"
                               r"#L3864-L3867\)")
        self.assertIn("(by name)", text)
        self.assertNotIn("`source ", text)

    def test_launcher_record_named_with_its_lines(self):
        evidence = {"read_by": [{"emulator": "launcher", "proof": "launcher",
                                 "entries": [], "runs_system": True}]}
        config = load_platform_config("batocera", PLATFORMS)
        launched = platformfiles._launcher_refs(config)["scph1001.bin"]
        text = platformfiles._category_evidence_md(evidence, launched)
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
                rendered = [text for texts in platformfiles._launcher_refs(config).values()
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

    def test_a_list_link_is_the_source_permalink(self):
        """browse() built its own GitHub and GitLab URLs, a space left unquoted."""
        github = list_source("https://github.com/o/r/blob/v1/dir/a b.cs")
        self.assertEqual(github.browse(start=3, end=5), "https://github.com/o/r/blob/v1/dir/a%20b.cs#L3-L5")
        self.assertEqual(list_source("https://codeload.github.com/o/r/tar.gz/v1").browse(),
                         "https://github.com/o/r/tree/v1")
        gitlab = list_source("https://gitlab.com/o/r/-/raw/v1/es_bios.xml")
        self.assertEqual(gitlab.browse(start=3, end=5), "https://gitlab.com/o/r/-/blob/v1/es_bios.xml#L3-5")
        tree = list_source("https://gitlab.com/recalbox/recalbox/-/tree/10.1.1/configs")
        self.assertEqual(tree.browse(), "https://gitlab.com/recalbox/recalbox/-/blob/10.1.1/configs")


class EachEntryNamesItsFile(unittest.TestCase):
    def test_served_held_and_missing(self):
        path, digest = next(
            (entry["path"], d)
            for d, entry in platformfiles._collection_db(str(siteinputs.current().db))["files"].items()
            if entry["path"].startswith("bios/") and entry["path"].count("/") >= 3)
        served = platformfiles._served_line({"status": "ok", "path": path})
        self.assertRegex(served, rf"\]\(\.\./systems/[^)]+\.md#sha1-{digest[:12]}\)")
        self.assertTrue(served.startswith("Served by: "))
        self.assertIn(f"`{digest[:8]}`", served)
        # The row already shows the declared sha1: repeating it said nothing.
        quiet = platformfiles._served_line({"status": "ok", "path": path}, f"aaaa, {digest.upper()}")
        self.assertNotIn(digest[:8], quiet.split(")", 1)[1])
        self.assertIn(f"`{digest[:8]}`", platformfiles._served_line(
            {"status": "ok", "path": path}, "a" * 40))
        self.assertEqual(platformfiles._served_line({"status": "missing"}), "Not held")
        self.assertTrue(platformfiles._served_line(
            {"status": "untested", "path": path}).startswith("Held, not the declared hash"))
        # Existence mode reports no path: nothing is claimed, held or not.
        self.assertEqual(platformfiles._served_line({"status": "ok"}), "")

    def test_a_long_system_list_is_cut_between_rows_by_elements(self):
        rows = [[f'<details class="rb-file"><summary>f{n}.bin</summary>x<br>y</details>']
                for n in range(4)]
        # Three elements a row: two rows fit in a budget of seven.
        runs = sitegen_parts.blocks_in_runs(rows, 7, platformfiles._element_weight)
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
        text = platformfiles._category_evidence_md(evidence)
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
        return platformpage.generate_platform_page("p", cov, registry or {})

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
               "core_present": 0, "core_missing": 0, "core_unplaced": 0,
               "core_unsourceable": 0,
               "config": {"hash_type": "md5", "hash_rule": "size_and_any_hash",
                          "systems": {"sony-playstation": {"files": [{"name": "f.bin"}]}},
                          "source": "https://github.com/o/r/tree/" + "a" * 40}}
        page = platformpage.generate_platform_page("romm", cov, {})
        self.assertIn(">size, then any hash</span>", page)
        self.assertNotIn(">MD5</span>", page)
        table = "\n".join(platformindex.setup_table({"romm": cov}))
        self.assertIn("| size, then any hash |", table)

    def test_systems_by_name_with_the_id_in_small_text(self):
        systems = {"sony-playstation": {"files": [{"name": "f.bin"}]}}
        page = self._page("md5", "md5", systems)
        name = runsections.system_name("sony-playstation")
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
        self.assertNotIn("rb-badge", gaps._ratio_cell(99, 100))
        self.assertIn('class="rb-bar"', gaps._ratio_cell(99, 100))
        self.assertIn("rb-badge-danger", gaps._ratio_cell(99, 100, 1))
        self.assertNotIn("_missing_required_firmware", script_source("generate_site.py"))

    def test_blocking_missing_reads_verify_severity(self):
        """The badge is verify's count: a required gap with an HLE fallback
        is INFO there and stopped no console, yet the page counted it."""
        def gap(mode: str, hle: bool) -> int:
            severity = compute_severity("missing", True, mode, hle)
            return blocking_missing({severity: 1}, mode)
        for mode in ("existence", "md5", "sha1"):
            self.assertEqual(gap(mode, False), 1, mode)
            self.assertEqual(gap(mode, True), 0, mode)
        self.assertEqual(blocking_missing({Severity.WARNING: 2}, "md5"), 0)

    def test_headings_and_header(self):
        source = script_source("generate_site.py")
        body = source[source.index("def generate_gap_analysis("):]
        body = body[:body.index("\ndef ", 10)]
        self.assertIn('"# What the packs do not hold"', body)
        self.assertIn("On its BIOS list (destinations)", body)
        self.assertIn('"### Files to source"', body)
        self.assertNotIn("### Files to source (", body)


class UpstreamsGrouped(unittest.TestCase):
    def test_mame_trees_are_one_project(self):
        keys = {crossref.upstream_project(u)[0] for u in (
            "https://github.com/mamedev/mame",
            "https://github.com/mamedev/mame/tree/mame0289",
            "https://github.com/mamedev/mame/tree/mame0135u4",
        )}
        self.assertEqual(keys, {"github.com/mamedev/mame"})
        self.assertEqual(crossref.upstream_project(
            "https://github.com/mamedev/mame/tree/mame0289")[1], "mame0289")

    def test_nested_groups_notes_and_archives(self):
        project = crossref.upstream_project
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
        self.assertEqual(crossref._upstream_label(key),
                         "Software Heritage revision dc20a615275f")

    def test_overview_and_a_page_per_platform(self):
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        coverages = {}
        for name in ("batocera", "retroarch"):
            config = load_platform_config(name, PLATFORMS)
            coverages[name] = {"platform": config.get("platform", name), "config": config}
        moved: dict[str, str] = {}
        page = crossref.generate_cross_reference(coverages, profiles, moved)
        self.assertEqual(set(moved), {"cross-reference-batocera", "cross-reference-retroarch"})
        self.assertNotIn("<details", page)
        upstream = page[page.index("## By upstream emulator"):]
        self.assertEqual(len(re.findall(r"\| \[mamedev/<wbr>mame\]\(", upstream)), 1)
        header = next(line for line in upstream.splitlines() if line.startswith("| Cores"))
        self.assertTrue(header.startswith("| Cores | Upstream |"))


class DatesAndNames(unittest.TestCase):
    def test_snapshot_date_in_words(self):
        self.assertEqual(provenance._date_in_words("2026-08-07T10:00:00Z"),
                         '<time datetime="2026-08-07">7 August 2026</time>')

    def test_data_page_title(self):
        self.assertIn("\n---\n\n# Data and API\n", datapage.generate_data_page([]))


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


TMP = Path(tempfile.gettempdir())


class PlatformPagesLinkTheirSystemsAndEmulators(unittest.TestCase):
    """8.9: the overview named emulators as ids, none of 1,463 linked."""

    def test_an_emulator_is_named_and_linked(self):
        link = platformfiles.emulator_named_link("beetle_psx", "../")
        self.assertRegex(link, r"^\[[^\]]+\]\(\.\./emulators/beetle_psx\.md\)$")
        self.assertNotEqual(link, "[beetle_psx](../emulators/beetle_psx.md)")

    def test_the_overview_column_uses_it(self):
        source = script_source("generate_site.py")
        block = source[source.index("### Systems overview"):source.index("render_platform_systems(by_system")]
        self.assertIn("emulator_named_link(e, \"../\")", block)
        self.assertNotIn('", ".join(sys_emus[:3])', block)

    def test_a_moved_list_opens_on_its_console_and_names_its_parent(self):
        # Past PLATFORM_SECTION_BUDGET, so the list leaves for a page of its own.
        files = [{"name": f"{'f' * 200}{i}.bin", "status": "ok"} for i in range(2000)]
        moved: dict[str, str] = {}
        platformfiles.render_platform_systems(
            {"sony-playstation": files}, {}, {}, ("retroarch", "RetroArch"), moved, {})
        self.assertTrue(moved)
        page = next(iter(moved.values()))
        self.assertTrue(page.startswith('---\nparent:\n  label: "RetroArch"\n'
                                        '  link: "/platforms/retroarch/"\n---\n'), page[:120])
        self.assertRegex(page, r"RetroArch's list for \[Sony PlayStation\]\(\.\./systems/")

    def test_part_pages_of_gaps_and_cross_reference_name_their_parent(self):
        moved: dict[str, str] = {}
        sitegen_parts.list_pages("gaps-x", "T", "intro", [], [["| a |"]], moved,
                                  parent=("What the packs do not hold", "/gaps/"))
        self.assertIn('parent:\n  label: "What the packs do not hold"\n  link: "/gaps/"', moved["gaps-x"])
        source = script_source("generate_site.py")
        self.assertIn('parent_front_matter(("Cores by platform", "/cross-reference/"))', source)
        self.assertIn('parent=("Dump provenance", "/provenance/")', source)


class TablesFitTheirColumn(unittest.TestCase):
    """8.12 and 8.13: a hash in a cell is 12 characters, the rest in its title."""

    def test_the_downloads_table(self):
        item = {"title": "SQLite snapshot", "url": "downloads/retrobios.sqlite",
                "media_type": "application/vnd.sqlite3", "bytes": 10, "sha256": "a" * 64}
        page = datapage.generate_data_page([item])
        row = next(line for line in page.splitlines() if "SQLite snapshot" in line and "|" in line)
        self.assertIn(f'<code title="{"a" * 64}">{"a" * 12}</code>', row)
        self.assertNotIn("a" * 13, row.replace(f'title="{"a" * 64}"', ""))

    def test_the_gaps_tables(self):
        problem = {"platform": "Batocera", "name": "x.bin", "status": "untested", "required": True,
                   "reason": "expected md5 differs", "declared": {"md5": ["b" * 32]}, "path": ""}
        table = "\n".join(gapproblems.render_problem_files([problem], db={"files": {}}))
        row = next(line for line in table.splitlines() if "x.bin" in line)
        self.assertIn(f'<code title="{"b" * 32}">{"b" * 12}</code>', row)
        self.assertIn('<span class="rb-reason">expected md5 differs</span>', row)
        source = script_source("generate_site.py")
        self.assertIn('expected = f"{algorithm} {short_hash(value)}"', source)
        self.assertIn("{reason_cell(u['reason'])}", source)


class SourceLinksGoWhereTheFileIs(unittest.TestCase):
    """8.14: trident cited a Panda3DS path and linked it into 3dsTrident."""

    PROFILE = {
        "emulator": "trident", "type": "libretro",
        "source": "https://github.com/DanAlexMorton/3dsTrident",
        "upstream": "https://github.com/wheremyfoodat/Panda3DS",
        "source_commit": "b" * 40,
    }

    def tearDown(self):
        sources._tree_paths.cache_clear()

    def _render(self, tree: frozenset[str]) -> str:
        original = sources._tree_paths
        sources._tree_paths = lambda repo, pin: tree
        try:
            return sources.source_ref_markdown(
                self.PROFILE, "src/emulator.cpp:234; src/core/loader/ncch.cpp:151-164")
        finally:
            sources._tree_paths = original

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
        if not sources.TREE_CACHE.is_dir():
            raise unittest.SkipTest("no cached tree listings")
        from model.profiles import load_emulator_profiles

        link = re.compile(r"\(https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/([^#)]+)")
        checked, wrong = 0, []
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        for key, profile in sorted(profiles.items()):
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict) or not entry.get("source_ref"):
                    continue
                for slug, pin, path in link.findall(
                        sources.source_ref_markdown(profile, entry["source_ref"])):
                    from core import upstream

                    repo = upstream.parse_repo(f"https://github.com/{slug}")
                    held = sources.tree_holds(repo, pin, urllib.parse.unquote(path))
                    if held is None:
                        continue
                    checked += 1
                    if not held:
                        wrong.append((key, slug, path))
        if not checked:
            raise unittest.SkipTest("no rendered link has a cached tree")
        self.assertEqual(wrong, [])


DOCS = REPO_ROOT / "website" / "src" / "content" / "docs"


# A source permalink of each forge family the pages write.
_PERMALINK = re.compile(
    r"\]\(https://(?P<host>[^/]+)/(?P<slug>[^/]+/[^/]+)/"
    r"(?:blob/|-/blob/|src/commit/)(?P<pin>[0-9a-f]{40})/(?P<path>[^#)]+)")


class SourceLinksOnlyWhereTheFileIs(unittest.TestCase):
    """8.6: the deploy reads the committed record, never a tree cache."""

    def test_an_address_in_a_binary_reads_as_one(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        text = sources.source_ref_markdown(
            profile, "Nesoid 2.5.0 libnes.so 0x455a4-0x45694 (setter), 0x8094-0x80ac")
        self.assertEqual(text, "offset `0x455a4-0x45694` in `Nesoid 2.5.0 libnes.so` (setter), "
                               "offset `0x8094-0x80ac` in `Nesoid 2.5.0 libnes.so`")

    def test_only_a_recorded_path_links(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40}
        repo = upstream.parse_repo("https://github.com/o/r")
        record = {sources.tree_key(repo, "e" * 40): frozenset({"src/a.c"})}
        with mock.patch.object(sources, "_verified", return_value=record):
            sources._tree_paths.cache_clear()
            try:
                text = sources.source_ref_markdown(profile, "src/a.c:5, src/b.c:7")
            finally:
                sources._tree_paths.cache_clear()
        self.assertIn("[`src/a.c:5`](https://github.com/o/r/blob/" + "e" * 40 + "/src/a.c#L5)", text)
        self.assertIn("`src/b.c:7`", text)
        self.assertNotIn("src/b.c#", text)

    def test_the_writer_keeps_held_paths_only(self):
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "notes": "see src/c.c:3", "files": [{"source_ref": "src/a.c:5, gone.c:1"}]}
        with mock.patch.object(sources, "_cached_tree",
                               return_value=frozenset({"src/a.c", "src/c.c", "x.c"})):
            held, unread = sources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {"github.com/o/r@" + "e" * 40: ["src/a.c", "src/c.c"]})
        self.assertEqual(unread, [])

    def test_a_tree_no_directory_answers_for_stays_unread(self):
        # TeknoParrotUI answers 404: listed folder by folder, every listing
        # failed and the tree read as holding nothing, so a fetch without its
        # cached tree dropped its four recorded paths.
        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "files": [{"source_ref": "src/a.c:5"}]}
        with mock.patch.object(sources, "_cached_tree", return_value=None), \
                mock.patch.object(core.upstreamtree, "list_directory",
                                  side_effect=forgehttp.UpstreamError("HTTP 404")):
            held, unread = sources.build_source_paths({"p": profile}, [TMP])
        self.assertEqual(held, {})
        self.assertEqual(unread, ["github.com/o/r@" + "e" * 40])

    def test_every_rendered_link_is_recorded(self):
        record = json.loads(sources.SOURCE_PATHS.read_text(encoding="utf-8"))
        pages = sorted(built(DOCS / "emulators").rglob("*.md*")) + sorted(DOCS.glob("gaps*.md*"))
        from model import measurements as mr

        # A Tested block links a record line and its data file in this
        # repository. The records are append-only, so a file a permalink
        # names is still in the tree.
        records = set(mr.tree_files(REPO_ROOT))
        checked, stray = 0, []
        for page in pages:
            for found in _PERMALINK.finditer(page.read_text(encoding="utf-8")):
                key = f"{found['host']}/{found['slug']}@{found['pin']}"
                path = urllib.parse.unquote(found["path"])
                if "/Abdess/retrobios/" in found[0]:
                    if path.startswith(f"{mr.RECORDS_DIR}/") and path not in records:
                        stray.append((page.name, key, path))
                    continue
                checked += 1
                if path not in record.get(key, ()):
                    stray.append((page.name, key, path))
        self.assertGreater(checked, 1000)
        self.assertEqual(stray[:20], [])

    def test_the_record_is_read_by_the_deploy(self):
        """The record is committed where the build reads it, sorted."""
        record = json.loads(sources.SOURCE_PATHS.read_text(encoding="utf-8"))
        self.assertGreater(len(record), 300)
        for key, paths in record.items():
            self.assertRegex(key, r"^[a-z0-9.-]+/.+@[0-9a-f]{40}$")
            self.assertEqual(paths, sorted(set(paths)), key)


class TheReferencePagesAnswerTheirWords(unittest.TestCase):
    """8.7, 8.8, 8.10 and 8.13."""

    def test_find_or_check_a_file(self):
        page = lookup.generate_files_page()
        self.assertTrue(page.startswith(
            "---\nterms: check my dump, md5 check, verify bios file, check hash, "
            "is my bios correct, is my bios right\n---\n"))
        self.assertIn("\n# Find or check a file\n\nCheck a BIOS dump: paste its hash "
                      "or choose the file.\n", page)

    def test_the_data_page(self):
        page = datapage.generate_data_page([])
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
        html = built(DIST / "platforms" / "batocera" / "index.html").read_text(encoding="utf-8")
        self.assertRegex(html, r"<small data-pagefind-ignore(=\"true\")?>sony-playstation</small>")
        self.assertRegex(html, r"<span data-pagefind-ignore(=\"true\")?>\d+/\d+</span>")


class NoEmptyCoreTable(unittest.TestCase):
    """8.11: MiSTer and BizHawk declare cores: [] and had a page of nothing."""

    def test_own_list_platforms_get_a_sentence(self):
        coverages = {"misterfpga": {"platform": "MiSTer FPGA", "config": {"cores": [], "systems": {}}}}
        moved: dict[str, str] = {}
        page = crossref.generate_cross_reference(coverages, {}, moved)
        self.assertEqual(moved, {})
        self.assertIn(platformpage.OWN_LIST_ONLY, page)

    def test_built_pages(self):
        built(DOCS / "cross-reference.md")
        for name in ("misterfpga", "bizhawk"):
            self.assertFalse((DOCS / f"cross-reference-{name}.md").exists())
            page = sitepages.page(f"platforms/{name}.md").read_text(encoding="utf-8")
            self.assertIn(platformpage.OWN_LIST_ONLY, page)
        redirects = json.loads((REPO_ROOT / "website" / "src" / "generated" /
                                "redirects.json").read_text())
        self.assertEqual(redirects.get("/cross-reference-misterfpga/"), "/platforms/misterfpga/")


class FilesToSourceOnAPhone(unittest.TestCase):
    """8.12: 601 rows on one page, no way to give a file."""

    def test_parts_of_a_hundred_rows_each_with_an_upload(self):
        built(DOCS / "gaps-files-to-source.md")
        parts = sorted(DOCS.glob("gaps-files-to-source*.md"))
        self.assertGreater(len(parts), 1)
        for part in parts:
            rows = [line for line in part.read_text(encoding="utf-8").splitlines()
                    if line.startswith("| `")]
            self.assertLessEqual(len(rows), gapsources.FILES_TO_SOURCE_PART, part.name)
            for row in rows:
                self.assertIn(f"[Have it? Upload]({gapsources.UPLOAD_URL}", row)

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


class LongGapTablesOnPagesOfTheirOwn(unittest.TestCase):
    """Mobile Lighthouse Performance stayed at 99 on /gaps/: two tables of
    340 and 283 rows were 8,300 elements, laid out in one 200 ms task.
    Each moved to a page of its own, its heading and anchor kept on the
    gaps page with the row count."""

    def _page(self, moved: dict[str, str] | None) -> str:
        unsourced = {"name": "KANJI2.ROM", "reason": "no dump distributed", "source_ref": ""}
        gap = {"name": "a.bin", "path": "a.bin", "required": True, "source": "missing",
               "in_repo": False, "identity": "", "source_ref": ""}
        report = {"xm7": {"emulator": "XM7", "gaps": 1, "gap_missing": 1, "gap_bios": 0,
                          "gap_data": 0, "gap_large_file": 0, "gap_bundled": 0,
                          "unsourceable": [unsourced], "gap_details": [gap]}}
        return gaps.generate_gap_analysis(
            {"xm7": {"emulator": "XM7", "files": []}}, {}, {"files": {}, "indexes": {}},
            gap_report=report, listing=gapsources.SourceListing(moved=moved))

    def test_both_tables_leave_with_their_anchors_kept(self):
        moved: dict[str, str] = {}
        page = self._page(moved)
        self.assertEqual(set(moved) - {"gaps-files-to-source"},
                         {gapsources.PER_EMULATOR_STEM, gapsources.NOT_COLLECTED_STEM})
        self.assertNotIn("| Emulator | Undeclared |", page)
        self.assertNotIn("| File | Emulator | Reason |", page)
        self.assertIn("### Per emulator", page)
        self.assertIn("1 emulator, listed on [a page of their own](gaps-per-emulator.md).", page)
        self.assertIn('<span id="acknowledged-gaps"></span>', page)
        self.assertIn("## Not collected yet", page)
        self.assertIn("[a page of their own](gaps-not-collected.md)", page)
        own = moved[gapsources.NOT_COLLECTED_STEM]
        self.assertIn('link: "/gaps/"', own)
        self.assertIn("| `KANJI2.ROM` | XM7 |", own)
        self.assertIn("gaps.md#not-collected-yet", own)
        self.assertIn("| [XM7](emulators/xm7.md) | 1 |", moved[gapsources.PER_EMULATOR_STEM])

    def test_without_pages_the_tables_stay(self):
        page = self._page(None)
        self.assertIn("| Emulator | Undeclared |", page)
        self.assertIn("| `KANJI2.ROM` | XM7 |", page)


if __name__ == "__main__":
    unittest.main()
