"""Renderings shared by the site pages, and the icon copies they read."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import siterender  # noqa: E402


class IconsComeFromTheLocalCopies(unittest.TestCase):
    """Icons were checked against upstream with a HEAD request per system on
    every build, and linked from a branch tip. The build now reads the copies
    in docs_assets/system-icons and makes no request."""

    def setUp(self) -> None:
        saved = dict(siterender._icon_available)
        self.addCleanup(lambda: (siterender._icon_available.clear(),
                                 siterender._icon_available.update(saved)))

    def test_availability_is_the_folder(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name) / "docs_assets" / "system-icons"
        folder.mkdir(parents=True)
        (folder / "A - One.png").write_bytes(b"png")
        with mock.patch.object(siterender, "ICON_DIR", folder), \
                mock.patch("builtins.print"):
            siterender.prime_system_icons({"A - One", "B - Two"})
        self.assertTrue(siterender._icon_available["A - One"])
        self.assertFalse(siterender._icon_available["B - Two"])
        self.assertEqual(siterender.system_icon_markdown("B", "Two"), "")
        self.assertIn("A%20-%20One.png", siterender.system_icon_markdown("A", "One"))

    def test_no_request_is_made(self):
        self.assertNotIn("urllib.request", (REPO_ROOT / "scripts" / "siterender.py").read_text())


class EveryPageAddressesPlatformsAsPeers(unittest.TestCase):
    """The exports page was held to neutral wording, and the gaps page next
    to it still called each platform's file a "corrected list". Reads the
    text every site generator writes, docstrings and bare identifiers aside."""

    WORDS = ("their file", "theirs", "of ours", "corrected", "left out", "drift")
    def test_no_page_text_judges_another_project(self):
        import ast
        import re

        from tests.sitepages import generator_sources

        found = []
        for source in generator_sources():
            name = source.name
            tree = ast.parse(source.read_text(encoding="utf-8"))
            docstrings = {
                id(node.body[0].value) for node in ast.walk(tree)
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                     ast.AsyncFunctionDef))
                and ast.get_docstring(node, clean=False) is not None
            }
            for node in ast.walk(tree):
                if (not isinstance(node, ast.Constant) or not isinstance(node.value, str)
                        or id(node) in docstrings or re.fullmatch(r"\w+", node.value)):
                    continue
                text = node.value.lower()
                found += [f"{name}:{node.lineno} {word!r}"
                          for word in self.WORDS if word in text]
        self.assertEqual(found, [])


class BundledFilesAreNotToSource(unittest.TestCase):
    """The gaps page summed the report's gap_missing, bundled files included:
    1,356 files to source where 609 were, and a red badge of 13 on ZQuest
    Classic, whose 13 missing files all come with its own package."""

    def test_the_summary_and_the_row_count_only_what_must_be_found(self):
        import generate_site

        gap = {"required": True, "source_ref": "x", "in_repo": False}
        report = {"zq": {
            "emulator": "ZQuest Classic", "gaps": 4, "gap_missing": 3, "gap_bios": 1,
            "unsourceable": [],
            "gap_details": [
                {**gap, "name": "a.dll", "source": "missing", "bundled": True},
                {**gap, "name": "b.dll", "source": "missing", "bundled": True},
                {**gap, "name": "c.bin", "source": "missing"},
                {**gap, "name": "d.bin", "source": "bios", "in_repo": True},
            ],
        }}
        page = generate_site.generate_gap_analysis(
            {"zq": {"emulator": "ZQuest Classic", "files": []}}, {},
            {"files": {}, "indexes": {}}, gap_report=report)
        self.assertIn("2 installed with their emulator, 1 to source.", page)
        self.assertIn("| missing | 1 | Not available, needs sourcing |", page)
        self.assertIn("| [ZQuest Classic](emulators/zq.md) | 4 | 1 | 0 | 0 | 2 | "
                      '<span class="rb-badge rb-badge-danger">1</span> |', page)

    def test_a_row_names_only_the_platforms_that_read_it(self):
        """cdbios.bin, read by standalone BlastEm only and never on RetroBat,
        was badged retroarch, lakka and retrobat."""
        import generate_site
        from common import load_platform_config, resolve_platform_cores

        root = Path(__file__).resolve().parents[1]
        profile = yaml.safe_load((root / "emulators" / "blastem.yml").read_text(encoding="utf-8"))
        configs = {}
        for name in ("retroarch", "lakka", "retrobat", "batocera"):
            config = load_platform_config(name, str(root / "platforms"))
            if "blastem" in resolve_platform_cores(config, {"blastem": profile}):
                configs[name] = config
        self.assertIn("retroarch", configs)
        self.assertIn("retrobat", configs)
        found = generate_site.reading_platforms("blastem", profile, "cdbios.bin", configs)
        self.assertFalse(found & {"retroarch", "lakka", "retrobat"}, found)


class StructuredBlocks(unittest.TestCase):
    PIN = "1e0de94dc7e669c0925a22c0fccf6cdc837af0a0"

    def profile(self, block: str, value: object) -> dict:
        return {"source": "https://github.com/libretro/blastem",
                "source_commit": self.PIN, block: value}

    def render(self, profile: dict) -> str:
        import generate_site

        return "\n".join(generate_site._render_structured_blocks(profile))

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def test_a_source_ref_in_a_block_is_a_pinned_link(self):
        """186 citations in analysis and firmware blocks were plain code."""
        page = self.render(self.profile("analysis", {"tmss": {
            "source_ref": "libblastem.c:355-359"}}))
        self.assertIn(
            f"[`libblastem.c:355-359`](https://github.com/libretro/blastem/blob/"
            f"{self.PIN}/libblastem.c#L355-L359)", page)

    def test_a_list_inside_a_list_item_is_shown(self):
        """cemu's firmware titles lost the files each title carries."""
        page = self.render(self.profile("firmware_titles", [
            {"id": "0005001b-10042400", "name": "Shared fonts",
             "content": ["CafeCn.ttf", "CafeKr.ttf"]}]))
        self.assertIn("\n- id: 0005001b-10042400, name: Shared fonts\n", page)
        self.assertIn("\n    - **content:**", page)
        self.assertIn("\n        - CafeKr.ttf", page)

    def test_a_folded_note_stays_inside_its_block(self):
        page = self.render(self.profile("analysis", {"tmss": {
            "note": "The core points\nsystem/tmss_path at the system directory."}}))
        self.assertIn("- **note:** The core points system/tmss_path at the", page)
        # Nothing of the note is left after the block closes.
        lines = page.split("\n")
        end = lines.index("</details>")
        self.assertEqual([line for line in lines[end + 1:] if line.strip()], [])

    def test_a_long_note_is_not_cut(self):
        note = "word " * 80 + "end."
        page = self.render(self.profile("analysis", {"x": {"note": note}}))
        self.assertIn("end.", page)


class FileCardsLinkTheReadingEntry(unittest.TestCase):
    def test_an_emulator_link_lands_on_its_entry(self):
        """The platform links landed on their section, the emulator links on
        the top of a page of a hundred entries."""
        import generate_site
        from cross_reference import FileConsumers

        consumers = FileConsumers({"files": {}})
        files = [{"name": "scph1001.bin"}, {"name": "scph5501.bin"},
                 {"name": "tmss.md", "sha1": "d0fd0c16" + "0" * 32},
                 {"name": "tmss.md", "sha1": "aa" * 20}]
        consumers.emulators = {"s": {"duckstation", "other"}, "t": {"blastem"}}
        consumers.emulator_entries = {"s": {"duckstation": 1}, "t": {"blastem": 2}}
        consumers.emulator_files = {"duckstation": files, "blastem": files}
        self.assertEqual(generate_site._emulator_links("s", consumers), [
            "[DuckStation](../emulators/duckstation.md#file-scph5501-bin)",
            "[other](../emulators/other.md)",
        ])
        self.assertEqual(generate_site._emulator_links("t", consumers),
                         ["[BlastEm](../emulators/blastem.md#file-tmss-md-d0fd0c16)"])


class DirectoryMembersNameTheirEmulator(unittest.TestCase):
    """The site resolved a ``type: directory`` entry by its own name: 11,976
    files under alephone's Plugins/, cdogs' and thextech's trees had no
    emulator on their card, and the directory card linked none of them."""

    SHA1 = "c63078a6c9ccaca7339a726a5d39410983933070"

    @classmethod
    def setUpClass(cls) -> None:
        from common import build_zip_contents_index, load_database, load_emulator_profiles
        from cross_reference import FileConsumers

        cls.db = load_database(str(REPO_ROOT / "database.json"))
        if cls.SHA1 not in cls.db.get("files", {}):
            raise unittest.SkipTest("the collection does not hold the alephone plugin")
        cls.profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["alephone"]
        cls.consumers = FileConsumers(cls.db, build_zip_contents_index(cls.db))
        cls.consumers.add_emulators({"alephone": cls.profile})

    def test_a_member_names_the_emulator_and_its_directory_entry(self):
        import generate_site

        files = self.profile["files"]
        index = self.consumers.emulator_entries[self.SHA1]["alephone"]
        self.assertEqual(files[index].get("type"), "directory")
        self.assertEqual(generate_site._emulator_links(self.SHA1, self.consumers),
                         ["[Aleph One](../emulators/alephone.md#file-marathon-plugins)"])

    def test_the_directory_card_points_at_its_copies(self):
        import generate_site

        entry = next(f for f in self.profile["files"]
                     if f.get("type") == "directory" and f.get("path") == "Marathon/Plugins/")
        line = generate_site._directory_copies(entry, self.consumers)[0]
        self.assertRegex(line, r"^Collection copies: \d+ files under "
                               r"\[`bios/Bungie/Marathon/Plugins/`\]\(\.\./systems/bungie\.md#")


class AnAliasTreeIsListedOnItsParentsPage(unittest.TestCase):
    """The 90 FreeIntv overlays were linked to the page of the alias that
    declares them, which is never generated: every permalink was a 404."""

    PROFILES = {
        "freeintv": {"type": "libretro"},
        "freeintv_ts_overlay": {
            "type": "alias", "alias_of": "freeintv",
            "data_directories": [{"ref": "freeintv-overlays",
                                  "destination": "freeintv_overlays"}],
        },
    }

    def test_the_permalink_goes_to_a_page_that_exists(self):
        import generate_site

        members = {"freeintv-overlays": {"a.png": {"sha1": "02" * 20}}}
        items = generate_site.file_location_items({"files": {}}, self.PROFILES, members)
        self.assertEqual(items, [{"sha1": "02" * 20,
                                  "url": "/retrobios/emulators/freeintv/#sha1-020202020202"}])

    def test_the_parent_page_lists_the_tree(self):
        import generate_site

        trees = generate_site.page_data_directories("freeintv", self.PROFILES)
        self.assertEqual([t["ref"] for t in trees], ["freeintv-overlays"])


class CitationsKeepTheirAnnotations(unittest.TestCase):
    """split_source_ref drops annotations for profile_sync, and the cards
    reused it: abuse's two lsf lines lost "(lsf default)" and "(lsf
    override)", the only words saying which one wins."""

    @mock.patch("sitesources.tree_holds", lambda *_args: True)
    def test_each_part_shows_what_the_profile_wrote_beside_it(self):
        import sitesources

        profile = {"source": "https://github.com/Xenoveritas/abuse",
                   "source_commit": "a" * 40}
        ref = ("src/loader2.cpp:284 (lsf default), src/netcfg.cpp:204 (lsf override), "
               "libretro.cpp:1520-1521 candidates_a1200, 30-31 (see <system_dir>), src/x.c:1")
        (label, items), = sitesources.source_ref_items(profile, ref)
        texts = [text for text, _role in items]
        self.assertTrue(texts[0].endswith(") (lsf default)"), texts[0])
        self.assertTrue(texts[1].endswith(") (lsf override)"), texts[1])
        self.assertTrue(texts[2].endswith(") candidates_a1200"), texts[2])
        self.assertTrue(texts[3].endswith(") (see &lt;system_dir>)"), texts[3])
        self.assertTrue(texts[4].endswith(")"), texts[4])

    def test_the_annotation_is_what_follows_the_location(self):
        from sourceref import ref_annotation

        self.assertEqual(ref_annotation("munt ROMInfo.cpp:206-213"), "")
        self.assertEqual(ref_annotation("source atari800/src/sysrom.c:91"), "")
        self.assertEqual(ref_annotation("doc/notes.txt (read at boot)"), "(read at boot)")
        self.assertEqual(ref_annotation("a.c (see b.c:12)"), "(see b.c:12)")
        self.assertEqual(ref_annotation("0x53c338-0x53c36f (dreamBios row)"), "(dreamBios row)")

    def test_a_binary_citation_keeps_its_annotation(self):
        import sitesources

        (_label, items), = sitesources.source_ref_items(
            {}, "demul.exe 0x6b4d80-0x6b4ea3 (dc table), 0x53ca4d-0x53ca7e (load, fatal)")
        self.assertEqual([text for text, _ in items], [
            "offset `0x6b4d80-0x6b4ea3` in `demul.exe` (dc table)",
            "offset `0x53ca4d-0x53ca7e` in `demul.exe` (load, fatal)",
        ])


class ForgesUpstreamDoesNotRead(unittest.TestCase):
    """Profiles pinned on SourceForge, voidpoint.io, Bitbucket or Software
    Heritage showed no revision, and their citations were plain code."""

    @mock.patch("sitesources.tree_holds", lambda *_args: True)  # a path the record confirms
    def links(self, url: str, ref: str, **extra: str) -> tuple[str, str]:
        import sitesources

        profile = {"source": url, "source_commit": "f6c00044" + "0" * 32, **extra}
        return (sitesources.revision_markdown(profile),
                sitesources._source_ref_markdown(profile, ref))

    def test_bitbucket(self):
        revision, ref = self.links("https://bitbucket.org/linuxwolf6/splitwolf",
                                   "id_lwmp.cpp:1831-1868", source_branch="scrubbed")
        pin = "f6c00044" + "0" * 32
        self.assertEqual(revision, f"[linuxwolf6/splitwolf@{pin[:12]}]"
                         f"(https://bitbucket.org/linuxwolf6/splitwolf/commits/{pin}), "
                         "branch `scrubbed`")
        self.assertIn(f"(https://bitbucket.org/linuxwolf6/splitwolf/src/{pin}/"
                      "id_lwmp.cpp#lines-1831:1868)", ref)

    def test_a_gitlab_instance(self):
        _revision, ref = self.links("https://voidpoint.io/terminx/eduke32",
                                    "source/duke3d/src/common.cpp:36")
        self.assertIn("https://voidpoint.io/terminx/eduke32/-/blob/f6c00044", ref)
        self.assertIn("/source/duke3d/src/common.cpp#L36)", ref)

    def test_sourceforge(self):
        revision, ref = self.links("https://sourceforge.net/p/dgen/dgen", "rc.cpp:12")
        self.assertIn("(https://sourceforge.net/p/dgen/dgen/ci/f6c00044", revision)
        self.assertRegex(ref, r"\(https://sourceforge\.net/p/dgen/dgen/ci/f6c00044\w+/tree/rc\.cpp\)")

    def test_software_heritage(self):
        revision, ref = self.links(
            "https://archive.softwareheritage.org/browse/revision/f6c00044/",
            "app/src/os.cpp:35-36")
        self.assertTrue(revision.startswith("[Software Heritage@f6c000440000]"))
        self.assertIn("/browse/revision/f6c00044" + "0" * 32 + "/?path=app/src/os.cpp#L35-L36)", ref)


class TheDatHoldsEveryCopy(unittest.TestCase):
    """The DAT held one path per content, the database's: auditing bios/
    with it flagged the 2,502 other copies (RPG Maker, engine trees, a dump
    filed under two consoles) as unknown, and a fix moved them away."""

    def test_a_second_copy_is_a_rom_of_its_own_folder(self):
        import generate_site

        sha1 = "9526ef63" + "0" * 32
        with tempfile.TemporaryDirectory() as tmp:
            for rel in ("Atari/ST/tos104.img", "Atari/ST/tos104uk.img"):
                (Path(tmp) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / rel).write_bytes(b"x")
            db = {
                "bios_dir": tmp,
                "files": {sha1: {"path": "bios/Atari/ST/tos104.img", "sha1": sha1,
                                 "size": 1, "name": "tos104.img"}},
                "indexes": {"by_path_suffix": {
                    "Atari/ST/tos104.img": [sha1], "ST/tos104.img": [sha1],
                    "Atari/ST/tos104uk.img": [sha1], "ST/tos104uk.img": [sha1],
                }},
            }
            dat = generate_site.collection_dat(db, "2026-10-21T00:00:00Z")
        self.assertIn('<rom name="tos104.img" size="1"', dat)
        self.assertIn('<rom name="tos104uk.img" size="1"', dat)
        self.assertEqual(dat.count("<rom "), 2)


class TheSearchLandsOnTheCard(unittest.TestCase):
    """The site search splits a page at its headings. Emulator cards were
    titled in bold and platform systems folded into blocks under one
    heading, so a pasted hash led to the page top or to the systems
    overview of a 100-block page."""

    def test_a_platform_system_is_a_heading(self):
        import generate_site

        by_system = {f"system-{i:02d}": [{"name": f"f{i}.bin", "status": "ok"}]
                     for i in range(11)}
        names = {sys_id: f"System {sys_id[-2:]}" for sys_id in by_system}
        with mock.patch.dict(siterender.SYSTEM_NAMES, names):
            lines = generate_site._render_platform_systems(by_system, {}, {})
        headings = [line for line in lines if line.startswith("### ")]
        self.assertEqual(len(headings), 11)
        self.assertTrue(headings[0].endswith("{ #system-00 }"))
        self.assertNotIn('<a id="system-00"></a>', lines)
        self.assertIn("<summary>1 file (OK)</summary>", lines)

    def test_an_emulator_card_is_a_heading_with_its_anchor(self):
        import generate_site

        entry = {"name": "scph5501.bin", "required": True}
        lines = generate_site._render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: True, "file-scph5501-bin")
        self.assertTrue(lines[2].startswith('<h3 id="file-scph5501-bin" class="rb-file-title"'))
        self.assertIn("<code>scph5501.bin</code>", lines[2])

    def test_a_system_card_is_a_heading_with_its_anchor(self):
        import generate_site
        from cross_reference import FileConsumers

        entry = {"name": "a.bin", "sha1": "a" * 40, "md5": "b" * 32, "size": 3}
        lines = generate_site._system_file_card(entry, FileConsumers({"files": {}}))
        self.assertTrue(lines[2].startswith('<h3 id="sha1-aaaaaaaaaaaa" class="rb-file-title"'))
        self.assertIn("<code>a.bin</code>", lines[2])


class TheSearchSkipsLinkLists(unittest.TestCase):
    """The search index was 24.7 MB, read and indexed before the first
    result. Lists of platforms, copies and source citations on every card
    made 6.6 MB of it, names already indexed on their own pages, and the
    hashes 4 MB more: files/?hash= finds those."""

    def test_a_system_card_keeps_its_name_and_skips_its_body(self):
        import generate_site
        from cross_reference import FileConsumers

        consumers = FileConsumers({"files": {}})
        sha1 = "a" * 40
        consumers.platforms = {sha1: {"retroarch"}}
        consumers.installed = {sha1: {"batocera": {"bios/a.bin"}}}
        consumers.emulators = {sha1: {"duckstation"}}
        entry = {"name": "a.bin", "sha1": sha1, "md5": "b" * 32, "size": 3}
        lines = generate_site._system_file_card(entry, consumers)
        self.assertIn("<code>a.bin</code>", lines[2])
        text = "\n".join(lines)
        searched, _sep, skipped = text.partition('<dl class="rb-facts" data-pagefind-ignore>')
        for label in ("MD5", "Emulators", "Packed for its emulators by", "On the setup's list"):
            self.assertIn(f"<dt>{label}</dt>", skipped)
            self.assertNotIn(f">{label}</dt>", searched)
        # The card's title is what the search reads: the setup
        # list made every excerpt a run of names and paths.
        self.assertNotIn('<dl class="rb-facts">', searched)

    def test_a_game_data_card_skips_its_name_too(self):
        import generate_site
        from cross_reference import FileConsumers

        entry = {"name": "0.ogg", "sha1": "a" * 40, "size": 3}
        lines = generate_site._system_file_card(
            entry, FileConsumers({"files": {}}), searchable=False)
        self.assertIn("data-pagefind-ignore", lines[2])
        self.assertNotIn("data-pagefind-weight", lines[2])

    def test_runs_alternate_in_card_order(self):
        import generate_site

        lines = ["- Path: `p`", "- SHA1: x", "- Source: `a.c:1`", "- Platforms: p",
                 "- Destination: `d`", "- Contents (1 members):", "    - `m`",
                 "- Note"]
        out = [line for line in generate_site._search_skipped_apart(lines) if line]
        self.assertEqual(out, [
            "- Path: `p`",
            '<div class="rb-search-skip" data-pagefind-ignore>',
            "- SHA1: x", "- Source: `a.c:1`", "- Platforms: p", "</div>",
            "- Destination: `d`",
            '<div class="rb-search-skip" data-pagefind-ignore>',
            "- Contents (1 members):", "    - `m`", "</div>",
            "- Note",
        ])

    def test_long_tables_leave_the_search(self):
        import generate_site

        short = "| a |\n|---|\n| 1 |"
        long = "    | a |\n    |---|\n" + "\n".join(f"    | {'x' * 50} |" for _ in range(80))
        text = generate_site.tables_out_of_search(f"# T\n\n{short}\n\n{long}\n")
        self.assertEqual(text.count("data-pagefind-ignore"), 1)
        self.assertIn("    <section data-pagefind-ignore>\n\n    | a |", text)
        self.assertIn(short, text)


class OneDefinitionPerName(unittest.TestCase):
    """generate_site defined _REGION_WORDS twice: the second table replaced
    the first at import, and _region_word, written beside the first, never
    read it."""

    def test_no_module_name_is_bound_twice(self):
        import ast

        for path in sorted((REPO_ROOT / "scripts").glob("*site*.py")):
            seen: dict[str, int] = {}
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    names = [node.name]
                elif isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    names = [node.target.id]
                else:
                    continue
                for name in names:
                    self.assertNotIn(name, seen, f"{path.name}:{node.lineno} binds {name} "
                                     f"again, first at line {seen.get(name)}")
                    seen[name] = node.lineno


@unittest.skipUnless((REPO_ROOT / "database.json").is_file(), "database.json is not built")
class AMemberIsReadInItsArchive(unittest.TestCase):
    """FBNeo reads sm1.sm1 inside neogeo.zip. Resolved by its crc32, the
    entry credited a loose sm1.sm1 FBNeo never opens, and no neogeo.zip card
    named FBNeo, while the pack ships it one."""

    def test_the_archive_is_credited_and_named_on_the_card(self):
        import json

        import generate_site as gs
        from common import archive_entry, resolve_local_file
        from cross_reference import FileConsumers

        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "fbneo.yml").read_text(encoding="utf-8"))
        files = profile["files"]
        consumers = FileConsumers(db)
        consumers.add_emulators({"fbneo": profile})
        credited = {consumers.path_of(sha1) for sha1 in consumers.emulators}
        shipped, _status = resolve_local_file(
            {**archive_entry("neogeo.zip", files), "source_profile": "fbneo"}, db)
        self.assertIn(shipped, credited)
        self.assertFalse([p for p in credited if p.endswith("/sm1.sm1")])
        sm1 = next(f for f in files if f["name"] == "sm1.sm1")
        rows = "\n".join(gs._render_emulator_file(sm1, profile, consumers, files,
                                                  lambda _f: True, owner="fbneo"))
        self.assertIn("Collection copy: member `sm1.sm1` of", rows)
        self.assertIn(shipped, rows)


class NoTooltipInsideAName(unittest.TestCase):
    """The glossary's capitalised terms matched almost only product names:
    Free Unix Spectrum Emulator, Windows Terminal, Documents/Dolphin Emulator."""

    def test_names_are_left_and_terms_are_marked(self):
        import sitestarlight

        terms = {"Emulator": "An app that acts like a console.",
                 "Terminal": "A window for typing commands.",
                 "BIOS": "The console's built-in software."}
        for line in ("Fuse (Free Unix Spectrum Emulator) reads it.",
                     "Open Windows Terminal (WSL).",
                     "Copy it to Documents/Dolphin Emulator/Sys."):
            with self.subTest(line=line):
                self.assertNotIn("rb-term", sitestarlight.add_tooltips(line, terms))
        marked = sitestarlight.add_tooltips(
            "Emulator settings come first. The PlayStation BIOS goes there.", terms)
        self.assertIn('title="An app that acts like a console.">Emulator</abbr>', marked)
        self.assertIn('>BIOS</abbr>', marked)


class TheArcadeCacheHoldsItsDatabase(unittest.TestCase):
    """The set of sha1s filed under Arcade/ was cached by id(db): a database
    freed and replaced at the same address answered with the first one's set,
    and an arcade card of the second landed in another section."""

    @staticmethod
    def _db(sha1: str) -> dict:
        return {"files": {}, "indexes": {"by_path_suffix": {"Arcade/x.zip": [sha1]}}}

    def test_a_new_database_at_a_reused_address_is_read_again(self):
        saved = siterender._suffix_cache[0]
        self.addCleanup(siterender._suffix_cache.__setitem__, 0, saved)
        first = self._db("a" * 40)
        self.assertTrue(siterender._in_arcade("a" * 40, first))
        address = id(first)
        del first
        # CPython hands a freed dict's address to a later one of its size,
        # unless the cache still holds the first database.
        for _ in range(1000):
            second = self._db("b" * 40)
            if id(second) == address:
                break
            del second
        else:
            second = self._db("b" * 40)
        self.assertTrue(siterender._in_arcade("b" * 40, second))
        self.assertFalse(siterender._in_arcade("a" * 40, second))


if __name__ == "__main__":
    unittest.main()
