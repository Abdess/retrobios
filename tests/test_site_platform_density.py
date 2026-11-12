"""A platform page lists one row per file, the evidence on demand.

Batocera, AmberELEC and RomM ran to 14,000 to 16,000 words: every file
spelled its full MD5, the copy serving it and each source reference of
each reader, with "(emulator code, libretro port)" after every one. A row
now shows the name, the folder, the status and a short hash. Opened, it
holds every hash, the served copy and the readers across the list, the
role of each reference named by one word that a legend defines once.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import html
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402

_SKIPPED = frozenset({"script", "style", "template"})
_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input",
                   "link", "meta", "source", "track", "wbr"})


class _Words(HTMLParser):
    """Words in <main>: all of them, and those a reader sees with every
    details block closed (a closed block shows its summary only)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.visible = 0
        self.total = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID:
            closed = tag == "details" and "open" not in dict(attrs)
            self.stack.append((tag, closed))

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return

    def _counted(self) -> bool:
        names = {name for name, _ in self.stack}
        return "main" in names and not names & _SKIPPED

    def _shown(self) -> bool:
        for index, (_name, closed) in enumerate(self.stack):
            if closed:
                rest = self.stack[index + 1:]
                if not rest or rest[0][0] != "summary":
                    return False
        return True

    def handle_data(self, data: str) -> None:
        if not self._counted():
            return
        count = len(data.split())
        self.total += count
        if self._shown():
            self.visible += count


def page_words(html: str) -> tuple[int, int]:
    """(visible words, all words) in a page's <main>."""
    parser = _Words()
    parser.feed(html)
    return parser.visible, parser.total


class VisibleWordsAreCounted(unittest.TestCase):
    def test_a_closed_block_shows_its_summary_only(self):
        page = ("<main><p>one two</p><details><summary>three</summary>four five"
                "<details open><summary>six</summary>seven</details></details>"
                "<details open><summary>eight</summary>nine</details>"
                "<script>no</script></main><p>outside</p>")
        self.assertEqual(page_words(page), (5, 9))


class ARowPerFile(unittest.TestCase):
    def _row(self, f: dict, entry: dict, hash_type: str = "md5") -> str:
        return generate_site._platform_file_row(f, entry, hash_type)

    def test_the_row_at_a_glance(self):
        md5, sha1 = "a" * 32, "b" * 40
        row = self._row({"name": "bios_a.bin", "status": "ok", "size": 2048},
                        {"name": "bios_a.bin", "md5": md5, "sha1": sha1, "crc32": "0badf00d",
                         "destination": "bios/bios_a.bin"})
        # The summary is the row: the name, its folder, the status.
        self.assertIn('<details class="rb-file"><summary>bios&#95;a.bin <code>bios/</code> '
                      '<span class="rb-badge rb-badge-success">OK</span></summary>', row)
        # The hash the platform checks, short, on one button beside the
        # summary (a summary is a control: no button inside it).
        details, button = row.split("</details>")
        self.assertNotIn("<button", details)
        self.assertEqual(button, f'<button class="rb-copy" data-copy="{md5}" '
                                 f'aria-label="Copy MD5 {md5[:generate_site.SHORT_HASH]}">{md5[:generate_site.SHORT_HASH]}</button>')
        # Every hash whole in the details, with the size.
        for value in (md5, sha1, "0badf00d"):
            self.assertIn(value, details)
        self.assertIn("(2.0 KB)", details)

    def test_a_file_at_the_root_prints_no_path(self):
        for destination in ("", "x.bin"):
            row = self._row({"name": "x.bin", "status": "ok"}, {"destination": destination})
            self.assertIn("<summary>x.bin <span", row)

    def test_a_list_drops_the_path_column_when_no_row_has_one(self):
        files = [{"name": "a.bin", "status": "ok"}, {"name": "b.bin", "status": "ok"}]
        system = "nintendo-gamecube"
        config = {(system, "a.bin"): [{"destination": "a.bin"}], (system, "b.bin"): [{}]}
        text = "\n".join(generate_site._render_platform_systems({system: files}, config, {}))
        self.assertIn('<div class="rb-files">', text)
        config[(system, "b.bin")] = [{"destination": "sub/b.bin"}]
        text = "\n".join(generate_site._render_platform_systems({system: files}, config, {}))
        self.assertIn('<div class="rb-files rb-files-path">', text)

    def test_status_words(self):
        cases = {
            ("missing", ""): ("Missing", "danger"),
            ("untested", "declared hash contradicted by the local file"): ("Other hash", "warning"),
            ("untested", "expected 1234... got 5678..."): ("Other hash", "warning"),
            ("untested", "bios/x read error"): ("Untested", "warning"),
        }
        for (status, reason), (word, tone) in cases.items():
            row = self._row({"name": "x", "status": status, "reason": reason}, {"md5": "c" * 32})
            self.assertIn(f'<span class="rb-badge rb-badge-{tone}">{word}</span>', row)
            if reason:
                self.assertIn(f"Not confirmed: {reason}", row)

    def test_accepted_values_all_in_the_details(self):
        values = ["1" * 32, "2" * 32, "3" * 32]
        row = self._row({"name": "x", "status": "ok"}, {"md5": ",".join(values)})
        self.assertIn(f'data-copy="{values[0]}"', row)
        self.assertIn(f">{values[0][:generate_site.SHORT_HASH]} +2</button>", row)
        for value in values:
            self.assertIn(f'<code class="rb-hash">{value}</code>', row)

    def test_markdown_never_reads_the_text(self):
        row = self._row({"name": "*a_b*[1].bin", "status": "ok"}, {})
        self.assertIn("&#42;a&#95;b&#42;&#91;1&#93;.bin", row)

    def test_a_long_list_gets_a_filter(self):
        rows = ["<details></details>"] * generate_site.FILTER_ROWS
        block = generate_site._platform_file_list(rows, False, "arcade")
        self.assertTrue(block[0].startswith('<div class="rb-table-filter" hidden data-pagefind-ignore>'
                                        '<label for="rb-files-filter-arcade">Filter files</label>'))
        self.assertNotIn("rb-table-filter", "".join(
            generate_site._platform_file_list(rows[1:], False, "arcade")))


class ReferencesNameTheirRoleOnce(unittest.TestCase):
    PROFILE = {"type": "libretro", "source": "https://example.org/port",
               "upstream": "https://example.org/emu"}
    REFS = "source libretro/libretro.c:1, source src/a.c:2, source src/b.c:3, upstream src/c.c:4"

    def test_grouped_by_role(self):
        text = generate_site._refs_by_role(self.PROFILE, self.REFS)
        self.assertEqual(text, "glue `libretro/libretro.c:1` and port `src/a.c:2`, `src/b.c:3` "
                               "and upstream `src/c.c:4`")
        for word in generate_site.ROLE_WORDS.values():
            self.assertIn(f"**{word}**", generate_site.ROLE_LEGEND)

    def test_other_pages_keep_the_role_after_each_reference(self):
        text = generate_site._source_ref_markdown(self.PROFILE, self.REFS)
        self.assertEqual(text.count("(emulator code, libretro port)"), 2)
        self.assertIn("`src/c.c:4` (upstream emulator)", text)


def _unescaped(text: str) -> str:
    return html.unescape(text)


@unittest.skipUnless((REPO_ROOT / "database.json").is_file(), "database.json absent")
class NothingIsLost(unittest.TestCase):
    """Every fact a file row carried is on the page or its parts: each
    declared hash whole, the served copy, every reader's references."""

    @classmethod
    def setUpClass(cls) -> None:
        from common import load_database
        from generate_readme import compute_coverage

        db = load_database(str(REPO_ROOT / "database.json"))
        cls.pages = {}
        for name in ("batocera", "retroarch"):
            cov = compute_coverage(name, str(REPO_ROOT / "platforms"), db)
            moved: dict[str, str] = {}
            page = generate_site.generate_platform_page(name, cov, {}, {}, moved)
            cls.pages[name] = (cov, page, moved)

    def test_every_fact_is_there(self):
        for name, (cov, page, moved) in self.pages.items():
            text = _unescaped("\n".join([page, *moved.values()]))
            systems = {d.get("system") for d in cov["details"]}
            for sys_id, system in cov["config"].get("systems", {}).items():
                if sys_id not in systems:
                    continue
                for entry in system.get("files", []):
                    for algorithm in ("sha1", "md5", "crc32", "sha256"):
                        for value in re.split(r"[,\s]+", str(entry.get(algorithm) or "")):
                            if value:
                                self.assertIn(value, text, (name, entry.get("name"), algorithm))
            for detail in cov["details"]:
                self.assertIn(detail["name"], text)
                if detail.get("path") and detail.get("status") != "missing":
                    self.assertIn(detail["path"], text, (name, detail["name"]))
                readers = (detail.get("category_evidence") or {}).get("read_by", [])
                # Cores of other systems that share the name are named, not
                # cited, when a core of this system reads the file.
                running = [reader for reader in readers if reader.get("runs_system")]
                for reader in running or readers:
                    for url in re.findall(r"\]\((https://[^)]+)\)", generate_site._category_evidence_md(
                            {"read_by": [reader]})):
                        self.assertIn(url, text, (name, detail["name"], reader["emulator"]))

    def test_the_role_is_a_word_defined_once(self):
        for name, (_cov, page, moved) in self.pages.items():
            for text in (page, *moved.values()):
                self.assertNotIn("(emulator code, libretro port)", text, name)
                self.assertEqual(text.count(generate_site.ROLE_LEGEND), 1, name)


# Visible words (outside closed details) measured on the built site,
# 2026-10-27. A ceiling is the measured value plus 5 %, never above the
# value before the rows were tables (Batocera 2,433, AmberELEC 1,301, RomM
# 1,607, RetroArch 2,207, the largest main page 2,459, the largest part
# 19,127: RetroDECK's arcade list). AmberELEC rose to 1,304 on 2026-11-11:
# MAME is named beside ProSystem, O2EM and FreeIntv, the cores its rom
# folders offer, and the MSX section shows its file count. 1,311 once
# its Neo Geo row names the emulators that read the set (AdvanceMAME,
# FinalBurn Neo, Geolith, MAME) beside FB Alpha 2012, the only one it named
# while the platforms' snk-neogeo met no profile id.
PAGE_CEILINGS = {"batocera": 2433, "amberelec": 1311, "romm": 1607, "retroarch": 2192}
MAIN_PAGE_CEILING = 2459
PART_PAGE_CEILING = 2219

_SITE = REPO_ROOT / "website" / "dist" / "platforms"


@unittest.skipUnless(_SITE.is_dir(), "website/dist not built")
class VisibleWordsStayUnderTheirCeiling(unittest.TestCase):
    def test_platform_pages(self):
        from common import list_registered_platforms

        mains = set(list_registered_platforms(str(REPO_ROOT / "platforms")))
        for page in sorted(_SITE.glob("*/index.html")):
            name = page.parent.name
            text = page.read_text(encoding="utf-8")
            if 'http-equiv="refresh"' in text[:2000]:
                continue
            visible, _total = page_words(text)
            ceiling = PAGE_CEILINGS.get(name, MAIN_PAGE_CEILING if name in mains else PART_PAGE_CEILING)
            self.assertLessEqual(visible, ceiling, name)


# Each platform with its part pages, before the rows were rewritten: pages,
# elements (outside scripts and styles, as validate_site counts them) and
# bytes of HTML, on the built site of 2026-10-27.
BEFORE_WEIGHT = {
    # Batocera's x86_64 RetroArch downloads buildbot cores, which its pages
    # name since 2026-11-09: each file lists every core that reads it with
    # its citations (the Game Boy Advance went from 4 readers to 10), and
    # Elektronika BK, FM Towns and Nintendo DS moved to part pages. Built
    # site of 27c33b966: 13 pages, 15,662 elements, 1,356,360 bytes, and 40
    # bytes more where its Amiberry build is named "Amiberry 8.0.0
    # (facaaeb, Batocera)" (twice). The search stopped reading the date
    # line and "Next steps" on 2026-11-10 (data-pagefind-ignore, about 68
    # bytes a page): 1,357,282 bytes on the built site of 25057ee3a. The
    # blueMSX and fMSX machine ROMs cite each reader since 2026-11-10 (the
    # config.ini line, machineCreate, readMachine, romLoad, LoadROM): the
    # MSX part went from 57,600 to 91,769 bytes, and the filter boxes and
    # file summaries got their spaces and labels (about 190 bytes a page).
    # 1,394,379 bytes on the built site of 7c5ad8366. MAME is named among
    # the readers of seven systems its rom folders offer it for, and the
    # LRPS2 that Batocera builds reads "LRPS2 (416291a, Batocera)" since
    # 2026-11-11: 1,396,309 bytes on the built site of 964875572. Its Neo
    # Geo system names every Neo Geo core since the platforms' snk-neogeo
    # met one: 1,396,380 bytes on the built site of 2026-11-11, in a
    # checkout without the release assets. The deployed site restores them,
    # and Batocera's pages then name four more files (PS3UPDAT.PUP, the two
    # Vita PUPs, dsi_nand.bin): 1,396,955 bytes on the site deployed from
    # 7d6efc352, 1,396,475 without the assets. Generated at 8d87f28cd and at
    # 750a6eb8e from the same inputs, the Markdown of all 13 pages is the
    # same size.
    "batocera": (13, 18_854, 1_396_955),
    # AmberELEC's MSX files cite the fMSX ROM loader since 2026-11-11 (fMSX
    # named 82 times instead of 28, the same 295 files): the section moved
    # to a part page of its own, 2 pages, 7,160 elements and 545,681 bytes
    # on the built site of 964875572. Its Neo Geo row names the emulators
    # that read the set (546,385 bytes on the built site of 2026-11-11).
    # The openMSX system ROMs collected on 2026-11-12 split the MSX system
    # page in two, and nine of its files now link to microsoft-msx-2:
    # 546,403 bytes on the built site of 82d134cd8.
    "amberelec": (2, 7_928, 546_403),
    "romm": (2, 9_561, 572_487),
    # RetroArch's MSX files cite the fMSX ROM loader and its ScummVM files
    # the readers of each data file since 2026-11-11 (46,737 and 9,275 bytes
    # more): 1,433,702 bytes on the built site of 964875572.
    "retroarch": (14, 21_503, 1_433_702),
}


@unittest.skipUnless(_SITE.is_dir(), "website/dist not built")
class APlatformWeighsNoMoreThanBefore(unittest.TestCase):
    """The split budget measured Markdown length: rows written as a table
    were longer Markdown, 38 systems moved to new part pages and Batocera
    with its parts rose from 18,854 to 21,875 elements."""

    def test_pages_elements_and_bytes(self):
        from validate_site import _PageParser

        for name, (pages, elements, size) in BEFORE_WEIGHT.items():
            paths, weight = [], 0
            for path in [_SITE / name / "index.html", *sorted(_SITE.glob(f"{name}-*/index.html"))]:
                parser = _PageParser(path)
                parser.feed(path.read_text(encoding="utf-8"))
                # A part folded back into its platform page left a redirect.
                if not parser.page.redirect:
                    paths.append(path)
                    weight += parser.page.elements
            self.assertLessEqual(len(paths), pages, name)
            self.assertLessEqual(weight, elements, name)
            self.assertLessEqual(sum(path.stat().st_size for path in paths), size, name)


if __name__ == "__main__":
    unittest.main()
