"""Long lists read as a table first, details on demand (density round).

MAME's card pages read 13,000 to 16,700 words, card after card, and
GroovyMAME 14,400 before its last entry. The TOSEC wanted list was 46
closed blocks, one per DAT, opened one by one to find a name. Each entry is
now a table row that opens to its card, and each wanted list one filtered
table under its counts. Nothing the pages said is lost: the tests below read
every name and hash back.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402
import siteentries  # noqa: E402
import validate_site  # noqa: E402

EMPTY_DB = {"files": {}, "indexes": {"by_name": {}}}
DIST = REPO_ROOT / "website" / "dist"


def _archive(i: int, members: int = 3, **fields: object) -> dict:
    return {
        "name": f"set{i:04d}.zip", "required": True, "category": "bios_zip",
        "contents": [{"name": f"m{i}_{k}.rom", "size": 1024, "crc32": f"{i:04x}{k:04x}",
                      "sha1": f"{i:04x}{k:04x}" * 5} for k in range(members)],
        **fields,
    }


class TheEntryTable(unittest.TestCase):
    def _rows(self, count: int) -> list[siteentries.Row]:
        return [siteentries.Row(f'<h3 id="file-{i}" class="rb-file-title">n{i}</h3>',
                                [f"- Size: {i} bytes"], [str(i), "", f"MD5 <code>{i}</code>"])
                for i in range(count)]

    def test_a_long_table_has_its_filter_box_and_stacks(self):
        lines = siteentries.entry_table(self._rows(25), gs.ENTRY_HEADS, "rb-entry-filter-x", "Required")
        text = "\n".join(lines)
        self.assertRegex(text, r'<div class="rb-table-filter" hidden data-pagefind-ignore>'
                               r'<label for="rb-entry-filter-x">Filter Required</label> '
                               r"<input id=\"rb-entry-filter-x\" type=\"search\"")
        self.assertIn('aria-live="polite">25 rows</span></div>\n<table class="rb-entries" '
                      'data-rb-stack="true">', text)
        # The Status column is empty on every row: not written.
        self.assertIn('<th scope="col">File</th><th scope="col">Contents</th>'
                      '<th scope="col">Hash</th>', text)
        self.assertNotIn("Status", text)
        self.assertEqual(text.count('<details class="rb-entry">'), 25)
        # Labels are written by site.ts on a table this long, as on a Markdown one.
        self.assertNotIn("data-label", text)

    def test_a_card_opens_under_its_name_as_markdown(self):
        lines = siteentries.entry_table(self._rows(2), gs.ENTRY_HEADS, "x", "Required")
        at = lines.index('<summary><h3 id="file-0" class="rb-file-title">n0</h3></summary>')
        # A blank line after the summary: the body is read as Markdown.
        self.assertEqual(lines[at + 1:at + 4], ["", "- Size: 0 bytes", ""])
        self.assertNotIn("rb-table-filter", "\n".join(lines))
        self.assertIn('<td data-label="Contents" data-pagefind-ignore>1</td>', lines)

    def test_a_card_loses_only_its_wrapper(self):
        card = ['<div class="rb-file-entry">', "", '<h3 id="a">x</h3>', "", "Desc.", "",
                '<div class="rb-search-skip">', "", "- SHA1: s", "", "</div>", "", "</div>", ""]
        title, body = siteentries.card_title_and_body(card)
        self.assertEqual(title, '<h3 id="a">x</h3>')
        self.assertEqual(body, ["Desc.", "", '<div class="rb-search-skip">', "", "- SHA1: s", "",
                                "</div>"])

    def test_the_placeholder_reads_like_the_plugin(self):
        self.assertEqual(siteentries.filter_placeholder(["File", "Contents", "Status", "Hash"]),
                         "File, contents, status, hash...")
        self.assertEqual(siteentries.filter_placeholder(["Name", "DAT", "Description", "SHA1"]),
                         "Name, DAT, description, SHA1...")


class ASplitEmulatorListsItsCardsAsRows(unittest.TestCase):
    def setUp(self):
        self.files = [_archive(i, members=1 + i % 4) for i in range(gs.EMULATOR_CARDS_PER_PAGE * 2)]
        self.pages = gs.emulator_pages(
            "big", {"emulator": "Big", "type": "standalone", "files": self.files}, EMPTY_DB)

    def test_parts_hold_at_most_a_part_of_cards(self):
        parts = gs.emulator_parts("big", self.files)
        self.assertEqual(len(parts), -(-len(self.files) // gs.EMULATOR_CARDS_PER_PART))
        self.assertLessEqual(max(len(entries) for _, entries in parts), gs.EMULATOR_CARDS_PER_PART)

    def test_every_name_and_member_hash_is_on_its_part(self):
        parts = {stem: page for stem, page in self.pages.items() if stem != "big"}
        anchors = gs.emulator_file_anchors(self.files)
        for stem, entries in gs.emulator_parts("big", self.files):
            page = parts[stem]
            self.assertIn('<table class="rb-entries" data-rb-stack="true">', page)
            self.assertNotIn('class="rb-file-entry"', page)
            for i in entries:
                f = self.files[i]
                self.assertIn(f'<summary><h3 id="{anchors[i]}" class="rb-file-title"', page)
                for member in f["contents"]:
                    self.assertIn(f"`{member['name']}`", page)
                    self.assertIn(f"CRC32 `{member['crc32']}`", page)
                    self.assertIn(f"SHA1 `{member['sha1']}`", page)
                # The row says how many members the archive holds.
                self.assertIn(f"data-pagefind-ignore>{len(f['contents'])}</td>", page)

    def test_the_section_badge_is_not_repeated_on_each_row(self):
        page = self.pages["big-files-1"]
        self.assertIn("## Required", page)
        self.assertNotIn(">required</span>", page)
        self.assertIn(">missing</span>", page)


class APartIsCutByTheWordsItsRowsShow(unittest.TestCase):
    """MAME's rows said "required for <system>" once 888 entries named a
    system, and its first part showed 1,931 words for the 180 cards a
    count allowed."""

    def setUp(self):
        systems = ["nintendo-nes", "sega-mega-drive", "sony-playstation"]
        self.files = [_archive(i, members=1, system=systems[i % 3], region="japan",
                               md5=f"{i:032x}")
                      for i in range(gs.EMULATOR_CARDS_PER_PART * 2)]
        self.profile = {"emulator": "Wide", "type": "standalone", "systems": systems,
                        "files": self.files}

    def test_rows_that_say_more_take_more_parts(self):
        parts = gs.emulator_parts("wide", self.files, self.profile, lambda _f: False)
        self.assertGreater(len(parts), -(-len(self.files) // gs.EMULATOR_CARDS_PER_PART))
        words = gs._entry_row_words(self.files, self.profile, lambda _f: False)
        shown = [sum(words[i] for i in entries) for _stem, entries in parts]
        self.assertLessEqual(max(shown), gs.EMULATOR_PART_WORDS)
        # Balanced: no part a remainder of a few rows.
        self.assertLess(max(shown) - min(shown), max(words) * 3)
        self.assertEqual(sorted(i for _stem, entries in parts for i in entries),
                         list(range(len(self.files))))

    def test_each_part_page_stays_under_the_built_ceiling(self):
        pages = gs.emulator_pages("wide", self.profile, EMPTY_DB)
        parts = gs.emulator_parts("wide", self.files, self.profile, lambda _f: False)
        self.assertEqual(sorted(pages), sorted(["wide", *(stem for stem, _e in parts)]))
        ceiling = VISIBLE_CEILINGS["emulator card parts"][1]
        for stem, _entries in parts:
            with self.subTest(stem=stem):
                parser = _Visible()
                parser.feed(f"<main>{pages[stem]}</main>")
                self.assertLessEqual(parser.words, ceiling)

    def test_the_budget_leaves_room_for_the_frame(self):
        self.assertLessEqual(gs.EMULATOR_PART_WORDS + 200,
                             VISIBLE_CEILINGS["emulator card parts"][1])


class ALongEmulatorPageIsOneTable(unittest.TestCase):
    def test_rows_replace_the_index_and_the_cards(self):
        files = ([_archive(i) for i in range(gs.EMULATOR_TABLE_MIN)]
                 + [{"name": f"opt{i}.bin", "md5": f"{i:032x}"} for i in range(10)])
        page = gs.generate_emulator_page(
            "long", {"emulator": "Long", "type": "standalone", "files": files}, EMPTY_DB, None, set())
        self.assertNotIn("| File |", page)
        self.assertNotIn('class="rb-file-entry"', page)
        self.assertEqual(page.count('<details class="rb-entry">'), len(files))
        optional = page[page.index("## Optional"):]
        # Hash column: the first 12 characters, the whole value in the title
        # and in the card.
        md5 = f"{9:032x}"
        self.assertIn(f'MD5 <code title="{md5}">{md5[:12]}</code>', optional)
        self.assertRegex(optional, rf'MD5: <code class="rb-hash"[^>]*>{md5}</code>')

    def test_a_shorter_page_keeps_its_cards(self):
        files = [_archive(i) for i in range(gs.EMULATOR_TABLE_MIN - 1)]
        page = gs.generate_emulator_page(
            "short", {"emulator": "Short", "type": "standalone", "files": files}, EMPTY_DB, None, set())
        self.assertIn('class="rb-file-entry"', page)
        self.assertNotIn('class="rb-entries"', page)


class TheWantedListIsOneFilteredTable(unittest.TestCase):
    def setUp(self):
        dats = ["Sony - PlayStation 2 - BIOS Images", "Nintendo - GameCube - BIOS Images"]
        self.missing = [{"name": f"bios{i}.bin", "sha1": f"{i:040x}", "description": f"Dump {i}",
                         "dat": dats[i % 2]} for i in range(30)]
        self.missing.append({"name": "both.bin", "sha1": "f" * 40, "dats": dats})
        report = {"redump": {
            "imported_at": "2026-01-01", "dats": {}, "matched": 12, "out_of_scope": 7,
            "covered_dats": dats + ["Sega - Dreamcast - BIOS Images"],
            "missing": [dict(entry) for entry in self.missing] + [
                {"name": "made.bin", "sha1": "a" * 40, "dat": dats[0]}],
        }}
        moved: dict[str, str] = {}
        self.main = gs.generate_provenance_page(
            {"files": {}}, report, {"a" * 40: {"from": ["bios/x.bin"], "transform": "half"}}, moved)
        self.page = moved["provenance-redump"]

    def test_the_counts_come_first(self):
        head = self.page[:self.page.index("<details")]
        self.assertIn("Held: **12** of 44, in the 3 DATs the collection reaches. "
                      "Wanted: **31**, from 2 DATs.", head)
        self.assertIn("1 more is [derivable]", head)
        self.assertIn("7 more sit in DATs the collection does not reach.", head)
        self.assertIn("| Sony - PlayStation 2 - BIOS Images | 16 |", self.page)
        self.assertIn("| Nintendo - GameCube - BIOS Images | 16 |", self.page)

    def test_every_dump_is_one_row_under_a_filter_box(self):
        box = re.search(r'<div class="rb-table-filter"[^>]*>.*?</div>\n<details[^>]*>\n'
                        r"<summary>All 31 wanted dumps</summary>\n<table class=\"rb-wanted\"",
                        self.page, re.S)
        self.assertIsNotNone(box)
        self.assertIn('aria-live="polite">31 rows</span>', box.group(0))
        self.assertEqual(self.page.count("<tr><td>"), 31)
        for entry in self.missing:
            self.assertIn(f"<tr><td>{entry['name']}</td>", self.page)
            self.assertIn(f'<td class="rb-hash" data-pagefind-ignore>{entry["sha1"]}</td>',
                          self.page)
        self.assertIn("Sony - PlayStation 2 - BIOS Images, Nintendo - GameCube - BIOS Images",
                      self.page)
        self.assertNotIn("made.bin", self.page)


class TheBrowserSide(unittest.TestCase):
    CSS = (REPO_ROOT / "website" / "src" / "styles" / "retrobios.css").read_text(encoding="utf-8")
    TS = (REPO_ROOT / "website" / "src" / "scripts" / "site.ts").read_text(encoding="utf-8")

    def test_a_filtered_row_stays_hidden_on_a_phone(self):
        # A stacked row is `display: block`, which outweighed `hidden`.
        self.assertIn(".sl-markdown-content table[data-rb-stack] tr[hidden] { display: none; }",
                      self.CSS)

    def test_a_box_above_a_closed_block_opens_it(self):
        self.assertIn("block?.previousElementSibling?.matches('.rb-table-filter')", self.TS)
        self.assertIn("if (block && query) block.open = true;", self.TS)

    def test_a_link_to_a_folded_card_opens_its_row(self):
        start = self.TS.index("const openTargetBlock = () =>")
        body = self.TS[start:self.TS.index("};", start)]
        self.assertIn("closest('details')", body)
        self.assertIn("block.open = true;", body)
        self.assertIn("addEventListener('hashchange', openTargetBlock);", self.TS)

    def test_an_open_card_takes_the_table_width(self):
        self.assertIn(".sl-markdown-content .rb-entries-wrap { container-type: inline-size; }",
                      self.CSS)
        self.assertIn("details.rb-entry[open] > :not(summary) { width: 100cqi; }", self.CSS)


class _Visible(HTMLParser):
    """Words in <main> outside closed blocks (their summary shows)."""

    VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                      "meta", "source", "track", "wbr"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, str]] = []
        self.hidden = self.main = self.skip = 0
        self.words = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        effect = ""
        if tag == "summary" and self.stack and self.stack[-1][1] == "hide":
            self.hidden -= 1
            effect = "show"
        elif tag == "details" and "open" not in dict(attrs):
            self.hidden += 1
            effect = "hide"
        if tag in ("script", "style", "template"):
            self.skip += 1
        if tag == "main":
            self.main += 1
        self.stack.append((tag, effect))

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        while self.stack:
            name, effect = self.stack.pop()
            self.hidden += {"hide": -1, "show": 1}.get(effect, 0)
            self.skip -= name in ("script", "style", "template")
            self.main -= name == "main"
            if name == tag:
                break

    def handle_data(self, data):
        if self.main and not self.skip and not self.hidden:
            self.words += len(data.split())


def _visible_words(page: str) -> int:
    parser = _Visible()
    parser.feed((DIST / page / "index.html").read_text(encoding="utf-8"))
    return parser.words


# Words a visitor sees with every block closed, by page type: the largest
# measured after the change plus 5 %, never above the largest before it.
# Before: MAME parts 16,680, long emulator pages 14,396 (groovymame),
# wanted lists 346 (tosec). After: 1,612, 2,000 (yaps2), 118.
VISIBLE_CEILINGS = {
    "emulator card parts": (r"emulators/[a-z0-9-]+-files-\d+$", 1_693),
    "long emulator pages": (r"emulators/(groovymame|yaps2|bizhawk|bluemsx|fbneo)$", 2_100),
    "wanted lists": (r"provenance-[a-z-]+$", 124),
}


@unittest.skipUnless((DIST / "emulators" / "mame-files-1" / "index.html").exists(),
                     "website/dist is not built")
class TheBuiltPagesStayShort(unittest.TestCase):
    def _pages(self, pattern: str) -> list[str]:
        found = [path.parent.relative_to(DIST).as_posix() for path in DIST.glob("**/index.html")]
        return sorted(page for page in found if re.fullmatch(pattern, page))

    def test_visible_words_under_each_ceiling(self):
        for kind, (pattern, ceiling) in VISIBLE_CEILINGS.items():
            pages = self._pages(pattern)
            self.assertTrue(pages, kind)
            for page in pages:
                with self.subTest(page=page):
                    self.assertLessEqual(_visible_words(page), ceiling, kind)

    def test_under_the_element_budget(self):
        for pattern, _ceiling in VISIBLE_CEILINGS.values():
            for page in self._pages(pattern):
                with self.subTest(page=page):
                    parsed = validate_site._PageParser(DIST / page / "index.html")
                    parsed.feed((DIST / page / "index.html").read_text(encoding="utf-8"))
                    self.assertLessEqual(parsed.page.elements, validate_site.MAX_PAGE_ELEMENTS)

    def test_every_mame_set_and_member_is_on_a_part(self):
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "mame.yml").read_text(encoding="utf-8"))
        html = "".join((DIST / page / "index.html").read_text(encoding="utf-8")
                       for page in self._pages(r"emulators/mame-files-\d+"))
        for f in profile["files"]:
            with self.subTest(name=f["name"]):
                self.assertIn(f"{f['name']}</code></h3></summary>", html)
                for member in f.get("contents") or []:
                    if member.get("crc32"):
                        self.assertIn(str(member["crc32"]), html)
                    if member.get("sha1"):
                        self.assertIn(str(member["sha1"]), html)


if __name__ == "__main__":
    unittest.main()
