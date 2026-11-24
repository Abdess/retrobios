"""The pages a newcomer reads stay short, plain and quick to act on.

The Start here pages ran 460 to 1,950 words, the first command of the
download page sat 2.8 phone screens down, and a sentence of 57 words listed
every platform's check. Each budget below is a number on the built page:
words before the first action, sentence and block length, words per page, and
a list of words a newcomer does not know or does not need.

Run ``python -m tests.test_site_copy --report website/src/content/docs`` to
print the measures of every page held here.
"""

from __future__ import annotations

import tests

import re
import statistics
import sys
import unittest
from pathlib import Path

from tests import sitepages
from tests.sitecopy import (
    Block,
    Page,
    START_PAGES,
    _docs,
    _load,
    count_words,
    parse,
    split_sentences,
)

DOCS = sitepages.CONTENT

# Reference pages written for anyone, held to the Start here budgets.
START_LEVEL_PAGES = {
    "wiki/measurements.md": 300,
    "wiki/archive-recipes.md": 160,
    # The drop box, then the steps from a file in hand to its merge.
    "wanted.md": 260,
}
# Level 1: the guide part of each setup page, above its Reference heading.
SETUP_CEILING = 220
# The setup index is a card per setup, one sentence each.
SETUP_INDEX_CEILING = 300

BUDGETS = {
    #            longest sentence, median sentence, longest block, words before the first action
    "start": (20, 12, 35, 50),
    "setup": (25, 14, 40, 90),
}
HOME_BEFORE_ACTION = 40
LIST_ITEMS = {"start": 5, "setup": 6}
HEADING_WORDS = 8

# Words that say nothing, or talk about the page instead of the task. The
# marketing words are held on every page by test_prose_style.
FILLER = (
    "just", "simply", "easy", "easily", "easiest", "basically", "actually",
    "really", "very", "quite", "note that", "please note", "keep in mind",
    "of course", "obviously", "clearly", "in order to", "worth", "goes through",
    "covers", "explains", "says more", "says where it stands", "what follows",
    "this page", "these pages", "each section", "the last section",
    "the rest of this page", "further down", "the usual causes", "come up",
    "one path", "a few minutes", "is the answer", "the normal way", "not a fault",
    "does not pretend", "plainly", "for when you want", "for your own tools",
    "welcome",
    "ensure", "utilize", "facilitate", "via", "e.g.", "i.e.", "etc.", "vs.",
    "respectively", "deliberately",
)
# Words a newcomer meets only with their meaning in the same sentence. The
# value is the gloss that makes the word allowed there, None when no gloss
# does: such a word belongs one level down.
JARGON = {
    "checksum": None, "md5": None, "sha1": None, "sha-1": None, "sha-256": None,
    "crc32": None, "hash": r"fingerprint", "manifest": None, "bootstrap": None,
    "execution policy": None, "libretro": None, "standalone": None, "hle": None,
    "dump": None, "revision": None, "verified": None, "frontend": None,
    "system id": None, "upstream": None, "scrape": None, "yaml": None,
    "json": None, "csv": None, "sqlite": None, "repository": None,
    "release asset": None, "rom set": None, "casefold": None,
    "case-sensitive": None, "mount": None, "read-only": None, "proxy": None,
    "https_proxy": None, "sudo": r"administrator", "ssh": r"terminal over the network",
    "termux": r"terminal app", "core": r"small emulator|one emulator|its own emulator",
    "interoperability": None, "fair use": None, "dmca": None, "circumvent": None,
    "rerecording": None, "fpga cores": None, "de10-nano": None, "amlogic": None,
    "rk356x": None, "h700": None, "rk3399": None, "emulationstation": None,
    "extract": None, "extracted": None,
}
# Level 0 says ZIP and setup, a setup page names its own pack and platform.
START_ONLY = {"pack": None, "packs": None, "platform": None, "platforms": None}
# A word glossed in place: "X, a ...", "X (a ...", "called X".
GENERIC_GLOSS = r"(?:{w}\*{{0,2}}, an? |{w}\*{{0,2}} \(an? |called \*{{0,2}}{w})"


def banned(block: Block, level: str) -> list[str]:
    """Filler, and jargon met without its meaning beside it."""
    found = []
    text = re.sub(r"`[^`]*`", "", block.text)
    if block.kind == "heading" and text.rstrip().endswith("."):
        return []  # a heading that quotes an installer message
    if block.kind == "term":
        return []
    for sentence in split_sentences(text) or [text]:
        lower = sentence.lower()
        found.extend(
            phrase
            for phrase in FILLER
            if re.search(rf"(?<![\w-]){re.escape(phrase)}(?![\w-])", lower)
        )
        terms = dict(JARGON)
        if level == "start":
            terms.update(START_ONLY)
        for term, gloss in terms.items():
            if not re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", lower):
                continue
            if gloss and re.search(gloss, lower):
                continue
            if re.search(GENERIC_GLOSS.format(w=re.escape(term)), lower):
                continue
            if term in block.defines:
                continue
            found.append(term)
    return found


def measure(page: Page) -> dict:
    lengths = [count_words(s) for s in page.sentences()]
    return {
        "words": page.words(),
        "before_action": page.before_action,
        "max_block": max((count_words(b.text) for b in page.prose()), default=0),
        "median_sentence": statistics.median(lengths) if lengths else 0,
        "max_sentence": max(lengths, default=0),
    }


def held_pages(docs: Path) -> list[tuple[str, str, int]]:
    """(relative path, level, ceiling) for every page the budgets hold."""
    pages = [(name, "start", ceiling)
             for name, ceiling in {**START_PAGES, **START_LEVEL_PAGES}.items()]
    pages += [
        (sitepages.name(path), "setup", SETUP_CEILING)
        for path in sorted((docs / "platforms").glob("*.md*"))
        if path.stem != "index"
        and "\n## Where the files go" in path.read_text(encoding="utf-8")
    ]
    pages.append(("platforms/index.md", "setup", SETUP_INDEX_CEILING))
    return [(name, level, ceiling) for name, level, ceiling in pages
            if sitepages.page(name).is_file()]


class CopyBudgets(unittest.TestCase):
    def test_sentences_stay_short(self):
        for name, level, _ceiling in held_pages(_docs()):
            longest, median, _block, _before = BUDGETS[level]
            page = _load(name)
            with self.subTest(page=name):
                long = [s for s in page.sentences() if count_words(s) > longest]
                self.assertEqual(long, [], f"sentences over {longest} words")
                self.assertLessEqual(measure(page)["median_sentence"], median)

    def test_blocks_stay_short(self):
        for name, level, _ceiling in held_pages(_docs()):
            limit = BUDGETS[level][2]
            page = _load(name)
            with self.subTest(page=name):
                long = [b.text for b in page.prose() if count_words(b.text) > limit]
                self.assertEqual(long, [], f"blocks over {limit} words")

    def test_the_first_action_comes_early(self):
        for name, level, _ceiling in held_pages(_docs()):
            limit = HOME_BEFORE_ACTION if name == "index.md" else BUDGETS[level][3]
            page = _load(name)
            if page.before_action is None:
                continue  # a page of definitions has nothing to run
            with self.subTest(page=name):
                self.assertLessEqual(page.before_action, limit)

    def test_pages_stay_under_their_ceiling(self):
        for name, _level, ceiling in held_pages(_docs()):
            with self.subTest(page=name):
                self.assertLessEqual(_load(name).words(), ceiling)

    def test_lists_of_choices_stay_short(self):
        for name, level, _ceiling in held_pages(_docs()):
            with self.subTest(page=name):
                self.assertLessEqual(max(_load(name).list_runs, default=0), LIST_ITEMS[level])

    def test_headings_stay_short(self):
        for name, _level, _ceiling in held_pages(_docs()):
            page = _load(name)
            long = [
                b.text for b in page.blocks
                if b.kind == "heading" and not b.text.endswith(".")
                and count_words(re.sub(r"`[^`]*`", "", b.text)) > HEADING_WORDS
            ]
            with self.subTest(page=name):
                self.assertEqual(long, [])


class PlainWords(unittest.TestCase):
    def test_no_filler_and_no_unexplained_jargon(self):
        offenders = []
        for name, level, _ceiling in held_pages(_docs()):
            for block in _load(name).blocks:
                if block.kind == "table":
                    continue
                words = banned(block, level)
                if words:
                    offenders.append(f"{name}: {sorted(set(words))} in: {block.text[:90]}")
        self.assertEqual(offenders, [], "\n".join(offenders[:40]))


class TheMeasureItself(unittest.TestCase):
    """The parser decides every number above, so it is held on a sample."""

    SAMPLE = (
        "---\nlevel: start\n---\n\n# Title\n\nOne two three. Four five.\n\n"
        "- Item **one**.\n- Item [two](x.md).\n\n```sh\nnot counted at all\n```\n\n"
        '<details class="rb-details rb-details-note">\n<summary>Hidden</summary>\n\n'
        "Collapsed words here.\n\n</details>\n\n"
        '<Tabs syncKey="os">\n<TabItem label="A">\n\nFirst tab.\n\n</TabItem>\n'
        '<TabItem label="B">\n\nSecond tab words.\n\n</TabItem>\n</Tabs>\n\n'
        "| A | B |\n|---|---|\n| cell | cell |\n\n## Reference: deep\n\nNot read.\n"
    )

    def test_blocks_and_counts(self):
        page = parse(self.SAMPLE)
        kinds = [b.kind for b in page.blocks]
        self.assertEqual(kinds, ["heading", "paragraph", "item", "item", "paragraph",
                                 "paragraph", "paragraph", "table"])
        self.assertEqual([b.hidden for b in page.blocks[5:7]], [False, True])
        self.assertEqual(page.words(), 1 + 5 + 2 + 2 + 3 + 2)
        self.assertEqual(page.before_action, 5 + 2 + 2)
        self.assertEqual(page.list_runs, [2])
        self.assertTrue(page.blocks[4].collapsed)
        self.assertEqual(page.sentences()[:2], ["One two three.", "Four five."])

    def test_a_gloss_allows_a_term(self):
        self.assertEqual(banned(Block("paragraph", "Install Termux, a terminal app."), "start"), [])
        self.assertEqual(banned(Block("paragraph", "Open Termux."), "start"), ["termux"])
        self.assertEqual(banned(Block("paragraph", "Run `sudo` first."), "start"), [])
        self.assertEqual(banned(Block("paragraph", "It is very easy."), "start"), ["easy", "very"])
        self.assertEqual(banned(Block("paragraph", "The RetroArch pack."), "setup"), [])


def report(docs: Path) -> str:
    rows = ["| Page | Words | Before action | Max block | Median / max sentence |",
            "|---|---:|---:|---:|---|"]
    for name, _level, _ceiling in held_pages(docs):
        m = measure(parse(sitepages.page(name).read_text(encoding="utf-8")))
        before = "none" if m["before_action"] is None else m["before_action"]
        rows.append(f"| {name} | {m['words']} | {before} | {m['max_block']} | "
                    f"{m['median_sentence']:g} / {m['max_sentence']} |")
    return "\n".join(rows)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--report":
        print(report(Path(sys.argv[2])))
    else:
        unittest.main()
