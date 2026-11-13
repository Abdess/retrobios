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

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import re
import statistics
import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from tests import sitepages  # noqa: E402

DOCS = sitepages.CONTENT

# Level 0: the Start here pages, with their own ceiling on words.
START_PAGES = {
    "index.md": 220,
    "which-pack.md": 400,
    "wiki/what-are-bios-files.md": 300,
    "wiki/first-install.md": 400,
    "wiki/troubleshooting.md": 300,
    "wiki/faq.md": 450,
    "wiki/glossary.md": 200,
}
# Reference pages written for anyone, held to the Start here budgets.
START_LEVEL_PAGES = {
    "wiki/measurements.md": 300,
    "wiki/archive-recipes.md": 160,
    "wanted.md": 160,
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

WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'._/\\:%~-]*")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\"(*\[])")


@dataclass
class Block:
    kind: str  # paragraph, item, term, definition, heading, table
    text: str
    collapsed: bool = False
    defines: str = ""
    hidden: bool = False  # in a tab other than the first: read instead of the first


@dataclass
class Page:
    blocks: list[Block] = field(default_factory=list)
    before_action: int | None = None
    list_runs: list[int] = field(default_factory=list)

    def prose(self) -> list[Block]:
        return [b for b in self.blocks if b.kind in ("paragraph", "item", "term", "definition")]

    def words(self) -> int:
        return sum(count_words(b.text) for b in self.blocks if b.kind != "table" and not b.hidden)

    def sentences(self) -> list[str]:
        return [s for b in self.prose() for s in split_sentences(b.text)]


def strip_inline(text: str) -> str:
    """Link text kept, targets, attribute lists, images and markup dropped."""
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\{\s*[#.:][^}]*\}", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    return text.replace("**", "").strip()


def count_words(text: str) -> int:
    return len(WORD.findall(re.sub(r"`[^`]*`", "code", text)))


def split_sentences(text: str) -> list[str]:
    return [s for s in SENTENCE_END.split(text.strip()) if WORD.search(s)]


def guide_part(markdown: str) -> str:
    """A page up to its Reference heading, without front matter."""
    if markdown.startswith("---\n"):
        markdown = markdown.split("\n---\n", 1)[1]
    match = re.search(r"^## Reference\b", markdown, re.M)
    return markdown[: match.start()] if match else markdown


def parse(markdown: str) -> Page:
    """Blocks of prose a reader sees, code and HTML left out.

    A collapsed block (<details>) counts, but not before the first action:
    the reader opens it on purpose. Of a group of tabs the first is read and
    the others only stand in for it.
    """
    text = guide_part(markdown)
    text = re.sub(r"<script.*?</script>", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    page = Page()
    seen_words = 0
    details = 0  # depth of collapsed blocks
    tab = 0  # the tab of a group being read, 0 outside a group
    fence: str | None = None
    current: list[str] = []
    kind = "paragraph"
    run = 0

    def flush() -> None:
        nonlocal current, seen_words, kind
        if current:
            body = strip_inline(" ".join(current))
            if WORD.search(body):
                term = page.blocks[-1].text.lower() if kind == "definition" and page.blocks else ""
                block = Block(kind, body, details > 0, term, tab > 1)
                page.blocks.append(block)
                if (page.before_action is None and not block.collapsed
                        and not block.hidden and kind not in ("table", "heading")):
                    seen_words += count_words(body)
        current = []
        if kind in ("item", "definition", "heading"):
            kind = "paragraph"

    def act() -> None:
        flush()
        if page.before_action is None:
            page.before_action = seen_words

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if fence:
            if stripped.startswith(fence):
                fence = None
            continue
        if stripped.startswith(("```", "~~~")):
            fence = stripped[:3]
            if tab < 2:
                act()
            continue
        if not stripped:
            flush()
            continue
        if stripped.startswith("import ") and stripped.endswith(";"):
            continue
        if stripped.startswith(":::"):
            flush()
            continue
        if stripped.startswith("<details"):
            flush()
            details += 1
            continue
        if stripped.startswith("</details>"):
            flush()
            details = max(0, details - 1)
            continue
        if stripped.startswith("<Tabs"):
            flush()
            tab = 0
            continue
        if stripped.startswith("<TabItem"):
            flush()
            tab += 1
            continue
        if stripped.startswith("</Tabs>"):
            flush()
            tab = 0
            continue
        if "rb-button" in stripped or "rb-tile" in stripped or stripped.startswith(
                ("<FilePicker", "<WantedFiles")):
            act()
            continue
        if re.match(r"</?(?!abbr\b|a\b|code\b|strong\b|em\b)[A-Za-z]", stripped):
            flush()
            continue
        if stripped.startswith("#"):
            flush()
            if run:
                page.list_runs.append(run)
                run = 0
            kind = "heading"
            current = [re.sub(r"\s*\{[^}]*\}\s*$", "", stripped.lstrip("#").strip())]
            flush()
            kind = "paragraph"
            continue
        if stripped.startswith("|"):
            if kind != "table":
                flush()
                kind = "table"
            if not re.fullmatch(r"\|[\s:|-]+\|?", stripped):
                current.append(stripped.replace("|", " "))
            continue
        if kind == "table":
            flush()
            kind = "paragraph"
        item = re.match(r"(?:[-*+]|\d+\.)\s+(.*)", stripped)
        definition = re.match(r":\s+(.*)", stripped)
        if item:
            flush()
            kind = "item"
            run += 1
            current = [item.group(1)]
            continue
        if definition:
            flush()
            if page.blocks and page.blocks[-1].kind == "paragraph":
                page.blocks[-1].kind = "term"
            kind = "definition"
            current = [definition.group(1)]
            continue
        if kind == "item" and indent == 0:
            flush()
            kind = "paragraph"
        if kind == "paragraph" and run:
            page.list_runs.append(run)
            run = 0
        if not current and kind in ("item", "definition") and indent == 0:
            kind = "paragraph"
        current.append(stripped)
    flush()
    if run:
        page.list_runs.append(run)
    return page


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
        for phrase in FILLER:
            if re.search(rf"(?<![\w-]){re.escape(phrase)}(?![\w-])", lower):
                found.append(phrase)
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


def _docs() -> Path:
    return sitepages.require()


def _load(name: str) -> Page:
    _docs()
    return parse(sitepages.page(name).read_text(encoding="utf-8"))


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
