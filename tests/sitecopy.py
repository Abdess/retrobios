"""The reader the copy budgets measure a generated page with."""

from __future__ import annotations

import tests

import re
from dataclasses import dataclass, field
from pathlib import Path

from tests import sitepages


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


class _PageParser:
    """The state parse() carries from one line to the next."""

    def __init__(self) -> None:
        self.page = Page()
        self.seen_words = 0
        self.details = 0  # depth of collapsed blocks
        self.tab = 0  # the tab of a group being read, 0 outside a group
        self.fence: str | None = None
        self.current: list[str] = []
        self.kind = "paragraph"
        self.run = 0

    def flush(self) -> None:
        page = self.page
        if self.current:
            body = strip_inline(" ".join(self.current))
            if WORD.search(body):
                kind = self.kind
                term = page.blocks[-1].text.lower() if kind == "definition" and page.blocks else ""
                block = Block(kind, body, self.details > 0, term, self.tab > 1)
                page.blocks.append(block)
                if (page.before_action is None and not block.collapsed
                        and not block.hidden and kind not in ("table", "heading")):
                    self.seen_words += count_words(body)
        self.current = []
        if self.kind in ("item", "definition", "heading"):
            self.kind = "paragraph"

    def act(self) -> None:
        self.flush()
        if self.page.before_action is None:
            self.page.before_action = self.seen_words

    def end_run(self) -> None:
        if self.run:
            self.page.list_runs.append(self.run)
            self.run = 0

    def feed(self, raw: str) -> None:
        line = raw.rstrip()
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if self.fence:
            if stripped.startswith(self.fence):
                self.fence = None
            return
        if self._markup(stripped):
            return
        if stripped.startswith("#"):
            self._heading(stripped)
            return
        if stripped.startswith("|"):
            self._table_row(stripped)
            return
        self._prose(stripped, indent)

    def _markup(self, stripped: str) -> bool:
        """Fences, blank lines and HTML: True when the line is consumed."""
        if stripped.startswith(("```", "~~~")):
            self.fence = stripped[:3]
            if self.tab < 2:
                self.act()
            return True
        if not stripped:
            self.flush()
            return True
        if stripped.startswith("import ") and stripped.endswith(";"):
            return True
        if stripped.startswith(":::"):
            self.flush()
            return True
        if self._container(stripped):
            return True
        if "rb-button" in stripped or "rb-tile" in stripped or stripped.startswith(
                ("<FilePicker", "<WantedFiles")):
            self.act()
            return True
        if re.match(r"</?(?!abbr\b|a\b|code\b|strong\b|em\b)[A-Za-z]", stripped):
            self.flush()
            return True
        return False

    def _container(self, stripped: str) -> bool:
        """Collapsed blocks and tab groups: True when the line is consumed."""
        if stripped.startswith("<details"):
            self.flush()
            self.details += 1
            return True
        if stripped.startswith("</details>"):
            self.flush()
            self.details = max(0, self.details - 1)
            return True
        if stripped.startswith("<Tabs"):
            self.flush()
            self.tab = 0
            return True
        if stripped.startswith("<TabItem"):
            self.flush()
            self.tab += 1
            return True
        if stripped.startswith("</Tabs>"):
            self.flush()
            self.tab = 0
            return True
        return False

    def _heading(self, stripped: str) -> None:
        self.flush()
        self.end_run()
        self.kind = "heading"
        self.current = [re.sub(r"\s*\{[^}]*\}\s*$", "", stripped.lstrip("#").strip())]
        self.flush()
        self.kind = "paragraph"

    def _table_row(self, stripped: str) -> None:
        if self.kind != "table":
            self.flush()
            self.kind = "table"
        if not re.fullmatch(r"\|[\s:|-]+\|?", stripped):
            self.current.append(stripped.replace("|", " "))

    def _prose(self, stripped: str, indent: int) -> None:
        if self.kind == "table":
            self.flush()
            self.kind = "paragraph"
        item = re.match(r"(?:[-*+]|\d+\.)\s+(.*)", stripped)
        definition = re.match(r":\s+(.*)", stripped)
        if item:
            self.flush()
            self.kind = "item"
            self.run += 1
            self.current = [item.group(1)]
            return
        if definition:
            self.flush()
            page = self.page
            if page.blocks and page.blocks[-1].kind == "paragraph":
                page.blocks[-1].kind = "term"
            self.kind = "definition"
            self.current = [definition.group(1)]
            return
        if self.kind == "item" and indent == 0:
            self.flush()
            self.kind = "paragraph"
        if self.kind == "paragraph":
            self.end_run()
        if not self.current and self.kind in ("item", "definition") and indent == 0:
            self.kind = "paragraph"
        self.current.append(stripped)

    def finish(self) -> Page:
        self.flush()
        if self.run:
            self.page.list_runs.append(self.run)
        return self.page


def parse(markdown: str) -> Page:
    """Blocks of prose a reader sees, code and HTML left out.

    A collapsed block (<details>) counts, but not before the first action:
    the reader opens it on purpose. Of a group of tabs the first is read and
    the others only stand in for it.
    """
    text = guide_part(markdown)
    text = re.sub(r"<script.*?</script>", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    parser = _PageParser()
    for raw in text.splitlines():
        parser.feed(raw)
    return parser.finish()


def _docs() -> Path:
    return sitepages.require()


def _load(name: str) -> Page:
    _docs()
    return parse(sitepages.page(name).read_text(encoding="utf-8"))
