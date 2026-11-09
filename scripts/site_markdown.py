#!/usr/bin/env python3
"""Each built page as Markdown, for the assistants that read the site.

An assistant asked to help with BIOS files reads a page and answers from
it. The HTML carries navigation, icons, buttons and scripts around the
words; the Markdown copy carries the words, the tables, the commands and
the links, at `<page>/index.md` beside `<page>/index.html`. Every page's
head names it (`<link rel="alternate" type="text/markdown">`, set in
website/astro.config.mjs), and llms.txt says the convention.

`llms-full.txt` joins the Markdown of the pages a setup is done with:
the start pages, the guides and each setup's page.

Run by the Astro build once the pages are written (astro.config.mjs),
on the built site:

    python scripts/site_markdown.py website/dist
"""

from __future__ import annotations

import argparse
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

SITE = "https://abdess.github.io"
BASE = "/retrobios/"
# Elements whose content is never words a reader needs.
SKIPPED = frozenset({"script", "style", "svg", "button", "nav", "template", "noscript", "video"})
HEADINGS = {f"h{n}": n for n in range(1, 7)}
# The pages llms-full.txt joins, by path under the site, in reading order.
FULL_PAGES = ("", "which-pack/", "wiki/what-are-bios-files/", "wiki/first-install/",
              "wiki/troubleshooting/", "wiki/faq/", "wiki/installer/", "wiki/legal/",
              "wiki/privacy/")


class _Converter(HTMLParser):
    """The Markdown of a page's article: its title and its content."""

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.out: list[str] = []
        self.skip = 0
        self.inside = 0
        self.depth_stack: list[str] = []
        self.lists: list[list[int]] = []
        self.pre = 0
        self.links: list[str | None] = []
        self.row: list[str] | None = None
        self.cell: list[str] | None = None
        self.table: list[list[str]] | None = None
        self.header_rows = 0
        self.title = ""
        self._in_title = False
        # A tab's name by its id, read from the tab list, said above its
        # panel: a command under the wrong OS is the answer an assistant
        # gets wrong.
        self.tab_names: dict[str, str] = {}
        self._tab: str | None = None
        self._card = False

    # Output

    def _emit(self, text: str) -> None:
        if self.cell is not None:
            self.cell.append(text)
        else:
            self.out.append(text)

    def _block(self) -> None:
        if self.cell is not None:
            self.cell.append(" ")
            return
        joined = "".join(self.out)
        if joined and not joined.endswith("\n\n"):
            self.out.append("\n" if joined.endswith("\n") else "\n\n")

    # Parsing

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key: value or "" for key, value in attrs}
        classes = set(attr.get("class", "").split())
        if tag == "h1" and attr.get("id") == "_top":
            self._in_title = True
        if not self.inside:
            if "sl-markdown-content" in classes:
                self.inside = 1
                self.depth_stack = [tag]
            return
        if tag not in ("br", "img", "hr", "input", "meta", "link", "source", "wbr"):
            self.depth_stack.append(tag)
        if attr.get("role") == "tablist":
            self.skip += 1
            if tag == "a" or attr.get("role") == "tab":
                pass
            return
        if self.skip and attr.get("role") == "tab" and attr.get("id"):
            self._tab = attr["id"]
            self.tab_names[self._tab] = ""
            self.skip += 1
            return
        if attr.get("role") == "tabpanel" and not self.skip:
            self._block()
            name = self.tab_names.get(attr.get("aria-labelledby", ""), "").strip()
            if name:
                self._emit(f"**{' '.join(name.split())}:**")
                self._block()
            return
        if self.skip or tag in SKIPPED or attr.get("aria-hidden") == "true" \
                or classes & {"sr-only", "sl-anchor-link", "copy", "rb-anchor"}:
            if tag not in ("br", "img", "hr", "input", "wbr"):
                self.skip += 1
            return
        if self.pre:
            # Inside a code block a line is a div, never a paragraph.
            if tag == "div" and "ec-line" in classes and not "".join(self.out[-1:]).endswith("```\n"):
                self._emit("\n")
            return
        if tag in HEADINGS:
            self._block()
            self._emit("#" * HEADINGS[tag] + " ")
        elif tag in ("p", "div", "section", "figure", "details", "blockquote", "dl"):
            self._block()
        elif tag == "summary":
            self._block()
            self._emit("**")
        elif tag in ("ul", "ol"):
            self._block()
            self.lists.append([0 if tag == "ol" else -1])
        elif tag == "li":
            if self.out and not "".join(self.out[-1:]).endswith("\n"):
                self._emit("\n")
            level = len(self.lists) - 1
            marker = "-"
            if self.lists and self.lists[-1][0] >= 0:
                self.lists[-1][0] += 1
                marker = f"{self.lists[-1][0]}."
            self._emit("  " * max(level, 0) + marker + " ")
        elif tag == "pre":
            self._block()
            self.pre += 1
            self._emit("```\n")
        elif tag == "code" and not self.pre:
            self._emit("`")
        elif tag in ("strong", "b"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag == "a" and "rb-card" in classes:
            # A card of a grid: one list line each, its name then what it
            # says, instead of one run-on line of links.
            href = attr.get("href", "")
            href = SITE + href if href.startswith("/") else href
            self._block()
            self._emit("- [")
            self.links.append(href or None)
            self._card = True
        elif tag == "span" and self._card and self.links:
            self._emit(": ")
        elif tag == "a":
            href = attr.get("href", "")
            if href.startswith("#"):
                href = self.page_url + href
            elif href.startswith("/"):
                href = SITE + href
            self.links.append(href or None)
            if href:
                self._emit("[")
        elif tag == "img":
            alt = attr.get("alt", "").strip()
            if alt:
                self._emit(alt)
        elif tag == "table":
            self._block()
            self.table, self.header_rows = [], 0
        elif tag == "tr" and self.table is not None:
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []
            if tag == "th" and not self.row:
                self.header_rows = max(self.header_rows, len(self.table or []) + 1)
        elif tag == "dt":
            self._block()
            self._emit("**")
        elif tag == "dd":
            self._emit(": ")

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._in_title:
            self._in_title = False
        if not self.inside:
            return
        if self.depth_stack:
            self.depth_stack.pop()
        if not self.depth_stack:
            self.inside = 0
            return
        if self.skip:
            if tag not in ("br", "img", "hr", "input", "wbr"):
                self.skip -= 1
            if tag == "a" and self._tab:
                self._tab = None
            return
        if self.pre and tag != "pre":
            return
        if tag in HEADINGS or tag in ("p", "section", "figure", "details", "blockquote", "dl"):
            self._block()
        elif tag == "summary":
            self._emit("**")
            self._block()
        elif tag in ("ul", "ol"):
            if self.lists:
                self.lists.pop()
            self._block()
        elif tag == "pre":
            self.pre -= 1
            self._emit("\n```")
            self._block()
        elif tag == "code" and not self.pre:
            self._emit("`")
        elif tag in ("strong", "b", "dt"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag == "a":
            href = self.links.pop() if self.links else None
            if href:
                self._emit(f"]({href})")
            if self._card:
                self._card = False
                self._emit("\n")
        elif tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append(" ".join("".join(self.cell).split()).replace("|", "\\|"))
            self.cell = None
        elif tag == "tr" and self.row is not None and self.table is not None:
            self.table.append(self.row)
            self.row = None
        elif tag == "table" and self.table is not None:
            rows, self.table = self.table, None
            if rows:
                width = max(len(r) for r in rows)
                rows = [r + [""] * (width - len(r)) for r in rows]
                head = rows[0] if self.header_rows else [""] * width
                body = rows[1:] if self.header_rows else rows
                lines = ["| " + " | ".join(head) + " |", "|" + "---|" * width]
                lines += ["| " + " | ".join(r) + " |" for r in body]
                self.out.append("\n".join(lines))
                self._block()
        elif tag == "br":
            self._emit("\n" if self.pre else "  \n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in ("img", "br", "hr", "input", "wbr", "meta", "link", "source"):
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.inside:
            self.title += data
            return
        if self._tab is not None:
            self.tab_names[self._tab] += data
        if not self.inside or self.skip:
            return
        if self.pre:
            # The whitespace between <pre> and its first line is no line.
            if data.strip() or not "".join(self.out[-1:]).endswith("```\n"):
                self._emit(data)
            return
        text = re.sub(r"\s+", " ", data)
        if text.strip() or (text and self.out and not "".join(self.out[-1:]).endswith((" ", "\n"))):
            self._emit(text)

    def markdown(self) -> str:
        body = "".join(self.out)
        body = re.sub(r"[ \t]+\n", "\n", body)
        body = re.sub(r"\n{3,}", "\n\n", body).strip()
        title = " ".join(self.title.split())
        return (f"# {title}\n\n" if title else "") + f"Source: {self.page_url}\n\n{body}\n"


def page_markdown(html: str, page_url: str) -> str:
    converter = _Converter(page_url)
    converter.feed(html)
    converter.close()
    return converter.markdown()


def convert_site(dist: Path) -> int:
    """Write index.md beside every page's index.html, then llms-full.txt."""
    written = 0
    for html_path in sorted(dist.rglob("index.html")):
        relative = html_path.parent.relative_to(dist).as_posix()
        page = "" if relative == "." else f"{relative}/"
        url = f"{SITE}{BASE}{page}"
        text = page_markdown(html_path.read_text(encoding="utf-8"), url)
        (html_path.parent / "index.md").write_text(text, encoding="utf-8")
        written += 1
    write_full(dist)
    return written


def write_full(dist: Path) -> None:
    """llms-full.txt from the pages' Markdown copies."""
    parts = ["# RetroBIOS: the guides in one file", "",
             "> The pages a setup is done with, in reading order. Every page of the site also has "
             "its own Markdown copy at `<page>/index.md`.", ""]
    for page in FULL_PAGES:
        md = dist / page / "index.md"
        if md.is_file():
            parts += [md.read_text(encoding="utf-8").rstrip(), "", "---", ""]
    # Each setup's own page (the setups the picker lists, not the parts a
    # long page is cut into), up to its reference of every file: what to
    # do and where, not the full lists, which its own copy keeps. All of
    # them was 6.9 MB, past what an assistant reads at once.
    import json  # noqa: PLC0415

    index = dist / "data" / "picker" / "index.json"
    setups = [str(item["platform"]) for item in json.loads(index.read_text(encoding="utf-8"))] \
        if index.is_file() else []
    for setup in [*setups, "linux-handhelds"]:
        md = dist / "platforms" / setup / "index.md"
        if md.is_file():
            text = md.read_text(encoding="utf-8")
            parts += [text.split("\n## Reference", 1)[0].rstrip(), "", "---", ""]
    (dist / "llms-full.txt").write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    parser.add_argument("dist", type=Path, help="the built site (website/dist)")
    args = parser.parse_args()
    if not (args.dist / "index.html").is_file():
        print(f"error: {args.dist} holds no built site", file=sys.stderr)
        return 1
    count = convert_site(args.dist)
    print(f"Markdown copies: {count} pages, llms-full.txt", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
