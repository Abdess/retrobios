"""Front matter, page levels and search weight given to every page."""

from __future__ import annotations

import functools
import re
import sys
import urllib.request
from pathlib import Path

import release_record
from model import siteinputs
from model.database import load_database
from sitegen import markup, measurements as sitemeasurements, starlight as sitestarlight
from sitegen.config import SITE_NAME, SITE_URL, _REPO_ROOT, yaml
from sitegen.descriptions import PAGE_DATA, _browser_title, _page_description, _page_title
from sitegen.diagrams import prepare_page, unresolved_images
from sitegen.render import WIKI_SRC_DIR
from sitegen.write import _undecorated, write_decorated


# Working notes kept under docs/ during development, never part of the site,
# and no generated page lives in a directory of these names.
LOCAL_NOTE_DIRS = ("plans", "specs")


# The funnel: who each page is written for, from someone who knows nothing
# (start) to someone adding to the project (contribute). The label sits above
# the title, and the search ranks the first two levels higher.
LEVELS = {
    "start": "Start here",
    "setup": "Setup guide",
    "explore": "Details",
    "reference": "Reference",
    "contribute": "For contributors",
}
# How much the site search weighs the words of a page (Pagefind's
# data-pagefind-weight, 1 by default). Each value was measured on the
# queries of website/tools/search_gate.py.
# - Start here pages answer a beginner's words first.
# - A system page holds the file cards themselves: a file name finds its
#   card before a guide that cites the name as an example.
# - A setup guide is found by its name (the page title weighs it).
# - A guide behind the first two levels (reference, options, contributing)
#   names everything a reader types, and ranks after the page that answers.
# - A launcher, an alias or a frozen copy answers a name after the emulator.
# - A part of a split page (a console's files, 5 of 9) holds cards, each found
#   by its own heading, and ranks after the page that answers the question.
SEARCH_WEIGHT = {"start": 10, "setup": 1.5, "reference": 0.5, "contribute": 0.5, "part": 0.5}
SYSTEM_PAGE_WEIGHT = 5
DEEP_GUIDE_WEIGHT = 0.5
SEARCH_DEMOTED: set[str] = set()
# A tool page a reader reaches by a task, not its name: "check my dump",
# "md5 check" found emulator pages and never the page that checks a file.
SEARCH_WEIGHT_OF_PAGE = {"files/index.md": 2}
DEMOTED_WEIGHT = 0.5


def search_weight(relative: Path, level: str) -> float | None:
    """The search weight of a page, None for the default. A part page
    states its own in its front matter: search_weight(path, "part")."""
    if level == "part":
        return SEARCH_WEIGHT["part"]
    if relative.as_posix() in SEARCH_WEIGHT_OF_PAGE:
        return SEARCH_WEIGHT_OF_PAGE[relative.as_posix()]
    if relative.as_posix() in SEARCH_DEMOTED:
        return DEMOTED_WEIGHT
    if relative.parts[0] == "systems":
        return SYSTEM_PAGE_WEIGHT
    if relative.parts[0] == "wiki" and level not in ("start", "setup"):
        return DEEP_GUIDE_WEIGHT
    return SEARCH_WEIGHT.get(level)


_REFERENCE_PAGES = {
    "gaps.md", "cross-reference.md", "provenance.md", "exports.md", "data.md",
    "files/index.md", "wiki/data-model.md", sitemeasurements.EXPLORER_PAGE,
}


def page_level(relative: Path) -> str:
    """The level of a generated page. A wiki page states its own."""
    path = relative.as_posix()
    if path in ("index.md", "which-pack.md"):
        return "start"
    if relative.parts[0] in ("platforms", release_record.GET_DIR):
        return "setup"
    if relative.parts[0] in ("systems", "emulators") or path == "explore.md":
        return "explore"
    if path in _REFERENCE_PAGES:
        return "reference"
    if path in ("contributing.md", "wanted.md"):
        return "contribute"
    return ""


def level_label(level: str) -> str:
    """The visible label of a level, plain text for the theme to style."""
    return f'<span class="rb-level rb-level-{level}">{LEVELS[level]}</span>'


def _front_matter(markdown: str) -> dict:
    """The YAML front matter of a page, empty when it has none."""
    if not markdown.startswith("---\n"):
        return {}
    end = markdown.find("\n---\n", 4)
    if end == -1:
        return {}
    data = yaml.safe_load(markdown[4:end])
    return data if isinstance(data, dict) else {}


@functools.cache
def _sha1_by_prefix(db_path: str) -> dict[str, str]:
    return {sha1[:12]: sha1 for sha1 in load_database(db_path)["files"]}


def _cards_elsewhere(markdown: str) -> str:
    """A start line links each file to its card. A console split over part
    pages keeps its cards on the parts, so a card this page does not hold
    is reached by its permanent link instead."""
    links = set(re.findall(r"\]\(#(sha1-[0-9a-f]{12})\)", markdown))
    away = {ident for ident in links if f'id="{ident}"' not in markdown}
    if not away:
        return markdown
    by_prefix = _sha1_by_prefix(str(siteinputs.current().db))
    for ident in away:
        full = by_prefix[ident.removeprefix("sha1-")]
        markdown = markdown.replace(f"](#{ident})", f"]({markup.site_href(f'files/?sha1={full}')})")
    return markdown


def decorate_markdown_pages(docs: Path) -> dict[str, str]:
    """Add per-page descriptions and machine-readable structured data.

    Under Starlight each page is written in its final form (front matter,
    site addresses, pinned heading ids) and the dates a page states are
    returned by address, for the sitemap.
    """
    lastmod: dict[str, str] = {}
    terms = sitestarlight.glossary_terms(_REPO_ROOT / WIKI_SRC_DIR / "glossary.md")
    # The console words of every system page, decorated or not: a console
    # another page's words cover gets a search field of its own.
    console_words: dict[str, set[str]] = {}
    for path in sorted((docs / "systems").glob("*.md*")):
        text = path.read_text(encoding="utf-8")
        words = sitestarlight.page_console_words(_front_matter(text), text)
        if words:
            console_words[path.relative_to(docs).with_suffix("").as_posix()] = words
    for path in sorted(docs.rglob("*.md")):
        relative = path.relative_to(docs)
        if any(part in LOCAL_NOTE_DIRS for part in relative.parts[:-1]):
            continue
        original = path.read_text(encoding="utf-8")
        authored = _front_matter(original)
        if "head" in authored:
            # Written in its final form by an earlier pass and rewritten by
            # nothing since: a second pass would find no title to read.
            continue
        markdown = _cards_elsewhere(prepare_page(original, relative))
        for image_id in unresolved_images(markdown):
            print(f"  WARNING: {relative}: no diagram named {image_id!r}", file=sys.stderr)
        stripped = _undecorated(markdown)
        if stripped is not markdown:
            markdown = stripped
        elif authored:
            # A wiki page states its own level: keep it, wrap the body.
            markdown = markdown[markdown.find("\n---\n", 4) + 5:].lstrip("\n")
        level = authored.get("level") or page_level(relative)

        title = _page_title(markdown, relative)
        browser_title = _browser_title(relative, title)
        description = str(authored.get("description") or _page_description(markdown, relative, title))
        if relative.name == "index.md":
            page_path = "" if len(relative.parts) == 1 else "/".join(relative.parts[:-1]) + "/"
        else:
            page_path = relative.with_suffix("").as_posix() + "/"
        # Encoded as mkdocs encodes the canonical link and the sitemap:
        # idtech4a++ named .../idtech4a++/ here and .../idtech4a%2B%2B/ there.
        canonical = urllib.parse.urljoin(SITE_URL, urllib.parse.quote(page_path))
        schema_type = "WebSite" if relative.as_posix() == "index.md" else "TechArticle"
        if relative.as_posix() == "data.md":
            schema_type = "Dataset"
        structured = {
            "@context": "https://schema.org",
            "@type": schema_type,
            "name": title,
            "description": description,
            "url": canonical,
            "isPartOf": {
                "@type": "WebSite",
                "name": SITE_NAME,
                "url": SITE_URL,
            },
            **PAGE_DATA.get(relative.as_posix(), {}),
        }
        if schema_type == "WebSite":
            # The home page is the site: named as the site, part of nothing.
            structured["name"] = SITE_NAME
            del structured["isPartOf"]
        target, text = sitestarlight.render_page(
            relative.as_posix(), markdown, sitestarlight.PageMeta(
                level=level,
                weight=search_weight(relative, level),
                browser_title=browser_title,
                description=description, structured=structured, terms=terms,
                search=authored.get("search") != "exclude",
                logo=str(authored.get("logo") or ""),
                parent=authored.get("parent"),
                authored=authored,
                words_by_page=console_words,
            ),
        )
        write_decorated(docs / target, text)
        # One file per page: a page that gained or lost its components
        # changed extension, and the other one would claim its address.
        stem = relative.with_suffix("").as_posix()
        for suffix in (".md", ".mdx"):
            if f"{stem}{suffix}" != target:
                (docs / f"{stem}{suffix}").unlink(missing_ok=True)
        if structured.get("dateModified"):
            lastmod[sitestarlight.page_url(target)] = str(structured["dateModified"])
    return lastmod
