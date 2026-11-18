"""Page budgets, and the long lists cut into parts of their own."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from core.paths import REPO_ROOT
from sitegen import starlight as sitestarlight
from sitegen.config import date_line
from sitegen.decorate import front_matter


# A platform's file lists are split by the share of a page they render to,
# in thousandths: their elements against validate_site's MAX_PAGE_ELEMENTS,
# their bytes against the 600,000 of test_site_built_gate, whichever is
# larger. Measured in Markdown characters, the lists split anew whenever
# their markup changed: rows written as tables moved 38 more systems to
# pages of their own.
PAGE_ELEMENTS = 10_000
PAGE_BYTES = 600_000
# A system whose list passes this share gets a page of its own.
PLATFORM_SECTION_BUDGET = 400
# A system's own page in runs of at most this share.
PLATFORM_PART_BUDGET = 700
# The share of a platform page's file lists, past which the largest
# systems move to pages of their own.
PLATFORM_REFERENCE_BUDGET = 600


# Every part page the site has published, with the page it belongs to:
# platforms/batocera-atari-st.md -> platforms/batocera.md#atari-st,
# gaps-files-to-source-7.md -> gaps.md. When a budget or a list changes, a
# part can fold back or the list shrink, and its address then redirects to
# that page instead of ending on the 404 page.
PUBLISHED_PARTS_FILE = (REPO_ROOT
                        / "website" / "src" / "data" / "published-parts.json")


def load_published_parts() -> dict[str, str]:
    if not PUBLISHED_PARTS_FILE.is_file():
        return {}
    return json.loads(PUBLISHED_PARTS_FILE.read_text(encoding="utf-8"))


def _parent_page(link: str) -> str:
    """The page a `parent:` link names (/platforms/batocera/), under docs/."""
    path, _, fragment = link.partition("#")
    # Written with the site's base (/retrobios/emulators/x/) or without it.
    path = path.removeprefix(sitestarlight.BASE.rstrip("/"))
    stem = path.strip("/") or "index"
    return f"{stem}.md" + (f"#{fragment}" if fragment else "")


def record_parts(docs: Path, present: set[str], published: dict[str, str]) -> dict[str, str]:
    """``published`` with every page of this run that names its parent.

    Only platform parts were recorded: gaps-files-to-source-7 or
    mame-files-10, gone once their list shrank, ended on the 404 page. A
    part already recorded keeps its target, which may name a section.
    """
    found = dict(published)
    for rel in sorted(present):
        page = docs / rel
        if not page.is_file():
            page = page.with_suffix(".mdx")
        try:
            parent = front_matter(page.read_text(encoding="utf-8")).get("parent")
        except OSError:
            continue
        if isinstance(parent, dict) and parent.get("link") and rel not in found:
            found[rel] = _parent_page(str(parent["link"]))
    return dict(sorted(found.items()))


# A list moved off a reference page (gaps, provenance) is cut in parts of
# at most this much Markdown: about 450 KB of HTML each.
LIST_PART_BUDGET = 300_000


def character_count(lines: list[str]) -> int:
    return sum(len(line) + 1 for line in lines)


def blocks_in_runs(blocks: list[list[str]], budget: int,
                    weigh: Callable[[list[str]], float] = character_count) -> list[list[str]]:
    """Blocks (table rows, folded lists) in runs of at most ``budget``, by
    default in characters, a block never cut."""
    runs: list[list[str]] = [[]]
    size: float = 0
    for block in blocks:
        weight = weigh(block)
        if runs[-1] and size + weight > budget:
            runs.append([])
            size = 0
        runs[-1].extend(block)
        size += weight
    return runs


def parent_front_matter(parent: tuple[str, str] | None) -> list[str]:
    """The `parent:` front matter of a part page: the page it belongs to,
    by label and site path, which the breadcrumb and sidebar read."""
    if parent is None:
        return []
    label, link = parent
    return ["parent:", f"  label: {json.dumps(label)}", f"  link: {json.dumps(link)}"]


def list_pages(
    stem: str, title: str, intro: str, head: list[str], blocks: list[list[str]],
    moved: dict[str, str], budget: int = LIST_PART_BUDGET,
    parent: tuple[str, str] | None = None,
) -> str:
    """Pages of their own for a long list: ``head`` (a table header, say)
    opens each part, ``blocks`` are cut between parts. Returns where the list
    went, as the page it left says it. ``parent`` (label, site path) is the
    page the parts belong to, for the breadcrumb."""
    runs = blocks_in_runs(blocks, budget)
    stems = [stem + (f"-{n}" if n > 1 else "") for n in range(1, len(runs) + 1)]
    for n, (here, run) in enumerate(zip(stems, runs), 1):
        part = f" (part {n} of {len(runs)})" if len(runs) > 1 else ""
        # The page description is the opening of the intro: parts sharing
        # one read as duplicates to search and to validate_site.
        opening = f"Part {n} of {len(runs)}. {intro}" if len(runs) > 1 else intro
        moved[here] = "\n".join([
            "---", "level: reference", *parent_front_matter(parent), "---", "",
            f"# {title}{part}", "", opening, "",
            *([", ".join(f"[part {i}]({other}.md)" if other != here else f"part {i}"
                         for i, other in enumerate(stems, 1)), ""] if len(runs) > 1 else []),
            *head, *run, "", date_line(),
        ]) + "\n"
    if len(stems) == 1:
        return f"[a page of their own]({stems[0]}.md)"
    return "pages of their own: " + ", ".join(
        f"[part {i}]({other}.md)" for i, other in enumerate(stems, 1))
