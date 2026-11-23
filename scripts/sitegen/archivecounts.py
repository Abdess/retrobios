"""The generated block of wiki/archive-recipes.md: how many archives rebuild exact and canonical."""

from __future__ import annotations

import re
from pathlib import Path

from sitegen.render import WIKI_SRC_DIR

ARCHIVE_RECIPES_PAGE = Path(WIKI_SRC_DIR) / "archive-recipes.md"
_ARCHIVE_BLOCK = re.compile(
    r"(<!-- generated: archive-recipes -->\n)(.*?)(<!-- /generated: archive-recipes -->)", re.S)


def archive_recipe_lines(counts: dict[str, int]) -> list[str]:
    """What an exact and a canonical rebuild are, each with its count."""
    total = f"{counts['total']:,}"
    return [
        f"- **Exact**: the same bytes as the archive in the collection."
        f" {counts['exact']:,} of {total} archives.",
        f"- **Canonical**: the same files inside, packed another way."
        f" {counts['canonical']:,} of {total} archives.",
    ]


def with_archive_counts(page: str, counts: dict[str, int]) -> str:
    """The archive recipes page with its counts read from recipes/archives.json."""
    block = "\n".join(archive_recipe_lines(counts)) + "\n"
    if not _ARCHIVE_BLOCK.search(page):
        raise ValueError(f"{ARCHIVE_RECIPES_PAGE}: no archive-recipes block to write the counts in")
    return _ARCHIVE_BLOCK.sub(lambda m: f"{m.group(1)}{block}{m.group(3)}", page, count=1)
