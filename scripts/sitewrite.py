"""Writing the site, and knowing what was written.

The generated tree is swept rather than deleted: a page is removed
only once nothing produces it, so a page whose content did not move
keeps its bytes and a deploy stops republishing the whole site for
the clock alone."""

from __future__ import annotations

from pathlib import Path
from artifacts import write_if_changed as _write_artifact
import os
# Every path this run produced. The generated directories used to be deleted
# before the build, which made every page new: write_if_changed had no earlier
# version to compare against, so the whole site was rewritten for the clock
# alone and a deploy republished 600 unchanged pages. They are swept instead,
# and a page is only removed once nothing produced it.
_produced: set[str] = set()

def _record(path: str | Path) -> None:
    _produced.add(os.path.realpath(str(path)))

# The reader level label the decoration pass puts above a page's title.
LEVEL_LABEL_START = '<span class="rb-level '


def _undecorated(markdown: str) -> str:
    """Return a page body without the front matter the decoration pass adds."""
    if markdown.startswith("---\n") and "generated_by: retrobios-site" in markdown[:300]:
        end = markdown.find("\n---\n", 4)
        if end != -1:
            markdown = markdown[end + 5:].lstrip("\n")
            script_end = markdown.find("</script>\n\n")
            if markdown.startswith('<script type="application/ld+json">') and script_end != -1:
                markdown = markdown[script_end + len("</script>\n\n"):]
            if markdown.startswith(LEVEL_LABEL_START):
                markdown = markdown[markdown.find("\n\n") + 2:]
    return markdown

def write_if_changed(path: str, content: str) -> bool:
    """Write a page body only when it moved, and remember it either way.

    A page is written twice: the body here, then the same body wrapped in
    front matter by the decoration pass. This comparison therefore reduces
    the file on disk to its body. The decoration pass compares in full -
    normalizing there too would make its own write look like a no-op and
    every page would lose its front matter.
    """
    _record(path)
    return _write_artifact(path, content, normalize=_undecorated)

def write_decorated(path: str | Path, content: str) -> bool:
    """Write the wrapped page, comparing front matter and body together."""
    _record(path)
    return _write_artifact(str(path), content)

# A page body is written as .md and the decoration pass, which runs after
# the sweep, gives it its final extension: .mdx when it holds components,
# the other file removed. The .mdx a previous run left is that same page.
_PAGE_SUFFIXES = (".md", ".mdx")


def _was_produced(path: Path) -> bool:
    """Whether this run produced *path*, a page under either extension."""
    if os.path.realpath(str(path)) in _produced:
        return True
    return path.suffix in _PAGE_SUFFIXES and any(
        os.path.realpath(str(path.with_suffix(suffix))) in _produced
        for suffix in _PAGE_SUFFIXES if suffix != path.suffix)


def _sweep_generated(docs: Path, directories: list[str]) -> int:
    """Delete files in the generated tree that this run did not produce."""
    removed = 0
    for name in directories:
        root = docs / name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and not _was_produced(path):
                path.unlink()
                removed += 1
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
    return removed


def _sweep_top_pages(docs: Path) -> int:
    """Delete the pages at the root of the docs tree this run did not produce.

    The root holds only generated pages, one per stem (`cross-reference-*`,
    `gaps-*`), and a stem that stops being produced, such as a platform
    whose core table moved to its own page, otherwise kept its old page
    and claimed the address its redirect needs.
    """
    removed = 0
    for path in sorted(docs.glob("*.md*")):
        if path.is_file() and path.suffix in _PAGE_SUFFIXES and not _was_produced(path):
            path.unlink()
            removed += 1
    return removed
