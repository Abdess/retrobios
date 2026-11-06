"""The generated site pages, for the tests that read them.

generate_site.py writes each page into the Starlight project's content
collection, as .md or as .mdx when it uses a component. A test names a
page by its docs path (``which-pack.md``) and gets whichever file holds it.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTENT = REPO_ROOT / "website" / "src" / "content" / "docs"


def require() -> Path:
    """The content folder, or a skip when the site was not generated (a
    failure in CI, which generates it before the suite)."""
    if not (CONTENT / "index.md").is_file():
        if os.environ.get("CI"):
            raise AssertionError("CI generates the site before the suite")
        raise unittest.SkipTest("site not generated (python scripts/generate_site.py)")
    return CONTENT


def page(name: str) -> Path:
    """The file of a page named by its docs path."""
    stem = name[:-3] if name.endswith(".md") else name
    for suffix in (".md", ".mdx"):
        candidate = CONTENT / f"{stem}{suffix}"
        if candidate.is_file():
            return candidate
    return CONTENT / f"{stem}.md"


def pages() -> list[Path]:
    """Every page file, sorted."""
    root = require()
    return sorted(p for p in root.rglob("*") if p.suffix in (".md", ".mdx"))


def name(path: Path) -> str:
    """A page file's docs path, the name tests use for it."""
    return path.relative_to(CONTENT).with_suffix(".md").as_posix()


def generator_sources() -> list[Path]:
    """Every module whose strings reach a page: generate_site.py, each
    scripts/site*.py and the pack README writer. Listed by glob, so text
    moved out of generate_site.py stays under the guards that read it."""
    scripts = REPO_ROOT / "scripts"
    return sorted({*scripts.glob("site*.py"), scripts / "generate_site.py",
                   scripts / "packreadme.py"})
