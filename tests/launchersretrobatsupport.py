"""Fixture readers shared by the RetroBat launcher test modules."""

from __future__ import annotations

import tests

import textwrap
from pathlib import Path

from scraper.retrobat_generators import GENERATORS
from scraper.csharp_source import Source


REPO_ROOT = Path(__file__).resolve().parent.parent

G = GENERATORS


def _sources(**texts: str) -> dict[str, Source]:
    return {
        path: Source(path, textwrap.dedent(text).lstrip("\n")) for path, text in texts.items()
    }
