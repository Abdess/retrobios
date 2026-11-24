"""Paths and readers shared by the reference page test modules."""

from __future__ import annotations

import tests

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


DIST = REPO_ROOT / "website" / "dist"


PUBLIC = REPO_ROOT / "website" / "public"

API = PUBLIC / "api" / "v1"

SITE = "https://abdess.github.io/retrobios/"


def _built(path: Path) -> Path:
    if not path.exists():
        raise unittest.SkipTest(f"{path.relative_to(REPO_ROOT)} not generated")
    return path
