"""Page readers shared by the doc page test modules."""

from __future__ import annotations

import tests
from tests import mdsections

import functools
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

WIKI = ROOT / "wiki"

PUBLISHED = sorted(WIKI.glob("*.md")) + [ROOT / "README.md", ROOT / "CONTRIBUTING.md"]


def _page(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


# A section runs to the next heading of any level.
_section = functools.partial(mdsections.section, stop=6)


def _table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    rows.extend(
        [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        for line in text.splitlines()
        if line.startswith("|") and not re.match(r"\|\s*-", line)
    )
    return rows[1:]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


def _registry() -> dict:
    import yaml

    return yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))["platforms"]
