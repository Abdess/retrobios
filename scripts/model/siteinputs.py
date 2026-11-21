"""The collection, profiles and platform files the site describes.

generate_site.py takes them as --db, --emulators-dir and --platforms-dir and
installs them here before writing a page. Every page module reads its inputs
from current(), so a run on another collection describes that collection on
every page. A module used on its own reads the repository's files.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.paths import REPO_ROOT


@dataclass(frozen=True)
class SiteInputs:
    db: Path = REPO_ROOT / "database.json"
    emulators: Path = REPO_ROOT / "emulators"
    platforms: Path = REPO_ROOT / "platforms"
    # The install manifests; None places them beside the database.
    manifests: Path | None = None


_current = [SiteInputs()]


def current() -> SiteInputs:
    return _current[0]


def use(inputs: SiteInputs) -> None:
    _current[0] = inputs


def bios_dir(db: dict) -> Path:
    """The database's bios folder, as the inputs place it.

    database.json names it relative to its own folder ("bios"). Read from the
    working directory instead, a tool started elsewhere found no copy on disk
    and dropped five system sections and 2,500 collection paths in silence.
    """
    named = Path(str(db.get("bios_dir") or "bios"))
    return named if named.is_absolute() else current().db.parent / named


def collection_path(rel: str) -> Path:
    """A path database.json names, under the database's own folder."""
    return current().db.parent / rel


def manifests_dir() -> Path:
    """The install manifests built from the collection the inputs name."""
    inputs = current()
    return inputs.manifests or inputs.db.parent / "install"
