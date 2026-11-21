"""Where the games data is read from, and how its YAML and JSON files are loaded."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.paths import EMULATORS_DIR, PLATFORMS_DIR
from model.sources import source_yaml_file

FORMAT_VERSION = 1
OUTPUT = Path("install") / "games"
GAMES = Path("games")

REGIONS_FILE = GAMES / "regions.yml"
EXTRAS_FILE = GAMES / "extras.yml"
HEADERS_FILE = GAMES / "headers.yml"


@dataclass(frozen=True)
class Inputs:
    """Where each source is read from. The defaults are the repository's."""

    games: Path = GAMES
    romfolders: Path = Path("platforms") / "romfolders"
    install: Path = Path("install")
    emulators: str = EMULATORS_DIR
    platforms: str = PLATFORMS_DIR


def load_yaml(path: Path) -> dict:
    return source_yaml_file(path) or {}


def load_optional_yaml(path: Path) -> dict:
    """A YAML file of the games data, empty when it does not exist."""
    if not path.exists():
        return {}
    return load_yaml(path)


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)
