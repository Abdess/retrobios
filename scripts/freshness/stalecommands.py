"""The commands that refresh each stale subject, by area, and the areas they reach."""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

from core.paths import DATA_DIRS_FILE, REPO_ROOT
from model.registry import data_dir_registry_at
from freshness.findings import (
    AREAS, FBNEO_RECIPES, INSTALLER_PIN, MAME_RECIPES, NO_INTRO_GAMES, REDUMP_GAMES,
    is_unprofiled_cores,
)
from freshness.scrapers import rescrape_command

DATA_DIRS_REGISTRY = REPO_ROOT / DATA_DIRS_FILE


@dataclass(frozen=True)
class Chain:
    """The first command of a refresh and those run after it while each succeeds."""

    command: list[str]
    then: tuple[tuple[str, ...], ...] = ()


@lru_cache(maxsize=1)
def _data_dir_keys() -> frozenset[str]:
    """The entries refresh_data_dirs.py --key accepts."""
    return frozenset(data_dir_registry_at(DATA_DIRS_REGISTRY, required=True))


def verify_command(platform: str) -> list[str]:
    """The check a rescraped platform file is read with before it is kept."""
    return [sys.executable, "scripts/verify.py", "--platform", platform]


def truth_refresh(platform: str) -> list[str]:
    return [sys.executable, "scripts/generate_truth.py", "--platform", platform]


def native_refresh(platform: str) -> list[str]:
    return [
        sys.executable,
        "scripts/export_native.py",
        "--platform",
        platform,
        "--refresh-cache",
    ]


def export_refresh(platform: str) -> list[str]:
    """Rewrite the published export from the refreshed original."""
    return [sys.executable, "scripts/export_native.py", "--platform", platform]


def _platform_chain(subject: str, registry: dict[str, dict]) -> Chain | None:
    command = rescrape_command("platforms", subject, f"platforms/{subject}.yml", registry)
    if command is None:
        return None
    # The truth reads the platform file: regenerated first, or the
    # native refresh refuses it as older than the profiles.
    return Chain(command, (
        tuple(truth_refresh(subject)),
        tuple(native_refresh(subject)),
        tuple(export_refresh(subject)),
        tuple(verify_command(subject)),
    ))


def native_chain(subject: str, registry: dict[str, dict] | None = None) -> Chain:
    """The export of *subject* rebuilt: truth, original, then the export."""
    # export_native refuses a truth older than the profiles, so the truth
    # comes first and the original follows.
    return Chain(
        truth_refresh(subject),
        (tuple(native_refresh(subject)), tuple(export_refresh(subject))),
    )


def _ci_chain(subject: str, registry: dict[str, dict]) -> Chain | None:
    if subject != INSTALLER_PIN:
        # PyPI versions and pinned actions are bumped by a human.
        return None
    # The pin is the hash of the committed install.py, nothing to judge.
    return Chain([sys.executable, "scripts/pin_installer.py"])


def _target_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    # "<platform> cores" rows list buildbot names without a profile. No
    # scraper fixes that, a human writes `cores:` or _overrides.yml.
    if is_unprofiled_cores(subject):
        return None
    return rescrape_command("targets", subject, f"platforms/targets/{subject}.yml")


def _data_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    if subject not in _data_dir_keys():
        # "_data_dirs.yml" and "buildbot system" name the registry and
        # what it does not track yet: a human adds the entry.
        return None
    return [
        sys.executable,
        "scripts/refresh_data_dirs.py",
        "--key",
        subject,
        "--force",
    ]


# The romset recipes and the game DATs each importer fetches, by row.
_RECIPE_SOURCES = {MAME_RECIPES: "mame", FBNEO_RECIPES: "fbneo"}
_GAME_SOURCES = {NO_INTRO_GAMES: "no-intro", REDUMP_GAMES: "redump"}


def _catalog_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    if subject in _RECIPE_SOURCES:
        return [
            sys.executable,
            "-m",
            "scripts.scraper.arcade.romset_dat_importer",
            "--source",
            _RECIPE_SOURCES[subject],
            "--fetch",
        ]
    if subject in _GAME_SOURCES:
        # The game DATs download without a browser, unlike the BIOS ones.
        return [
            sys.executable,
            "-m",
            "scripts.scraper.dats.game_dat_importer",
            "--source",
            _GAME_SOURCES[subject],
            "--fetch",
            "--refresh",
            "--floor",
        ]
    # redump / no-intro / tosec need manual DAT download.
    return None


def _single(
    build: Callable[[str, dict[str, dict]], list[str] | None],
) -> Callable[[str, dict[str, dict]], Chain | None]:
    def chain(subject: str, registry: dict[str, dict]) -> Chain | None:
        command = build(subject, registry)
        return None if command is None else Chain(command)
    return chain


# The areas a command can refresh. A row of any other area, or one its
# builder returns None for, is listed for a human.
_AREA_CHAINS: dict[str, Callable[[str, dict[str, dict]], Chain | None]] = {
    "platforms": _platform_chain,
    "native": native_chain,
    "targets": _single(_target_command),
    "data": _single(_data_command),
    "catalogs": _single(_catalog_command),
    "ci": _ci_chain,
}
AUTO_AREAS = tuple(area for area in AREAS if area in _AREA_CHAINS)
# A rom-folder pin is moved by hand in platforms/romfolders/_sources/,
# then `python -m scripts.scraper.romfolders --setup NAME` reads it again.
MANUAL_AREAS = tuple(area for area in AREAS if area not in _AREA_CHAINS)


def refresh_chain(area: str, subject: str, registry: dict[str, dict]) -> Chain | None:
    """The refresh of a stale finding, or None when a human resolves it."""
    builder = _AREA_CHAINS.get(area)
    return builder(subject, registry) if builder else None
