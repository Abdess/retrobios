"""The command that pulls the upstream of each stale subject, by area."""

from __future__ import annotations

import sys
from collections.abc import Callable
from functools import lru_cache

from core.paths import DATA_DIRS_FILE, REPO_ROOT
from model.registry import data_dir_registry_at
from freshness.scrapers import rescrape_command

DATA_DIRS_REGISTRY = REPO_ROOT / DATA_DIRS_FILE


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


def _platform_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    return rescrape_command("platforms", subject, f"platforms/{subject}.yml", registry)


def _target_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    # "<platform> cores" rows list buildbot names without a profile. No
    # scraper fixes that, a human writes `cores:` or _overrides.yml.
    if subject.endswith(" cores"):
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


def _catalog_command(subject: str, registry: dict[str, dict]) -> list[str] | None:
    if subject == "mame recipes":
        return [
            sys.executable,
            "-m",
            "scripts.scraper.romset_dat_importer",
            "--source",
            "mame",
            "--fetch",
        ]
    if subject == "fbneo recipes":
        return [
            sys.executable,
            "-m",
            "scripts.scraper.romset_dat_importer",
            "--source",
            "fbneo",
            "--fetch",
        ]
    if subject in ("no-intro games", "redump games"):
        # The game DATs download without a browser, unlike the BIOS ones.
        return [
            sys.executable,
            "-m",
            "scripts.scraper.game_dat_importer",
            "--source",
            subject.split()[0],
            "--fetch",
            "--refresh",
            "--floor",
        ]
    # redump / no-intro / tosec need manual DAT download.
    return None


_AREA_COMMANDS: dict[str, Callable[[str, dict[str, dict]], list[str] | None]] = {
    "platforms": _platform_command,
    "targets": _target_command,
    "data": _data_command,
    "catalogs": _catalog_command,
}


def command_for(
    area: str, subject: str, registry: dict[str, dict]
) -> list[str] | None:
    """Map a stale finding to its refresh command, or None if manual."""
    if area == "native":
        # export_native refuses a truth older than the profiles, so the
        # truth comes first and the original follows (Job.then).
        return truth_refresh(subject)

    if area == "ci" and subject == "install.py pin":
        # The pin is the hash of the committed install.py, nothing to judge.
        return [sys.executable, "scripts/pin_installer.py"]

    builder = _AREA_COMMANDS.get(area)
    if builder:
        return builder(subject, registry)

    # coreinfo, ci, profiles: never auto-refresh.
    return None
