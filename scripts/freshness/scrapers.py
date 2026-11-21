"""Which scraper rewrites a platform file or a target file, and the command that runs it."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

from scraper.targets import discover_target_scrapers


def platform_scraper(entry: Mapping) -> str | None:
    """The module that scrapes a platform file, from its registry entry."""
    scraper = entry.get("scraper")
    return f"scripts.scraper.{scraper}_scraper" if scraper else None


def rescrape_args(entry: Mapping) -> tuple[str, ...]:
    """What a rescrape passes so the scraper reads upstream's moving head.

    A scraper that rereads the revision its platform file pins by default
    (RetroBat) names the ref to move to in the registry's rescrape_args.
    """
    return tuple(str(a) for a in entry.get("rescrape_args") or ())


@lru_cache(maxsize=1)
def target_scrapers() -> dict[str, str]:
    """platform -> scraper module for every target scraper on disk.

    Named from the repository root, as `python -m` runs it there, whatever
    path this process imported the package by.
    """
    return {
        platform: f"scripts.scraper.targets.{cls.__module__.rpartition('.')[2]}"
        for platform, cls in discover_target_scrapers().items()
    }


def rescrape_command(
    area: str, platform: str, output: str | Path, registry: Mapping[str, Mapping] | None = None,
) -> list[str] | None:
    """The scrape of a platform file or a target file into *output*, None without a scraper.

    The freshness check runs it on a throwaway copy and refresh_stale on the
    committed file: both read the scraper and its arguments here.
    """
    if area == "platforms":
        entry = (registry or {}).get(platform) or {}
        module, extra = platform_scraper(entry), rescrape_args(entry)
    elif area == "targets":
        module, extra = target_scrapers().get(platform), ()
    else:
        raise ValueError(f"no scraper rewrites the {area} area")
    if module is None:
        return None
    return [sys.executable, "-m", module, "-o", str(output), *extra]
