"""Scraper plugin discovery module.

Auto-detects *_scraper.py files and exposes their scrapers.
Each scraper module must define:
    PLATFORM_NAME: str
    Scraper: class inheriting BaseScraper
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

# Scrapers run both as `python -m scripts.scraper.x` and as plain scripts, and
# they share helpers with the rest of scripts/. Putting that directory on the
# path once here is what lets every submodule say `from common import ...`
# instead of carrying its own bootstrap.
_SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from .base_scraper import BaseScraper  # noqa: E402

_scrapers: dict[str, type] = {}


def discover_scrapers() -> dict[str, type]:
    """Auto-discover all *_scraper.py modules and return {platform_name: ScraperClass}."""
    if _scrapers:
        return _scrapers

    package_dir = Path(__file__).parent

    for finder, name, ispkg in pkgutil.iter_modules([str(package_dir)]):
        if not name.endswith("_scraper"):
            continue

        module = importlib.import_module(f".{name}", package=__package__)

        platform_name = getattr(module, "PLATFORM_NAME", None)
        scraper_class = getattr(module, "Scraper", None)

        if platform_name and scraper_class and issubclass(scraper_class, BaseScraper):
            _scrapers[platform_name] = scraper_class

    return _scrapers


def get_scraper(platform_name: str) -> BaseScraper | None:
    """Get an instantiated scraper for a platform."""
    scrapers = discover_scrapers()
    cls = scrapers.get(platform_name)
    return cls() if cls else None
