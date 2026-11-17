#!/usr/bin/env python3
"""Scraper for MyMinUI's pak list: the MinUI scraper on MyMinUI's repository."""

from __future__ import annotations

from . import minui_scraper

PLATFORM_NAME = "myminui"


class Scraper(minui_scraper.Scraper):
    """Pak scraper for MyMinUI."""

    variant = minui_scraper.VARIANTS["myminui"]


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape the MyMinUI pak list")


if __name__ == "__main__":
    main()
