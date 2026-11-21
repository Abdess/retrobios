"""Target scraper plugin discovery module.

Auto-detects *_targets_scraper.py files and exposes their scrapers.
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path

from model.safeparse import require_yaml
from model.sourcerevision import platform_revision

# Every target scraper reads the network through the platform scrapers'
# helpers: one retry policy, one size cap, one token rule.
from ..base_scraper import fetch_text, forge_headers

__all__ = ["BaseTargetScraper", "discover_target_scrapers", "fetch_text", "forge_headers",
           "target_cli"]


class BaseTargetScraper(ABC):
    """Base class for target scrapers."""

    def __init__(self, url: str = "") -> None:
        self.url = url

    @abstractmethod
    def fetch_targets(self) -> dict:
        """Fetch targets and their core lists. Returns dict matching target YAML format."""
        ...

    @staticmethod
    def pinned_revision(platform: str, platforms_dir: str | None = None) -> str:
        """The upstream revision platforms/<platform>.yml was scraped at.

        A target list describes the same release as the platform's BIOS
        list: read on its own "latest stable tag", a Recalbox 10.2 board list
        filtered 10.1.1 systems. Moving to a new release is a rescrape of the
        platform first.
        """
        directory = Path(platforms_dir) if platforms_dir else (
            Path(__file__).resolve().parents[3] / "platforms"
        )
        return platform_revision(directory / f"{platform}.yml")

    def write_output(self, data: dict, output_path: str) -> None:
        """Write target data to YAML file."""
        from core.artifacts import write_text_atomic

        write_text_atomic(
            output_path, require_yaml().dump(data, default_flow_style=False, sort_keys=False)
        )


def target_cli(scraper_class: type[BaseTargetScraper], description: str, unit: str = "cores") -> None:
    """The command line every target scraper shares: --dry-run prints each
    target and its count of `unit`, --output writes the YAML, else it is printed."""
    import yaml

    parser = argparse.ArgumentParser(allow_abbrev=False, description=description)
    parser.add_argument("--dry-run", action="store_true", help="Show target summary")
    parser.add_argument("--output", "-o", help="Output YAML file")
    args = parser.parse_args()

    scraper = scraper_class()
    data = scraper.fetch_targets()
    if args.dry_run:
        for name, info in data["targets"].items():
            print(f"  {name} ({info['architecture']}): {len(info['cores'])} {unit}")
        return
    if args.output:
        scraper.write_output(data, args.output)
        print(f"Written to {args.output}")
        return
    print(yaml.dump(data, default_flow_style=False, sort_keys=False))


_scrapers: dict[str, type] = {}


def discover_target_scrapers() -> dict[str, type]:
    """Auto-discover all *_targets_scraper.py modules."""
    if _scrapers:
        return _scrapers
    package_dir = Path(__file__).parent
    for _finder, name, _ispkg in pkgutil.iter_modules([str(package_dir)]):
        if not name.endswith("_targets_scraper"):
            continue
        module = importlib.import_module(f".{name}", package=__package__)
        platform_name = getattr(module, "PLATFORM_NAME", None)
        scraper_class = getattr(module, "Scraper", None)
        if platform_name and scraper_class:
            _scrapers[platform_name] = scraper_class
    return _scrapers
