"""Target scraper plugin discovery module.

Auto-detects *_targets_scraper.py files and exposes their scrapers.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path


class BaseTargetScraper(ABC):
    """Base class for target scrapers."""

    def __init__(self, url: str = ""):
        self.url = url

    @abstractmethod
    def fetch_targets(self) -> dict:
        """Fetch targets and their core lists. Returns dict matching target YAML format."""
        ...

    def write_output(self, data: dict, output_path: str) -> None:
        """Write target data to YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError("PyYAML required: pip install pyyaml")
        from common import write_text_atomic

        write_text_atomic(
            output_path, yaml.dump(data, default_flow_style=False, sort_keys=False)
        )


_scrapers: dict[str, type] = {}


def discover_target_scrapers() -> dict[str, type]:
    """Auto-discover all *_targets_scraper.py modules."""
    if _scrapers:
        return _scrapers
    package_dir = Path(__file__).parent
    for finder, name, ispkg in pkgutil.iter_modules([str(package_dir)]):
        if not name.endswith("_targets_scraper"):
            continue
        module = importlib.import_module(f".{name}", package=__package__)
        platform_name = getattr(module, "PLATFORM_NAME", None)
        scraper_class = getattr(module, "Scraper", None)
        if platform_name and scraper_class:
            _scrapers[platform_name] = scraper_class
    return _scrapers
