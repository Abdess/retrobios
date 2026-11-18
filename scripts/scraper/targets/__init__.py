"""Target scraper plugin discovery module.

Auto-detects *_targets_scraper.py files and exposes their scrapers.
"""

from __future__ import annotations

import argparse
import importlib
import pkgutil
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path

from core.github import github_token


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
        import yaml

        directory = Path(platforms_dir) if platforms_dir else (
            Path(__file__).resolve().parents[3] / "platforms"
        )
        with open(directory / f"{platform}.yml", encoding="utf-8") as handle:
            source = str((yaml.safe_load(handle) or {}).get("source", ""))
        for pattern in (
            r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/([^/]+)/",
            r"^https://github\.com/[^/]+/[^/]+/(?:blob|tree)/([^/]+)/",
            r"^https://gitlab\.com/.+?/-/(?:raw|blob|tree)/([^/]+)/",
            r"^https://codeload\.github\.com/[^/]+/[^/]+/(?:tar\.gz|zip)/([^/]+)$",
        ):
            match = re.match(pattern, source)
            if match:
                return match.group(1)
        raise RuntimeError(
            f"platforms/{platform}.yml names no pinned revision in its source "
            f"({source!r}): rescrape the platform first"
        )

    def write_output(self, data: dict, output_path: str) -> None:
        """Write target data to YAML file."""
        try:
            import yaml
        except ImportError as exc:
            raise ImportError("PyYAML required: pip install pyyaml") from exc
        from core.artifacts import write_text_atomic

        write_text_atomic(
            output_path, yaml.dump(data, default_flow_style=False, sort_keys=False)
        )


def fetch_text(url: str, headers: dict[str, str] | None = None) -> str:
    """GET a URL as UTF-8 text, RuntimeError with the URL when it fails."""
    try:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": "retrobios-scraper/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        # A target written from a failed request loses its cores in silence.
        raise RuntimeError(f"cannot fetch {url}: {e}") from e


def forge_headers(url: str, accept: str | None = None) -> dict[str, str]:
    """Request headers, with the GitHub token when the URL is api.github.com."""
    headers = {"User-Agent": "retrobios-scraper/1.0"}
    if accept is not None:
        headers["Accept"] = accept
    token = github_token()
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    return headers


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
