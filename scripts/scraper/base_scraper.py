"""Base scraper interface for platform BIOS requirement sources."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class BiosRequirement:
    """A single BIOS file requirement from a platform source."""
    name: str
    system: str
    sha1: str | None = None
    md5: str | None = None
    crc32: str | None = None
    size: int | None = None
    destination: str = ""
    required: bool = True
    zipped_file: str | None = None  # If set, md5 is for this ROM inside the ZIP


@dataclass
class ChangeSet:
    """Differences between scraped requirements and current config."""
    added: list[BiosRequirement] = field(default_factory=list)
    removed: list[BiosRequirement] = field(default_factory=list)
    modified: list[tuple[BiosRequirement, BiosRequirement]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} added")
        if self.removed:
            parts.append(f"-{len(self.removed)} removed")
        if self.modified:
            parts.append(f"~{len(self.modified)} modified")
        return ", ".join(parts) if parts else "no changes"


class BaseScraper(ABC):
    """Abstract base class for platform BIOS requirement scrapers."""

    @abstractmethod
    def fetch_requirements(self) -> list[BiosRequirement]:
        """Fetch current BIOS requirements from the platform source."""
        ...

    def compare_with_config(self, config: dict) -> ChangeSet:
        """Compare scraped requirements against existing platform config."""
        scraped = self.fetch_requirements()
        changes = ChangeSet()

        existing = {}
        for sys_id, system in config.get("systems", {}).items():
            for f in system.get("files", []):
                key = (sys_id, f["name"])
                existing[key] = f

        scraped_map = {}
        for req in scraped:
            key = (req.system, req.name)
            scraped_map[key] = req

        for key, req in scraped_map.items():
            if key not in existing:
                changes.added.append(req)
            else:
                existing_file = existing[key]
                if req.sha1 and existing_file.get("sha1") and req.sha1 != existing_file["sha1"]:
                    changes.modified.append((
                        BiosRequirement(
                            name=existing_file["name"],
                            system=key[0],
                            sha1=existing_file.get("sha1"),
                            md5=existing_file.get("md5"),
                        ),
                        req,
                    ))
                elif req.md5 and existing_file.get("md5") and req.md5 != existing_file["md5"]:
                    changes.modified.append((
                        BiosRequirement(
                            name=existing_file["name"],
                            system=key[0],
                            md5=existing_file.get("md5"),
                        ),
                        req,
                    ))

        for key in existing:
            if key not in scraped_map:
                f = existing[key]
                changes.removed.append(BiosRequirement(
                    name=f["name"],
                    system=key[0],
                    sha1=f.get("sha1"),
                    md5=f.get("md5"),
                ))

        return changes

    def test_connection(self) -> bool:
        """Test if the source URL is reachable."""
        try:
            self.fetch_requirements()
            return True
        except Exception:
            return False

    @abstractmethod
    def validate_format(self, raw_data: str) -> bool:
        """Validate source data format. Returns False if format has changed unexpectedly."""
        ...


def fetch_github_latest_version(repo: str) -> str | None:
    """Fetch the latest release version tag from a GitHub repo."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "retrobios-scraper/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("tag_name", "")
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


def fetch_github_latest_tag(repo: str, prefix: str = "") -> str | None:
    """Fetch the most recent matching tag from a GitHub repo."""
    url = f"https://api.github.com/repos/{repo}/tags?per_page=50"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "retrobios-scraper/1.0",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            tags = json.loads(resp.read())
            for tag in tags:
                name = tag["name"]
                if prefix and not name.startswith(prefix):
                    continue
                return name
            return tags[0]["name"] if tags else None
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None
