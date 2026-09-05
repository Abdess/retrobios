#!/usr/bin/env python3
"""Scraper for RetroPie's package list.

Source: RetroPie/RetroPie-Setup -> scriptmodules/
Format: one bash script per package, `rp_module_id` naming it

RetroPie publishes no BIOS list: platforms.cfg carries extensions and full
names, and the files a package needs are named in prose inside its
`rp_module_help`, without hashes. So there is nothing here to transcribe as
requirements, and `fetch_requirements` returns none. What RetroPie does
state precisely is which packages it ships, and that is what this reads.

It matters because the config said `cores: all_libretro`, inherited from
RetroArch: RetroPie claimed every libretro core in existence while shipping
96 of them, and claimed none of the standalone emulators it also packages
(openmsx, pcsx2, xroar, sdltrs, amiberry and the rest). Both halves were
wrong, in opposite directions.
"""

from __future__ import annotations

import io
import re
import tarfile
import urllib.error
import urllib.request

try:
    from .base_scraper import BaseScraper, BiosRequirement
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement

PLATFORM_NAME = "retropie"

SOURCE_URL = (
    "https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/refs/heads/master"
)
GITHUB_REPO = "RetroPie/RetroPie-Setup"
MAX_ARCHIVE = 64 * 1024 * 1024

_MODULE_ID = re.compile(r'^rp_module_id="([^"]+)"', re.MULTILINE)
# Sections RetroPie does not build as emulators: setup helpers, themes,
# drivers and the like carry no core.
_PACKAGE_DIRS = ("emulators", "libretrocores", "ports")


class Scraper(BaseScraper):
    """Scraper for the RetroPie package list."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)
        self._modules: list[str] | None = None

    def _fetch_archive(self) -> bytes:
        request = urllib.request.Request(
            self.url, headers={"User-Agent": "retrobios-scraper/1.0"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read(MAX_ARCHIVE + 1)
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Failed to fetch {self.url}: {exc}") from exc
        if len(payload) > MAX_ARCHIVE:
            raise ValueError(f"{self.url}: response larger than {MAX_ARCHIVE} bytes")
        return payload

    def module_ids(self, payload: bytes | None = None) -> list[str]:
        """Every package RetroPie ships, by the id its script declares."""
        if self._modules is not None:
            return self._modules

        raw = payload if payload is not None else self._fetch_archive()
        found: set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith(".sh"):
                    continue
                relative = member.name.split("/", 1)[-1]
                parts = relative.split("/")
                if len(parts) != 3 or parts[0] != "scriptmodules":
                    continue
                if parts[1] not in _PACKAGE_DIRS:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                text = handle.read().decode("utf-8", errors="replace")
                match = _MODULE_ID.search(text)
                if match:
                    found.add(match.group(1))

        self._modules = sorted(found)
        return self._modules

    def fetch_requirements(self) -> list[BiosRequirement]:
        """None: RetroPie names BIOS in prose, with no hash to transcribe.

        The prose is read where it can be acted on, by the exporter that
        rewrites those sentences.
        """
        self.module_ids()
        return []

    def validate_format(self, raw_data: str) -> bool:
        return bool(self.module_ids())

    def generate_platform_yaml(self) -> dict:
        """Build the RetroPie platform configuration.

        The systems stay inherited from RetroArch: RetroPie installs the
        libretro cores and reads the same files, at BIOS/ instead of
        system/. Only the core list is its own.
        """
        # A libretro package is lr-<core>; a standalone package is named
        # after the emulator itself.
        cores = sorted({module.removeprefix("lr-") for module in self.module_ids()})

        return {
            "inherits": "retroarch",
            "platform": "RetroPie",
            "homepage": "https://retropie.org.uk",
            "source": SOURCE_URL,
            "base_destination": "BIOS",
            "cores": cores,
        }


def main() -> None:
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        from base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape the RetroPie package list")


if __name__ == "__main__":
    main()
