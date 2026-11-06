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

The same scripts carry the launcher layer (retropie_launchers): where each
package links, copies or passes a BIOS file, what it builds and which
systems it registers.
"""

from __future__ import annotations

import io
import re
import tarfile
import urllib.error
import urllib.request

try:
    from .base_scraper import BaseScraper, BiosRequirement, fetch_branch_head
    from .retropie_launchers import SCRIPTMODULES
    from .retropie_launchers import SECTIONS as _SCRIPT_SECTIONS
    from .retropie_launchers import extract_launchers
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement, fetch_branch_head
    from retropie_launchers import SCRIPTMODULES
    from retropie_launchers import SECTIONS as _SCRIPT_SECTIONS
    from retropie_launchers import extract_launchers

PLATFORM_NAME = "retropie"

SOURCE_URL = "https://codeload.github.com/RetroPie/RetroPie-Setup/tar.gz/{rev}"
GITHUB_REPO = "RetroPie/RetroPie-Setup"
MAX_ARCHIVE = 64 * 1024 * 1024

_MODULE_ID = re.compile(r'^rp_module_id="([^"]+)"', re.MULTILINE)
# RetroPie updates in place from master, so its release tags stop at the last
# SD image. The version a user runs is the one this script declares.
_VERSION_FILE = "retropie_packages.sh"
_VERSION = re.compile(r'^__version="([^"]+)"', re.MULTILINE)
# Sections RetroPie does not build as emulators: setup helpers, themes,
# drivers and the like carry no core.
_PACKAGE_DIRS = _SCRIPT_SECTIONS


def core_name(module_id: str) -> str:
    """The core a RetroPie package installs, as the buildbot names it.

    A libretro package is lr-<core> with the name hyphenated (lr-beetle-psx
    builds beetle_psx). A standalone package keeps its id (dosbox-staging).
    The platform and target scrapers both read it here.
    """
    if module_id.startswith("lr-"):
        return module_id[3:].replace("-", "_")
    return module_id


class Scraper(BaseScraper):
    """Scraper for the RetroPie package list."""

    lists_files = False

    def __init__(self, url: str | None = None) -> None:
        # The package list is read from master: the commit read is recorded.
        if url is None:
            url = SOURCE_URL.format(rev=fetch_branch_head(GITHUB_REPO, "master"))
        super().__init__(url=url)
        self._modules: list[str] | None = None
        self._version = ""
        # Package scripts and the launch scripts beside them, by repo path.
        self._scripts: dict[str, str] = {}

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
                is_version_file = relative == _VERSION_FILE
                is_package = (
                    len(parts) == 3
                    and parts[0] == "scriptmodules"
                    and parts[1] in _PACKAGE_DIRS
                )
                is_launch_script = (
                    len(parts) == 4 and parts[0] == SCRIPTMODULES and parts[1] in _SCRIPT_SECTIONS
                )
                if not (is_version_file or is_package or is_launch_script):
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                text = handle.read().decode("utf-8", errors="replace")
                if is_package or is_launch_script:
                    self._scripts[relative] = text
                if is_launch_script:
                    continue
                match = (_VERSION if is_version_file else _MODULE_ID).search(text)
                if not match:
                    continue
                if is_version_file:
                    self._version = match.group(1)
                else:
                    found.add(match.group(1))

        if not found:
            raise ValueError(f"{self.url}: no rp_module_id under {SCRIPTMODULES}/")
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
        # Named by core_name(), as the target scraper names them. Kept
        # hyphenated, lr-dosbox-pure named dosbox-pure, the standalone
        # DOSBox Pure Unleashed build RetroPie does not ship.
        modules = self.module_ids()
        cores = sorted({core_name(m) for m in modules})
        libretro = {m.removeprefix("lr-") for m in modules if m.startswith("lr-")}
        # The retroarch package is the frontend that runs the lr- cores.
        standalone = sorted(
            m for m in modules if not m.startswith("lr-") and m != "retroarch"
        )
        if not self._version:
            raise ValueError(f"{self.url}: no __version in {_VERSION_FILE}")

        return {
            "inherits": "retroarch",
            "platform": "RetroPie",
            "version": self._version,
            "homepage": "https://retropie.org.uk",
            "source": self.url,
            "base_destination": "BIOS",
            "cores": cores,
            "standalone_cores": standalone,
            # Shipped both as lr-<name> and as <name>: each layout gets its files.
            "dual_mode_cores": [m for m in standalone if m in libretro],
            "launchers": extract_launchers(self._scripts),
        }


def main() -> None:
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        from base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape the RetroPie package list")


if __name__ == "__main__":
    main()
