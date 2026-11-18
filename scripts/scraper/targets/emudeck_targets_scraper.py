"""Scraper for EmuDeck emulator targets.

Sources:
  SteamOS: dragoonDorise/EmuDeck, functions/EmuScripts/*.sh, read at the
           revision platforms/emudeck.yml was scraped at
  Windows: EmuDeck/emudeck-we, functions/EmuScripts/*.ps1, default branch:
           the platform file is read from dragoonDorise/EmuDeck alone and
           pins no emudeck-we revision
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


from model.safeparse import yaml_load

from ..emudeck_launchers import SCRIPT_SUFFIXES, emulator_of_script
from . import BaseTargetScraper, fetch_text, forge_headers, target_cli

PLATFORM_NAME = "emudeck"

STEAMOS_API = (
    "https://api.github.com/repos/dragoonDorise/EmuDeck/contents/functions/EmuScripts"
)
WINDOWS_API = (
    "https://api.github.com/repos/EmuDeck/emudeck-we/contents/functions/EmuScripts"
)
RETROARCH_TARGETS = Path(__file__).resolve().parents[3] / "platforms" / "targets" / "retroarch.yml"

def _fetch(url: str) -> str:
    return fetch_text(url, forge_headers(url))


def _list_emuscripts(api_url: str) -> list[str]:
    """List emulator script filenames from GitHub API."""
    entries = json.loads(_fetch(api_url))
    names = [
        e["name"] for e in entries if e.get("name", "").endswith(SCRIPT_SUFFIXES)
    ]
    if not names:
        raise RuntimeError(f"no emulator scripts listed at {api_url}")
    return names


class Scraper(BaseTargetScraper):
    """Fetches emulator lists for EmuDeck SteamOS and Windows targets."""

    def __init__(
        self, url: str = "https://github.com/dragoonDorise/EmuDeck", revision: str | None = None
    ) -> None:
        super().__init__(url=url)
        self._revision = revision

    @property
    def revision(self) -> str:
        """The checkBIOS.sh commit platforms/emudeck.yml was read at."""
        if self._revision is None:
            self._revision = self.pinned_revision(PLATFORM_NAME)
        return self._revision

    def _fetch_cores_for_target(
        self, api_url: str, label: str, retroarch_target: str
    ) -> list[str]:
        print(f"  fetching {label} EmuScripts...", file=sys.stderr)
        scripts = _list_emuscripts(api_url)
        cores: list[str] = []
        seen: set[str] = set()
        has_retroarch = False
        for script in scripts:
            core = emulator_of_script(script)
            # RetroArch stands for its libretro cores, added below.
            if core == "retroarch":
                has_retroarch = True
            elif core and core not in seen:
                seen.add(core)
                cores.append(core)

        standalone_count = len(cores)
        # EmuDeck ships RetroArch = all its libretro cores are available
        if has_retroarch:
            ra_cores = self._load_retroarch_cores(retroarch_target)
            for c in ra_cores:
                if c not in seen:
                    seen.add(c)
                    cores.append(c)

        print(
            f"    {label}: {standalone_count} standalone + "
            f"{len(cores) - standalone_count} via RetroArch = {len(cores)} total",
            file=sys.stderr,
        )
        return sorted(cores)

    @staticmethod
    def _load_retroarch_cores(target: str, path: Path = RETROARCH_TARGETS) -> list[str]:
        """The buildbot's libretro cores for one RetroArch target, by name:
        linux-x86_64 and windows-x86_64 share an architecture, not a list."""
        with path.open(encoding="utf-8") as f:
            data = yaml_load(f) or {}
        cores = ((data.get("targets") or {}).get(target) or {}).get("cores")
        if not cores:
            raise RuntimeError(f"no {target} core list in {path}")
        return cores

    def fetch_targets(self) -> dict:
        steamos_cores = self._fetch_cores_for_target(
            f"{STEAMOS_API}?ref={self.revision}", "SteamOS", "linux-x86_64"
        )
        windows_cores = self._fetch_cores_for_target(WINDOWS_API, "Windows", "windows-x86_64")

        targets: dict[str, dict] = {}
        if steamos_cores:
            targets["steamos"] = {
                "architecture": "x86_64",
                "cores": steamos_cores,
            }
        if windows_cores:
            targets["windows"] = {
                "architecture": "x86_64",
                "cores": windows_cores,
            }

        return {
            "platform": "emudeck",
            "source": f"{self.url}/tree/{self.revision}",
            "scraped_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "targets": targets,
        }


def main() -> None:
    target_cli(Scraper, "Scrape EmuDeck emulator targets", "emulators")


if __name__ == "__main__":
    main()
