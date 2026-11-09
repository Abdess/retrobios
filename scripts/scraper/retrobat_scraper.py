#!/usr/bin/env python3
"""Scraper for RetroBat batocera-systems.json.

Source: https://github.com/RetroBat-Official/emulatorlauncher
Format: JSON with system keys containing biosFiles arrays
Hash: MD5 primary
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

try:
    from .base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_branch_head,
        fetch_bytes,
        fetch_github_latest_version,
        requirement_entry,
    )
    from .batocera_scraper import SYSTEM_SLUG_MAP as BATOCERA_SLUGS
    from .retrobat_launchers import SOURCE_FILES as LAUNCHER_FILES
    from .retrobat_launchers import extract_launchers
except ImportError:
    from base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_branch_head,
        fetch_bytes,
        fetch_github_latest_version,
        requirement_entry,
    )
    from batocera_scraper import SYSTEM_SLUG_MAP as BATOCERA_SLUGS
    from retrobat_launchers import SOURCE_FILES as LAUNCHER_FILES
    from retrobat_launchers import extract_launchers

PLATFORM_NAME = "retrobat"

LAUNCHER_REPO = "RetroBat-Official/emulatorlauncher"
SOURCE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/"
    "{rev}/batocera-systems/Resources/batocera-systems.json"
)

LAUNCHER_FILE_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/emulatorlauncher/{rev}/{path}"
)

GITHUB_REPO = "RetroBat-Official/retrobat"

ES_SYSTEMS_URL = (
    "https://raw.githubusercontent.com/RetroBat-Official/retrobat/{tag}"
    "/system/templates/emulationstation/es_systems.cfg"
)


def es_systems_dual(text: str) -> set[str]:
    """Emulators es_systems.cfg offers both as a libretro core and standalone."""
    from common import parse_untrusted_xml

    libretro: set[str] = set()
    standalone: set[str] = set()
    for emulator in parse_untrusted_xml(text, "es_systems.cfg").iter("emulator"):
        name = (emulator.get("name") or "").strip()
        if name == "libretro":
            libretro |= {(core.text or "").strip() for core in emulator.iter("core")} - {""}
        elif name:
            standalone.add(name)
    return libretro & standalone


def es_systems_cores(text: str) -> tuple[set[str], set[str]]:
    """Every core RetroBat's ES offers, and the emulators it runs standalone.

    emulatorlauncher starts what es_systems.cfg lists: a libretro core by its
    name under ``<emulator name="libretro">``, any other emulator by its own
    name. batocera-systems.json names BIOS files only, so the platform read
    from it alone had no core list and relied on one kept by hand.
    """
    from common import parse_untrusted_xml

    root = parse_untrusted_xml(text, "es_systems.cfg")
    cores: set[str] = set()
    standalone: set[str] = set()
    for emulator in root.iter("emulator"):
        name = (emulator.get("name") or "").strip()
        if not name:
            continue
        listed = {(core.text or "").strip() for core in emulator.iter("core")} - {""}
        if name == "libretro":
            cores |= listed
        else:
            cores.add(name)
            standalone.add(name)
    return cores, standalone


def es_systems_libretro_systems(text: str) -> dict[str, list[str]]:
    """libretro core -> the ES systems es_systems.cfg offers it for.

    emulatorLauncher hands a libretro core saves\\<system> at each launch
    (LibRetro.Generator.cs Configure: savefile_directory), so a file a core
    reads below its save directory sits once in each of these system
    folders. A commented-out system is no element and counts for nothing.
    """
    from common import parse_untrusted_xml

    found: dict[str, set[str]] = {}
    for system in parse_untrusted_xml(text, "es_systems.cfg").iter("system"):
        name = (system.findtext("name") or "").strip()
        if not name:
            continue
        for emulator in system.iter("emulator"):
            if (emulator.get("name") or "").strip() != "libretro":
                continue
            for core in emulator.iter("core"):
                core_name = (core.text or "").strip()
                if core_name:
                    found.setdefault(core_name, set()).add(name)
    return {core: sorted(systems) for core, systems in sorted(found.items())}


def launcher_revision(url: str) -> str:
    """The emulatorLauncher commit a source URL is pinned to."""
    found = re.search(r"/emulatorlauncher/([0-9a-f]{40})/", url)
    if found is None:
        raise ValueError(f"{url} names no emulatorLauncher commit")
    return found.group(1)


def fetch_launchers(rev: str) -> list[dict]:
    """Launcher records read from the generators at the commit the BIOS list comes from."""
    texts = {
        path: fetch_bytes(LAUNCHER_FILE_URL.format(rev=rev, path=path)).decode("utf-8-sig")
        for path in LAUNCHER_FILES
    }
    return extract_launchers(texts)


# RetroBat's system keys are Batocera's (its emulatorlauncher reads the same
# batocera-systems.json format): psx, nds and atari800 met no profile system
# until the two shared one map.
SYSTEM_SLUG_MAP = {
    **BATOCERA_SLUGS,
    "amiga4000": "commodore-amiga",
    "arcadia": "emerson-arcadia-2001",
    "ecwolf": "wolfenstein3d",
    "namco2x6": "namco-system246",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psvita": "sony-playstation-vita",
    "gsplus": "apple-iigs",
}


class Scraper(BaseScraper):
    """Scraper for RetroBat batocera-systems.json."""

    def __init__(self, url: str | None = None) -> None:
        # batocera-systems.json is read from master: the commit read is recorded.
        if url is None:
            url = SOURCE_URL.format(rev=fetch_branch_head(LAUNCHER_REPO, "master"))
        super().__init__(url=url)
        self._parsed: dict | None = None

    def _parse_json(self) -> dict:
        if self._parsed is not None:
            return self._parsed

        raw = self._fetch_raw()
        try:
            self._parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}") from e
        return self._parsed

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse batocera-systems.json and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("batocera-systems.json format validation failed")

        data = self._parse_json()
        requirements = []

        for sys_key, sys_data in data.items():
            if not isinstance(sys_data, dict):
                continue

            bios_files = sys_data.get("biosFiles", [])
            if not isinstance(bios_files, list):
                continue

            for bios in bios_files:
                if not isinstance(bios, dict):
                    continue

                declared_path = bios.get("file", "")
                file_path = declared_path
                md5 = bios.get("md5", "")

                if not file_path:
                    continue

                # Strip bios/ prefix from file paths
                if file_path.startswith("bios/"):
                    file_path = file_path[5:]

                name = file_path.split("/")[-1] if "/" in file_path else file_path

                native: dict[str, object] = {}
                sys_name = sys_data.get("name", "") if isinstance(sys_data, dict) else ""
                if sys_name:
                    native["native_name"] = sys_name
                # One held file of a group is enough (Program.cs): verify reads it.
                if bios.get("group"):
                    native["group"] = str(bios["group"])

                requirements.append(
                    BiosRequirement(
                        name=name,
                        system=SYSTEM_SLUG_MAP.get(sys_key, sys_key),
                        md5=md5 or None,
                        destination=file_path,
                        required=not bios.get("optional", False),
                        native_id=sys_key,
                        native_path=declared_path,
                        native=native,
                    )
                )

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate that raw_data is valid JSON containing biosFiles entries."""
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False

        if not isinstance(data, dict):
            return False

        has_bios = False
        for sys_key, sys_data in data.items():
            if isinstance(sys_data, dict) and "biosFiles" in sys_data:
                has_bios = True
                break

        return has_bios

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        raw = self._fetch_raw()
        source_data = json.loads(raw)
        display_names: dict[str, str] = {}
        for sys_key, sys_data in source_data.items():
            if isinstance(sys_data, dict):
                dname = sys_data.get("name", "")
                if dname:
                    slug = SYSTEM_SLUG_MAP.get(sys_key, sys_key)
                    display_names[slug] = dname

        systems = {}
        for req in requirements:
            if req.system not in systems:
                sys_entry: dict = {"files": []}
                dname = display_names.get(req.system)
                if dname:
                    sys_entry["name"] = dname
                systems[req.system] = sys_entry

            systems[req.system]["files"].append(requirement_entry(req))

        version = fetch_github_latest_version(GITHUB_REPO)
        es_url = ES_SYSTEMS_URL.format(tag=version)
        req = urllib.request.Request(es_url, headers={"User-Agent": "retrobios-scraper/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                es_text = resp.read().decode("utf-8")
            cores, standalone = es_systems_cores(es_text)
            dual = es_systems_dual(es_text)
            libretro_systems = es_systems_libretro_systems(es_text)
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {es_url}: {e}") from e
        if not cores:
            raise RuntimeError(f"es_systems.cfg at {version} names no core")

        return {
            "platform": "RetroBat",
            "version": version,
            "homepage": "https://www.retrobat.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": sorted(cores),
            "standalone_cores": sorted(standalone),
            # Launched both ways: each layout gets its files.
            **({"dual_mode_cores": sorted(dual)} if dual else {}),
            "systems": systems,
            # The systems each libretro core runs for: its save folders.
            "libretro_systems": libretro_systems,
            "launchers": fetch_launchers(launcher_revision(self.url)),
        }


def main() -> None:
    from scripts.scraper.base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape retrobat BIOS requirements")


if __name__ == "__main__":
    main()
