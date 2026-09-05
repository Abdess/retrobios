#!/usr/bin/env python3
"""Scraper for Recalbox BIOS requirements.

Source: https://gitlab.com/recalbox/recalbox/-/raw/master/board/recalbox/fsoverlay/recalbox/share_init/system/.emulationstation/es_bios.xml
Format: XML (es_bios.xml)
Hash: MD5 (multiple valid hashes per entry, comma-separated)

Recalbox verification logic:
- Checks MD5 of file on disk against list of valid hashes
- Multiple MD5s accepted per BIOS (different ROM revisions)
- Alternate file paths (pipe-separated)
- hashMatchMandatory flag: if false, wrong hash = warning (YELLOW) not error (RED)
- ZIP files get composite MD5 calculation
"""

from __future__ import annotations

from common import parse_untrusted_xml

from .base_scraper import BaseScraper, BiosRequirement, requirement_entry

PLATFORM_NAME = "recalbox"

def _fetch_gitlab_stable_tag() -> str | None:
    """Fetch the latest stable x.y.z tag from the Recalbox GitLab."""
    import json
    import re
    import urllib.error
    import urllib.request

    url = "https://gitlab.com/api/v4/projects/recalbox%2Frecalbox/repository/tags?per_page=50"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "retrobios-scraper/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            tags = json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None
    stable = [t["name"] for t in tags if re.fullmatch(r"[0-9]+\.[0-9]+(\.[0-9]+)?", t["name"])]
    return stable[0] if stable else None


_STABLE_TAG = _fetch_gitlab_stable_tag() or "master"

SOURCE_URL = (
    f"https://gitlab.com/recalbox/recalbox/-/raw/{_STABLE_TAG}/"
    "board/recalbox/fsoverlay/recalbox/share_init/system/"
    ".emulationstation/es_bios.xml"
)

SYSTEM_SLUG_MAP = {
    "3do": "3do",
    "amiga600": "commodore-amiga",
    "amiga1200": "commodore-amiga",
    "amigacd32": "commodore-amiga",
    "amigacdtv": "commodore-amiga",
    "amstradcpc": "amstrad-cpc",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "atarist": "atari-st",
    "c64": "commodore-c64",
    "channelf": "fairchild-channel-f",
    "colecovision": "coleco-colecovision",
    "dreamcast": "sega-dreamcast",
    "fds": "nintendo-fds",
    "gamecube": "nintendo-gamecube",
    "gamegear": "sega-game-gear",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "intellivision": "mattel-intellivision",
    "jaguar": "atari-jaguar",
    "mastersystem": "sega-master-system",
    "megadrive": "sega-mega-drive",
    "msx": "microsoft-msx",
    "msx1": "microsoft-msx",
    "msx2": "microsoft-msx",
    "n64": "nintendo-64",
    "naomi": "sega-dreamcast-arcade",
    "naomigd": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "nds": "nintendo-ds",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "o2em": "magnavox-odyssey2",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "ps2": "sony-playstation-2",
    "psx": "sony-playstation",
    "saturn": "sega-saturn",
    "scummvm": "scummvm",
    "segacd": "sega-mega-cd",
    "snes": "nintendo-snes",
    "supergrafx": "nec-pc-engine",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
}


class Scraper(BaseScraper):
    """Scraper for Recalbox es_bios.xml."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)

    def _fetch_cores(self) -> list[str]:
        """Extract unique core names from es_bios.xml bios elements."""
        raw = self._fetch_raw()
        root = parse_untrusted_xml(raw, "es_bios.xml")
        cores: set[str] = set()
        for bios_elem in root.findall(".//system/bios"):
            raw_core = bios_elem.get("core", "").strip()
            if not raw_core:
                continue
            for part in raw_core.split(","):
                name = part.strip()
                if name:
                    cores.add(name)
        return sorted(cores)

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse es_bios.xml and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("es_bios.xml format validation failed")

        root = parse_untrusted_xml(raw, "es_bios.xml")
        requirements = []
        seen = set()

        for system_elem in root.findall(".//system"):
            platform = system_elem.get("platform", "")
            system_slug = SYSTEM_SLUG_MAP.get(platform, platform)
            fullname = system_elem.get("fullname", "")

            for bios_elem in system_elem.findall("bios"):
                paths_str = bios_elem.get("path", "")
                md5_str = bios_elem.get("md5", "")
                mandatory = bios_elem.get("mandatory", "true") != "false"

                paths = [p.strip() for p in paths_str.split("|") if p.strip()]
                if not paths:
                    continue

                primary_path = paths[0]
                name = (
                    primary_path.split("/")[-1] if "/" in primary_path else primary_path
                )

                md5_list = [m.strip() for m in md5_str.split(",") if m.strip()]
                all_md5 = ",".join(md5_list) if md5_list else None

                dedup_key = (platform, primary_path)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                native: dict[str, object] = {}
                if fullname:
                    native["native_name"] = fullname
                core = bios_elem.get("core", "").strip()
                if core:
                    native["core"] = core
                note = bios_elem.get("note", "").strip()
                if note:
                    native["note"] = note
                # Recalbox reads a missing attribute as true for both flags,
                # so only the explicit value carries information.
                hash_match = bios_elem.get("hashMatchMandatory")
                if hash_match is not None:
                    native["hash_match_mandatory"] = hash_match != "false"
                if bios_elem.get("mandatory") is not None:
                    native["mandatory_declared"] = mandatory
                if len(paths) > 1:
                    native["alt_paths"] = paths[1:]

                requirements.append(
                    BiosRequirement(
                        name=name,
                        system=system_slug,
                        md5=all_md5,
                        destination=primary_path,
                        required=mandatory,
                        native_id=platform,
                        native=native,
                    )
                )

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate es_bios.xml format."""
        return "<biosList" in raw_data and "<system" in raw_data and "<bios" in raw_data

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems: dict[str, dict] = {}
        for req in requirements:
            if req.system not in systems:
                sys_entry: dict = {"files": []}
                if req.native_id:
                    sys_entry["native_id"] = req.native_id
                systems[req.system] = sys_entry

            systems[req.system]["files"].append(requirement_entry(req))

        version = _STABLE_TAG if _STABLE_TAG != "master" else ""
        if not version:
            version = "10.0"

        return {
            "platform": "Recalbox",
            "version": version,
            "homepage": "https://www.recalbox.com",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": self._fetch_cores(),
            "systems": systems,
        }


def main():
    """CLI entry point."""
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape Recalbox es_bios.xml")


if __name__ == "__main__":
    main()
