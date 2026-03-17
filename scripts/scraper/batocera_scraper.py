#!/usr/bin/env python3
"""Scraper for Batocera batocera-systems.

Source: https://github.com/batocera-linux/batocera.linux/.../batocera-systems
Format: Python dict with systems -> biosFiles
Hash: MD5 primary
"""

from __future__ import annotations

import ast
import re
import sys
import urllib.request
import urllib.error

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_tag

PLATFORM_NAME = "batocera"

SOURCE_URL = (
    "https://raw.githubusercontent.com/batocera-linux/batocera.linux/"
    "master/package/batocera/core/batocera-scripts/scripts/batocera-systems"
)

SYSTEM_SLUG_MAP = {
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atarist": "atari-st",
    "lynx": "atari-lynx",
    "3do": "3do",
    "amiga": "commodore-amiga",
    "amiga600": "commodore-amiga",
    "amiga1200": "commodore-amiga",
    "amigacd32": "commodore-amiga",
    "amigacdtv": "commodore-amiga",
    "c128": "commodore-c128",
    "colecovision": "coleco-colecovision",
    "dreamcast": "sega-dreamcast",
    "naomi": "sega-dreamcast-arcade",
    "naomi2": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "fds": "nintendo-fds",
    "gamecube": "nintendo-gamecube",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "nds": "nintendo-ds",
    "n64dd": "nintendo-64dd",
    "satellaview": "nintendo-satellaview",
    "sgb": "nintendo-sgb",
    "snes": "nintendo-snes",
    "channelf": "fairchild-channel-f",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "msx1": "microsoft-msx",
    "msx2": "microsoft-msx",
    "msxturbor": "microsoft-msx",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "odyssey2": "magnavox-odyssey2",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "supergrafx": "nec-pc-engine",
    "pc88": "nec-pc-88",
    "pc98": "nec-pc-98",
    "pcfx": "nec-pc-fx",
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "psp": "sony-psp",
    "saturn": "sega-saturn",
    "segacd": "sega-mega-cd",
    "mastersystem": "sega-master-system",
    "megadrive": "sega-mega-drive",
    "gamegear": "sega-game-gear",
    "x1": "sharp-x1",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
    "scummvm": "scummvm",
    "doom": "doom",
    "macintosh": "apple-macintosh-ii",
    "dos": "dos",
    "videopac": "philips-videopac",
    "pokemini": "nintendo-pokemon-mini",
}


class Scraper(BaseScraper):
    """Scraper for batocera-systems Python dict."""

    def __init__(self, url: str = SOURCE_URL):
        self.url = url
        self._raw_data: str | None = None

    def _fetch_raw(self) -> str:
        if self._raw_data is not None:
            return self._raw_data

        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "retrobios-scraper/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                self._raw_data = resp.read().decode("utf-8")
                return self._raw_data
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {self.url}: {e}") from e

    def _extract_systems_dict(self, raw: str) -> dict:
        """Extract and parse the 'systems' dict from the Python source via ast.literal_eval."""
        match = re.search(r'^systems\s*=\s*\{', raw, re.MULTILINE)
        if not match:
            raise ValueError("Could not find 'systems = {' in batocera-systems")

        start = match.start() + raw[match.start():].index("{")
        depth = 0
        i = start
        while i < len(raw):
            if raw[i] == "{":
                depth += 1
            elif raw[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            elif raw[i] == "#":
                while i < len(raw) and raw[i] != "\n":
                    i += 1
            i += 1

        dict_str = raw[start:i + 1]

        lines = []
        for line in dict_str.split("\n"):
            in_string = False
            string_char = None
            clean = []
            for j, ch in enumerate(line):
                if ch in ('"', "'") and not in_string:
                    in_string = True
                    string_char = ch
                    clean.append(ch)
                elif ch == string_char and in_string:
                    in_string = False
                    clean.append(ch)
                elif ch == "#" and not in_string:
                    break
                else:
                    clean.append(ch)
            lines.append("".join(clean))

        clean_dict_str = "\n".join(lines)

        clean_dict_str = clean_dict_str.replace("OrderedDict(", "dict(")

        try:
            return ast.literal_eval(clean_dict_str)
        except (SyntaxError, ValueError) as e:
            raise ValueError(f"Failed to parse systems dict: {e}") from e

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse batocera-systems and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("batocera-systems format validation failed")

        systems = self._extract_systems_dict(raw)
        requirements = []

        for sys_key, sys_data in systems.items():
            system_slug = SYSTEM_SLUG_MAP.get(sys_key, sys_key)
            bios_files = sys_data.get("biosFiles", [])

            for bios in bios_files:
                file_path = bios.get("file", "")
                md5 = bios.get("md5", "")
                zipped_file = bios.get("zippedFile", "")

                if file_path.startswith("bios/"):
                    file_path = file_path[5:]

                name = file_path.split("/")[-1] if "/" in file_path else file_path

                requirements.append(BiosRequirement(
                    name=name,
                    system=system_slug,
                    md5=md5 or None,
                    destination=file_path,
                    required=True,
                    zipped_file=zipped_file or None,
                ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate batocera-systems format."""
        has_systems = "systems" in raw_data and "biosFiles" in raw_data
        has_dict = re.search(r'^systems\s*=\s*\{', raw_data, re.MULTILINE) is not None
        has_md5 = '"md5"' in raw_data
        has_file = '"file"' in raw_data
        return has_systems and has_dict and has_md5 and has_file

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict from scraped data."""
        requirements = self.fetch_requirements()

        systems = {}
        for req in requirements:
            if req.system not in systems:
                systems[req.system] = {"files": []}

            entry = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.md5:
                entry["md5"] = req.md5
            if req.zipped_file:
                entry["zipped_file"] = req.zipped_file

            systems[req.system]["files"].append(entry)

        # Sort numerically since API returns by commit date, not version
        import json as _json
        batocera_version = ""
        try:
            _url = "https://api.github.com/repos/batocera-linux/batocera.linux/tags?per_page=50"
            _req = urllib.request.Request(_url, headers={
                "User-Agent": "retrobios-scraper/1.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(_req, timeout=15) as _resp:
                _tags = _json.loads(_resp.read())
            _versions = []
            for _t in _tags:
                _name = _t["name"]
                if _name.startswith("batocera-"):
                    _num = _name.replace("batocera-", "")
                    if _num.isdigit():
                        _versions.append(int(_num))
            if _versions:
                batocera_version = str(max(_versions))
        except Exception:
            pass

        return {
            "platform": "Batocera",
            "version": batocera_version or "",
            "homepage": "https://batocera.org",
            "source": SOURCE_URL,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "systems": systems,
        }


def main():
    """CLI entry point for testing."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Scrape batocera-systems")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", "-o")
    args = parser.parse_args()

    scraper = Scraper()

    try:
        reqs = scraper.fetch_requirements()
    except (ConnectionError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        by_system = {}
        for req in reqs:
            by_system.setdefault(req.system, []).append(req)

        for system, files in sorted(by_system.items()):
            print(f"\n{system} ({len(files)} files):")
            for f in files:
                hash_info = f.md5[:12] if f.md5 else "no-hash"
                print(f"  {f.name} ({hash_info}...)")

        print(f"\nTotal: {len(reqs)} BIOS files across {len(by_system)} systems")
        return

    if args.json:
        config = scraper.generate_platform_yaml()
        print(json.dumps(config, indent=2))
        return

    if args.output:
        try:
            import yaml
        except ImportError:
            print("Error: PyYAML required", file=sys.stderr)
            sys.exit(1)

        config = scraper.generate_platform_yaml()
        with open(args.output, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"Written to {args.output}")
    else:
        reqs = scraper.fetch_requirements()
        by_system = {}
        for req in reqs:
            by_system.setdefault(req.system, []).append(req)
        print(f"Scraped {len(reqs)} BIOS files across {len(by_system)} systems")


if __name__ == "__main__":
    main()
