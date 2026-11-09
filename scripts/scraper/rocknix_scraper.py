#!/usr/bin/env python3
"""Scraper for ROCKNIX BIOS requirements.

Source: projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems
Format: Python source, a `systems` mapping of per-system BIOS declarations
Hash: MD5

ROCKNIX verification logic (rocknix-systems, checkBios):
- md5sum() of the file on disk against the declared md5
- checkInsideZip() when zippedFile is set, with an optional altmd5
- an empty md5 means the check is presence only

EmulationStation surfaces the result through ApiSystem::getBiosInformations,
which shells out to `rocknix-systems` (es-app/src/ApiSystem.cpp:486-516).
"""
from __future__ import annotations

import re

try:
    from .base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_version,
        md5_field,
        requirement_entry,
    )
    from .rocknix_launchers import extract_launchers
    from .shell_launchers import RepoTree
except ImportError:
    from base_scraper import (
        BaseScraper,
        BiosRequirement,
        fetch_github_latest_version,
        md5_field,
        requirement_entry,
    )
    from rocknix_launchers import extract_launchers
    from shell_launchers import RepoTree

PLATFORM_NAME = "rocknix"

GITHUB_REPO = "ROCKNIX/distribution"

SOURCE_TEMPLATE = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/{ref}/"
    "projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems"
)
# The branch a test or a manual run can still name. A scrape reads the tag
# of the release its YAML is labelled with.
SOURCE_URL = SOURCE_TEMPLATE.format(ref="next")
EMULATORS_MK_URL = (
    "https://raw.githubusercontent.com/ROCKNIX/distribution/{ref}"
    "/projects/ROCKNIX/packages/virtual/emulators/package.mk"
)
STANDALONE_TREE_URL = (
    "https://api.github.com/repos/ROCKNIX/distribution/contents/"
    "projects/ROCKNIX/packages/emulators/standalone?ref={ref}"
)


def launcher_revision(url: str) -> str:
    """The tag or commit a rocknix-systems URL is read at."""
    found = re.search(r"/ROCKNIX/distribution/([^/]+)/projects/", url)
    if found is None:
        raise ValueError(f"{url} names no ROCKNIX/distribution revision")
    return found.group(1)


def standalone_emulators(package_names: list[str]) -> list[str]:
    """The standalone emulators ROCKNIX packages, by the names profiles use.

    A package is named after its emulator with an ``-sa`` suffix
    (``duckstation-sa``), once without its hyphen (``hatarisa``), and both
    spellings are kept so a profile listing either is found.
    """
    names: set[str] = set()
    for package in package_names:
        names.add(package)
        stripped = _emulator_of(package)
        if stripped != package:
            names.add(stripped)
    return sorted(names)

def _emulator_of(package: str) -> str:
    return re.sub(r"-?sa$", "", package) or package


def dual_mode_emulators(standalone: list[str], package_mk: str) -> list[str]:
    """The standalone emulators RetroArch also runs as a core.

    package.mk adds each launch option with `add_emu_core <system> <emulator>
    <core> <default>`. Only an emulator also added as `retroarch <core>` is
    launched both ways: ARMSX2 is added as armsx2-sa alone.
    """
    retroarch = set(re.findall(r"^\s*add_emu_core\s+\S+\s+retroarch\s+(\S+)", package_mk, re.M))
    return sorted(name for name in standalone if _emulator_of(name) in retroarch)


# ROCKNIX system key -> retrobios system ID
SYSTEM_SLUG_MAP = {
    "xbox": "microsoft-xbox",
    "gamecube": "nintendo-gamecube",
    "nds": "nintendo-ds",
    "gb": "nintendo-gb",
    "gba": "nintendo-gba",
    "gbc": "nintendo-gbc",
    "dreamcast": "sega-dreamcast",
    "gamegear": "sega-game-gear",
    "mastersystem": "sega-master-system",
    "segacd": "sega-mega-cd",
    "saturn": "sega-saturn",
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psp": "sony-psp",
    "3do": "3do",
    "amiga": "commodore-amiga",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarilynx": "atari-lynx",
    "colecovision": "coleco-colecovision",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "neogeo": "snk-neogeo",
    "neogeocd": "snk-neogeo-cd",
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine-cd",
    "x68000": "sharp-x68000",
    "zxspectrum": "sinclair-zx-spectrum",
}

_SYSTEM_HEADER = re.compile(
    r'"(?P<key>[\w\-]+)"\s*:\s*\{\s*"name"\s*:\s*"(?P<name>[^"]+)"\s*,'
    r'\s*"biosFiles"\s*:\s*\[',
)
_FIELD = re.compile(r'"(\w+)"\s*:\s*"([^"]*)"')
# A field written as a list of strings (`"md5": [ "a", "b" ]`), the form
# batocera.linux 6b08b873 gives the md5 of a file several dumps satisfy.
_LIST_FIELD = re.compile(r'"(\w+)"\s*:\s*\[([^\[\]]*)\]')
_LIST_ITEM = re.compile(r'"([^"]*)"')


def _slice_bios_block(source: str, start: int) -> tuple[str, int]:
    """Return the biosFiles list body starting at an opening bracket."""
    depth = 0
    for i in range(start, len(source)):
        char = source[i]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return source[start + 1:i], i
    raise ValueError("unterminated biosFiles list")


def parse_systems(source: str) -> dict[str, dict]:
    """Extract per-system BIOS declarations from the rocknix-systems source.

    Parsed textually rather than evaluated: the file is upstream code, and
    the declarations are plain string literals.
    """
    source = re.sub(r"#[^\n]*", "", source)
    systems: dict[str, dict] = {}

    for header in _SYSTEM_HEADER.finditer(source):
        body, _ = _slice_bios_block(source, header.end() - 1)
        files = []
        for raw_entry in re.findall(r"\{[^{}]*\}", body):
            fields: dict[str, str | list[str]] = dict(_FIELD.findall(raw_entry))
            for key, items in _LIST_FIELD.findall(raw_entry):
                fields[key] = _LIST_ITEM.findall(items)
            if fields.get("file"):
                files.append(fields)
        systems[header.group("key")] = {
            "name": header.group("name"),
            "biosFiles": files,
        }

    if not systems:
        raise ValueError("no system declarations found in rocknix-systems")
    return systems


class Scraper(BaseScraper):
    """Scraper for the ROCKNIX rocknix-systems script."""

    def __init__(self, url: str | None = None) -> None:
        self.tag = None if url else fetch_github_latest_version(GITHUB_REPO)
        super().__init__(url=url or SOURCE_TEMPLATE.format(ref=self.tag))

    def _built_cores(self, standalone: list[str]) -> tuple[list[str], list[str]]:
        """(cores, standalone cores) at least one device image carries.

        RetroArch runs the libretro cores the packages of its emulators
        metapackage install per device
        (projects/ROCKNIX/packages/virtual/emulators/package.mk), read by
        the targets scraper, where every libretro profile counted before. A
        standalone package no device carries is not run either.
        """
        try:
            from .targets.rocknix_targets_scraper import Scraper as DeviceTargets
        except ImportError:
            from scraper.targets.rocknix_targets_scraper import Scraper as DeviceTargets
        builds = DeviceTargets().device_builds(self.tag or launcher_revision(self.url))
        libretro = sorted({core for _arch, lr, _sa in builds.values() for core in lr})
        carried = set(standalone_emulators(sorted({p for *_rest, sa in builds.values() for p in sa})))
        standalone = [name for name in standalone if name in carried]
        return sorted({*libretro, *standalone}), standalone

    def _fetch_standalone(self) -> list[str]:
        """The packages of projects/ROCKNIX/packages/emulators/standalone."""
        import json
        import urllib.error
        import urllib.request

        from .base_scraper import github_headers

        url = STANDALONE_TREE_URL.format(ref=self.tag or "next")
        req = urllib.request.Request(url, headers=github_headers())
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                listing = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            raise ConnectionError(f"Failed to list {url}: {e}") from e
        packages = [item["name"] for item in listing if item.get("type") == "dir"]
        if not packages:
            raise RuntimeError(f"no standalone emulator package at {url}")
        return standalone_emulators(packages)

    def _fetch_emulators_mk(self) -> str:
        """The package.mk that adds each emulator and core to es_systems."""
        import urllib.error
        import urllib.request

        url = EMULATORS_MK_URL.format(ref=self.tag or "next")
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                text = resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to fetch {url}: {e}") from e
        if "add_emu_core" not in text:
            raise RuntimeError(f"no add_emu_core line in {url}")
        return text

    def validate_format(self, raw_data: str) -> bool:
        """Validate the rocknix-systems format."""
        has_dict = re.search(r"^systems\s*=\s*\{", raw_data, re.MULTILINE) is not None
        has_check = "def checkBios" in raw_data
        return has_dict and has_check and '"biosFiles"' in raw_data and '"md5"' in raw_data

    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse rocknix-systems and return BIOS requirements."""
        if not self.validate_format(self._fetch_raw()):
            raise ValueError("rocknix-systems format validation failed")
        requirements = []

        for key, entry in parse_systems(self._fetch_raw()).items():
            system_slug = SYSTEM_SLUG_MAP.get(key, key)
            for bios in entry["biosFiles"]:
                path = bios["file"]
                # Declared paths are relative to the storage root: strip the
                # leading bios/ so destinations match base_destination
                destination = path[len("bios/"):] if path.startswith("bios/") else path
                values, as_list = md5_field(bios.get("md5"))
                native: dict[str, object] = {"native_name": entry["name"]}
                if as_list:
                    native["md5_list"] = True
                req = BiosRequirement(
                    name=destination.rsplit("/", 1)[-1],
                    system=system_slug,
                    md5=",".join(values) or None,
                    alt_md5=bios.get("altmd5", "") or None,
                    destination=destination,
                    required=True,
                    native_id=key,
                    native=native,
                )
                if bios.get("zippedFile"):
                    req.zipped_file = bios["zippedFile"]
                requirements.append(req)

        return requirements

    def generate_platform_yaml(self) -> dict:
        """Build the ROCKNIX platform configuration."""
        raw = parse_systems(self._fetch_raw())
        names = {key: entry["name"] for key, entry in raw.items()}
        systems: dict[str, dict] = {}

        for req in self.fetch_requirements():
            entry = systems.setdefault(
                req.system,
                {
                    "files": [],
                    "native_id": req.native_id,
                    "name": names.get(req.native_id, req.system),
                },
            )
            entry["files"].append(requirement_entry(req))

        cores, standalone = self._built_cores(self._fetch_standalone())
        return {
            "platform": "ROCKNIX",
            "version": self.tag or fetch_github_latest_version(GITHUB_REPO),
            "homepage": "https://rocknix.org",
            "source": self.url,
            "base_destination": "bios",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            # Launched both ways only where package.mk also adds the
            # emulator as a RetroArch core.
            "dual_mode_cores": dual_mode_emulators(standalone, self._fetch_emulators_mk()),
            "systems": systems,
            # Read at the revision the BIOS list comes from.
            "launchers": extract_launchers(
                RepoTree.github(GITHUB_REPO, launcher_revision(self.url))
            ),
        }


def main() -> None:
    """Entry point."""
    try:
        from .base_scraper import scraper_cli
    except ImportError:
        from base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape ROCKNIX BIOS requirements")


if __name__ == "__main__":
    main()
