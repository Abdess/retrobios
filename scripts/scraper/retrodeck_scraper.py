#!/usr/bin/env python3
"""Scraper for RetroDECK BIOS requirements.

Platform contributed by @monster-penguin (#36).

Source: https://github.com/RetroDECK/components
Format: component_manifest.json per component directory
Hash:   MD5 (primary), SHA256 for some entries (melonDS DSi)

RetroDECK stores BIOS requirements in component_manifest.json files,
one per emulator component. BIOS entries can appear in three locations:
  - top-level 'bios' key
  - preset_actions.bios (duckstation, dolphin, pcsx2)
  - cores.bios (retroarch)

Path tokens: $bios_path, $saves_path, $roms_path map to
~/retrodeck/bios/, ~/retrodeck/saves/, ~/retrodeck/roms/ respectively.
$saves_path entries are directory placeholders (excluded).
$roms_path entries (neogeo.zip etc.) get roms/ prefix in destination.
Entries with no paths key default to bios/ (RetroDECK's default BIOS dir).

Verification logic (api_data_processing.sh:289-405):
  - md5sum per file, compared against known_md5 (comma-separated list)
  - one result per manifest entry: a file two entries declare with other
    md5 lists is checked against each list on its own
  - envsubst resolves path tokens at runtime
  - Multi-threaded on system_cpu_max_threads
"""

from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

if not __package__:
    # Allow running directly: python scripts/scraper/retrodeck_scraper.py
    sys.path.insert(0, str(Path(__file__).parent.parent))
    importlib.import_module("scraper")
    __package__ = "scraper"

from core.hashing import parse_hash_list

from .base_scraper import (
    BaseScraper,
    BiosRequirement,
    fetch_branch_head,
    fetch_github_latest_version,
    fetch_present,
    fetch_text,
    github_tree,
    json_object,
    md5_field,
    systems_from_requirements,
)
from .retrodeck_launchers import extract_launchers
from .romfolders.es import command_core, esde_systems

PLATFORM_NAME = "retrodeck"
COMPONENTS_REPO = "RetroDECK/components"
COMPONENTS_BRANCH = "main"
RAW_BASE = "https://raw.githubusercontent.com/" + COMPONENTS_REPO + "/{rev}"
SKIP_DIRS = {"archive_later", "archive_old", "automation-tools", ".github"}

# ES-DE's system list as RetroDECK's fork builds it.
ES_DE_REPO = "RetroDECK/ES-DE"
ES_DE_SYSTEMS_URL = (
    "https://raw.githubusercontent.com/" + ES_DE_REPO
    + "/{rev}/resources/systems/linux/es_systems.xml"
)


def es_systems_libretro_systems(text: str) -> dict[str, list[str]]:
    """libretro core -> the ROM folders of the systems whose commands load it.

    RetroDECK's RetroArch sorts saves by content and not by core
    (retroarch/rd_assets/rd_config/retroarch.cfg, sort_savefiles_by_content_enable
    and sort_savefiles_enable): a core is handed saves/<folder holding the
    ROM>, the system's <path> folder below %ROMPATH%. A commented-out
    command counts for nothing.
    """
    found: dict[str, set[str]] = {}
    for _name, path, _extensions, commands in esde_systems(text, "es_systems.xml"):
        folder = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if not folder or folder.startswith("%"):
            continue
        for _label, command in commands:
            emulator, core = command_core(command)
            if emulator == "retroarch" and core:
                found.setdefault(core, set()).add(folder)
    return {core: sorted(folders) for core, folders in sorted(found.items())}


def component_modes(
    components: list[str], libretro_systems: dict[str, list[str]]
) -> tuple[list[str], list[str]]:
    """(standalone_cores, dual_mode_cores) of RetroDECK's emulator components.

    Every component but retroarch is an emulator RetroDECK launches on its
    own (its component_launcher.sh execs the emulator's binary). One whose name
    is also a core an ES-DE command loads through RetroArch is offered both
    ways: es_systems.xml lists "Azahar (Standalone)" and "Azahar"
    (azahar_libretro.so) for n3ds. The core itself ships, RetroArch's cores
    coming whole from the buildbot's nightly RetroArch_cores.7z
    (retroarch/component_recipe.json:250-262 at components fcd0d729).
    """
    standalone = [c for c in components if c != "retroarch"]
    return standalone, [c for c in standalone if c in libretro_systems]


NON_EMULATOR_COMPONENTS = {
    "framework",
    "es-de",
    "steam-rom-manager",
    "flips",
    "portmaster",
}

# RetroDECK system ID -> retrobios slug.
# None = skip (system not relevant for BIOS packs).
# Missing key = pass through as-is.
SYSTEM_SLUG_MAP: dict[str, str | None] = {
    # Nintendo
    "nes": "nintendo-nes",
    "snes": "nintendo-snes",
    "snesna": "nintendo-snes",
    "n64": "nintendo-64",
    "n64dd": "nintendo-64dd",
    "gc": "nintendo-gamecube",
    "wii": "nintendo-wii",
    "wiiu": "nintendo-wii-u",
    "switch": "nintendo-switch",
    "gb": "nintendo-gb",
    "gbc": "nintendo-gbc",
    "gba": "nintendo-gba",
    "nds": "nintendo-ds",
    "3ds": "nintendo-3ds",
    "n3ds": "nintendo-3ds",
    "fds": "nintendo-fds",
    "sgb": "nintendo-sgb",
    "virtualboy": "nintendo-virtual-boy",
    # Sony
    "psx": "sony-playstation",
    "ps2": "sony-playstation-2",
    "ps3": "sony-playstation-3",
    "psp": "sony-psp",
    "psvita": "sony-playstation-vita",
    # Sega
    "megadrive": "sega-mega-drive",
    "genesis": "sega-mega-drive",
    "megacd": "sega-mega-cd",
    "megacdjp": "sega-mega-cd",
    "segacd": "sega-mega-cd",
    "saturn": "sega-saturn",
    "saturnjp": "sega-saturn",
    "dreamcast": "sega-dreamcast",
    "naomi": "sega-dreamcast-arcade",
    "naomi2": "sega-dreamcast-arcade",
    "atomiswave": "sega-dreamcast-arcade",
    "gamegear": "sega-game-gear",
    "mastersystem": "sega-master-system",
    "sms": "sega-master-system",
    # NEC
    "pcengine": "nec-pc-engine",
    "pcenginecd": "nec-pc-engine",
    "turbografx16": "nec-pc-engine",
    "pcfx": "nec-pc-fx",
    "pc98": "nec-pc-98",
    "pc9800": "nec-pc-98",
    "pc88": "nec-pc-88",
    "pc8800": "nec-pc-88",
    # Other
    "3do": "3do",
    "amstradcpc": "amstrad-cpc",
    "arcade": "arcade",
    "mame": "arcade",
    "fbneo": "arcade",
    "atari800": "atari-400-800",
    "atari5200": "atari-5200",
    "atari7800": "atari-7800",
    "atarijaguar": "atari-jaguar",
    "atarilynx": "atari-lynx",
    "atarist": "atari-st",
    "atarixe": "atari-400-800",
    "c64": "commodore-c64",
    "amiga": "commodore-amiga",
    "cdimono1": "philips-cdi",
    "channelf": "fairchild-channel-f",
    "colecovision": "coleco-colecovision",
    "intellivision": "mattel-intellivision",
    "msx": "microsoft-msx",
    "xbox": "microsoft-xbox",
    "doom": "doom",
    "j2me": "j2me",
    "mac2": "apple-macintosh-ii",
    "macintosh": "apple-macintosh-ii",
    "apple2": "apple-ii",
    "apple2gs": "apple-iigs",
    "enterprise": "enterprise-64-128",
    "gamecom": "tiger-game-com",
    "gmaster": "hartung-game-master",
    "pokemini": "nintendo-pokemon-mini",
    "scv": "epoch-scv",
    "supervision": "watara-supervision",
    "wonderswan": "bandai-wonderswan",
    "neogeocd": "snk-neogeo-cd",
    "neogeocdjp": "snk-neogeo-cd",
    # xroar files the CoCo 1/2 ROMs under coco and the Dragon 64's under
    # dragon64, the ids Batocera uses too.
    "coco": "coco",
    "trs80": "tandy-trs-80",
    "dragon": "dragon64",
    "tanodragon": "dragon64",
    "pico8": "pico8",
    "vsmile": "vtech-vsmile",
    "wolfenstein": "wolfenstein-3d",
    "zxspectrum": "sinclair-zx-spectrum",
}


def _sanitize_path(p: str) -> str:
    """Fix upstream typos in path tokens."""
    return re.sub(r"\$saves_\w+", "$saves_path", p)


def _resolve_path(p: str) -> str:
    """Resolve RetroDECK path tokens to pack-relative paths."""
    p = _sanitize_path(p)
    p = p.replace("$bios_path", "bios")
    p = p.replace("$saves_path", "saves")
    p = p.replace("$roms_path", "roms")
    return p.strip("/")


def _extract_bios_entries(component_val: dict) -> list[dict]:
    """Extract BIOS entries from all three possible locations in a component.

    No dedup here: dedup is done in fetch_requirements() with full
    (system, filename) key to avoid dropping valid same-filename entries
    across different systems.
    """
    entries: list[dict] = []

    def collect(bios_data: list | dict) -> None:
        if isinstance(bios_data, dict):
            bios_data = [bios_data]
        if not isinstance(bios_data, list):
            return
        entries.extend(
            entry for entry in bios_data
            if isinstance(entry, dict) and entry.get("filename", "").strip()
        )

    if "bios" in component_val:
        collect(component_val["bios"])

    pa = component_val.get("preset_actions", {})
    if isinstance(pa, dict) and "bios" in pa:
        collect(pa["bios"])

    cores = component_val.get("cores", {})
    if isinstance(cores, dict) and "bios" in cores:
        collect(cores["bios"])

    return entries


def _map_system(raw_system: str) -> str | None:
    """Map RetroDECK system ID to retrobios slug.

    Returns None for systems explicitly excluded from the map.
    Unknown systems pass through as-is.
    """
    if raw_system in SYSTEM_SLUG_MAP:
        return SYSTEM_SLUG_MAP[raw_system]
    return raw_system


def _entry_folder(paths_raw: object) -> str | None:
    """The folder a BIOS entry's paths resolve to, None for a saves-only entry."""
    if isinstance(paths_raw, str):
        resolved = _resolve_path(paths_raw)
    elif isinstance(paths_raw, list):
        resolved = ""
        for p in paths_raw:
            rp = _resolve_path(str(p))
            if not rp.startswith("saves"):
                resolved = rp
                break
        if not resolved:
            return None
    else:
        resolved = ""

    # Skip saves-only entries
    if resolved.startswith("saves"):
        return None
    return resolved


_MD5 = re.compile(r"[0-9a-f]{32}")


def _entry_md5(md5_raw: object) -> str:
    """The valid md5 values of a manifest entry, comma-joined.

    An entry writes one string or a list of strings, as a batocera-systems
    item does. A value that is not a 32-digit hex md5 is an upstream error
    and is left out.
    """
    values, _listed = md5_field(md5_raw or None)
    return ",".join(m for m in parse_hash_list(values) if _MD5.fullmatch(m))


def _entry_requirement(entry: dict, comp_key: str, default_system: object) -> BiosRequirement | None:
    filename = entry["filename"].strip()
    raw_system = entry.get("system", default_system)
    if isinstance(raw_system, list):
        raw_system = raw_system[0] if raw_system else default_system

    system = _map_system(str(raw_system))
    if system is None:
        return None

    resolved = _entry_folder(entry.get("paths"))
    if resolved is None:
        return None

    # Build destination: default to bios/ if no path specified
    if resolved:
        destination = f"{resolved}/{filename}"
    else:
        destination = f"bios/{filename}"

    md5 = _entry_md5(entry.get("md5", ""))

    required_raw = entry.get("required", "")
    required = bool(required_raw) and str(required_raw).lower() not in (
        "false",
        "no",
        "optional",
        "",
    )

    native: dict[str, object] = {"component": comp_key}
    description = str(entry.get("description", "")).strip()
    if description:
        native["description"] = description
    if required_raw not in (None, ""):
        native["required_label"] = str(required_raw)

    sha256 = str(entry.get("sha256", "")).strip().lower()

    return BiosRequirement(
        name=filename,
        system=system,
        destination=destination,
        md5=md5,
        sha256=sha256 or None,
        required=required,
        native_id=str(raw_system),
        native=native,
    )


def _repeat_key(req: BiosRequirement) -> tuple[object, ...]:
    """What makes two manifest entries one declaration.

    RetroDECK checks every entry of every manifest on its own: one result
    row per entry, the md5 of the file found under that exact basename
    tested against that entry's list alone (api_data_processing.sh:304-313,
    322-339 and 350-361 at RetroDECK 0.10.10b). Two entries that differ in
    their hashes are two verdicts on the file (decocass.zip for MAME and for
    FBNeo, the three 64DD_IPL.bin revisions), and two spellings are two files
    on its Linux filesystem (MSX.ROM and MSX.rom). Only the same name at the
    same place with the same hashes repeats a declaration.
    """
    return (
        req.system,
        req.name,
        req.destination,
        frozenset(parse_hash_list(req.md5)),
        req.sha256 or "",
    )


class Scraper(BaseScraper):
    """RetroDECK BIOS scraper from component manifests."""

    platform_name = PLATFORM_NAME

    def __init__(self, manifests_dir: str = "") -> None:
        super().__init__()
        self.manifests_dir = manifests_dir
        self._manifests: list[tuple[str, dict]] | None = None
        self._files: dict[str, str | None] = {}
        # The manifests are read from main: one commit for the tree and for
        # every file, and that commit is the one recorded.
        self.revision = (
            "" if manifests_dir else fetch_branch_head(COMPONENTS_REPO, COMPONENTS_BRANCH)
        )

    def _get_manifests(self) -> list[tuple[str, dict]]:
        """Fetch manifests once, cache for reuse."""
        if self._manifests is None:
            self._manifests = (
                self._fetch_local_manifests()
                if self.manifests_dir
                else self._fetch_remote_manifests()
            )
        return self._manifests

    def _fetch_remote_manifests(self) -> list[tuple[str, dict]]:
        """Fetch component manifests via GitHub API."""
        component_dirs = [
            item["path"]
            for item in github_tree(COMPONENTS_REPO, self.revision, recursive=False)
            if item.get("type") == "tree" and item["path"] not in SKIP_DIRS
        ]

        manifests: list[tuple[str, dict]] = []
        for comp in sorted(component_dirs):
            url = f"{RAW_BASE.format(rev=self.revision)}/{comp}/component_manifest.json"
            print(f"  {comp} ...", file=sys.stderr, end="", flush=True)
            # Only a 404 says the component has no manifest. A 429, a 503 or
            # a dropped connection is no answer: skipping it wrote
            # retrodeck.yml without that component's systems, exit code 0.
            text = fetch_present(url)
            if text is None:
                print(" no manifest", file=sys.stderr)
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                raise ValueError(f"{url}: not JSON: {e}") from e
            manifests.append((comp, data))
            print(" ok", file=sys.stderr)
        return manifests

    def _fetch_local_manifests(self) -> list[tuple[str, dict]]:
        """Read manifests from local RetroDECK install."""
        root = Path(self.manifests_dir)
        manifests: list[tuple[str, dict]] = []
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name in SKIP_DIRS or d.name.startswith("."):
                continue
            mf = d / "component_manifest.json"
            if not mf.exists():
                continue
            # Skipped with a warning, an unreadable manifest left its
            # component's systems out of retrodeck.yml, exit code 0, where
            # the remote read stops.
            try:
                with open(mf) as f:
                    manifests.append((d.name, json.load(f)))
            except json.JSONDecodeError as e:
                raise ValueError(f"{mf}: not JSON: {e}") from e
        return manifests

    def component_file(self, path: str) -> str | None:
        """A file of the components repo at the scraped revision, None when it has none.

        Only a 404 says the file is absent: any other failure stops the
        scrape, as for the manifests.
        """
        if path in self._files:
            return self._files[path]
        if self.manifests_dir:
            local = Path(self.manifests_dir) / path
            text = local.read_text(encoding="utf-8") if local.is_file() else None
        else:
            text = fetch_present(f"{RAW_BASE.format(rev=self.revision)}/{path}")
        self._files[path] = text
        return text

    def validate_format(self, raw_data: str) -> bool:
        return json_object(raw_data) is not None

    def fetch_requirements(self) -> list[BiosRequirement]:
        manifests = self._get_manifests()

        requirements: list[BiosRequirement] = []
        seen: set[tuple[object, ...]] = set()

        for _comp_name, manifest in manifests:
            for comp_key, comp_val in manifest.items():
                if not isinstance(comp_val, dict):
                    continue

                default_system = comp_val.get("system", comp_key)
                if isinstance(default_system, list):
                    default_system = default_system[0] if default_system else comp_key

                for entry in _extract_bios_entries(comp_val):
                    req = _entry_requirement(entry, comp_key, default_system)
                    if req is None:
                        continue
                    key = _repeat_key(req)
                    if key in seen:
                        continue
                    seen.add(key)
                    requirements.append(req)

        return requirements

    def _fetch_libretro_systems(self) -> dict[str, list[str]]:
        """libretro core -> ROM folders, from the ES-DE build RetroDECK ships.

        RetroDECK takes ES-DE's latest release of its fork
        (automation-tools/alchemist/desired_versions.sh, ES_DE_DESIRED_VERSION).
        """
        tag = fetch_github_latest_version(ES_DE_REPO)
        text = fetch_text(ES_DE_SYSTEMS_URL.format(rev=tag))
        return es_systems_libretro_systems(text)

    def generate_platform_yaml(self) -> dict:
        reqs = self.fetch_requirements()
        manifests = self._get_manifests()

        cores = sorted(
            {
                comp_name
                for comp_name, _ in manifests
                if comp_name not in SKIP_DIRS
                and comp_name not in NON_EMULATOR_COMPONENTS
            }
        )

        systems = systems_from_requirements(reqs)

        version = fetch_github_latest_version("RetroDECK/RetroDECK")
        # The ROM folders each libretro core runs for: its save folders.
        libretro_systems = self._fetch_libretro_systems()
        standalone, dual = component_modes(cores, libretro_systems)

        return {
            "platform": "RetroDECK",
            "version": version,
            "homepage": "https://retrodeck.net",
            "source": (
                f"https://github.com/{COMPONENTS_REPO}/tree/{self.revision}"
                if self.revision
                else f"https://github.com/{COMPONENTS_REPO}"
            ),
            "base_destination": "",
            "hash_type": "md5",
            "verification_mode": "md5",
            "cores": cores,
            "standalone_cores": standalone,
            **({"dual_mode_cores": dual} if dual else {}),
            "systems": systems,
            "libretro_systems": libretro_systems,
            "launchers": extract_launchers(cores, self.component_file),
        }


def main() -> None:
    from .base_scraper import scraper_cli

    scraper_cli(Scraper, "Scrape RetroDECK BIOS requirements")


if __name__ == "__main__":
    main()
