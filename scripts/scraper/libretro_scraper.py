#!/usr/bin/env python3
"""Scraper for libretro System.dat (RetroArch, Lakka).

Source: https://github.com/libretro/libretro-database/blob/master/dat/System.dat
Format: clrmamepro DAT
Hash: SHA1 primary
"""

from __future__ import annotations

import sys
import urllib.request
import urllib.error

from .base_scraper import BaseScraper, BiosRequirement, fetch_github_latest_version
from .dat_parser import parse_dat, parse_dat_metadata, validate_dat_format

PLATFORM_NAME = "libretro"

SOURCE_URL = (
    "https://raw.githubusercontent.com/libretro/libretro-database/"
    "master/dat/System.dat"
)

# Libretro cores that expect BIOS files in a subdirectory of system/.
# System.dat lists filenames flat; the scraper prepends the prefix.
# ref: each core's libretro.c or equivalent — see platforms/README.md
CORE_SUBDIR_MAP = {
    "nec-pc-98": "np2kai",         # libretro-np2kai/sdl/libretro.c
    "sharp-x68000": "keropi",      # px68k/libretro/libretro.c
    "sega-dreamcast": "dc",        # flycast/shell/libretro/libretro.cpp
    "sega-dreamcast-arcade": "dc", # flycast — same subfolder
}

SYSTEM_SLUG_MAP = {
    "3DO Company, The - 3DO": "3do",
    "Amstrad - CPC": "amstrad-cpc",
    "Arcade": "arcade",
    "Atari - 400-800": "atari-400-800",
    "Atari - 5200": "atari-5200",
    "Atari - 7800": "atari-7800",
    "Atari - Lynx": "atari-lynx",
    "Atari - ST": "atari-st",
    "Coleco - ColecoVision": "coleco-colecovision",
    "Commodore - Amiga": "commodore-amiga",
    "Commodore - C128": "commodore-c128",
    "Dinothawr": "dinothawr",
    "DOS": "dos",
    "EPOCH/YENO Super Cassette Vision": "epoch-scv",
    "Elektronika - BK-0010/BK-0011(M)": "elektronika-bk",
    "Enterprise - 64/128": "enterprise-64-128",
    "Fairchild Channel F": "fairchild-channel-f",
    "Id Software - Doom": "doom",
    "J2ME": "j2me",
    "MacII": "apple-macintosh-ii",
    "Magnavox - Odyssey2": "magnavox-odyssey2",
    "Mattel - Intellivision": "mattel-intellivision",
    "Microsoft - MSX": "microsoft-msx",
    "NEC - PC Engine - TurboGrafx 16 - SuperGrafx": "nec-pc-engine",
    "NEC - PC-98": "nec-pc-98",
    "NEC - PC-FX": "nec-pc-fx",
    "Nintendo - Famicom Disk System": "nintendo-fds",
    "Nintendo - Game Boy Advance": "nintendo-gba",
    "Nintendo - GameCube": "nintendo-gamecube",
    "Nintendo - Gameboy": "nintendo-gb",
    "Nintendo - Gameboy Color": "nintendo-gbc",
    "Nintendo - Nintendo 64DD": "nintendo-64dd",
    "Nintendo - Nintendo DS": "nintendo-ds",
    "Nintendo - Nintendo Entertainment System": "nintendo-nes",
    "Nintendo - Pokemon Mini": "nintendo-pokemon-mini",
    "Nintendo - Satellaview": "nintendo-satellaview",
    "Nintendo - SuFami Turbo": "nintendo-sufami-turbo",
    "Nintendo - Super Game Boy": "nintendo-sgb",
    "Nintendo - Super Nintendo Entertainment System": "nintendo-snes",
    "Phillips - Videopac+": "philips-videopac",
    "SNK - NeoGeo CD": "snk-neogeo-cd",
    "ScummVM": "scummvm",
    "Sega - Dreamcast": "sega-dreamcast",
    "Sega - Dreamcast-based Arcade": "sega-dreamcast-arcade",
    "Sega - Game Gear": "sega-game-gear",
    "Sega - Master System - Mark III": "sega-master-system",
    "Sega - Mega CD - Sega CD": "sega-mega-cd",
    "Sega - Mega Drive - Genesis": "sega-mega-drive",
    "Sega - Saturn": "sega-saturn",
    "Sharp - X1": "sharp-x1",
    "Sharp - X68000": "sharp-x68000",
    "Sinclair - ZX Spectrum": "sinclair-zx-spectrum",
    "Sony - PlayStation": "sony-playstation",
    "Sony - PlayStation 2": "sony-playstation-2",
    "Sony - PlayStation Portable": "sony-psp",
    "Texas Instruments TI-83": "ti-83",
    "Videoton - TV Computer": "videoton-tvc",
    "Wolfenstein 3D": "wolfenstein-3d",
}


class Scraper(BaseScraper):
    """Scraper for libretro System.dat."""

    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)


    def fetch_requirements(self) -> list[BiosRequirement]:
        """Parse System.dat and return BIOS requirements."""
        raw = self._fetch_raw()

        if not self.validate_format(raw):
            raise ValueError("System.dat format validation failed")

        roms = parse_dat(raw)
        requirements = []

        for rom in roms:
            native_system = rom.system
            system_slug = SYSTEM_SLUG_MAP.get(native_system, native_system.lower().replace(" ", "-"))

            destination = rom.name
            name = rom.name.split("/")[-1] if "/" in rom.name else rom.name

            subdir = CORE_SUBDIR_MAP.get(system_slug)
            if subdir and not destination.startswith(subdir + "/"):
                destination = f"{subdir}/{destination}"

            requirements.append(BiosRequirement(
                name=name,
                system=system_slug,
                sha1=rom.sha1 or None,
                md5=rom.md5 or None,
                crc32=rom.crc32 or None,
                size=rom.size or None,
                destination=destination,
                required=True,
                native_id=native_system,
            ))

        return requirements

    def validate_format(self, raw_data: str) -> bool:
        """Validate System.dat format."""
        return validate_dat_format(raw_data)

    def fetch_metadata(self) -> dict:
        """Fetch version info from System.dat header and GitHub API."""
        raw = self._fetch_raw()
        meta = parse_dat_metadata(raw)

        retroarch_version = fetch_github_latest_version("libretro/RetroArch")
        db_version = fetch_github_latest_version("libretro/libretro-database")

        return {
            "dat_version": meta.version,
            "retroarch_version": retroarch_version,
            "db_version": db_version,
        }

    def _fetch_core_metadata(self) -> dict[str, dict]:
        """Fetch per-core metadata from libretro-core-info .info files."""
        metadata = {}
        try:
            url = f"https://api.github.com/repos/libretro/libretro-core-info/git/trees/master?recursive=1"
            req = urllib.request.Request(url, headers={
                "User-Agent": "retrobios-scraper/1.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                import json
                tree = json.loads(resp.read())

            info_files = [
                item["path"] for item in tree.get("tree", [])
                if item["path"].endswith("_libretro.info")
            ]

            for filename in info_files:
                core_name = filename.replace("_libretro.info", "")
                try:
                    info_url = f"https://raw.githubusercontent.com/libretro/libretro-core-info/master/{filename}"
                    req = urllib.request.Request(info_url, headers={"User-Agent": "retrobios-scraper/1.0"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        content = resp.read().decode("utf-8")

                    info = {}
                    for line in content.split("\n"):
                        line = line.strip()
                        if " = " in line:
                            key, _, value = line.partition(" = ")
                            info[key.strip()] = value.strip().strip('"')

                    fw_count = int(info.get("firmware_count", "0"))
                    if fw_count == 0:
                        continue

                    system_name = info.get("systemname", "")
                    manufacturer = info.get("manufacturer", "")
                    display_name = info.get("display_name", "")
                    categories = info.get("categories", "")

                    # Map core to our system slug via firmware paths
                    from .coreinfo_scraper import CORE_SYSTEM_MAP
                    system_slug = CORE_SYSTEM_MAP.get(core_name)
                    if not system_slug:
                        continue

                    if system_slug not in metadata:
                        metadata[system_slug] = {
                            "core": core_name,
                            "manufacturer": manufacturer,
                            "display_name": display_name or system_name,
                            "docs": f"https://docs.libretro.com/library/{core_name}/",
                        }
                except (urllib.error.URLError, urllib.error.HTTPError):
                    continue
        except (ConnectionError, ValueError, OSError):
            pass

        return metadata

    def generate_platform_yaml(self) -> dict:
        """Generate a platform YAML config dict, merging System.dat with core-info metadata."""
        requirements = self.fetch_requirements()
        metadata = self.fetch_metadata()
        core_meta = self._fetch_core_metadata()

        systems = {}
        for req in requirements:
            if req.system not in systems:
                system_entry: dict = {"files": []}
                if req.native_id:
                    system_entry["native_id"] = req.native_id
                if req.system in core_meta:
                    cm = core_meta[req.system]
                    if cm.get("core"):
                        system_entry["core"] = cm["core"]
                    if cm.get("manufacturer"):
                        system_entry["manufacturer"] = cm["manufacturer"]
                    if cm.get("docs"):
                        system_entry["docs"] = cm["docs"]
                systems[req.system] = system_entry

            entry = {
                "name": req.name,
                "destination": req.destination,
                "required": req.required,
            }
            if req.sha1:
                entry["sha1"] = req.sha1
            if req.md5:
                entry["md5"] = req.md5
            if req.crc32:
                entry["crc32"] = req.crc32
            if req.size:
                entry["size"] = req.size

            systems[req.system]["files"].append(entry)

        # Systems not in System.dat but needed for RetroArch — added via
        # shared groups in _shared.yml. The includes directive is resolved
        # at load time by load_platform_config().
        EXTRA_SYSTEMS = {
            "nec-pc-88": {
                "includes": ["quasi88"],
                "core": "quasi88",
                "manufacturer": "NEC",
                "docs": "https://docs.libretro.com/library/quasi88/",
            },
            # ref: Vircon32/libretro.c — virtual console, single BIOS
            "vircon32": {
                "files": [
                    {"name": "Vircon32Bios.v32", "destination": "Vircon32Bios.v32", "required": True},
                ],
                "core": "vircon32",
                "manufacturer": "Vircon",
                "docs": "https://docs.libretro.com/library/vircon32/",
            },
            # ref: xrick/src/sysvid.c, xrick/src/data.c — game data archive
            "xrick": {
                "files": [
                    {"name": "data.zip", "destination": "xrick/data.zip", "required": True},
                ],
                "core": "xrick",
                "manufacturer": "Other",
                "docs": "https://docs.libretro.com/library/xrick/",
            },
        }
        for sys_id, sys_data in EXTRA_SYSTEMS.items():
            if sys_id not in systems:
                systems[sys_id] = sys_data

        # Arcade BIOS present in the repo but absent from System.dat.
        # FBNeo expects them in system/ or system/fbneo/.
        # ref: fbneo/src/burner/libretro/libretro.cpp
        # ref: fbneo/src/burner/libretro/libretro.cpp — search order:
        # 1) romset dir 2) system/fbneo/ 3) system/
        EXTRA_ARCADE_FILES = [
            {"name": "namcoc69.zip", "destination": "namcoc69.zip", "required": True},
            {"name": "namcoc70.zip", "destination": "namcoc70.zip", "required": True},
            {"name": "namcoc75.zip", "destination": "namcoc75.zip", "required": True},
            {"name": "msx.zip", "destination": "msx.zip", "required": True},
            {"name": "qsound.zip", "destination": "qsound.zip", "required": True},
            # FBNeo non-arcade subsystem BIOS (MAME-format ZIPs)
            # ref: fbneo/src/burn/drv/ per-driver source files
            {"name": "channelf.zip", "destination": "channelf.zip", "required": True},
            {"name": "coleco.zip", "destination": "coleco.zip", "required": True},
            {"name": "neocdz.zip", "destination": "neocdz.zip", "required": True},
            {"name": "ngp.zip", "destination": "ngp.zip", "required": True},
            {"name": "spectrum.zip", "destination": "spectrum.zip", "required": True},
            {"name": "spec128.zip", "destination": "spec128.zip", "required": True},
            {"name": "spec1282a.zip", "destination": "spec1282a.zip", "required": True},
            {"name": "fdsbios.zip", "destination": "fdsbios.zip", "required": True},
            {"name": "aes.zip", "destination": "aes.zip", "required": True},
        ]
        if "arcade" in systems:
            existing = {f["name"] for f in systems["arcade"].get("files", [])}
            for ef in EXTRA_ARCADE_FILES:
                if ef["name"] not in existing:
                    systems["arcade"]["files"].append(ef)

        # segasp.zip for Sega System SP (Flycast)
        if "sega-dreamcast-arcade" in systems:
            existing = {f["name"] for f in systems["sega-dreamcast-arcade"].get("files", [])}
            if "segasp.zip" not in existing:
                systems["sega-dreamcast-arcade"]["files"].append({
                    "name": "segasp.zip",
                    "destination": "dc/segasp.zip",
                    "required": True,
                })

        # Extra files missing from System.dat for specific systems.
        # Each traced to the core's source code.
        EXTRA_SYSTEM_FILES = {
            # melonDS DS DSi mode — ref: JesseTG/melonds-ds/src/libretro.cpp
            "nintendo-ds": [
                {"name": "dsi_bios7.bin", "destination": "dsi_bios7.bin", "required": True},
                {"name": "dsi_bios9.bin", "destination": "dsi_bios9.bin", "required": True},
                {"name": "dsi_firmware.bin", "destination": "dsi_firmware.bin", "required": True},
                {"name": "dsi_nand.bin", "destination": "dsi_nand.bin", "required": True},
            ],
            # bsnes SGB naming — ref: bsnes/target-libretro/libretro.cpp
            "nintendo-sgb": [
                {"name": "sgb.boot.rom", "destination": "sgb.boot.rom", "required": False},
            ],
            # JollyCV — ref: jollycv/libretro.c
            "coleco-colecovision": [
                {"name": "BIOS.col", "destination": "BIOS.col", "required": True},
                {"name": "coleco.rom", "destination": "coleco.rom", "required": True},
                {"name": "bioscv.rom", "destination": "bioscv.rom", "required": True},
            ],
            # Kronos ST-V — ref: libretro-kronos/libretro/libretro.c
            "sega-saturn": [
                {"name": "stvbios.zip", "destination": "kronos/stvbios.zip", "required": True},
            ],
            # PCSX ReARMed / Beetle PSX alt BIOS — ref: pcsx_rearmed/libpcsxcore/misc.c
            # docs say PSXONPSP660.bin (uppercase) but core accepts any case
            "sony-playstation": [
                {"name": "psxonpsp660.bin", "destination": "psxonpsp660.bin", "required": False},
            ],
            # Dolphin GC — ref: DolphinLibretro/Boot.cpp:72-73,
            # BootManager.cpp:200-217, CommonPaths.h:139 GC_IPL="IPL.bin"
            # Core searches system/dolphin-emu/Sys/ for data and BIOS.
            # System.dat gc-ntsc-*.bin names are NOT what Dolphin loads.
            # We add the correct Dolphin paths for BIOS + essential firmware.
            "nintendo-gamecube": [
                {"name": "gc-ntsc-12.bin", "destination": "dolphin-emu/Sys/GC/USA/IPL.bin", "required": False},
                {"name": "gc-pal-12.bin", "destination": "dolphin-emu/Sys/GC/EUR/IPL.bin", "required": False},
                {"name": "gc-ntsc-12.bin", "destination": "dolphin-emu/Sys/GC/JAP/IPL.bin", "required": False},
                # DSP firmware — ref: Source/Core/Core/HW/DSPLLE/DSPHost.cpp
                {"name": "dsp_coef.bin", "destination": "dolphin-emu/Sys/GC/dsp_coef.bin", "required": True},
                {"name": "dsp_rom.bin", "destination": "dolphin-emu/Sys/GC/dsp_rom.bin", "required": True},
                # Fonts — ref: Source/Core/Core/HW/EXI/EXI_DeviceIPL.cpp
                {"name": "font_western.bin", "destination": "dolphin-emu/Sys/GC/font_western.bin", "required": False},
                {"name": "font_japanese.bin", "destination": "dolphin-emu/Sys/GC/font_japanese.bin", "required": False},
            ],
            # minivmac casing — ref: minivmac/src/MYOSGLUE.c
            # doc says MacII.rom, repo has MacII.ROM — both work on case-insensitive FS
            "apple-macintosh-ii": [
                {"name": "MacII.ROM", "destination": "MacII.ROM", "required": True},
            ],
        }
        for sys_id, extra_files in EXTRA_SYSTEM_FILES.items():
            if sys_id in systems:
                existing = {
                    (f["name"], f.get("destination", f["name"]))
                    for f in systems[sys_id].get("files", [])
                }
                for ef in extra_files:
                    key = (ef["name"], ef.get("destination", ef["name"]))
                    if key not in existing:
                        systems[sys_id]["files"].append(ef)
                        existing.add(key)

        # ep128emu shared group for Enterprise
        if "enterprise-64-128" in systems:
            systems["enterprise-64-128"].setdefault("includes", [])
            if "ep128emu" not in systems["enterprise-64-128"]["includes"]:
                systems["enterprise-64-128"]["includes"].append("ep128emu")

        # Inject shared group references for systems that have core-specific
        # subdirectory requirements already defined in _shared.yml.
        # Note: fuse/ prefix NOT injected for sinclair-zx-spectrum.
        # Verified in fuse-libretro/src/compat/paths.c — core searches
        # system/ flat, not fuse/ subfolder. Docs are wrong on this.
        SYSTEM_SHARED_GROUPS = {
            "nec-pc-98": ["np2kai"],
            "sharp-x68000": ["keropi"],
            "sega-saturn": ["kronos"],
        }
        for sys_id, groups in SYSTEM_SHARED_GROUPS.items():
            if sys_id in systems:
                systems[sys_id].setdefault("includes", []).extend(
                    g for g in groups if g not in systems[sys_id].get("includes", [])
                )

        # Data directories: full core data folders included in packs.
        # ref: each entry cites the core source code requiring the directory.
        SYSTEM_DATA_DIRS = {
            "nintendo-gamecube": [
                {"ref": "dolphin-sys", "destination": "dolphin-emu/Sys"},
            ],
            "sony-psp": [
                {"ref": "ppsspp-assets", "destination": "PPSSPP"},
            ],
            # single buildbot ZIP contains both Databases/ and Machines/
            # ref: libretro.c:1118-1119 — system_dir/Machines + system_dir/Databases
            "microsoft-msx": [
                {"ref": "bluemsx", "destination": ""},
            ],
            # FreeIntv overlays — system/freeintv_overlays/<rom>.png
            # ref: FreeIntv/src/libretro.c:273 — stbi_load from system dir
            # ZIP contains FreeIntvTS_Overlays/ subfolder, cache preserves it
            # pack destination maps cache root to system/freeintv_overlays
            # so final path is system/freeintv_overlays/FreeIntvTS_Overlays/<rom>.png
            # but core expects system/freeintv_overlays/<rom>.png
            # fix: point destination into the subfolder
            "mattel-intellivision": [
                {"ref": "freeintv-overlays", "destination": "freeintv_overlays"},
            ],
        }
        for sys_id, data_dirs in SYSTEM_DATA_DIRS.items():
            if sys_id in systems:
                systems[sys_id]["data_directories"] = data_dirs

        return {
            "platform": "RetroArch",
            "version": metadata["retroarch_version"] or "",
            "dat_version": metadata["dat_version"] or "",
            "homepage": "https://www.retroarch.com",
            "source": "https://github.com/libretro/libretro-database/blob/master/dat/System.dat",
            "base_destination": "system",
            "hash_type": "sha1",
            "verification_mode": "existence",
            "systems": systems,
        }


def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape libretro BIOS requirements")


if __name__ == "__main__":
    main()
