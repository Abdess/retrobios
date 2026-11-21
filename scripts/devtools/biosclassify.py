"""The Manufacturer/Console folder a legacy BIOS path belongs to, read from its name and folder."""

from __future__ import annotations

import os

BIOS_FILE_MAP = {
    "panafz": ("3DO Company", "3DO"),
    "goldstar.bin": ("3DO Company", "3DO"),
    "sanyotry.bin": ("3DO Company", "3DO"),
    "3do_arcade_saot.bin": ("3DO Company", "3DO"),
    "3dobios.zip": ("3DO Company", "3DO"),
    "cpc464.rom": ("Amstrad", "CPC"),
    "cpc664.rom": ("Amstrad", "CPC"),
    "cpc6128.rom": ("Amstrad", "CPC"),
    "neogeo.zip": ("SNK", "Neo Geo"),
    "pgm.zip": ("Arcade", "Arcade"),
    "skns.zip": ("Arcade", "Arcade"),
    "bubsys.zip": ("Arcade", "Arcade"),
    "cchip.zip": ("Arcade", "Arcade"),
    "decocass.zip": ("Arcade", "Arcade"),
    "isgsm.zip": ("Arcade", "Arcade"),
    "midssio.zip": ("Arcade", "Arcade"),
    "nmk004.zip": ("Arcade", "Arcade"),
    "ym2608.zip": ("Arcade", "Arcade"),
    "qsound.zip": ("Arcade", "Arcade"),
    "ATARIBAS.ROM": ("Atari", "400-800"),
    "ATARIOSA.ROM": ("Atari", "400-800"),
    "ATARIOSB.ROM": ("Atari", "400-800"),
    "ATARIXL.ROM": ("Atari", "400-800"),
    "BB01R4_OS.ROM": ("Atari", "400-800"),
    "XEGAME.ROM": ("Atari", "400-800"),
    "5200.rom": ("Atari", "5200"),
    "7800 BIOS (U).rom": ("Atari", "7800"),
    "7800 BIOS (E).rom": ("Atari", "7800"),
    "lynxboot.img": ("Atari", "Lynx"),
    "tos.img": ("Atari", "ST"),
    "colecovision.rom": ("Coleco", "ColecoVision"),
    "coleco.rom": ("Coleco", "ColecoVision"),
    "kick33180.A500": ("Commodore", "Amiga"),
    "kick34005.A500": ("Commodore", "Amiga"),
    "kick34005.CDTV": ("Commodore", "Amiga"),
    "kick37175.A500": ("Commodore", "Amiga"),
    "kick37350.A600": ("Commodore", "Amiga"),
    "kick39106.A1200": ("Commodore", "Amiga"),
    "kick39106.A4000": ("Commodore", "Amiga"),
    "kick40060.CD32": ("Commodore", "Amiga"),
    "kick40060.CD32.ext": ("Commodore", "Amiga"),
    "kick40063.A600": ("Commodore", "Amiga"),
    "kick40068.A1200": ("Commodore", "Amiga"),
    "kick40068.A4000": ("Commodore", "Amiga"),
    "sl31253.bin": ("Fairchild", "Channel F"),
    "sl31254.bin": ("Fairchild", "Channel F"),
    "sl90025.bin": ("Fairchild", "Channel F"),
    "prboom.wad": ("Id Software", "Doom"),
    "ecwolf.pk3": ("Id Software", "Wolfenstein 3D"),
    "MacII.ROM": ("Apple", "Macintosh II"),
    "MacIIx.ROM": ("Apple", "Macintosh II"),
    "vMac.ROM": ("Apple", "Macintosh II"),
    "o2rom.bin": ("Magnavox", "Odyssey2"),
    "g7400.bin": ("Philips", "Videopac+"),
    "jopac.bin": ("Philips", "Videopac+"),
    "exec.bin": ("Mattel", "Intellivision"),
    "grom.bin": ("Mattel", "Intellivision"),
    "ECS.bin": ("Mattel", "Intellivision"),
    "IVOICE.BIN": ("Mattel", "Intellivision"),
    "MSX.ROM": ("Microsoft", "MSX"),
    "MSX2.ROM": ("Microsoft", "MSX"),
    "MSX2EXT.ROM": ("Microsoft", "MSX"),
    "MSX2P.ROM": ("Microsoft", "MSX"),
    "MSX2PEXT.ROM": ("Microsoft", "MSX"),
    "syscard1.pce": ("NEC", "PC Engine"),
    "syscard2.pce": ("NEC", "PC Engine"),
    "syscard2u.pce": ("NEC", "PC Engine"),
    "syscard3.pce": ("NEC", "PC Engine"),
    "syscard3u.pce": ("NEC", "PC Engine"),
    "gexpress.pce": ("NEC", "PC Engine"),
    "pcfx.rom": ("NEC", "PC-FX"),
    "disksys.rom": ("Nintendo", "Famicom Disk System"),
    "gba_bios.bin": ("Nintendo", "Game Boy Advance"),
    "gb_bios.bin": ("Nintendo", "Game Boy"),
    "dmg_boot.bin": ("Nintendo", "Game Boy"),
    "gbc_bios.bin": ("Nintendo", "Game Boy Color"),
    "BS-X.bin": ("Nintendo", "Satellaview"),
    "sgb_bios.bin": ("Nintendo", "Super Game Boy"),
    "sgb_boot.bin": ("Nintendo", "Super Game Boy"),
    "sgb2_boot.bin": ("Nintendo", "Super Game Boy"),
    "SGB1.sfc": ("Nintendo", "Super Game Boy"),
    "SGB2.sfc": ("Nintendo", "Super Game Boy"),
    "bios7.bin": ("Nintendo", "Nintendo DS"),
    "bios9.bin": ("Nintendo", "Nintendo DS"),
    "firmware.bin": ("Nintendo", "Nintendo DS"),
    "biosnds7.bin": ("Nintendo", "Nintendo DS"),
    "biosnds9.bin": ("Nintendo", "Nintendo DS"),
    "dsfirmware.bin": ("Nintendo", "Nintendo DS"),
    "biosdsi7.bin": ("Nintendo", "Nintendo DS"),
    "biosdsi9.bin": ("Nintendo", "Nintendo DS"),
    "dsifirmware.bin": ("Nintendo", "Nintendo DS"),
    "bios.min": ("Nintendo", "Pokemon Mini"),
    "64DD_IPL.bin": ("Nintendo", "Nintendo 64DD"),
    "dc_boot.bin": ("Sega", "Dreamcast"),
    "dc_flash.bin": ("Sega", "Dreamcast"),
    "bios.gg": ("Sega", "Game Gear"),
    "bios_E.sms": ("Sega", "Master System"),
    "bios_J.sms": ("Sega", "Master System"),
    "bios_U.sms": ("Sega", "Master System"),
    "bios_CD_E.bin": ("Sega", "Mega CD"),
    "bios_CD_J.bin": ("Sega", "Mega CD"),
    "bios_CD_U.bin": ("Sega", "Mega CD"),
    "bios_MD.bin": ("Sega", "Mega Drive"),
    "mpr-17933.bin": ("Sega", "Saturn"),
    "mpr-18811-mx.ic1": ("Sega", "Saturn"),
    "mpr-19367-mx.ic1": ("Sega", "Saturn"),
    "saturn_bios.bin": ("Sega", "Saturn"),
    "sega_101.bin": ("Sega", "Saturn"),
    "stvbios.zip": ("Sega", "Saturn"),
    "scph1001.bin": ("Sony", "PlayStation"),
    "SCPH1001.BIN": ("Sony", "PlayStation"),
    "scph5500.bin": ("Sony", "PlayStation"),
    "scph5501.bin": ("Sony", "PlayStation"),
    "scph5502.bin": ("Sony", "PlayStation"),
    "scph7001.bin": ("Sony", "PlayStation"),
    "scph101.bin": ("Sony", "PlayStation"),
    "ps1_rom.bin": ("Sony", "PlayStation"),
    "psxonpsp660.bin": ("Sony", "PlayStation"),
    "PSXONPSP660.BIN": ("Sony", "PlayStation Portable"),
    "scummvm.zip": ("ScummVM", "ScummVM"),
    "MT32_CONTROL.ROM": ("Roland", "MT-32"),
    "MT32_PCM.ROM": ("Roland", "MT-32"),
}

PATH_PREFIX_MAP = {
    "neocd/": ("SNK", "Neo Geo CD"),
    "dc/": ("Sega", "Dreamcast"),
    "np2kai/": ("NEC", "PC-98"),
    "quasi88/": ("NEC", "PC-98"),
    "keropi/": ("Sharp", "X68000"),
    "xmil/": ("Sharp", "X1"),
    "fuse/": ("Sinclair", "ZX Spectrum"),
    "vice/": ("Commodore", "C128"),
    "bk/": ("Elektronika", "BK"),
    "dragon/": ("Dragon", "Dragon"),
    "oricutron/": ("Tangerine", "Oric"),
    "trs80coco/": ("Tandy", "CoCo"),
    "ti994a/": ("Texas Instruments", "TI-99"),
    "gamecube/": ("Nintendo", "GameCube"),
    "Mupen64plus/": ("Nintendo", "Nintendo 64DD"),
    "ps2/": ("Sony", "PlayStation 2"),
    "fmtowns/": ("Fujitsu", "FM Towns"),
    "mame/": ("Arcade", "MAME"),
    "fbneo/": ("Arcade", "Arcade"),
    "saves/3ds/": ("Nintendo", "3DS"),
    "saves/citra-emu/": ("Nintendo", "3DS"),
    "saves/dolphin-emu/": ("Nintendo", "Wii"),
    "saves/xbox/": ("Microsoft", "Xbox"),
    "cemu/": ("Nintendo", "Wii U"),
    "wsh57/": ("Other", "Misc"),
    "Machines/COL - ColecoVision/": ("Coleco", "ColecoVision"),
    "Machines/Shared Roms/": ("Microsoft", "MSX"),
    "Sony - PlayStation 2/": ("Sony", "PlayStation 2"),
    "Sony - PlayStation/": ("Sony", "PlayStation"),
}

TOS_PATTERN_MAP = {
    "tos": ("Atari", "ST"),
}

SKIP_LARGE_ROM_DIRS = {"roms/"}

SKIP_FILES = {
    "README.md",
    ".gitignore",
    "desktop.ini",
    "telemetry_id",
    "citra_log.txt",
}
SKIP_EXTENSIONS = {".txt", ".log", ".pem", ".nvm", ".ctg", ".exe", ".bat", ".sh"}


ARCADE_ROM_PREFIXES = (
    "roms/fba/",
    "roms/fbneo/",
    "roms/mame/",
    "roms/mame-libretro/",
    "roms/neogeo/",
    "roms/naomi/",
    "roms/atomiswave/",
    "roms/macintosh/",
)


def _strip_branch_prefix(filepath: str) -> str | None:
    """The path below its bios/ or arcade roms/ folder, None for any other
    roms/ path."""
    if filepath.startswith("roms/") and not filepath.startswith(ARCADE_ROM_PREFIXES):
        return None
    for prefix in ("bios/", "BIOS/", *ARCADE_ROM_PREFIXES):
        if filepath.startswith(prefix):
            return filepath[len(prefix) :]
    return filepath


def _classify_by_name(name: str, filepath: str) -> tuple[str, str] | None:
    if name in BIOS_FILE_MAP:
        return BIOS_FILE_MAP[name]

    for prefix, target in BIOS_FILE_MAP.items():
        if name.lower().startswith(prefix.lower()) and len(prefix) > 3:
            return target

    if name.startswith("tos") and name.endswith(".img"):
        return ("Atari", "ST")

    if name.startswith("kick") and (name.endswith(".rom") or "." in name):
        return ("Commodore", "Amiga")

    if name.startswith("amiga-"):
        return ("Commodore", "Amiga")

    if name.upper().startswith("SCPH"):
        if "70004" in name or "39001" in name or "30004" in name or "10000" in name:
            return ("Sony", "PlayStation 2")
        return ("Sony", "PlayStation")

    if name.endswith(".zip") and filepath.startswith(("roms/", "BIOS/")):
        return ("Arcade", "Arcade")
    return None


def classify_file(filepath: str) -> tuple[str, str] | None:
    """Determine (Manufacturer, Console) for a file path from a branch.

    Returns None if the file should be skipped.
    """
    name = os.path.basename(filepath)

    if name in SKIP_FILES:
        return None
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return None

    clean = _strip_branch_prefix(filepath)
    if clean is None:
        return None

    for prefix, target in PATH_PREFIX_MAP.items():
        if clean.startswith(prefix):
            return target

    return _classify_by_name(name, filepath)


def get_subpath(filepath: str, manufacturer: str, console: str) -> str:
    """Get the sub-path within the console directory (for nested files like neocd/*)."""
    name = os.path.basename(filepath)

    clean = filepath
    for prefix in ("bios/", "BIOS/"):
        if clean.startswith(prefix):
            clean = clean[len(prefix) :]
            break

    for prefix in PATH_PREFIX_MAP:
        if clean.startswith(prefix):
            remaining = clean[len(prefix) :]
            if "/" in remaining:
                return remaining
            return remaining

    return name
