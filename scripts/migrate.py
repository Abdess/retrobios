#!/usr/bin/env python3
"""Migrate current flat structure AND other branches to bios/Manufacturer/Console/ hierarchy.

Usage:
    python scripts/migrate.py [--dry-run] [--source DIR] [--target DIR] [--include-branches]

Reads existing directories like "Sony - PlayStation" and moves files to
"bios/Sony/PlayStation/". With --include-branches, also extracts unique BIOS files
from all remote branches (RetroArch, RetroPie, Recalbox, batocera, Other).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from common import compute_hashes

SYSTEM_MAP = {
    "3DO Company, The - 3DO": ("3DO Company", "3DO"),
    "Arcade": ("Arcade", "Arcade"),
    "Atari - 400-800": ("Atari", "400-800"),
    "Atari - 5200": ("Atari", "5200"),
    "Atari - 7800": ("Atari", "7800"),
    "Atari - Lynx": ("Atari", "Lynx"),
    "Atari - ST": ("Atari", "ST"),
    "Coleco - ColecoVision": ("Coleco", "ColecoVision"),
    "Commodore - Amiga": ("Commodore", "Amiga"),
    "Fairchild Channel F": ("Fairchild", "Channel F"),
    "Id Software - Doom": ("Id Software", "Doom"),
    "J2ME": ("Java", "J2ME"),
    "MacII": ("Apple", "Macintosh II"),
    "Magnavox - Odyssey2": ("Magnavox", "Odyssey2"),
    "Mattel - Intellivision": ("Mattel", "Intellivision"),
    "Microsoft - MSX": ("Microsoft", "MSX"),
    "NEC - PC Engine - TurboGrafx 16 - SuperGrafx": ("NEC", "PC Engine"),
    "NEC - PC-98": ("NEC", "PC-98"),
    "NEC - PC-FX": ("NEC", "PC-FX"),
    "Nintendo - Famicom Disk System": ("Nintendo", "Famicom Disk System"),
    "Nintendo - Game Boy Advance": ("Nintendo", "Game Boy Advance"),
    "Nintendo - GameCube": ("Nintendo", "GameCube"),
    "Nintendo - Gameboy": ("Nintendo", "Game Boy"),
    "Nintendo - Gameboy Color": ("Nintendo", "Game Boy Color"),
    "Nintendo - Nintendo 64DD": ("Nintendo", "Nintendo 64DD"),
    "Nintendo - Nintendo DS": ("Nintendo", "Nintendo DS"),
    "Nintendo - Nintendo Entertainment System": ("Nintendo", "NES"),
    "Nintendo - Pokemon Mini": ("Nintendo", "Pokemon Mini"),
    "Nintendo - Satellaview": ("Nintendo", "Satellaview"),
    "Nintendo - SuFami Turbo": ("Nintendo", "SuFami Turbo"),
    "Nintendo - Super Game Boy": ("Nintendo", "Super Game Boy"),
    "Nintendo - Super Nintendo Entertainment System": ("Nintendo", "SNES"),
    "Phillips - Videopac+": ("Philips", "Videopac+"),
    "SNK - NeoGeo CD": ("SNK", "Neo Geo CD"),
    "ScummVM": ("ScummVM", "ScummVM"),
    "Sega - Dreamcast": ("Sega", "Dreamcast"),
    "Sega - Game Gear": ("Sega", "Game Gear"),
    "Sega - Master System - Mark III": ("Sega", "Master System"),
    "Sega - Mega CD - Sega CD": ("Sega", "Mega CD"),
    "Sega - Mega Drive - Genesis": ("Sega", "Mega Drive"),
    "Sega - Saturn": ("Sega", "Saturn"),
    "Sharp - X1": ("Sharp", "X1"),
    "Sharp - X68000": ("Sharp", "X68000"),
    "Sinclair - ZX Spectrum": ("Sinclair", "ZX Spectrum"),
    "Sony - PlayStation": ("Sony", "PlayStation"),
    "Sony - PlayStation Portable": ("Sony", "PlayStation Portable"),
    "Wolfenstein 3D": ("Id Software", "Wolfenstein 3D"),
}

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
    "MT32_CONTROL.ROM": ("ScummVM", "ScummVM"),
    "MT32_PCM.ROM": ("ScummVM", "ScummVM"),
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
    "oricutron/": ("Oric", "Oric"),
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

BRANCHES = ["RetroArch", "RetroPie", "Recalbox", "batocera", "Other"]

SKIP_FILES = {
    "README.md", ".gitignore", "desktop.ini",
    "telemetry_id", "citra_log.txt",
}
SKIP_EXTENSIONS = {".txt", ".log", ".pem", ".nvm", ".ctg", ".exe", ".bat", ".sh"}


def sha1_blob(data: bytes) -> str:
    """Compute SHA1 hash of raw bytes."""
    return hashlib.sha1(data).hexdigest()


def classify_file(filepath: str) -> tuple:
    """Determine (Manufacturer, Console) for a file path from a branch.

    Returns None if the file should be skipped.
    """
    name = os.path.basename(filepath)

    if name in SKIP_FILES:
        return None
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return None

    clean = filepath
    for prefix in ("bios/", "BIOS/", "roms/fba/", "roms/fbneo/", "roms/mame/",
                   "roms/mame-libretro/", "roms/neogeo/", "roms/naomi/",
                   "roms/atomiswave/", "roms/macintosh/"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
            break

    if filepath.startswith("roms/") and not any(
        filepath.startswith(p) for p in (
            "roms/fba/", "roms/fbneo/", "roms/mame/", "roms/mame-libretro/",
            "roms/neogeo/", "roms/naomi/", "roms/atomiswave/", "roms/macintosh/"
        )
    ):
        return None

    for prefix, target in PATH_PREFIX_MAP.items():
        if clean.startswith(prefix):
            return target

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

    if "saves/" in filepath:
        return None

    if name.endswith(".chd"):
        return None

    if name.endswith((".img", ".lst", ".dat")) and "saves/" in filepath:
        return None

    return None


def get_subpath(filepath: str, manufacturer: str, console: str) -> str:
    """Get the sub-path within the console directory (for nested files like neocd/*)."""
    name = os.path.basename(filepath)

    clean = filepath
    for prefix in ("bios/", "BIOS/"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
            break

    for prefix in PATH_PREFIX_MAP:
        if clean.startswith(prefix):
            remaining = clean[len(prefix):]
            if "/" in remaining:
                return remaining
            return remaining

    return name


def extract_from_branches(target: Path, dry_run: bool, existing_hashes: set) -> int:
    """Extract BIOS files from all branches into the target structure."""
    extracted = 0

    for branch in BRANCHES:
        ref = f"origin/{branch}"

        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                capture_output=True, check=True
            )
        except subprocess.CalledProcessError:
            print(f"  Branch {branch} not found, skipping")
            continue

        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", ref],
            capture_output=True, text=True
        )
        files = result.stdout.strip().split("\n")
        print(f"\n  Branch '{branch}': {len(files)} files")

        branch_extracted = 0
        for filepath in files:
            classification = classify_file(filepath)
            if classification is None:
                continue

            manufacturer, console = classification
            subpath = get_subpath(filepath, manufacturer, console)
            dest_dir = target / manufacturer / console
            dest = dest_dir / subpath

            try:
                blob = subprocess.run(
                    ["git", "show", f"{ref}:{filepath}"],
                    capture_output=True, check=True
                )
                content = blob.stdout
            except subprocess.CalledProcessError:
                continue

            file_hash = sha1_blob(content)

            if file_hash in existing_hashes:
                continue

            if dest.exists():
                existing_hash = compute_hashes(dest)["sha1"]
                if existing_hash == file_hash:
                    existing_hashes.add(file_hash)
                    continue
                variant_dir = dest_dir / ".variants"
                variant_name = f"{dest.name}.{file_hash[:8]}"
                dest = variant_dir / variant_name

                if dest.exists():
                    continue

                if dry_run:
                    print(f"    VARIANT: {filepath} -> {dest.relative_to(target)}")
                else:
                    variant_dir.mkdir(parents=True, exist_ok=True)
                    with open(dest, "wb") as f:
                        f.write(content)
                    print(f"    VARIANT: {filepath} -> {dest.relative_to(target)}")
                existing_hashes.add(file_hash)
                branch_extracted += 1
                continue

            if dry_run:
                print(f"    NEW: {filepath} -> {dest.relative_to(target)}")
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(content)
                print(f"    NEW: {filepath} -> {dest.relative_to(target)}")

            existing_hashes.add(file_hash)
            branch_extracted += 1

        print(f"    -> {branch_extracted} new files from {branch}")
        extracted += branch_extracted

    return extracted


def migrate_local(source: Path, target: Path, dry_run: bool) -> tuple:
    """Migrate files from local flat structure to Manufacturer/Console hierarchy."""
    moved = 0
    skipped = 0
    errors = []
    existing_hashes = set()

    for old_dir_name, (manufacturer, console) in sorted(SYSTEM_MAP.items()):
        old_path = source / old_dir_name
        if not old_path.is_dir():
            continue

        new_path = target / manufacturer / console
        files = [f for f in old_path.iterdir() if f.is_file()]

        if not files:
            continue

        print(f"  {old_dir_name}/ -> bios/{manufacturer}/{console}/")

        if not dry_run:
            new_path.mkdir(parents=True, exist_ok=True)

        for f in files:
            dest = new_path / f.name
            if dest.exists():
                print(f"    SKIP (exists): {f.name}")
                skipped += 1
                continue

            if dry_run:
                print(f"    COPY: {f.name}")
            else:
                try:
                    shutil.copy2(str(f), str(dest))
                except OSError as e:
                    errors.append((f, str(e)))
                    print(f"    ERROR: {f.name}: {e}")
                    continue

            file_hash = compute_hashes(f)["sha1"]
            existing_hashes.add(file_hash)
            moved += 1

    return moved, skipped, errors, existing_hashes


def main():
    parser = argparse.ArgumentParser(
        description="Migrate BIOS files to Manufacturer/Console structure"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without moving files")
    parser.add_argument("--source", default=".",
                        help="Source directory (repo root)")
    parser.add_argument("--target", default="bios",
                        help="Target directory for organized BIOS files")
    parser.add_argument("--include-branches", action="store_true",
                        help="Also extract BIOS files from all remote branches")
    args = parser.parse_args()

    source = Path(args.source)
    target = Path(args.target)

    if not source.is_dir():
        print(f"Error: Source directory '{source}' not found", file=sys.stderr)
        sys.exit(1)

    print(f"Migrating from {source}/ to {target}/Manufacturer/Console/")
    if args.dry_run:
        print("(DRY RUN - no files will be moved)\n")
    else:
        print()

    print("=== Phase 1: Local files (libretro branch) ===")
    moved, skipped, errors, existing_hashes = migrate_local(source, target, args.dry_run)
    action = "Would copy" if args.dry_run else "Copied"
    print(f"\n{action} {moved} files, skipped {skipped}")

    if args.include_branches:
        print("\n=== Phase 2: Extracting from other branches ===")
        branch_count = extract_from_branches(target, args.dry_run, existing_hashes)
        print(f"\n{action} {branch_count} additional files from branches")
        moved += branch_count

    if source.is_dir():
        known = set(SYSTEM_MAP.keys()) | {
            "bios", "scripts", "platforms", "schemas", ".github", ".cache",
            ".git", "README.md", ".gitignore",
        }
        for d in sorted(source.iterdir()):
            if d.name not in known and not d.name.startswith("."):
                if d.is_dir():
                    print(f"\nWARNING: Unmapped directory: {d.name}")

    print(f"\nTotal: {moved} files migrated, {len(existing_hashes)} unique hashes")

    if errors:
        print(f"Errors: {len(errors)}")
        for f, e in errors:
            print(f"  {f}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
