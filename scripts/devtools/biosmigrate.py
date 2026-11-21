"""The move of a flat BIOS tree and of the legacy branches' files into bios/Manufacturer/Console/."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from acquire.fetch import LEGACY_BRANCHES, legacy_branch_blob, legacy_branch_files
from core.hashing import file_digest
from devtools.biosclassify import classify_file, get_subpath

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


def sha1_blob(data: bytes) -> str:
    """Compute SHA1 hash of raw bytes."""
    return hashlib.sha1(data).hexdigest()


def extract_from_branches(target: Path, dry_run: bool, existing_hashes: set[str]) -> int:
    """Extract BIOS files from all branches into the target structure."""
    extracted = 0

    for branch in LEGACY_BRANCHES:
        files = legacy_branch_files(branch)
        if files is None:
            print(f"  Branch {branch} not found, skipping")
            continue
        print(f"\n  Branch '{branch}': {len(files)} files")

        branch_extracted = 0
        for filepath in files:
            classification = classify_file(filepath)
            if classification is None:
                continue

            manufacturer, console = classification
            dest_dir = target / manufacturer / console
            dest = dest_dir / get_subpath(filepath)

            content = legacy_branch_blob(branch, filepath)
            if content is None:
                continue

            file_hash = sha1_blob(content)

            if file_hash in existing_hashes:
                continue

            label = "NEW"
            if dest.exists():
                if file_digest(dest) == file_hash:
                    existing_hashes.add(file_hash)
                    continue
                dest = dest_dir / ".variants" / f"{dest.name}.{file_hash[:8]}"
                if dest.exists():
                    continue
                label = "VARIANT"

            if not dry_run:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            print(f"    {label}: {filepath} -> {dest.relative_to(target)}")
            existing_hashes.add(file_hash)
            branch_extracted += 1

        print(f"    -> {branch_extracted} new files from {branch}")
        extracted += branch_extracted

    return extracted


def migrate_local(
    source: Path, target: Path, dry_run: bool,
) -> tuple[int, int, list[tuple[Path, str]], set[str]]:
    """Migrate files from local flat structure to Manufacturer/Console hierarchy."""
    moved = 0
    skipped = 0
    errors: list[tuple[Path, str]] = []
    existing_hashes: set[str] = set()

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

            existing_hashes.add(file_digest(f))
            moved += 1

    return moved, skipped, errors, existing_hashes


def unmapped_directories(source: Path) -> list[str]:
    """Folders of the source that no system maps and that are not the repository's own."""
    known = set(SYSTEM_MAP.keys()) | {
        "bios",
        "scripts",
        "platforms",
        "schemas",
        ".github",
        ".cache",
        ".git",
        "README.md",
        ".gitignore",
    }
    return [d.name for d in sorted(source.iterdir())
            if d.name not in known and not d.name.startswith(".") and d.is_dir()]
