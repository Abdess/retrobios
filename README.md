<p align="center">
  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">
</p>

Complete BIOS and firmware packs for Batocera, BizHawk, EmuDeck, Lakka, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

**7,350** verified files across **396** systems, ready to extract into your emulator's BIOS directory.

## Quick Install

Copy one command into your terminal:

```bash
# Linux / macOS / Steam Deck
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex

# Handheld (SD card mounted on PC)
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh -s -- --platform retroarch --dest /path/to/sdcard
```

The script auto-detects your platform, downloads only missing files, and verifies checksums.

## Download BIOS packs

Pick your platform, download the ZIP, extract to the BIOS path.

| Platform | BIOS files | Extract to | Download |
|----------|-----------|-----------|----------|
| Batocera | 353 | `/userdata/bios/` | [Download](../../releases/latest) |
| BizHawk | 118 | `Firmware/` | [Download](../../releases/latest) |
| EmuDeck | 161 | `Emulation/bios/` | [Download](../../releases/latest) |
| Lakka | 448 | `system/` | [Download](../../releases/latest) |
| Recalbox | 346 | `/recalbox/share/bios/` | [Download](../../releases/latest) |
| RetroArch | 448 | `system/` | [Download](../../releases/latest) |
| RetroBat | 339 | `bios/` | [Download](../../releases/latest) |
| RetroDECK | 2006 | `~/retrodeck/bios/` | [Download](../../releases/latest) |
| RetroPie | 448 | `BIOS/` | [Download](../../releases/latest) |
| RomM | 374 | `bios/{platform_slug}/` | [Download](../../releases/latest) |

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
Each file is checked against the emulator's source code to match what the code actually loads at runtime.

- **10 platforms** supported with platform-specific verification
- **329 emulators** profiled from source (RetroArch cores + standalone)
- **396 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **7,350 files** verified with MD5, SHA1, CRC32 checksums
- **8777 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 362+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Coverage | Verified | Untested | Missing |
|----------|----------|----------|----------|---------|
| Batocera | 352/353 (99.7%) | 351 | 1 | 1 |
| BizHawk | 118/118 (100.0%) | 118 | 0 | 0 |
| EmuDeck | 161/161 (100.0%) | 161 | 0 | 0 |
| Lakka | 448/448 (100.0%) | 448 | 0 | 0 |
| Recalbox | 346/346 (100.0%) | 346 | 0 | 0 |
| RetroArch | 448/448 (100.0%) | 448 | 0 | 0 |
| RetroBat | 339/339 (100.0%) | 339 | 0 | 0 |
| RetroDECK | 2006/2006 (100.0%) | 2006 | 0 | 0 |
| RetroPie | 448/448 (100.0%) | 448 | 0 | 0 |
| RomM | 374/374 (100.0%) | 374 | 0 | 0 |

## Build your own pack

Clone the repo and generate packs for any platform, emulator, or system:

```bash
# Full platform pack
python scripts/generate_pack.py --platform retroarch --output-dir dist/
python scripts/generate_pack.py --platform batocera --output-dir dist/

# Single emulator or system
python scripts/generate_pack.py --emulator dolphin
python scripts/generate_pack.py --system sony-playstation-2

# List available emulators and systems
python scripts/generate_pack.py --list-emulators
python scripts/generate_pack.py --list-systems

# Verify your BIOS collection
python scripts/verify.py --all
python scripts/verify.py --platform batocera
python scripts/verify.py --emulator flycast
python scripts/verify.py --platform retroarch --verbose  # emulator ground truth
```

Only dependency: Python 3 + `pyyaml`.

## Documentation site

The [documentation site](https://abdess.github.io/retrobios/) provides:

- **Per-platform pages** with file-by-file verification status and hashes
- **Per-emulator profiles** with source code references for every file
- **Per-system pages** showing which emulators and platforms cover each console
- **Gap analysis** identifying missing files and undeclared core requirements
- **Cross-reference** mapping files across 10 platforms and 329 emulators

## How it works

Documentation and metadata can drift from what emulators actually load.
To keep packs accurate, each file is checked against the emulator's source code.

1. **Read emulator source code** - trace every file the code loads, its expected hash and size
2. **Cross-reference with platforms** - match against what each platform declares
3. **Build packs** - include baseline files plus what each platform's cores need
4. **Verify** - run platform-native checks and emulator-level validation

## Contributors

<a href="https://github.com/PixNyb"><img src="https://avatars.githubusercontent.com/u/40770831?v=4" width="50" title="PixNyb"></a>
<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" title="monster-penguin"></a>


## Community tools

- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool) by [monster-penguin](https://github.com/monster-penguin) - scan, verify, and stage your own BIOS collection using RetroBIOS hash metadata

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This repository provides BIOS files for personal backup and archival purposes.

*Auto-generated on 2026-04-13T10:33:28Z*
