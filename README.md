# RetroBIOS

Complete BIOS and firmware packs for Batocera, BizHawk, EmuDeck, Lakka, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

**7,245** verified files across **357** systems, ready to extract into your emulator's BIOS directory.

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
| Batocera | 359 | `/userdata/bios/` | [Download](../../releases/latest) |
| BizHawk | 118 | `Firmware/` | [Download](../../releases/latest) |
| EmuDeck | 161 | `Emulation/bios/` | [Download](../../releases/latest) |
| Lakka | 448 | `system/` | [Download](../../releases/latest) |
| Recalbox | 346 | `/recalbox/share/bios/` | [Download](../../releases/latest) |
| RetroArch | 448 | `system/` | [Download](../../releases/latest) |
| RetroBat | 331 | `bios/` | [Download](../../releases/latest) |
| RetroDECK | 2007 | `~/retrodeck/bios/` | [Download](../../releases/latest) |
| RetroPie | 448 | `BIOS/` | [Download](../../releases/latest) |
| RomM | 374 | `bios/{platform_slug}/` | [Download](../../releases/latest) |

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
Each file is checked against the emulator's source code to match what the code actually loads at runtime.

- **10 platforms** supported with platform-specific verification
- **328 emulators** profiled from source (RetroArch cores + standalone)
- **357 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **7,245 files** verified with MD5, SHA1, CRC32 checksums
- **9266 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 323+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Coverage | Verified | Untested | Missing |
|----------|----------|----------|----------|---------|
| Batocera | 359/359 (100.0%) | 354 | 5 | 0 |
| BizHawk | 118/118 (100.0%) | 118 | 0 | 0 |
| EmuDeck | 161/161 (100.0%) | 161 | 0 | 0 |
| Lakka | 443/448 (98.9%) | 443 | 0 | 5 |
| Recalbox | 276/346 (79.8%) | 273 | 3 | 70 |
| RetroArch | 443/448 (98.9%) | 443 | 0 | 5 |
| RetroBat | 330/331 (99.7%) | 326 | 4 | 1 |
| RetroDECK | 1958/2007 (97.6%) | 1932 | 26 | 49 |
| RetroPie | 443/448 (98.9%) | 443 | 0 | 5 |
| RomM | 372/374 (99.5%) | 372 | 0 | 2 |

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
- **Cross-reference** mapping files across 10 platforms and 328 emulators

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


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This repository provides BIOS files for personal backup and archival purposes.

*Auto-generated on 2026-03-29T14:15:30Z*
