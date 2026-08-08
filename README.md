<p align="center">
  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">
</p>

<p align="center">
  <a href="https://github.com/Abdess/retrobios/actions/workflows/build.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>
</p>

Complete BIOS and firmware packs for Batocera, BizHawk, EmuDeck, Lakka, MiSTer FPGA, ROCKNIX, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

**7,651** verified files across **396** systems, ready to extract into your emulator's BIOS directory.

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
| EmuDeck | 161 | `~/Emulation/bios/` | [Download](../../releases/latest) |
| Lakka | 530 | `/storage/system/` | [Download](../../releases/latest) |
| MiSTer FPGA | 65 | `/media/fat/games/` | [Download](../../releases/latest) |
| ROCKNIX | 38 | `/storage/roms/bios/` | [Download](../../releases/latest) |
| Recalbox | 346 | `/recalbox/share/bios/` | [Download](../../releases/latest) |
| RetroArch | 530 | `system/` | [Download](../../releases/latest) |
| RetroBat | 341 | `bios/` | [Download](../../releases/latest) |
| RetroDECK | 2008 | `~/retrodeck/` | [Download](../../releases/latest) |
| RetroPie * | 530 | `~/RetroPie/BIOS/` | [Download](../../releases/latest) |
| RomM | 374 | `bios/{platform_slug}/` | [Download](../../releases/latest) |

The RetroDECK pack already contains its own `bios/` folder, so it extracts into `~/retrodeck/` rather than into the BIOS folder.

\* Archived: the configuration is kept and packs are still built, but upstream is no longer scraped on a schedule.

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
Every file passes its platform's own verification; where an emulator profile exists, the expected hashes and sizes are read from the emulator's source code (the Source-backed column below).

- **12 platforms** supported with platform-specific verification
- **318 emulators** profiled from source (RetroArch cores + standalone)
- **396 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **7,651 files** indexed with SHA1, MD5, SHA256 and CRC32 checksums: 2,366 system files, 2,746 arcade ROM sets, 2,539 game and engine data files
- **527 files** matched to dump-preservation catalogs (No-Intro, Redump, TOSEC)
- **9832 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 362+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Coverage | Verified | Untested | Missing | Source-backed |
|----------|----------|----------|----------|---------|---------------|
| Batocera | 353/353 (100.0%) | 353 | 0 | 0 | 96/353 (27%) |
| BizHawk | 118/118 (100.0%) | 118 | 0 | 0 | 4/118 (3%) |
| EmuDeck | 161/161 (100.0%) | 161 | 0 | 0 | 16/161 (10%) |
| Lakka | 530/530 (100.0%) | 530 | 0 | 0 | 124/530 (23%) |
| MiSTer FPGA | 65/65 (100.0%) | 65 | 0 | 0 | - |
| ROCKNIX | 38/38 (100.0%) | 38 | 0 | 0 | 29/38 (76%) |
| Recalbox | 346/346 (100.0%) | 346 | 0 | 0 | 86/346 (25%) |
| RetroArch | 530/530 (100.0%) | 530 | 0 | 0 | 124/530 (23%) |
| RetroBat | 341/341 (100.0%) | 341 | 0 | 0 | 84/341 (25%) |
| RetroDECK | 2008/2008 (100.0%) | 2008 | 0 | 0 | 121/2008 (6%) |
| RetroPie * | 530/530 (100.0%) | 530 | 0 | 0 | 124/530 (23%) |
| RomM | 374/374 (100.0%) | 374 | 0 | 0 | 88/374 (24%) |

Coverage is measured against the file list each platform declares, using that platform's own verification mode.
Source-backed counts the files whose content the emulator's own code checks: a size or hash read from its source, reproduced at verification. A dash means no profiled emulator applies to the platform, whose own source is then the only authority.
The [gap analysis](https://abdess.github.io/retrobios/gaps/) page counts separately the files a profile documents without a content check, and tracks where platform lists and emulator source code disagree.

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
- **Cross-reference** mapping files across 12 platforms and 318 emulators

## How it works

Documentation and metadata can drift from what emulators actually load.
To keep packs accurate, platform lists are checked against emulator source code, file by file where a profile exists; when the two disagree, the code wins.

Hashes document what emulator code loads and accepts, not dump provenance; that boundary, and how it relates to preservation catalogs such as No-Intro, is drawn in the [FAQ](https://abdess.github.io/retrobios/wiki/faq/#are-these-files-verified-against-original-hardware-dumps).

1. **Read emulator source code** - trace every file the code loads, its expected hash and size
2. **Cross-reference with platforms** - match against what each platform declares
3. **Build packs** - include baseline files plus what each platform's cores need
4. **Verify** - run platform-native checks and emulator-level validation

## Contributors

<a href="https://github.com/PixNyb"><img src="https://avatars.githubusercontent.com/u/40770831?v=4" width="50" title="PixNyb"></a>
<a href="https://github.com/Takiiiiiii"><img src="https://avatars.githubusercontent.com/u/40776277?v=4" width="50" title="Takiiiiiii"></a>
<a href="https://github.com/Takiiiiiiii"><img src="https://avatars.githubusercontent.com/u/43725718?v=4" width="50" title="Takiiiiiiii"></a>
<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" title="monster-penguin"></a>
<a href="https://github.com/zjl88858"><img src="https://avatars.githubusercontent.com/u/29473998?v=4" width="50" title="zjl88858"></a>


## Community tools

- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool) by [monster-penguin](https://github.com/monster-penguin) - scan, verify, and stage your own BIOS collection using RetroBIOS hash metadata

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

The scripts and tooling are released under the [MIT License](LICENSE).
The BIOS and firmware files are not covered by that license: they are third-party system software, preserved and provided for personal backup, archival, and interoperability with emulation software.
The legal reasoning is laid out in the [FAQ](https://abdess.github.io/retrobios/wiki/faq/#is-this-legal).

*Auto-generated on 2026-08-08T02:07:01Z*
