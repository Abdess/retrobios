<p align="center">
  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">
</p>

<p align="center">
  <a href="https://github.com/Abdess/retrobios/actions/workflows/build.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>
</p>

Complete BIOS and firmware packs for Batocera, BizHawk, EmuDeck, Lakka, MiSTer FPGA, ROCKNIX, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

**7,652** verified files across **396** systems, ready to extract into your emulator's BIOS directory.

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

| Platform | Size | Extract to | Download |
|----------|------|-----------|----------|
| Batocera | 2.7 GB | `/userdata/bios/` | [Download](../../releases/latest) |
| BizHawk | 2.4 GB | `Firmware/` | [Download](../../releases/latest) |
| EmuDeck | 1.6 GB | `~/Emulation/bios/` | [Download](../../releases/latest) |
| Lakka | 3.9 GB | `/storage/system/` | [Download](../../releases/latest) |
| MiSTer FPGA | 23 MB | `/media/fat/games/` | [Download](../../releases/latest) |
| ROCKNIX | 3.8 GB | `/storage/roms/bios/` | [Download](../../releases/latest) |
| Recalbox | 2.3 GB | `/recalbox/share/bios/` | [Download](../../releases/latest) |
| RetroArch | 3.9 GB | `system/` | [Download](../../releases/latest) |
| RetroBat | 3.1 GB | `bios/` | [Download](../../releases/latest) |
| RetroDECK | 4.6 GB | `~/retrodeck/` | [Download](../../releases/latest) |
| RetroPie * | - | `~/RetroPie/BIOS/` | [Download](../../releases/latest) |
| RomM | 1.4 GB | `bios/{platform_slug}/` | [Download](../../releases/latest) |

The RetroDECK pack already contains its own `bios/` folder, so it extracts into `~/retrodeck/` rather than into the BIOS folder.

\* Archived: the configuration is kept and packs are still built, but upstream is no longer scraped on a schedule.

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
Every file passes its platform's own verification; where an emulator profile exists, the expected hashes and sizes are read from the emulator's source code (the Source-backed column below).

- **12 platforms** supported with platform-specific verification
- **321 emulators** profiled from source (RetroArch cores + standalone)
- **396 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **7,652 files** indexed with SHA1, MD5, SHA256 and CRC32 checksums: 2,366 system files, 2,747 arcade ROM sets, 2,539 game and engine data files
- **527 files** matched to dump-preservation catalogs (No-Intro, Redump, TOSEC)
- **9832 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 362+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Files in pack | Still missing | Verified by |
|----------|--------------:|--------------:|-------------|
| Batocera | 1,601 | 0 | MD5 hash |
| BizHawk | 539 | 0 | SHA1 hash |
| EmuDeck | 525 | 0 | MD5 hash |
| Lakka | 1,631 | 0 | file presence |
| MiSTer FPGA | 65 | 0 | MD5 hash |
| ROCKNIX | 1,496 | 0 | MD5 hash |
| Recalbox | 1,184 | 0 | MD5 hash |
| RetroArch | 1,631 | 0 | file presence |
| RetroBat | 1,235 | 0 | MD5 hash |
| RetroDECK | 3,266 | 0 | MD5 hash |
| RetroPie * | 1,678 | 0 | file presence |
| RomM | 543 | 0 | MD5 hash |

A pack carries what the platform declares plus what its emulators load without the platform listing it, so it holds more files than the platform's own list.
Still missing counts files an emulator needs that are not in the collection yet; verified by is the check the platform itself runs on them.
The [gap analysis](https://abdess.github.io/retrobios/gaps/) page names those missing files and details how far each platform's files are corroborated against emulator source code.

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
- **Cross-reference** mapping files across 12 platforms and 321 emulators

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

*Auto-generated on 2026-08-08T04:18:10Z*
