<p align="center">
  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">
</p>

<p align="center">
  <a href="https://github.com/Abdess/retrobios/actions/workflows/build.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>
</p>

Complete BIOS and firmware packs for Batocera, BizHawk, EmuDeck, Lakka, MiSTer FPGA, ROCKNIX, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

Pick your platform below and extract the pack: it carries every file its emulators load, read from their source code. Nothing to configure, nothing to hunt down.

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
Every file passes the check its platform runs at startup: an MD5 or SHA1 comparison on most, file presence on RetroArch, Lakka and RetroPie, whose code checks nothing else. That is what the Verified by column reports, platform by platform. The collection itself carries SHA1, MD5, SHA256 and CRC32 for every file, and where an emulator profile exists the expected hashes and sizes come from that emulator's own source.

- **91 files** the platforms' emulators load are not in the collection yet, named in the [gap analysis](https://abdess.github.io/retrobios/gaps/)
- **12 platforms** supported with platform-specific verification
- **340 emulators** profiled from source (RetroArch cores + standalone)
- **412 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **7,763 files** indexed with SHA1, MD5, SHA256 and CRC32 checksums: 2,478 system files, 2,746 arcade ROM sets, 2,539 game and engine data files
- **531 of 2,478 system files** matched to dump-preservation catalogs (No-Intro, Redump, TOSEC); arcade sets and engine data fall outside what those catalogs index
- **9854 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 378+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Platform list | Read from emulator code | Verified by |
|----------|--------------:|------------------------:|-------------|
| Batocera | 353/353 | 1,146/1,237 | MD5 hash |
| BizHawk | 118/118 | 367/368 | SHA1 hash |
| EmuDeck | 161/161 | 404/404 | MD5 hash |
| Lakka | 530/530 | 1,149/1,154 | file presence |
| MiSTer FPGA | 65/65 | - | MD5 hash |
| ROCKNIX | 38/38 | 1,484/1,489 | MD5 hash |
| Recalbox | 346/346 | 717/722 | MD5 hash |
| RetroArch | 530/530 | 1,149/1,154 | file presence |
| RetroBat | 341/341 | 808/898 | MD5 hash |
| RetroDECK | 2,008/2,008 | 1,183/1,189 | MD5 hash |
| RetroPie * | 530/530 | 1,149/1,154 | file presence |
| RomM | 374/374 | 267/270 | MD5 hash |

Each fraction reads collected over needed, required and optional files alike, since both go in the pack. Platform list is the BIOS list the platform publishes. Read from emulator code counts the files the cores it ships load that the list never mentions, traced in their source: routinely several times the list itself, and it includes the files documented as impossible to source.
It is a floor, not a ceiling: a core that accepts any file handed to it declares nothing to count, so what such an emulator can load is not enumerable from its code.
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
- **Cross-reference** mapping files across 12 platforms and 340 emulators

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

*Auto-generated on 2026-08-08T10:50:34Z*
