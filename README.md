<p align="center">
  <img src=".github/assets/banner.png" alt="RetroBIOS" width="400">
</p>

<p align="center">
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

# Android (Termux, after pkg install python and termux-setup-storage)
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh

# Handheld (SD card mounted on PC)
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh -s -- --platform retroarch --dest /path/to/sdcard
```

The script auto-detects your platform, downloads only missing files, and verifies checksums.

## Download BIOS packs

One pack per platform, and it holds everything the platform runs: its own BIOS list plus every file its emulator cores load. Pick your platform, download the ZIP, extract to the BIOS path. The installer above does the same file by file, and `--target` narrows it to one machine; for a region or a bare minimum, build your own pack below.
The size is what the files occupy once extracted; the ZIP itself downloads smaller, and anything over 2 GB arrives split into `.zip.001`, `.zip.002` volumes. Open the `.001` with 7-Zip or PeaZip, or join them first (`cat Pack.zip.0* > Pack.zip`, or `copy /b Pack.zip.001+Pack.zip.002 Pack.zip` on Windows).

Every release ships `SHA256SUMS.txt` and a detached signature of it, checkable against `allowed_signers` in this repository: [verifying a release](https://abdess.github.io/retrobios/wiki/release-process/#verifying-a-release).

| Platform | Extracted size | Extract to | Download |
|----------|---------------:|-----------|----------|
| Batocera | 4.0 GB | `/userdata/bios/` | [Download](../../releases/latest) |
| BizHawk | 2.2 GB | `Firmware/` | [Download](../../releases/latest) |
| EmuDeck | 3.2 GB | `~/Emulation/bios/` | [Download](../../releases/latest) |
| Lakka | 5.5 GB | `/storage/system/` | [Download](../../releases/latest) |
| MiSTer FPGA | 24 MB | `/media/fat/games/` | [Download](../../releases/latest) |
| ROCKNIX | 5.3 GB | `/storage/roms/bios/` | [Download](../../releases/latest) |
| Recalbox | 3.6 GB | `/recalbox/share/bios/` | [Download](../../releases/latest) |
| RetroArch | 5.5 GB | `system/` | [Download](../../releases/latest) |
| RetroBat | 4.4 GB | `bios/` | [Download](../../releases/latest) |
| RetroDECK | 6.2 GB | `~/retrodeck/` | [Download](../../releases/latest) |
| RetroPie * | 5.5 GB | `~/RetroPie/BIOS/` | [Download](../../releases/latest) |
| RomM | 1.3 GB | `bios/{platform_slug}/` | [Download](../../releases/latest) |

The RetroDECK pack already contains its own `bios/` folder, so it extracts into `~/retrodeck/` rather than into the BIOS folder.

\* Archived: the configuration is kept and packs are still built, but upstream is no longer scraped on a schedule.

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
These are the files an emulator loads from disk instead of carrying inside itself. Some are required to boot a system, others improve accuracy or unlock a feature; the packs carry both.

Each file is checked the way your platform checks it. Most compare a checksum, the fingerprint of a file's contents, which catches a corrupt or unexpected copy. RetroArch, Lakka and RetroPie only look for the filename, because that is all their code does: the Coverage table says which applies to you. Independently of that, the collection records five fingerprints per file, and wherever an emulator's code states an expected size or hash, that value is read from its source and rechecked here.

- **6 files** the platforms' emulators load are still to be found, and 21 more cannot be sourced at all (per-user keys, user-filled slots, dumps nobody has made); both are named in the [gap analysis](https://abdess.github.io/retrobios/gaps/)
- **12 platforms** supported with platform-specific verification
- **449 emulators** profiled from source (RetroArch cores + standalone)
- **470 systems** handled by those emulators (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **10,330 files**, each with its SHA1, MD5, SHA256, CRC32 and Adler-32 fingerprints: 4,983 system files, 2,808 arcade ROM sets, 2,539 game and engine data files
- **553 of 4,983 system files** matched to dump-preservation catalogs (No-Intro, Redump, TOSEC); arcade sets and engine data fall outside what those catalogs index
- **12706 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 436+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | On its BIOS list | Files its emulators load | Checked by |
|----------|-----------------:|-------------------------:|------------|
| Batocera | 353/353 | 1,299/1,316 | MD5 hash |
| BizHawk | 118/118 | 370/375 | SHA1 hash |
| EmuDeck | 166/168 | 427/427 | MD5 hash |
| Lakka | 530/530 | 1,206/1,224 | file presence |
| MiSTer FPGA | 72/72 | - | MD5 hash |
| ROCKNIX | 38/38 | 1,636/1,654 | MD5 hash |
| Recalbox | 351/351 | 827/842 | MD5 hash |
| RetroArch | 530/530 | 1,206/1,224 | file presence |
| RetroBat | 343/343 | 938/953 | MD5 hash |
| RetroDECK | 2,008/2,008 | 1,250/1,269 | MD5 hash |
| RetroPie * | 530/530 | 1,529/1,554 | file presence |
| RomM | 381/381 | 284/293 | MD5 hash |

Each fraction is what the pack has over what is needed, counting required and optional files alike since both ship. The first column is the BIOS list the platform publishes. The second counts files its emulators load that this list never mentions, found by reading their source code, and it is routinely several times larger. A short fraction means files are still missing, and they are named in the [gap analysis](https://abdess.github.io/retrobios/gaps/).
That second number is a floor, not a ceiling: an emulator that accepts any file handed to it names none in its code, so nothing there can be counted.
Checked by is the test your platform runs on its own, replicated here from its source code, so the result matches what you would see in the frontend ([how each one works](https://abdess.github.io/retrobios/wiki/verification-modes/)).

## Build your own pack

Clone the repo and generate packs for any platform, emulator, or system:

```bash
# The pack of a platform, as released
python scripts/generate_pack.py --platform retroarch --output-dir dist/
python scripts/generate_pack.py --platform batocera --output-dir dist/

# Single emulator or system
python scripts/generate_pack.py --emulator dolphin
python scripts/generate_pack.py --system sony-playstation-2

# One region, best first, one file per system and region
python scripts/generate_pack.py --platform retroarch --region us,eu,jp
python scripts/generate_pack.py --platform retroarch --region us --one-per-slot

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
- **Cross-reference** mapping files across 12 platforms and 449 emulators
- **Versioned data access** through JSON, CSV and SQLite exports with published SHA-256 checksums

## How it works

Documentation and metadata can drift from what emulators actually load.
To keep packs accurate, platform lists are checked against emulator source code, file by file where a profile exists; when the two disagree, the code wins.

Hashes document what emulator code loads and accepts, not dump provenance; that boundary, and how it relates to preservation catalogs such as No-Intro, is drawn in the [FAQ](https://abdess.github.io/retrobios/wiki/faq/#are-these-files-verified-against-original-hardware-dumps).

1. **Read emulator source code** - trace every file the code loads, its expected hash and size
2. **Cross-reference with platforms** - match against what each platform declares
3. **Build packs** - include baseline files plus what each platform's cores need
4. **Verify** - run platform-native checks and emulator-level validation

## Contributors

<a href="https://github.com/PixNyb"><img src="https://avatars.githubusercontent.com/u/40770831?v=4" width="50" alt="PixNyb" title="PixNyb"></a>
<a href="https://github.com/Takiiiiiii"><img src="https://avatars.githubusercontent.com/u/40776277?v=4" width="50" alt="Takiiiiiii" title="Takiiiiiii"></a>
<a href="https://github.com/Takiiiiiiii"><img src="https://avatars.githubusercontent.com/u/43725718?v=4" width="50" alt="Takiiiiiiii" title="Takiiiiiiii"></a>
<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" alt="monster-penguin" title="monster-penguin"></a>
<a href="https://github.com/zjl88858"><img src="https://avatars.githubusercontent.com/u/29473998?v=4" width="50" alt="zjl88858" title="zjl88858"></a>


## Community tools

- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool) by [monster-penguin](https://github.com/monster-penguin) - scan, verify, and stage your own BIOS collection using RetroBIOS hash metadata

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

The scripts and tooling are released under the [MIT License](LICENSE).
The BIOS and firmware files are not covered by that license: they are third-party system software, preserved and provided for personal backup, archival, and interoperability with emulation software. [NOTICE](NOTICE) sets out their status and how to ask for a file to be removed.
The reasoning, and where it is weakest, is in the [FAQ](https://abdess.github.io/retrobios/wiki/faq/#is-this-legal).

*Auto-generated on 2026-09-05T11:57:09Z*
