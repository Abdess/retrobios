<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/banner-dark.svg">
    <img src=".github/assets/banner-light.svg" alt="RetroBIOS" width="400">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml"><img src="https://github.com/Abdess/retrobios/actions/workflows/deploy-site.yml/badge.svg" alt="Site"></a>
</p>

BIOS and firmware files for AmberELEC, Batocera, BizHawk, EmuDeck, EmuELEC, KNULLI, Lakka, MiSTer FPGA, MinUI, MyMinUI, NextUI, ROCKNIX, Recalbox, RetroArch, RetroBat, RetroDECK, RetroPie, and RomM.

A pack holds the files its emulators read, as their source code names them, and leaves out what the emulators install themselves.

## Quick install

Copy one command into your terminal:

```bash
# Linux / macOS / Steam Deck
curl -fsSL https://abdess.github.io/retrobios/i | sh

# Windows (PowerShell)
irm https://abdess.github.io/retrobios/i.ps1 | iex

# Android (Termux: it installs Python and asks for storage access)
curl -fsSL https://abdess.github.io/retrobios/i | sh

# SD card mounted on a PC: a muOS, KNULLI, ROCKNIX, Lakka, MiSTer, Onion, spruceOS or MinUI card
# is found by itself. For another card, --dest is its BIOS folder
# (RetroArch on Switch: retroarch/cores/system, on Android: RetroArch/system)
curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --platform retroarch --dest /path/to/sdcard/retroarch/cores/system

# Options in PowerShell: anything after | iex goes to iex, so the script runs as a block
&([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1))) --check
```

The script opens a full-screen installer, driven with the arrow keys and Enter, or with a controller on a handheld. It finds your setup and its BIOS folder, downloads only the missing files and checks each one. It can also copy the BIOS files from your old SD card.
Every option, and what the installer detects and writes, is on the [installer page](https://abdess.github.io/retrobios/wiki/installer/#passing-options).

First time? Follow the [first install, step by step](https://abdess.github.io/retrobios/wiki/first-install/). A game does not start: [what to check](https://abdess.github.io/retrobios/wiki/troubleshooting/). Other questions: the [FAQ](https://abdess.github.io/retrobios/wiki/faq/).

## Download BIOS packs

A pack holds its platform's own BIOS list plus the files its emulator cores load. What no pack carries yet is in the [gap analysis](https://abdess.github.io/retrobios/gaps/). Pick your platform, download the ZIP, extract to the BIOS path. Each Download link is a page that keeps its address from one release to the next. The installer above does the same file by file: its screen installs everything, or fewer under **Choose systems**, and `--system`, `--core`, `--region` and `--target` make the same choice without questions. For a bare minimum, build your own pack below.

A pack over 2 GB comes in several parts (`Pack.part1of2.zip`, `Pack.part2of2.zip`), and every part is needed. Each part is an ordinary ZIP: extract them all into the same folder.

Every release ships `SHA256SUMS.txt` and a detached signature of it, checkable against `allowed_signers` in this repository: [verifying a release](https://abdess.github.io/retrobios/wiki/release-process/#verifying-a-release).

The Files column counts what a pack holds once extracted, the figure a file manager shows for the folder. It differs from one platform to the next because a pack carries only what that platform's emulators load. The size is what the files occupy once extracted, and the ZIP itself downloads smaller.

| Platform | Files | Extracted size | Extract to | Download |
|----------|------:|---------------:|-----------|----------|
| AmberELEC | - | - | `/storage/roms/` | [Use the command](https://abdess.github.io/retrobios/get/amberelec/) |
| Batocera | 12,810 | 7.5 GB | `/userdata/bios/` | [Download](https://abdess.github.io/retrobios/get/batocera/) |
| BizHawk | - | - | `Firmware/` | [Use the command](https://abdess.github.io/retrobios/get/bizhawk/) |
| EmuDeck | 620 | 3.2 GB | `~/Emulation/bios/` | [Download](https://abdess.github.io/retrobios/get/emudeck/) |
| EmuELEC | - | - | `/storage/roms/` | [Use the command](https://abdess.github.io/retrobios/get/emuelec/) |
| KNULLI | - | - | `/userdata/bios/` | [Use the command](https://abdess.github.io/retrobios/get/knulli/) |
| Lakka | - | - | `/storage/system/` | [Use the command](https://abdess.github.io/retrobios/get/lakka/) |
| MiSTer FPGA | 83 | 29 MB | `/media/fat/games/` | [Download](https://abdess.github.io/retrobios/get/misterfpga/) |
| MinUI | - | - | `<SD card>/` | [Use the command](https://abdess.github.io/retrobios/get/minui/) |
| MyMinUI | - | - | `<SD card>/` | [Use the command](https://abdess.github.io/retrobios/get/myminui/) |
| NextUI | - | - | `<SD card>/` | [Use the command](https://abdess.github.io/retrobios/get/nextui/) |
| ROCKNIX | - | - | `/storage/roms/bios/` | [Use the command](https://abdess.github.io/retrobios/get/rocknix/) |
| Recalbox | - | - | `/recalbox/share/bios/` | [Use the command](https://abdess.github.io/retrobios/get/recalbox/) |
| RetroArch | 8,504 | 6.0 GB | `system/` | [Download](https://abdess.github.io/retrobios/get/retroarch/) |
| RetroBat | 12,399 | 7.9 GB | `bios/` | [Download](https://abdess.github.io/retrobios/get/retrobat/) |
| RetroDECK | - | - | `~/retrodeck/` | [Use the command](https://abdess.github.io/retrobios/get/retrodeck/) |
| RetroPie | - | - | `~/RetroPie/BIOS/` | [Use the command](https://abdess.github.io/retrobios/get/retropie/) |
| RomM | 1,087 | 1.5 GB | `library/bios/` | [Download](https://abdess.github.io/retrobios/get/romm/) |

ZIPs are made for the setups most people download. The others read "Use the command": the installer above installs every file for them and checks each one, and `--dry-run` shows what it would install ([why no ZIP](https://abdess.github.io/retrobios/wiki/faq/#why-is-there-no-zip-for-my-setup)).

## What's included

BIOS, firmware, and system files for consoles from Atari to PlayStation 3.
These are the files an emulator loads from disk instead of carrying inside itself. Some are required to boot a system, others improve accuracy or unlock a feature, and the packs carry both.

Each file is checked the way your platform checks it. Most compare a checksum, the fingerprint of a file's contents, which catches a corrupt or unexpected copy. RetroArch, Lakka and RetroPie check that the file is present under its name without reading its contents (`path_is_valid` in RetroArch's `core_info.c`), and MinUI, NextUI and MyMinUI hand each core its folder without opening a file in it: the Coverage table says which applies to you. Independently of that, the collection records five fingerprints per file, and wherever an emulator's code states an expected size or hash, that value is read from its source and rechecked here.

- **1,087 files** the platforms' emulators load are still to be found, and 138 more the collection does not hold and does not serve by name (retail data, per-user keys, user-filled slots), each with its reason. Both are named in the [gap analysis](https://abdess.github.io/retrobios/gaps/)
- **18 platforms** supported with platform-specific verification
- **623 emulators** profiled from source (RetroArch cores + standalone)
- **532 systems** handled by those emulators (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **19,947 files in the collection**, each with its SHA1, MD5, SHA256, CRC32 and Adler-32 fingerprints: 5,744 system files, 2,975 arcade ROM sets, 11,228 game and engine data files. That is every platform and emulator together, so no pack holds them all: each carries what its own emulators load, counted in the download table
- **566 of 5,744 system files** matched to dump-preservation catalogs (No-Intro, Redump, TOSEC). Arcade sets and engine data fall outside what those catalogs index
- **15.8 GB** for the whole collection

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 498+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | On its BIOS list | Files its emulators load | Checked by |
|----------|-----------------:|-------------------------:|------------|
| AmberELEC | 414/434 | 4,754/4,937 | MD5 |
| Batocera | 353/353 | 14,172/15,292 | MD5 |
| BizHawk | 118/118 | - | SHA-1 |
| EmuDeck | 168/168 | 8,427/8,529 | MD5 |
| EmuELEC | 543/572 | 4,788/10,217 | MD5 |
| KNULLI | 290/290 | 9,127/15,351 | MD5 |
| Lakka | 532/532 | 7,910/7,995 | name only |
| MiSTer FPGA | 81/81 | - | MD5 |
| MinUI | 0/0 | 78/79 | name only |
| MyMinUI | 0/0 | 356/367 | name only |
| NextUI | 0/0 | 343/350 | name only |
| ROCKNIX | 38/38 | 7,428/9,140 | MD5 |
| Recalbox | 351/351 | 3,125/3,344 | MD5 |
| RetroArch | 526/526 | 7,919/7,986 | name only |
| RetroBat | 348/348 | 5,135/9,659 | MD5 |
| RetroDECK | 2,007/2,008 | 6,706/6,993 | MD5 |
| RetroPie | 532/532 | 8,118/12,772 | name only |
| RomM | 383/383 | 83/875 | size, then any hash |

Each fraction is what the pack has over what is needed, counting required and optional files alike since both ship. The first column is the BIOS list the platform publishes. The second counts files its emulators load that this list never mentions, found by reading their source code, and it is routinely several times larger. A short fraction means files are still missing, and they are named in the [gap analysis](https://abdess.github.io/retrobios/gaps/).
That second number is a floor, not a ceiling: an emulator that accepts any file handed to it names none in its code, so nothing there can be counted.
Checked by is the test your platform runs on its own, replicated here from its source code, so the result matches what you would see in the frontend ([how each one works](https://abdess.github.io/retrobios/wiki/verification-modes/)).

## Build your own pack

Packs are built from a clone, and the clone carries the collection: its checkout alone is over 7.7 GB. `git clone --depth 1 https://github.com/Abdess/retrobios.git` leaves the history out. Files kept as release assets are downloaded when a pack needs them. Then generate packs for any platform, emulator, or system:

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

# Firmware only: the game data a list or a core names is left out, each file named
python scripts/generate_pack.py --platform emuelec --no-game-data

# The bare minimum: only the files each core needs to start
python scripts/generate_pack.py --platform batocera --required-only

# List available emulators and systems
python scripts/generate_pack.py --list-emulators
python scripts/generate_pack.py --list-systems

# Coverage of this repository's collection per platform, emulator or system
# (it reads database.json and bios/: for your own BIOS folder, run the installer with --check)
python scripts/verify.py --all
python scripts/verify.py --platform batocera
python scripts/verify.py --emulator flycast
python scripts/verify.py --platform retroarch --verbose  # emulator ground truth
```

Requires Python 3.9 or newer and `pyyaml`. The one-line installer alone runs on Python 3.8.

## Documentation site

The [documentation site](https://abdess.github.io/retrobios/) provides:

- **Per-platform pages** with file-by-file verification status and hashes
- **Per-emulator profiles** with source code references for every file
- **Per-system pages** showing which emulators and platforms cover each console
- **Gap analysis** identifying missing files and undeclared core requirements
- **Cross-reference** mapping files across 18 platforms and 623 emulators
- **Versioned data access** through JSON, CSV and SQLite exports with published SHA-256 checksums

## How it works

A platform's BIOS list and an emulator's code are maintained separately. Each list is compared with the emulator source code, file by file where a profile exists, and where the two differ the code decides.

Hashes document what emulator code loads and accepts, not dump provenance. That boundary, and how it relates to preservation catalogs such as No-Intro, is drawn in the [technical questions](https://abdess.github.io/retrobios/wiki/technical-faq/#are-these-files-verified-against-original-hardware-dumps).

1. **Read emulator source code**: trace every file the code loads, its expected hash and size
2. **Cross-reference with platforms**: match against what each platform declares
3. **Build packs**: include baseline files plus what each platform's cores need
4. **Verify**: run platform-native checks and emulator-level validation

## Contributors

<a href="https://github.com/habib256"><img src="https://avatars.githubusercontent.com/u/1260156?v=4" width="50" alt="habib256" title="habib256"></a>
<a href="https://github.com/PixNyb"><img src="https://avatars.githubusercontent.com/u/40770831?v=4" width="50" alt="PixNyb" title="PixNyb"></a>
<a href="https://github.com/Takiiiiiii"><img src="https://avatars.githubusercontent.com/u/40776277?v=4" width="50" alt="Takiiiiiii" title="Takiiiiiii"></a>
<a href="https://github.com/Takiiiiiiii"><img src="https://avatars.githubusercontent.com/u/43725718?v=4" width="50" alt="Takiiiiiiii" title="Takiiiiiiii"></a>
<a href="https://github.com/dajiaohuang"><img src="https://avatars.githubusercontent.com/u/108231307?v=4" width="50" alt="dajiaohuang" title="dajiaohuang"></a>
<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" alt="monster-penguin" title="monster-penguin"></a>
<a href="https://github.com/zjl88858"><img src="https://avatars.githubusercontent.com/u/29473998?v=4" width="50" alt="zjl88858" title="zjl88858"></a>


## Community tools

- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool) by [monster-penguin](https://github.com/monster-penguin) - scan, verify, and stage your own BIOS collection using RetroBIOS hash metadata

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

The scripts and tooling are released under the [MIT License](LICENSE).
The BIOS and firmware files are not covered by that license: they are third-party system software, preserved and provided for personal backup, archival, and interoperability with emulation software. [NOTICE](NOTICE) sets out their status and how to ask for a file to be removed.
The reasoning, and where it is weakest, is in [the project's legal position](https://abdess.github.io/retrobios/wiki/legal/).

*Auto-generated on 2026-11-06T10:21:06Z*
