# RetroBIOS

Complete BIOS and firmware packs for RetroArch, Batocera, Recalbox, Lakka, RetroPie, EmuDeck, RetroBat, and RetroDECK.

**6,748** verified files across **294** systems, ready to extract into your emulator's BIOS directory.

## Download BIOS packs

Pick your platform, download the ZIP, extract to the BIOS path.

| Platform | BIOS files | Extract to | Download |
|----------|-----------|-----------|----------|
| Batocera | 359 | `/userdata/bios/` | [Download](../../releases/latest) |
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

- **9 platforms** supported with platform-specific verification
- **306 emulators** profiled from source (RetroArch cores + standalone)
- **294 systems** covered (NES, SNES, PlayStation, Saturn, Dreamcast, ...)
- **6,748 files** verified with MD5, SHA1, CRC32 checksums
- **5251 MB** total collection size

## Supported systems

NES, SNES, Nintendo 64, GameCube, Wii, Game Boy, Game Boy Advance, Nintendo DS, Nintendo 3DS, Switch, PlayStation, PlayStation 2, PlayStation 3, PSP, PS Vita, Mega Drive, Saturn, Dreamcast, Game Gear, Master System, Neo Geo, Atari 2600, Atari 7800, Atari Lynx, Atari ST, MSX, PC Engine, TurboGrafx-16, ColecoVision, Intellivision, Commodore 64, Amiga, ZX Spectrum, Arcade (MAME), and 260+ more.

Full list with per-file details: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Coverage

| Platform | Coverage | Verified | Untested | Missing |
|----------|----------|----------|----------|---------|
| Batocera | 359/359 (100.0%) | 358 | 1 | 0 |
| EmuDeck | 161/161 (100.0%) | 161 | 0 | 0 |
| Lakka | 448/448 (100.0%) | 448 | 0 | 0 |
| Recalbox | 346/346 (100.0%) | 346 | 0 | 0 |
| RetroArch | 448/448 (100.0%) | 448 | 0 | 0 |
| RetroBat | 331/331 (100.0%) | 331 | 0 | 0 |
| RetroDECK | 2007/2007 (100.0%) | 2007 | 0 | 0 |
| RetroPie | 448/448 (100.0%) | 448 | 0 | 0 |
| RomM | 374/374 (100.0%) | 359 | 15 | 0 |

## How it works

Documentation and metadata can drift from what emulators actually load.
To keep packs accurate, each file is checked against the emulator's source code.

1. **Read emulator source code** - trace every file the code loads, its expected hash and size
2. **Cross-reference with platforms** - match against what each platform declares
3. **Build packs** - include baseline files plus what each platform's cores need
4. **Verify** - run platform-native checks and emulator-level validation

## Documentation

Per-file hashes, emulator profiles, gap analysis, cross-reference: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Contributors

<a href="https://github.com/PixNyb"><img src="https://avatars.githubusercontent.com/u/40770831?v=4" width="50" title="PixNyb"></a>
<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" title="monster-penguin"></a>


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This repository provides BIOS files for personal backup and archival purposes.

*Auto-generated on 2026-03-25T22:12:06Z*
