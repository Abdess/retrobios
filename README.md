# RetroBIOS

Source-verified BIOS and firmware packs for retrogaming platforms.

Documentation and metadata can drift from what emulators actually load at runtime.
To keep packs accurate, each file here is checked against the emulator's source code:
what the code opens, what hashes it expects, what happens when a file is missing.
305 emulators profiled, 8 platforms cross-referenced,
6,733 files verified.

### How it works

1. **Read emulator source code** - identify every file the code loads, its expected hash and size
2. **Cross-reference with platforms** - match against what RetroArch, Batocera, Recalbox and others declare
3. **Build packs** - for each platform, include its baseline files plus what its cores need
4. **Verify** - run each platform's native checks (MD5, existence) and emulator-level validation (CRC32, size)

When a platform and an emulator disagree on a file, the discrepancy is reported.
When a variant in the repo satisfies both, it is preferred automatically.

> **6,733** files | **5043.6 MB** | **8** platforms | **305** emulator profiles

## Download

| Platform | Files | Verification | Pack |
|----------|-------|-------------|------|
| Batocera | 359 | md5 | [Download](../../releases/latest) |
| EmuDeck | 161 | md5 | [Download](../../releases/latest) |
| Lakka | 448 | existence | [Download](../../releases/latest) |
| Recalbox | 346 | md5 | [Download](../../releases/latest) |
| RetroArch | 448 | existence | [Download](../../releases/latest) |
| RetroBat | 331 | md5 | [Download](../../releases/latest) |
| RetroDECK | 2007 | md5 | [Download](../../releases/latest) |
| RetroPie | 448 | existence | [Download](../../releases/latest) |

## Coverage

| Platform | Coverage | Verified | Untested | Missing |
|----------|----------|----------|----------|---------|
| Batocera | 359/359 (100.0%) | 358 | 1 | 0 |
| EmuDeck | 161/161 (100.0%) | 161 | 0 | 0 |
| Lakka | 448/448 (100.0%) | 440 | 8 | 0 |
| Recalbox | 346/346 (100.0%) | 341 | 5 | 0 |
| RetroArch | 448/448 (100.0%) | 440 | 8 | 0 |
| RetroBat | 331/331 (100.0%) | 330 | 1 | 0 |
| RetroDECK | 2007/2007 (100.0%) | 2001 | 6 | 0 |
| RetroPie | 448/448 (100.0%) | 440 | 8 | 0 |

## Documentation

Full file listings, platform coverage, emulator profiles, and gap analysis: **[https://abdess.github.io/retrobios/](https://abdess.github.io/retrobios/)**

## Contributors

<a href="https://github.com/monster-penguin"><img src="https://avatars.githubusercontent.com/u/266009589?v=4" width="50" title="monster-penguin"></a>


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This repository provides BIOS files for personal backup and archival purposes.

*Auto-generated on 2026-03-25T14:43:03Z*
