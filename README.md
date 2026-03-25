# RetroBIOS

Source-verified BIOS and firmware packs for retrogaming platforms.

Every file in this collection is traced to its ground truth: the emulator's source code.
Not .info files, not documentation, not community wikis - the actual code that loads the file.
305 emulators profiled from source, 8 platforms cross-referenced,
6,733 files verified.

### How it works

1. **Profile emulators from source code** - read the code, document every file loaded, its hash, size, and validation
2. **Cross-reference with platforms** - each platform (RetroArch, Batocera, Recalbox...) declares what it needs
3. **Build packs** - for each platform, include the baseline files + what its cores actually require
4. **Verify everything** - platform-native verification (MD5, existence) + emulator-level validation (CRC32, SHA256, size)

When a platform and an emulator disagree on a file, we detect it. When a better variant exists in the repo, we use it.

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

*Auto-generated on 2026-03-25T13:49:31Z*
