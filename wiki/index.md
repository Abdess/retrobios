# Wiki - RetroBIOS

Technical documentation for the RetroBIOS toolchain.

Pages are grouped by what you came to do. **For users** walks through
installing and checking files. **Technical reference** describes how the
toolchain behaves, one subject per page. **For contributors** is task-oriented:
each page takes one job from start to finish.

## For users

- **[Getting started](getting-started.md)** - installation, BIOS directory paths per platform, verification
- **[Installer](installer.md)** - the one-liner in full: bootstrap, options, environment overrides, platform detection, trust boundary
- **[FAQ](faq.md)** - common questions, troubleshooting, hash explanations

If you just want to download BIOS packs, see the [home page](../index.md).

## Technical reference

- **[Architecture](architecture.md)** - directory structure, data flow, platform inheritance, pack grouping, security, edge cases, CI workflows
- **[Tools](tools.md)** - CLI reference for every script, pipeline usage, scrapers
- **[Advanced usage](advanced-usage.md)** - custom packs, target filtering, truth generation, emulator verification, offline workflow
- **[Verification modes](verification-modes.md)** - how each platform verifies BIOS files, severity matrix, resolution chain
- **[Data model](data-model.md)** - database.json structure, indexes, file resolution order, YAML formats
- **[Troubleshooting](troubleshooting.md)** - diagnosis by symptom: missing BIOS, hash mismatch, pack issues, verify errors

See also [dump provenance](../provenance.md) for how the collection lines up
against the No-Intro, Redump and TOSEC catalogs.

## For contributors

- **[Profiling guide](profiling.md)** - create an emulator profile from source code, YAML field reference
- **[Adding a platform](adding-a-platform.md)** - scraper, registry, YAML config, exporter, target scraper, install detection
- **[Adding a scraper](adding-a-scraper.md)** - plugin architecture, BaseScraper, parsers, target scrapers
- **[Testing guide](testing-guide.md)** - run tests, fixture pattern, how to add tests, CI integration
- **[Release process](release-process.md)** - CI workflows, large files, manual release

See [contributing](../contributing.md) for submission guidelines.

## Community

- **[Community tools](community-tools.md)** - projects built on RetroBIOS data

## Glossary

- **BIOS** - firmware burned into console hardware, needed by emulators that rely on original boot code
- **firmware** - system software loaded by a console at boot; used interchangeably with BIOS in this project
- **HLE** - High-Level Emulation; software reimplementation of BIOS functions, avoids needing the original file
- **hash** - fixed-length fingerprint of a file's contents; this project uses MD5, SHA1, SHA256, CRC32, and Adler-32
- **platform** - a distribution that packages emulators (RetroArch, Batocera, Recalbox, EmuDeck, etc.)
- **core** - an emulator packaged as a libretro plugin, loaded by RetroArch or compatible frontends
- **profile** - a YAML file in `emulators/` documenting one core's BIOS requirements, verified against source code
- **system** - a game console or computer being emulated (e.g. sony-playstation, nintendo-gameboy-advance)
- **pack** - a ZIP archive containing all BIOS files needed by a specific platform
- **ground truth** - the emulator's source code, treated as the authoritative reference for BIOS requirements
- **cross-reference** - comparison of emulator profiles against platform configs to find undeclared files
- **scraper** - a script that fetches BIOS requirement data from an upstream source (System.dat, es_bios.xml, etc.)
- **exporter** - a script that converts ground truth data back into a platform's native format
- **target** - a hardware architecture that a platform runs on (e.g. switch, rpi4, x86_64, steamos)
- **variant** - an alternative version of a BIOS file (different revision, region, or dump), stored in `.variants/`
- **required** - a file the core needs to function; determined by source code behavior
- **optional** - a file the core functions without, possibly with reduced accuracy or missing features
- **hle_fallback** - flag on a file indicating the core has an HLE path; absence is downgraded to INFO severity
- **severity** - the urgency of a verification result: OK (verified), INFO (negligible), WARNING (degraded), CRITICAL (broken)
- **status** - the outcome of a single file check: `ok`, `untested` (present, hash not the expected one), or `missing`
- **discrepancy** - a file that passes the platform check but fails the emulator's own size or hash validation
- **shared group** - a file group in `_shared.yml` that several platforms include, carrying the destination a core expects
- **data directory** - a whole directory tree a core needs (Dolphin `Sys/`, PPSSPP assets), cached in `data/`, not indexed in the database
- **storage tier** - where a file comes from: `embedded` (in `bios/`), `external` (downloaded at build), `user_provided`
- **truth** - platform-shaped data generated from emulator profiles, used to diff against what the platform declares
- **dump catalog** - a preservation project (Redump, No-Intro, TOSEC) publishing DATs of verified hardware dumps
- **provenance** - the catalogs that list a file, joined into the database by hash; an annotation, never an authority
- **manifest** - the JSON file list per platform in `install/`, consumed by `install.py`
