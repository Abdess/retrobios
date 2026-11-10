---
level: contribute
order: 90
---

# Terms of the reference pages

The words the reference and contributor pages use, each with a real case. The
everyday words (BIOS, emulator, core, hash) are in the [glossary](glossary.md).

**Frontend**
:   The menu that picks and starts games, such as EmulationStation, MinUI or
    the RetroArch menu. It starts the emulator.

**Pack**
:   One ZIP file with every BIOS file a setup uses. A pack over 2 GB comes in
    several parts, and every part is needed. A release publishes packs for the
    setups the registry marks `release_pack`, and the installer serves the rest.

**Profile and source_ref**
:   A profile records which files one emulator opens, read from its code.
    Every entry has a `source_ref`, the line of code that proves it, at the
    revision named by `source_commit` (the pin). Example:
    `emulators/duckstation.yml` lists `scph5501.bin` at
    `src/core/bios.cpp:47`, read at its `source_commit`.

**Alias**
:   Another name the same emulator accepts for a file, listed under `aliases:`
    in its profile, never as a second file.

**Region and priority**
:   `region:` is the territory for which the code picks a file. `priority:` is
    the order the code tries files that fill the same role, lowest first.
    Example: DuckStation gives `scph5501.bin` priority 5 and `scph1001.bin`
    priority 10, so with both present it loads `scph5501.bin`.

**Slot**
:   One role a file fills for one system and region, such as the North
    American PlayStation BIOS. `scph5501.bin`, `scph1001.bin` and `scph7001.bin`
    fill the same slot. `--one-per-slot` keeps the one the emulator prefers.

**Category: firmware, game data, unread**
:   Each entry of a platform's list is sorted by what its emulators do with
    it: firmware they load, game data, or a file none of them opens. Only
    missing firmware counts as a fault. Example: AmberELEC lists
    `hardwareconfig.xml` in each blueMSX machine folder, and blueMSX never
    opens it, so it is `unread`.

**Romset and recipe**
:   An arcade BIOS is a ZIP of several chips, and each MAME or FBNeo version
    expects a slightly different ZIP. A recipe is the list of chips (name and
    CRC32) one version expects, enough to rebuild that exact ZIP from chips
    already held. Example: `spec128.zip` (MD5 `1a524bfa...`) was rebuilt from
    the FBNeo recipe.

**Profile**
:   A YAML file in `emulators/` that documents what one emulator loads, read
    from its source code.

**Ground truth**
:   The emulator's source code, the reference every profile is checked against.

**System**
:   A console or computer being emulated, named by an id such as
    `sony-playstation` or `nintendo-gba`.

**Verification mode**
:   How a setup checks a file: by its name only (existence), by MD5 or by SHA1.
    Reference: [How each platform checks files](verification-modes.md).

**Status**
:   The outcome of one file check: `ok`, `untested` (present, but not the
    expected hash) or `missing`. Batocera's own checker prints the same
    `UNTESTED` for a file whose MD5 is not on its list (`batocera-systems`,
    `checkBios`).

**Severity**
:   How much a check result matters: OK, INFO (negligible), WARNING (degraded),
    CRITICAL (the emulator cannot start games).

**Discrepancy**
:   A file that passes the setup's own check but fails the emulator's size or
    hash check. Example: RetroBat accepts `d64_1.rom`, while XRoar checks its
    CRC32 and expects `84f68bf9`, not `60a4634c`. `verify.py` prints it as
    `DISCREPANCY`, and the gaps page lists it under that name, with the check
    that failed (size or hash) in the row.

**HLE**
:   High-level emulation: code inside the emulator that does the BIOS's job,
    so some games start without the file. Some games glitch or do not start
    with it, so the real file still ships.

**hle_fallback**
:   A flag on a profile entry: the emulator has HLE for this file, so its
    absence is reported at INFO. It does not make the file optional: a few
    entries that carry it are `required: true`, among them QUASI88's
    `n88.rom`.

**Variant**
:   Another version of a BIOS file (a revision, a region or another dump), kept
    in `.variants/` in the repository.

**Cross-reference**
:   The comparison of emulator profiles with a setup's own list, which finds the
    files the setup's emulators load and its list does not name. The packs add
    those files, and [What the packs do not hold](../gaps.md) counts them. The
    page [Cores by platform](../cross-reference.md) lists the cores this
    comparison reads.

**Shared group**
:   A group of files in `_shared.yml` that several setups include, with the
    folder an emulator expects.

**Data directory**
:   A whole folder an emulator needs, such as Dolphin's `Sys/` or the PPSSPP
    assets, kept in `data/` and not indexed in the database.

**Storage tier**
:   Where a file comes from: `embedded` (in `bios/`), `external` (downloaded at
    build time), `user_provided`, or `large_file` and `release` (an asset of
    the `large-files` release).

**Target**
:   A hardware architecture a setup runs on, such as `switch`, `rpi4` or
    `x86_64`.

**Manifest**
:   The JSON list of files per setup in `install/`, which the installer reads.

**Scraper**
:   A script that reads a setup's own BIOS list (System.dat, es_bios.xml and
    others) into this project's format.

**Exporter**
:   A script that writes the project's data back in a setup's own format.

**Truth**
:   A setup's file list generated from the emulator profiles, compared with the
    list the setup publishes.

**Dump catalog**
:   A preservation project (Redump, No-Intro, TOSEC) that publishes lists of
    verified hardware dumps.

**Provenance**
:   Whether a file is byte for byte a dump that Redump, No-Intro or TOSEC
    catalogues, joined to the database by hash. Example: `scph5501.bin` is
    Redump's `ps-30a.bin`. It says where a dump is known from, not whether an
    emulator accepts it, and it never overrides the emulator code. Where a pack
    takes a file from (the collection, a data folder, a release asset) is its
    source, not its provenance.

## Next steps

- [How each platform checks files](verification-modes.md)
- [Words used on this site](glossary.md)

