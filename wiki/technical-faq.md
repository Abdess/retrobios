---
level: reference
order: 120
terms: mame version, romset version, which mame
---

# Technical questions

Answers to "how is this known?" questions: how a file is identified, why one BIOS
has several fingerprints, why some files are not BIOS, and which MAME version an
arcade set belongs to. Each answer gives a real file as its example, to check on the
system pages. Questions asked before installing are in
[Common questions](faq.md).

## What's a hash/checksum?

A hash is a fixed-length fingerprint computed from a file's contents. If even one byte differs, the hash changes completely. Every file in the database carries these:

| Type | Length | Example | Used for |
|------|--------|---------|----------|
| SHA1 | 40 hex chars | `10155d8d6e6e832d8ea1571511e40dfb15fede05` | database primary key, BizHawk, installer downloads |
| MD5 | 32 hex chars | `924e392ed05558ffdb115408c263dccf` | most platform verification |
| SHA256 | 64 hex chars | `9a1c...` | emulator profiles whose upstream publishes SHA256 |
| CRC32 | 8 hex chars | `2F468B96` | ROM-set matching, arcade DATs |

Emulator profiles add Adler-32 where the code checks it, which is how Dolphin
checks its DSP ROMs (`dsp_rom.bin` and `dsp_coef.bin`, hashed byte-swapped).
`IPL.bin` is not one of them: Dolphin loads it without a hash check.

Verification uses whichever one the platform itself uses: MD5 for Batocera,
RetroBat, Recalbox, EmuDeck, RetroDECK, RomM, ROCKNIX, KNULLI, AmberELEC, EmuELEC
and MiSTer FPGA, SHA1 for
BizHawk, and nothing at all for RetroArch, Lakka and RetroPie, which only check
that the file exists.

## How is a missing file ranked?

In verification output, missing required files appear as CRITICAL or WARNING
depending on the platform. Missing optional files appear as WARNING or INFO.

When a core has HLE support, the verification tool lowers the severity of a
missing BIOS to INFO. The file is still included in packs because the real BIOS
gives better results. The full table is the
[severity matrix](verification-modes.md#severity-matrix).

## Why are there multiple hashes for the same file?

Two main reasons:

1. **Regional variants.** The same filename (e.g., `IPL.bin` for GameCube) exists in different versions for USA, Europe, and Japan. Each region has a different hash.
2. **Revision differences.** Console manufacturers released updated BIOS versions over time. A PlayStation SCPH-5501 BIOS differs from a SCPH-7001.

Platforms that verify by MD5 accept specific hashes. A file that matches no known hash may be a bad dump or an uncommon revision.

A filename is never allowed to stand in for a declared hash. When a file entry
carries a hash, resolution matches on content and reports `hash_mismatch` if the
only same-named copy disagrees. What happens next depends on the platform: an
MD5 or SHA1 platform would report the file as not the expected one, so the pack
omits it and says why,
while an existence platform only checks presence, so the file ships and the divergence
is reported instead.

## Why are there files that aren't BIOS?

A file earns its place when an emulator loads it from disk and does not bundle it. That covers actual BIOS ROMs, console firmware, arcade BIOS sets, and also game data, such as `doom.wad` for the PrBoom core (`category: game_data` in `emulators/prboom.yml`) or soundfonts for EasyRPG.

This follows the platforms themselves: EmuELEC lists Diablo's `diabdat.mpq` in its BIOS list (`platforms/emuelec.yml`, destination `ports/diablo/diabdat.mpq`), and libretro declares such files in the `firmware` field of its core info. The word "BIOS" is their vocabulary for "external file the emulator needs". Files are tagged by category (`bios`, `game_data`, `bios_zip`) in the emulator profiles, so the distinction stays visible.

A file the emulator carries inside itself is not one of them. PrBoom compiles its engine data `prboom.wad` into the core from `src/prboom_wad_data.h` and never opens it on disk (`emulators/prboom.yml`, `src/d_main.c:1449-1465`), so no PrBoom pack needs it.

## Why is a file the emulator reads not in the pack?

A pack brings what the user has to obtain. A file the emulator installs itself
(a font, a shader, a game database, a free replacement BIOS) is already on the
machine once the emulator is installed, so the pack leaves it out. This is
decided per build and per platform: the PPSSPP standalone release ships its
`assets/` folder, the PPSSPP libretro core does not, so RetroArch packs carry
those files and a standalone PPSSPP pack does not. When a platform's own
package installs data beside a core (Batocera with blueMSX), that platform's
pack leaves it out too. The emulator's page marks these files as installed with
the emulator.

## What's HLE?

HLE (high-level emulation) is code inside an emulator that does the BIOS's job,
so some games start without the file. Beetle PSX, for one, carries OpenBIOS for
that (`emulators/beetle_psx.yml`, notes). The real file still ships, because
the stand-in is not perfect: some games glitch or do not start.

A profile entry records it as `hle_fallback: true`. That flag does not decide
`required`: some entries that carry it are required, such as Yabause's
`saturn_bios.bin`. Verification reports a missing `hle_fallback` file at INFO
either way.

## How often are packs updated?

The platforms' own lists (libretro's System.dat, batocera-systems and the
others) are read again by hand, and the difference is reviewed before it lands.
A release follows when files are added or profiles change.

## Are these files verified against original hardware dumps?

No. The hashes here document what
emulator code loads and accepts, read from the source. When several
revisions or regions pass, all of them are kept (`.variants/` in the
repository, per-emulator pages list each one), and the pack ships the
variant satisfying the most checks, logging any conflict it cannot
resolve.

Whether a file byte-matches the original hardware ROM is a different
question, answered by dump-preservation catalogs such as No-Intro,
Redump, and TOSEC, not by emulator code. The collection is
cross-referenced against their DATs: files matching a catalog entry
carry a verified dump badge on the system pages, and catalog entries
absent from the collection are tracked as acquisition targets. When
the two views differ, this project follows the code, because that is
what decides whether the emulator boots.

The [dump provenance](../provenance.md) page has the current coverage
per catalog and the full list of catalogued dumps still missing.

## Which MAME version do the arcade BIOS sets match?

Game sets and BIOS sets must come from the same version as the arcade
emulator.

<!-- generated: romsets -->
| Emulator, as RetroArch names it | Sets from |
|---|---|
| MAME 2000 | MAME 0.37b5 |
| MAME 2003, MAME 2003 Midway | MAME 0.78 |
| MAME 2003-Plus | MAME 0.78 (plus backports) |
| MAME 2009 | MAME 0.135u4 |
| MAME 2010 | MAME 0.139 |
| MAME 2014, MAME 2015 | MAME 0.159 |
| MAME 2016 | MAME 0.174 |
| MAME, MAME/Arcade, MAME/MESS | MAME 0.289 |
| FB Alpha 2012 CPS-1, FB Alpha 2012 CPS-2 | FB Alpha v0.2.97.28 |
| FB Alpha 2012 Neo Geo | FB Alpha v0.2.97.29 |
| FB Alpha 2012, FB Alpha 2012 CPS-3 | FB Alpha v0.2.97.30 |
| FB Alpha 2019 | FB Alpha v0.2.97.44 |
| FinalBurn Neo, FinalBurn Neo (CPS-1 / CPS-2), FinalBurn Neo (Neo-Geo) | FinalBurn Neo v1.0.0.03 |
<!-- /generated: romsets -->

Each emulator's page names its version too.

### How this is known

Arcade BIOS sets are coupled to the romset version, so there is one
profile per MAME core generation (MAME 2000, 2003, 2003-Plus, 2009, 2010,
2015, 2016 and current MAME), each read from that version's own source
tree, because the BIOS root sets differ between versions. The table is
written from the profiles, and each version is the one the core's source
states at the revision its profile was read at. Derivatives and ports
carry their own profiles on top of those generations: `mamearcade`,
`mamemess`, `mame2003_midway`, the three `mame4droid` drops,
`advancemame`, `groovymame` and `hbmame`. Recalbox compiles two MAME
versions of its own, 0.258 and 0.278, profiled as `mame0258` and
`mame0278`. The pack ships the sets matching the core in use, and a
generic unversioned arcade pack cannot do that.

## Why does a verification report say UNTESTED? { #why-does-my-verification-report-say-untested }

`untested` means the file exists on disk but its hash does not match the expected value. This happens on MD5 and SHA1 platforms (Batocera, Recalbox, BizHawk, ROCKNIX, MiSTer FPGA, and the rest) when the file is present but contains different data than what the platform declares.

On existence-mode platforms (RetroArch, Lakka, RetroPie, MinUI, NextUI, MyMinUI), files are never `untested` because the platform only checks presence, not content. Those files show as `ok` if present, whatever they contain.

Running `verify.py --emulator <core> --verbose` shows the emulator-level ground truth, which can confirm whether the file's hash matches what the source code expects. The platform report applies the same check on its own: `verify.py --platform retroarch` prints a `DISCREPANCY` line for every file the platform accepts and a profiled emulator rejects.

It reaches only as far as the profiles do. Files no profile states a value for are platform-only, and nothing can be said about their content. The footer of the platform report gives that ratio as `Ground truth: N/M files have emulator validation`.

## Why do BIOS pictures and sounds show in a phone's gallery?

Android's media scanner indexes every image, sound and video in shared
storage, and the RetroArch BIOS folder holds 3,842 of them (FBNeo samples,
overlays, PPSSPP assets, sdlpal's videos). An empty file named `.nomedia` in
the BIOS folder hides it and every folder below it. The installer writes one
on Android and the RetroArch pack carries one: see [Android](installer.md#android).
Copied by hand without either, the folder needs that empty file created by hand.

## Why were files left out on an exFAT card?

FAT, exFAT and Windows refuse `< > : " | ? *` in a name, and RetroDECK's list
names three files with a colon, like `zxs:48.rom`. The installer leaves those
out on such a card and names them. An ext4 card holds them. See
[Upper and lower case](installer.md#upper-and-lower-case).

## Next steps

- [Reference](index.md), every reference page in one list
- For contributors: [How to contribute](../contributing.md)

