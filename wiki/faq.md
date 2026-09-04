# FAQ - RetroBIOS

## My game shows a black screen

Most likely a missing or incorrect BIOS file. Run verification for your platform:

```bash
python scripts/verify.py --platform retroarch
```

Look for `missing` or `untested` entries. `missing` means the file is not there at all. `untested` means the file is there but its hash is not the expected one, so it is the wrong version or a bad dump: replace it with one matching the hash listed on the system page.

Some cores also support HLE (see below), so a missing BIOS may not always be the cause. Check the emulator's logs for error messages.

## What's the difference between required and optional?

**Required** means the emulator will not start games for that system without the file. **Optional** means the emulator works without it, but with reduced accuracy or missing features (e.g., boot screen animation, wrong font rendering, or degraded audio).

In verification output, missing required files appear as CRITICAL or WARNING depending on the platform. Missing optional files appear as WARNING or INFO.

## What's HLE?

HLE (High-Level Emulation) is a software reimplementation of what the original BIOS does. Some cores can boot games without a real BIOS file by using their built-in HLE fallback. The trade-off is lower accuracy: some games may have glitches or fail to boot entirely.

When a core has HLE support, the verification tool lowers the severity of a missing BIOS to INFO. The file is still included in packs because the real BIOS gives better results.

## Why are there multiple hashes for the same file?

Two main reasons:

1. **Regional variants.** The same filename (e.g., `IPL.bin` for GameCube) exists in different versions for USA, Europe, and Japan. Each region has a different hash.
2. **Revision differences.** Console manufacturers released updated BIOS versions over time. A PlayStation SCPH-5501 BIOS differs from a SCPH-7001.

Platforms that verify by MD5 accept specific hashes. If yours doesn't match any known hash, it may be a bad dump or an uncommon revision.

A filename is never allowed to stand in for a declared hash. When a file entry
carries a hash, resolution matches on content and reports `hash_mismatch` if the
only same-named copy disagrees. What happens next depends on the platform: an
MD5 or SHA1 platform would reject the file, so the pack omits it and says why;
an existence platform only checks presence, so the file ships and the divergence
is reported instead.

## Why are there files that aren't BIOS?

A file earns its place when an emulator loads it from disk and does not bundle it. That covers actual BIOS ROMs, console firmware, arcade BIOS sets, and also game data like `prboom.wad` for the PrBoom core or soundfonts for EasyRPG.

This follows the platforms themselves: Batocera lists `prboom.wad` in its BIOS checker, and libretro declares these files in the `firmware` field of its core info. The word "BIOS" is their vocabulary for "external file the emulator needs". Files are tagged by category (`bios`, `game_data`, `bios_zip`) in the emulator profiles, so the distinction stays visible.

## Are these files verified against original hardware dumps?

No, and that is a deliberate boundary. The hashes here document what
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
what decides whether your emulator boots.

The [dump provenance](../provenance.md) page has the current coverage
per catalog and the full list of catalogued dumps still missing.

## Which MAME version do the arcade BIOS sets match?

Arcade BIOS sets are coupled to the romset version, so there is one
profile per MAME core generation: MAME 2000 (0.37b5), MAME 2003 (0.78),
MAME 2003-Plus, MAME 2009 (0.135u4), MAME 2010 (0.139), MAME 2015
(0.160), MAME 2016 (0.174), and current MAME (0.289), each read from that
version's own source tree, because the BIOS root sets differ between
versions. Derivatives and ports carry their own profiles on top of those
generations: `mamearcade`, `mamemess`, `mame2003_midway`, the three
`mame4droid` drops, `advancemame`, `groovymame` and `hbmame`. The pack
ships the sets matching the core you run; a generic unversioned arcade
pack cannot do that.

## How do I know which BIOS I need?

Two approaches:

1. **Run verify.py** for your platform. It lists every expected file with its hash and status.
2. **Check the project site.** Each platform page lists all required and optional BIOS files per system.

For a specific emulator core:

```bash
python scripts/verify.py --emulator beetle_psx --verbose
```

The `--verbose` flag shows source references and expected values from the emulator's source code.

## Is piping the installer into a shell safe?

The one-liner runs a small bootstrap, not the installer. That bootstrap fetches
`install.py` over HTTPS only, refuses anything over 2 MB, and requires its
SHA-256 to equal the value written inside the bootstrap itself. A substituted
installer aborts with `install.py SHA-256 mismatch` before a single line of it
runs.

The installer then verifies every file it downloads against the size, SHA-256
and SHA-1 the manifest declares, and moves it into place only once those match.
The manifest is treated as untrusted: a destination cannot be absolute, carry a
drive letter or climb out of the BIOS directory.

Reading the bootstrap before running it is two lines:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh -o install.sh
less install.sh && sh install.sh
```

See [Installer](installer.md) for the full behaviour.

## Can I run the installer again?

Yes, and re-running is the normal way to update. A file already present with
the expected hash is left untouched, one whose contents do not match is
replaced by the verified copy, and files the manifest does not name are never
read, moved or deleted. `--check` does the same inspection and exits without
writing.

## Can I install onto an SD card or another machine's drive?

Yes, `--dest` takes any path and the one-liner forwards arguments:

```bash
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh \
  | sh -s -- --platform retroarch --dest /path/to/sdcard
```

On Windows the arguments need a script block, since `iex` would read them as
its own; the form is on the [Installer](installer.md#passing-options) page.

## Is this legal?

Redistributing firmware is not settled law, and this page does not pretend otherwise. What follows is the reasoning the project acts on, with the strength of each argument stated plainly so anyone can weigh it. None of it is legal advice, and none of it has been tested in court.

### Emulation and BIOS redistribution

- **Writing an emulator is lawful.** *Sony v. Connectix* (2000) and *Sega v. Accolade* (1992) held that copying a work during reverse engineering, to reach the functional elements needed for interoperability, is fair use. Both concern the act of copying while developing, and *Connectix* specifically involved copying Sony's BIOS in the course of that work. Neither decision addresses distributing firmware to third parties, so they support the legality of emulation itself rather than of this collection.
- **Fair use (US, 17 USC 107) is a defence, argued case by case.** The project's position is that non-commercial redistribution for personal backup and archival weighs favourably on purpose and on market effect, since these files are not sold separately. It weighs poorly on the amount used: each file is copied whole. Manufacturers do still monetise some of this firmware indirectly, through re-releases, subscription services and mini consoles, so the market factor is contestable rather than clear.
- **Interoperability in the EU.** The Software Directive (2009/24/EC, Art. 5-6) permits decompilation and use to achieve interoperability, subject to conditions, and Art. 6 restricts passing the resulting information to others. It supports the emulation use case; it is not a general redistribution permission.
- **Discontinued hardware.** Most firmware here is for hardware no longer sold or supported. This bears on the fair-use market factor and on the practical likelihood of complaint. "Abandonware" is not a legal doctrine in any jurisdiction, and nothing here rests on it.

### Encryption keys (Switch prod.keys, 3DS AES keys, Wii U keys)

This is the most contested area, and the weakest part of the project's position.

- **Keys are unlikely to be copyrightable.** A bare numeric value has no author's creative expression, so copyright is a poor fit. This says nothing about the DMCA, which is the provision that actually applies.
- **DMCA 1201(f) is narrow.** Section 1201(f) allows a person who has lawfully obtained the right to use a copy to circumvent for the sole purpose of achieving interoperability with an independently created program, and 1201(f)(3) allows the means to be made available to others only for that same purpose. Publishing keys openly is not obviously within that allowance, and the trafficking prohibitions in 1201(a)(2) and 1201(b) remain in play. This is the clearest legal risk the project carries.
- **Library of Congress exemptions do not cover this repository.** The triennial exemptions at 37 CFR 201.40 let an eligible library, archive or museum circumvent access controls to preserve a lawfully acquired video game whose server support has ended, with access limited to the institution's premises. The Ninth Triennial Proceeding (2024 cycle) renewed them and declined to extend them to off-premises remote access. A public repository is neither an eligible institution nor an on-premises reading room, so these exemptions show which way preservation policy is moving without authorising what is done here.
- **Keys come from consumer hardware.** They are extracted from retail devices their owners bought. *Chamberlain v. Skylink* (2004) held that a 1201 claim requires some nexus to copyright infringement, in a dispute over a garage-door opener; later cases have narrowed its reach, and it is a weak foundation for a general post-sale right.
- **Trade secret is not a live issue.** Keys embedded in millions of shipped devices and widely republished are not kept secret by reasonable measures.

### Recent firmware (Switch 19.0.0, PS3UPDAT, PSVUPDAT)

- **Free download is not a licence.** Manufacturers publish these updates on open CDNs without authentication, which makes them easy to obtain but does not grant a right to redistribute them; PlayStation firmware ships under an end-user licence agreement. The practical argument is that mirroring a file the manufacturer already gives away for free causes no identifiable loss, not that doing so is expressly permitted.
- **Functional necessity.** Emulators cannot run the software these systems were built for without this firmware. That is why the files are collected; it is a statement of purpose, not a legal defence in itself.
- **Yuzu context.** The Yuzu settlement (2024) concerned the emulator and its alleged facilitation of piracy. Yuzu settled without admitting liability, so it set no precedent either way on firmware or key redistribution. It does show that rights holders in this space litigate.

### Summary

This project preserves BIOS files, firmware and keys for personal use, archival and interoperability. The strongest ground is the older, discontinued firmware, where fair use and the absence of a market both point the same way. The weakest is the encryption keys, where DMCA 1201 applies and the interoperability exemption is narrower than the use made of it here. The project accepts that risk deliberately, in the belief that these files are worth preserving while they can still be obtained.

This reflects the project's good-faith understanding, not legal advice.

### Asking for a file to be removed

A rights holder, or anyone acting for one, can [open an issue](https://github.com/Abdess/retrobios/issues) identifying the file by path or hash. A file whose removal is requested by its rights holder is removed from the repository and from the next release; no formal notice is required and none will be demanded. State the file and the basis of the claim. The same channel is open to anyone else with a concern about a specific file.

## Isn't the Switch or PS3 too recent for a retro project?

Age is not what decides inclusion here; availability is. Firmware distribution depends on manufacturer servers, and those disappear: Nintendo closed the 3DS and Wii U eShops in March 2023, Sony shut the PSP store in 2021. Once a CDN goes offline, the files only survive where someone archived them.

The project tries to archive files while they are still available rather than after they have become rare. "Retro" is a moving window: the PlayStation 2 was current hardware when its BIOS was first preserved, and today's consoles will be tomorrow's retro systems. A file is included for the same reason at any age: an emulator needs it, and nothing guarantees it stays available.

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
RetroBat, Recalbox, EmuDeck, RetroDECK, RomM, ROCKNIX and MiSTer FPGA, SHA1 for
BizHawk, and nothing at all for RetroArch, Lakka and RetroPie, which only check
that the file exists.

## Why does my verification report say UNTESTED?

`untested` means the file exists on disk but its hash does not match the expected value. This happens on MD5 and SHA1 platforms (Batocera, Recalbox, BizHawk, ROCKNIX, MiSTer FPGA, and the rest) when the file is present but contains different data than what the platform declares.

On existence-mode platforms (RetroArch, Lakka, RetroPie), files are never `untested` because the platform only checks presence, not content. Those files show as `ok` if present, whatever they contain.

Running `verify.py --emulator <core> --verbose` shows the emulator-level ground truth, which can confirm whether the file's hash matches what the source code expects. The platform report applies the same check on its own: `verify.py --platform retroarch` prints a `DISCREPANCY` line for every file the platform accepts and a profiled emulator rejects.

It reaches only as far as the profiles do. Files no profile states a value for are platform-only, and nothing can be said about their content; the footer of the platform report gives that ratio as `Ground truth: N/M files have emulator validation`.

## Can I use BIOS from one platform on another?

Yes. BIOS files are console-specific, not platform-specific. A PlayStation BIOS works in RetroArch, Batocera, Recalbox, and any other platform that emulates PlayStation. The only differences between platforms are:

- **Where the file goes** (each platform has its own BIOS directory)
- **What filename is expected** (usually the same, occasionally different)
- **How verification works** (MD5 check vs. existence check)

The packs differ per platform because each platform declares its own set of supported systems and expected files.

## How often are packs updated?

Upstream sources (libretro System.dat, batocera-systems, etc.) are re-scraped by hand and the diff is reviewed before it lands. Releases happen as needed when new BIOS files are added or profiles are updated.
