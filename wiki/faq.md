# FAQ - RetroBIOS

## My game shows a black screen

Most likely a missing or incorrect BIOS file. Run verification for your platform:

```bash
python scripts/verify.py --platform retroarch
```

Look for MISSING or HASH MISMATCH entries. If a file shows HASH MISMATCH, you have a BIOS file but it's the wrong version or a bad dump. Replace it with one that matches the expected hash.

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
Redump, and TOSEC, not by emulator code.
The two views usually agree; when they differ, this project follows the
code, because that is what decides whether your emulator boots.

## Which MAME version do the arcade BIOS sets match?

Arcade BIOS sets are coupled to the romset version, so there is one
profile per MAME core generation: MAME 2000 (0.37b5), MAME 2003 (0.78),
MAME 2003-Plus, MAME 2009 (0.135u4), MAME 2010 (0.139), MAME 2015
(0.160), MAME 2016 (0.174), and current MAME (0.287), each read from that
version's own source tree, because the BIOS root sets differ between
versions. The pack ships the sets matching the core you run; a generic
unversioned arcade pack cannot do that.

## How do I know which BIOS I need?

Two approaches:

1. **Run verify.py** for your platform. It lists every expected file with its hash and status.
2. **Check the project site.** Each platform page lists all required and optional BIOS files per system.

For a specific emulator core:

```bash
python scripts/verify.py --emulator beetle_psx --verbose
```

The `--verbose` flag shows source references and expected values from the emulator's source code.

## Is this legal?

The project believes so, in good faith and for the specific purposes it serves: preservation, personal backup, and interoperability with emulation software. That belief rests on case law and statutory exemptions across several jurisdictions, documented below so anyone can weigh the reasoning.

### Emulation and BIOS redistribution

- **Emulation is legal.** *Sony v. Connectix* (2000) and *Sega v. Accolade* (1992) established that creating emulators and reverse-engineering console firmware for interoperability is lawful. BIOS files are functional prerequisites for this legal activity.
- **Fair use (US, 17 USC 107).** Non-commercial redistribution of firmware for personal emulation and archival is transformative use. The files serve a different purpose (interoperability) than the original (running proprietary hardware). No commercial market exists for standalone BIOS files.
- **Fair dealing (EU, UK, Canada, Australia).** Equivalent doctrines protect research, private study, and interoperability. The EU Software Directive (2009/24/EC, Art. 5-6) explicitly permits decompilation and use for interoperability.
- **Abandonware.** The vast majority of firmware here is for discontinued hardware no longer sold, supported, or distributed by the original manufacturer. No active commercial market is harmed.

### Encryption keys (Switch prod.keys, 3DS AES keys, Wii U keys)

This is the most contested area. The legal position:

- **Keys are not copyrightable.** Encryption keys are mathematical values, not creative expression. Copyright protects original works of authorship; a 256-bit number does not meet the threshold of originality. *Bernstein v. DOJ* (1996) established that code and algorithms are protected speech, and the mere publication of numeric values cannot be restricted under copyright.
- **DMCA 1201(f) interoperability exemption.** The DMCA prohibits circumvention of technological protection measures, but Section 1201(f) explicitly permits circumvention for the purpose of achieving interoperability between programs. Emulators require these keys to decrypt and run legally purchased game software. The keys enable interoperability, not piracy.
- **Library of Congress DMCA exemptions.** The triennial rulemaking process has repeatedly expanded exemptions for video game preservation. The 2024 exemption (37 CFR 201.40) covers circumvention for preservation of software and video games, including when the original hardware is no longer available.
- **Keys derived from consumer hardware.** These keys are extracted from retail hardware owned by consumers. Once a product is sold, the manufacturer cannot indefinitely control how the purchaser uses or examines their own property. *Chamberlain v. Skylink* (2004) held that using a product in a way the manufacturer dislikes is not automatically a DMCA violation.
- **No trade secret protection.** For keys to qualify as trade secrets, the holder must take reasonable steps to maintain secrecy. Keys embedded in millions of consumer devices and widely published online do not meet this standard.

### Recent firmware (Switch 19.0.0, PS3UPDAT, PSVUPDAT)

- **Firmware updates are freely distributed.** Nintendo, Sony, and other manufacturers distribute firmware updates via CDN without authentication or purchase requirements. Redistributing freely available data does not create new legal liability.
- **Functional necessity.** Emulators require system firmware to function. Providing firmware is equivalent to providing the operating environment the software was designed to run in.
- **Yuzu context.** The Yuzu settlement (2024) concerned the emulator itself and its facilitation of piracy, not the legality of firmware or key distribution. Yuzu settled without admitting liability and the case created no binding precedent against BIOS or key redistribution.

### Summary

This project preserves BIOS files, firmware, and the keys emulators require, for personal use, archival, and interoperability. That position rests on fair use, statutory interoperability exemptions, preservation precedent, and the functional nature of the files involved.

This reflects the project's good-faith understanding, not legal advice. Anyone with a concern about a specific file, rights holders included, can open an issue and will receive a considered answer.

## Isn't the Switch or PS3 too recent for a retro project?

Age is not what decides inclusion here; availability is. Firmware distribution depends on manufacturer servers, and those disappear: Nintendo closed the 3DS and Wii U eShops in March 2023, Sony shut the PSP store in 2021. Once a CDN goes offline, the files only survive where someone archived them.

The project tries to archive files while they are still available rather than after they have become rare. "Retro" is a moving window: the PlayStation 2 was current hardware when its BIOS was first preserved, and today's consoles will be tomorrow's retro systems. A file is included for the same reason at any age: an emulator needs it, and nothing guarantees it stays available.

## What's a hash/checksum?

A hash is a fixed-length fingerprint computed from a file's contents. If even one byte differs, the hash changes completely. The project uses three types:

| Type | Length | Example |
|------|--------|---------|
| MD5 | 32 hex chars | `924e392ed05558ffdb115408c263dccf` |
| SHA1 | 40 hex chars | `10155d8d6e6e832d8ea1571511e40dfb15fede05` |
| CRC32 | 8 hex chars | `2F468B96` |

Different platforms use different hash types for verification. Batocera uses MD5, RetroArch checks existence only, BizHawk uses SHA1, and RomM uses MD5.

## Why does my verification report say UNTESTED?

UNTESTED means the file exists on disk but its hash does not match the expected value. This happens on MD5/SHA1-mode platforms (Batocera, Recalbox, BizHawk, etc.) when the file is present but contains different data than what the platform declares.

On existence-mode platforms (RetroArch, Lakka, RetroPie), files are never UNTESTED because the platform only checks presence, not content. Those files show as OK if present.

Running `verify.py --emulator <core> --verbose` shows the emulator-level ground truth, which can confirm whether the file's hash matches what the source code expects.

## Can I use BIOS from one platform on another?

Yes. BIOS files are console-specific, not platform-specific. A PlayStation BIOS works in RetroArch, Batocera, Recalbox, and any other platform that emulates PlayStation. The only differences between platforms are:

- **Where the file goes** (each platform has its own BIOS directory)
- **What filename is expected** (usually the same, occasionally different)
- **How verification works** (MD5 check vs. existence check)

The packs differ per platform because each platform declares its own set of supported systems and expected files.

## How often are packs updated?

A weekly automated sync checks upstream sources (libretro System.dat, batocera-systems, etc.) for changes. If differences are found, a pull request is created automatically. Manual releases happen as needed when new BIOS files are added or profiles are updated.
