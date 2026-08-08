# Troubleshooting - RetroBIOS

Diagnosis guide organized by symptom. Each section describes what to check and how to fix it.

## Game won't start / black screen

Most launch failures are caused by a missing or incorrect BIOS file.

**Check if the BIOS exists:**

```bash
python scripts/verify.py --platform retroarch --verbose
python scripts/verify.py --system sony-playstation
```

Look for `MISSING` entries in the output. A missing required BIOS means the core
cannot start games for that system at all.

**Check if the hash matches:**

Look for `untested` entries in the verify output. This means the file exists but
its hash does not match the expected value. Common causes:

- Wrong region (a PAL BIOS instead of NTSC, or vice versa)
- Wrong hardware revision (e.g. SCPH-5501 vs SCPH-1001 for PlayStation)
- Corrupted download

Each system page on the site lists the expected hashes. Compare your file's
MD5 or SHA1 against those values.

**Wrong region BIOS:**

Some cores require region-specific BIOS files. A Japanese BIOS won't boot
North American games on cores that enforce region matching. Check the emulator
profile for your core to see which regions are supported and which files
correspond to each.

## BIOS not found by emulator

The file exists on disk, but the emulator reports it as missing.

**Wrong directory:**

Each platform expects BIOS files in a specific base directory:

- RetroArch: `system/` inside the RetroArch directory
- Lakka: `/storage/system/`
- Batocera: `/userdata/bios/`
- Recalbox: `/recalbox/share/bios/`
- RetroPie: `~/RetroPie/BIOS/`
- ROCKNIX: `/storage/roms/bios/`
- MiSTer FPGA: `/media/fat/games/`
- BizHawk: `Firmware/` inside the BizHawk directory
- EmuDeck: `~/Emulation/bios/`
- RetroDECK: `~/retrodeck/bios/`
- RetroBat: `bios/` inside the RetroBat directory

Some cores expect files in subdirectories (e.g. `dc/` for Dreamcast, `pcsx2/bios/`
for PlayStation 2). Check the `path:` field in the emulator profile for the exact
expected location relative to the base directory.

**Wrong filename:**

Cores match BIOS files by exact filename. If a core expects `scph5501.bin` and your
file is named `SCPH-5501.BIN`, it won't be found on platforms that do exact name matching.

Check the emulator profile for the expected filename and any aliases listed under
`aliases:`. Aliases are alternative names that the core also accepts.

**Case sensitivity:**

Linux filesystems are case-sensitive. A file named `Bios.ROM` won't match a lookup
for `bios.rom`. Windows and macOS are case-insensitive by default, so the same
file works there but fails on Linux.

Batocera's verification uses `casefold()` for case-insensitive matching, but
the actual emulator may still require exact case. When in doubt, use the exact
filename from the emulator profile.

## Hash mismatch / UNTESTED

`verify.py` reports `UNTESTED` for a file.

The file exists and was hashed, but the computed hash doesn't match any expected
value. This means you have a different version of the file than what the platform
or emulator expects. The reason field shows the expected vs actual hash prefix.

To find the correct version, check the system page on the site. It lists every
known BIOS file with its expected MD5 and SHA1.

**Existence-mode platforms never report UNTESTED:**

On RetroArch, Lakka and RetroPie, verification only asks whether the file is
there, so the only outcomes are OK and MISSING. A wrong-region or corrupt file
still shows as OK. To find out whether the content is right on those platforms,
run `verify.py --verbose`: it adds the emulator ground truth from the profiles
and flags a `DISCREPANCY` when the file passes the platform check but fails the
emulator's own size or hash validation.

**The .variants/ directory:**

When multiple versions of the same BIOS exist (different revisions, regions, or
dumps), the primary version lives in the main directory and alternatives live in
`.variants/`. `verify.py` checks the primary file first, then falls back to
variants when resolving by hash.

If your file matches a variant hash but not the primary, it's a valid BIOS --
just not the preferred version. Some cores accept multiple versions.

## Pack is missing files

A generated pack doesn't contain all the files you expected.

**Severity levels:**

`verify.py` assigns a severity to each issue. Not all missing files are equally
important:

| Severity | Meaning | Action needed |
|----------|---------|---------------|
| CRITICAL | Required file missing on an MD5 or SHA1 platform | Must fix. Core won't function. |
| WARNING | Optional file missing on an MD5 or SHA1 platform, hash mismatch (UNTESTED) on any hash platform, or a required file missing on an existence platform | Core works but with reduced functionality, or runs on content nobody verified. |
| INFO | Optional file missing on an existence-only platform, or a missing file the core covers with an HLE fallback | Core works fine, BIOS improves accuracy. |
| OK | File present and verified | No action needed. |

The full mapping, including how `hle_fallback` overrides the platform mode, is
in [verification modes](verification-modes.md#severity-matrix).

Focus on CRITICAL issues first. WARNING files improve the experience but aren't
strictly necessary. INFO files are nice to have.

**Large files (over 50 MB):**

Files like PS3UPDAT.PUP, PSVUPDAT.PUP, and Switch firmware are too large for the
git repository. They are stored as GitHub release assets under the `large-files`
release and downloaded at build time.

If a pack build fails to include these, check your network connection. In offline
mode (`--offline`), large files are only included if already cached locally in
`.cache/large/`.

**Data directories:**

Some cores need entire directory trees rather than individual files (e.g. Dolphin's
`Sys/` directory, PPSSPP's `assets/`). These are fetched by `refresh_data_dirs.py`
from upstream repositories.

In offline mode, data directories are only included if already cached in `data/`.
Run `python scripts/refresh_data_dirs.py` to fetch them.

## verify.py reports errors

How to read and interpret `verify.py` output.

**Status codes:**

| Status | Meaning |
|--------|---------|
| `ok` | File present, hash matches (or existence check passed) |
| `untested` | File present, hash not confirmed against expected value |
| `missing` | File not found in the repository |

Hash and size mismatches are reported as `untested` with a reason field
showing expected vs actual values (e.g., `expected abc123… got def456…`).

**Reading the output:**

Each line shows the file path, its status, and severity. In verbose mode, ground
truth data from emulator profiles is appended, showing which cores reference the
file and what validations they perform.

```
scph5501.bin        ok       [OK]
dc_boot.bin         missing  [CRITICAL]
gba_bios.bin        untested [WARNING]
```

**Cross-reference section:**

After per-file results, `verify.py` prints a cross-reference report. This lists
files that emulator cores need but that the platform YAML doesn't declare. These
files are still included in packs automatically, but the report helps identify
gaps in platform coverage data.

The cross-reference uses `resolve_platform_cores()` to determine which emulator
profiles are relevant for each platform, then checks whether each profile's files
appear in the platform config.

**Filtering output:**

```bash
# By platform
python scripts/verify.py --platform batocera

# By emulator core
python scripts/verify.py --emulator beetle_psx

# By system
python scripts/verify.py --system sony-playstation

# By hardware target
python scripts/verify.py --platform retroarch --target switch

# JSON for scripted processing
python scripts/verify.py --platform retroarch --json
```

## Installation script fails

Problems with `install.py`, `install.sh`, or `download.sh`.

**Network issues:**

The installer downloads packs from GitHub releases. If the download fails:

- Check your internet connection
- Verify that `https://github.com` is reachable
- If behind a proxy, set `HTTPS_PROXY` in your environment
- Try again later if GitHub is experiencing issues

**Permission denied:**

The installer needs write access to the target directory.

- On Linux/macOS: check directory ownership (`ls -la`) and run with appropriate
  permissions. Avoid running as root unless the target directory requires it.
- On Windows: run PowerShell as Administrator if installing to a protected directory.

**Platform not detected:**

`install.py` auto-detects your platform by checking for known config files. If
detection fails, specify the platform manually:

```bash
python install.py --platform retroarch --dest ~/RetroArch/system/
python install.py --platform batocera --dest /userdata/bios/
```

Use `python install.py --help` to see all available platforms and options.

**Pack not found in release:**

If the installer reports that no pack exists for your platform, check available
releases:

```bash
python scripts/download.py --list
# or
bash scripts/download.sh --list
```

Some platforms share packs (Lakka uses the RetroArch pack). The installer handles
this mapping automatically, but if you're downloading manually, check which pack
name corresponds to your platform.
