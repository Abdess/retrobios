---
level: reference
order: 15
group: Checking files
---

# Reading this project's own reports

These sections are about this repository's own tools, run from a clone.
`scripts/verify.py` checks the collection in `bios/` against each platform, never
a user's BIOS folder: for that, use the installer's `--check`
([When a game does not start](troubleshooting.md)). How each platform checks a
file is on [How each platform checks files](verification-modes.md).

## Hash mismatch / UNTESTED

`verify.py` reports `UNTESTED` for a file of the collection that was hashed
and does not match what the platform declares. The line gives the reason:

```
  UNTESTED (required): nintendo-ds/dsifirmware.bin: declared hash contradicted by the local file
```

The system page on the site lists every known version of the file with its
expected MD5 and SHA1.

### Existence-mode platforms never report UNTESTED

On RetroArch, Lakka and RetroPie, the platform check only asks whether the file
is there, so the only outcomes are OK and MISSING. `verify.py` adds the emulator
ground truth from the profiles and flags a `DISCREPANCY` when a file passes the
platform check but fails the emulator's own size or hash validation.

### The .variants/ directory

When multiple versions of the same BIOS exist (different revisions, regions, or
dumps), the primary version lives in the main directory and alternatives live in
`.variants/`. `verify.py` checks the primary file first, then falls back to
variants when resolving by hash.

A file that matches a variant hash but not the primary works. It is not the
version the emulator tries first, and some cores accept several versions.

## Pack is missing files

A generated pack lacks some of the expected files.

### Severity levels

`verify.py` assigns a severity to each issue, counted under `severity_counts`
in its `--json` output. Not all missing files are equally important:

| Severity | Meaning | Action needed |
|----------|---------|---------------|
| CRITICAL | Required file missing on an MD5 or SHA1 platform | The setup's own check fails. Whether the core starts without it is on the emulator's page. |
| WARNING | Optional file missing on an MD5 or SHA1 platform, hash mismatch (UNTESTED) on any hash platform, or a required file missing on an existence platform | The setup's check warns, or a file it does not read is absent. The emulator's page says what the core does without it. |
| INFO | Optional file missing on an existence-only platform, or a missing file the core covers with an HLE fallback | The profile records that the core runs without it. |
| OK | File present and verified | No action needed. |

The full mapping, including how `hle_fallback` overrides the platform mode, is
in the [severity matrix](verification-modes.md#severity-matrix).

Focus on CRITICAL issues first. WARNING files improve the experience but aren't
strictly necessary. INFO files are nice to have.

### Large files (release assets)

Files like PS3UPDAT.PUP, PSVUPDAT.PUP, and Switch firmware are too large for the
git repository. They are stored as GitHub release assets under the `large-files`
release and downloaded at build time.

If a pack build fails to include these, check the network connection. In offline
mode (`--offline`), large files are only included if already cached locally in
`.cache/large/`.

### Data directories

Some cores need entire directory trees rather than individual files (e.g. Dolphin's
`Sys/` directory, PPSSPP's `assets/`). These are fetched by `refresh_data_dirs.py`
from upstream repositories.

In offline mode, data directories are only included if already cached in `data/`.
Run `python scripts/refresh_data_dirs.py` to fetch them.

## verify.py reports errors

How to read and interpret `verify.py` output.

### Status codes

| Status | Meaning |
|--------|---------|
| `OK` | File present, hash matches (or existence check passed) |
| `UNTESTED` | File present, hash not confirmed against the expected value |
| `MISSING` | File not found in the repository |
| `DISCREPANCY` | The platform check passes, an emulator's own check fails |

### Reading the output

The first line counts the platform's files and names its check. Under it come
the entries that need attention, one per line as `STATUS (required|optional):
system/file`, followed by a reason where there is one, then the counts of the
files the emulator cores add. From `python scripts/verify.py --platform retrodeck`:

```
RetroDECK: 2007/2008 OK, 1 untested [md5]
  UNTESTED (required): nintendo-ds/dsifirmware.bin: declared hash contradicted by the local file
  DISCREPANCY: nintendo-snes/sgb2.boot.rom: RetroDECK says OK but supersnes9x says size mismatch: got 524288, accepted [256]
    supersnes9x [size]
  Core files: 1812 in pack, 0 required missing, 125 optional missing (--verbose lists them)
  Bundled with their emulator, not collected: 34 (cg.dll, cg2.dll, cgGL.dll, libCg.so, libCgGL.so, libstdc++.so.5, libstdc++.so.6, 27 more, --verbose lists them)
  Core files held but not packed: 155 (143 installed with its emulator, 8 read below a save folder per system and no system runs the core there, 4 a packed file occupies its directory)
  Game data: 5104 in pack, 31 missing (--verbose lists them)
  Game data held but not packed: 30 (installed with its emulator)
  No external files: 81 cores (--verbose lists them)
  Ground truth: 109/2008 files have emulator validation (5%)
    442 platform-only (no emulator profile)
```

The run prints more `DISCREPANCY` lines than this excerpt shows. The core
and game data lines count what the emulator cores add beyond the platform's
own list. A required core file the collection lacks is named under them, with
the emulator that needs it. A file held but not packed is left out for the
reason in parentheses, each reason with its count when the files have several.

`--verbose` also lists the passing entries that an emulator validates, with
the check and the source lines behind it:

```
Recalbox: 351/351 OK [md5]
  OK (required): macintosh/MacII.ROM
    minivmac validates size=262144 [minivmac/cfg/CNFGRAPI.h:32, minivmac/src/OSGLUERETRO.c:781]
```

### Cross-reference section

The `Core files` and `Game data` lines are the cross-reference: files that
emulator cores need but that the platform YAML does not declare. These files
are still included in packs automatically. A required one the collection lacks
is listed under the counts, and `--verbose` lists the optional ones too.

The cross-reference uses `resolve_platform_cores()` to determine which emulator
profiles are relevant for each platform, then checks whether the platform
already declares each profile's files (`declaration_settles()`). A name alone
is not enough. The declaration must fill the core's own slot or have a size the
core accepts: Galaksija's 4 KiB `ROM1.BIN` does not stand for DOSBox's 32 KiB
SC-55 one. An alias counts only at the path where the core reads it, so
RetroDECK's root `MSX.ROM` is not CLK's `MSX/MSX.ROM`. An archive counts by its
name.

### Filtering output

```bash
# By platform
python scripts/verify.py --platform batocera

# By emulator core
python scripts/verify.py --emulator beetle_psx

# By system
python scripts/verify.py --system sony-playstation

# By hardware target
python scripts/verify.py --platform retroarch --target switch

# JSON for scripted processing: the entries that need attention
python scripts/verify.py --platform retroarch --json
# every entry, passing ones included, with its ground truth
python scripts/verify.py --platform retroarch --json --verbose
```
