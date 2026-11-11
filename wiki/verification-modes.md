---
level: reference
order: 10
group: Checking files
---

# How each platform checks files

Most setups can show which BIOS files are missing. Each one checks differently.
RetroArch only asks whether a file with the right name is in the folder.
Batocera computes the file's MD5 and compares it with its list, so a
wrong-region file, or another file given the right name, shows as `UNTESTED`:
present, but not the expected file. BizHawk does the same with SHA1. A file
RetroArch accepts can still be one Batocera reports. The emulator, not the
check, is what fails when a game starts.

Example: `scph5501.bin`, MD5 `490f666e1afb15b7362b406ed1cea246`. Any file named
`scph5501.bin` passes on RetroArch. On Batocera only those exact bytes pass.

This project's `verify.py` reproduces each setup's own check, so its report
says what the setup itself would say. A missing file is then ranked by
**severity**, from the setup's check mode and the `required` flag of its list:
CRITICAL for a required file missing where the setup checks hashes, WARNING
for a required file missing where it checks names, or a hash in doubt, INFO
for an optional file or one the core replaces with a built-in fallback
([severity matrix](#severity-matrix)).

<!-- image: verification-modes -->

Each reference to a checker's code below links the revision of that code the
platform's own list was read from.

## Existence mode

**Platforms**: RetroArch, Lakka, RetroPie, MinUI, NextUI, MyMinUI

**Source**: RetroArch v1.22.2 [`core_info.c:2285`](https://github.com/libretro/RetroArch/blob/v1.22.2/core_info.c#L2285), `path_is_valid()`. For the MinUI family, minarch.

A file is OK if it exists at the expected path. No hash is checked. Any file
with the correct name passes, regardless of content.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| File present | OK | OK | OK |
| File missing | MISSING | WARNING | INFO |

RetroArch does not distinguish between a correct and an incorrect BIOS at the verification
level. A corrupt or wrong-region file still shows as present: RetroArch's
`core_info.c` only calls `path_is_valid()` and does not open or hash the file.

Lakka and RetroPie inherit this behavior through platform config inheritance
(`inherits: retroarch` in the platform YAML).

MinUI, NextUI and MyMinUI check nothing at all. They hand each core its own
folder, `Bios/<TAG>/`, and open nothing in it: minarch answers
`RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY` with that folder (MinUI [`workspace/all/minarch/minarch.c:1889-1893`](https://github.com/shauninman/MinUI/blob/dbf89435a5179788418ff3573042cf9c7e75d9e0/workspace/all/minarch/minarch.c#L1889-L1893) and [`:2943`](https://github.com/shauninman/MinUI/blob/dbf89435a5179788418ff3573042cf9c7e75d9e0/workspace/all/minarch/minarch.c#L2943)). The
core decides what it loads, so the files are the ones its profile documents,
placed below each folder a pak hands it (`core_system_dirs` in the platform
YAML).


## MD5 mode

**Platforms**: Batocera, RetroBat, Recalbox, EmuDeck, RetroDECK, RomM, ROCKNIX, KNULLI, AmberELEC, EmuELEC, MiSTer FPGA

All MD5-mode platforms compute a hash of the file and compare it against an expected value.
The details vary by platform.

### Standard MD5 (Batocera, RetroBat)

**Source**: Batocera 43.1 `batocera-systems`, [`md5sum()`](https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/package/batocera/core/batocera-scripts/scripts/batocera-systems#L987-L992) and
function [`checkBios`](https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/package/batocera/core/batocera-scripts/scripts/batocera-systems#L1047).

`verify.py` replicates Batocera's `md5sum()` function. The file is read in binary mode,
hashed with MD5, and compared case-insensitively against the expected value.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| Hash matches | OK | OK | OK |
| File present, hash differs | UNTESTED | WARNING | WARNING |
| File missing | MISSING | CRITICAL | WARNING |

If finding the file already confirmed the MD5 match (status `md5_exact` of the
[file resolution chain](#file-resolution-chain)), `verify.py` skips re-hashing
and returns OK directly.

### MD5 shorter than 32 characters (Batocera)

Batocera's script compares the full string ([`batocera-systems:1088`](https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/package/batocera/core/batocera-scripts/scripts/batocera-systems#L1088)), so an MD5
shorter than 32 characters matches no file there. The Batocera scraper completes such
a value when exactly one MD5 in `database.json` starts with it
(`_resolve_truncated_md5` in `scripts/scraper/batocera_scraper.py`) and keeps it as
written otherwise. `resolve_local_file` and `--from-md5` read a value still shorter
than 32 characters by the same rule (`cut_md5_owner` in `scripts/hashing.py`), and the
resolver keeps the file only when its name is one the entry names. Every verdict
compares whole digests, as Batocera does: a cut value never verifies a file.

### md5_composite (Recalbox ZIP verification)

Recalbox hashes a ZIP with `Zip::Md5Composite`
([`es-core/src/utils/Zip.cpp:71-96`](https://gitlab.com/recalbox/recalbox/-/blob/10.1.1/projects/frontend/es-core/src/utils/Zip.cpp#L71-96) in
Recalbox 10.1.1): one MD5 over the contents of every member, read in filename
order. The members' own MD5s are not involved, and neither is the MD5 of the ZIP
file itself: `Bios::Scan` takes the composite for every `.zip`
([`es-app/src/bios/Bios.cpp:86-91`](https://gitlab.com/recalbox/recalbox/-/blob/10.1.1/projects/frontend/es-app/src/bios/Bios.cpp#L86-91)). `verify.py` computes the same value with
`md5_composite()` (`scripts/hashing.py`).

The registry gives Recalbox `zip_digest: composite`. For a platform so marked, a
`.zip` entry is checked against its composite alone, by the resolver
(`resolve_local_file`) and by the pack check (`digest_verdict` in
`scripts/validation.py`). On other platforms the ZIP file's direct MD5 is tried first
and the composite after it.

### Multi-hash (Recalbox)

Recalbox allows comma-separated MD5 values for a single file entry, accepting any one
of them as valid. `verify.py` splits on commas and tries each hash. A match against any
listed hash is OK.

### Mandatory levels (Recalbox)

Recalbox colours each entry of `es_bios.xml` from two attributes, `mandatory` and
`hashMatchMandatory`, both true unless written `"false"`
([`es-app/src/bios/Bios.cpp:187-188`](https://gitlab.com/recalbox/recalbox/-/blob/10.1.1/projects/frontend/es-app/src/bios/Bios.cpp#L187-188) in
Recalbox 10.1.1, colours set by `Bios::Scan` at
[lines 106-130](https://gitlab.com/recalbox/recalbox/-/blob/10.1.1/projects/frontend/es-app/src/bios/Bios.cpp#L106-130)). The platform YAML carries them as
`required` and, when the attribute is written, `hash_match_mandatory`.

| File | mandatory | hashMatchMandatory | Recalbox | verify.py |
|------|-----------|--------------------|----------|-----------|
| hash matches | (any) | (any) | GREEN | OK |
| missing | true | (any) | RED | CRITICAL |
| missing | false | (any) | YELLOW | WARNING |
| hash differs | true | true | RED | WARNING |
| hash differs | true | false | YELLOW | WARNING |
| hash differs | false | (any) | YELLOW | WARNING |

`verify.py` applies the MD5-mode table above and does not read
`hash_match_mandatory`, so a present file whose hash differs is a WARNING where
Recalbox shows RED for a mandatory entry with `hashMatchMandatory`.

### checkInsideZip (Batocera zippedFile)

When a platform entry has a `zipped_file` field, the expected MD5 is not the hash of the
ZIP container but of a specific ROM file inside the ZIP. `verify.py` replicates Batocera's
[`checkInsideZip()`](https://github.com/batocera-linux/batocera.linux/blob/batocera-43.1/package/batocera/core/batocera-scripts/scripts/batocera-systems#L994):

1. Open the ZIP.
2. Find the inner file by name (case-insensitive via `casefold()`).
3. Read its contents and compute MD5.
4. Compare against the expected hash.

If the inner file is not found inside the ZIP, the status is UNTESTED with a reason string.

### RomM verification

**Source**: RomM 5.4.1 [`backend/models/firmware.py:58-76`](https://github.com/rommapp/romm/blob/5.4.1/backend/models/firmware.py#L58-L76), `Firmware.verify_file_hashes`

RomM reads the file's bytes (`verification_mode: md5`) but does not compare one
digest. Its platform YAML carries `hash_rule: size_and_any_hash`: the file's
size must equal the declared size, then any one of MD5, SHA1 and CRC32 must
match. An entry without a size never verifies, since RomM reads it as 0. A
wrong hash beside a right one does not withhold the file. `verify.py`, the
pack builder and the install manifest apply that rule. ZIP files are not
opened, only the container is checked.

`verification_mode` answers whether the frontend reads the bytes, and
`hash_rule` answers which comparison it makes. A frontend whose acceptance is
not a single digest gets a new `hash_rule` value, never a new mode.

### ROCKNIX verification

**Source**: ROCKNIX 20261101 [`rocknix-systems:137-197`](https://github.com/ROCKNIX/distribution/blob/20261101/projects/ROCKNIX/packages/rocknix/sources/scripts/rocknix-systems#L137-L197), function `checkBios`

ROCKNIX derives its BIOS checker from Batocera's, so the logic has the same
shape: `md5sum()` on the file, `checkInsideZip()` for archive entries, and an
`altmd5` field that accepts a second hash for the same entry. Every entry the
platform declares is mandatory in its own data, so the platform YAML marks every
file `required: true`, and none of them uses `zippedFile`.

### KNULLI, AmberELEC and EmuELEC verification

**Source**: function `checkBios` in [`knulli-systems:867-928`](https://github.com/knulli-cfw/knulli-linux/blob/20260511/package/system/knulli-scripts/scripts/knulli-systems#L867-L928)
(KNULLI 20260511), and in `batocera-systems` for
[AmberELEC](https://github.com/AmberELEC/AmberELEC/blob/a21975bfb1a3af68f66e07a931b994b523e1e6e2/packages/amberelec/sources/scripts/batocera-systems#L583-L644) and [EmuELEC 4.8](https://github.com/EmuELEC/EmuELEC/blob/v4.8/packages/sx05re/emuelec/bin/batocera/batocera-systems#L817-L834)

All three keep Batocera's `systems` dict and its checker, run by their
EmulationStation's BIOS screen.

- **KNULLI** runs Batocera's `checkBios` on files under `/userdata`: `md5sum()`,
  `checkInsideZip()` for `zippedFile` entries, and the `emulator`/`core` gates
  read from `es_systems.cfg`.
- **AmberELEC** runs the same checker on files under `/storage/roms`. Its list
  sets no gate, and names `neogeo/neogeo.zip` and `neogeo/aes.zip` beside
  `bios/`, so the pack extracts into `/storage/roms`.
- **EmuELEC** hashes the whole file under `/storage/roms` and never reads
  `zippedFile`: an entry that names a member inside an archive compares the
  archive's MD5 with the member's and reports `UNTESTED` whatever the archive
  holds. Its list also names game data under `ports/`.

A key written twice in the dict (`naomi` and `Dinothawr` in EmuELEC, `msx1`
and `msx2+` in KNULLI) keeps its later value, as when Python runs the script.

### MiSTer FPGA verification

**Source**: `Downloader_MiSTer`, `jobs/process_db_index_worker.py`

The MiSTer downloader hashes the file at its destination path and compares it
against the MD5 recorded in the BIOS database. There is no ZIP inspection and
no required/optional distinction: an entry either matches or it does not.

Scope note: only the BiosDB entries are in scope. They carry an explicit `url`
because MiSTer cannot host them, which is exactly what the user has to supply.
The `games/` files shipped by the `Distribution_MiSTer` repository carry no URL
and install themselves, so they are not part of the pack.


## SHA1 mode

**Platforms**: BizHawk

**Source**: BizHawk 2.11.1 [`FirmwareDatabase.cs`](https://github.com/TASEmulators/BizHawk/blob/2.11.1/src/BizHawk.Emulation.Common/Database/FirmwareDatabase.cs)

BizHawk firmware entries use SHA1 as the primary hash. `verify.py` computes SHA1
via `compute_hashes()` and compares case-insensitively.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| SHA1 matches | OK | OK | OK |
| File present, SHA1 differs | UNTESTED | WARNING | WARNING |
| File missing | MISSING | CRITICAL | WARNING |


## Emulator-level validation

Independent of platform verification mode, `verify.py` runs emulator-level validation
from `validation.py`. This layer uses data from emulator profiles (YAML files in
`emulators/`), which are source-verified against emulator code.

### Validation index

`_build_validation_index()` (`validation.py`) builds a per-filename index of
validation rules from the profiles it is given. A platform report, its pack and
its install manifest pass only the profiles `resolve_platform_cores` resolves for
that platform (`verify.py`, `verify_platform`). A profile that does not run on the
platform has nothing to say about its pack: standalone ZEsarUX reads a 48 KB
`cpc6128.rom` of its own, and its size check reported cap32's 32 KB file in the
RetroArch pack as a mismatch while every profile was indexed. The same holds for
`hle_fallback`, which is read from the same set of profiles. A report or pack for `--emulator` or `--system` indexes the
profiles it selected. When multiple emulators reference the same file, checks
are merged (union of all check types). Conflicting expected values are kept as sets
(e.g., multiple accepted CRC32 values for different ROM versions).

Each entry in the index tracks:

- `checks`: list of validation types (e.g., `["size", "crc32"]`)
- `sizes`: set of accepted exact sizes
- `min_size`, `max_size`: bounds when the code accepts a range
- `crc32`, `md5`, `sha1`, `sha256`: sets of accepted hash values
- `adler32`: set of accepted Adler-32 values
- `size_multiples`: granules a size must be a whole number of
- `rules[].content`: the content tests of each entry (`romdir`, `masked_sha1`) with their spec
- `crypto_only`: non-reproducible checks (see below)
- `per_emulator`: per-core detail with source references

### Check categories

Validation checks fall into two categories:

**Reproducible** (`_HASH_CHECKS`): `crc32`, `md5`, `sha1`, `adler32`. These can be
computed from the file alone. `verify.py` calculates hashes and compares against
accepted values from the index.

**Non-reproducible** (`_CRYPTO_CHECKS`): `signature`, `crypto`. These require
console-specific cryptographic keys (e.g., RSA-2048 for 3DS, AES-128-CBC for certain
firmware). `verify.py` reports these as informational but cannot verify them without
the keys. Size checks still apply if combined with crypto.

**Content tests** (`CONTENT_CHECKS` in `common.py`): `romdir` walks a PS2 ROM
directory the way the profile's fork reads it (`scripts/romdir.py`), and
`masked_sha1` hashes a file with a byte range cleared. `content_fits()` runs them,
and the name steps of the resolver, the folder scans of the pack and manifest,
the emulator expansion and `verify.py` all call it, so they accept and refuse the
same files.

### Size validation

Three forms:

- **Exact size**: `size: 524288` with `validation: [size]`. File must be exactly this many bytes.
- **Range**: `min_size: 40`, `max_size: 131076` with `validation: [size]`. File size must fall within bounds.
- **Informational**: `size: 524288` without `validation: [size]`. The size is documented but the emulator does not check it at runtime.

### Complement to platform checks

Emulator validation runs after platform verification. When a file passes platform checks
(e.g., existence-mode OK) but fails emulator validation (e.g., wrong CRC32), the result
includes a `discrepancy` field:

```
file present (OK) but handy says size mismatch: got 256, accepted [512]
```

This catches cases where a file has the right name but wrong content, which existence-mode
platforms cannot detect.


## Severity matrix

`compute_severity()` maps the combination of status, required flag, verification mode,
and HLE fallback to a severity level.

| Mode | Status | required | hle_fallback | Severity |
|------|--------|----------|--------------|----------|
| any | OK | any | any | OK |
| any | MISSING | any | true | INFO |
| existence | MISSING | true | false | WARNING |
| existence | MISSING | false | false | INFO |
| md5/sha1 | MISSING | true | false | CRITICAL |
| md5/sha1 | MISSING | false | false | WARNING |
| md5/sha1 | UNTESTED | any | false | WARNING |

**HLE fallback**: when an emulator profile marks a file with `hle_fallback: true`, the
core has a built-in high-level emulation path and functions without the file. Missing
files are downgraded to INFO regardless of platform mode or required status. The file
is still included in packs (better accuracy with the real BIOS), but its absence is not
actionable.

**Firmware, game data, unread**: a platform's list can name more than firmware.
EmuELEC lists the data files of the games its ports run (Diablo's `diabdat.mpq`, the
Sonic `Data.rsdk` files), and AmberELEC lists a `hardwareconfig.xml` in each blueMSX
machine folder, a file blueMSX never opens. Each missing entry gets one of three
categories, read from the profiles of the cores the platform runs:

| Category | When | Severity |
|----------|------|----------|
| firmware | a core reads it as firmware, or nothing settles the question | from the matrix above |
| game data | only `category: game_data` entries of those profiles name it | none, counted apart |
| unread | the platform declares its cores, the cores of the entry's system all have a profile, at least one of them emulates it, and no examined core opens the entry | none, counted apart |

The cores of a system are the ones the platform's file lists for it (`cores:` on the
system, read from the platform's own emulator menu: KNULLI, AmberELEC and EmuELEC
carry it). Where a system has no such list, every core the platform names counts.

Every entry, held or missing, carries what establishes its category: the profile
entries that read it, with their source reference, or the cores of its system that
were examined and found no reader, or the reason the question stays open. A reader
whose core runs the entry's system is named first. A core of another system that
declares a file of the same name is listed after it as "also named by".
`--verbose` prints it under a missing entry, `--json` carries it as
`category_evidence` on each entry, and each platform page shows it under every
file. Only a missing entry's category changes its severity.

The report counts the last two on a line of their own (`Missing, not firmware: ...`)
and `--verbose` names them. They stay in the platform's file and in the totals, but
`--strict` fails on firmware gaps only, and the pack check does not count them as
pack errors. A core of the system that has no profile yet makes nothing unread.
The same goes for a system none of the examined cores emulates: in both cases the
absence of a reader proves nothing.

The same category filters: `--no-game-data` builds, verifies and installs the
firmware without the game data, and the install manifest marks each game data
file `"category": "game_data"`
([details](advanced-usage.md#firmware-without-game-data)).


## File resolution chain

Before verification, each file entry is resolved to a local path by `resolve_local_file()`.
The function tries these steps in order, returning the first
evidence-compatible match:

| Step | Method | Returns | When it applies |
|------|--------|---------|-----------------|
| 1 | SHA1 | `sha1_exact` | A declared SHA1 identifies a database record, and every other declared hash must agree with that same record |
| 2 | SHA256 | `sha256_exact` | A declared SHA256 identifies a record, again requiring all declarations to agree |
| 3 | CRC32 plus size | `crc32_exact` | Used only when no stronger hash is declared. Size confirms the weaker checksum when available |
| 4 | MD5 | `md5_exact` | Direct lookup. An explicitly supported truncated MD5 also needs a compatible name |
| 5 | Path suffix | `path_exact` or a hash-exact status | Disambiguates regional paths. With any declared hash, the path is accepted only when the content matches it. A platform declaration with no hash then looks for its destination's tail in the data directories: AmberELEC's `Machines/MSX - Arabic/config.ini` is blueMSX's, never the first `config.ini` the name step meets |
| 6 | Name or alias | `name_exact` | Existence/size resolution only when no content hash is declared. Prefers primary files and supports casefold matching |
| 7 | Named candidate inspection | `md5_composite_exact`, `md5_exact`, or `hash_mismatch` | Checks composite ZIP MD5 or direct MD5. A matching name with wrong content is surfaced, never treated as exact |
| 8 | ZIP contents index | `zip_exact` | `zipped_file` with MD5. Searches the inner-ROM index only after name-based resolution fails |
| 9 | MAME clone | `mame_clone` | Resolves a deduplicated clone to its canonical set only when no content hash was declared |
| 10 | Data directory | `data_dir` or `data_dir_hash_exact` | Searches exact path then case-insensitive basename, then computes every declared hash before accepting an unindexed candidate |
| 11 | Agnostic fallback | `agnostic_fallback` | Size/path constrained lookup only when no content hash was declared |

If no step matches, the result is `(None, "not_found")`.

Two kinds of entry skip every answer given by a name alone: steps 6 and 9, the
`hash_mismatch` of step 7, and the name lookup of step 10 when no hash is declared.

- An entry whose profile carries `unsourceable:`. The collection cannot hold that
  file, so a file answering to its name belongs to something else: `kanji.rom`
  names an FPseNG font, an openMSX font and a 3DO ROM.
- An entry whose full destination path is in the `by_path_suffix` index while no
  indexed copy is on disk. That file is a release asset the checkout has not
  restored (`scripts/restore_large_files.py`), and another file of the same name
  is not it.

The content steps still apply to both, so collecting the real bytes, or restoring
the asset, makes the entry resolve.

A platform's own entry with no hash, whose system id names a maker (`nec-pc-88`
names `NEC`), takes no file filed under another maker's folder in steps 6 and 7.
`bios/Other/` and `bios/Arcade/` file copies by emulator and stay open to it.
`load_platform_config` writes the system on each entry as `platform_system`. When
no copy is left, step 6 reads `by_shadowed_alias`, the profile aliases that
`by_name` refuses because a primary already carries the name, and keeps only the
files under the system's maker. AmberELEC's `DISK.ROM` got the 16 KB MSX disk ROM
by name. QUASI88 reads that name as `n88sub.rom`, the 2 KB PC-88 disk ROM, and
that is now the file served. An entry that names its emulator is placed by that
emulator's tree instead.

Step 6 reads a name through `by_proven_name` first. A name lands there when no
declaration of it proves the held file by hash, while declarations of it prove
another primary in the same directory. `dsi_bios7.bin` holds the DSi Panda devkit
boot ROM, whose eMMC key-Y is zeroed, and every md5 and crc32 declared under that
name designates a retail dump: an entry with no hash gets the retail ROM.

The `hash_mismatch` status means a file with the right name or path exists but its hash
does not match. This still resolves to a local path (the file is present), but verification
will report it as UNTESTED with a reason string showing the expected vs actual hash prefix.

A path or filename is never allowed to mask a declared strong hash: the
identity steps run first, and a path or name is accepted only when no content
hash was declared or when the content agrees with the one that was.

What the pack does with a `hash_mismatch` is set by the platform's mode, as
[discrepancy detection](#discrepancy-detection) describes.


## Discrepancy detection

When platform verification passes but emulator validation fails, the file has a discrepancy.
This happens most often in existence-mode platforms where any file with the right name is
accepted.

A local file that contradicts a declared hash is handled by the platform's
own mode, never by one global rule. An existence frontend never reads the
bytes, so the file is packed and the difference reported: a hash in System.dat
that differs from the local dump must not remove a file RetroArch would have
loaded. An md5 or sha1 frontend would report it as not the expected file
(Batocera's `checkBios` marks it `UNTESTED`), so it is left out of the pack
and counted as `unsafe excluded`, left out because the platform would not
accept it, which is distinct from `missing`. The pack
report and the installer manifest both record it. The pack builder and the
pack verification apply the same rule.

### Variant search

`validated_choice()` (`scripts/validation.py`) decides the file a platform
destination ships when the emulators reading that destination check it. The
pack, verify and the install manifest all read it, so they name the same file.

1. Only the cores that read this destination judge it: a core checking the
   same name at another path has no say (ZEsarUX's 48 KB `cpc6128.rom` check
   does not judge `ep128emu/roms/cpc6128.rom`).
2. The resolved file is kept when every check of those cores passes.
3. Otherwise `find_validated_variant()` looks for a held file that passes them
   all, warning-level checks included. Candidates come first from the hashes
   the emulator declares, which finds a dump stored under another name, then
   from the files sharing the name, `.variants/` included, in a stable order.
   On a md5 or sha1 platform a candidate must also carry a value the platform
   entry declares, or the frontend's own check would not accept it.
4. When only a warning-level check fails (`on_mismatch: warn`), the file
   itself stands: the core runs it.
5. Then a held file the core at least runs.
6. Failing all of these, the platform-verified file is kept and the
   disagreement is reported ("<core> says ..."), never as compatible.

### Worked example

RetroBat lists `dragon/d64_1.rom` with MD5 `5f0bee59710e55f5880e74890912ed78`
(`platforms/retrobat.yml`). The collection holds that dump, CRC32 `60a4634c`,
and RetroBat's check passes. XRoar, which RetroBat runs for the Dragon, checks
the CRC32 of the same file and accepts `84f68bf9` only. The collection holds a
dump with that CRC32 too (`bios/Dragon/Dragon/d64_1.rom`), but its MD5 is
`be9bc86ee5eb401d0a40d0377f65fefa`, not the one RetroBat lists, so RetroBat
would not accept it at that path (step 3). The RetroBat file ships, and the
[gaps page](../gaps.md) lists the discrepancy with the dump XRoar accepts.

## Next steps

- [Reading this project's own reports](reading-reports.md): `verify.py` output,
  status codes and severity levels
- [What the packs do not hold](../gaps.md)
