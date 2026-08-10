# Verification Modes

Each platform verifies BIOS files differently. `verify.py` replicates the native behavior
of each platform so that verification results match what the platform itself would report.


## Existence Mode

**Platforms**: RetroArch, Lakka, RetroPie

**Source**: RetroArch `core_info.c`, function `path_is_valid()`

The most straightforward mode. A file is OK if it exists at the expected path. No hash is checked.
Any file with the correct name passes, regardless of content.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| File present | OK | OK | OK |
| File missing | MISSING | WARNING | INFO |

RetroArch does not distinguish between a correct and an incorrect BIOS at the verification
level. A corrupt or wrong-region file still shows as present. This is by design in the
upstream code: `core_info.c` only calls `path_is_valid()` and does not open or hash the file.

Lakka and RetroPie inherit this behavior through platform config inheritance
(`inherits: retroarch` in the platform YAML).


## MD5 Mode

**Platforms**: Batocera, RetroBat, Recalbox, EmuDeck, RetroDECK, RomM, ROCKNIX, MiSTer FPGA

All MD5-mode platforms compute a hash of the file and compare it against an expected value.
The details vary by platform.

### Standard MD5 (Batocera, RetroBat)

`verify.py` replicates Batocera's `md5sum()` function. The file is read in binary mode,
hashed with MD5, and compared case-insensitively against the expected value.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| Hash matches | OK | OK | OK |
| File present, hash differs | UNTESTED | WARNING | WARNING |
| File missing | MISSING | CRITICAL | WARNING |

If the `resolve_local_file` step already confirmed the MD5 match (status `md5_exact`),
`verify.py` skips re-hashing and returns OK directly.

### Truncated MD5 (Batocera bug)

Some entries in Batocera's system data contain 29-character MD5 strings instead of
the standard 32. This is a known upstream bug. `verify.py` handles it by prefix matching:
if the expected hash is shorter than 32 characters, the actual hash is compared against
only its first N characters.

### md5_composite (Recalbox ZIP verification)

Recalbox computes `Zip::Md5Composite` for ZIP files: the MD5 of the concatenation of all
inner file MD5s (sorted by filename). `verify.py` replicates this with `md5_composite()`
from `common.py`. When a ZIP file's direct MD5 does not match, the composite is tried
before reporting a mismatch.

### Multi-hash (Recalbox)

Recalbox allows comma-separated MD5 values for a single file entry, accepting any one
of them as valid. `verify.py` splits on commas and tries each hash. A match against any
listed hash is OK.

### Mandatory levels (Recalbox)

Recalbox uses three severity levels derived from two YAML fields (`mandatory` and
`hashMatchMandatory`):

| mandatory | hashMatchMandatory | Color  | verify.py mapping |
|-----------|--------------------|--------|-------------------|
| true      | true               | RED    | CRITICAL          |
| true      | false              | YELLOW | WARNING           |
| false     | (any)              | GREEN  | WARNING           |

### checkInsideZip (Batocera zippedFile)

When a platform entry has a `zipped_file` field, the expected MD5 is not the hash of the
ZIP container but of a specific ROM file inside the ZIP. `verify.py` replicates Batocera's
`checkInsideZip()`:

1. Open the ZIP.
2. Find the inner file by name (case-insensitive via `casefold()`).
3. Read its contents and compute MD5.
4. Compare against the expected hash.

If the inner file is not found inside the ZIP, the status is UNTESTED with a reason string.

### RomM verification

RomM uses MD5 verification (`verification_mode: md5`). The platform YAML stores
SHA1, MD5, and CRC32 for reference, but `verify.py` checks only the MD5 field,
matching the platform's runtime behavior. ZIP files are not opened; only the
container is checked.

### ROCKNIX verification

**Source**: `rocknix-systems`, function `checkBios`

ROCKNIX derives its BIOS checker from Batocera's, so the logic has the same
shape: `md5sum()` on the file, `checkInsideZip()` for archive entries, and an
`altmd5` field that accepts a second hash for the same entry. Every entry the
platform declares is mandatory in its own data, so the platform YAML marks all
38 files `required: true` and none of them use `zippedFile`.

### MiSTer FPGA verification

**Source**: `Downloader_MiSTer`, `jobs/process_db_index_worker.py`

The MiSTer downloader hashes the file at its destination path and compares it
against the MD5 recorded in the BIOS database. There is no ZIP inspection and
no required/optional distinction: an entry either matches or it does not.

Scope note: only the BiosDB entries are in scope. They carry an explicit `url`
because MiSTer cannot host them, which is exactly what the user has to supply.
The 208 `games/` files shipped by the `Distribution_MiSTer` repository carry no
URL and install themselves, so they are not part of the pack.


## SHA1 Mode

**Platforms**: BizHawk

BizHawk firmware entries use SHA1 as the primary hash. `verify.py` computes SHA1
via `compute_hashes()` and compares case-insensitively.

| Condition | Status | Severity (required) | Severity (optional) |
|-----------|--------|---------------------|---------------------|
| SHA1 matches | OK | OK | OK |
| File present, SHA1 differs | UNTESTED | WARNING | WARNING |
| File missing | MISSING | CRITICAL | WARNING |


## Emulator-Level Validation

Independent of platform verification mode, `verify.py` runs emulator-level validation
from `validation.py`. This layer uses data from emulator profiles (YAML files in
`emulators/`), which are source-verified against emulator code.

### Validation index

`_build_validation_index()` reads all emulator profiles and builds a per-filename
index of validation rules. When multiple emulators reference the same file, checks
are merged (union of all check types). Conflicting expected values are kept as sets
(e.g., multiple accepted CRC32 values for different ROM versions).

Each entry in the index tracks:

- `checks`: list of validation types (e.g., `["size", "crc32"]`)
- `sizes`: set of accepted exact sizes
- `min_size`, `max_size`: bounds when the code accepts a range
- `crc32`, `md5`, `sha1`, `sha256`: sets of accepted hash values
- `adler32`: set of accepted Adler-32 values
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


## Severity Matrix

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


## File Resolution Chain

Before verification, each file entry is resolved to a local path by `resolve_local_file()`.
The function tries these steps in order, returning the first
evidence-compatible match:

| Step | Method | Returns | When it applies |
|------|--------|---------|-----------------|
| 1 | SHA1 | `sha1_exact` | A declared SHA1 identifies a database record; every other declared hash must agree with that same record |
| 2 | SHA256 | `sha256_exact` | A declared SHA256 identifies a record, again requiring all declarations to agree |
| 3 | CRC32 plus size | `crc32_exact` | Used only when no stronger hash is declared; size confirms the weaker checksum when available |
| 4 | MD5 | `md5_exact` | Direct lookup; an explicitly supported truncated MD5 also needs a compatible name |
| 5 | Path suffix | `path_exact` or a hash-exact status | Disambiguates regional paths. With any declared hash, the path is accepted only when the content matches it |
| 6 | Name or alias | `name_exact` | Existence/size resolution only when no content hash is declared; prefers primary files and supports casefold matching |
| 7 | Named candidate inspection | `md5_composite_exact`, `md5_exact`, or `hash_mismatch` | Checks composite ZIP MD5 or direct MD5. A matching name with wrong content is surfaced, never treated as exact |
| 8 | ZIP contents index | `zip_exact` | `zipped_file` with MD5; searches the inner-ROM index only after name-based resolution fails |
| 9 | MAME clone | `mame_clone` | Resolves a deduplicated clone to its canonical set only when no content hash was declared |
| 10 | Data directory | `data_dir` or `data_dir_hash_exact` | Searches exact path then case-insensitive basename; computes every declared hash before accepting an unindexed candidate |
| 11 | Agnostic fallback | `agnostic_fallback` | Size/path constrained lookup only when no content hash was declared |

If no step matches, the result is `(None, "not_found")`.

The `hash_mismatch` status means a file with the right name or path exists but its hash
does not match. This still resolves to a local path (the file is present), but verification
will report it as UNTESTED with a reason string showing the expected vs actual hash prefix.

A path or filename is never allowed to mask a declared strong hash: the
identity steps run first, and a path or name is accepted only when no content
hash was declared or when the content agrees with the one that was.

What the pack does with a `hash_mismatch` follows the platform's own mode. An
MD5 or SHA1 platform would reject those bytes, so the file is left out and
counted as an unsafe exclusion, distinct from a file the collection does not
have. An existence platform reads no bytes at all, so the file is packed and
the divergence is printed as a discrepancy: an error in an upstream BIOS list
must not remove a file the frontend would have loaded.


## Discrepancy Detection

When platform verification passes but emulator validation fails, the file has a discrepancy.
This happens most often in existence-mode platforms where any file with the right name is
accepted.

### Variant search

`_find_best_variant()` searches for an alternative file in the repository that satisfies
both the platform MD5 requirement and emulator validation:

1. Look up all files with the same name in the `by_name` index.
2. Skip the current file (already known to fail validation).
3. For each candidate, check that its MD5 matches the platform expectation.
4. Run `check_file_validation()` against the candidate.
5. Return the first candidate that passes both checks.

The search covers files in `.variants/` (alternate hashes stored during deduplication).
If a better variant is found, the pack uses it instead of the primary file. If no variant
satisfies both independent contracts, the platform-verified baseline is retained but the
emulator discrepancy remains explicit; it is never reported as source-compatible.

### Practical example

A `scph5501.bin` file passes Batocera MD5 verification (hash matches upstream declaration)
but fails the emulator profile's size check because the profile was verified against a
different revision. `_find_best_variant` scans `.variants/scph5501.bin.*` for a file
that matches both the Batocera MD5 and the emulator's size expectation. If found, the
variant is used in the pack. If not, the Batocera-verified baseline is retained and the
emulator discrepancy stays visible in verification and gap reporting.
