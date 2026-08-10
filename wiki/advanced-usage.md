# Advanced Usage

Fine-grained control over pack generation, hardware filtering, truth analysis, and verification.

## Custom Packs

### Build from hash

Look up a single MD5 in the database:

```bash
python scripts/generate_pack.py --from-md5 d8f1206299c48946e6ec5ef96d014eaa
```

Build a pack containing only files matching hashes from a list (one MD5 per line, `#` for comments):

```bash
python scripts/generate_pack.py --platform batocera --from-md5-file missing.txt
```

This is useful when a platform reports missing files and you want to generate a targeted pack
rather than re-downloading the full archive.

### Split packs

Generate one ZIP per system instead of a single monolithic pack:

```bash
python scripts/generate_pack.py --platform retroarch --split
```

Group the split ZIPs by manufacturer (Sony, Nintendo, Sega, etc.):

```bash
python scripts/generate_pack.py --platform retroarch --split --group-by manufacturer
```

### System-specific packs

Extract only the files for a single system within a platform:

```bash
python scripts/generate_pack.py --platform retroarch --system sony-playstation
```

### Required only

Exclude optional files from the pack:

```bash
python scripts/generate_pack.py --platform batocera --required-only
```

What counts as "required" depends on the platform YAML. For existence-mode platforms
(RetroArch), the distinction comes from the `.info` file's `required` field.
For MD5-mode platforms (Batocera), all declared files are treated as required unless
explicitly marked optional.

### Region filtering

Keep one regional BIOS per system instead of all of them:

```bash
python scripts/generate_pack.py --platform retroarch --region us
python scripts/generate_pack.py --platform retroarch --region us,eu,jp
```

The list is an **ordered priority**, best first, the same model ROM managers use
for 1G1R. `--region us,eu,jp` means prefer North America, fall back to Europe,
fall back to Japan. It does not mean "keep all three": when a US BIOS exists for
a system, the European and Japanese ones are dropped.

Accepted names are territory slugs (`japan`, `north-america`, `europe`,
`south-korea`, `taiwan`, `brazil`, `france`...) plus short aliases (`jp`, `us`,
`eu`, `kr`) and the signal spellings (`ntsc-j`, `ntsc-u`, `pal`). Territories
nest, so `--region europe` keeps a BIOS declared `[france]`, and `--region france`
keeps one declared `[europe]`.

Three rules keep a filtered pack usable:

- **No system is ever emptied.** If nothing matches, the whole group is kept.
  `--region us` still ships `disksys.rom`, because the Famicom Disk System has no
  American BIOS.
- **Region-free files always survive.** `psxonpsp660.bin`, `ps1_rom.bin` and
  `openbios.bin` are declared `[world]`; they add a capability rather than
  competing regionally.
- **Untagged files always survive.** Most BIOS are not regional and carry no
  `region:` at all.

What this does and does not do: it shrinks the pack. It does not change how cores
pick a BIOS. Most cores already select per region from fixed filename lists driven
by the game's region (PicoDrive in `libretro.c`, Genesis Plus GX in `loadrom.c`),
so a USA game already gets the US BIOS when it is present. Only cores that load a
single unqualified file change behaviour. Loading imports from another region may
need the unfiltered pack.

Verification takes the same flag, and needs it: a filtered pack checked without it
reports every dropped file as missing.

```bash
python scripts/generate_pack.py --platform recalbox --region us --verify-packs
python scripts/verify.py --platform recalbox --region us
python scripts/verify.py --emulator duckstation --region us
python scripts/verify.py --system sony-playstation --region us
```

`verify.py --region` narrows the coverage report to the same file set, through the
same selection function, so the two never disagree: `--emulator duckstation`
reports 105 files, `--emulator duckstation --region us` reports 34, and a pack
built with the same flags carries exactly those 34.

`--region` composes with `--split`, `--target`, `--required-only`, `--source`,
`--emulator` and `--system`. It is mutually exclusive with `--from-md5`, which
selects by hash. `pipeline.py` never passes it, so the released packs stay
complete.

Region and target both appear in the output filename
(`RetroArch_v1.22.2_NorthAmerica_Switch_BIOS_Pack.zip`,
`install/retroarch_northamerica_switch.json`), so a filtered build can never
overwrite the full one.


## Pack Source Variants

A pack is built from two file sources: the platform's own declared list
(layer 1) and the requirements of the emulator profiles that apply to it
(layer 3). `--source` selects which of the two contributes.

| `--source` | Contents | Name suffix |
|-----------|----------|-------------|
| `full` (default) | platform baseline plus everything its cores need | none |
| `platform` | only what the platform itself declares | `_Platform` |
| `truth` | only what the emulator profiles require | `_Truth` |

`--required-only` crosses with each of them and adds `_Required`:

```bash
python scripts/generate_pack.py --platform retroarch --source platform
python scripts/generate_pack.py --platform retroarch --source truth --required-only
python scripts/generate_pack.py --all --all-variants --output-dir dist/
```

`--all-variants` builds all six combinations in one run, producing names like
`RetroArch_Lakka_v1.22.2_BIOS_Pack.zip`,
`RetroArch_Lakka_v1.22.2_Platform_BIOS_Pack.zip` and
`RetroArch_Lakka_v1.22.2_Truth_Required_BIOS_Pack.zip`.

Which one to pick: `full` is the one to ship, since it covers alternate cores
and optional firmware. `platform` is much smaller and matches exactly what the
frontend checks for, which suits SD cards and handhelds. `truth` is a
diagnostic build: it shows what the emulator source code asks for, independent
of what the platform declares, and is how a gap between the two becomes
visible.

Variants compose with `--split`, `--target` and `--manifest`.


## Hardware Target Filtering

### What targets are

A target represents a hardware architecture where a platform runs. Each architecture
has a different set of available cores. For example, the RetroArch Switch target
has fewer cores than the x86_64 target because some cores are not ported to ARM.

Target data is scraped from upstream sources (buildbot nightly listings, board configs,
scriptmodules) and stored in `platforms/targets/<platform>.yml`.

### Usage

Filter packs or verification to only include systems reachable by cores available
on the target hardware:

```bash
python scripts/generate_pack.py --platform retroarch --target switch
python scripts/generate_pack.py --all --target x86_64
python scripts/verify.py --platform batocera --target rpi4
```

When combined with `--all`, platforms that define the target are filtered. Platforms
without a target file for that name are left unfiltered (no information to exclude anything).
Platforms that have target data but not the requested target are skipped with an INFO message.

### How it works

The filtering pipeline has three stages:

1. **`load_target_config()`** reads `platforms/targets/<platform>.yml` and returns
   the set of cores available on the target. Aliases from `_overrides.yml` are resolved
   (e.g., `--target rpi4` may match `bcm2711` in the target file).

2. **`resolve_platform_cores()`** determines which emulator profiles are relevant
   for the platform, then intersects the result with the target's core set. The
   intersection uses a reverse index built from each profile's `cores:` field, so
   that upstream names (e.g., `mednafen_psx` on the buildbot) map to profile keys
   (e.g., `beetle_psx`).

3. **`filter_systems_by_target()`** removes platform systems where every core that
   emulates them is absent from the target. Systems with no core information are kept
   (benefit of the doubt). System ID normalization strips manufacturer prefixes and
   separators so that `xbox` matches `microsoft-xbox`.

### List available targets

```bash
python scripts/verify.py --platform retroarch --list-targets
```

### Overrides

`platforms/targets/_overrides.yml` provides two mechanisms:

- **Aliases**: map user-facing names to internal target IDs
  (e.g., `rpi4` -> `bcm2711`).
- **add/remove cores**: patch the scraped core list for a specific target
  without overwriting the entire file. Useful when a core is known to work
  but is not listed on the buildbot, or vice versa.

### Single-target platforms

Platforms with only one target (e.g., RetroBat with `windows`, RomM with `browser`)
treat `--target <their-only-target>` as a no-op: the output is identical to running
without `--target`.


## Truth Generation and Diffing

### What truth is

Truth data is ground truth generated from emulator profiles. It represents what each
core actually needs based on source code analysis, independent of what platform
scrapers declare. The purpose is gap analysis: finding files that platforms miss
or declare incorrectly.

### Generate truth

Build truth YAMLs from emulator profiles for a platform or all platforms:

```bash
python scripts/generate_truth.py --platform retroarch
python scripts/generate_truth.py --all --output-dir dist/truth/
```

Each truth YAML lists every system with its files, hashes, and the emulator profiles
that reference them. The output mirrors the platform YAML structure so the two can
be diffed directly.

### Diff truth vs scraped

Find divergences between generated truth and scraped platform data:

```bash
python scripts/diff_truth.py --platform retroarch
python scripts/diff_truth.py --all
```

The diff reports:

- Files present in truth but absent from the platform YAML (undeclared).
- Files present in the platform YAML but absent from truth (orphaned or from cores
  not profiled yet).
- Hash mismatches between truth and platform data.

### Export to native formats

Convert truth data to the native format each platform consumes:

```bash
python scripts/export_native.py --platform batocera    # Python dict (batocera-systems)
python scripts/export_native.py --platform recalbox    # XML (es_bios.xml)
python scripts/export_native.py --all --output-dir dist/upstream/
```

This allows submitting corrections upstream in the format maintainers expect.


## Emulator-Level Verification

### Per-emulator checks

Verify files against a single emulator's ground truth (size, hashes, crypto):

```bash
python scripts/verify.py --emulator handy
python scripts/verify.py --emulator handy --verbose
```

Default output shows aggregate results per file: the core name and which checks apply.
With `--verbose`, each file expands to one line per core with the exact validation
parameters and source code reference:

```
lynxboot.img
  handy validates size=512 crc32=0x0d973c9d [src/handy/system.h:45]
```

### Per-system checks

Aggregate verification across all cores that emulate a system:

```bash
python scripts/verify.py --system atari-lynx
```

### Standalone mode

Some cores have both libretro and standalone modes with different file requirements.
Filter to standalone-only:

```bash
python scripts/verify.py --emulator dolphin --standalone
```

### Ground truth in verbose output

The verbose report includes a coverage footer:

```
Ground truth: 142/160 files have emulator validation (88%)
```

This indicates how many files in the platform can be cross-checked against source-verified
emulator profiles. Files without ground truth rely solely on platform-level verification.
JSON output (`--json`) always includes the full per-emulator detail regardless of verbosity.


## Offline Workflow

### Full offline pipeline

Run the entire pipeline without network access:

```bash
python scripts/pipeline.py --offline
```

This skips data directory refresh, MAME/FBNeo hash fetch, and buildbot staleness checks.
All other steps (database generation, verification, pack building, consistency check,
README, site generation) run normally using cached data.

### Partial runs

Skip pack generation when you only need verification results:

```bash
python scripts/pipeline.py --offline --skip-packs
```

Skip documentation generation:

```bash
python scripts/pipeline.py --offline --skip-docs
```

### Truth pipeline

Include truth generation and diffing in the pipeline:

```bash
python scripts/pipeline.py --offline --with-truth
```

Include truth + native format export:

```bash
python scripts/pipeline.py --offline --with-export
```

### Combining flags

Flags compose freely:

```bash
python scripts/pipeline.py --offline --skip-docs --with-truth --target switch
```

This runs: database generation, verification (filtered to Switch cores), truth generation
and diff, consistency check. Packs and docs are skipped, no network access.
