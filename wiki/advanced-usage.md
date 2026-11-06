---
level: contribute
order: 80
---

# Build your own packs

Fine-grained control over pack generation, hardware filtering, truth analysis (the file
list a platform would have if it were written from the emulators' code) and
verification.

The [latest release](https://github.com/Abdess/retrobios/releases/latest)
carries a pack for the setups most people download (`release_pack: true` in
`platforms/_registry.yml`), and the installer serves the others. A pack holds
everything its platform runs: the BIOS list it publishes, plus every file its emulator cores
load, read from their source code. There is no lighter variant to choose,
because a pack that leaves out a file a core needs means a game that does not
boot, with no message saying why. It is not a guarantee either: source
profiles can document files nobody has dumped or that only the user can
provide, all of them visible in the [gap analysis](../gaps.md).

From a clone of the repository, `python scripts/generate_pack.py --platform
retroarch --region us` builds a narrower pack, `--required-only` the bare
minimum each core needs to start, and `--no-game-data` keeps the firmware and
leaves out the files a game reads. `--help` lists every way to build your own,
and the sections below describe each one.

## Custom packs

### Build from hash

Look up a single MD5 in the database:

```bash
python scripts/generate_pack.py --from-md5 490f666e1afb15b7362b406ed1cea246
```

It prints the file's name, hashes, path and whether the collection holds it,
and exits 1 when a hash is not in the database, so a script can tell.

Build a pack containing only files matching hashes from a list. Each line
carries one hash (MD5, SHA-1 or CRC32), alone or beside a file name as
`md5sum` writes it. A `#` starts a comment:

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

The parts together hold exactly the files of the full pack, so every part
can be extracted into the same folder. Core files of a system the platform
does not list go in an `Other_Cores` part.

### System-specific packs

Extract only the files for a single system within a platform:

```bash
python scripts/generate_pack.py --platform retroarch --system sony-playstation
python scripts/generate_pack.py --platform batocera --system psx
python scripts/verify.py --platform batocera --system psx
```

Beside `--platform`, `--system` accepts the platform's own name for a system
as well as our id: `psx` is what Batocera calls `sony-playstation`, and both
build the same pack. The names come from `native_system` in the platform
YAML, the mapping the installer reads as `system_names`, and
`--platform batocera --list-systems` shows them after each id. A comma-separated
value that is itself one name stays one name (Recalbox's `msx1,msx2`). A name
the platform does not know is refused with the closest matches before the
database is read.

### Required only

Exclude optional files from the pack:

```bash
python scripts/generate_pack.py --platform batocera --required-only
```

What counts as "required" depends on the platform YAML. For existence-mode platforms
(RetroArch), the distinction comes from the `.info` file's `required` field.
For MD5-mode platforms (Batocera), all declared files are treated as required unless
explicitly marked optional.

An emulator or system pack keeps the files and trees its profiles do not mark
`required: false`, and an archive unless it and every ROM it carries are
optional. `verify.py` takes the same flag and reports on that pack:

```bash
python scripts/verify.py --platform batocera --required-only
python scripts/verify.py --emulator mame --required-only
```

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
`south-korea`, `taiwan`, `brazil`, `france`...) plus short aliases (`us`, `eu`,
and the ISO 3166 code of each territory: `jp`, `kr`, `au`, `br`, `fr`...) and
the signal spellings (`ntsc-j`, `ntsc-u`, `pal`). Territories
nest, so `--region europe` keeps a BIOS declared `[france]`, and `--region france`
keeps one declared `[europe]`.

Three rules keep a filtered pack usable:

- **No system is ever emptied.** If nothing matches, the whole group is kept.
  `--region us` still ships `disksys.rom`, because the Famicom Disk System has no
  American BIOS.
- **Region-free files survive.** A file one of the platform's cores declares
  `[world]` is kept. SwanStation declares `psxonpsp660.bin` and `ps1_rom.bin`
  that way, DuckStation `openbios.bin`. The tag comes from each core:
  PCSX ReARMed reads the region inside `psxonpsp660.bin` and files it as
  `[japan]`, so on MinUI, NextUI and MyMinUI, where it is the only PlayStation
  core, `--region us` drops it.
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

### One file per slot

Region filtering leaves a system with every revision of the same BIOS:
`scph1001` (v2.2), `scph5501` (v3.0) and `scph7001` (v4.1) are all North
American. `--one-per-slot` keeps a single one per system and region:

```bash
python scripts/generate_pack.py --platform retroarch --region us --one-per-slot
```

It only acts on evidence. The winner comes from `priority:`, the preference
order the core's own code applies, lowest first. DuckStation keeps the image
whose priority is lower and de-prioritizes by raising the number, so its
European slot resolves to `scph5502.bin` at 5 over `scph7002.bin` at 10.
PicoDrive walks three ordered search lists instead (`biosfiles_us/eu/jp`), and
those map onto the same field as 1, 2, 3.

A slot is a system **and** a declared region: the Japanese and American
PlayStation BIOS are not alternatives to each other, so their ranks are never
compared.

Where no such list is declared, the group is left untouched and counted. The
RetroArch build above, with `--region us`, printed:

```
  104 slot(s) with no declared order: every candidate kept
```

Two rules keep a declared order from overreaching:

- **Cores that disagree cancel out.** pcsx1 walks `scph1001` first while
  DuckStation prefers `scph5501`. The pack serves both cores, so neither order
  wins and both files stay.
- **A slot mixing unrelated roles stays open.** px68k's IPL ROMs are ranked,
  but its character ROM shares the same system and carries no rank, so the
  whole group is kept. Ordering an IPL against a font would be meaningless.

That number is the remaining work, not a failure. Picking a file without a
declared order would be the arbitrary selection this exists to remove, and it
could drop the one the core would have loaded.

Every candidate of a slot must carry a rank. A set where one member is unranked
cannot be ordered, so the whole slot is left alone: the North American
PlayStation slot stays open because `scph101.bin` carries no priority, even
though `scph5501.bin` would otherwise win at 5.

`--one-per-slot` works with or without `--region`, requires `--platform` or
`--all`, and is refused with `--manifest`, `--emulator`, `--system` and
`--from-md5` rather than silently ignored. It tags the output name
(`Recalbox_10.1.1_OnePerSlot_BIOS_Pack.zip`) so a narrowed build never
overwrites the full one, and the pack README says the pack was narrowed.


`--region` composes with `--split`, `--target`, `--required-only`, `--source`,
`--emulator` and `--system`. It is mutually exclusive with `--from-md5`, which
selects by hash. `pipeline.py` never passes it, so the released packs stay
complete.

Every dimension that removes files appears in the output filename and in the
pack README, because the five places that name an artefact (the pack, the
`--split` parts, the `_Split` directory, the grouped-alias rename and the
manifest) all build from one list (`_narrowings` in `generate_pack.py`). A pack narrowed three ways is called
`Recalbox_10.1.1_NorthAmerica_OnePerSlot_Required_BIOS_Pack.zip` and opens with
a `PACK TYPE: Narrowed` block listing the three. Adding a new way to narrow a
pack means adding it to that list, so it cannot reach users nameless or
unannounced.

Region and target both appear in the output filename
under the name the platform files the target by, whichever alias was typed:
`--region us --target switch` writes
`RetroArch_v1.22.2_NorthAmerica_NintendoSwitch_BIOS_Pack.zip` and
`install/retroarch_northamerica_nintendoswitch.json`, so a filtered build can
never overwrite the full one.


## Pack source variants

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
`RetroArch_v1.22.2_BIOS_Pack.zip`,
`RetroArch_v1.22.2_Platform_BIOS_Pack.zip` and
`RetroArch_v1.22.2_Truth_Required_BIOS_Pack.zip`.

Which one to pick: `full` is the one to ship, since it covers alternate cores
and optional firmware. `platform` is much smaller and matches exactly what the
frontend checks for, which suits SD cards and handhelds. `truth` is a
diagnostic build: it shows what the emulator source code asks for, independent
of what the platform declares, and is how a gap between the two becomes
visible.

Variants compose with `--split`, `--target` and `--manifest`.


## Firmware without game data

The firmware an emulator needs comes first. A platform list can also name the
files a game reads (EmuELEC lists the Doom WADs), and a core profile marks the
data of the games it runs `category: game_data`: MAME's software lists, the
RPG Maker run-time packages, a game engine's own files. `--no-game-data`
leaves both out and keeps the firmware:

```bash
python scripts/generate_pack.py --platform emuelec --no-game-data
python scripts/generate_pack.py --platform emuelec --no-game-data --verify-packs
python scripts/verify.py --platform emuelec --no-game-data
```

A platform entry is game data when the only cores of the platform that read it
read it as game data (see [Verification modes](verification-modes.md) for how
entries are categorized). An entry that some core reads as firmware stays.
The build names every file it left out and why: the platform's entries with
the cores that read them as game data, then each core with the game data
files its profile declares.

The pack is named `EmuELEC_4.8_NoGameData_BIOS_Pack.zip` and its README says
it was narrowed. `verify.py --no-game-data` reports on the same file set, and
`--verify-packs --no-game-data` checks the pack against it. The flag composes
with `--region`, `--target`, `--required-only`, `--source`, `--one-per-slot`,
`--split`, `--system` and `--manifest`
(`install/emuelec_nogamedata.json`). It needs `--platform` or `--all` and is
refused with `--emulator`, `--system` alone, `--from-md5` and
`--all-variants`: game data is categorized against a platform's list and the
cores it runs. The installer's `--no-game-data` makes the same cut from the
full manifest, where each game data file carries `"category": "game_data"`.


## Hardware target filtering

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


## Truth generation and diffing

### What truth is

Truth data is ground truth generated from emulator profiles. It represents what each
core actually needs based on source code analysis, independent of what platform
scrapers declare. The purpose is gap analysis: finding the files the code loads that a platform
list does not name, and the values that differ from the code.

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

Write a platform's own BIOS file with the updates its emulators' source code
supports. The output is the platform's original file with those updates applied:
a hash the emulator source states is updated, an entry the source says nothing
about is kept as written, and a file the platform's emulators read that the list
does not name yet is added.

```bash
python scripts/export_native.py --platform batocera --fetch   # batocera-systems
python scripts/export_native.py --platform recalbox --fetch   # es_bios.xml
python scripts/export_native.py --all --fetch                # every platform, into exports/
```

The updated files are committed under `exports/<platform>/`, and
`exports/<platform>.json` names every change the run made. The site's
[updated platform files](../exports.md) page is built from those reports:
one row per platform, a download link, and each updated hash, added hash
and change not applied listed in full.

Seven of the formats carry code as well as data: Batocera's and ROCKNIX's
scripts, EmuDeck's shell library, BizHawk's C# database, RetroDECK's
component manifests, MiSTer's BiosDB, RetroPie's scriptmodules. Those are
patched from the platform's own file, which `--fetch` downloads once into
`.cache/upstream-native/`. Without it the export fails rather than
publishing a fragment.

RetroPie keeps its BIOS information in the `rp_module_help` sentence of each
package rather than in a list. The export adds a file name to a sentence a
maintainer already wrote, never removes one, and never drafts a sentence where
there was none.

The run reports what it changed, and what it had to leave out: an entry a
format cannot express is named, never written half-formed. `es_bios.xsd`
makes md5 and core required on every element, and RomM compares the file
size before any hash, so an entry missing either could never verify.


## Emulator-level verification

### Per-emulator checks

Verify files against a single emulator's ground truth (size, hashes, crypto):

```bash
python scripts/verify.py --emulator handy
python scripts/verify.py --emulator handy --verbose
```

The first line counts the files the profile declares and names the checks they
carry. A file that is missing or fails a check gets a line of its own, followed by
the cores that check it. `--verbose` also lists the files that pass, each followed
by one line per core with the values it expects and the source reference the
profile cites:

```
handy: 2/2 OK [crc32+existence+size]
  OK (optional): lynxboot.img
    handy validates crc32=0d973c9d,size=512 [lynx/rom.h:48-49 (ROM_SIZE=0x200, ROM_CRC32=0x0D973C9D), lynx/rom.cpp:76-129 (CRom constructor), libretro/libretro.cpp:1231-1258 (bios path + CSystem init)]
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


## Offline workflow

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

Include truth + native format export. Offline, the platforms' own files
must already be cached ([tools](tools.md#pipeline)):

```bash
python scripts/pipeline.py --offline --with-export
```

### Combining flags

These flags compose, except the pairs the [pipeline flags](tools.md#pipeline) table marks as refused:

```bash
python scripts/pipeline.py --offline --skip-packs --skip-docs --with-truth --target switch
```

This runs: database generation, verification (filtered to Switch cores), truth generation
and diff. Packs, manifests and docs are skipped, no network access. Without
`--skip-packs` the same run empties `dist/` and rebuilds every pack for the
target.
