---
level: contribute
order: 70
---

# Command-line tools

All tools are Python scripts in `scripts/`. They need Python 3.9 or newer and `pyyaml`,
and only `validate_schemas.py` also needs `jsonschema[format-nongpl]`. `install.py`
alone runs on Python 3.8.

## Pipeline

Run everything in sequence:

```bash
python scripts/pipeline.py --offline              # DB + verify + packs + manifests + integrity + readme + site
python scripts/pipeline.py --offline --skip-packs  # no packs or manifests
python scripts/pipeline.py --offline --skip-docs   # skip readme + site generation
python scripts/pipeline.py --offline --target switch  # filter by hardware target
python scripts/pipeline.py --offline --with-truth  # include truth generation + diff
python scripts/pipeline.py --offline --with-export # include native format export
python scripts/pipeline.py --check-buildbot        # online run + buildbot freshness check
```

`--offline` skips the data directory refresh, so on a fresh clone run
`python scripts/refresh_data_dirs.py` once first. A run that builds packs with no
data directory cached is refused before step 0.

`--with-export` online passes `--fetch` to step 2e, which downloads each
platform's own file and patches it. Offline that file must already be in
`.cache/upstream-native/`: on a fresh clone run
`python scripts/export_native.py --all --refresh-cache` once first. An offline
run with `--with-export` and an empty cache for any platform it patches is
refused before step 0.

Pipeline steps:

| Step | Description | Skipped by |
|------|-------------|------------|
| 0 | Validate profiles and platform YAMLs against the schemas | - (no `jsonschema` installed) |
| 1 | Generate database | - |
| 1b | Dump-catalog coverage report | - (offline, reads `provenance/`) |
| 1c | Romset recipes: identify archives, list rebuild targets, then `--capture` writes a recipe for every archive (`recipes/archives.json`) | - (offline, reads `recipes/`) |
| 2 | Refresh data directories | `--offline` |
| 2a | Refresh MAME BIOS hashes | `--offline` |
| 2a2 | Refresh FBNeo BIOS hashes | `--offline` |
| 2b | Check buildbot staleness | only with `--check-buildbot`, skipped by `--offline` |
| 2b2 | Release assets against the gitignored files (size and sha256) | `--offline` |
| 2c | Generate truth YAMLs | only with `--with-truth` / `--with-export` |
| 2d | Diff truth vs scraped | only with `--with-truth` / `--with-export` |
| 2e | Export native formats | only with `--with-export` |
| 3 | Verify all platforms (`--strict`) | - |
| 3a | File identity: one content under two identities (`identity.py --strict`, gates the run) | - |
| 3b | Slot arbitration: destinations both layers claim (`slots.py`, reports only) | - |
| 4 | Generate the packs of the platforms marked `release_pack` | `--skip-packs` |
| 4b | Generate install manifests | `--skip-packs` |
| 4c | Generate target manifests | `--skip-packs` |
| 4d | Collected copies only an emulator install provides (`bundled_only.py --strict`, gates the run) | - |
| 4e | Games index: what the installer reads for the games on a card (`generate_games_index.py`, fails under its coverage floor) | - (reads the committed install lists) |
| 5 | Consistency check: counts, paths per archive, every emulator and system pack, the narrowed platform packs, the `--split` parts | `--skip-packs`, or no full pack built (`--source platform` or `truth`) |
| 6 | Pack integrity (extract + hash) | `--skip-packs`, or no full pack built |
| 7 | Generate README and CONTRIBUTING, then the installer page's tables and run samples (`generate_installer_doc.py`) | `--skip-docs` |
| 8 | Generate site | `--skip-docs` |
| 8b | Render the site with `npm run build --prefix website`, then `validate_site.py`, as the deploy does | `--skip-docs`, or Node not set up (`npm ci --prefix website`) |

Pipeline flags:

| Flag | Effect |
|------|--------|
| `--offline` | skip every step that needs the network (2, 2a, 2a2, 2b, 2b2), and pack only the release assets already in `.cache/large/` |
| `--skip-packs` | skip steps 4, 4b, 4c, 5 and 6. Steps 4d and 4e still run, and README and site are still rewritten unless `--skip-docs` is given too |
| `--skip-docs` | skip steps 7, 8 and 8b |
| `--target TARGET` | filter verify, packs and truth by hardware target |
| `--source {platform,truth,full}` | pack file source, passed through to `generate_pack.py`. Refused with `--skip-packs` |
| `--all-variants` | build the 6 source x required combinations. Refused with `--skip-packs` and with `--source` |
| `--full-narrowings` | step 5 compares every region, target and system of each platform instead of three of each. Refused with `--skip-packs` and with `--source platform` or `--source truth` |
| `--check-buildbot` | run step 2b. Additive, and ignored under `--offline` |
| `--with-truth` | run steps 2c and 2d |
| `--with-export` | run steps 2c, 2d and 2e |
| `--output-dir DIR` | pack output directory (default `dist/`) |

`--check-buildbot` runs the whole pipeline online. For the freshness check
alone, run `python scripts/check_buildbot_system.py`.

## Conventions every tool keeps

- **A flag is applied or refused.** A mode that accepts a flag it does not
  apply leaves the user believing they filtered. Four such cases were found
  (`verify --emulator --region` among them), and a test now runs every mode
  against every flag.
- **Every dimension that narrows an artifact appears in its name.** Region,
  target, required-only, standalone and source variant are part of the pack
  and manifest names. `--manifest --target switch` once overwrote the
  manifest every installer downloads with a narrowed one.
- **A step that did not run says SKIPPED**, never OK.
- **verify.py and generate_pack.py read the same functions.** A count or a
  path that differs between the report and the pack is a defect, which is
  what step 5 checks: the counts, the paths each archive holds against the
  ones verify credits (`--destinations`), every emulator pack, each
  profile in each build, built in memory against `verify --emulator`, and
  every system pack that gathers several profiles against `verify --system`.
  Each of them is also built with `--required-only` and with the regions
  its files declare (first, middle and last, all of them with
  `--full-narrowings`). 2,112 emulator and 1,493 system packs took about
  two minutes on 2026-11-06.
  Equal counts once hid four RetroArch paths credited and never written.
- **Each narrowed platform pack is compared too.** Step 5 builds in memory
  the `--required-only` and `--no-game-data` pack of every platform, and its
  `--region`, `--target` and `--system` packs, against verify with the same
  narrowing. The full matrix is 1,150 packs and took 25 minutes on 2026-11-05,
  so a run compares the first, the middle and the last region, target and
  system of each platform (155 packs, about 3 minutes), which reaches every
  code path each narrowing takes. `--full-narrowings` compares them all.
  `--source` and `--one-per-slot` are not compared: verify has no report of
  a platform-only, truth-only or one-per-slot pack. A test fails when a new
  narrowing reaches the pack name without being compared or exempted.
- **The `--split` parts add up to the full pack.** Step 5 builds the parts of
  every platform in memory and compares their union with the full pack, path
  for path and byte for byte: a part is built against the full pack's own
  placement, so a path the full pack settles (a file/directory clash, a case
  twin, a path two systems declare) is not written again in a part. The 17
  platform packs took about four and a half minutes on 2026-11-06.
- **Generators write through `write_if_changed()`.** A new timestamp alone
  rewrites nothing, so a diff on a generated file always means content.
- **One run per output directory.** Pack generation takes a lock on
  `<output-dir>/.lock`, and a second run on the same folder stops at once
  rather than read a half-written ZIP. Pack experiments with
  `generate_pack.py` use a scratch `--output-dir` under `tmp/`. A pipeline
  run also writes `database.json`, `install/`, `README.md`, `CONTRIBUTING.md`
  and `website/` at fixed paths, so it holds the repository's `.lock` as well, and a second
  pipeline is refused whatever its `--output-dir`.
- **Read the exit status before the output.** A generator that crashed leaves
  the previous artifact in place, which reads exactly like a run that changed
  nothing.

## Individual tools

### generate_db.py

Scan `bios/` and build `database.json` with multi-indexed lookups.
Large files in `.gitignore` are preserved from the existing database
and downloaded from GitHub release assets if not cached locally.

```bash
python scripts/generate_db.py --force --bios-dir bios --output database.json
```

### verify.py

Check BIOS coverage for each platform using its native verification mode.

```bash
python scripts/verify.py --all                     # all platforms
python scripts/verify.py --all --strict            # exit 1 on a missing required file (md5/sha1 platforms)
python scripts/verify.py --platform batocera       # single platform
python scripts/verify.py --platform retroarch --verbose  # with ground truth details
python scripts/verify.py --emulator dolphin        # single emulator
python scripts/verify.py --emulator dolphin --standalone  # standalone mode only
python scripts/verify.py --emulator handy --strict  # exit 1 on a required file missing with no HLE
python scripts/verify.py --system atari-lynx       # single system
python scripts/verify.py --platform batocera --system psx  # one system of a platform pack
python scripts/verify.py --platform retroarch --target switch  # filter by hardware
python scripts/verify.py --platform recalbox --region us   # regional priority list
python scripts/verify.py --platform emuelec --no-game-data  # the firmware-only pack, game data named
python scripts/verify.py --emulator mame --required-only    # the pack built with --required-only
python scripts/verify.py --all --destinations tmp/paths.json  # also write the paths each pack holds
python scripts/verify.py --all --offline             # a release asset the cache lacks counts missing, as in an offline build (any mode, --emulator included)
python scripts/verify.py --list-platforms          # list all platforms
python scripts/verify.py --list-emulators          # list all emulators
python scripts/verify.py --list-systems            # list all systems
python scripts/verify.py --platform retroarch --list-targets  # list available targets
```

Verification modes per platform:

| Platform | Mode | Logic |
|----------|------|-------|
| RetroArch, Lakka, RetroPie | existence | file present = OK |
| Batocera, RetroBat | md5 | MD5 hash match, plus `checkInsideZip` for `zippedFile` entries |
| Recalbox | md5 | MD5 multi-hash, `md5_composite` for ZIPs |
| EmuDeck | md5 | MD5 whitelist per system |
| RetroDECK | md5 | MD5 per file via component manifests |
| RomM | md5 | size + any hash (MD5/SHA1/CRC32), no ZIP inspection |
| ROCKNIX | md5 | MD5 hash match, same shape as Batocera |
| KNULLI | md5 | Batocera's `checkBios` in `knulli-systems`, `checkInsideZip` and emulator/core gates included |
| AmberELEC | md5 | MD5 of each file under `/storage/roms`, `checkInsideZip` for `zippedFile` entries |
| EmuELEC | md5 | MD5 of each file under `/storage/roms`; `zippedFile` is never read |
| MiSTer FPGA | md5 | MD5 of the file at its destination, no ZIP inspection |
| BizHawk | sha1 | SHA1 per firmware from `FirmwareDatabase.cs` |
| MinUI, NextUI, MyMinUI | existence | none: minarch hands each core `Bios/<TAG>/` and opens no file |

Full details and severity mapping: [verification modes](verification-modes.md).
`--region` narrows the report to the file set a regional pack would carry, and a
mode that cannot apply it refuses it rather than ignoring it: see
[region filtering](advanced-usage.md#region-filtering). `--no-game-data` narrows
it to the pack built with the same flag and names what it left out. It needs
`--platform` or `--all`.

`--db`, `--platforms-dir` and `--emulators-dir` point the run at another
database or source tree, which is how the tests drive it against fixtures.

### generate_pack.py

Build platform-specific BIOS ZIP packs.

```bash
# Full platform packs (--all: the platforms marked release_pack)
python scripts/generate_pack.py --all --output-dir dist/
python scripts/generate_pack.py --platform batocera
python scripts/generate_pack.py --emulator dolphin
python scripts/generate_pack.py --system atari-lynx

# Granular options
python scripts/generate_pack.py --platform retroarch --system sony-playstation
python scripts/generate_pack.py --platform batocera --system psx
python scripts/generate_pack.py --platform batocera --required-only
python scripts/generate_pack.py --platform emuelec --no-game-data
python scripts/generate_pack.py --platform retroarch --split
python scripts/generate_pack.py --platform retroarch --split --group-by manufacturer

# Hash-based lookup and custom packs
python scripts/generate_pack.py --from-md5 490f666e1afb15b7362b406ed1cea246
python scripts/generate_pack.py --platform batocera --from-md5-file missing.txt
python scripts/generate_pack.py --platform retroarch --list-systems

# Hardware target filtering
python scripts/generate_pack.py --all --target x86_64
python scripts/generate_pack.py --platform retroarch --target switch

# Regional filtering
python scripts/generate_pack.py --platform retroarch --region us
python scripts/generate_pack.py --platform retroarch --region us,eu,jp
python scripts/generate_pack.py --platform retroarch --region us --one-per-slot

# Source variants
python scripts/generate_pack.py --platform retroarch --source platform  # YAML baseline only
python scripts/generate_pack.py --platform retroarch --source truth     # emulator profiles only
python scripts/generate_pack.py --platform retroarch --source full      # both (default)
python scripts/generate_pack.py --all --all-variants --output-dir dist/ # all 6 combinations
python scripts/generate_pack.py --all --all-variants --verify-packs --output-dir dist/

# Listing and integrity
python scripts/generate_pack.py --list-platforms      # list available platforms
python scripts/generate_pack.py --list-emulators
python scripts/generate_pack.py --list-systems
python scripts/generate_pack.py --platform retroarch --list-targets
python scripts/generate_pack.py --all --verify-packs --output-dir dist/  # extract + hash

# Data refresh
python scripts/generate_pack.py --all --refresh-data  # force re-download data dirs
python scripts/generate_pack.py --all --offline       # cache-only, never open the network

# Install manifests (consumed by install.py)
python scripts/generate_pack.py --all --manifest --output-dir install/
python scripts/generate_pack.py --manifest-targets --output-dir install/targets/
python scripts/generate_installer_doc.py  # run samples of wiki/installer.md, from the manifests
```

Packs include platform baseline files plus files required by the platform's cores.
When a file passes platform verification but fails emulator validation,
the tool searches for a variant that satisfies both.
If none exists, the platform version is kept and the discrepancy is reported.
A declared hash that the local dump contradicts is settled by the platform's
own verification mode ([discrepancy detection](verification-modes.md#discrepancy-detection)).

### Granular options

- `--system` with `--platform`: filter to specific systems within a platform pack.
  It takes the collection's system ids (`sony-playstation`) and the platform's own names,
  read from `native_system` in its YAML (Batocera `psx`, Recalbox `msx1,msx2`).
  `--platform <name> --list-systems` prints both. `verify.py --platform --system`
  reports on the same narrowed pack, and the installer's `--system` reads the
  same mapping from the manifest's `system_names`. An unknown name is refused
  with the closest matches before any work. Without `--platform`, `--system`
  takes the collection's ids only.
- `--required-only`: exclude optional files and the data directories declared
  `required: false`, keep only required. `verify.py --required-only` reports
  on the same file set, for `--platform`, `--emulator` and `--system`
- `--no-game-data`: firmware only. Leaves out the platform's entries
  categorized game data and the cores' `category: game_data` files, and names
  each one. Tags the pack `_NoGameData`. `verify.py --no-game-data` and
  `--verify-packs --no-game-data` check the same file set
  ([details](advanced-usage.md#firmware-without-game-data))
- `--split`: generate one ZIP per system instead of one big pack
- `--split --group-by manufacturer`: group split packs by manufacturer (Sony, Nintendo, Sega...)
- `--from-md5`: look up a hash in the database, or build a custom pack with
  `--platform`/`--emulator`. Any digest is read by its length: CRC32 (8 hex
  digits), MD5 (32, or the 29 Batocera writes), SHA-1 (40), SHA-256 (64).
  Anything else is refused with the value that is not a hash
- `--from-md5-file`: same, reading hashes from a file: one per line, alone or
  beside a file name as `md5sum` writes it, `#` for comments. A line with no
  hash is refused with its number. A lookup exits 1 when a hash is not in the
  database
- `--target`: filter by hardware target (e.g. `switch`, `rpi4`, `x86_64`)
- `--region`: ordered priority list, best first. Regions nest, a system with no
  regional split keeps everything, and a group with no candidate in any named
  region is kept whole rather than emptied
- `--one-per-slot`: keep one file per system and declared region, ranked by the
  `priority:` the emulator source states, lowest first
- `--db`, `--platforms-dir`, `--emulators-dir`: read another database or source
  tree instead of the repository's
- `--source {platform,truth,full}`: select file source (platform YAML only, emulator profiles only, or both)
- `--all-variants`: generate all 6 combinations of source x required_only. With
  `--verify-packs`, the full pack is compared to the platform's list and each
  narrowed variant is named with the hash check the build ran on its members
- `--refresh-data`: force re-download all data directories before packing
- `--no-refresh-data`: pack the data directories as cached, still fetching release assets (what `pipeline.py` does after its own refresh step)

How regions are ordered, what a slot is and what each narrowing adds to the
pack name: [region filtering](advanced-usage.md#region-filtering).

### cross_reference.py

Compare emulator profiles against platform configs.
Reports files that cores need beyond what platforms declare.

```bash
python scripts/cross_reference.py                    # all
python scripts/cross_reference.py --emulator dolphin  # single
python scripts/cross_reference.py --emulator dolphin --json  # JSON output
python scripts/cross_reference.py --platform batocera        # single platform
python scripts/cross_reference.py --platform retroarch --target switch
```

### truth.py, generate_truth.py, diff_truth.py

Generate ground truth from emulator profiles, diff against scraped platform data.

```bash
python scripts/generate_truth.py --platform retroarch     # single platform truth
python scripts/generate_truth.py --all --output-dir dist/truth/  # all platforms
python scripts/diff_truth.py --platform retroarch         # diff truth vs scraped
python scripts/diff_truth.py --all                        # diff all platforms
```

### export_native.py

Write each platform's own BIOS file, updated from the emulators' code: System.dat, es_bios.xml,
batocera-systems, checkBIOS.sh, FirmwareDatabase.cs, the RetroDECK manifests,
MiSTer's BiosDB, RetroPie's scriptmodules. Every platform in the registry.

```bash
python scripts/export_native.py --platform batocera --fetch
python scripts/export_native.py --all --fetch   # into exports/, published on the site
```

`--fetch` downloads the platform's own file into `.cache/upstream-native/`,
at the revision the platform YAML's `source:` names. Formats that carry
code are patched from it rather than regenerated, and the export fails
without it. The URL each cached file came from is recorded beside the
cache, so a platform file that moves to a new tag is fetched again instead
of patching the previous one.

A branch URL keeps its name while its content moves, and no URL comparison
can see that. `--refresh-cache` downloads every file again and writes no
export. It is what follows a rescrape, so the original and the platform
YAML describe the same moment.

```bash
python scripts/export_native.py --platform retrobat --refresh-cache
python scripts/export_native.py --all --refresh-cache
```

A list is written in the order the code looks: `priority:` first (lowest
wins), then the profile's own declaration order. What a format cannot
state is reported rather than written: EmuDeck's arrays are shared
between emulators its file does not name, so a hash is updated in place
and never added.

`exports/<platform>.json` lists every change under `changes`, each with
its kind, entry, field and the value before and after (an addition carries
the fields it is written with). The exports page shows both values, and a
test reads the original and the updated System.dat and es_bios.xml back to
check that the list is the diff.

No entry the platform declares is removed. One the truth does not pair is
looked for, in this order: by the tail of a `path:` in the profiles of every
core the platform runs, by a name the platform's own launch code reads (its
`launchers:` records, such as the 22 names Batocera's DuckStation generator
tries), then in those profiles by name or alias, by any hash (archive
members included), under a `type: directory` entry or a data directory. An entry
none of them answers is written to `exports/<platform>.json` under
`removal_candidates`, with the cores examined for its system and a reason.
The verdict is `undetermined` when a core the platform names has no
profile (`common.unresolved_platform_cores`) or when the entry is a ROM set
and a core of the system opens sets its profile does not list. BizHawk and
MiSTer resolve no core, so nothing is examined and nothing is listed.

A destination the platform's own list declares twice, for two different
files, is written under `doubled` (`slots.find_collisions` finds it). One
path holds one file, so one of the two checks fails on every install.
Each declaration carries its system, component, hashes and the file it
resolves to, with the emulators the platform runs whose profile reads
that file: a member list it holds, a hash it matches, or a name and a
size it fits. Both entries stay in the updated file.

MAME and FBNeo entries are `.zip` ROM sets: their meaningful hashes belong
to the files inside the archive, so the exported DAT lists those entries
without a container sha1. Anyone submitting the DAT upstream should mention
this.

### fileless_audit.py

Names the profiles that declare no files whose source asks for a directory to
read from.

```bash
python scripts/fileless_audit.py --all            # every profile not yet answered
python scripts/fileless_audit.py virtualjaguar b2 # the profiles named
```

It exits 1 when a profile is worth a reading or a source could not be reached
(`--offline` reads the cache only, `--cache-dir` moves it), and ends on a
count of what it read.

An empty `files:` list is the one assertion in the repository that ages
unwatched: there is no file to go missing and no ref to drift, so nothing
notices when a core that embedded everything grows a path. virtualjaguar
carried "No external BIOS files are required or loaded by this core" while its
source had grown eleven filenames read from the system directory.

The signal is the request itself, `RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY` and
its spellings, looked for in the sources the profile already cites. Finding one
does not prove a file is loaded, which is why this reports rather than
concludes.

Three answers settle a profile and it is not reported again: it declares files,
it declares `data_directories` (dinothawr reads `system_dir/dinothawr/` and
says so there), or it carries an `exclusion_note` saying what the directory is
for. craft writes its world database in it, dice stores the answer in a
variable no other file names, lutro hands it to the Lua game. What is left is
the set nobody has read yet, which is the only set worth reading.

### mame_ref_audit.py

Checks that each MAME romset ref names the line declaring its own set, at the
profile's pinned revision.

```bash
python scripts/mame_ref_audit.py mame mamearcade mamemess groovymame
python scripts/mame_ref_audit.py mame --write
```

`profile_sync` follows content: a ref that drifted still anchors wherever the
cited text went, which is what drift detection is for. It cannot answer the
only question a MAME ref asks, whether that line declares that set. Asking the
stronger question found nineteen stale refs in one driver file where
profile_sync had flagged five, and ninety-two across the four profiles whose
upstream still moves.

The set name is argument 1 of the machine macro, after the year: matching it
anywhere on the line would also match every clone naming that set as its
parent, which is most of a driver file. Comments are stripped first, since a
declaration can sit behind one, as `/* Naomi */ GAME( 1998, naomi, ...)` does.

A set no machine macro declares is reported as not judgeable rather than
wrong: device ROMs take the shortname of their `DEFINE_DEVICE_TYPE`, and some
archives are bare `ROM_START` blocks. The frozen generations, mame2009 through
mame2016, come out clean, which is the check saying it finds drift only where
drift can happen.

### profile_sync.py

Confront a profile with its upstream. The pinned commit is the profile's
`source_commit` when present, else the last upstream commit at
`profiled_date`. Each cited line range is extracted at the pin and located
in the HEAD revision of the same file.

```bash
python scripts/profile_sync.py --emulator vice
python scripts/profile_sync.py --emulator vice --full-diff
python scripts/profile_sync.py --all --triage
python scripts/profile_sync.py --all --changed-only --json
python scripts/profile_sync.py --emulator vice --fetch-plan
```

Selection narrows `--all` before any request is spent: `--system sega-saturn`,
`--type standalone`, `--stale-before 2026-06-01` (profiled before that date)
and `--limit 20`. Output takes `--markdown` (a report written under
`--report-dir`, `reports/` by default), and `--full-diff` takes `--ref PATH`
to show one cited file and `--context N` lines around each hunk. `--strict`
exits 1 when a profile has refs to review, and CI runs it on every profile a change
adds. `--offline` answers from `--cache-dir` alone. `--changed` selects the
profiles the branch adds or edits, uncommitted ones included, and `--added`
the ones it adds, both against the merge base of `--base` and HEAD. By
default `--base` is the project's main line: `upstream/main` or `origin/main`
when that remote is the project, fetched from the project in a fork's clone,
where `origin/main` is the fork.

```bash
python scripts/profile_sync.py --all --system sega-saturn --changed-only
python scripts/profile_sync.py --all --stale-before 2026-06-01 --limit 20 --triage
python scripts/profile_sync.py --emulator vice --full-diff --ref vice/src/c64/c64rom.h --context 6
python scripts/profile_sync.py --emulator vice --strict
python scripts/profile_sync.py --changed --strict
python scripts/profile_sync.py --added --strict
```

Per part of a ref: `ANCHORED` (same content, same lines), `SHIFTED` (same
content, moved), `RENAMED` (the source file moved), `CHANGED` (content
edited), `AMBIGUOUS` (several equally good candidates), `GONE` (nothing
left to anchor to), `EXTERNAL` (the ref names a project the profile does
not declare, so no revision can confirm it), `UNCHECKED` (a pin equal to
HEAD is judged on self-consistency, and an entry with neither a hash nor
a name gives that check nothing to look for). An entry carries the worst
status of its parts. Only `CHANGED`, `GONE` and `AMBIGUOUS` count as
needing a re-read, with each prose citation `--realign-prose` would move or
refuse (written under an older pin, it holds the pin back). A zero next to
a row of `unchecked` is not a proof.

A part opening with `source` or `upstream`, in a source_ref or in prose,
is read in that repository. The word belongs to the part, not to its path:
one profile can cite the same file under both. `--triage` prints a header,
ranks worst first and closes on the number of profiles with something to
review. Online, a pass over many profiles takes several minutes or more: it
names its size on stderr, then writes a progress line every 30 seconds.
Ctrl-C prints the output for the profiles already read and exits 130.
`--offline` answers from the cache alone.

A single cited line is often not distinctive, so the anchor widens by
steps of ±3, ±6, ±12, ±25 and ±50 lines until it is unique. Three further
strategies settle what widening cannot, each requiring corroboration
rather than a guess:

- **File shift.** Refs already resolved in the same file vote on a line
  shift. When at least three agree and exactly one candidate sits on that
  shift, it is taken. Repetitive driver tables resolve this way.
- **Declared value.** A cited line that is blank, or that misses its
  subject, is moved onto the nearest line carrying the entry's hash or
  name, within 60 lines and only when that line is unambiguous.
- **Every declared repository.** A vanished path is looked for in all the
  repositories the profile declares, not only the one that owns it.

Anything still unsettled is reported, never guessed.

`source_commit` always names the revision the refs are written against, so
recaling is all or nothing per profile: a profile that still needs a
re-read is left untouched and moves as a whole once resolved. Rewrites
preserve the prose of annotated refs, replacing only the location.

Those two writes belong in one pass, because a profile whose refs moved
without its pin describes two revisions at once:

```bash
python scripts/profile_sync.py --all --rebase-refs --bump-commit --dry-run
python scripts/profile_sync.py --all --rebase-refs --bump-commit
```

Asking for both makes the pass atomic. The work happens on a copy, and the
copy is promoted only when the pin follows the refs. A profile whose refs
describe one revision while its pin names another is the state the
all-or-nothing rule exists to prevent, and recaling alone produces it. What
holds a pin back is an annotated ref, one under a mode key, or a prose run the
pass cannot rewrite without guessing: those are repaired first, by hand or
with `--realign-prose`.

The first prints the plan and changes nothing: `would recale` per ref and
`would set source_commit` (and `upstream_commit`, when that one moves too)
per pin the write changes. It reaches that plan by running the
real write path over a throwaway copy, so the planned bump reads the text
the recale would have left rather than the one on disk, and a pin held back by
prose that the same pass would have moved is not reported as blocked. Drop
`--dry-run` and the same pass writes, recale before bump on each profile.

A moved pin also moves the links the site draws into the cited sources: a
path is linked only where `website/src/data/source-paths.json` records it in
the tree the profile pins. Refresh that record after a pin moves or a profile
is added, and commit it with the profiles. Every tree a run tries is recorded,
read or not, so `check_freshness.py` reports a pinned tree the record lacks:

```bash
python scripts/sitesources.py --fetch
```

A forge can also go for good. A 451, a 410 or a host that stops resolving
is reported as `upstream gone` in its own bucket rather than retried and
printed as a failure every pass, and the profile leaves the review backlog,
where nothing could be done about it. A 403 is not that: small Forgejo
instances behind anti-bot filters answer 403 to a script and 200 to a
browser, so it stays a refusal.

When no mirror serves it either, `upstream_gone` states why, and the profile
stops being an open problem: the refs describe the last revision anyone could
reach and nothing further is possible. The declaration is guarded rather than
trusted, since a forge can come back: a profile that declares it while the
forge answers is reported as the contradiction it is.

`source_mirror` names a repository carrying the same tree, consulted after
`source` and `upstream` so a live primary always decides attribution. It is
what keeps a profile checkable once its own forge stops answering: eden
reads from its Codeberg copy, which holds the same head and the pinned
commit. A repository that refuses is muted for the rest of the pass instead
of ending it, keyed by host as well as slug, since a mirror carries the same
slug on another forge.

`--accept-changed` recales `CHANGED` refs too, for a profile whose diff
has been read and judged benign. It applies to one profile at a time and
is refused with `--all`.

A profile can document a frozen release line that lives as a tag inside a
still-developed repository. HEAD is then a different program, so comparing
against it says nothing, and recaling would repoint refs at code the frozen
release never contained. When the declared `core_version` names a tag whose
commit is the pin, the profile is judged on self-consistency instead: does
each cited range carry the value its entry declares, at the pinned revision?
Recaling and bumping are refused outright for those profiles.

Three shorthand forms appear in the corpus and are resolved rather than
reported missing. A part reduced to a line range continues the previous
part's file (`geo.c:234-243, 273-285`). A profile whose `source` differs
from its `upstream` may cite paths from both, and each path is attributed
to the repository that carries it. A path prefixed with a repository
directory name (`EightyOne/Source/HW_.cpp`) is stripped as a last resort,
only after the path as written has failed everywhere, and the result is
reported as `RENAMED` so `--rebase-refs` cleans the profile.

`--check-version` compares `core_version` with the latest upstream tag and
release. A project that publishes no release is read by its newest tag when
that tag is a version number. It warns when the pin already contains a later
release than `core_version` names, or when a later one is out and the pin is
not held. A `core_version` that names no tag is compared by number, within
one numbering scheme. `--detect-new-files` lists filename literals at HEAD the profile
does not declare. `--watch-hashes` lists hash literals added upstream that
match no entry. Both land in the `--json` report (`new_files`, with
`since_pin` true for a name the pinned file did not carry, and
`new_hashes`), which `check_freshness.py --profiles` reads: a name gained
since the pin or an undeclared hash makes the profile stale. `--tree-diff`
shows added, removed and renamed files in the directories the refs point at.

`core_version` is the version of the code at the pin, and `version_basis`
says where it is read: a pattern in one file (`file`), the nearest tag and
the commits after it (`tag`, written in git describe's form), the profile an
alias follows (`alias`), an artefact read outside any source tree
(`package`), `none` when the code states nothing, with `core_version`
null, or `unverified` when no reading can be made (a forge gone, a host the
tools cannot read, no artefact to read): `core_version` stays as written,
reported unconfirmed, and `why` names the reason. `--verify-version` reads
it again at the pin and exits 1 on a difference or a missing basis. `--set-version` writes what the code states.
A pin advance reads the version at the new pin in the same write and is
refused when it cannot: a package version moves by hand.

```bash
python scripts/profile_sync.py --all --verify-version --changed-only
python scripts/profile_sync.py --emulator snes9x --set-version
```

Branch tips, tags and releases are cached for six hours. `--fresh` asks the
forges again for them, which matters right after an upstream commit or a
hand-set pin: a tip cached before the pin reads as behind it. It is refused
with `--offline`. A run that writes a profile also rebuilds the site's record
of cited source paths (`website/src/data/source-paths.json`).

Writes are explicit and mechanical only. `--backfill-commits` fills a
missing `source_commit`, `--rebase-refs` recales `SHIFTED` and `RENAMED`
line ranges and moves `source_commit` to HEAD with them, all or nothing,
`--bump-commit` advances `source_commit` to HEAD only when nothing needs a
re-read. It leaves a profile a single registered platform ships until the
profile says what that platform builds: `pin_frozen` for a fixed revision,
`pin_follows` for the branch tip. All three refuse to run on a dirty `emulators/` without `--force`,
and every write is verified by reparsing the document.

Uses `GITHUB_TOKEN` when set, which `--all` requires. Responses are cached
under `.cache/upstream/`, addressed by commit sha, so `--offline` replays a
previous run. GitHub, GitLab and Forgejo upstreams are supported, other
hosts are reported as skipped.

The forge side lives in `upstream.py`: it resolves a revision, fetches a
file at a given sha, and compares trees, for the forge families the
profiles point at. It knows nothing about profile structure, so anchoring
logic and repository access stay testable apart.

### validation.py

Validation index and ground truth formatting. Used by verify.py for emulator-level checks
(size, CRC32, MD5, SHA1, crypto). Separates reproducible hash checks from cryptographic
validations that require console-specific keys.

### refresh_data_dirs.py

Fetch data directories (Dolphin Sys, PPSSPP assets, blueMSX databases)
from upstream repositories into `data/`.

```bash
python scripts/refresh_data_dirs.py
python scripts/refresh_data_dirs.py --key dolphin-sys --force
python scripts/refresh_data_dirs.py --dry-run              # preview without downloading
python scripts/refresh_data_dirs.py --platform batocera    # single platform only
python scripts/refresh_data_dirs.py --registry path/to/_data_dirs.yml
```

A download that fails or does not read as an archive is tried three times,
after waits of 5 and 20 seconds: a mirror once answered with a page instead of
`ScummVM.zip` and served the archive minutes later. An archive that reads but
holds nothing under the expected path fails at once, since a retry gets the
same bytes.

### check_freshness.py

Ask every transcribed layer whether the local copy is the one upstream serves
today, and answer with one row per subject. Platform and target files are
re-scraped through the scrapers' own write path into a throwaway copy and
diffed against the committed file, so the diff decides rather than a version
string. Core-info is listed and compared with the profiles (a core with no
profile, a profile that calls standalone a core libretro now builds, a
profiled core whose `.info` git blob differs from the one recorded in
`platforms/_core_info.json`). Once the changed `.info` is read against the
profile, `--record-coreinfo <core>` records its blob as reviewed. Data
directories are checked against their upstream, dump catalogs and romset
snapshots against the catalog they were read from (Redump DAT versions, the
No-Intro daily rebuild, the newest TOSEC pack, the newest MAME release, the
git blobs of the FBNeo DATs), the game catalogs of `games/catalogs/` against
the No-Intro pack and the Redump datfiles they were read from, the CI
toolchain against PyPI and the actions' latest releases, and the site's exact
npm pins in `website/package.json` against the npm registry.

The `native` area needs no network. It reads the cache `export_native.py`
patches from and reports an original that is absent, that came from another
URL than the one the platform YAML names, or that was fetched before the
platform YAML was last rewritten.

The `romfolders` area compares each pin of `platforms/romfolders/_sources/`.
A setup that is a registered platform must be read at the revision its
platform file was scraped at, which needs no network unless one side names a
tag and the other a commit. Any other setup is compared with its project's
newest release, or with its branch head when the project publishes none. A
stale pin is moved by hand, then `python -m scripts.scraper.romfolders --setup
NAME` reads the folders again.

The `profiles` area always checks `website/src/data/source-paths.json`
against the profiles, offline: a recorded tree that no profile pins any more
is `STALE` until `sitesources.py --fetch` runs again. It also reads each
`pin_build` reference of a held pin: where the platform YAML was scraped at
the reference's own revision the row is `OK` without network, otherwise the
build file is fetched at the platform's new revision (or at the branch head
of a platform this repository does not scrape) and its variable compared
with the recorded value. A different value is `STALE`: the platform now
builds another revision, and the pin, the refs and `pin_build` move with it.
Profiles with `pin_frozen` and no `pin_build` are counted on one `SKIPPED`
row, since no build file names their revision.

```bash
python scripts/check_freshness.py
python scripts/check_freshness.py --only platforms,targets
python scripts/check_freshness.py --json
python scripts/check_freshness.py --profiles     # also runs profile_sync (slow)
python scripts/check_freshness.py --offline      # local ages only
python scripts/check_freshness.py --record-coreinfo virtualjaguar  # .info read, record it
```

The exit code is non-zero when anything is stale or an upstream asked could
not be read (`UNKNOWN`), so a run that reached no remote does not pass for a
fresh collection. `--offline` asks no upstream and its rows are `SKIPPED`.
Emulator profiles are the one layer left to `profile_sync.py`, which the
`--profiles` flag folds in. A profile skipped by nature (upstream declared
gone, a host no forge API serves, no `source_ref`) is `SKIPPED`, one no
declared repository answers is `UNKNOWN`. When rows are stale, the summary
names `refresh_stale.py`, which runs the refresher behind each of them.

### refresh_stale.py

Run the refresher behind every stale row of `check_freshness.py`, several at
a time, and leave the result in the working tree for review. Nothing is
committed.

| Stale row | Command |
|-----------|---------|
| `platforms/<name>` | the platform scraper, then the `native` refresh for the same platform, then `verify.py --platform <name>` |
| `native/<name>` | `generate_truth.py --platform <name>`, `export_native.py --platform <name> --refresh-cache`, then the export itself |
| `targets/<name>` | the target scraper |
| `data/<key>` | `refresh_data_dirs.py --key <key> --force` |
| `catalogs/mame recipes`, `catalogs/fbneo recipes` | `scraper/romset_dat_importer.py --source <source> --fetch` |

Rows that need a decision are listed and never run: a buildbot core with no
profile, a new `.info` file, the Redump, No-Intro and TOSEC packs, the CI
pins, `profile_sync`, and a rom-folder pin (moved by hand in
`platforms/romfolders/_sources/`, then `python -m scripts.scraper.romfolders
--setup NAME` reads it again). `--dry-run --json` prints the plan as JSON.
A failed scraper leaves its cached original
untouched. Each job writes its output to `tmp/refresh_stale/`, and a GitHub
token is taken from `GITHUB_TOKEN` or from `gh auth token`.

A platform that inherits from a rescraped one (`lakka` and `retropie` from
`retroarch`) reads the parent's file, so its jobs start once the parent's have
ended, and its export is rewritten even when no row named it. A rescrape can
add systems whose files the collection lacks: the report ends with the
`verify.py --platform` summary of every rescraped platform, to read before
keeping the new YAML.

```bash
python scripts/refresh_stale.py --dry-run
python scripts/refresh_stale.py
python scripts/refresh_stale.py --only platforms,targets --jobs 6
```

### autorun.py

Runs the jobs declared in `automation/jobs.yml`, one at a time. Nothing is
scheduled by default: a maintainer runs a job by hand, and a contributor who
wants a schedule on their own machine installs the timers below. The registry
holds each job's commands, its gate, the artifacts computed twice, the paths
each commit may carry and the schedule. Changing any of them is a reviewed
commit.

| Guard | Rule |
|-------|------|
| Lock | One host-wide `flock` on `~/.local/state/retrobios/auto.lock` (`RETROBIOS_AUTO_LOCK` moves it). A job that finds it held is `deferred`. |
| Load | Waits while the 1-minute load is above a quarter of the CPUs, up to `max_load_wait` seconds, then `deferred`. |
| Disk | Below the job's `min_free_gb` the job is `refused`. Under 100 GB free the `disk` alert is raised. |
| Retry | Exit 139 (or signal 11), `SystemError` or "unknown opcode" is run again once on an idle host. A second failure is a failure. |
| Environment | A step, gate or recomputation inherits `PATH`, `HOME`, `LANG`, `LC_*`, `TZ` and `TMPDIR`, the runner's own markers and the variables its `env:` key names. A name with `TOKEN`, `SECRET` or `PASS` in it, `GH_TOKEN` and the RomStation account are dropped even when named, and a step naming one is refused when the registry loads. `GITHUB_TOKEN` goes to the push, the `gh` calls that read CI, and a step marked `github_token: true`. The registry accepts that key only on `python scripts/check_freshness.py`, `python scripts/refresh_stale.py` and `python -m scripts.scraper.*` tracked in this repository, and never in the `campaign` job. |
| Double computation | Each `twice` entry recomputes an artifact the gate wrote and compares both, timestamps aside. A difference is recomputed once on an idle host, then the job fails with the `host-integrity` alert. |

Jobs that commit run in `.cache/autorun/worktree`, on the branch `autorun`,
never in the shared checkout and its index. The first run creates it and
hard-links `.cache/large/`, `data/` and the gitignored `bios/` files from the
main checkout. Before each job it is fast-forwarded, or rebased when it holds
unpushed commits, onto `origin/main`. A job that finds anything uncommitted
there stops as `blocked` and cleans nothing. Commits name their files
(`git commit -- <paths>`), and their subjects are checked against
`scripts/commit_rules.py`, the rules the commit-msg hook runs, when the
registry loads. A job that leaves a change no commit
rule takes fails.

`--push` sends the batch: rebase on `origin/main` (a conflict keeps the batch
and pushes nothing), the gate again when `origin/main` moved, then a push that
never forces. It is off by default. A push waits while the previous automation
push has no green CI. A red run on a pushed automation commit, read with
`gh run list`, opens a circuit breaker: every committing job is `blocked`
until a green run on `main` follows.

State is `.cache/autorun/state.json`, logs are
`.cache/autorun/logs/<job>/<date>.log`, kept 30 days. A job's `report` key
names a JSON file one of its steps writes, and the runner keeps it in the
job's status. A report holding an `alert` raises the `job:<name>` alert
until a report without one. Exit codes: 0 for `ok`,
75 for `deferred`, 1 otherwise.

| Job | Schedule | What it does |
|-----|----------|--------------|
| `nightly` | 02:00 | `check_freshness.py --json` saved to a file, `refresh_stale.py --findings` on its `data` and `catalogs` rows, the MAME and FBNeo hash scrapers, then `pipeline.py --offline` as the gate. `database.json` and `install/*.json` are computed a second time and compared. Commits the hash profiles, the recipes, the game catalogs and the regenerated records |
| `assets` | 04:30 | `sync_release_assets.py`, as a dry run |
| `bios-integrity` | Sunday 08:30 | `bios_integrity.py --apply --json` in the main checkout, once the host is idle (up to four hours of waiting). Its report is kept in the job's status |
| `cleanup` | 05:30 | `cleanup_disk.py --apply --hours 72` in the main checkout |
| `disk-check` | hourly | `cleanup_disk.py --check`, without the lock |

```bash
python scripts/autorun.py run nightly --dry-run   # commands and the files each commit would take
python scripts/autorun.py run nightly
python scripts/autorun.py run nightly --push
python scripts/autorun.py status
python scripts/autorun.py status --json
python scripts/autorun.py install-timers          # writes systemd user units, enables nothing
python scripts/autorun.py install-timers --enable
```

`install-timers` writes `retrobios@.service` and one `retrobios-<job>.timer`
per scheduled job into `--unit-dir` (default `~/.config/systemd/user`).
`--enable` also runs `systemctl --user daemon-reload` and enables the timers.
`--with-push` writes units whose jobs run with `--push`.

### cleanup_disk.py

Frees the space idle session worktrees and `tmp/` hold. The candidates are
the linked worktrees placed inside the checkout, where sessions create
theirs. One is removed only when no process uses it, it is older than
`--hours`, and nothing tracked changed in it but generated files
(`database.json`, `install/*.json`, `exports/*.json`, `README.md`,
`CONTRIBUTING.md`, `website/src/data/*.json`). One holding real changes is listed, never removed. Branches
are always kept. A worktree elsewhere on disk and the automation worktree are
never candidates. `tmp/` entries older than `--hours` that no process uses
are removed, except `tmp/acquire`, `*.bundle` and an entry that holds a
linked worktree.

The last line gives free space, with an `ALERT` line under `--alert-gb`
(default 100), and the exit code is then 1. `--check` reports space only.

```bash
python scripts/cleanup_disk.py                    # dry run
python scripts/cleanup_disk.py --apply --hours 72
python scripts/cleanup_disk.py --check
```

### bios_integrity.py

A flipped bit keeps a file's size and mtime, so `git status` never shows it.
This rehashes every file `database.json` names and compares the SHA-1. A
mismatch is read a second time: two reads that disagree are a host misread
and change nothing. A confirmed mismatch on a committed file that git sees as
unmodified is restored from its blob in HEAD with `--apply`, once the blob's
object id and its content SHA-1 both check out, then hashed again. A file git
lists as modified is a working change and is left alone. A gitignored large
file, an untracked one, or a HEAD blob holding other bytes than the database
records is flagged, never repaired. The exit code is 1 while anything is
flagged. Run it on an idle host, since a busy CPU here computes wrong hashes.

```bash
python scripts/bios_integrity.py                  # report only
python scripts/bios_integrity.py --apply --json   # restore committed flips
python scripts/bios_integrity.py --db database.json
```

### sync_release_assets.py

Uploads the `large-files` assets that `check_release_assets.py` reports
missing, at another size or with another sha256. A file goes out only when
its SHA-1, read twice, gives the same value both times and equals the SHA-1
`database.json` records for its path. The asset keeps the name
`largefiles.asset_names()` gives it, a failed upload is tried once more, and
the release is read again afterwards. The release description is never
edited. Dry run by default. The exit code is 1 while an asset stays out of
date or is refused, so the nightly `assets` job reports it.

```bash
python scripts/sync_release_assets.py
python scripts/sync_release_assets.py --apply
```

### core_probe.py

Runs a libretro core with no window, no sound and no input device, and
reports what it did. It is the test in real conditions behind a claim about
a core: which files it opens, what it shows, which BIOS it ran.

These probes run on demand only, for three cases: to settle a dispute or an issue, to back a correction sent to a platform, and to check the packs before a release. They are never run as a campaign over every emulator, and the site keeps no showcase of their runs: an emulator page shows a run only when a profile's `evidence:` names it or it answers an issue (`issue<N>-` subjects). Its **Proof** section has one line per claim, every record of that claim linked on it, and says what the runs showed: the BIOS the core ran, or the file strace saw it open. What an issue's run showed comes from `tests/campaign/observations.yml`, written by whoever watched it, and a run with nothing to state stays off the page. Every record stays in `measurements/` and on the Measurements page. Benchmarks (`bench`) stay in the records and the SQLite files and
only choose between variants: no page shows a time per frame.

```bash
# one run, printed as JSON
python scripts/core_probe.py run --core mednafen_saturn_libretro.so \
  --content game.cue --system-file sega_101.bin=bios/Sega/Saturn/sega_101.bin \
  --option beetle_saturn_region=Japan --frames 600

# timed repetitions after warm-up, written as a record
python scripts/core_probe.py bench --core core.so --content game.cue \
  --warmup 300 --frames 3000 --repeat 5 --record

# one system file swapped between runs, compared on one observable
python scripts/core_probe.py check --core core.so --content disc.cue \
  --vary mpeg_card.bin=a.bin --vary mpeg_card.bin=b.bin --vary mpeg_card.bin= \
  --observable video_sha1 --claim "..." --method "..." --record

# negative variants: the file, zeros of its size, its first half
python scripts/core_probe.py check --core core.so --content disc.cue \
  --frame-hash-every 10 --vary scph5501.bin=bios/scph5501.bin \
  --vary scph5501.bin=@zeros:524288 --vary scph5501.bin=@head:262144:bios/scph5501.bin \
  --observable frame_hashes --claim "..." --method "..." --repeat 2 --record
```

One measurement runs at a time on the host. core_probe takes the host lock
itself, per run: `~/.local/state/retrobios/probe.lock` (`RETROBIOS_PROBE_LOCK`
names another file), from its load check to its record, released when the run
ends. A run that finds it held waits and says so. Never wrap a whole pass in
`flock`: a pass of many runs then holds the host for hours, while called
directly its runs interleave with everyone else's. A caller that holds the
lock around one core_probe call sets `RETROBIOS_PROBE_LOCK_HELD=1`. The tests
use their own lock file.

Each repetition runs in a fresh process under `strace -f -e trace=openat,open`
when strace is installed. The worker starts with an empty environment and
clears its own before it loads the core, keeping only the `--env` values.
When bubblewrap works on the host, the worker runs in it, built as an
allowlist: `/usr` and the `/lib*`, `/bin`, `/sbin` links, the files of `/etc`
the loader, fonts, TLS, the clock and user lookups read, all read-only. Home,
`/tmp` and `/mnt` are empty, the core, the content folder and the staged
system directory are read-only, and only the repetition's scratch folder is
writable. Every namespace is unshared, the network included, so nothing of
the user (`~/.config`, `~/.ssh`, `~/.git-credentials`) or of the checkout is
there to read. Each repetition names what it ran under in `isolation`
(`bwrap`, or `environment only` with the reason), and `--require-sandbox`
refuses to run without it. The files the core opened under the system
directory come from the kernel, each hashed again after the run. Without
strace the record says that tracing was unavailable.

**Boot oracle.** Every repetition and every variant carries a `verdict` and
the `verdict_evidence` that decided it (record version 4), judged against
`tests/campaign/oracle.yml` (`--oracle`), in this order:

| Verdict | Evidence |
|---------|----------|
| `hang` | the worker was killed after `--timeout` (`timeout`) |
| `crash` | the worker died, by exit status or signal (`exit_status`). Its logs and sampled frames are rebuilt from the events it streamed |
| `boots` | a sampled frame or the last frame is a `game` reference frame of this content on this core (`reference_frame`), with the `stages` reached: `bios` for a screen only the console's BIOS draws, `game` for one of the content. The BIOS screens alone are never a boot: the stages go into the evidence of the verdict below |
| `bios_error` | a log line matches an error pattern of the core (`error_pattern`), or a frame is one of its error screens (`error_screen`) |
| `hang` | every sampled frame of the second half is one colour (`uniform_tail`) |
| `unknown` | none of these (`no_evidence`) |

A variant's verdict is the one all its repetitions agree on, else `unknown`
(`repetitions_disagree`). A check lists them in `check.result.verdicts`, and
`inputs.oracle` keeps what they were judged against. The oracle finds a
content by the sha1 of the file handed to the core and a core by its library
name. A reference frame is recorded once with the full BIOS set and reviewed
by looking at its PNG. An error pattern is a log line after which the core
stops, read from its source: a line a core logs before it falls back to a
built-in BIOS is not one. A BIOS load pattern is the line a core logs once
it keeps the console's BIOS: it adds the `bios` stage for a core that hides
the BIOS screens by default (PCSX-ReARMed). Frames that differ from another run never make a
boot.

**The BIOS a run used.** Beetle PSX, SwanStation, PCSX-ReARMed and Flycast run
a built-in BIOS (OpenBIOS, HLE, reios) when they refuse or miss the file they
want, and the game boots. Each repetition and variant therefore names the BIOS
it ran in `bios_used` (record version 5), read from the core's log:

| `bios_used` | When |
|-------------|------|
| `staged:<dest>` | a load pattern of the core names the file (Beetle `Firmware found: ...`, PCSX-ReARMed `Loaded BIOS "..."`, SwanStation `Using BIOS '...'`) |
| `builtin` | a fallback pattern says the core ran its own BIOS (Beetle `Firmware is missing`, PCSX-ReARMed `No BIOS files found.`, SwanStation `No BIOS image found for ... region`, Flycast `Did not load BIOS, using reios`) |
| `unknown` | the log says neither. A file the core opened is no proof: Beetle hashes every file of the folder before it decides |

The last such line of the log decides, and every pattern carries the
`source_ref` it was read from. A boot on `builtin` reads "boots on its built-in
BIOS" on every page, and a boot is said to be another region's BIOS only when
`bios_used` names that file.

`core_probe.py rejudge` judges recorded runs again with the oracle as it stands,
offline: no core runs. For each live record of `core_probe` (another probe's
records are left to it) whose verdicts or `bios_used` come out otherwise, it
appends the same runs judged again, which `supersedes` the record and carries
`judged_at` and `judged_by` beside the unchanged `recorded_at`. `--emulator`
narrows it, `--dry-run` prints what would be appended. The campaign reads a
superseded record as its successor.

```bash
python scripts/core_probe.py rejudge --dry-run
python scripts/core_probe.py rejudge --emulator beetle_psx
```

`python scripts/core_probe.py <mode> --help` lists every option. These need
more than its one line:

| Option | Effect |
|--------|--------|
| `--timeout` | seconds allowed per repetition (default 1800), after which the run is killed and judged a hang |
| `--repeat N` | runs of each variant, each in a fresh process (`run` defaults to 1, `check` to 2, `bench` to 5) |
| `--vary DEST=SRC` | (`check`) one variant per occurrence. An empty SRC leaves DEST absent, `@zeros:SIZE` stages SIZE zero bytes and `@head:SIZE:PATH` the first SIZE bytes of PATH |
| `--option KEY=VALUE` | core option. Unset options take the first value the core declares |
| `--press FRAME:BUTTON[:LEN]` | hold a libretro joypad button on port 0 (`a`, `b`, `start`, `up`...). A menu may need 15 frames or more to see it |
| `--env KEY=VALUE` | environment of the core process. A core that reads the host clock repeats only with the clock fixed, for example `LD_PRELOAD` of a clock shim. `LD_PRELOAD` must name each library by an absolute path to a file, or the run is refused: the loader skips a library it cannot find without a word. A value naming a file is recorded by file name and sha256 |
| `--core-repo`, `--core-commit`, `--build-command` | where the core build comes from, copied into the record. No core binary is kept in the repository: a record is reproduced by building the core again at that commit, so a nightly recorded without its commit cannot be |
| `--record [DIR]` | append the record as one line of `measurements/<emulator>.jsonl` in the checkout `DIR`, by default this one. `DIR` must be the root of a git checkout, never its `measurements/` folder. Commit it |
| `--emulator` | the profile the record is filed under. By default the profile whose `cores:` names the `.so`, else the core's library name |
| `--subject` | a slug naming the test, shared by its reruns. By default derived from the claim and method, or from the inputs of a run or bench |
| `--core-artifact URL` | where a downloaded `.so` came from, such as a buildbot nightly, copied into the record |
| `--joypad-ports N` | ports given a joypad after loading, as RetroArch does (default 2). |
| `--state-var SECTION.VAR`, `--state-dir` | a variable of a Mednafen save state as an observable, and a folder that keeps the state of the first repetition to read it again |
| `--max-load` | refuse to record above this 1-minute load average (default a quarter of the CPUs). Never raise it: a busy host computes wrong hashes |
| `--no-trace` | run without strace. The record then says that tracing was unavailable |
| `@FILE` | read arguments from FILE, one per line |

Observables are `frame_sha1` (last frame), `video_sha1` (every frame, chained),
`audio_sha1`, `state_sha1` (save state at the end), plus `state:SECTION.VAR`
and `frame_hashes` when asked for, with `uniform_frames` (the sampled frames
of a single colour) beside it. A repetition that disagrees with the first
one is flagged. A `check` reports `inconclusive` instead of a comparison when,
in any variant, the compared observable differs between repetitions, a run did
not load, or a file changed during the run. A disagreement on another
observable stays flagged in the record. In core log lines, the staged system,
save and content directories read `<system>`, `<save>` and `<content>`. A record carries the core build (sha256 of the
`.so`, the compilers its `.comment` section names), the frontend commit, the
host (CPU, kernel, Python, load before and after) and each input by hash.
Core log lines arrive through the libretro log interface. Floating-point
arguments of a log line cannot be read from Python and print as `<double>`.

A record is stored whole, as one line (`measurement_records.py`): the claim,
method, result, host, core build, frontend commit, inputs by hash, and every
repetition of every variant in full (per-frame hashes, core logs, declared
options), with the raw timing values the statistics come from. The id is the
date and the first 12 hex digits of the sha256 of the record without its id,
in canonical JSON. Schema: `core-probe-record.schema.json`.

### Measurement records

The records live in `measurements/` of this repository, one file per
emulator: `measurements/<emulator>.jsonl`, one full record per line in the
order added. A line is never rewritten or removed: a new run is a new line at
the end of its file, and a correction is a new line naming the record it
`supersedes`. Every line must hash to its id and validate against the record
schema, which `validate_schemas.py` checks. `tests/test_measurements.py`
fails when a line that HEAD holds has changed or gone. The seven records of
2026-10-27 were first written one JSON file per run, then split into a line
and a gzip data file, then merged back into one line. Each keeps its first
id, which hashes the first file (`migrated_from_version: 1`), so the line
still proves it rebuilds that file. Two branches that each add a line
merge cleanly: `.gitattributes` marks `measurements/*.jsonl` `merge=union`.
`findings.jsonl` and `campaign-runs.jsonl` sit beside the records under the
same rules, written by `campaign.py`, and no profile takes those names.

`generate_site.py` compiles the records into files it never commits
(`sitemeasurements.py`): `public/data/measurements/index.json` (one item per
emulator and subject, its latest record not superseded, with method, host and
the permalink of its line), `public/downloads/measurements.sqlite`
(normalised tables, indexed on emulator, system and claim, `meta` naming the
commit) and one `public/downloads/measurements/<emulator>.sqlite` per
emulator. A permalink names the last commit that touched `measurements/`, and
the build warns when the records on disk differ from that commit. Rows are
sorted and nothing reads the clock, so two builds give the same bytes.

### campaign.py

Runs a batch of `core_probe.py` checks for the profiles a question names
(`--only`, `--system`): it gets the core and the test content, runs the
checks, applies what the runs prove and queues the rest. A maintainer runs it
on demand, for one of the three cases of `core_probe.py`, never over every
profile as a standing campaign. It is a thin layer over
`core_probe.py`, the libretro buildbot and romfetch. RetroArch's
`--max-frames` and libretro.py were the other candidates: neither traces the
files a core opens nor writes a record.

```bash
python scripts/campaign.py run --system sony-playstation --budget 6h
python scripts/campaign.py run --only beetle_psx,swanstation --dry-run
python scripts/campaign.py run --commit --commit-every 10
python scripts/campaign.py run --only pcsx_rearmed --bench   # with benchmarks
python scripts/campaign.py references --only beetle_psx --system sony-playstation
python scripts/campaign.py references --only beetle_saturn --content-file other.yml   # another content list
python scripts/campaign.py status            # done, failed, pending, and why
python scripts/campaign.py findings          # what waits for review
python scripts/campaign.py review beetle_psx/sony-playstation/scph5501.bin/validation \
  --status applied --set on_mismatch=warn --reason "logs the SHA1 and loads (libretro.c:853-860)"
python scripts/campaign.py gate              # the checks behind a commit
```

| Step | What happens |
|------|--------------|
| Core | The x86_64 Linux nightly from `buildbot.libretro.com`, for each name of the profile's `cores:` the buildbot publishes, downloaded again only when its `ETag` or `Last-Modified` changes. The record keeps the artifact URL, the `.so` sha256 and the `retro_get_system_info` version. With no nightly, the profile's `source_commit` is cloned and built once with `make` (`Makefile.libretro` first), the failure kept so it is not tried again for that commit. Host git only fetches into bare mirrors (`.cache/campaign/mirrors/`), one per repository, submodules included, that it alone touches: no working tree, never bound into a sandbox, and earlier working-tree clones are deleted. It runs with no user or system config, https as the only transport, and `-c` overrides emptying hooks, `core.fsmonitor`, `core.sshCommand`, `core.gitProxy`, credential helpers and every filter driver the mirror's config defines. The commit and each submodule at the commit its tree records are exported with `git archive` into a fresh folder, and `make` runs there in the same bubblewrap sandbox as a core, that folder the one writable path. The core copied out is the newest `*_libretro.so` that is a regular file inside that folder, opened without following links. The record's `build_command` says which isolation was used. A standalone emulator is `pending: standalone` |
| Content | Each system's games come from `tests/campaign/content.yml`, by catalog name and with the reason each was chosen. They are read from `.cache/test-content/<romfetch system>/<name>/`, each file checked against its `identity.json`. Missing content is fetched with `romfetch get <system> <name> --json` when romfetch is on `PATH`, in `RETROBIOS_ROMFETCH` or given with `--romfetch`. Otherwise the checks are `pending: content`, with romfetch's exit code and error code when it failed. Content never enters git, and a record keeps only its identity |
| Checks | `files` stages every declared file the collection holds (the full set) and reads which ones the core opens (strace). `none` runs the game with no BIOS at all. `negative` runs, for each declared file of the game's region the collection holds, the file alone, then zeros of its size, its first half and up to two other regions' dumps staged under its name. An entry neither the full set nor its own run opened is staged where the core looked for it (`path`), else flagged. The `boot_file:` entry is also staged under the names the core looked for with no BIOS (`alias`). `variants` runs each `.variants/` copy of a file the core opened. Each runs twice from a fresh process and is judged by the boot oracle. `bench` (only with `--bench`) times the game once the full set boots, warm-up excluded, 5 repetitions |
| Rules | `campaign_rules.py`, a fixed table of pure functions (below). A field the table settles is written into the profile, with `evidence:` naming the record ids. Anything else is a line of `measurements/findings.jsonl` |
| Content reuse | A game stays on disk until the last emulator that needs it in the pass is done, then the campaign deletes it if it fetched it. Past `--cache-cap-gb` (default 20) the least recently used goes first. An entry marked `pinned:`, or one the campaign did not fetch, is never deleted |

| Verdicts | Field | Written |
|----------|-------|---------|
| `none` boots, and the file changes the run: alone or as a wrong file, another verdict or other stages than with no BIOS | `hle_fallback` | `true`. A file the game never uses settles nothing: a core can open every file of the folder to hash it |
| `none` fails (`bios_error`, `crash`, `hang`) and the file alone boots | `required`, `hle_fallback` | `true`, `false` |
| Zeros of the file's size refused while the file boots | `validation` | a content check is proven. Agreeing adds evidence, a profile with no md5, sha1, sha256, crc32, adler32 or signature is an open finding |
| Zeros used while the file boots | `validation` | no content check. A profile that declares one is an open finding, unless it declares the check with `on_mismatch: warn` |
| Its first half refused while zeros are used | `validation` | `size`, added when missing |
| Its first half used | `validation` | no size check. A profile that declares one is an open finding |
| The core opened the file staged at another place it looked for | `path` | that path |
| The core opened the file staged under a name no entry declares | `aliases` | the name added |
| A staged file the game's region uses, never opened, staged alone either | nothing | flagged |
| Copies of one file whose verdicts differ | nothing | open finding |
| Anything else (an `unknown`, a profile that says `required: true` for a file the core boots without) | nothing | open finding |

A wrong file is refused when the run reports `bios_error`, or boots without
the `bios` screens the right file shows: the core fell back to a built-in
BIOS. It is used when it turns the run into a `hang` or a `crash` that the
run with no BIOS does not show. Another region's dump is recorded with its
verdict, and the region claims are settled by their own test. Evidence that a
record from before the oracle wrote no longer counts: when a verdict settles a
field again, those ids leave its `evidence:`.

`references` runs the full set once per core and content with every sampled
frame written as PNG under `tmp/campaign/references/<core>/<content>/`, and
prints the record id with the screens that stay on for 3 samples or more in
every repetition. A reviewer opens those PNGs and writes the chosen frames
into `tests/campaign/oracle.yml` with their stage and what they show.

The rules run on every pass, from the kept records when no check needs to run
again, so a change of the table applies without a run. A run that agrees with
the profile adds its record id to `evidence:` and
resolves an open finding of the same field. The profile is edited as text and
the edit is refused unless the result parses to the same profile with only
those fields changed.

State lives in `.cache/campaign/state.json` of the main checkout: each check
is `done`, `failed` (with the reason and its log) or `pending` (with the
reason), with the core sha256, the profile digest, the oracle entries of its
content and core (by sha1) and the record version it ran against. A pass
skips a check that is done or failed against the same four, so it
takes new nightlies, changed profiles, newly fetched content and pending
checks. The campaign's own `evidence:` writes do not count as a profile change.

| Guard | Rule |
|-------|------|
| Lock | The host-wide autorun lock. When a caller already holds it, `RETROBIOS_AUTO_LOCK_HELD` says so |
| Probe lock | Not held by the pass: each core_probe it starts takes the host probe lock for its own run, so the pass and other measurements (pack_probe, a core_probe loop) interleave. Two campaign passes still exclude each other through the automation lock, since they share `.cache/campaign/state.json`. Do not wrap `campaign.py run` in `flock` |
| Environment | `core_probe.py`, git and `make` get autorun's allowlist, romfetch the same plus its `ROMFETCH_*` settings. None sees a token or a password |
| Sandbox | Fails closed: without a working bubblewrap the pass is `refused` (exit 3) and nothing third-party runs, every probe is started with `--require-sandbox`, and a build is refused. `--allow-unsandboxed` overrides |
| Load | Before each run, waits while the 1-minute load is above a quarter of the CPUs, up to `--max-load-wait` seconds, then the pass stops as `paused` |
| Disk | Below `--min-free-gb` (default 30) the pass stops as `paused` |
| Budget | No check starts after `--budget` |
| Timeout | A repetition is killed after 900 seconds and judged `hang`. A core_probe call that outlives all its repetitions is `failed: timeout` |
| Crash | A core that dies is a `crash` verdict in its record. A core_probe call that fails for another reason is tried 3 times, then `failed` with its log |
| Network | Buildbot and romfetch source errors are retried after 10, 60 and 300 seconds |

Each pass appends one line to `measurements/campaign-runs.jsonl`: when it ran,
how it ended, the checks done, failed and pending by reason, the records and
the findings it added. Logs are `.cache/campaign/logs/`, kept 30 days.

`--commit` commits the records, findings and pass line in one commit, and
each changed profile in its own, behind `campaign.py gate`: the measurement
and campaign tests, `validate_schemas.py --source-only`, then `verify.py
--emulator` and `generate_pack.py --emulator` for each changed profile. A file
that had uncommitted changes before the pass is left alone.

A maintainer starts each pass, for a question that names its profiles. No
autorun job runs it on a schedule.

`review` closes an open finding once someone has read the core's code at the
profile's pin. `--status applied` writes each `--set FIELD=YAML` into the
entry the finding names, through the same profile editor, with the finding's
record ids added to `evidence:` under its field. With no `--set` it records a
profile already changed by hand. `--status rejected` keeps the profile as it
is. `--reason` is required and goes on the finding's line, with the file:line
it rests on. `--index` picks the entry when several share the file's name. A
rejected finding stays closed while later runs show the same thing.

Schemas: `campaign-finding.schema.json` and `campaign-run.schema.json`.

### region_check.py

Proves the `region:` fields of a profile on a real run. For each test game
of a region in `tests/campaign/content.yml`, it runs `core_probe.py` four
times, each a record whose subject is `region-<core>-<game>-<variant>`.

| Variant | BIOS staged |
|---------|-------------|
| `full` | every regional BIOS of the system the collection holds |
| `own` | only the entries whose `region:` holds the game's region |
| `others` | only the entries of the other regions |
| `pack` | the files of `generate_pack.py --emulator E --region R`, where the pack puts them |

```bash
python scripts/region_check.py run \
  --emulator beetle_psx --system sony-playstation --core-name mednafen_psx
python scripts/region_check.py report        # the outcome of every region record, as JSON
```

`region_check.py run --help` lists the options. The nightly `--core-name`
names is downloaded once into `.cache/region/cores/`. `--core` and
`--core-artifact` run a core built elsewhere instead, `--content-dir` points
at another romfetch folder, and `--variants` reruns some of the four runs only. A run refused on a busy
host is tried again every 15 seconds for `--max-load-wait` seconds, and the
load threshold stays core_probe's.

The file the core opened in the `full` run, read from strace, settles the
claim: `confirmed` when its `region:` holds the game's region, `contradicted`
when it does not, `ambiguous` when the core opened its own region's file and the others too (PCSX-ReARMed opens all three), `unread` when it opened none of them. Each variant's
result is the oracle verdict of its record. While the oracle has no reference
frame for a game, a variant counts as booting when it samples the same frames
as the `full` run, and the outcome says it was judged that way. Other frames give no verdict: the US disc reaches its game on the Japanese and European BIOS through another licence screen. A boot
counts as another region's BIOS only when `bios_used` names that file: Beetle
PSX and SwanStation boot their built-in OpenBIOS with only the other regions'
files, which they refused. `report` prints the outcomes as JSON, and no page
shows them: a profile's `region:` cites a record in its `evidence:` when one
settles it. A maintainer starts each run, on demand. Each core_probe run takes the host probe lock for itself and frees it before the next, so do not wrap the command in `flock`. Nothing runs by itself.

### standalone_probe.py

Runs a platform's standalone emulator on a game and records it like
`core_probe.py`, in the same `measurements/<emulator>.jsonl` and the same
record schema (`frontend.script` names this script). No existing harness
traces the files a standalone emulator opens or writes a record, so this is
a thin layer over the emulator's own batch mode, Xvfb and core_probe's
sandbox, oracle and record functions, imported and not copied. Like
`core_probe.py`, it runs on demand only: for an issue or a dispute, to back a
correction sent to a platform, or to check the packs before a release.

```bash
python scripts/standalone_probe.py resolve duckstation   # the asset EmuDeck's installer picks
python scripts/standalone_probe.py fetch duckstation     # download and unpack it, by sha256
python scripts/standalone_probe.py run duckstation \
  --content game.cue --content-label "Bust-A-Move 2 - Arcade Edition (USA)" \
  --bios-file scph5501.bin=bios/Sony/PlayStation/scph5501.bin \
  --samples 60 --interval 1.5 --require-sandbox --record
python scripts/standalone_probe.py check pcsx2 \
  --content game.bin --vary ps2-0230a-20080220.bin= \
  --vary "ps2-0230a-20080220.bin=bios/Sony/PlayStation 2/ps2-0230a-20080220.bin" \
  --claim "..." --method "..." --require-sandbox --record
```

| Step | What happens |
|------|--------------|
| Binary | The release asset the platform installs, chosen by its installer's own rule. EmuDeck's `getReleaseURLGH` takes the first asset, over GitHub's release list in its order, pre-releases included, whose name matches: `DuckStation-x64.AppImage` and `pcsx2-*-Qt.AppImage`. It is downloaded into `.cache/standalone/<emulator>/<sha256>/` and unpacked with `unsquashfs` at the offset the AppImage runtime computes, so the runtime is never run. The record names the asset, its release tag, its URL and its sha256 |
| Settings | Written before each repetition in a scratch data folder, `$XDG_CONFIG_HOME/duckstation/settings.ini` and `$XDG_CONFIG_HOME/PCSX2/inis/PCSX2.ini`, the places the emulators read on Linux. The BIOS folder setting names the staged BIOS folder, as EmuDeck points it at `Emulation/bios`. Software rendering, no update check, no setup wizard. `--setting SECTION.KEY=VALUE` adds one. The record lists every setting |
| Sandbox | The allowlist bubblewrap sandbox of `core_probe.py`: the unpacked emulator, the content folder and the staged BIOS folder read-only, the repetition's scratch folder the one writable path, no network. Xvfb runs inside it, on the sandbox's own `/tmp`, so the display is private to the run. `--require-sandbox` refuses to run without bubblewrap |
| Screen | Xvfb keeps its screen as a file (`-fbdir`). The probe reads it every `--interval` seconds, `--samples` times, and hashes each sample's pixels. `--png-dir` writes each distinct sample as PNG for review |
| Files | `strace -f` inside the sandbox: the files the emulator opened in the staged BIOS folder, and the ones it looked for there and did not find |
| Verdict | `core_probe.judge` on each repetition, with the oracle of `tests/campaign/oracle.yml` looked up by the content's sha1 and the emulator's name, plus the emulator's own error strings this script lists (DuckStation's "No BIOS image found for", PCSX2's "Unable to auto locate a BIOS image"). An emulator that exits before the last sample is a crash |

`standalone_probe.py <mode> --help` lists the options. `--sha256` runs an
older fetched asset than the newest. The ones it shares with `core_probe.py`
(`--record`, `--max-load`, `--no-trace`, `--require-sandbox`) mean the same
there, and `check` compares on `verdict` by default.

Supported: DuckStation and PCSX2. Dolphin, Flycast, PPSSPP, melonDS, xemu and
MAME are installed by EmuDeck from Flathub, Ryujinx from a Codeberg tarball and
RPCS3 from its own update server: each needs its installer's rule before it
can be added. Cemu is an AppImage like the two supported ones, and waits for
Wii U content, which no catalog romfetch reads holds. Each run takes the host probe lock (`RETROBIOS_PROBE_LOCK`) for itself, its load check included, and frees it when it ends, as `core_probe.py` does. A maintainer starts each run. Nothing runs
by itself.

### pack_probe.py

Tests what the project promises: a platform's pack, installed the way a user
installs it, starts that platform's games. A maintainer starts it before a
release, or to answer an issue about a pack, nothing runs it on a schedule. It takes the host's probe lock
(`~/.local/state/retrobios/probe.lock`, `RETROBIOS_PROBE_LOCK`) around each
`core_probe` run and releases it before the next, so other probes run between
its runs, and tells `core_probe` it holds it (`RETROBIOS_PROBE_LOCK_HELD=1`).
Never wrap the whole command in `flock`:

```bash
python scripts/pack_probe.py run --platform retroarch
python scripts/pack_probe.py run --platform batocera --system sega-saturn --install pack
python scripts/pack_probe.py plan --platform retrobat   # systems, games and cores, nothing run
```

`--system`, `--core` and `--install` narrow a run, `--pack` reuses a built
pack, `--fetch` gets a missing game through romfetch, `--refresh-cores`
downloads the nightlies again, and `--keep` leaves the laid-out folders in
`--work-dir` (default `tmp/pack_probe`) after the run.

| Step | What happens |
|------|--------------|
| Layout | `generate_pack.py --platform X --offline` builds the pack into `tmp/pack_probe/<platform>/dist` (`--pack` reuses one). `pack`: the archive extracted at the root of the BIOS folder, each file mapped to its member. `installer`: `install.py --platform X --dest <root>/system --save-dir <root>/saves --from-pack <pack> --manifest install/X.json --offline`, each file mapped to the manifest entry that names it (`files:`, `case_variants:`, `data_directories:`). Both by default, `--install` picks one |
| Games | `tests/campaign/content.yml` and `tests/campaign/pack_content.yml`, same format, read from `.cache/test-content` of the main checkout and checked against their `identity.json`. `--fetch` gets a missing one through romfetch |
| Cores | `resolve_platform_cores` with the target of the platform (`linux-x86_64` for RetroArch, `x86_64` for Batocera, `windows` for RetroBat), kept when the profile serves the system and its libretro build runs there: not a `standalone_cores` entry, unless `dual_mode_cores` names it. The `.so` is the buildbot's x86_64 Linux nightly, every build the target names, else the one named after the profile, else the first of its `cores:`. Kept in `.cache/pack-probe/cores` with its URL and `Last-Modified` |
| Staging | `core_probe.py` copies what it stages, and a pack holds gigabytes, so the probe stages what the core can reach: the profile's libretro entries (path or name, and aliases), the platform's list for the system, every file of the folders those sit in, and for a profile with `found_by: content` every root file of a size it declares. A file or folder the core then looks for that the layout holds is staged and the run repeated, up to 6 runs |
| Run | `core_probe.py run --require-sandbox --record`, the game's frames and frame sampling from its content entry, no core option set. The first run is recorded. When the staging grew, the closed staging runs again, recorded with `--supersedes` the first. Each run holds the probe lock. Before a recorded run, lock held, the probe waits for the 1-minute load to fall to a quarter of the CPUs, up to 30 minutes, then stops with exit 3 |

Each probe is one line of `measurements/pack-probes.jsonl`
(`pack-probe.schema.json`): the platform and its version, the install path,
the pack by sha256 and the manifest by sha256 and generation date, the commit
the pack was built from, the core build, the game, the `core_probe` record
ids, the verdict and its evidence from the record's first variant (`unknown`
for a record written before the boot oracle), every file the core opened
with the pack entry that put it there, and the findings:

| Finding | Meaning |
|---------|---------|
| `missing_declared` | the core looked for a file its profile declares, and the folder lacks it |
| `missing_undeclared` | the same for a name no entry of the profile declares |
| `elsewhere` | the folder holds a file of that name, compared without case, under another path |
| `not_staged` | the folder holds it, but the staging did not close within 6 runs |
| `unlisted` | the core opened a file of the folder that no pack member or manifest entry names |

A name the core tried before it read another name of the same profile entry
is no finding: BlastEm tries `tmss.md`, then reads `bios_MD.bin`.

The run cannot see two things the platform does: core options a frontend
sets (Batocera's configgen writes some), and the files the installer puts in
the save directory, counted in `source.save_dir_files`. A maintainer runs it
before a release (wiki/release-process.md). Its lines stay in
`measurements/pack-probes.jsonl`, and no page shows a table of them.

### Other tools

| Script | Purpose |
|--------|---------|
| `common.py` | Shared library: hash computation, file resolution, platform config loading, emulator profiles, target filtering |
| `retired_files.py` | The record of files that left the collection, `retired.json`, which `generate_db.py` appends to and the site's lookup reads. `--backfill` rebuilds it from the history of `database.json` since content addresses were published (`--output` names another file) |
| `dedup.py` | Deduplicate `bios/` (`--dry-run`, `--bios-dir`): byte-identical copies are deleted and one kept. Identical MAME sets under other names stay one file, named in `_mame_clones.json`. Trees addressed by path are left alone (`NODEDUP_DIRS`), under a folder of that name at any depth: BBK, Bungie, C-Dogs SDL, Ikemen GO, mame, PinMAME, RPG Maker, ScummVM, Softdisk, TheXTech, splitwolf, Theme Hospital, c64-emu, opentyrian, tzdata |
| `identity.py` | One content filed under two identities: groups `bios/` by content and reports a group that crosses manufacturers outside `KNOWN_SHARED` (`--strict` exits 1, pipeline step 3a) |
| `slots.py` | Destinations the platform and a core both claim, and how the pack settles each (`--platform`, `--target`, `--json`, `--strict`, and pipeline step 3b passes the run's own `--target`) |
| `region_audit.py` | Confront every profile `region:` with the regions No-Intro names for the same dump (`--json`, `--db`, `--emulators-dir`). An opinion, never an authority: the code decides, and a disagreement is a line to read in the emulator's source |
| `validate_pr.py` | Validate BIOS files in pull requests, post markdown report |
| `pr_checks.py` | Run the checks `validate.yml` runs on a pull request, in its order, past a failure as CI does, and name each check that failed or whose tool is absent (`--list` prints them) |
| `validate_schemas.py` | Validate the data contracts: schemas and semantic invariants. `--source-only` checks `emulators/` and `platforms/` alone, which is what PR validation runs |
| `generate_event_schema.py` | Write `schemas/install-events.schema.json` from `EVENT_KEYS` in `install.py` (`--check` exits 1 when the file is stale, which `validate_schemas.py` also reports) |
| `generate_installer_doc.py` | Rewrite the generated blocks of `wiki/installer.md` from `install.py`: the tables (options, events, exit codes, keys per route, card markers), the line menu, and the run samples `install.py` prints in a sandbox against the committed `install/*.json`, so a new list rewrites the page (`--check` exits 1 when a block is stale, `--page FILE` writes another copy of the page). Pipeline step 7 |
| `pin_installer.py` | Write the SHA-256 of `install.py` into the pins of `install.sh` and `install.ps1`, which refuse any other installer (`--check` writes nothing and exits 1 when a pin is stale). `check_freshness.py` reports a stale pin and `refresh_stale.py` runs this |
| `auto_fetch.py` | Fetch missing BIOS files from known sources (4-step pipeline). A download is accepted only when every cryptographic hash the entry declares (sha256, sha1, md5) matches. crc32 and size find a file the database already holds, never accept a download. An entry with no cryptographic hash is reported and not searched |
| `list_platforms.py` | List the registered platforms as JSON |
| `download.py` | Download a pack from GitHub releases, every part checked (Python, stdlib only) |
| `download.sh` | Same, as a shell one-liner (`curl` + `unzip`) |
| `split_pack.py` | Cut a pack over the release asset limit into parts that are each a ZIP of whole files, each with a marker naming every part, read back before the pack is removed |
| `provenance_report.py` | Dump-catalog coverage and acquisition targets (see above) |
| `find_pinned_revision.py` | Walk the upstream commits that touched a file and return the revision whose bytes match a platform's pinned md5 (`--write` saves them) |
| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |
| `generate_site.py` | Generate the site (this documentation) into the Starlight project in `website/` |
| `sitesources.py` | Record which cited source paths each pinned upstream tree holds, for the site's source links (`--fetch` reads a tree no cache holds) |
| `site_markdown.py` | Write each built page as Markdown beside its HTML (`<page>/index.md`, named in every page's head) and `llms-full.txt`, the guides and every setup's page in one file, for the assistants that read the site. The Astro build runs it once the pages are written |
| `site_insights.py` | What readers look for and do not find, from totals only: searches that show the site but are rarely clicked, file names searched and whether the collection holds them, site searches that found nothing, broken addresses, "Did this page help?" answers, GitHub traffic and release downloads (`--days`, `--skip gsc,goatcounter,github`, `--output`). Reads Search Console, GoatCounter and GitHub with credentials kept outside the repository. [What the site counts](privacy.md) |
| `make_demo.py` | Record the installer demos of the README and the site into `docs_assets/demo/`. An ArkOS card with six games is built under `tmp/demo/` in a mount namespace of the user, this checkout is served on loopback, and VHS runs one tape per variant: `default` (`install.tape`, the one-line command in a terminal, the card at `/media/EASYROMS`, needs `unshare`) and `handheld` (`install-handheld.tape`, the full-screen interface at 640x480 on an ArkOS root made with `bwrap`, as its Tools menu starts it, driven by the keys gptokeyb sends for the buttons). `--variant NAME` records one (repeatable), every variant by default, the others kept. Each needs `vhs`, `ttyd` and `ffmpeg`. The default gets the README's GIF, each gets a WebM, an MP4 and a poster, held to their size targets, and an entry in `demo.json` with what it shows and its alt text. No Windows variant: under pwsh on Linux the installer's summary gives `--dest /mnt/e/bios` back. Never run by the build |
| `validate_site.py` | Validate rendered metadata, heading order, image alternatives, JSON-LD, local resources, links and fragments, and the page size and search index budgets |
| `indexnow.py` | List the pages a deploy changes, read against the `digests.json` the live site serves, as the IndexNow request the deploy posts once the new site is live. `--dist` names the built site, `--output` appends the request to a step output |
| `romset_recipes.py` | Identify which emulator version an arcade archive matches, rebuild a pinned archive from ROMs already held, record a recipe for every archive the collection holds and build any of them from the members it holds (see [Archive recipes](#archive-recipes)) |
| `archive_build.py` | The archive recipes behind `romset_recipes.py --capture`, `--build` and `--build-all`: capture, member lookup by sha1, verified build |
| `scraper/romset_dat_importer.py` | Fetch and import per-set recipes from MAME `-listxml` or FBNeo DATs into `recipes/`. `--fetch` alone takes the newest MAME release, and FBNeo DATs are refreshed by git blob sha. `--fetch <revision>` reads FBNeo at that tag, branch or commit |
| `deterministic_zip.py` | The fixed date pack members carry. Its archive rebuild is no longer called by the pack, which copies each ZIP byte for byte |
| `torrentzip.py` | Build TorrentZip archives for MAME/FBNeo ROM sets (archive bytes depend only on contents, with stock zlib), streaming one member at a time |
| `crypto_verify.py` | 3DS RSA signature and AES crypto verification |
| `sect233r1.py` | Pure Python ECDSA verification on sect233r1 curve (3DS OTP cert) |
| `check_buildbot_system.py` | Detect stale data directories by comparing with buildbot |
| `check_freshness.py` | One report on every upstream the repository transcribes (see above) |
| `refresh_stale.py` | Run the refresher behind every stale row of that report (see above) |
| `autorun.py` | Run the unattended jobs of `automation/jobs.yml` under one lock, in their own worktree (see above) |
| `cleanup_disk.py` | Remove idle session worktrees and old `tmp/` entries, alert under 100 GB free (see above) |
| `bios_integrity.py` | Rehash every file the database names, restore a confirmed bit flip of a committed file from HEAD (see above) |
| `sync_release_assets.py` | Upload the `large-files` assets the release serves out of date, after a double SHA-1 check (see above) |
| `migrate.py` | Migrate flat bios structure to Manufacturer/Console/ hierarchy |

Further options, by script:

| Script | Options |
|--------|---------|
| `auto_fetch.py` | `--create-issues` prints a GitHub issue body per platform for the files still missing, with their full hashes. It posts nothing |
| `check_buildbot_system.py` | `--update` refreshes the entries found stale, `--json`, `--registry` |
| `check_freshness.py` | `--cache-dir`, `--native-cache-dir` (originals of the native export) and `--truth-dir` move the caches it reads |
| `check_release.py` | `--tag`, `--sums dist/SHA256SUMS.txt`, `--record` (default `release.json`), `--json` |
| `check_release_assets.py` | `--gitignore` (the asset registry), `--db`, `--notes FILE`, `--json` |
| `diff_truth.py` | `--format markdown` (or `--markdown`), `--json` (one of them), `--truth-dir`, `--target` |
| `download.py` | `--list`, `--info <platform>` shows a pack's file name, size and parts without downloading |
| `export_native.py` | `--truth-dir`, `--upstream-dir` (where the platforms' own files are cached) |
| `find_pinned_revision.py` | `--repo URL --path FILE --md5 HASH`, `--write PATH`, `--cache-dir` |
| `generate_db.py` | `--provenance-dir` (dump-catalog snapshots joined into the database) |
| `generate_site.py` | `--site-dir` (the Starlight project, `website/` by default), `--docs-dir` (the pages, `src/content/docs` of that project by default) |
| `mame_ref_audit.py` | `--write` points each stale ref at the line declaring its set, `--offline`, `--cache-dir` |
| `migrate.py` | `--dry-run`, `--include-branches` also reads BIOS files from every remote branch |
| `provenance_report.py` | `--provenance-dir`, `--write-derivable PATH` (with `--derive`, and the pipeline writes `derivable.json`) |
| `refresh_stale.py` | `--freshness-arg FLAG` passes a flag through to `check_freshness.py`, repeatable. `--findings FILE` reads a saved `check_freshness.py --json` report instead of running it, kept to the `--only` areas |
| `bundled_only.py` | `--strict` (exit 1 while a collected file only an emulator install provides remains, pipeline step 4d), `--json`, `--install-dir`. Lists every copy of such a file, the database keeping one path per content |
| `release_record.py` | `--install-dir` (manifests the archives are held against), `--platforms-dir` (registry the full pack names are rebuilt from: any other pack in the directory is refused), `--output` |
| `release_notes.py` | `--whats-new FILE` (required, appended as written), `--record`, `--platforms-dir`, `--output` |
| `restore_large_files.py` | `--cache` (downloaded assets), `--gitignore`, `--db` |
| `romset_recipes.py` | `--dat-recipes PATH`, a snapshot or a directory of them (default `recipes/`). `--archives FILE` (default `recipes/archives.json`), `--output-dir DIR` for `--build` and `--build-all`, `--discard` deletes each build once verified |
| `split_pack.py` | `--max-size 1900M`, the ceiling per part (K, M, G, default 2G) |
| `torrentzip.py` | `--check ZIP` reports conformance, `--rebuild ZIP -o OUT` normalizes an archive |
| `validate_pr.py` | `--changed` takes the BIOS files the branch changes, a folder named checks every file under it, `--place` copies each recognised file from outside `bios/` to its folder and declared name (or its `.variants/` slot), `--markdown`, `--json` |
| `validate_site.py` | `--site-dir` (rendered site, default `website/dist`), `--base` (path the site is served under), `--max-errors N` |
| `scraper/coreinfo_scraper.py` | `--compare-db database.json` lists the `.info` firmware the database lacks |
| `scraper/mame_hash_scraper.py` | `--release mameNNNN --profile FILE --source-commit SHA --core NAME --built-by PLATFORM` writes the profile of a MAME build a platform compiles. `--devices --listxml FILE` documents in `mame.yml` every device set with dumped ROMs that the release's `-listxml` names (`isdevice="yes"`), with `--dry-run` to preview |
| `scraper/romset_dat_importer.py` | `--cache-dir` (downloaded listxml and DATs) |
| `scraper/game_dat_importer.py` | `--source no-intro\|redump` (repeatable), `--pack FILE` imports a local ZIP, directory or DAT, `--refresh` asks the servers again, `--cache-dir`, `--output-dir`, `--dry-run` |
| `scraper/arcade_parent_importer.py` | `--profile NAME` (one core version), `--emulators-dir`, `--db` (BIOS roots checked against it by archive name), `--output-dir`, `--cache-dir`, `--offline`, `--dry-run` |
| `scraper/romfolders` | `--sources DIR` (default `platforms/romfolders/_sources`), `--output-dir`, `--dry-run` |
| `game_rules.py` | `--regions`, `--extras`, `--headers` (files checked against the profiles and the header readers), `--emulators-dir`, `--json` |
| `generate_games_index.py` | `--output-dir` (default `install/games`), `--check`, `--quiet` |

## Installation tools

Cross-platform BIOS installer for end users:

```bash
# Python installer (auto-detects platform)
python install.py

# One-line automatic install (Linux/macOS)
curl -fsSL https://abdess.github.io/retrobios/i | sh

# One-line automatic install (Windows PowerShell)
irm https://abdess.github.io/retrobios/i.ps1 | iex
```

`install.py` auto-detects the user's platform by checking config files,
downloads the missing files from an immutable release revision, verifies their
SHA-256 and SHA-1, and replaces each destination atomically. Both
one-liners, shell and PowerShell, verify the downloaded Python installer against the SHA-256
embedded in their bootstrap before running it. Copies into standalone-emulator
directories are opt-in through `--standalone-copies`. Manifest entries with no
available payload are reported as safely omitted, and they are never replaced by a
same-named file.

`scripts/download.sh` remains available for downloading a prebuilt platform
ZIP when a manually reviewed pack release contains it. It is separate from the
per-file automatic installer above. A pack over 2 GB is published in several
parts: both downloaders group them under one platform name, download each
one and check it against the release's `SHA256SUMS.txt`. Parts that are each
a ZIP are extracted one after the other, and the `.zip.001` slices of releases up
to v2026.09.04 are joined first.
That list carries a detached signature, `SHA256SUMS.txt.sig`, verifiable
against `allowed_signers` at the repository root, and the
[release process](release-process.md#verifying-a-release) gives the commands.
Volumes are staged inside the destination directory rather than the system
temp directory, which is a RAM disk on Batocera, ROCKNIX and RetroDECK.
`RETROBIOS_API` points them at another releases endpoint, HTTPS only, plain
HTTP allowed to loopback for end-to-end tests.

Options, environment overrides, platform detection and the trust boundary are
documented on the [Installer](installer.md) page.

## Romset recipes

A profile's `contents:` block lists the member names and CRC32s one emulator
version expects inside an archive. TorrentZip makes archive bytes a function of
that list alone, so a recipe plus the ROM bytes reproduces the archive exactly.

```bash
python scripts/romset_recipes.py --identify   # which version each archive is
python scripts/romset_recipes.py --missing    # pinned archives we lack
python scripts/romset_recipes.py --missing --write   # write what can be rebuilt
```

Recipes come from two places. Profiles document a few hundred sets by hand. A
DAT documents every set of one emulator version at once, and both upstreams
publish theirs without a browser: MAME ships its `-listxml` as a release asset,
FBNeo keeps its DATs in the repository.

```bash
python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289
python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0250
python -m scripts.scraper.romset_dat_importer --source fbneo --fetch
python -m scripts.scraper.romset_dat_importer --source fbneo --fetch v1.0.0.02
```

FBNeo DATs are read at one commit: the revision named (tag, branch or commit,
the default branch when bare) is resolved first, and every DAT downloaded is
held against the blob sha the listing gives, so a cached branch URL cannot
serve older bytes. Their headers keep one version across commits, so DATs read
at a named revision are labelled `<DAT name> @ <revision>` and accumulate
beside the tip's. Only an import of the tip records the blobs the freshness
check compares with.

Snapshots land in `recipes/`, not `provenance/`: the latter holds dump catalogues
and a recipe is not one. Versions accumulate rather than replace each other,
because a platform pins the archive of whichever version its list was built
against. Every MAME release with a `-listxml` asset is imported, 0.177 to
0.289, not one in five. Kept sets:

- the archive names a profile or platform references;
- the archive names the collection holds;
- the sets holding a dump-catalog entry the collection lacks (crc32 and size,
  and sha1 when both sides carry one), so `provenance_report.py --missing` can
  name the set that ships it: MAME's `fm7740sx` carries the FM77AV40SX
  `DICROM.rom`, `EXTSUB.rom` and `KANJI2.rom` that No-Intro lists;
- every set whose member list equals an archive the collection keeps under
  another name. `aga.zip` holds exactly MAME's `isa_aga`: the entry carries
  the collection's name and keeps the upstream one in `set`. When several sets
  share one member list (thirty keyboard sets carry the same ROM), the set
  named like the archive is kept, then the first by name.

A `romof` parent's members are merged into the child, and members with no
CRC32 are dropped: those are undumped and a real romset does not carry them.

The store is compacted: 113 MAME versions produce 173,988 entries but only 2,939
distinct recipes, since most sets do not change between releases. Each is kept
once, `dats` listing every version that agrees and `dat` naming the earliest, so
an identification reads as "unchanged since that version".

`--identify` answers what an archive on disk actually is: the version whose
recipe reproduces it byte for byte. Step 1c of the pipeline prints how many
archives that is on the current collection. `--missing` takes the container MD5s the platforms pin, keeps those the
collection does not have, and tries every recipe whose ROMs are present.

Reconstruction only works when the pinned archive is itself TorrentZip. An
archive whose bytes carry metadata unrelated to its contents cannot be derived
from ROMs by anyone, so those are reported as unreproducible rather than guessed
at. Writing is explicit: the pipeline only ever reports.

### Archive recipes

The collection must regenerate every archive it serves from the ROMs it holds
plus a committed recipe, without a copy of that archive from elsewhere.
`recipes/archives.json` holds one record per archive in `database.json`,
`.variants/` copies included, keyed by path:

- the members in archive order, each with its size, crc32 and sha1;
- the container's sha1, md5 and size;
- `rebuild`: `exact` when `build_torrentzip()` over the members gives the
  container byte for byte (proven at capture by rebuilding it), `canonical`
  when the archive was written by another tool, so the build gives the same
  members in other container bytes. Directory entries are listed under
  `directories` and not rebuilt;
- `sources`: the profile `contents:` blocks and the MAME and FBNeo DAT
  recipes whose member list equals the archive's, matched by members rather
  than by name, then `collection`, the archive itself. A DAT is provenance,
  never the only source;
- `bytes_pinned` and `pins` when a platform or a profile pins the container
  hash. A `zipped_file` md5 and a Recalbox composite md5 name no container
  bytes and are not pins.

```bash
python scripts/romset_recipes.py --capture                 # pipeline step 1c
python scripts/romset_recipes.py --build neogeo.zip --output-dir tmp/built
python scripts/romset_recipes.py --build "bios/SNK/Neo Geo CD/neocdz.zip" --output-dir tmp/built
python scripts/romset_recipes.py --build-all --output-dir tmp/built --discard
```

`--capture` reads only the archives whose sha1 changed since the last run,
and recomputes sources and pins every time. `--build` takes a path or a file
name (every archive of that name is built, each at its path below `bios/`
inside the output directory). Each member is read by its sha1: a loose file
first, then a member of another archive, then the archive's own copy. The
result is written beside its destination, read back from disk and checked
against the recipe: the recorded sha1 for an exact recipe, the members for a
canonical one. A mismatch is built once more, then refused, and nothing is
moved into place. `--build-all` prints one line per archive (exact, canonical,
or impossible with the member nothing holds) and exits 1 when an archive
failed or was impossible. `--discard` deletes each build once verified, which
proves the whole collection without the disk space.

The summary also counts the archives that read a member from their own copy:
that member is held nowhere else, and would have to become a loose file before
the archive bytes could be dropped from `bios/`.

**Deflate implementation.** TorrentZip bytes are the output of zlib's level-9
deflate (`compressobj(9, DEFLATED, -15)`). Stock zlib 1.2.13 to 1.3.2
reproduced all 1,561 TorrentZip archives tested in November 2026, on Linux and
on Windows. zlib-ng does not: python.org CPython 3.14 and 3.15 on Windows
(zlib-ng 2.2.4) reproduced 479, and zlib-ng 2.3.3 545, the two versions
disagreeing with each other. `--capture` refuses to run under zlib-ng, and
`--build` says so and checks every recipe by its members, never claiming an
exact rebuild. `torrentzip.zlib_ng_version()` is the test.

## Large files

Files too large for git are stored as assets on the `large-files` GitHub
release. `.gitignore` is the list of them: a `bios/` path listed there is a
release asset, whatever its size, and a committed file is served from the
repository even past 50 MB.
`generate_db.py` downloads them from the release when rebuilding the database,
using `fetch_large_file()` from `largefiles.py`. `generate_pack.py` calls the
same function when the file is absent locally or holds another revision than
the entry declares, and keeps the asset only when it matches a declared hash.
The rules for asset names, uploads and checks are on the
[release process](release-process.md#large-files-management) page.

## Scrapers

Located in `scripts/scraper/`. Each platform scraper inherits `BaseScraper` and
implements its two abstract methods, `fetch_requirements()` and
`validate_format()`. The MAME and FBNeo hash scrapers read a source tree and
stand alone.

| Scraper | Source | Format |
|---------|--------|--------|
| `libretro_scraper` | System.dat + core-info .info files | clrmamepro DAT |
| `batocera_scraper` | batocera-systems script, es_systems.yml (cores) | Python dict, YAML |
| `recalbox_scraper` | es_bios.xml, recalbox-romfs2 system.ini files (cores) | XML, INI |
| `retrobat_scraper` | batocera-systems.json | JSON |
| `emudeck_scraper` | checkBIOS.sh | Bash + CSV |
| `retrodeck_scraper` | component manifests | JSON per component |
| `romm_scraper` | known_bios_files.json | JSON |
| `rocknix_scraper` | rocknix-systems script | Python dict |
| `knulli_scraper` | knulli-systems script, es_systems.yml and configgen-defaults.yml (cores) | Python dict, YAML |
| `amberelec_scraper` | batocera-systems script at the newest prerelease's commit, es_systems.cfg (cores) | Python dict, XML |
| `emuelec_scraper` | batocera-systems script, es_systems.json (cores) | Python dict, JSON |
| `retropie_scraper` | RetroPie-Setup scriptmodules (`rp_module_id`, `rp_module_help`) and `retropie_packages.sh` (version) | Bash |
| `misterfpga_scraper` | BiosDB_MiSTer bios_db.json.zip | JSON in ZIP |
| `minui_scraper`, `nextui_scraper`, `myminui_scraper` | each pak's `launch.sh` (`EMU_EXE`, the tag from the pak folder), each device's `cores/makefile` (the repository a library is built from) and the minarch statement that sets `core.bios_dir` | Shell, Make, C |
| `coreinfo_scraper` | .info files from libretro-core-info | INI-like |
| `bizhawk_scraper` | FirmwareDatabase.cs | C# source |
| `mame_hash_scraper` | mamedev/mame source tree. `--release mameNNNN` writes the profile of one release a platform builds. `--devices --listxml FILE` adds the device ROM sets of the release's `-listxml` | C source (sparse clone), listxml |
| `fbneo_hash_scraper` | FBNeo source tree | C source (sparse clone) |

A machine that instantiates a device loads the device's ROMs from
`<device shortname>.zip`, and a missing ROM that is neither optional nor
undumped stops that machine. The BIOS root scan never sees these sets, so
`--devices` reads them from the `-listxml` of the release `mame.yml` is pinned
on and refuses another release. Each set is cited at the `ROM_START` to
`ROM_END` block holding its ROMs, in the file the listxml names, read at the
release tag through the upstream cache. When several blocks qualify, the one
matching every ROM by name and CRC wins, then the one named after the set, then
the one the device class returns from `device_rom_region`. A set still
undecided is written without a `source_ref` and listed in the output. New sets
go under the `Device ROM sets (generated from MAME -listxml)` comment at the end
of `files:` with `required: false`. A set the profile already lists keeps every
field a reader wrote and only gets its contents refreshed.

Each generated set is filed under the systems of the machines that can load
it. A machine takes the `system:` of the first set on its `romof` chain that a
written entry lists (a clone reaches its parent, a parent its BIOS root set),
and passes it to every device in its `device_ref` list and every card its
slots offer (`slotoption`), followed through those devices' own links and
their parent ROM devices. A set loaded by machines of one system gets
`system:`, of several `systems:`, of none neither field, and then serves every
system of the profile. The driver file is never used: `neogeo.cpp` declares
the MVS and the AES. The output counts the sets in each case.

A machine set no written entry lists is also seeded when a registered platform
declares `<set>.zip` under one of the profile's systems (Batocera files
`bbcb.zip` under `acorn-bbc-micro`). The set must be a machine of the release,
not a device, and a set two platforms state under two different systems seeds
nothing and is listed.

The same walk files the support trees. Each `hash/<list>.xml` the release
ships and a placed machine or slot card declares (`softwarelist`) is written
under the `Software lists (generated from MAME -listxml)` comment, ahead of the
device section, with the systems of those machines. A list no placed machine
declares stays a member of the `hash/` entry. Each floppy sound sample gets the
systems whose machines can instantiate a drive selecting its list: the form
factor comes from the drive's `setup_characteristics` in the source, 3" drives
take the 3.5" list and every other drive the 5.25" one, as
`floppy_sound_samples::select` does. `plugins/` stays unfiled: every machine
starts the Lua engine.

A plain run (pipeline step 2a) that moves `mame.yml` to a new release
downloads that release's `-listxml` into `.cache/dats/` and runs the device
merge itself, so the BIOS root sets and the device sets name one release.

```bash
python -m scripts.scraper.mame_hash_scraper --devices --listxml .cache/dats/mame0289lx.zip --dry-run
python -m scripts.scraper.mame_hash_scraper --devices --listxml .cache/dats/mame0289lx.zip
```

Internal modules: `base_scraper.py` (abstract base with `_fetch_raw()` caching
and shared CLI), `dat_parser.py` (clrmamepro DAT format parser),
`logiqx_parser.py` (Logiqx XML DAT parser, used by the dump catalogs),
`mame_parser.py` (MAME C source BIOS root set parser),
`fbneo_parser.py` (FBNeo C source BIOS set parser),
`_hash_merge.py` (text-based YAML patching that preserves formatting).

Adding a scraper: inherit `BaseScraper`, implement `fetch_requirements()` and
`validate_format()` (a class missing either cannot be instantiated), call
`scraper_cli(YourScraper)` in `__main__`. The full recipe is in
[adding-a-scraper.md](adding-a-scraper.md).

## Dump-catalog provenance

Snapshots of the preservation catalogs are committed to `provenance/` and
refreshed manually. `generate_db.py` joins them into `database.json`,
and `provenance_report.py` reports the gaps.

```bash
python -m scripts.scraper.redump_dat_scraper --dry-run
python -m scripts.scraper.redump_dat_scraper --output provenance/redump.json
python -m scripts.scraper.dat_pack_importer --source no-intro --pack no-intro.zip
python -m scripts.scraper.dat_pack_importer --source tosec --pack TOSEC-v2025.zip
python scripts/provenance_report.py            # coverage summary (pipeline step 1b)
python scripts/provenance_report.py --missing  # list acquisition targets
python scripts/provenance_report.py --missing --derive  # mark targets a held dump already contains
python scripts/provenance_report.py --json     # full report
```

A catalog lists chips as they come off the board, the collection often holds
the image an emulator reads. `--derive` reads every file of the collection and
marks a missing entry DERIVABLE when a held file produces its sha1 by halving,
quartering, splitting into even and odd bytes or 16-bit words (byte-swapped
or not), swapping bytes, mirroring, or joining two files of one directory.
The Amiga Kickstart chip pairs and TOSEC's split C64 and VES ROMs are found
this way. Pipeline step 1b records what it finds in `derivable.json`.

A missing entry that is a file an emulator profile reads and the collection
lacks is listed first, with `needed by <emulator> as <name>` and whether the
profile requires it. The match is by hash when the profile declares one, by
name and size when it declares a size or size range and no hash (XM7's
`DICROM.ROM`, which No-Intro lists for the FM77AV40SX). `--emulators-dir`
names the profiles read.

| Catalog | Acquisition | Notes |
|---------|------------|-------|
| Redump | direct fetch from redump.info, one `/bios/<CODE>` route per system | 4 BIOS DATs. redump.org serves BIOS DATs dated 2010 to 2022, redump.info the current ones |
| No-Intro | local pack, imported with `dat_pack_importer` | Dat-o-Matic serves its DATs through a browser session, and the `dantob/auto-datfile-generator` mirror rebuilds daily. `check_freshness` reads a pack older than a week as a stopped mirror |
| TOSEC | local pack, imported with `dat_pack_importer` | annual pack from tosecdev.org, 138 Firmware DATs |

The join is by SHA1, then by MD5 + size. A match sets the `provenance` field
on the database entry and renders a verified dump badge on the system pages.
It never overrides the emulator source code: see
[architecture](architecture.md#dump-catalog-provenance).

## Games on the card

The installer's games-on-card mode reads the rom folders of a card, identifies
each game and installs only the BIOS those games need. Its data is generated
from sources and published under `install/games/` by pipeline step 4e.

```bash
python -m scripts.scraper.romfolders --list                 # setups and the format each is read in
python -m scripts.scraper.romfolders --all                  # platforms/romfolders/<setup>.yml at the pins of _sources/
python -m scripts.scraper.romfolders --setup batocera --offline
python -m scripts.scraper.game_dat_importer --fetch --floor # games/catalogs/: No-Intro and Redump game DATs
python -m scripts.scraper.game_dat_importer --floor         # same from .cache/game-dats/ only
python -m scripts.scraper.arcade_parent_importer --all      # games/arcade/: game set to BIOS parent, per core
python scripts/game_rules.py                                # games/regions.yml and games/extras.yml against the profiles
python scripts/generate_games_index.py                      # install/games/ (pipeline step 4e)
python scripts/generate_games_index.py --check              # exit 1 when a published file would change
```

| Source | Written by | Holds |
|--------|-----------|-------|
| `platforms/romfolders/_sources/<setup>.yml` | hand, each fact with its `source_ref` | pins, roms root, case rule, folders never scanned |
| `platforms/romfolders/<setup>.yml` | `scraper/romfolders` | folders, extensions and default core as the OS writes them |
| `games/catalogs/<source>/<system>.json` | `scraper/game_dat_importer.py` | crc32, size, sha1, region and title per game, disc serials |
| `games/headers.yml` | hand, cited | header fields each core reads and the region each value means |
| `games/regions.yml`, `games/extras.yml` | hand, cited | region routes, the cases that keep every region, per-game files |
| `games/arcade/<profile>.json` | `scraper/arcade_parent_importer.py` | BIOS parent and device sets of each game set, from the DAT the pin names or, for mame2000, mame2003 and mame2003-plus, from the driver code |

Folder names resolve to systems through `SYSTEM_ALIASES` and `_norm_system_id`
in `common.py`, the one alias table, and core names to profiles through the
profiles' `cores:`. The fallback set of a folder, what an unrecognised game
keeps, is computed from `install/<platform>.json` with the installer's own
core narrowing. Every published file is listed in `install/games/index.json`
with its size, its gzip size and its sha256.

`validate_schemas.py` refuses a `games/arcade/<profile>.json` whose source
commit or `core_version` is not the one its profile pins: after a profile's pin
moves, rerun `arcade_parent_importer --profile NAME`.

## Target scrapers

Located in `scripts/scraper/targets/`. Each inherits `BaseTargetScraper` and implements `fetch_targets()`.

| Scraper | Source | One target per |
|---------|--------|----------------|
| `retroarch_targets_scraper` | libretro buildbot nightly listings | buildbot architecture |
| `batocera_targets_scraper` | Config.in + es_systems.yml + Buildroot Kconfig | board |
| `knulli_targets_scraper` | the same, read from KNULLI's tree and Buildroot fork | board |
| `recalbox_targets_scraper` | board defconfigs + system.ini cores | board |
| `rocknix_targets_scraper` | emulators package.mk + device options | device |
| `amberelec_targets_scraper` | Makefile devices + metapackage extra cores + es_systems.cfg | device |
| `emuelec_targets_scraper` | release assets + metapackage package.mk + core install steps + es_systems.json | device |
| `lakka_targets_scraper` | libretro_cores package.mk + project and device options | device image |
| `emudeck_targets_scraper` | EmuScripts (SteamOS and Windows) | operating system |
| `retropie_targets_scraper` | scriptmodules + rp_module_flags | platform flag |

`verify.py --platform <name> --list-targets` prints the current list with
each target's core count.

```bash
python -m scripts.scraper.targets.retroarch_targets_scraper --dry-run
python -m scripts.scraper.targets.batocera_targets_scraper --dry-run
```

## Exporters

Located in `scripts/exporter/`. Each inherits `BaseExporter`, defined in
`base_exporter.py`, and implements `render()` and `validate()`.

| Exporter | Writes |
|----------|--------|
| `systemdat_exporter` | libretro `System.dat`, a clrmamepro DAT |
| `lakka_exporter` | the same `System.dat`, which Lakka reads unchanged |
| `batocera_exporter` | the systems block of the `batocera-systems` script, patched entry by entry |
| `rocknix_exporter` | the systems mapping of the `rocknix-systems` script, patched the same way |
| `knulli_exporter` | the systems mapping of the `knulli-systems` script, patched the same way |
| `amberelec_exporter` | AmberELEC's `batocera-systems`, paths from `/storage/roms`, additions without a runner gate |
| `emuelec_exporter` | EmuELEC's `batocera-systems`, as AmberELEC's |
| `retrobat_exporter` | `batocera-systems.json` |
| `recalbox_exporter` | `es_bios.xml`, valid against `es_bios.xsd` |
| `emudeck_exporter` | the MD5 lists of the `checkBIOS.sh` functions, patched in place |
| `retrodeck_exporter` | the BIOS list inside each component's `component_manifest.json` |
| `romm_exporter` | `known_bios_files.json`, every entry with a size and a hash |
| `bizhawk_exporter` | `FirmwareDatabase.cs`, BizHawk's own C# |
| `misterfpga_exporter` | hash and size in MiSTer's BiosDB (`bios_db.json`) |
| `retropie_exporter` | the `rp_module_help` prose of each scriptmodule, by adding a file name the package's emulator reads |

The five script formats (Batocera, ROCKNIX, KNULLI, AmberELEC, EmuELEC) write
an md5 as one string or, where the checker reads one, as a list. The export
reads the checker of the pinned file, never a version number: when `checkBios`
hands an item's md5 to a function that tests it with `isinstance(..., list)`
(`md5Matches` since batocera.linux `6b08b873`), an entry whose emulator code
accepts several dumps is written with all of them. Without that code, an entry
keeps the one md5 it can hold, and an addition that would need several is left
out and counted. An item with `altmd5` keeps a string, since the checker wraps
it in a list of its own. The report gives a list as a list, and the summary
counts the lists written.
