---
level: contribute
order: 10
---

# Profiling guide

A profile is a YAML file that says which files one emulator opens, under which
names, what it checks in them and whether it runs without them. Each line
points at the code that proves it, at a fixed revision of that code (the pin,
`source_commit`), so anyone can check it. Packs, checks and every emulator page
on this site are built from profiles.

Example, one entry of `emulators/duckstation.yml`:

```yaml
- name: "scph5501.bin"
  region: [north-america, latin-america]
  group: ps-bios
  md5: "490f666e1afb15b7362b406ed1cea246"
  priority: 5
  source_ref: "src/core/bios.cpp:47"
```

This guide shows how to read an emulator's code to write one.

## Approach

A profile documents what an emulator loads at runtime.
The source code is the reference because it reflects actual behavior.
Documentation, .info files, and wikis are useful starting points
but are verified against the code.

### Source hierarchy

The desmume2015 `.info` file declares `firmware_count=3`. The source at the
pinned revision opens no firmware file. Documentation and metadata are where a
profile starts, and the code is where it is checked.

When sources conflict, priority follows the chain of actual execution:

1. **Original emulator source** (ground truth, what the code does)
2. **Libretro port** (may adapt paths, add compatibility shims, or drop features)
3. **.info metadata** (declarative, may be outdated or copied from another core)

For standalone emulators like BizHawk or amiberry, there is only one
level. The emulator's own codebase is the single source of truth. No
.info, no wrapper, no divergence to track.

A note on libretro port differences: the most common change is path
resolution. The upstream emulator loads files from the current working
directory, and the libretro wrapper redirects to `retro_system_directory`.
This is normal adaptation, not a divergence worth documenting. Similarly,
filename changes like `naomi2_eeprom.bin` becoming `n2_eeprom.bin` are
often deliberate. RetroArch uses a single shared system directory for
all cores, so the port renames files to prevent collisions between cores
that emulate different systems but happen to use the same generic
filenames. The upstream name goes in `aliases:`.

## Steps

### 1. Find the source code

Check these locations in order:

1. Upstream original (the emulator's own repository)
2. Libretro fork (may have adapted paths or added files)
3. If not on GitHub: GitLab, Codeberg, SourceForge, archive.org

Always clone both upstream and libretro port to compare.

For libretro cores, cloning both repositories and diffing them reveals
what the port changed. Path changes (fopen of a relative path becoming
a system_dir lookup) are expected. What matters are file additions the
port introduces, files the port dropped, or hash values that differ
between the two codebases.

Source hosted outside GitHub is searched on GitLab, Codeberg, SourceForge,
Bitbucket, archive.org snapshots and community mirror tarballs. Copyright
headers and license strings in the libretro fork often name the original
author's site. A source not found yet is a search not finished, and the
profile waits for it.

Each profile gets its own reading of the code, even when the same repository
was read for a related profile (`fbneo`, then `fbneo_neogeo`). The earlier
reading says what that profile loads, not what the new one loads.

A declared upstream that answers 404 is not proof the project is gone. The
account can differ from the Android package id (`aenu.aps3e` lives at
`aenu1/aps3e`), a repository can be renamed, and a live repository can belong
to the parent project rather than the one that publishes the package. A code
search on the package id usually names the real repository.

A closed-source emulator is profiled from what it ships: decompiled IL for a
.NET or Unity build, the string table and import directory of a native binary,
the debug information a library was not stripped of. A source drop published
after the fact can be older than every shipped build, so its option and file
name strings are compared with a genuine binary before it is trusted.

An Android package is fingerprinted before a byte of it is read. Mirrors carry
rebuilt and re-signed copies of paid emulators, and a profile read from one
describes someone else's modification. Read the signing certificate, compare
it with a build known to be genuine, and prefer an older genuine build to a
newer repack. The profile names the rejected copies.

### 2. Trace file loading

Read the code flow, tracing from the entry point.
Each emulator has its own way of loading files.

Look for:

- `fopen`, `open`, `read_file`, `load_rom`, `load_bios` calls
- `retro_system_directory` / `system_dir` in libretro cores
- File existence checks (`path_is_valid`, `file_exists`)
- Hash validation (MD5, CRC32, SHA1 comparisons in code)
- Size validation (`fseek`/`ftell`, `stat`, fixed buffer sizes)

Grepping for "bios" or "firmware" across the source tree can be a
useful first pass, but it may miss emulators that use different terms
(bootrom, system ROM, IPL, program.rom) and can surface false matches
from test fixtures or comments.

A more reliable approach is starting from the entry point
(`retro_load_game` for libretro, `main()` for standalone) and tracing
the actual file-open calls forward. Each emulator has its own loading
flow. Dolphin loads region-specific IPL files through a boot sequence
object. BlastEm reads a list of ROM paths from a configuration
structure. same_cdi opens CD-i BIOS files through a machine
initialization routine. The loading flow varies widely between emulators.

Check which build reaches the code. When one tree builds a desktop and an
Android app, the Android project can remove sources from its compile and wire
other entry points, so a file the shared code opens may never be read on
Android. A platform header can also leave a symbol undefined whatever the
comment above it says. Read the project file and the macro block before
calling a load path live, and scope the file in its `note:` when only one
build reads it.

Everything the code opens from outside goes in the profile, not only BIOS
images: fonts, keyboard maps, NV memory, samples, DSP firmware, game databases,
data directories, native libraries loaded by name. For a library shipped
inside a package, the test is whether the emulator's own code names it.
ArcadeFlashWeb ships a whole Qt deployment, and its profile lists the few files
its source names, such as the Flash runtime passed on the command line.
Operating system runtimes (`VCRUNTIME140.dll`) are prerequisites written in
`notes:`, never files.

### 3. Determine required vs optional

This is decided by code behavior, not by judgment:

- **required**: the core does not start or function without the file
- **optional**: the core works with degraded functionality without it
- **hle_fallback: true**: the core has a high-level emulation path when the file is missing

The decision is based on the code's behavior. If the core crashes or
refuses to boot without the file, it is required. If it continues with
degraded functionality (missing boot animation, different fonts, reduced
audio in menus), it is optional. This keeps the classification objective
and consistent across all profiles.

When a core has HLE (high-level emulation), code of its own that stands
in for the file, mark the entry `hle_fallback: true`. The flag records the
stand-in. It does not decide `required`, which still comes from what the
code does without the file: most entries that carry the flag are optional,
and a few are required, among them QUASI88's `n88.rom`
(`emulators/quasi88.yml`). The file still ships in packs, and
verification reports its absence at INFO whatever `required` says.

MAME is read the same way. A missing ROM is fatal only when it is neither
`ROM_OPTIONAL` nor `NO_DUMP` (`src/emu/romload.cpp`), so a set made only of
`NO_DUMP` entries is not required, and MAME hashes the members of an archive,
never the archive: those hashes go in `contents:`.

### 3b. Decide whether the file carries a region

Set `region:` only when the **code branches on a territory to select the
file**. It documents the region the emulator picks the file *for*, never the
region the dump came from. The two usually agree, and when they do not, the
code wins: `psxonpsp660.bin` is a Japanese PSP dump that DuckStation uses as a
region-free override for all three regions, so it is `[world]`.

What qualifies:

```c
switch (region_code) {                 // Genesis Plus GX, core/loadrom.c
  case REGION_USA:    load(CD_BIOS_US); break;
  case REGION_EUROPE: load(CD_BIOS_EU); break;
  default:            load(CD_BIOS_JP); break;
}
```

What does not, and why each trap is easy to fall into:

- **A user option on a non-territorial axis.** Geargrafx picks
  `syscard1/2/3.pce` by `cdrom_bios`, a card *generation*, and its `game_db.h`
  accepts the Japanese and the American CRC32 under the same filename.
  Tagging it `[japan]` would delete the PC Engine BIOS from a `--region us`
  pack.
- **A model enum.** SameBoy maps `SGB2 -> GB_BOOT_ROM_SGB2 -> sgb2_boot.bin`.
  That the SGB2 shipped only in Japan is hardware history, not a code branch.
- **A configured path.** PCSX2 accepts any 4-8 MB file with a valid romdir.
  Mednafen reads whatever `md.cdbios` points at.
- **A television standard.** Gopher2600 branches on
  `env.Loader.ReqSpec == "PAL"`, a video specification, and the Atari 2600 has
  no region lock. There is no signal field: drop `region:` rather than map it.
  The exception is hardware that fuses both axes in one register, such as the
  Saturn SMPC area codes behind `asia-ntsc` and `asia-pal`. Mednafen names
  them for Taiwan and China, so a `--region taiwan` request reaches an
  `asia-ntsc` file and a `--region china` request an `asia-pal` one, and the
  other way round (`AREA_TERRITORIES` in `scripts/region.py`).
- **A single-region system.** When every file of a system shares one region,
  the pack filter keeps them all anyway, so annotating adds nothing.
- **A language without a territory.** Arabic MSX variants, CJK fonts. The
  vocabulary is territorial by design and inventing a slug would break it.

One naming trap: in `ORIC.PAL-PROM-TBP24S10-1ab9b572.bin`, PAL is a
Programmable Array Logic, not the television standard.

Two traps run the other way, where a region is real but wider than it looks:

- **The detector's default branch.** Genesis Plus GX and PicoDrive set the US
  region for every Mega CD disc whose security byte is neither Europe's nor
  Japan's, so the US BIOS serves Latin America as well. Read where the region
  value comes from, not only the switch that uses it.
- **A territory the code folds into another.** Dolphin maps NTSC-K discs to
  NTSC-J (`ToGameCubeRegion`), so the Japanese IPL is also Korea's.

`python scripts/region_audit.py` then lists every `region:` that disagrees with
the regions No-Intro gives the same dump. Each disagreement is a line to read
in the source, not a correction to apply: the field records the code's
selection, and a Hong Kong PS2 is an NTSC-J console.

### 3c. Record the search order

When several files can fill one slot (one role for one system and region, such
as the North American PlayStation BIOS), `priority:` records the order the code
looks for them, lowest first, read from the source alone. Two cores can rank
the same file differently: pcsx1 walks `scph1001`, `scph5501`, `scph7001` in
that order while DuckStation prefers `scph5501` (5) to `scph1001` (10). The
two uses of the field then answer differently. Choosing one file per slot
(`--one-per-slot`) keeps every candidate, since dropping one would drop
another core's first choice. Ordering a list keeps the best rank any core
gives and notes the disagreement beside it, because a list drops nothing and
the file the emulator prefers is the one a reader copies first.

### 4. Document divergences

When the libretro port differs from the upstream:

- `mode: libretro` - file only used by the libretro core
- `mode: standalone` - file only used in standalone mode
- `mode: both` - used by both (default, can be omitted)

Path differences (current dir vs system_dir) are normal adaptation,
not a divergence. Name changes (e.g. `naomi2_` to `n2_`) may be intentional
to avoid conflicts in the shared system directory.

RetroArch's system directory is shared by every installed core. When
the libretro port renames a file, it is usually solving a real problem:
two cores that both expect `bios.rom` would overwrite each other. The
upstream name goes in `aliases:` and `mode: libretro` on the port-specific
name, so both names are indexed.

True divergences worth documenting are: files the port adds that the
upstream never loads, files the upstream loads that the port dropped
(a gap in the port), and hash differences in embedded ROM data between
the two codebases. These get noted in the profile because they affect
what the user actually needs to provide.

### 5. Write the YAML profile

```yaml
emulator: Dolphin
type: standalone + libretro
core_classification: community_fork
source: "https://github.com/libretro/dolphin"
upstream: "https://github.com/dolphin-emu/dolphin"
profiled_date: "2026-03-23"
source_commit: "3aac3f052f733f8df2f1616843a4d2e14002ed11"
upstream_commit: "0d93fc035539f25790deca638d06ee3b3b45ee64"
core_version: "2609-437-g3aac3f0"
version_basis:
  kind: tag
  tag: "2609"
  distance: 437
systems: [nintendo-gamecube, nintendo-wii, sega-triforce]

files:
  - name: "IPL.bin"
    path: "dolphin-emu/Sys/GC/USA/IPL.bin"
    standalone_path: "GC/USA/IPL.bin"
    system: nintendo-gamecube
    region: [north-america, latin-america]
    size: 2097152
    required: false
    hle_fallback: true
    source_ref: "upstream Source/Core/Common/CommonPaths.h:139, source Source/Core/Core/HW/EXI/EXI_DeviceIPL.cpp:108"
```

This excerpt of `emulators/dolphin.yml` leaves out the notes and the other
entries.

Record `source_commit` when profiling: upstream code moves, and a
`source_ref` line number only stays checkable against the commit it was
read at. Profiles written before this field existed carry `profiled_date`
and `core_version` instead. They gain `source_commit` as they are
re-verified.

### Citations and pins

Every choice in a profile carries a `source_ref` to the original emulator's
code, and to the wrapper's too when the wrapper changes the path. Line numbers
only hold at one revision, so a few rules keep them checkable.

- **The pin and the references move together.** A profile rewritten from a
  reading of the current head records that head's sha in `source_commit` in
  the same edit. References updated without the pin describe one revision
  while the pin names another, and the next comparison reads the old code at
  line numbers that only make sense in the new.
- **Paths start at the repository root.** `src/xenia/ui/imgui_drawer.cc:39`
  anchors, `ui/imgui_drawer.cc:39` reports GONE although the file exists, and
  the failure looks like deleted code. A bare file name anchors only while one
  file in the tree carries it.
- **Citations in prose count.** Every `file:line` in notes and free text is
  checked like a `source_ref`, and a pin does not advance while one of them
  still describes the old revision.
- **Line numbers are read, not copied.** Search tools disagree on whether lines
  count from 0 or 1. Read the cited span at the pinned revision before writing
  it.
- **A frozen line is pinned to its tag.** A profile documenting a release that
  lives as a tag in a still active repository (`pcsx2-legacy` at PCSX2 v1.6.0)
  is checked against its own revision and never rebased onto the head. An
  `upstream` whose pin is the tag `core_version` names (GroovyMAME's base,
  `mame0289`) is read at that tag the same way, while the port itself is still
  compared with its head, and a bump leaves `upstream_commit` on the tag.
- **A fork's base comes from the forge.** `upstream_commit` of a fork is the
  merge base the compare API returns. A vendored `version.h` can name the
  project the fork once came from. When a package ships prebuilt binaries
  built from different commits of its own repository, the pin is the revision
  whose sources describe the shipped bytes, found by hashing each binary
  against the history.
- **Upstream moved, the profile is read again.** When the code a profile cites
  is rewritten or moved, the profile is re-profiled at the new revision. A
  profile held on a revision nobody ships documents a program that no longer
  exists.

### Writing style

Notes in a profile describe what the core does, kept focused on:
what files get loaded, how, and from where. Comparisons with other
cores, disclaimers, and feature coverage beyond file requirements
belong in external documentation. The profile is a technical spec.

Profiles are standalone documentation. Someone should be able to take
a single YAML file and integrate it into their own project without
knowing anything about this repository's database, directory layout,
or naming conventions. The YAML documents what the emulator expects.
The tooling resolves the YAML against the local file collection
separately.

A few field conventions that protect the toolchain:

- `type:` is operational. `resolve_platform_cores()` uses it to filter
  which profiles apply to a platform. Valid values are `libretro`,
  `standalone + libretro`, `standalone`, `alias`, `launcher`, `game`,
  `utility`. Putting a classification concept here (like
  "bizhawk-native") breaks the filtering. A BizHawk core is
  `type: standalone`. A libretro core that emulates no machine stays
  `type: libretro` and says what it is for in `role:` (`game`, `utility`
  or `test`): typed by its role, 2048 fell out of every all_libretro
  platform and RetroArch's manifest no longer named it.

- `core_classification:` is descriptive. It documents the relationship
  between the core and the original emulator (pure_libretro,
  official_port, community_fork, frozen_snapshot, etc.). It has no
  effect on tooling behavior.

- Alternative filenames go in `aliases:` on the file entry (rather than
  as separate entries in platform YAMLs or `_shared.yml`). When the same
  physical ROM is known by three names across different platforms, one
  name is `name:` and the rest are `aliases:`.

- Hashes come from source code. If the source has a hardcoded hex
  string (like emuscv's `635a978...` in memory.cpp), that goes in. If
  the source embeds ROM data as byte arrays (like ep128emu's roms.hpp),
  the bytes can be extracted and hashed. If the source performs no hash
  check at all, the hash is omitted from the profile. An MD5 the .info or
  the docs alone give is not written: pokketstation's `.info` names a
  revision no copy in circulation has.
  A data file the build generates is rebuilt from the tree and compared
  byte for byte with the official release before its hash is recorded
  (PrBoom+ builds `prboom-plus.wad` with its own tool). A firmware URL that
  embeds an MD5, as Sony's update URLs do, names the revision the code
  expects, and records `md5:` without `validation: [md5]`. A hash that comes
  from neither the code nor the shipped file is not written, even labelled
  informative.

- A name a platform's launcher reads (a Batocera generator, a RetroBat
  launcher) is not an alias: it describes the platform, and the platform's
  scraper records it under `launchers:`. `aliases:` holds the names the
  emulator itself opens.

- For a file the code finds by content (`found_by: content`), `name:` is a
  label. It reuses the name other profiles give that exact dump, so it never
  collides with another dump's established name: ares labels borrowed from
  other cores once put its revision on a path where RetroBat pins a different
  dump.

- `bundled: true` keeps a file out of packs because the user already has it.
  `not_bundled_on`, `installed_on` and `unread_on` refine that per platform
  from that platform's own package or launcher, each with the reference that
  shows it.

- `unsourceable:` stops a different file with the same name from being served
  in the entry's place. It never means the file cannot be found, and the entry
  stays an acquisition target. XM7's kanji ROMs carry it because the
  collection's `KANJI.ROM` files are other machines' fonts.

- `path:` is the full destination, file name included. A directory-only value
  collapses several entries into one count. On a profile that is
  `type: standalone`, `mode: standalone` sits at the top only: repeated on each
  file it hides them from the cross-reference.

- An entry of a multi-system profile carries `system:`, read from the code.
  The toolchain never guesses it, and an entry without one is counted as
  unattributed.

- Every name in `cores:`, and every numeric file name, is a quoted string:
  `name: 01` reads back as `1`. `cores:` lists every name the buildbot and the
  platforms use for the core, since a name no profile claims is a core that
  target filtering skips.

- Metadata goes in fields, never in parentheses inside a string.

### 6. Validate

```bash
python scripts/cross_reference.py --emulator dolphin --json
python scripts/verify.py --emulator dolphin
python scripts/verify.py --emulator dolphin --verbose   # per-core checks + source refs
python scripts/profile_sync.py --emulator dolphin       # do the source_ref lines still hold
```

The profile also has to satisfy `schemas/emulator.schema.json` and the semantic
invariants checked beside it, which CI runs on every PR touching `emulators/`.
The same command, locally:

```bash
python scripts/validate_schemas.py --source-only
```

A schema check alone accepts profiles this rejects: a check declared with no
value to compare (`validation: [crc32]` and no `crc32`), a `data_directories`
ref the registry does not name, a `path:` written in this repository's layout
instead of the emulator's, a citation no declared revision can reach.

Three more checks catch what the schema cannot see:

- `python scripts/profile_sync.py --emulator NAME` reports 0 to re-read. A
  batch of GONE references on a new profile means the path prefix, not
  upstream drift.
- In `python scripts/verify.py --emulator NAME --json`, the status counts add
  up to the number of entries. An entry the collection was never meant to
  hold that reports OK is a homonym being served, and needs `unsourceable:`.
- A profile that becomes `standalone + libretro` joins every RetroArch pack.
  Generate the RetroArch manifest with and without it into a scratch
  `--output-dir` and compare the destinations: a standalone layout written
  into `path:` shows up as files at destinations no core reads.

### Lessons learned

These are patterns that have come up while building profiles. Sharing
them here in case they save time.

**.info metadata can lag behind the code.** The desmume2015 .info
declares `firmware_count=3`, but the core source at the pinned version
never opens any firmware file. The .info is useful as a starting point
but benefits from a cross-check against the actual code.

**Fresh analysis per profile helps.** When fbneo was profiled for
arcade systems, NeoGeo-specific BIOS files were outside the analysis
scope. Profiling fbneo_neogeo later surfaced files the first pass
hadn't covered. Doing a fresh pass for each profile, even on a
familiar codebase, avoids carrying over blind spots.

**Path adaptation vs real divergence.** The libretro wrapper changing
`fopen("./rom.bin")` to load from `system_dir` is the standard
porting pattern. The file is the same, only the directory resolution
changed. True divergences (added/removed files, different embedded
data) are the ones worth documenting.

**Each core has its own loading logic.** snes9x and bsnes both
emulate the Super Nintendo, but they handle the Super Game Boy BIOS
and DSP firmware through different code paths. Checking the actual
code for each core avoids assumptions based on a related profile.

**Code over docs.** Wiki pages and README files sometimes reference
files from older versions or a different fork. A file the source code
does not load is left out of the profile, even when documentation or the
`.info` mentions it (desmume2015's `.info` lists three firmware files its
code never opens).

## YAML field reference

### Profile fields

`schemas/emulator.schema.json` is the contract CI validates every profile
against. It requires `emulator` and `type`, then `files`, or `alias_of` for an
alias. A profile also carries `source_commit` or `profiled_date`: without
either, profile_sync has no revision to read the `source_ref` lines at and
reports the profile as uncheckable, and the CI job that runs
`profile_sync.py --strict` on each profile a pull request adds fails on it.

| Field | Required | Description |
|-------|----------|-------------|
| `emulator` | yes | display name |
| `type` | yes | `libretro`, `standalone`, `standalone + libretro`, `alias`, `launcher`, `game`, `utility` |
| `role` | no | `game`, `utility`, `test`: what a libretro core that emulates no machine is for. The site and coverage leave `test` cores out |
| `core_classification` | no | `pure_libretro`, `official_port`, `community_fork`, `frozen_snapshot`, `enhanced_fork`, `game_engine`, `embedded_hle`, `launcher`, `alias`, `other` |
| `source` | no | libretro core repository URL. A dict when the core ships under several repos |
| `upstream` | no | original emulator repository URL |
| `profiled_date` | see above | date of source analysis. Quote it, or YAML parses it as a date object |
| `core_version` | every profile (`tests/test_version_basis.py`) | the version of the code at the pin, read where `version_basis` says. null when the code states none, never `Git`, `SVN` or a branch name. A dict keyed by build mode when the builds differ |
| `version_basis` | every profile (`tests/test_version_basis.py`) | where `core_version` is read, by `kind`: `file` (`path`, `pattern`, optional `format`, and `url` with its `commit` for a file outside the profile's repositories, such as the package file of a build a platform ships), `tag` (the nearest `tag` in the pin's history and its `distance`, `core_version` in git describe's form, `match` the glob a tag must fit), `alias` (`of`), `package` (`artifact`, the APK or binary read, `url` where it was obtained), `none` (the code states no version: `core_version` null) or `unverified` (no reading could be made: `core_version` stays as written and is reported unconfirmed, `why` says why: `no_pin`, `host_unsupported`, `host_gone`, `host_unreachable`, `pin_off_branch`, `no_artifact`, `no_source`). `repo` names `upstream` or `source_mirror` when the version is that tree's. `profile_sync --verify-version` reads it again, and a pin advance rewrites `core_version` from it |
| `source_commit` | see above | commit SHA of `source` the code was read at. Anchors every `source_ref` line number |
| `upstream_commit` | no | same, for `upstream` |
| `pin_frozen` | no | why `source_commit` is held on purpose rather than followed. The profile is then judged against its own revision, like one pinned to a superseded tag |
| `pin_build` | no | the build file each platform shipping a `pin_frozen` build reads its revision from: a list of `platform` (registry slug), `repo` (the platform's own repository), `revision` (the tag or commit the file was read at), `path`, `variable` (`PKG_VERSION`, `<PKG>_VERSION`, `rp_module_repo`) and `value` (what it held there). `check_freshness.py` reads the file again where the platform's YAML now stands and reports the profile `STALE` when the platform builds another revision. A hold that no build file names (a release binary, an abandoned repository) carries `pin_frozen` alone. A `pin_build` list stands only beside the `pin_frozen` or the `config_reads` that it serves |
| `pin_follows` | no | why `source_commit` follows the branch tip when a single platform ships the profile: that platform builds the tip, cited by its build file. A bump refuses a profile one platform ships until it carries `pin_frozen` or `pin_follows` |
| `groups` | no | the sets of entries the code takes one of, by name, each with its `required`. A member names its sets with `group` and writes no `required` of its own: it is required when one of its sets is |
| `data_root` | no | per operating system (`android`, `ios`, `windows`, `macos`, `linux`), the folder the app reads its user data from, under which `standalone_path` destinations sit: `path` as the user finds it (`Android/data/<package>/files`, `%APPDATA%/...`), with the `source_ref` that builds it. Only the systems the app runs on are keyed |
| `upstream_frozen` | no | why `upstream_commit` is held: the port vendors that upstream tree, synced to that release, or merged that commit. The upstream view is read at its own pin and a bump leaves it. Without it, a port that is a GitHub fork of its upstream follows the merge base of the two |
| `prose_written_at` | no | the pin a reader confirmed the prose citations against. When the profile's history shows a text living under several pins, profile_sync takes this one as the revision the text describes, so a bump is no longer refused for a citation already reread. It never overrides a history with a single candidate |
| `version_source` | no | for a project published outside any forge, `{url, pattern}`: the page that announces releases and a regular expression whose first group is the latest version. `profile_sync --check-version` compares it with `core_version`, and `check_freshness --profiles` calls the profile stale when they differ. `no_genuine_copy` names an announced version found only rebuilt or re-signed: the profile stays on the newest unmodified build and is not stale until the page announces a later one |
| `upstream_gone` | no | why the declared upstream can no longer be reached, when that is settled rather than transient. Records the death instead of leaving the profile failing every pass. profile_sync reports it as declared, and reports the contradiction if the forge answers again |
| `source_mirror` | no | a repository carrying the same tree, consulted after `source` and `upstream`. What keeps a profile checkable once its own forge stops answering |
| `source_ref` | no | the code a profile with no file entry rests on: the load routine that opens nothing from outside (`emulators/craft.yml`) |
| `found_by` | no | the default `found_by` of every file entry (see the file entry fields) |
| `source_branch` | no | branch `source` was read from when it is not the default one (a port living on a pull request branch). profile_sync follows it |
| `built_by` | no | platforms that ship this build under its core name, compiled by them or installed from the project's own release (Recalbox's `mame0278`, the GSplus legacy build). On those platforms the name resolves to this profile, never through `all_libretro`: the buildbot does not publish it |
| `bios_mode` | no | `agnostic` when the core takes any file of the right shape in its BIOS folder instead of a fixed name (PCSX2). Packs then carry every matching dump, and a `<bios>.bin` placeholder stands for them |
| `bios_directory` | no | the folder an agnostic core scans, relative to the system directory (`pcsx2/bios/`). A scan never seeds from files outside it |
| `standalone_directories` | no | what the standalone build resolves `standalone_path` against, as its code names it: a directory (`$XDG_DATA_HOME/flycast`), a setting (`Dreamcast.BiosPath`), an environment variable (`FLYCAST_BIOS_PATH`) or the function returning the directory (`find_user_data_dir`). A platform whose launcher links or passes a folder of its BIOS tree under one of them gets the standalone files in that folder |
| `standalone_pools` | no | settings the standalone build reads as a list of directories it searches one after the other, each mapped to the subfolder of the layout (relative to `standalone_directories`, empty for the whole of it) its directories stand for: openMSX's filepool entries are searched like `share/systemroms`, XRoar's rompath entries hold the ROMs themselves. A file in any entry is read, so several platform records naming entries give the first one a pack can fill |
| `libretro_pools` | no | options of the command line a libretro build is handed as its content that set a list of directories it searches, each mapped to the folder below the system directory its directories stand for: a `folder` with the `source_ref` where the build reads the option. libretro MAME hands MAME `<system>/mame/bios` unless the content's own `-rompath` replaces it |
| `config_reads` | no | the configs the build loads and the keys it opens a file from, so a platform launcher record citing a config is proven: each entry names the `file` (a name, a glob, a path, a flag, `command line` or `core options`), the `source_ref` where it is found and loaded, and `keys`, each `key` with the `source_ref` where it is read and its value opened. An entry naming `platforms` is read at their `pin_build` revision, or at `revision` or in `binary_sha256` with `revision_from` saying where that was read. One naming none is read at `source_commit` |
| `display_name` | no | full display name (e.g. "Sega - Mega Drive (BlastEm)") |
| `logo` | no | image URL used on the emulator page |
| `systems` | no | list of system IDs this core handles |
| `cores` | no | every upstream name the core is known by, for buildbot/target matching |
| `alias_of` | for `type: alias` | profile key this one aliases. The alias carries no `files` |
| `library_name` | when a libretro file has `load_from: save_dir` | the `library_name` the core reports in `retro_get_system_info`, read from the code. RetroArch sorts saves by core by default and hands the core `<save directory>/<library_name>`, so packs and the installer need it to place a file read there. Empty when the core reports an empty name, for which RetroArch adds no folder (FS-UAE, `libretro/libretro.c:575`) |
| `save_folder_once` | no | `true` when the core adds its own folder to the save directory only where the directory it is handed is not already named so (Cemu's `in_named_dir`, `src/libretro/CemuLibretro.cpp:1670-1681`). Every `load_from: save_dir` path then starts with that folder, the `library_name`, and the file lands in the same place whether the frontend sorts saves by core or not |
| `mode` | no | default mode: `standalone`, `libretro`, or `both` |
| `verification` | no | how the core verifies BIOS: `existence`, `md5`, `sha1`, `crc32` |
| `files` | yes, unless `type: alias` | list of file entries |
| `data_directories` | no | whole directory trees the core needs, referencing `_data_dirs.yml` keys. An entry may carry `mode:` when only one build reads the tree, `required: false` when the core runs without it (`--required-only` then leaves it out), and `load_from: content_dir` when the core reads it beside the content rather than in the system directory. Every platform that runs the core as a libretro core gets the tree in its pack, unless the entry names it in `installed_on` or `unread_on`, or the `_data_dirs.yml` entry has a `for_platforms` list without it |
| `notes` | no | free-form technical notes |
| `note` | no | single-paragraph variant of `notes` |
| `exclusion_note` | no | why the profile has no files despite .info declaring firmware |
| `analysis` | no | structured per-subsystem analysis (capabilities, supported modes) |
| `analysis_date`, `analysis_commit` | no | when and at which commit `analysis` was produced |
| `platform_details` | no | per-system platform-specific details (paths, romsets, forced systems) |
| `mame_version` | no | MAME romset generation a MAME-family profile targets |
| `archive_prefix`, `pack_structure` | no | how arcade entries are laid out inside the pack |

Descriptive fields, rendered on the emulator page and read by no tool:
`author`, `based_on` (the project and version a fork starts from), `core` and
`core_name` (the library file name), `bios_size`, `bios_identical_to` (the
profile whose BIOS set is the same), `resources_directory`, `rom_path`,
`builtin_boot_roms`, `valid_bios_crc32`, `memory_layout`, `machine_properties`,
`machine_directories`, `model_kickstart_map`, `whdload_kickstarts`,
`firmware_titles` and `mlc_structure` (system titles a Wii U or Switch
firmware installs), `dev_flash`, `dev_flash2`, `dev_flash3` (PS3 flash
partitions), and `game_count`.

### Files read from the save directory

Some libretro cores read system data below the save directory the frontend
hands them, not below the system directory. Azahar moves its whole user folder
to `<save_dir>/Azahar/` under the default option "LibRetro Default"
(`src/citra_libretro/core_settings.cpp:1048-1080`), falling back to the system
directory only when the frontend gives none. Such an entry carries
`load_from: save_dir` (or `{libretro: save_dir}`), a `path` relative to the
save directory, and the profile names its `library_name`.

The save directory itself is the platform's: `save_directory` in
`platforms/_registry.yml` names it where the frontend keeps it in one place.
RetroArch keeps `saves/` beside `system/` and sorts by core, so Azahar's keys
land in `saves/Azahar/Azahar/sysdata/keys.txt`. Lakka keeps
`/storage/savefiles`, and EmuDeck one unsorted `~/Emulation/saves/retroarch/saves`
for every core.

Batocera, KNULLI, Recalbox, RetroBat and RetroDECK hand a core the save folder
of the system it was launched for (`by_system`): Batocera's configgen writes
`/userdata/saves/<system>` at each launch. The file then goes once below each
system that runs the core there, so libretro Dolphin's `User/GBA/gba_bios.bin`
lands in both `saves/gamecube/User/GBA/` and `saves/wii/User/GBA/` on Batocera.
RetroBat sorts Dolphin's saves by core too, which adds `dolphin-emu/`.

A platform whose registry entry has no `save_directory` keeps no single save
place: RetroPie, ROCKNIX, AmberELEC and EmuELEC keep saves beside each game,
and RomM runs cores in the browser. Those entries are listed as omitted
(`no_save_directory`), never placed in the BIOS tree where the core does not
look.

### File entry fields

| Field | Description |
|-------|-------------|
| `name` | filename as the core expects it |
| `required` | true if the core needs this file to function. Not written on a member of a `group`: derived from the sets in `groups` |
| `system` | system ID this file belongs to (for multi-system profiles) |
| `systems` | the systems of the profile this file serves, when it serves several but not all (a MAME device set the machines of two systems load). Never written with `system` |
| `archive` | ROM set the file lives inside, for arcade entries (e.g. `neogeo.zip`) |
| `size` | expected size in bytes, or a list when the code accepts several exact sizes |
| `min_size`, `max_size` | size range when the code accepts a range |
| `size_multiple` | granule the size must be a whole number of, the bounds still applying (xemu maps any flash image of a positive multiple of 64 KiB) |
| `md5`, `sha1`, `crc32`, `sha256` | expected hashes from source code |
| `known_hash_adler32`, `adler32_byteswap` | expected Adler-32 hash (Dolphin's DSP ROMs). Pair with `adler32_byteswap` when the code hashes 16-bit byte-swapped data |
| `adler32_pairs_with`, `adler32_pairs` | the file hashed together with this one and the combinations the code accepts, this file's value first, in table order: Dolphin warns on a DSP ROM pair outside its `known_roms` even when each file passes alone |
| `validation` | checks the code performs: `size`, `crc32`, `md5`, `sha1`, `adler32`, `romdir`, `masked_sha1`, `signature`, `crypto`. Can be a list or dict `{core: [...], upstream: [...]}` for divergent checks |
| `romdir` | how the code reads a PS2 ROM directory for `validation: [romdir]`: `reset_compare` (5 or 10 bytes compared with RESET), `missing_reset`, `terminated_names`, `extinfo`, `unreadable_romver`, `truncated_walk`, `offset_width`, and `refused_serials`, `zones`, `refused_zones` for the tests after the walk. Each is read in the fork's `LoadBiosVersion` |
| `masked_sha1` | for `validation: [masked_sha1]`: the bytes the code clears (`zeroed`), the lengths it hashes for each file size it tries (`reads`) and the SHA-1 it compares (Amiberry's CyberStorm and Blizzard PPC flash images) |
| `aliases` | alternate filenames for the same file |
| `mode` | `libretro`, `standalone`, or `both` |
| `hle_fallback` | true if a high-level emulation path exists |
| `evidence` | by field (`required`, `hle_fallback`, `path`, `aliases`), the ids of the records in `measurements/<emulator>.jsonl` whose runs settled it. Written by `campaign.py` from its rule table, never by hand |
| `category` | `bios` (default), `game_data`, `bios_zip` |
| `region` | always a list of territory slugs from the schema enum (`[north-america]`, `[japan, asia-ntsc]`). The region the code selects the file **for**, never the region of the dump. See step 3b |
| `region_check` | true if the core refuses to boot a game whose region does not match the BIOS |
| `fast_boot` | BIOS generation label the core uses to decide whether fast boot is available |
| `priority` | preference order when several BIOS satisfy the same slot, **lowest wins**. DuckStation's `FindBIOSImageInDirectory` keeps the image whose priority is lower, and its table de-prioritizes by raising the number: the buggy launch console sits at 50 and PS2 images at 100, while `scph5501` sits at 5. A core that walks an ordered search list, as PicoDrive does with `biosfiles_us/eu/jp`, maps onto the same field as 1, 2, 3. Only set it from the source. `--one-per-slot` reads it, comparing the members of one `group` |
| `group` | the sets of the profile's `groups:` map an entry belongs to. A set is one need: the code loads one member (the first it finds, as Yabause tries `saturn_bios.bin`, `sega_101.bin`, `mpr-17933.bin`) and holding any member fills it. Verify, the gap report and the packs report a set nobody holds as one gap under its first member, and no member of a held set as missing. A `--required-only` build keeps one member per required set, the first the code reads among those held. A list puts a file in several sets, a map from set to rank gives its place in each when it differs (pom2's `apple2.rom` is second for the ][ and third at boot). Where the code keeps a list per region, each list is its own set (PicoDrive's `mega-cd-us`, `mega-cd-eu`, `mega-cd-jp`). An archive's own entry joins a set like a loose file, its unit under `archive_prefix` ranking before the same name at the root (Kronos reads `kronos/stvbios.zip`, else `stvbios.zip`), and its members still settle it by their contents |
| `groups` (profile) | the requirement of each set, `{name: {required: bool}}`. A member writes no `required`: it is required when one of its sets is, so a fallback shared by a required set and an optional one needs no value of its own |
| `embedded` | true if the data is compiled into the binary and the external file is optional |
| `bundled` | true if the emulator's own release installs the file where it reads it, for the build `mode` names (all builds when `mode` is absent). Packs and the installer leave it out: the user already has it. A file the standalone release ships but the libretro core does not (PPSSPP's assets, Dolphin's Sys) is bundled with `mode: standalone` only |
| `not_bundled_on` | platforms (registry keys) whose package leaves out a file the release bundles: their packs bring it (Batocera installs hcl without its data) |
| `unread_on` | platforms (registry keys) whose launcher points the emulator at other files, so the entry is never opened there and leaves that platform's report and pack (RetroBat gives standalone BlastEm absolute BIOS paths) |
| `installed_on` | platforms whose own package installs the file beside the emulator although the release does not: their packs leave it out (Batocera and RetroPie copy blueMSX's machines beside the core) |
| `has_builtin` | true if the core falls back to a built-in copy when the file is absent |
| `config_key` | configuration key the emulator exposes to point at the file |
| `load_from` | directory the core reads the file from when it is not the system directory, keyed by build (`{libretro: save_dir}`) when the standalone build reads `standalone_path` from its own folder. `save_dir` is the directory the frontend returns for `RETRO_ENVIRONMENT_GET_SAVE_DIRECTORY`: `path` is then relative to it, as the code joins it (Azahar's `Azahar/sysdata/keys.txt`, Dolphin's `User/GBA/gba_bios.bin`), and packs and the installer place the libretro build's file below the save directory (see [Files read from the save directory](#files-read-from-the-save-directory)). `content_dir`, `working_directory`, `config_dir`, `data_dir` and the others describe places no pack reaches |
| `found_by` | `name` when the code opens the file by its name (the default), `content` when it scans a folder and identifies the file by hash, so the name is only a label (DuckStation by MD5, `bios.cpp:208`). Set on the profile or on one file, a dict splits `standalone` from `libretro`. A label is never written into a platform file as a name to hold, and pairs with a platform entry only by hash |
| `source_ref` | source file and line number (e.g. `boot.cpp:42`), read at the profile's `source_commit` when set. A dict splits `standalone` from `libretro` when they diverge. In a profile that declares both `source` and `upstream`, each cited path opens with the one its lines are in: `source libretro.c:120` for the port's own code, `upstream emu/memory.c:46` for the emulator's, including the copy a port carries. `profile_sync --attribute-refs` writes these words from where the lines are found, and the site labels each citation with them |
| `path` | destination path relative to the system directory, or to the save directory under `load_from: save_dir` |
| `standalone_path` | where the standalone build reads the file, under its own data folder, when it differs from `path` (the libretro destination). Packs for a platform running the emulator standalone use it |
| `on_mismatch` | what the code does when a declared check fails: `reject` (default) or `warn` and run with it, for every check or check by check (`{size: warn, md5: reject}`) |
| `selection_slot` | files one core chooses between by a rule other than first found (the disc's territory, a core option, a feature probe), one slot of the core whatever system each is filed under: PicoDrive's twelve Mega CD BIOS, picked by disc region, O2EM's four BIOS, picked by a core option. Region selection compares them together and keeps one per slot. A member does not stand in for another: entries that do are a `group` |
| `size_note` | how the code treats the file's size when no size field can say it (a read capped at 32 bytes, a file created empty when absent) |
| `type` | `directory` when the code reads a whole tree (an RTP, a folder of speech samples). `path` is then the directory, written with its trailing slash, and the entry stands for every file the collection holds under it. A name ending in `/` requires it |
| `description` | what this file is |
| `note` | additional context |
| `contents` | structure of files inside a BIOS ZIP (`name`, `description`, `size`, `crc32`) |
| `storage` | `embedded` (default), `external`, `user_provided`, or `large_file`/`release` for files stored as release assets (listed in `.gitignore`) |
| `agnostic` | true if any file under the system path within size constraints satisfies the requirement |
| `unsourceable` | why the collection cannot hold these exact bytes. It stops a different file with the same name from being served in the entry's place, while every hash proof still runs. The entry stays an acquisition target |
| `destination` | target path within the BIOS directory |

