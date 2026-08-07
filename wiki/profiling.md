# Profiling guide - RetroBIOS

How to create an emulator profile from source code.

## Approach

A profile documents what an emulator loads at runtime.
The source code is the reference because it reflects actual behavior.
Documentation, .info files, and wikis are useful starting points
but are verified against the code.

### Source hierarchy

Documentation and metadata are valuable starting points, but they can
fall out of sync with the actual code over time. The desmume2015 .info
file is a good illustration: it declares `firmware_count=3`, but the
source code at the pinned version opens zero firmware files. Cross-checking
against the source helps catch that kind of gap early.

When sources conflict, priority follows the chain of actual execution:

1. **Original emulator source** (ground truth, what the code actually does)
2. **Libretro port** (may adapt paths, add compatibility shims, or drop features)
3. **.info metadata** (declarative, may be outdated or copied from another core)

For standalone emulators like BizHawk or amiberry, there is only one
level. The emulator's own codebase is the single source of truth. No
.info, no wrapper, no divergence to track.

A note on libretro port differences: the most common change is path
resolution. The upstream emulator loads files from the current working
directory; the libretro wrapper redirects to `retro_system_directory`.
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

If the source is hosted outside GitHub, it's worth exploring further. Emulator
source on GitLab, Codeberg, SourceForge, Bitbucket, archive.org
snapshots, and community mirror tarballs. Inspecting copyright headers
or license strings in the libretro fork often points to the original
author's site. The upstream code exists somewhere; it's worth continuing the search before concluding the source is unavailable.

One thing worth noting: even when the same repository was analyzed for
a related profile (e.g., fbneo for arcade systems), it helps to do a
fresh pass for each new profile. When fbneo_neogeo was profiled, the
NeoGeo subset referenced BIOS files that the main arcade analysis
hadn't encountered. A fresh look avoids carrying over blind spots.

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

When a core has HLE (high-level emulation), the real BIOS typically
gives better accuracy, but the core functions without it. These files
are marked with `hle_fallback: true` and `required: false`. The file
still ships in packs (better experience for the user), but its absence
does not raise alarms during verification.

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
source: https://github.com/libretro/dolphin
upstream: https://github.com/dolphin-emu/dolphin
profiled_date: 2026-03-25
core_version: 5.0-21264
systems:
  - nintendo-gamecube
  - nintendo-wii

files:
  - name: GC/USA/IPL.bin
    system: nintendo-gamecube
    required: false
    hle_fallback: true
    size: 2097152
    validation: [size, adler32]
    known_hash_adler32: 0x4f1f6f5c
    region: north-america
    source_ref: Source/Core/Core/Boot/Boot_BS2Emu.cpp:42
```

Record `source_commit` when profiling: upstream code moves, and a
`source_ref` line number only stays checkable against the commit it was
read at. Profiles written before this field existed carry `profiled_date`
and `core_version` instead; they gain `source_commit` as they are
re-verified.

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
  `utility`, `test`. Putting a classification concept here (like
  "bizhawk-native") breaks the filtering. A BizHawk core is
  `type: standalone`.

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
  check at all, the hash is omitted from the profile. The .info or docs
  may list an MD5, but source confirmation makes it more reliable.

### 6. Validate

```bash
python scripts/cross_reference.py --emulator dolphin --json
python scripts/verify.py --emulator dolphin
```

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
porting pattern. The file is the same; only the directory resolution
changed. True divergences (added/removed files, different embedded
data) are the ones worth documenting.

**Each core has its own loading logic.** snes9x and bsnes both
emulate the Super Nintendo, but they handle the Super Game Boy BIOS
and DSP firmware through different code paths. Checking the actual
code for each core avoids assumptions based on a related profile.

**Code over docs.** Wiki pages and README files sometimes reference
files from older versions or a different fork. If the source code
does not load a particular file, it can be left out of the profile
even if documentation mentions it.

## YAML field reference

### Profile fields

| Field | Required | Description |
|-------|----------|-------------|
| `emulator` | yes | display name |
| `type` | yes | `libretro`, `standalone`, `standalone + libretro`, `alias`, `launcher`, `game`, `utility`, `test` |
| `core_classification` | no | `pure_libretro`, `official_port`, `community_fork`, `frozen_snapshot`, `enhanced_fork`, `game_engine`, `embedded_hle`, `launcher`, `other` |
| `source` | yes | libretro core repository URL |
| `upstream` | no | original emulator repository URL |
| `profiled_date` | yes | date of source analysis |
| `core_version` | yes | version analyzed |
| `source_commit` | no | upstream commit SHA the source was read at; anchors every `source_ref` line number |
| `display_name` | no | full display name (e.g. "Sega - Mega Drive (BlastEm)") |
| `systems` | yes | list of system IDs this core handles |
| `cores` | no | list of upstream core names for buildbot/target matching |
| `mode` | no | default mode: `standalone`, `libretro`, or `both` |
| `verification` | no | how the core verifies BIOS: `existence` or `md5` |
| `files` | yes | list of file entries |
| `notes` | no | free-form technical notes |
| `exclusion_note` | no | why the profile has no files despite .info declaring firmware |
| `analysis` | no | structured per-subsystem analysis (capabilities, supported modes) |
| `platform_details` | no | per-system platform-specific details (paths, romsets, forced systems) |

### File entry fields

| Field | Description |
|-------|-------------|
| `name` | filename as the core expects it |
| `required` | true if the core needs this file to function |
| `system` | system ID this file belongs to (for multi-system profiles) |
| `size` | expected size in bytes |
| `min_size`, `max_size` | size range when the code accepts a range |
| `md5`, `sha1`, `crc32`, `sha256` | expected hashes from source code |
| `known_hash_adler32` | expected Adler-32 hash (used by Dolphin IPL files) |
| `validation` | checks the code performs: `size`, `crc32`, `md5`, `sha1`, `adler32`, `signature`, `crypto`. Can be a list or dict `{core: [...], upstream: [...]}` for divergent checks |
| `aliases` | alternate filenames for the same file |
| `mode` | `libretro`, `standalone`, or `both` |
| `hle_fallback` | true if a high-level emulation path exists |
| `category` | `bios` (default), `game_data`, `bios_zip` |
| `region` | geographic region (e.g. `north-america`, `japan`) |
| `source_ref` | source file and line number (e.g. `boot.cpp:42`), read at the profile's `source_commit` when set |
| `path` | destination path relative to system directory |
| `description` | what this file is |
| `note` | additional context |
| `contents` | structure of files inside a BIOS ZIP (`name`, `description`, `size`, `crc32`) |
| `storage` | `large_file` for files > 50 MB stored as release assets |
| `agnostic` | true if any file under the system path within size constraints satisfies the requirement |
| `unsourceable` | reason why the file cannot be sourced (acknowledged gap) |
| `destination` | target path within the BIOS directory |

