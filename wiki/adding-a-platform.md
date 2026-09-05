# Adding a platform

How to add support for a new retrogaming platform (e.g. a frontend like Batocera,
a manager like EmuDeck, or a firmware database like BizHawk).

## Prerequisites

Before starting, gather the following from the upstream project:

- **Where does it define BIOS requirements?** Each platform has a canonical source:
  a DAT file, a JSON fixture, an XML manifest, a Bash script, a C# database, etc.
- **What verification mode does it use?** Read the platform source code to determine
  how it checks BIOS files at runtime: file existence only (`existence`), MD5 hash
  matching (`md5`), SHA1 matching (`sha1`), or a combination of size and hash.
- **What is the base destination?** The directory name where BIOS files are placed
  on disk (e.g. `system` for RetroArch, `bios` for Batocera, `Firmware` for BizHawk).
- **What hash type does it store?** The primary hash format used in the platform's
  own data files (SHA1 for RetroArch/BizHawk, MD5 for Batocera/Recalbox/EmuDeck).

## Step 1: Create the scraper

Scrapers live in `scripts/scraper/` and are auto-discovered by the plugin system.
Any file matching `*_scraper.py` in that directory is loaded at import time via
`pkgutil.iter_modules`. No registration step is needed beyond placing the file.

### Module contract

The module must export two names:

```python
PLATFORM_NAME = "myplatform"  # matches the key in _registry.yml

class Scraper(BaseScraper):
    ...
```

### Inheriting BaseScraper

`BaseScraper` provides:

- `_fetch_raw() -> str` - HTTP GET with 50 MB response limit, cached after first call.
  Uses `urllib.request` with a `retrobios-scraper/1.0` user-agent and 30s timeout.
- `compare_with_config(config) -> ChangeSet` - diffs scraped requirements against
  an existing platform YAML, returning added/removed/modified entries.
- `test_connection() -> bool` - checks if the source URL is reachable.

Two abstract methods must be implemented:

```python
def fetch_requirements(self) -> list[BiosRequirement]:
    """Parse the upstream source and return one BiosRequirement per file."""

def validate_format(self, raw_data: str) -> bool:
    """Return False if the upstream format has changed unexpectedly."""
```

### BiosRequirement fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Filename as the platform expects it |
| `system` | `str` | Retrobios system ID (e.g. `sony-playstation`) |
| `sha1` | `str \| None` | SHA1 hash if available |
| `md5` | `str \| None` | MD5 hash if available |
| `crc32` | `str \| None` | CRC32 if available |
| `size` | `int \| None` | Expected file size in bytes |
| `destination` | `str` | Relative path within the BIOS directory |
| `required` | `bool` | Whether the platform considers this file mandatory |
| `zipped_file` | `str \| None` | If set, the hash refers to a ROM inside a ZIP |
| `native_id` | `str \| None` | Original system name before normalization |

### System ID mapping

Every scraper needs a mapping from the platform's native system identifiers to
retrobios system IDs. Define this as a module-level dict:

```python
SLUG_MAP: dict[str, str] = {
    "psx": "sony-playstation",
    "saturn": "sega-saturn",
    ...
}
```

Warn on unmapped slugs so new systems are surfaced during scraping.

### generate_platform_yaml (optional)

If the scraper defines a `generate_platform_yaml() -> dict` method, the shared
CLI will use it instead of the generic YAML builder. This allows the scraper to
include platform metadata (homepage, version, inherits, cores list) in the output.

### CLI entry point

Add a `main()` function and `__main__` guard:

```python
def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape MyPlatform BIOS requirements")

if __name__ == "__main__":
    main()
```

`scraper_cli` provides `--dry-run`, `--json`, and `--output` flags automatically.

### Test the scraper

```bash
python -m scripts.scraper.myplatform_scraper --dry-run
```

This fetches from upstream and prints a summary without writing anything.

## Step 2: Register the platform

Add an entry to `platforms/_registry.yml` under the `platforms:` key.

The registry describes *where the data comes from*. How the platform behaves
at runtime (`verification_mode`, `base_destination`) belongs to the platform
YAML, because that is what `verify.py` and `generate_pack.py` load. Keeping the
two apart means a re-scrape can rewrite the YAML without touching the registry.

### Required fields

```yaml
platforms:
  myplatform:
    config: myplatform.yml           # platform YAML filename in platforms/
    status: active                   # active or archived
    scraper: myplatform              # matches PLATFORM_NAME, null if hand-maintained
    schedule: weekly                 # re-scrape cadence, run by hand: weekly, monthly, or null
    source_url: https://...          # upstream data URL
    source_format: json              # json, xml, clrmamepro_dat, python_dict,
                                     # bash_script+csv, csharp_firmware_database,
                                     # github_component_manifests, mister_downloader_db
    hash_type: md5                   # primary hash in the upstream data
    cores:                           # which emulator profiles apply
    - core_a
    - core_b
```

A platform without a scraper (`scraper: null`, `schedule: null`) keeps its YAML
as a hand-maintained file. RetroPie is the example: it inherits RetroArch's
file set and has nothing of its own to fetch.

The `cores` field determines which emulator profiles are resolved for this platform.
Three strategies exist:

- **Explicit list**: `cores: [beetle_psx, dolphin, ...]` - match by profile key name.
  Used by Batocera, Recalbox, RetroBat, RomM.
- **all_libretro**: `cores: all_libretro` - include every profile with `type: libretro`
  or `type: standalone + libretro`. Used by RetroArch, Lakka, RetroPie.
- **Omitted**: fallback to system ID intersection. Used by EmuDeck.

### Optional fields

```yaml
    logo: https://...                # SVG or PNG for UI/docs
    inherits_from: retroarch         # inherit systems/cores from another platform
    case_insensitive_fs: true        # if the platform runs on case-insensitive filesystems
    source_wiki: https://...         # human-readable upstream reference
    target_scraper: myplatform_targets  # hardware target scraper name, null if static
    target_source: https://...       # target data source URL
    contributed_by:                  # credited in README, site, and packs
    - username: someone
      contribution: platform support
      pr: 50
    install:
      detect:                        # auto-detection for install.py
      - os: linux
        method: config_file
        config: $HOME/.config/myplatform/config.ini
        parse_key: bios_directory
```

### Platform YAML header

The runtime behavior lives at the top of `platforms/myplatform.yml`:

```yaml
platform: MyPlatform
verification_mode: md5   # existence, md5, or sha1
hash_type: md5           # primary hash stored in the file entries
base_destination: bios   # root directory the pack extracts into
inherits: retroarch      # optional, merges the parent's systems
systems:
  sony-playstation:
    files: [...]
```

`base_destination` is what the pack prefixes every entry with. Leave it empty
when the upstream destinations already carry their own root, as RetroDECK does
with `bios/` and `roms/`.

### Inheritance

If the new platform inherits from an existing one (e.g. Lakka inherits RetroArch),
set `inherits_from` in the registry AND add `inherits: retroarch` in the platform
YAML itself. `load_platform_config()` reads the `inherits:` field from the YAML to
merge parent systems and shared groups into the child. The child YAML only needs to
declare overrides.

## Step 3: Generate the platform YAML

Run the scraper with `--output` to produce the initial platform configuration:

```bash
python -m scripts.scraper.myplatform_scraper --output platforms/myplatform.yml
```

If a file already exists at the output path, the CLI preserves fields that the
scraper does not generate (e.g. `data_directories`, manually added metadata).
Only the `systems` section is replaced.

Verify the result:

```bash
python scripts/verify.py --platform myplatform
python scripts/verify.py --platform myplatform --verbose
```

## Step 4: Add verification logic

Check how the platform verifies BIOS files by reading its source code.
The `verification_mode` in the platform YAML tells `verify.py` which strategy
to use:

| Mode | Behavior | Example platforms |
|------|----------|-------------------|
| `existence` | File must exist, no hash check | RetroArch, Lakka, RetroPie |
| `md5` | MD5 must match the declared hash | Batocera, Recalbox, RetroBat, EmuDeck, RetroDECK, RomM, ROCKNIX, MiSTer FPGA |
| `sha1` | SHA1 must match | BizHawk |

Inheriting platforms take the parent's mode: Lakka and RetroPie do not declare
one, they get `existence` from RetroArch.

If the platform has unique verification behavior (e.g. Batocera's `checkInsideZip`,
Recalbox's multi-hash comma-separated MD5, RomM's size + any-hash), add the logic
to `verify.py` in the platform-specific verification path.

Read the platform's source code to understand its exact verification behavior before writing any logic. Batocera's `checkInsideZip` uses `casefold()` for case-insensitive matching. Recalbox supports comma-separated MD5 lists. RomM checks file size before hashing. These details matter: the project replicates native behavior, not an approximation of it.

## Step 5: Create an exporter (optional)

Exporters convert truth data back to the platform's native format. They live in
`scripts/exporter/` and follow the same auto-discovery pattern (`*_exporter.py`).

### Module contract

The module must export an `Exporter` class inheriting `BaseExporter`:

```python
from scripts.exporter.base_exporter import BaseExporter

class Exporter(BaseExporter):
    @staticmethod
    def platform_name() -> str:
        return "myplatform"

    def export(self, truth_data: dict, output_path: str, scraped_data: dict | None = None) -> None:
        # Write truth_data in the platform's native format to output_path
        ...

    def validate(self, truth_data: dict, output_path: str) -> list[str]:
        # Return a list of issues (empty = valid)
        ...
```

`BaseExporter` provides helper methods:

- `_is_pattern(name)` - True if the filename contains wildcards or placeholders.
- `_dest(fe)` - resolve destination path from a file entry dict.
- `_display_name(sys_id, scraped_sys)` - convert a system slug to a display name.

### Round-trip validation

```bash
python -m scripts.scraper.myplatform_scraper --output platforms/myplatform.yml
python scripts/export_native.py --platform myplatform --fetch --output-dir tmp/native
diff .cache/upstream-native/myplatform/<their file> \
     tmp/native/myplatform/<their file>
```

The export must not lose anything the platform already declares. If your
format carries code as well as data - a script, a C# database, a manifest
whose BIOS list sits beside launch configuration - say so with
`needs_original()` and patch their file rather than writing a new one. An
exporter that regenerates such a file from BIOS data alone hands the
maintainer something that no longer runs.

## Step 6: Create a target scraper (optional)

Target scrapers determine which emulator cores are available on each hardware
target (e.g. which RetroArch cores exist for Switch, RPi4, or x86_64).
They live in `scripts/scraper/targets/` and are auto-discovered by filename
(`*_targets_scraper.py`).

### Module contract

```python
from scripts.scraper.targets import BaseTargetScraper

PLATFORM_NAME = "myplatform_targets"

class Scraper(BaseTargetScraper):
    def fetch_targets(self) -> dict:
        return {
            "platform": "myplatform",
            "source": "https://...",
            "scraped_at": "2026-03-30T00:00:00Z",
            "targets": {
                "x86_64": {
                    "architecture": "x86_64",
                    "cores": ["beetle_psx", "dolphin", "..."],
                },
                "rpi4": {
                    "architecture": "aarch64",
                    "cores": ["pcsx_rearmed", "mgba", "..."],
                },
            },
        }
```

Add `target_scraper` and `target_source` to the platform's registry entry.

### Overrides

Hardware-specific overrides go in `platforms/targets/_overrides.yml`. This file
defines aliases (e.g. `arm64` maps to `aarch64`) and per-platform core
additions/removals that the scraper cannot determine automatically.

### Single-target platforms

For platforms that only run on one target (e.g. RetroBat on Windows, RomM in the
browser), create a static YAML file in `platforms/targets/` instead of a scraper.
Set `target_scraper: null` in the registry.

## Step 7: Add install detection (optional)

The `install` section in `_registry.yml` tells `install.py` how to detect
the platform on the user's machine and locate its BIOS directory.

Three detection methods are available:

| Method | Description | Fields |
|--------|-------------|--------|
| `config_file` | Parse a key from a config file | `config`, `parse_key`, optionally `bios_subdir` |
| `path_exists` | Check if a directory exists | `path`, optionally `bios_path` |
| `file_exists` | Check if a file exists | `file`, optionally `bios_path` |

Each entry is scoped to an OS (`linux`, `darwin`, `windows`). Multiple entries
per OS are tried in order.

## Step 8: Validate the full pipeline

After all pieces are in place, run the full pipeline:

```bash
python scripts/pipeline.py --offline
```

This executes in sequence:

1. `generate_db.py` - rebuild `database.json` from `bios/`
1b. `provenance_report.py` - dump-catalog coverage from `provenance/`
2. `refresh_data_dirs.py` - update data directories (skipped with `--offline`)
3. `verify.py --all` - verify all platforms including the new one
4. `generate_pack.py --all` - build ZIP packs + install and target manifests
5. Consistency check - verify counts match between verify and pack
6. Pack integrity - extract ZIPs and verify hashes per platform mode
7. `generate_readme.py` - regenerate README and CONTRIBUTING
8. `generate_site.py` - regenerate documentation site and `mkdocs.yml`

A new platform is archived-by-default nowhere: `status: active` puts it in
`list_platforms.py`, the CI matrix, and the scrapers. Set
`status: archived` to keep the configuration without the automation; archived
platforms are excluded unless `--all` or `--include-archived` is passed.

Check the output for:

- The new platform appears in verify results
- No unexpected CRITICAL or WARNING entries
- Pack generation succeeds and includes the expected files
- Consistency check passes (verify file counts match pack file counts)

Verification is not optional. A platform that passes `pipeline.py` today may break tomorrow if upstream changes its data format. Run the full pipeline on every change, even if the modification seems trivial. The consistency check (verify counts must match pack counts) catches subtle issues where files resolve during verification but fail during pack generation, or vice versa.

## Checklist

- [ ] Scraper file in `scripts/scraper/<name>_scraper.py`
- [ ] `PLATFORM_NAME` and `Scraper` class exported
- [ ] `fetch_requirements()` and `validate_format()` implemented
- [ ] System ID mapping covers all upstream systems
- [ ] Entry added to `platforms/_registry.yml`
- [ ] Platform YAML generated and verified
- [ ] `python scripts/pipeline.py --offline` passes
- [ ] Exporter in `scripts/exporter/<name>_exporter.py` (if applicable)
- [ ] Target scraper in `scripts/scraper/targets/<name>_targets_scraper.py` (if applicable)
- [ ] Install detection entries in `_registry.yml` (if applicable)
