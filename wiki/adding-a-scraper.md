---
level: contribute
order: 30
---

# Adding a scraper

A scraper reads a platform's own BIOS list and writes it as
`platforms/<name>.yml`, the file every pack, check and page of that platform
starts from. It copies what the platform declares, as the platform wrote it,
and leaves the corrections to the emulator profiles.

Example: `scripts/scraper/romm_scraper.py` reads RomM's
`known_bios_files.json` and writes `platforms/romm.yml`. Adding a scraper means
one `*_scraper.py` file with a class that extends `BaseScraper`, the base class
every scraper extends.

## Scraper architecture

### Plugin discovery

Scrapers are discovered automatically at import time. The `scripts/scraper/__init__.py`
module uses `pkgutil.iter_modules` to scan for files matching `*_scraper.py` in
the scraper directory. Each module must export:

- `PLATFORM_NAME: str` - the platform identifier (matches `_registry.yml`)
- `Scraper: class` - a subclass of `BaseScraper`

No registration code is needed. Drop a file, export the two names, and it works.

```python
# scripts/scraper/__init__.py (simplified)
for finder, name, ispkg in pkgutil.iter_modules([package_dir]):
    if not name.endswith("_scraper"):
        continue
    module = importlib.import_module(f".{name}", package=__package__)
    # looks for PLATFORM_NAME and Scraper attributes
```

### BaseScraper ABC

`BaseScraper` (`scripts/scraper/base_scraper.py`) provides the foundation:

```
BaseScraper
  __init__(url: str)
  lists_files: bool = True          # False: the platform lists no file of its own
  _fetch_raw() -> str               # HTTP GET, cached, 50 MB limit
  fetch_requirements() -> list       # abstract: parse upstream data
  validate_format(raw_data) -> bool  # abstract: detect format changes
  compare_with_config(config) -> ChangeSet  # diff against existing YAML
  test_connection() -> bool          # reachability check
```

`_fetch_raw()` goes through `fetch_bytes()`: `urllib.request` with a
`retrobios-scraper/1.0` user-agent and a 30-second timeout, the response read in
64 KB chunks with a 50 MB hard limit. A 429, 502, 503 or 504 answer is retried
up to five attempts, after the server's `Retry-After` or a doubling wait. The
result is cached on the instance after the first call.

### BiosRequirement

A dataclass representing a single BIOS file entry:

```python
@dataclass
class BiosRequirement:
    name: str                        # filename
    system: str                      # retrobios system ID
    sha1: str | None = None
    md5: str | None = None
    crc32: str | None = None
    size: int | None = None
    destination: str = ""            # relative path in BIOS dir
    required: bool = True
    zipped_file: str | None = None   # ROM name inside a ZIP
    native_id: str | None = None     # original system name
    sha256: str | None = None
    alt_md5: str | None = None       # a second accepted MD5
    native_path: str | None = None   # the reference as the platform writes it
    mirror_of: str | None = None     # the native system this entry repeats
    native: dict[str, object] = field(default_factory=dict)  # fields written back unchanged
```

[BiosRequirement fields](adding-a-platform.md#biosrequirement-fields) says what
each one carries.

### ChangeSet

Returned by `compare_with_config()`. Contains:

- `added: list[BiosRequirement]` - new files not in the existing config
- `removed: list[BiosRequirement]` - files present in config but gone upstream
- `modified: list[tuple[BiosRequirement, BiosRequirement]]` - hash changes
- `has_changes: bool` - True if any of the above are non-empty
- `summary() -> str` - human-readable summary (e.g. `+3 added, ~1 modified`)

### scraper_cli

`scraper_cli(scraper_class, description)` provides a shared CLI:

| Flag | Behavior |
|------|----------|
| `--dry-run` | Fetch and print a summary grouped by system |
| `--json` | Output all requirements as JSON |
| `--output FILE` | Write platform YAML to FILE |
| `--revision REF` | Read a branch head or a commit instead of the revision the platform file pins. Offered only to a scraper whose constructor takes `revision` (RetroBat), and passed by `check_freshness.py` and `refresh_stale.py` from the registry's `rescrape_args` |

When `--output` targets an existing file, every top-level key the scraper writes
is replaced and the others are kept, as is a system's `data_directories` the new
scrape does not carry. If the scraper defines `generate_platform_yaml()`, that
method is used instead of the generic YAML builder. A scrape that returns no entry,
or a YAML that lists no file, stops with an error instead of writing, unless the
scraper sets `lists_files = False`.

### Helper functions

Two additional functions in `base_scraper.py`:

- `fetch_github_latest_version(repo)` - fetches the latest release tag via GitHub API.
- `fetch_github_latest_tag(repo, prefix)` - fetches the most recent tag matching
  an optional prefix.

Both send `GITHUB_TOKEN` when it is set and raise `RuntimeError` when the tag
cannot be read, rather than letting a scraper fall back to a branch.

## Creating a BIOS scraper

### Minimal example

Based on the RomM scraper pattern (JSON source, flat structure):

```python
"""Scraper for MyPlatform BIOS requirements."""
from __future__ import annotations

import json
import sys

try:
    from .base_scraper import BaseScraper, BiosRequirement
except ImportError:
    from base_scraper import BaseScraper, BiosRequirement

PLATFORM_NAME = "myplatform"

SOURCE_URL = "https://raw.githubusercontent.com/org/repo/main/bios_list.json"

SLUG_MAP: dict[str, str] = {
    "psx": "sony-playstation",
    "saturn": "sega-saturn",
}


class Scraper(BaseScraper):
    def __init__(self, url: str = SOURCE_URL):
        super().__init__(url=url)

    def fetch_requirements(self) -> list[BiosRequirement]:
        raw = self._fetch_raw()
        if not self.validate_format(raw):
            raise ValueError("Format validation failed")

        data = json.loads(raw)
        requirements = []
        for entry in data:
            system = SLUG_MAP.get(entry["platform"])
            if not system:
                print(f"Warning: unmapped '{entry['platform']}'", file=sys.stderr)
                continue
            requirements.append(BiosRequirement(
                name=entry["filename"],
                system=system,
                md5=entry.get("md5"),
                sha1=entry.get("sha1"),
                size=entry.get("size"),
                destination=entry["filename"],
                required=entry.get("required", True),
            ))
        return requirements

    def validate_format(self, raw_data: str) -> bool:
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False
        return isinstance(data, list) and len(data) > 0


def main():
    from scripts.scraper.base_scraper import scraper_cli
    scraper_cli(Scraper, "Scrape MyPlatform BIOS requirements")

if __name__ == "__main__":
    main()
```

### Parsing different upstream formats

Each platform stores its BIOS requirements differently. The scraper's job is to
normalize them into `BiosRequirement` entries.

| Format | Example | Parsing approach |
|--------|---------|-----------------|
| JSON | RomM `known_bios_files.json` | `json.loads()`, iterate keys |
| XML | Recalbox `es_bios.xml` | `xml.etree.ElementTree`, xpath or iter |
| clrmamepro DAT | RetroArch `System.dat` | Use `dat_parser` module (see below) |
| Python dict | Batocera `batocera-systems` | `ast.literal_eval` or regex extraction |
| Bash script | EmuDeck `checkBIOS.sh` | Line-by-line regex parsing |
| C# source | BizHawk `FirmwareDatabase.cs` | Regex for method calls and string literals |
| C source | MAME/FBNeo drivers | Use `mame_parser` or `fbneo_parser` (see below) |
| JSON (GitHub API) | RetroDECK component manifests | `json.loads()` per manifest file |
| JSON in ZIP | MiSTer `bios_db.json.zip` | `zipfile` then `json.loads()` |
| Logiqx XML | Redump, No-Intro, TOSEC DATs | Use `logiqx_parser` (see below) |

### System ID mapping

Every scraper maintains a `SLUG_MAP` (or equivalent) that translates the platform's
native system identifiers to retrobios system IDs. The retrobios system ID format
is `manufacturer-console` in lowercase with hyphens (e.g. `sony-playstation`,
`sega-mega-drive`, `nintendo-gba`).

When a native slug has no mapping, print a warning to stderr. This surfaces new
systems added upstream that need to be mapped.

System ID consistency matters for cross-platform operations. The same console must use the same ID across all scrapers and platforms. Before inventing a new ID, check existing profiles and platform YAMLs for precedent. The canonical format is `manufacturer-console` in lowercase with hyphens (e.g., `sony-playstation`, `sega-mega-drive`). The `SYSTEM_ALIASES` dict in `common.py` maps common variations to canonical IDs.

### Hash normalization

- Normalize all hashes to lowercase hex strings.
- Handle missing hashes gracefully (set to `None`, not empty string).
- Some platforms provide multiple hash types per entry. Populate whichever fields
  are available.
- An MD5 shorter than 32 characters is completed when exactly one MD5 in
  `database.json` starts with it, as the Batocera scraper does
  (`_resolve_truncated_md5`, through `cut_md5_owner`), and kept as written
  otherwise. A value kept short verifies nothing.

Scraped data reflects what the upstream declares, which can differ from what the emulator source reads. The scraper's job is faithful transcription of upstream data, not correction. Corrections happen in the emulator profiles (source-verified) and in `_shared.yml` (curated). If a scraper meets a hash or filename that differs from the emulator source, log a warning and still include the upstream value. The divergence will surface during truth diffing.

A few rules keep that transcription honest:

- An entry the upstream file does not carry is marked: `shared_group`,
  `mirror_of` or `curated`. Unmarked, it would be counted and exported as
  something the platform declares.
- A scraper that reads nothing raises. An empty input (a refused API call, a
  moved file) must not rewrite a platform or target file as empty.
- Names that YAML would turn into numbers or dates are written quoted, so the
  next scrape produces the same file.

## Creating a target scraper

Target scrapers determine which emulator cores are available on each hardware
target. They live in `scripts/scraper/targets/` and follow the same auto-discovery
pattern (`*_targets_scraper.py`).

### BaseTargetScraper ABC

```
BaseTargetScraper
  __init__(url: str)
  fetch_targets() -> dict    # abstract: return target data
  pinned_revision(platform)  # the upstream revision platforms/<platform>.yml was read at
  write_output(data, path)   # write YAML to disk
```

### Output format

`fetch_targets()` must return a dict with this structure:

```python
{
    "platform": "myplatform",
    "source": "https://...",
    "scraped_at": "2026-03-30T12:00:00Z",
    "targets": {
        "x86_64": {
            "architecture": "x86_64",
            "cores": ["beetle_psx", "dolphin", "snes9x"],
        },
        "rpi4": {
            "architecture": "aarch64",
            "cores": ["pcsx_rearmed", "mgba"],
        },
    },
}
```

The `targets` dict maps target names to their available cores. Core names must
match the names used in emulator profile `cores:` fields for the target filtering
pipeline to work correctly.

### Overrides

`platforms/targets/_overrides.yml` provides post-scrape adjustments:

- **aliases**: other names a target answers to (Batocera's `bcm2711` is also `rpi4`)
- **add_cores**: cores present on a target but not detected by the scraper
- **remove_cores**: names the scraper reads as cores that emulate nothing
- **_default**: an entry applied to every target of the platform

`apply_target_overrides()` in `common.py` applies them, read by
`load_target_config()` and by the target manifests. The scraper itself does not
handle overrides.

### Module contract

```python
from scripts.scraper.targets import BaseTargetScraper

PLATFORM_NAME = "myplatform"  # the platform's registry key

class Scraper(BaseTargetScraper):
    def __init__(self):
        super().__init__(url="https://...")

    def fetch_targets(self) -> dict:
        # Fetch and parse target data
        ...
```

Register the target scraper in `_registry.yml`:

```yaml
  myplatform:
    target_scraper: myplatform_targets
    target_source: https://...
```

### Existing target scrapers

| Scraper | Source | Approach |
|---------|--------|----------|
| `retroarch_targets` | libretro buildbot nightly | Scrape directory listings for each target arch |
| `batocera_targets` | Config.in + es_systems.yml | Cross-reference kernel config with system definitions |
| `knulli_targets` | KNULLI's own Config.in + es_systems.yml | The Batocera scraper's Kconfig resolution against KNULLI's tree |
| `emudeck_targets` | EmuScripts + RetroArch cores | GitHub API for script availability per OS |
| `retropie_targets` | scriptmodules + rp_module_flags | Parse Bash scriptmodules for platform flags |
| `lakka_targets` | Lakka-LibreELEC `package.mk` and project options | Core list minus each project and device's exclusions |
| `recalbox_targets` | board defconfigs + `system.ini` | Buildroot packages each image enables, cores per system |
| `rocknix_targets` | emulators `package.mk` + device options | Cores per SoC block and 32-bit support per device |
| `amberelec_targets` | Makefile devices + metapackage `package.mk` + `es_systems.cfg` | Extra cores kept only on the devices the metapackage names |
| `emuelec_targets` | release asset names + metapackage `package.mk` + each core's install step | Packages per device, mapped to cores by the `.so` or program each installs |

## Parser modules

Shared parsers in `scripts/scraper/` handle formats used by multiple scrapers
or formats complex enough to warrant dedicated parsing logic.

### dat_parser

Parses clrmamepro DAT format as used in RetroArch's `System.dat`:

```
game (
    name "System"
    comment "Platform Name"
    rom ( name filename size 12345 crc ABCD1234 md5 ... sha1 ... )
)
```

Produces `DatRom` dataclass instances with `name`, `size`, `crc32`, `md5`, `sha1`,
and `system` fields. The `libretro_scraper` uses this parser.

### logiqx_parser

Parses Logiqx XML DATs, the format the dump-preservation catalogs publish:

```xml
<datafile>
  <header><name>Sony - PlayStation - BIOS Images</name></header>
  <game name="..."><rom name="..." size="524288" crc="..." md5="..." sha1="..."/></game>
</datafile>
```

Used by `redump_dat_scraper` (fetches the four Redump BIOS DATs directly) and
by `dat_pack_importer` (reads a locally downloaded No-Intro or TOSEC pack,
since neither can be fetched without a browser). Both write a snapshot to
`provenance/`, and they do not touch platform YAMLs.

### mame_parser

Parses MAME C source files to extract BIOS root sets. Handles:

- Machine declaration macros: `GAME`, `GAMEL`, `SYST`, `COMP`, `CONS`
- `MACHINE_IS_BIOS_ROOT` flag detection
- `ROM_START`/`ROM_END` blocks
- `ROM_LOAD` variants and `ROM_REGION` declarations
- `ROM_SYSTEM_BIOS` entries
- `NO_DUMP` filtering and `BAD_DUMP` flagging

Used by `mame_hash_scraper` to auto-fetch BIOS hashes from MAME driver sources
for each tagged MAME version.

### fbneo_parser

Parses FBNeo C source files:

- `BurnRomInfo` structs (static ROM arrays with name, size, CRC)
- `BurnDriver` structs (driver registration with `BDF_BOARDROM` flag)
- BIOS set identification via the boardrom flag

Used by `fbneo_hash_scraper` to extract BIOS ROM definitions.

### _hash_merge

Text-based YAML patching that merges fetched hash data into emulator profiles
while preserving formatting. Two strategies:

- **MAME**: updates `bios_zip` entries with `contents` lists (name, size, CRC32)
- **FBNeo**: updates individual ROM entries grouped by `archive` field

The merge preserves fields the hash data does not generate (system, note, required)
and leaves entries not present in the hash data untouched. Uses text-level YAML
manipulation rather than load-dump to maintain human-readable formatting.

## Testing

### Development workflow

1. **Start with --dry-run**. It's helpful to preview before writing output:

   ```bash
   python -m scripts.scraper.myplatform_scraper --dry-run
   ```

2. **Check JSON output** for data quality:

   ```bash
   python -m scripts.scraper.myplatform_scraper --json | python -m json.tool | head -50
   ```

3. **Compare with existing YAML** if updating a scraper. The output goes to the
   repository's `tmp/`, listed in `.gitignore`, because `/tmp` is a RAM disk on
   many systems:

   ```bash
   mkdir -p tmp
   python -m scripts.scraper.myplatform_scraper --output tmp/test.yml
   diff platforms/myplatform.yml tmp/test.yml
   ```

4. **Run verification** after generating:

   ```bash
   python scripts/verify.py --platform myplatform
   python scripts/verify.py --platform myplatform --verbose
   ```

5. **Run the full pipeline** before committing:

   ```bash
   python scripts/pipeline.py --offline
   ```

### Round-trip testing

The scrape and the export are two directions of the same transcription, so
run them against each other: scrape upstream, export it back, and diff the
result against the original file. Nothing the platform declares may
be missing from the round trip.

```bash
# Scrape upstream -> platform YAML
python -m scripts.scraper.myplatform_scraper --output platforms/myplatform.yml

# Build the truth model the export reads (refused when out of date)
python scripts/generate_truth.py --platform myplatform --output-dir dist/truth

# Rewrite the platform's own file with the changes applied
python scripts/export_native.py --platform myplatform --fetch \
    --output-dir tmp/native

# Compare with the file upstream publishes, cached by --fetch
diff .cache/upstream-native/myplatform/<original file> \
     tmp/native/myplatform/<original file>
```

Every line of that diff is a change the emulator source supports. A line that
only reshapes the original formatting means the scraper lost something the
exporter then had to invent: record it in the requirement instead, through
the fields listed in [BiosRequirement fields](adding-a-platform.md#biosrequirement-fields).

### Common issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Unmapped slug warnings | New system added upstream | Add mapping to `SLUG_MAP` |
| `upstream returned no BIOS entry` | Upstream format changed | Check `validate_format()`, update parser |
| Hash mismatch in verify | Upstream updated hashes | Re-scrape and regenerate platform YAML |
| Scraper hangs | URL unreachable, no timeout | `_fetch_raw()` has 30s timeout, check URL |
| `Response exceeds 52428800 byte limit` | Upstream file grew | Investigate, may need chunked parsing |
| `validate_format` fails | Upstream restructured | Update both `validate_format` and `fetch_requirements` |

### E2E tests

The project's test suite (`tests/test_e2e.py`) covers scraper integration at the
pipeline level. When adding a new scraper, verify that the full pipeline passes:

```bash
python -m unittest tests.test_e2e
python scripts/pipeline.py --offline
```

Both must pass before the scraper is considered complete.
