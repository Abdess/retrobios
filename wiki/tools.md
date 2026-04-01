# Tools - RetroBIOS

All tools are Python scripts in `scripts/`. Single dependency: `pyyaml`.

## Pipeline

Run everything in sequence:

```bash
python scripts/pipeline.py --offline              # DB + verify + packs + manifests + integrity + readme + site
python scripts/pipeline.py --offline --skip-packs  # DB + verify only
python scripts/pipeline.py --offline --skip-docs   # skip readme + site generation
python scripts/pipeline.py --offline --target switch  # filter by hardware target
python scripts/pipeline.py --offline --with-truth  # include truth generation + diff
python scripts/pipeline.py --offline --with-export # include native format export
python scripts/pipeline.py --check-buildbot        # check buildbot data freshness
```

Pipeline steps:

| Step | Description | Skipped by |
|------|-------------|------------|
| 1/8 | Generate database | - |
| 2/8 | Refresh data directories | `--offline` |
| 2a | Refresh MAME BIOS hashes | `--offline` |
| 2a2 | Refresh FBNeo BIOS hashes | `--offline` |
| 2b | Check buildbot staleness | only with `--check-buildbot` |
| 2c | Generate truth YAMLs | only with `--with-truth` / `--with-export` |
| 2d | Diff truth vs scraped | only with `--with-truth` / `--with-export` |
| 2e | Export native formats | only with `--with-export` |
| 3/8 | Verify all platforms | - |
| 4/8 | Generate packs | `--skip-packs` |
| 4b | Generate install manifests | `--skip-packs` |
| 4c | Generate target manifests | `--skip-packs` |
| 5/8 | Consistency check | if verify or pack skipped |
| 6/8 | Pack integrity (extract + hash) | `--skip-packs` |
| 7/8 | Generate README | `--skip-docs` |
| 8/8 | Generate site | `--skip-docs` |

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
python scripts/verify.py --platform batocera       # single platform
python scripts/verify.py --platform retroarch --verbose  # with ground truth details
python scripts/verify.py --emulator dolphin        # single emulator
python scripts/verify.py --emulator dolphin --standalone  # standalone mode only
python scripts/verify.py --system atari-lynx       # single system
python scripts/verify.py --platform retroarch --target switch  # filter by hardware
python scripts/verify.py --list-emulators          # list all emulators
python scripts/verify.py --list-systems            # list all systems
python scripts/verify.py --platform retroarch --list-targets  # list available targets
```

Verification modes per platform:

| Platform | Mode | Logic |
|----------|------|-------|
| RetroArch, Lakka, RetroPie | existence | file present = OK |
| Batocera, RetroBat | md5 | MD5 hash match |
| Recalbox | md5 | MD5 multi-hash, 3 severity levels |
| EmuDeck | md5 | MD5 whitelist per system |
| RetroDECK | md5 | MD5 per file via component manifests |
| RomM | md5 | size + any hash (MD5/SHA1/CRC32) |
| BizHawk | sha1 | SHA1 per firmware from FirmwareDatabase.cs |

### generate_pack.py

Build platform-specific BIOS ZIP packs.

```bash
# Full platform packs
python scripts/generate_pack.py --all --output-dir dist/
python scripts/generate_pack.py --platform batocera
python scripts/generate_pack.py --emulator dolphin
python scripts/generate_pack.py --system atari-lynx

# Granular options
python scripts/generate_pack.py --platform retroarch --system sony-playstation
python scripts/generate_pack.py --platform batocera --required-only
python scripts/generate_pack.py --platform retroarch --split
python scripts/generate_pack.py --platform retroarch --split --group-by manufacturer

# Hash-based lookup and custom packs
python scripts/generate_pack.py --from-md5 d8f1206299c48946e6ec5ef96d014eaa
python scripts/generate_pack.py --platform batocera --from-md5-file missing.txt
python scripts/generate_pack.py --platform retroarch --list-systems

# Hardware target filtering
python scripts/generate_pack.py --all --target x86_64
python scripts/generate_pack.py --platform retroarch --target switch

# Install manifests (consumed by install.py)
python scripts/generate_pack.py --all --manifest --output-dir install/
python scripts/generate_pack.py --manifest-targets --output-dir install/targets/
```

Packs include platform baseline files plus files required by the platform's cores.
When a file passes platform verification but fails emulator validation,
the tool searches for a variant that satisfies both.
If none exists, the platform version is kept and the discrepancy is reported.

**Granular options:**

- `--system` with `--platform`: filter to specific systems within a platform pack
- `--required-only`: exclude optional files, keep only required
- `--split`: generate one ZIP per system instead of one big pack
- `--split --group-by manufacturer`: group split packs by manufacturer (Sony, Nintendo, Sega...)
- `--from-md5`: look up a hash in the database, or build a custom pack with `--platform`/`--emulator`
- `--from-md5-file`: same, reading hashes from a file (one per line, comments with #)
- `--target`: filter by hardware target (e.g. `switch`, `rpi4`, `x86_64`)

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

Export truth data to native platform formats (System.dat, es_bios.xml, checkBIOS.sh, etc.).

```bash
python scripts/export_native.py --platform batocera
python scripts/export_native.py --all --output-dir dist/upstream/
```

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
```

### Other tools

| Script | Purpose |
|--------|---------|
| `common.py` | Shared library: hash computation, file resolution, platform config loading, emulator profiles, target filtering |
| `dedup.py` | Deduplicate `bios/`, move duplicates to `.variants/`. RPG Maker and ScummVM excluded (NODEDUP) |
| `validate_pr.py` | Validate BIOS files in pull requests, post markdown report |
| `auto_fetch.py` | Fetch missing BIOS files from known sources (4-step pipeline) |
| `list_platforms.py` | List active platforms (used by CI) |
| `download.py` | Download packs from GitHub releases (Python, multi-threaded) |
| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |
| `generate_site.py` | Generate all MkDocs site pages (this documentation) |
| `deterministic_zip.py` | Rebuild MAME BIOS ZIPs deterministically (same ROMs = same hash) |
| `crypto_verify.py` | 3DS RSA signature and AES crypto verification |
| `sect233r1.py` | Pure Python ECDSA verification on sect233r1 curve (3DS OTP cert) |
| `check_buildbot_system.py` | Detect stale data directories by comparing with buildbot |
| `migrate.py` | Migrate flat bios structure to Manufacturer/Console/ hierarchy |

## Installation tools

Cross-platform BIOS installer for end users:

```bash
# Python installer (auto-detects platform)
python install.py

# Shell one-liner (Linux/macOS)
bash scripts/download.sh retroarch ~/RetroArch/system/
bash scripts/download.sh --list

# Or via install.sh wrapper (detects curl/wget, runs install.py)
bash install.sh
```

`install.py` auto-detects the user's platform by checking config files,
downloads the matching BIOS pack from GitHub releases with SHA1 verification,
and extracts files to the correct directory. `install.ps1` provides
equivalent functionality for Windows/PowerShell.

## Large files

Files over 50 MB are stored as assets on the `large-files` GitHub release.
They are listed in `.gitignore` to keep the git repository lightweight.
`generate_db.py` downloads them from the release when rebuilding the database,
using `fetch_large_file()` from `common.py`. The same function is used by
`generate_pack.py` when a file has a hash mismatch with the local variant.

## Scrapers

Located in `scripts/scraper/`. Each inherits `BaseScraper` and implements `fetch_requirements()`.

| Scraper | Source | Format |
|---------|--------|--------|
| `libretro_scraper` | System.dat + core-info .info files | clrmamepro DAT |
| `batocera_scraper` | batocera-systems script | Python dict |
| `recalbox_scraper` | es_bios.xml | XML |
| `retrobat_scraper` | batocera-systems.json | JSON |
| `emudeck_scraper` | checkBIOS.sh | Bash + CSV |
| `retrodeck_scraper` | component manifests | JSON per component |
| `romm_scraper` | known_bios_files.json | JSON |
| `coreinfo_scraper` | .info files from libretro-core-info | INI-like |
| `bizhawk_scraper` | FirmwareDatabase.cs | C# source |
| `mame_hash_scraper` | mamedev/mame source tree | C source (sparse clone) |
| `fbneo_hash_scraper` | FBNeo source tree | C source (sparse clone) |

Internal modules: `base_scraper.py` (abstract base with `_fetch_raw()` caching
and shared CLI), `dat_parser.py` (clrmamepro DAT format parser),
`mame_parser.py` (MAME C source BIOS root set parser),
`fbneo_parser.py` (FBNeo C source BIOS set parser),
`_hash_merge.py` (text-based YAML patching that preserves formatting).

Adding a scraper: inherit `BaseScraper`, implement `fetch_requirements()`,
call `scraper_cli(YourScraper)` in `__main__`.

## Target scrapers

Located in `scripts/scraper/targets/`. Each inherits `BaseTargetScraper` and implements `fetch_targets()`.

| Scraper | Source | Targets |
|---------|--------|---------|
| `retroarch_targets_scraper` | libretro buildbot nightly | 20+ architectures |
| `batocera_targets_scraper` | Config.in + es_systems.yml | 35+ boards |
| `emudeck_targets_scraper` | EmuScripts GitHub API | steamos, windows |
| `retropie_targets_scraper` | scriptmodules + rp_module_flags | 7 platforms |

```bash
python -m scripts.scraper.targets.retroarch_targets_scraper --dry-run
python -m scripts.scraper.targets.batocera_targets_scraper --dry-run
```

## Exporters

Located in `scripts/exporter/`. Each inherits `BaseExporter` and implements `export()`.

| Exporter | Output format |
|----------|--------------|
| `systemdat_exporter` | clrmamepro DAT (RetroArch System.dat) |
| `batocera_exporter` | Python dict (batocera-systems) |
| `recalbox_exporter` | XML (es_bios.xml) |
| `retrobat_exporter` | JSON (batocera-systems.json) |
| `emudeck_exporter` | Bash script (checkBIOS.sh) |
| `retrodeck_exporter` | JSON (component_manifest.json) |
| `romm_exporter` | JSON (known_bios_files.json) |
| `lakka_exporter` | clrmamepro DAT (delegates to systemdat) |
| `retropie_exporter` | clrmamepro DAT (delegates to systemdat) |
