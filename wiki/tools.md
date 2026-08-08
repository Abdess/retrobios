# Tools - RetroBIOS

All tools are Python scripts in `scripts/`. Single dependency: `pyyaml`.

## Pipeline

Run everything in sequence:

```bash
python scripts/pipeline.py --offline              # DB + verify + packs + manifests + integrity + readme + site
python scripts/pipeline.py --offline --skip-packs  # DB + verify + readme + site
python scripts/pipeline.py --offline --skip-docs   # skip readme + site generation
python scripts/pipeline.py --offline --target switch  # filter by hardware target
python scripts/pipeline.py --offline --with-truth  # include truth generation + diff
python scripts/pipeline.py --offline --with-export # include native format export
python scripts/pipeline.py --offline --include-archived  # include archived platforms
python scripts/pipeline.py --check-buildbot        # online run + buildbot freshness check
```

Pipeline steps:

| Step | Description | Skipped by |
|------|-------------|------------|
| 1/8 | Generate database | - |
| 1b | Dump-catalog coverage report | - (offline, reads `provenance/`) |
| 2/8 | Refresh data directories | `--offline` |
| 2a | Refresh MAME BIOS hashes | `--offline` |
| 2a2 | Refresh FBNeo BIOS hashes | `--offline` |
| 2b | Check buildbot staleness | only with `--check-buildbot`, skipped by `--offline` |
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

Pipeline flags:

| Flag | Effect |
|------|--------|
| `--offline` | skip every step that needs the network (2, 2a, 2a2, 2b) |
| `--skip-packs` | skip steps 4, 4b, 4c, 6 and the consistency check |
| `--skip-docs` | skip steps 7 and 8 |
| `--include-archived` | include archived platforms in verify, packs, truth and export |
| `--target TARGET` | filter verify, packs and truth by hardware target |
| `--source {platform,truth,full}` | pack file source, passed through to `generate_pack.py` |
| `--all-variants` | build the 6 source x required combinations |
| `--check-buildbot` | run step 2b; additive, and ignored under `--offline` |
| `--with-truth` | run steps 2c and 2d |
| `--with-export` | run steps 2c, 2d and 2e |
| `--output-dir DIR` | pack output directory (default `dist/`) |

`--check-buildbot` runs the whole pipeline online. For the freshness check
alone, run `python scripts/check_buildbot_system.py`.

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
| Batocera, RetroBat | md5 | MD5 hash match, plus `checkInsideZip` for `zippedFile` entries |
| Recalbox | md5 | MD5 multi-hash, `md5_composite` for ZIPs, 3 severity levels |
| EmuDeck | md5 | MD5 whitelist per system |
| RetroDECK | md5 | MD5 per file via component manifests |
| RomM | md5 | size + any hash (MD5/SHA1/CRC32), no ZIP inspection |
| ROCKNIX | md5 | MD5 hash match, same shape as Batocera |
| MiSTer FPGA | md5 | MD5 of the file at its destination, no ZIP inspection |
| BizHawk | sha1 | SHA1 per firmware from `FirmwareDatabase.cs` |

Full details and severity mapping: [verification modes](verification-modes.md).

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

# Source variants
python scripts/generate_pack.py --platform retroarch --source platform  # YAML baseline only
python scripts/generate_pack.py --platform retroarch --source truth     # emulator profiles only
python scripts/generate_pack.py --platform retroarch --source full      # both (default)
python scripts/generate_pack.py --all --all-variants --output-dir dist/ # all 6 combinations
python scripts/generate_pack.py --all --all-variants --verify-packs --output-dir dist/

# Listing and integrity
python scripts/generate_pack.py --list                # list available platforms
python scripts/generate_pack.py --list-emulators
python scripts/generate_pack.py --list-systems
python scripts/generate_pack.py --platform retroarch --list-targets
python scripts/generate_pack.py --all --verify-packs --output-dir dist/  # extract + hash

# Data refresh
python scripts/generate_pack.py --all --refresh-data  # force re-download data dirs
python scripts/generate_pack.py --all --offline       # skip the refresh entirely

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
- `--source {platform,truth,full}`: select file source (platform YAML only, emulator profiles only, or both)
- `--all-variants`: generate all 6 combinations of source x required_only
- `--refresh-data`: force re-download all data directories before packing

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

MAME and FBNeo entries are `.zip` ROM sets: their meaningful hashes belong
to the files inside the archive, so the exported DAT lists those entries
without a container sha1. Anyone submitting the DAT upstream should mention
this.

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

Per part of a ref: `ANCHORED` (same content, same lines), `SHIFTED` (same
content, moved), `RENAMED` (the source file moved), `CHANGED` (content
edited), `AMBIGUOUS` (several equally good candidates), `GONE` (nothing
left to anchor to), `EXTERNAL` (the ref names a project the profile does
not declare, so no revision can confirm it). An entry carries the worst
status of its parts. Only `CHANGED`, `GONE` and `AMBIGUOUS` count as
needing a re-read.

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
release. `--detect-new-files` lists filename literals at HEAD the profile
does not declare. `--watch-hashes` lists hash literals added upstream that
match no entry. `--tree-diff` shows added, removed and renamed files in the
directories the refs point at.

Writes are explicit and mechanical only. `--backfill-commits` fills a
missing `source_commit`, `--rebase-refs` recales `SHIFTED` and `RENAMED`
line ranges, `--bump-commit` advances `source_commit` to HEAD only when
nothing needs a re-read. All three refuse to run on a dirty `emulators/`
without `--force`, and every write is verified by reparsing the document.

Uses `GITHUB_TOKEN` when set, which `--all` requires. Responses are cached
under `.cache/upstream/`, addressed by commit sha, so `--offline` replays a
previous run. GitHub, GitLab and Forgejo upstreams; other hosts are
reported as skipped.

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

### Other tools

| Script | Purpose |
|--------|---------|
| `common.py` | Shared library: hash computation, file resolution, platform config loading, emulator profiles, target filtering |
| `dedup.py` | Deduplicate `bios/` (`--dry-run`, `--bios-dir`), move duplicates to `.variants/`. RPG Maker and ScummVM excluded (NODEDUP) |
| `validate_pr.py` | Validate BIOS files in pull requests, post markdown report |
| `auto_fetch.py` | Fetch missing BIOS files from known sources (4-step pipeline) |
| `list_platforms.py` | List active platforms (`--all` includes archived, used by CI) |
| `download.py` | Download packs from GitHub releases (Python, multi-threaded) |
| `download.sh` | Same, as a shell one-liner (`curl` + `unzip`) |
| `provenance_report.py` | Dump-catalog coverage and acquisition targets (see above) |
| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |
| `generate_site.py` | Generate all MkDocs site pages (this documentation) |
| `deterministic_zip.py` | Rebuild MAME BIOS ZIPs deterministically (same ROMs = same hash) |
| `torrentzip.py` | Build TorrentZip archives for MAME/FBNeo ROM sets (archive bytes depend only on contents) |
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
| `rocknix_scraper` | rocknix-systems script | Python dict |
| `misterfpga_scraper` | BiosDB_MiSTer bios_db.json.zip | JSON in ZIP |
| `coreinfo_scraper` | .info files from libretro-core-info | INI-like |
| `bizhawk_scraper` | FirmwareDatabase.cs | C# source |
| `mame_hash_scraper` | mamedev/mame source tree | C source (sparse clone) |
| `fbneo_hash_scraper` | FBNeo source tree | C source (sparse clone) |

Internal modules: `base_scraper.py` (abstract base with `_fetch_raw()` caching
and shared CLI), `dat_parser.py` (clrmamepro DAT format parser),
`logiqx_parser.py` (Logiqx XML DAT parser, used by the dump catalogs),
`mame_parser.py` (MAME C source BIOS root set parser),
`fbneo_parser.py` (FBNeo C source BIOS set parser),
`_hash_merge.py` (text-based YAML patching that preserves formatting).

Adding a scraper: inherit `BaseScraper`, implement `fetch_requirements()`,
call `scraper_cli(YourScraper)` in `__main__`.

## Dump-catalog provenance

Snapshots of the preservation catalogs are committed to `provenance/` and
refreshed manually. `generate_db.py` joins them into `database.json`;
`provenance_report.py` reports the gaps.

```bash
python -m scripts.scraper.redump_dat_scraper --dry-run
python -m scripts.scraper.redump_dat_scraper --output provenance/redump.json
python -m scripts.scraper.dat_pack_importer --source no-intro --pack no-intro.zip
python -m scripts.scraper.dat_pack_importer --source tosec --pack TOSEC-v2025.zip
python scripts/provenance_report.py            # coverage summary (pipeline step 1b)
python scripts/provenance_report.py --missing  # list acquisition targets
python scripts/provenance_report.py --json     # full report
```

| Catalog | Acquisition | Notes |
|---------|------------|-------|
| Redump | direct fetch from redump.info `/static/bios` | 4 BIOS DATs. redump.org serves stale DATs |
| No-Intro | local pack, imported with `dat_pack_importer` | Dat-o-Matic blocks automation; the `hugo19941994/auto-datfile-generator` mirror rebuilds daily |
| TOSEC | local pack, imported with `dat_pack_importer` | annual pack from tosecdev.org, 138 Firmware DATs |

The join is by SHA1, then by MD5 + size. A match sets the `provenance` field
on the database entry and renders a verified dump badge on the system pages.
It never overrides the emulator source code: see
[architecture](architecture.md#dump-catalog-provenance).

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

Located in `scripts/exporter/`. Each inherits `BaseExporter`, defined in
`base_exporter.py` with `export()` and `validate()`, and implements both.

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
