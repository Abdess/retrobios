# Tools - RetroBIOS

All tools are Python scripts in `scripts/`. Single dependency: `pyyaml`.

## Pipeline

Run everything in sequence:

```bash
python scripts/pipeline.py --offline          # DB + verify + packs + readme + site
python scripts/pipeline.py --offline --skip-packs  # DB + verify only
python scripts/pipeline.py --skip-docs        # skip readme + site generation
```

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
python scripts/verify.py --all                # all platforms
python scripts/verify.py --platform batocera  # single platform
python scripts/verify.py --emulator dolphin   # single emulator
python scripts/verify.py --system atari-lynx  # single system
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

### generate_pack.py

Build platform-specific BIOS ZIP packs.

```bash
python scripts/generate_pack.py --all --output-dir dist/
python scripts/generate_pack.py --platform batocera
python scripts/generate_pack.py --emulator dolphin
python scripts/generate_pack.py --system atari-lynx
```

Packs include platform baseline files plus files required by the platform's cores.
When a file passes platform verification but fails emulator validation,
the tool searches for a variant that satisfies both.
If none exists, the platform version is kept and the discrepancy is reported.

### cross_reference.py

Compare emulator profiles against platform configs.
Reports files that cores need but platforms don't declare.

```bash
python scripts/cross_reference.py                    # all
python scripts/cross_reference.py --emulator dolphin # single
```

### refresh_data_dirs.py

Fetch data directories (Dolphin Sys, PPSSPP assets, blueMSX databases)
from upstream repositories into `data/`.

```bash
python scripts/refresh_data_dirs.py
python scripts/refresh_data_dirs.py --key dolphin-sys --force
```

### Other tools

| Script | Purpose |
|--------|---------|
| `dedup.py` | Deduplicate `bios/`, move duplicates to `.variants/`. RPG Maker and ScummVM excluded (NODEDUP) |
| `validate_pr.py` | Validate BIOS files in pull requests |
| `auto_fetch.py` | Fetch missing BIOS files from known sources |
| `list_platforms.py` | List active platforms (used by CI) |
| `download.py` | Download packs from GitHub releases |
| `common.py` | Shared library: hash computation, file resolution, platform config loading, emulator profiles |
| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |
| `generate_site.py` | Generate all MkDocs site pages (this documentation) |
| `deterministic_zip.py` | Rebuild MAME BIOS ZIPs deterministically (same ROMs = same hash) |
| `crypto_verify.py` | 3DS RSA signature and AES crypto verification |
| `sect233r1.py` | Pure Python ECDSA verification on sect233r1 curve (3DS OTP cert) |
| `batch_profile.py` | Batch profiling automation for libretro cores |
| `migrate.py` | Migrate flat bios structure to Manufacturer/Console/ hierarchy |

## Large files

Files over 50 MB are stored as assets on the `large-files` GitHub release.
They are listed in `.gitignore` so they don't bloat the git repository.
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
| `coreinfo_scraper` | .info files from libretro-core-info | INI-like |

Internal modules: `base_scraper.py` (abstract base with `_fetch_raw()` caching
and shared CLI), `dat_parser.py` (clrmamepro DAT format parser).

Adding a scraper: inherit `BaseScraper`, implement `fetch_requirements()`,
call `scraper_cli(YourScraper)` in `__main__`.

