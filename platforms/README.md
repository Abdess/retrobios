# Platform Configs

How platform YAML files work and where subdirectory requirements come from.

## Files

- `_registry.yml` -- platform metadata (name, status, display order)
- `_shared.yml` -- shared file groups with canonical destinations
- `<platform>.yml` -- per-platform BIOS declarations
- Inheritance: `lakka.yml` inherits `retroarch`, `retropie.yml` inherits `retroarch`

## Shared groups (`_shared.yml`)

The subdirectory a BIOS goes into is determined by the **libretro core**, not
the platform. NP2kai expects `np2kai/BIOS.ROM` whether you're on RetroArch,
Batocera, or Recalbox. Only `base_destination` varies (`system/` vs `bios/`).

Shared groups define files with correct destinations **once**. Platforms
reference them via `includes: [group_name]` in their system definitions.
`load_platform_config()` in `common.py` resolves includes at load time,
deduplicating by filename.

When to use shared groups: whenever 2+ platforms share files that a core
expects in a specific subdirectory. The group carries the correct destination
so platforms can't drift.

For RetroArch specifically, `libretro_scraper.py` injects `includes:`
references and applies subdirectory prefixes via `CORE_SUBDIR_MAP` during
generation. Manual edits to `retroarch.yml` will be overwritten on next scrape.

## Data directories (`_data_dirs.yml`)

Some cores need entire directory trees, not just individual BIOS files.
Dolphin needs `dolphin-emu/Sys/` (GameSettings, DSP firmware, fonts),
PPSSPP needs `PPSSPP/` (font assets, shaders), blueMSX needs `Databases/`
and `Machines/` (machine configs).

These are defined in `_data_dirs.yml` as a central registry with upstream
source URLs. The pack generator auto-refreshes from upstream before building
(use `--offline` to skip). Data directories live in `data/` (not `bios/`)
and are NOT indexed in `database.json`.

Adding a data directory:
1. Add entry to `_data_dirs.yml` with source URL, extraction path, cache location
2. Reference via `data_directories: [{ref: key, destination: path}]` in platform systems
3. For scraper-generated platforms, add to `SYSTEM_DATA_DIRS` in the scraper
4. Run `python scripts/refresh_data_dirs.py --key <name>` to populate the cache

## Subdirectory reference

Each entry documents where the requirement comes from. Check these source
files to verify or update the paths.

| Core | Subdirectory | Source |
|------|-------------|--------|
| NP2kai | `np2kai/` | `libretro-np2kai/sdl/libretro.c` |
| PX68k | `keropi/` | `px68k/libretro/libretro.c` |
| QUASI88 | `quasi88/` | `quasi88/src/libretro.c` |
| Kronos | `kronos/` | `libretro-kronos/libretro/libretro.c` |
| ep128emu | `ep128emu/rom/` | `ep128emu-core/src/libretro.cpp` |
| Flycast | `dc/` | `flycast/shell/libretro/libretro.cpp` |
| FBNeo NeoCD | `neocd/` | `fbneo/src/burn/drv/neogeo/neo_run.cpp` |
| Fuse | `fuse/` | `fuse-libretro/fuse/settings.c` |
| hatari | `hatari/tos/` | `hatari/src/tos.c` |

Full libretro docs: `https://docs.libretro.com/library/<core>/`

## Adding a platform

1. Create `platforms/<name>.yml`
2. Set `base_destination` (`system` or `bios`), `verification_mode`, `hash_type`
3. Use `includes: [group]` for systems with subdirectory requirements
4. Use `inherits: retroarch` to share RetroArch's file set
5. Add platform-specific overrides in `overrides.systems`
6. Test: `python scripts/verify.py --platform <name>`

## Adding a shared group

1. Add the group to `_shared.yml` with a source ref comment
2. Include: filename, destination with subdirectory prefix, required flag, hashes
3. Reference via `includes: [group_name]` in platform system definitions
4. For scraper-generated platforms, add the mapping in the scraper's
   `SYSTEM_SHARED_GROUPS` dict so it persists across regeneration

## Verification modes

| Platform | Mode | Native logic | Upstream source |
|----------|------|-------------|----------------|
| RetroArch | existence | `path_is_valid()` -- file exists | `core_info.c` |
| Lakka | existence | inherits RetroArch | idem |
| RetroPie | existence | inherits RetroArch | idem |
| Batocera | md5 | `md5sum()` + `checkInsideZip()` | `batocera-systems` |
| RetroBat | md5 | MD5 check via JSON config | `batocera-systems.json` |
| EmuDeck | md5 | MD5 whitelist per system | `checkBIOS.sh` |
| Recalbox | md5 | multi-hash comma-separated | `es_bios.xml` + `Bios.cpp` |
| RomM | md5 | MD5 | `known_bios_files.json` |
