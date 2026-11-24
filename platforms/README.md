# Platform configs

What each file of this folder holds. How a platform checks its files is in
[How each platform checks files](../wiki/verification-modes.md), and the
steps to add one are in [Adding a platform](../wiki/adding-a-platform.md).

## Files

- `<platform>.yml`: the platform's own BIOS list, written by its scraper
  (`scripts/scraper/<platform>_scraper.py`). A hand edit is overwritten by the
  next scrape: the fix goes in the scraper, `_shared.yml` or a profile.
  `lakka.yml` and `retropie.yml` inherit `retroarch`, `romm.yml` inherits
  `emulatorjs`.
- `_registry.yml`: platform metadata (name, scraper, release pack, install
  detection, display order).
- `_shared.yml`: file groups several platforms include, with the destination
  the core expects.
- `_data_dirs.yml`: whole directory trees a core needs.
- `_guides.yml`: the guide text of each platform's page on the site.
- `_core_info.json`: the git blob of every libretro `.info` as last reviewed,
  written by `check_freshness.py --record-coreinfo`.
- `targets/`: the cores each hardware target runs, one file per platform.
- `romfolders/`: the rom folders of each setup.

## Shared groups (`_shared.yml`)

The subdirectory a BIOS goes into is set by the core, not the platform.
NP2kai expects `np2kai/BIOS.ROM` on RetroArch, Batocera and Recalbox alike.
Only `base_destination` varies (`system/` or `bios/`).

A group declares those files and their destination once, and platforms
include it with `includes: [group_name]` in a system. `load_platform_config()`
(`scripts/model/platforms.py`) resolves the includes at load time. A scraper
that writes a platform keeps its includes in its own `SYSTEM_SHARED_GROUPS`,
so they survive the next scrape. `libretro_scraper.py` also prefixes the
subdirectory of the cores in `CORE_SUBDIR_MAP`.

Adding a group:

1. Add it to `_shared.yml` with a comment citing the code that reads the path.
2. Give each file its name, destination with the subdirectory, `required` and
   hashes.
3. Reference it with `includes: [group_name]`, in the scraper's
   `SYSTEM_SHARED_GROUPS` for a scraped platform.

Where the subdirectories come from:

| Core | Subdirectory | Source |
|------|-------------|--------|
| NP2kai | `np2kai/` | `libretro-np2kai/sdl/libretro.c` |
| PX68k | `keropi/` | `px68k/libretro/libretro.c` |
| QUASI88 | `quasi88/` | `quasi88/src/libretro.c` |
| Kronos | `kronos/` | `libretro-kronos/libretro/libretro.c` |
| ep128emu | `ep128emu/roms/` | `ep128emu-core/src/libretro.cpp` |
| Flycast | `dc/` | `flycast/shell/libretro/libretro.cpp` |
| FBNeo NeoCD | `neocd/` | `fbneo/src/burn/drv/neogeo/neo_run.cpp` |
| Fuse | `fuse/` | `fuse-libretro/fuse/settings.c` |
| hatari | `hatari/tos/` | `hatari/src/tos.c` |

## Data directories (`_data_dirs.yml`)

Some cores need a whole tree: Dolphin's `dolphin-emu/Sys/`, PPSSPP's assets,
blueMSX's `Databases/` and `Machines/`. Each entry names its upstream source.
`scripts/refresh_data_dirs.py` fetches them into `data/`, which is not indexed
in `database.json`, and pack generation refreshes them first unless
`--offline` is given.

Adding a data directory:

1. Add the entry with its source URL, extraction path and cache location.
2. Reference it with `data_directories: [{ref: key, destination: path}]` in a
   platform system, in the scraper's `SYSTEM_DATA_DIRS` for a scraped platform.
3. Run `python scripts/refresh_data_dirs.py --key <name>` to fill the cache.

## Targets (`targets/`)

`<platform>.yml` lists the cores of each hardware target, written by the
platform's target scraper (`scripts/scraper/targets/`), or kept by hand for a
single-target platform. `_overrides.yml` is never overwritten: it adds
aliases and adds or removes cores per target, `_default` for every target.

## Rom folders (`romfolders/`)

`_sources/<setup>.yml` names the repositories and commits to read and the
facts a parser cannot read from a table. `python -m scripts.scraper.romfolders`
writes `<setup>.yml` from them, with the folder names the OS itself uses.
