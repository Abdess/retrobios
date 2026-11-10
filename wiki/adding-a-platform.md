---
level: contribute
order: 20
---

# Adding a platform

Adding a platform gives its users a pack and a one-line install with the files
their setup checks, in the place it checks them, plus every file its emulators
need that its own list does not name. The work is to read how the platform
declares and checks BIOS files, then teach this project to read that
declaration. A platform can be a frontend like Batocera, a manager like EmuDeck
or a firmware database like BizHawk.

Example: RomM declares its BIOS files in
`backend/models/fixtures/known_bios_files.json` and checks size plus any one
hash (`firmware.py`, `verify_file_hashes`). Its scraper turns that JSON into
`platforms/romm.yml`, and the pack, the installer and its site page follow.

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
- `lists_files` - `True` by default, and an empty read then stops the scrape.
  A scraper whose platform lists no file of its own sets it to `False`: RetroPie
  inherits RetroArch's files and reads only its packages, and MinUI names no
  file at all.

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
| `native_id` | `str \| None` | The platform's own system id, written as `native_system` |
| `sha256` | `str \| None` | SHA256 hash if available |
| `alt_md5` | `str \| None` | A second accepted MD5 (Batocera and ROCKNIX `altmd5`) |
| `native_path` | `str \| None` | The file reference as the platform writes it, kept when it differs from `name`. libretro writes `iplromco.dat` bare although the file lives under `keropi/`, and `ep128emu/roms/cpc464.rom` with its directory |
| `mirror_of` | `str \| None` | The native system whose entry this one repeats under another system. The platform's own file does not carry the copy, so the export skips it |
| `native` | `dict` | Fields the platform declares that the model has no place for, written back unchanged by the export: `native_name`, `md5_list` (a Batocera md5 written as a list), `core`, `note`, `description`, `hash_match_mandatory`, `mandatory_declared`, `alt_paths`, `component`, `required_label`, `group` (RetroBat: files of one group are alternatives, one held is enough) |

`requirement_entry()` in `base_scraper.py` is the single serializer from a
requirement to a platform YAML entry, and every scraper goes through it.
Anything an export writes back is recorded by the scraper, never rebuilt by the
exporter: several native systems can fall onto one slug (Recalbox files
`pcengine`, `pcenginecd` and `supergrafx` under `nec-pc-engine`), and a path
or a label the YAML does not hold cannot be derived. When an export needs a
value the YAML lacks, the scraper and `schemas/platform.schema.json` gain it,
then the platform is scraped again.

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

The registry describes *where the data comes from*, and the platform YAML
holds what the upstream file declares, `verification_mode` and
`base_destination` included. A re-scrape rewrites the YAML without touching the
registry. `load_platform_config` copies every registry key the YAML does not
carry into the config that `verify.py` and `generate_pack.py` read, so a runtime
rule that no upstream file states (`zip_digest`, `firmware_folder_flat`) is
written in the registry, where the next scrape leaves it in place.

### Required fields

```yaml
platforms:
  myplatform:
    config: myplatform.yml           # platform YAML filename in platforms/
    release_pack: true               # optional: a release publishes its ZIP
    device_group: handheld           # computer, gaming-os, handheld, fpga or server
    scraper: myplatform              # matches PLATFORM_NAME, null if hand-maintained
    schedule: weekly                 # re-scrape cadence, run by hand: weekly, monthly, or null
    source_url: https://...          # upstream data URL
    source_format: json              # json, xml, clrmamepro_dat, python_dict,
                                     # bash_script+csv, csharp_firmware_database,
                                     # github_component_manifests, mister_downloader_db,
                                     # pak_launch_scripts
    hash_type: md5                   # primary hash in the upstream data
    cores:                           # which emulator profiles apply
    - core_a
    - core_b
```

`device_group` places the platform among the devices a reader picks from: on
the site's "Get the files" page, in the "Setups" navigation and on the home
page. The groups, their labels and their anchors are under `device_groups` in
`platforms/_guides.yml`, beside the platform's [guide text](#guide-text).

A platform without a scraper (`scraper: null`, `schedule: null`) keeps its YAML
as a hand-maintained file. Every registered platform has a scraper today, so
none is edited by hand: RetroPie inherits RetroArch's file set and its scraper
writes the packages it builds, read from the `rp_module_id` of each
scriptmodule, and any manual change is overwritten on the next scrape.

The `cores` field determines which emulator profiles are resolved for this
platform (`resolve_platform_cores` in `common.py`). Alias profiles are never
resolved. Three strategies exist:

- **Explicit list**: `cores: [beetle_psx, dolphin, ...]` - match by profile key name
  or by any name in a profile's `cores:`. When a profile's `built_by` names this
  platform, that profile answers for the name (ROCKNIX's `yabadabadoo`). On a
  `dual_mode_cores` name it answers for its own build mode only: Batocera's
  patched LRPS2 (`lrps2-416291a`) takes the libretro `pcsx2` and the standalone
  PCSX2 stays. Used by
  Batocera, Recalbox, RetroBat, RomM, KNULLI, AmberELEC, EmuELEC, MinUI, NextUI,
  MyMinUI, ROCKNIX, RetroPie, EmuDeck, RetroDECK. A list that names `retroarch`
  (the last three) also takes every libretro profile, as `all_libretro` does,
  plus the libretro builds whose `built_by` names this platform. A name in `installable_cores`, a buildbot core the
  platform's RetroArch downloads, designates libretro builds only. Under
  `--target` such a core counts only on the boards whose downloader offers one
  of its names (`downloadable_on`), and the install list gives those boards in
  `downloaded_cores`. An empty list
  (BizHawk, MiSTer FPGA) resolves no profile, and the pack holds the platform's own
  files.
- **all_libretro**: `cores: all_libretro` - every profile whose `type` contains
  `libretro`, except those that carry `built_by`: a build a platform compiles itself
  is absent from the buildbot and is reached only by its name (Recalbox's `mame0258`
  and `mame0278`). Used by RetroArch and Lakka.
- **Omitted**: fallback to system ID intersection, `built_by` profiles excluded.

Two lists say how each resolved emulator is laid out. `standalone_cores` names the
ones the platform launches as standalone apps: their files go to `standalone_path`
(`path` for a profile with no libretro build), under the folder the platform hands
the emulator when its `launchers:` say so. A `links` or `passes_path` record of a
directory at or below one of the profile's `standalone_directories` binds that
subfolder of the layout to a folder (`launchers.standalone_bindings`): RetroPie
links Flycast's `~/.local/share/flycast` to `BIOS/dc`, EmuDeck yuzu's `keys` to
`bios/yuzu/keys`, and ROCKNIX's patched data directory is followed through the link
its start script makes. A launch script that enters a folder hands the `getcwd`
directory: RetroPie starts UAE4All2 in `$md_inst`, whose `kickstarts` it links to
`BIOS/amiga`. A profile declaring `executable directory` is bound where a record
executes one of its files: Batocera runs `pico-8/pico8` from `bios`, ROCKNIX
`pico8_64` from `/storage/roms/pico-8`, below the `roms_directory` its registry entry
names, which the manifest writes as `root: roms`. RetroBat runs `pico8.exe` from an
emulator folder its generators name by key: the registry's `emulators_directory`
spells that key and lists the places the launcher searches, and the manifest writes
`root: emulators`, which the installer places only beside RetroBat's own launcher
config. Two records giving two folders
leave the profile's layout. Once a platform binds part of a layout, an entry no
binding covers is read in a folder outside the BIOS tree: it is never packed, and
the manifest names it (`root: emulator`, `outside_bios_folder`).
`dual_mode_cores` names those it launches both ways (RetroPie packages `lr-hatari`
and `hatari`): both layouts are packed. A profile without a standalone build keeps
its libretro layout whatever the platform calls it.

A platform that hands each libretro core a system directory of its own declares
them in `core_system_dirs`, keyed by the directory relative to the pack root,
each with the `cores` started with it and the `source_ref` of the launcher that
names them. MinUI, NextUI and MyMinUI give every launch tag `Bios/<TAG>/`
(`system_directory_ref` cites the minarch statement). A core's files are then
placed below each directory listed for it, an archive's core subfolder
(`archive_prefix`) moves with it, and a core listed nowhere gets no file: the
platform hands it no folder. `platform_layouts` builds one view per directory,
so the builder, the manifest, verify and slots read the same placement, and the
resolver still looks the collection up by the core's own path.

A launcher that hands each libretro core a save directory per system needs to
know which systems run each core. The scraper writes `libretro_systems`, each
libretro core name with the systems the platform's own list offers it for, under
the name the launcher puts in the path: Batocera and KNULLI from `es_systems.yml`
(`libretro:` entries), RetroBat from `es_systems.cfg`, Recalbox from each
`system.ini`, RetroDECK from the ROM folders of the ES-DE commands that load the
core. With `save_directory.by_system`, a file a core reads below its save
directory goes once below each of those folders, and a core no system runs is
listed as omitted (`no_save_system`).

### Guide text

`platforms/_guides.yml` holds each platform's guide: what it is, where its
BIOS folder is, where the install command runs. It is data, edited like the registry, and
no Python changes when a platform is added. The registry keeps what tools read
and `_guides.yml` keeps what people read, so neither grows unreadable.

```yaml
guides:
  knulli:
    summary: A system for handhelds, based on Batocera.
    folders:
    - where: On KNULLI                # no path: the registry's extract_to
    run: [device]                     # terminal tabs, in the order shown
    reference_notes:
    - KNULLI runs on handhelds among them the RG35XX family (H700).
    logo_owner: KNULLI
    logo_licence: GitHub organisation avatar of knulli-cfw
```

- `summary`, `folders` and `run` are required. Every value is Markdown.
- A folder row without `path` shows the registry's `extract_to`. That folder
  is written once, where the installer and the release notes read it too.
- `run` names entries of `terminals` in the same file: `windows`, `macos`,
  `linux`, `steamdeck`, `android`, `device` or `server`.
- `dest` puts `--dest` in the command, and `on_card: true` makes it the SD
  card's path.
- `more_folders` lists rare builds, shown folded under `more_folders_title`.
  `more_folders_detected: true` adds a row for each named system the
  registry's `install.detect` rules find the platform on.
- `download_hint` adds a line under the pack download.
- `pack_manual` is the manual part of the README inside the pack, in plain
  text. Without it the README names the `bios_path` of the detection rules.
- `logo_owner` and `logo_licence` credit the registry's `logo`, read by
  `scripts/fetch_site_images.py`.

The guide text is read by someone who knows their device and little else.
`summary` is one plain sentence, with no chip or board names. `notes` hold
one fact each that the reader acts on. A source citation, a list of models or
how the installer finds the folder goes in `reference_notes`, which open the
Reference part of the page. The guide part of every setup page is held to the
word budgets of [Pages for newcomers](testing-guide.md#pages-for-newcomers).

`scripts/siteguides.py` loads the file and stops the build with the key at
fault: a registered platform without a guide, a guide for no registered
platform, a misspelt key, an unknown terminal, a group the file does not
describe. `tests/test_site_content_data.py` also fails when a script holds a
table of text keyed by platform or a page branches on one platform's name:
that text belongs in a guide field.

### Optional fields

```yaml
    logo: https://...                # SVG or PNG for UI/docs
    logo_flip: true                  # a raster stored bottom row first (a boot logo)
    logo_trim: true                  # cut the plain background around the mark
    inherits_from: retroarch         # the parent, for readers: the merge reads
                                     # inherits: in the platform YAML
    case_insensitive_fs: true        # if the platform runs on case-insensitive filesystems
    extract_to: /userdata/bios/      # folder the pack extracts into, shown in the README,
                                     # the site and the release notes
    save_directory:                  # the save directory the frontend hands libretro cores,
      folder: saves                  # where it is one place: the pack folder holding the
      by_core: true                  # files cores read there (load_from: save_dir), its
                                     # default place beside the BIOS folder (a relative
                                     # path, saves/retroarch/saves on EmuDeck), and whether
                                     # the frontend appends the core's library_name.
      by_system: true                # the launcher hands <folder>/<system> at each launch
                                     # (Batocera, RetroBat): one copy per system in the
                                     # platform file's libretro_systems
      by_core_for: [dolphin]         # cores the launcher alone sorts by core (RetroBat)
      pack_folder: userdata-saves    # the pack's folder for them, where the BIOS tree
                                     # already has one named like folder (Batocera)
                                     # null when saves sit beside each game
    zip_digest: composite            # the frontend hashes a .zip by its members only
    firmware_folder_flat: true       # the frontend lists each system folder without
                                     # descending into it
    native_list: none                # the platform's code names no BIOS file, so no
                                     # exporter hands one back
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

A frontend whose BIOS live on its SD card is installed from the computer the
card is mounted on. Its rule is `os: any`, `method: card_marker`, with `file`
(a path below the card root) and `first_line_prefix`: `install.py` reads that
file under `--dest` and names the platform when its first line starts with the
prefix. MinUI, NextUI and MyMinUI write their release name to
`.system/version.txt`.

`native_list: none` marks a platform whose own code publishes no BIOS list
(the MinUI family hands each core a folder and names no file in it). The test
that every registered platform has an exporter exempts it, and a second test
holds that its platform YAML declares no file.

`zip_digest: composite` is set where the frontend's own check takes
`Zip::Md5Composite` for every `.zip` and never the container's MD5 (Recalbox,
`Bios.cpp:64-68`). Each `.zip` entry is then checked against its composite alone,
by the resolver and by the pack check, as
[verification modes](verification-modes.md#md5_composite-recalbox-zip-verification)
describes.

`firmware_folder_flat: true` is set where the frontend reads a system's firmware
folder without descending into it (RomM 5.4.1,
`backend/handler/filesystem/base_handler.py:1002`, `recursive=False`). On such a platform, a core file whose destination has a
subfolder is left out of the pack (`nested` in `scripts/packextras.py`), since no
core would receive it.

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
with `bios/` and `roms/`. Core files then go under the root most destinations
share, or under `core_destination` when the list names other folders too:
AmberELEC and EmuELEC declare `neogeo/` and `ports/` beside `bios/`, and set
`core_destination: bios`.

### Launchers

Between the file a user drops in the BIOS folder and the emulator, a
platform's own launch code often decides which name is read and where it is
handed over. Batocera's DuckStation generator tries a list of names for each
region, first found wins, and writes the hit into `settings.ini`. That behaviour belongs to
the platform, not to the emulator, so the scraper records it from the
platform's code under `launchers:`, never as an alias in an emulator profile.

```yaml
launchers:
- emulator: duckstation        # as the platform names it
  build: standalone            # standalone or libretro
  kind: names_searched
  slot: NTSCU                  # the key the code files this list under
  names: [scph101.bin, scph1001.bin, scph5501.bin, scph7001.bin, scph7501.bin]
  case_insensitive: true
  search_dir: /userdata/bios
  passes_to: "[BIOS] PathNTSCU"
  fails_when_missing: No PSX1 BIOS found
  fails_scope: emulator        # raised only when every slot found nothing
  source_ref: "package/.../duckstationGenerator.py:115-136, 501-523"
```

| Field | Meaning |
|-------|---------|
| `emulator` | Emulator or core as the platform names it |
| `build` | `standalone` or `libretro` |
| `kind` | `names_searched` (tried in order, first found wins), `fixed_name` (one path per name), `core_option` (an option value names the file), `passes_path`, `links`, `copies`, `moves` (a file left in one folder is moved to the one the launcher links from), `scans_dir`, `package` (no file: what a package builds and registers) |
| `package` | The platform package whose script the record comes from (RetroPie's `rp_module_id`) |
| `repo` | What the package fetches and builds, as the script writes it (`rp_module_repo`: method, URL, branch or commit) |
| `systems` | Systems the package registers, under the platform's names (`addSystem`, `addPort` for ports) |
| `slot` | The key the code files the list under: a region, a machine |
| `machines` | On a record naming systems, the machines the platform offers the emulator under them (RetroBat's `xroar_machine` choices for coco) |
| `names` | In the order the code tries or writes them, relative to `search_dir` |
| `expands` | Values a `{X}` placeholder in `names` takes, in the order tried (Hatari tries each TOS in ten languages) |
| `case_insensitive` | Whether the launcher matches names regardless of case |
| `search_dir` | Directory the launcher reads, as the code resolves it |
| `passes_to` | Config key, command-line flag or core option that receives the file |
| `fails_when_missing` | `false`, or the message the launcher raises |
| `fails_scope` | `emulator` when the failure needs every record of the emulator to come up empty |
| `depends_on_option` | Options or conditions that decide whether the record applies |
| `device` | Devices whose shipped config the record reads, set only where a package ships configs that differ between devices |
| `source_ref` | `path:lines` in the repository and at the revision `source` pins, which the site links |

Batocera's generators are read with `ast`, RetroBat's C# generators as text.
ROCKNIX and EmuDeck launch from shell scripts and configs shipped with each
package, so `scripts/scraper/shell_launchers.py` reads assignments, `for`
loops, `ln -s` commands and `key = value` lines. A ROCKNIX package can ship
one config per device: the configs are grouped by the value read, and
`device` appears only when there is more than one group. melonDS writes its
seven BIOS paths on every device but AMD64, where the keys are left empty:

```yaml
- emulator: melonds
  build: standalone
  kind: fixed_name
  names: []
  passes_to: melonDS.ini BIOS9Path, BIOS7Path, FirmwarePath, DSiBIOS9Path,
    DSiBIOS7Path, DSiFirmwarePath, DSiNANDPath left empty
  device: AMD64
```

An extractor that no longer recognises the shape of the code raises: an
empty list would read as a launcher that looks for nothing.

A libretro frontend that picks the system directory per core records each
choice as a `passes_path` entry with no `names`. Recalbox gives gpsp
`bios/gba` and geargrafx `bios/pcenginecd`, so a core that opens `gba_bios.bin`
reads it from there. `emulator: libretro` stands for every core Recalbox runs,
for the default directory and for the per-system overrides applied after the
per-core choice, and `<system>` in `search_dir` is the system's own name.

Shell platforms are read as text. RetroPie's scriptmodules are walked the way
RetroPie runs them, one shell for every package: local assignments, arrays,
`for` loops, brace expansion, `$md_id` and calls into another package's
functions (`dosbox-sdl2` runs `configure_dosbox`). Paths keep the variables
the scripts write, `$biosdir` being `~/RetroPie/BIOS` (`retropie_packages.sh:48-49`).
Each package also gets one `kind: package` record, and that record is what
maps a package to the profile of the build it compiles: `repo` names the
project (`minivmac` builds github.com/minivmac/minivmac, Mini vMac 37, not the
libretro port), so the mapping never rests on stripping `lr-` from a name.
DraStic reads its BIOS below the folder its generated launch script enters
(`pushd "$md_conf_root/nds/drastic"`, `drastic.sh:48`), outside `$biosdir`:
that folder is a `passes_path` record, and the scrape stops if the script no
longer enters one.
RetroDECK's records come from each component's `component_prepare.sh`,
`component_launcher.sh` and `component_functions.sh`, and from the presets
they copy, with `$bios_path` as the framework names it. In both, every line
that names the BIOS directory must match a known construct, else the scrape
stops with `LauncherPatternMissing`.

`verify.py` and the pack builder read the records through one function,
`LauncherLayer.settle()` in `scripts/launchers.py`, applied inside the
cross-reference both of them consume. A `names_searched` list is one place:
the names are tried in order and one held file fills it, so a core file the
launcher would never open once another name of the list is there is not
reported missing. A `fixed_name` or `core_option` name is a place of its own,
and so is a `links` name: ROCKNIX links `/storage/roms/bios/nds_bios_arm9.bin`
into DraStic's system folder, so that path is the one DraStic reads.
Only a record that applies without condition settles the core's own name: a
core option the user may never set, or a record tied to one system, leaves
the core's default in use elsewhere. Settled, the core's own name is neither
reported nor packed, held or not: EmuDeck passes `Complex_4627v1.03.bin` to
xemu, which then never opens `Complex_4627.bin`.
A place that no declared file and no packed core file fills receives, under
the launcher's name, a file the core accepts: the file the collection knows
under that name when the core takes its content, otherwise the copy held for
the core entry read under that name. Records that only hand over a directory
(`passes_path`, `scans_dir`, a `links` record with no names) or copy a file
the platform already names (`copies`, its `names` under the `search_dir` it
copies from, the target in `passes_to`) place nothing, and a `search_dir` the
code describes rather than names ("directory of the Chihiro BIOS found") is
skipped. `$biosdir`, `${biosPath}` and `$bios_path` are the BIOS directory as
RetroPie, EmuDeck and RetroDECK spell it, and a path from a root
(`/userdata/bios`, `$HOME/RetroPie/BIOS/dc`) is placed by the platform's
`base_destination`.

### Inheritance

If the new platform inherits from an existing one (e.g. Lakka inherits RetroArch),
add `inherits: retroarch` in the platform YAML. `load_platform_config()` reads that
field to merge the parent's systems and shared groups into the child, and the child
YAML only declares what differs. The registry's `inherits_from` names the parent
for readers and is read by no tool.

## Step 3: Generate the platform YAML

Run the scraper with `--output` to produce the initial platform configuration:

```bash
python -m scripts.scraper.myplatform_scraper --output platforms/myplatform.yml
```

If a file already exists at the output path, every top-level key the scraper
writes is replaced, and the keys it does not write are kept. A system's
`data_directories` is kept as well when the new scrape does not carry one.

The YAML is the scraper's output and is never edited by hand: the next scrape
would undo the edit, and the file would stop describing the platform. Anything
an export has to write back (the platform's own system id, path, name) is
recorded by the scraper and never reconstructed later, because several of the
platform's systems can fold into one of the collection's. A rescrape can add systems, so
read `verify.py --platform` before committing the regenerated YAML.

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
| `existence` | File must exist, no hash check | RetroArch, Lakka, RetroPie, MinUI, NextUI, MyMinUI |
| `md5` | MD5 must match the declared hash | Batocera, Recalbox, RetroBat, EmuDeck, RetroDECK, RomM, ROCKNIX, KNULLI, AmberELEC, EmuELEC, MiSTer FPGA |
| `sha1` | SHA1 must match | BizHawk |

Inheriting platforms take the parent's mode: Lakka and RetroPie do not declare
one, they get `existence` from RetroArch.

If the platform has unique verification behavior (e.g. Batocera's `checkInsideZip`,
Recalbox's multi-hash comma-separated MD5, RomM's size + any-hash), add the logic
to `verify.py` in the platform-specific verification path.

Read the platform's source code to understand its exact verification behavior before writing any logic. Batocera's `checkInsideZip` uses `casefold()` for case-insensitive matching. Recalbox supports comma-separated MD5 lists. RomM checks file size before hashing. These details matter: the project replicates native behavior, not an approximation of it.

## Step 5: Create an exporter

An exporter writes the platform's own BIOS file back, updated with what the
emulator code shows. Every registered platform has one, unless its registry
entry says `native_list: none`: `tests/test_exporters.py` fails otherwise.
Exporters live in `scripts/exporter/` and are found the same way as scrapers
(`*_exporter.py`).

### Module contract

The module exports an `Exporter` class that extends `BaseExporter`
(`scripts/exporter/base_exporter.py`):

```python
from .base_exporter import BaseExporter
from .baseline import NativeSystem, Report


class Exporter(BaseExporter):
    @staticmethod
    def platform_name() -> str:
        return "myplatform"

    @staticmethod
    def native_filename() -> str:
        return "bios_list.json"            # the name the platform gives its file

    @staticmethod
    def native_sources() -> dict[str, str]:
        return {"bios_list.json": "https://..."}  # the original it patches

    def render(self, systems: dict[str, NativeSystem], report: Report,
               originals: dict[str, str], scraped: dict | None = None) -> dict[str, str]:
        # Return {relative output path: file content}
        ...

    def validate(self, systems: dict[str, NativeSystem], produced: dict[str, str]) -> list[str]:
        # Return a list of issues (empty = valid)
        ...
```

`platform_name`, `native_filename`, `render` and `validate` are abstract. The
other methods say what the format can hold, and their defaults fit a plain list
of files:

- `carries()` - the fields the format has a place for (`md5` by default). A
  correction to a field it cannot hold is not counted as made.
- `requires()` - the hash a new entry cannot be written without.
- `can_add()` - `False` when an entry is code rather than a row of data
  (BizHawk), so nothing is added.
- `keys_by_system()` - `True` when the platform finds a file by the name of its
  own system, so an entry filed under one of the collection's system ids is never written.
- `needs_original()` - `True` as soon as `native_sources()` names a file.

Those methods say what the format could hold. The report counts what `render()`
actually wrote, through a second set, read entry by entry:

- `lands(fe)` - whether the entry is in the written file. Defaults to
  `writable()`. Override it when `render()` drops an entry the format could
  hold: RetroBat merges an addition into a path it already declares, and
  System.dat leaves out a file with no section name.
- `states(fe, field)` - whether the written entry carries the corrected field.
  Defaults to `field in carries()`.
- `fills(fe, field)` and `clears(fe, field)` - whether a hash only the truth
  names is written, and whether a hash the truth contradicts leaves the entry.
  Both default to `states()`.
- `names_anew(fe)` - whether the render wrote, for the first time, a file the
  platform already declares. Only a format whose unit is not the entry needs it
  (a RetroPie help sentence).
- `withheld()` - corrections the render proved and still did not write, named
  so the run does not read as nothing to do.

An exporter whose `render()` skips anything the defaults count must override
the matching method. Otherwise the summary announces a change the maintainer
will not find in the diff.

### Round-trip validation

The scraper and the exporter are checked against each other as
[round-trip testing](adding-a-scraper.md#round-trip-testing) describes. The
export must not lose anything the platform already declares. If the
format carries code as well as data (a script, a C# database, a manifest
whose BIOS list sits beside launch configuration), name the file in
`native_sources()` and patch it rather than writing a new one. An exporter
that regenerates such a file from BIOS data alone hands the maintainer
something that no longer runs.

## Step 6: Create a target scraper (optional)

Target scrapers determine which emulator cores are available on each hardware
target (e.g. which RetroArch cores exist for Switch, RPi4, or x86_64).
They live in `scripts/scraper/targets/` and are auto-discovered by filename
(`*_targets_scraper.py`).

### Module contract

```python
from scripts.scraper.targets import BaseTargetScraper

PLATFORM_NAME = "myplatform"  # the registry key, as the scraper module names it

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

Add `target_scraper: myplatform_targets` (the module name without `_scraper`)
and `target_source` to the platform's registry entry.

### Overrides

Hardware-specific overrides go in `platforms/targets/_overrides.yml`, which no
scraper writes. Each target can list `aliases` (Batocera's `bcm2711` also
answers to `rpi4`), `add_cores` and `remove_cores`, and `_default` applies to
every target of the platform. `apply_target_overrides()` in `common.py` applies
them, for the packs and for the published target lists alike.

### Single-target platforms

For platforms that only run on one target (e.g. RetroBat on Windows, RomM in the
browser), create a static YAML file in `platforms/targets/` instead of a scraper.
Set `target_scraper: null` in the registry.

Its target writes `cores: null`, which means every core the platform declares.
A core list written by hand there falls behind the scraped platform and drops
cores the pack ships.

## Step 7: Add install detection (optional)

The `install.detect` rules in `_registry.yml` say how `install.py` finds the
platform on the user's machine and where its BIOS folder is. The installer
runs before it fetches any manifest, so it carries the same rules in its own
tables, and `tests/test_install.py` holds the two equal.

| Method | Finds the platform when | Fields |
|--------|-------------------------|--------|
| `config_file` | a key of a config file names the folder | `config`, `parse_key`, optionally `bios_subdir` or `bios_path` |
| `path_exists` | a folder exists | `path`, optionally `bios_path` |
| `file_exists` | a file exists | `file`, `bios_path`, optionally `name`, `config`, `home` |
| `os_release` | `/etc/os-release` holds one of the `match` pairs | `match`, `name`, `bios_path`, optionally `config`, `home` |
| `file_matches` | a file's text matches `pattern` | `file`, `pattern`, `name`, `bios_path` |
| `executable` | a portable install's program is found | `file` (glob patterns), `bios_subdir` |
| `registry` | a Windows registry value names the install folder | `key`, `value`, `bios_subdir` |
| `card_marker` | a file on the SD card starts with a prefix | `file`, `first_line_prefix` |

Each rule names its `os`: `linux`, `darwin`, `windows`, or `any` for a card
read from another computer. Rules for one OS are tried in order.
`derives_from` names the system a rule's system is built on.

## Step 8: Validate the full pipeline

After all pieces are in place, run the full pipeline:

```bash
python scripts/pipeline.py --offline
```

This executes in sequence, numbered as the run prints them (`STEP_LABELS` in
`scripts/pipeline.py`):

- 0 `validate_schemas.py --source-only`, the schema check PR validation runs
- 1 `generate_db.py`, rebuild `database.json` from `bios/`
- 1b `provenance_report.py`, dump-catalog coverage from `provenance/`
- 1c `romset_recipes.py`, which version each arcade archive is
- 2 `refresh_data_dirs.py`, update data directories
- 2a `mame_hash_scraper`, MAME BIOS hashes
- 2a2 `fbneo_hash_scraper`, FBNeo BIOS hashes
- 2b `check_buildbot_system.py`, with `--check-buildbot` only
- 2b2 `check_release_assets.py`, release assets against gitignored files
- 2c `generate_truth.py`, with `--with-truth` or `--with-export`
- 2d `diff_truth.py`, truth against the scraped platforms
- 2e `export_native.py`, with `--with-export`
- 3 `verify.py --all`, verify all platforms including the new one
- 3a `identity.py --strict`, one content under two identities
- 3b `slots.py`, destinations both layers claim
- 4 `generate_pack.py --all`, build the ZIP packs
- 4b `generate_pack.py --manifest`, install manifests
- 4c `generate_pack.py --manifest-targets`, target manifests
- 4d `bundled_only.py --strict`, copies only an emulator install provides
- 4e `generate_games_index.py`, what the games-on-card mode reads under `install/games/`
- 5 Consistency check: verify and the pack agree on counts and on the paths each archive holds
- 6 Pack integrity: extract the ZIPs and check hashes per platform mode
- 7 `generate_readme.py`, regenerate README and CONTRIBUTING, then `generate_installer_doc.py` rewrites the tables and run samples of `wiki/installer.md`
- 8 `generate_site.py`, regenerate the site pages and navigation
- 8b `npm run build` in `website/`, then `validate_site.py`

`--offline` skips steps 2 to 2b2.

Every registered platform is covered by the runs that cover every platform
(`verify.py --all`, `slots.py`, `pipeline.py`, `list_platforms.py`), the
installer manifests, the site, the native export and `check_freshness.py`.
No tool scrapes a platform on its own: the `schedule:` field is the cadence
a maintainer keeps by hand.

A new platform has no release ZIP: `release_pack: true` is set for the setups
most people download, and the installer serves every other one from its
manifest. `generate_pack.py --platform myplatform` still builds its pack.
[Which platforms get a pack](release-process.md#which-platforms-get-a-pack)
says how the list is read from download counts.

Check the output for:

- The new platform appears in verify results
- No unexpected CRITICAL or WARNING entries
- Pack generation succeeds and includes the expected files
- Consistency check passes (verify file counts match pack file counts)

Verification is not optional. A platform that passes `pipeline.py` today may break tomorrow if upstream changes its data format. Run the full pipeline on every change, even if the modification seems trivial. The consistency check (verify and the pack must agree on counts and paths) catches subtle issues where files resolve during verification but fail during pack generation, or vice versa.

## Checklist

- [ ] Scraper file in `scripts/scraper/<name>_scraper.py`
- [ ] `PLATFORM_NAME` and `Scraper` class exported
- [ ] `fetch_requirements()` and `validate_format()` implemented
- [ ] System ID mapping covers all upstream systems
- [ ] Entry added to `platforms/_registry.yml`
- [ ] Guide added to `platforms/_guides.yml`
- [ ] Platform YAML generated and verified
- [ ] `python scripts/pipeline.py --offline` passes
- [ ] Exporter in `scripts/exporter/<name>_exporter.py`, unless the registry says `native_list: none`
- [ ] Target scraper in `scripts/scraper/targets/<name>_targets_scraper.py` (if applicable)
- [ ] Install detection entries in `_registry.yml` (if applicable)
