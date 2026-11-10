---
level: contribute
order: 60
---

# Architecture

How a BIOS list on a platform's site becomes a pack on a drive. Scrapers
copy each platform's own list. Emulator profiles record what each emulator's
code opens. `database.json` indexes every file the collection holds by its
contents. The pack builder joins the three and ships every file a platform's
emulators need, and the verifier checks the result the way the platform itself
would.

Example: libretro's `System.dat` names the files RetroArch checks. The cores
RetroArch runs load many more, and the RetroArch pack carries both.
[What the packs do not hold](../gaps.md) gives the current counts.

## Directory structure

```
bios/                    BIOS and firmware files, organized by Manufacturer/Console/
  Manufacturer/Console/  canonical files (one per unique content)
  .variants/             alternate versions (different hash, same purpose)
emulators/               one YAML profile per core/engine
platforms/               one YAML config per platform (scraped from upstream)
  _shared.yml            shared file groups across platforms
  _registry.yml          platform metadata (logos, scrapers, release packs, install config)
  _guides.yml            the guide text of each platform's page
  _data_dirs.yml         data directory definitions (Dolphin Sys, PPSSPP...)
  targets/               hardware target configs + _overrides.yml
provenance/              dump-catalog snapshots (redump, no-intro, tosec)
recipes/                 romset recipes read from MAME and FBNeo DATs, and
                         archives.json, the recipe of every archive held
exports/                 each platform's own file, updated, with a report of the changes
measurements/            records of real runs, one JSONL file per emulator
scripts/                 all tooling (Python and pyyaml, jsonschema for schema checks)
  scraper/               upstream scrapers (libretro, batocera, recalbox...)
  scraper/targets/       hardware target scrapers (one *_targets_scraper.py per platform)
  exporter/              native format exporters (batocera, recalbox, emudeck...)
install/                 JSON install manifests per platform
  targets/               JSON target manifests per platform (cores per architecture)
install.py               the installer, with install.sh and install.ps1 to start it
ports/                   launchers that run the installer on handhelds
automation/              jobs.yml, the unattended jobs scripts/autorun.py runs
data/                    cached data directories (not BIOS, fetched at build)
schemas/                 JSON schemas for platform and emulator YAML (checked in CI)
tests/                   test suite with synthetic fixtures
wiki/                    hand-written documentation sources
docs_assets/             logos, icons and images the site uses
website/                 Astro Starlight project; pages, data and navigation
                         are generated into it (gitignored, rebuilt in CI)
_mame_clones.json        MAME parent/clone set mappings
database.json            file index built from bios/ (SHA1 primary key)
derivable.json           files a held dump already contains, from provenance_report.py
retired.json             files that left the collection, written by generate_db.py
release.json             files, sizes and assets of each pack of the last release
allowed_signers          public key that signs SHA256SUMS.txt
dist/                    generated packs (gitignored)
.cache/                  hash cache and large file downloads (gitignored)
```

The generated pages in `website/` are never edited by hand: `generate_site.py`
rebuilds them from `platforms/`, `emulators/`, `database.json`, and the `wiki/`
sources. Documentation changes belong in `wiki/` or in the generator.

The site search splits each page at its headings and sends a result to the
heading above the match. Every file card is therefore a level 3 heading with
the card's anchor, under its console or a Files heading, and every platform
system a heading of its own: a file name typed in the search opens that card,
not the top of the page. On pages of cards (systems, emulators, platforms) the
table of contents stops at level 2, and a page of cards under one or two
headings has none (`scripts/sitestarlight.py`).

The search is Pagefind, which loads its index in pieces: the words typed pick
the chunks it fetches. The index holds names and prose only. Hashes, lists of
other pages, install commands, member tables and long reference tables carry
`data-pagefind-ignore`. A hash goes to [Find a file](../files/index.md), which
reads one shard of `api/v1/lookup/` named by the first two characters of the
value.

A page has a budget, set by constants in `scripts/generate_site.py`. A
manufacturer page over `SYSTEM_PAGE_BUDGET` becomes a summary: its largest
consoles move to pages of their own, cut into parts when one console alone is
over the budget, and every console keeps its heading on the summary. An
emulator with more than `EMULATOR_CARDS_PER_PAGE` entries (MAME) lists them in
a table on its page, each row holding the old anchor of the card, and the cards
move to pages of `EMULATOR_CARDS_PER_PART`. A platform system whose list passes
`PLATFORM_SECTION_BUDGET` moves to a page of its own. A card anchor
(`#sha1-...`) that a page no longer holds is looked up by content, so a link
cited before a split still opens the card. `validate_site.py` fails a page over
`MAX_PAGE_BYTES` of HTML or `MAX_PAGE_ELEMENTS` elements, a search index over
`MAX_PAGEFIND_TOTAL_BYTES`, a skipped heading level, a table header without
text, a script from another host and a diagram drawn at runtime.

## Data flow

```
Upstream sources          Scrapers parse       generate_db.py scans
  System.dat (libretro)   + fetch versions     bios/ on disk
  batocera-systems                             builds database.json
  es_bios.xml (recalbox)                       (SHA1 primary key,
  core-info .info files                         indexes: by_md5, by_name,
  FirmwareDatabase.cs                           by_crc32, by_sha256, by_path_suffix,
                                                by_shadowed_alias,
                                                by_proven_name)
  bios_db.json.zip (MiSTer)
  MAME/FBNeo source

provenance/*.json        generate_db.py joins  database.json entries carry
  redump, no-intro,       by SHA1, then by      a provenance field naming
  tosec snapshots         MD5 + size            the catalogs that list them

emulators/*.yml          verify.py checks      generate_pack.py resolves
  source-verified         platform-native       files by hash, builds ZIP
  from code               verification          packs per platform

truth.py generates       diff_truth.py         export_native.py
  ground truth from       compares truth vs     rewrites each platform's
  emulator profiles       scraped platform      own file, updated
```

`pipeline.py` runs every step in order, from the schema check to the rendered
site. [Adding a platform](adding-a-platform.md#step-8-validate-the-full-pipeline)
lists the steps, and [tools](tools.md) the options.

<!-- image: pipeline -->

## Principles

Every part of the toolchain follows from a few rules.

- **The emulator's source code is the authority.** A profile records what the
  code opens, under which names, what it checks and whether it runs without
  the file. Documentation, `.info` files and platform lists are starting
  points to verify. When they disagree with the code, the code wins.
- **Every statement rests on a fact anyone can check.** A field, a deletion or
  a wording names what settles it: a `file:line` at a pinned revision, a hash,
  a command and its output. Where no fact settles a question, the answer is
  "not verified" until one is found.
- **The collection serves the user.** A pack carries what the user has to
  obtain to run their emulators. When something forces the user or a
  contributor to work around the toolchain, the toolchain is changed rather
  than the workaround documented.
- **Profiles document the emulator, not this repository.** A profile can be
  taken into another project as is. No field refers to this repository's
  folders, file names or database, nor to one platform's conventions. The
  toolchain resolves a profile against the collection.
- **Other projects are peers.** A finding about another project says what
  changes, never who erred, and comes with its evidence. The data here can be
  wrong too, and an issue that shows it is as welcome as a finding sent
  upstream.
- **An inconsistency found is fixed now.** A fix comes with a test that fails
  without it, so the same mistake cannot return unnoticed.
- **Collect everything a working setup needs.** BIOS, firmware, keys, fonts,
  boot and DSP ROMs, databases, data files. Age and licence are not criteria.
  A file the collection lacks is an acquisition target, not an end state.

## Three layers of data

| Layer | Source | Role |
|-------|--------|------|
| Platform YAML | Scraped from upstream | What the platform declares it needs |
| `_shared.yml` | Curated | Shared files across platforms, reflects actual behavior |
| Emulator profiles | Source-verified | What the code actually loads. Used for cross-reference and gap detection |

The pack combines platform baseline (layer 1) with core requirements (layer 3).
Neither too much (no files from unused cores) nor too few (no missing files for active cores).
A same-named local file that contradicts a declared hash is settled by the
platform's verification mode ([discrepancy detection](verification-modes.md#discrepancy-detection)).

The emulator's source code serves as ground truth for what files are needed,
what names they use, and what validation the emulator performs. Platform YAML
configs are scraped from upstream and record what each platform declares. A
list kept by hand can lag behind an emulator release. The emulator profiles complement the
platform data by documenting what the code actually loads. Files the code needs
are included even if the platform does not declare them. Files the platform
declares but no profile references are kept as well (flagged during
cross-reference), since the upstream may cover cases not yet profiled.

### When both layers claim one destination

A platform and an emulator profile can each name a different file for the same
place in the BIOS folder: RetroBat puts its own `ATARIOSB.ROM` at
`bios/ATARIOSB.ROM`, where atari800 reads another dump. A claim counts only when
it rests on content or on the path. A file found by its name alone claims
nothing, unless its copy has the exact size the profile declares and the
platform's file has another size (`size_exact`): RetroDECK's `sgb2.boot.rom` is
the Super Game Boy 2 SNES program ROM where supersnes9x reads a 256-byte boot ROM.
Two files of equal size are revisions, not a conflict. The pack then answers to
whoever asked for it:

- A **platform pack** must leave the frontend's own check green, since a user
  reading red concludes the pack is broken. Where the frontend only looks for
  the name (`existence`), the emulator's file satisfies both, and the pack takes
  it. Where the frontend checks an MD5 or SHA1, one path cannot hold both
  answers: the platform's file stays, and the loss is reported. Only the
  platform's own list can change what its frontend accepts there.
- A pack built with `--emulator` answers to that emulator, and takes its file.

`scripts/slots.py` prints each contested destination and the reason for its
winner (`python scripts/slots.py --platform retrobat`), as `slots.arbitrate()`
decides it. `generate_pack.py`, the install manifest and `verify.py` all read
`slots.slot_choices()` through `slots.pack_overrides()`, which applies the same
order, so the pack, the installer and the report agree.

A platform YAML is regenerated by its scraper and never edited by hand: an
edit would be lost at the next scrape, and the file would stop describing the
platform. Where the emulator source states something else, the profile and
`_shared.yml` carry it.
Another name for the same file is an `aliases:` entry in the profile, never a
second entry in a platform YAML or in `_shared.yml`. A name a platform's own
launcher reads, such as the names Batocera's DuckStation generator tries
for each region, describes the platform and lives in its `launchers:` records (see
[launchers](adding-a-platform.md#launchers)).

Some entries in a platform YAML are not the platform's own: files a
`_shared.yml` group injects (`shared_group`), copies the RomM scraper mirrors
to a twin system (`mirror_of`) and additions the libretro scraper makes
(`curated`). `native_layer()` removes them wherever the question is what the
platform itself declares: the export, the truth diff and the site's
comparison tables. Counted as the platform's, they would be written into
System.dat as if libretro had declared them.

<!-- image: data-layers -->

## The inverted model

Packs are built today from what each platform declares, completed by what the
cores need. The direction the project works toward is the inverse: generate
each platform's file from what the emulators' code needs, file by file, and
offer it to that platform's maintainers as a source they can check and adopt.
The [updated platform files](../exports.md) page publishes these files, every
change traceable to code, presented as suggestions. Keeping a BIOS list in
step with every emulator release is a large amount of work, and the files are
written to make it lighter.

An entry a platform declares is never removed from its file on the strength of
a missing match. When this was measured, entries the generated data did not
pair were often still read, by an alias, a hash, a directory entry or a core
outside the resolved set. A removal needs positive proof:
every core of the system profiled, each with a reference showing the closed
set of names it opens. Until then the entry is listed as a removal candidate
with the cores examined (see [export_native.py](tools.md#export_nativepy)).

## Dump-catalog provenance

Snapshots of the dump-preservation catalogs (Redump, No-Intro, TOSEC) live in
`provenance/` as committed JSON. `generate_db.py` joins them against the
collection by SHA1, falling back to MD5 + size, and writes a `provenance` field
on each matching database entry. The system pages render it as a verified dump
badge.

Provenance is an annotation, never an authority. It answers "does this file
byte-match a catalogued dump", which is a different question from "does the
emulator accept it". When the two disagree, pack contents and verification
follow the emulator source code.

`provenance_report.py` reports the reverse direction: catalog entries absent
from the collection, which become acquisition targets. A DAT counts as covered
when the collection holds at least one of its entries. Entries from DATs the
collection does not cover are counted but not listed, since No-Intro tags every
non-game dump as `[BIOS]`, including tens of thousands of digital-distribution
entries that are out of scope here.

## Pack grouping

Platforms that produce identical packs are grouped automatically.
Two platforms share a pack when they declare the same files, run the same
emulators and see file names the same way. Lakka declares RetroArch's files
and cores but runs on Linux, where `bios.col` and `BIOS.col` are two files
that different cores open, while RetroArch's pack folds them for Windows and macOS.
So Lakka gets its own pack. RetroPie inherits RetroArch's systems but ships its
own package list, standalone emulators included, and is case-sensitive too, so
it gets a separate pack and a separate install manifest.
With `--target`, the fingerprint includes target cores so platforms
with different hardware filters get separate packs. Emulator and system packs
also retain system identity, `selection_slot` and requested region. Same-named
regional files are never collapsed merely because their display label matches.

## Pack reproducibility

A pack is a function of its inputs. Two builds from the same collection and
the same `database.json` produce the same bytes, so a third party can rebuild
a published pack and compare it against the checksum in `SHA256SUMS.txt`.
That list is signed with a release key whose public half is `allowed_signers`
at the repository root, so the comparison does not rest on the release page
being intact: see [verifying a release](release-process.md#verifying-a-release).

Three things make that hold. Generated members (`README.txt`, `manifest.json`)
carry a fixed date rather than the wall clock, and the manifest's `generated`
field is read from `database.json` instead of the build time. Each ZIP of the
collection, MAME and FBNeo romsets included, is copied byte for byte, so it
hashes to the SHA1 the install list and the site publish, and git fixes those
bytes. And every member is written with the same fixed date: `ZipFile.write`
copies the source file's mtime, which is the checkout time for a file from the
collection and the wall clock for one the build just staged in `tmp/`.

`tests/test_deterministic_zip.py` builds the same fixture twice and compares
the bytes, for both the platform and the emulator pack paths. Its fixture
holds a ZIP, so the comparison covers the archive copy as well as loose files.

## Collection rules

How files enter `bios/`, and why.

- **Variants keep every layer served.** A different dump under an existing
  name goes to `.variants/`. The primary carries the name the emulator's
  source uses, and a dump a platform pins under an older name stays a variant,
  so each layer receives the bytes it checks. A destination that already
  exists is something a platform depends on: a `segaboot.gcm` that Batocera
  requires was once overwritten by the dump RetroDECK requires, and is now
  kept beside it.
- **One content, one file.** A byte-identical copy under another name is
  removed, and the name it carried becomes a profile alias. Trees addressed by
  path keep their equal files, since equality is part of their layout: those
  folders are `NODEDUP_DIRS` in `scripts/dedup.py`.
- **Archives the project builds are TorrentZip.** `build_torrentzip()` makes
  an archive's bytes depend on its contents alone, so anyone can rebuild it.
  An upstream romset whose MD5 a platform pins stays verbatim in `.variants/`.
  A member renamed by hand in an existing archive gives bytes that match no
  distributed romset and that nobody can regenerate.
- **Every archive has a recipe.** `recipes/archives.json` records the members
  of each archive the collection holds, by sha1, and whether the TorrentZip
  build gives its bytes (`exact`) or only its members (`canonical`), so the
  collection can rebuild it from the ROMs it holds
  ([Archive recipes](tools.md#archive-recipes)).
- **A pack carries what the user must obtain.** A file the emulator installs
  itself (`bundled: true`) is not kept once nothing else needs it, and step 4d
  of the pipeline fails on such a copy. Its sha1 and size are written into the
  profile first, so the entry keeps the file's identity.
- **A platform's older revision needs the core's own claim first.** When a
  platform pins an older revision of a data file, collecting it makes the
  platform's hash the only content proof at that destination, and a core
  profile without a hash then receives the old file. The profile first
  declares the hash of the file at its own `source_commit`
  (`find_pinned_revision.py` finds the revision behind a pinned md5).
- **A transformation of a held dump is collected by reproducing it.** A byte
  swap, a permutation, a concatenation or a published patch is replayed from
  its source and checked against the expected hash, and the profile states
  what the file derives from.
- **A dump says what it is.** The version string inside a ROM names its model,
  whatever folder it arrived in. Dumps once filed for one handheld announced
  another model in their own strings.
- **Game data lives under the tree its engine reads.** Engines open generic
  names in their own folders: `pak0.pak` is Quake II's under `baseq2/` and
  Half-Life's under `valve/`. Each game's files are stored under that tail so
  they resolve by path, and `tests/test_game_data_homonyms.py` fails when one
  game's entry reaches another game's file by name.
- **A file a platform pins by hash is collected into `bios/`.** A data
  directory cache that happens to hold it is not enough, because the installer
  cannot fetch from the cache.
- **Collected means committed.** A file indexed by the database but never
  committed gives the installer a 404, so
  `git ls-files --others --exclude-standard bios` is empty before manifests
  are regenerated.
- **MAME and FBNeo archives are named the way the emulator opens them.** A
  MAME device's archive takes the short name of its `DEFINE_DEVICE_TYPE`, not
  the `ROM_START` label. An FBNeo archive is named after its `RomDesc`, once
  the driver's `GetZipName` function strips the system prefix (`msx_msx`
  opens `msx.zip`). BIOS root sets change between MAME versions and are listed
  from each version's source. A distributed non-merged archive also holds the
  ROMs of every device the machine pulls in, which is what a `-listxml` DAT
  describes and why [romset recipes](tools.md#romset-recipes) come from DATs.

## Storage tiers

| Tier | Meaning |
|------|---------|
| `embedded` (default) | file is in the `bios/` directory, included in packs |
| `external` | file has a `source_url`, downloaded at pack build time |
| `user_provided` | user must provide the file (instructions included in pack) |
| `large_file`, `release` | file is an asset of the `large-files` release, listed in `.gitignore`, fetched at build time |

## Verification severity and discrepancies

How a missing or mismatched file is reported, and what happens when the
platform's check and the emulator's check disagree, follow the platform's
verification mode: see the [severity matrix](verification-modes.md#severity-matrix)
and [discrepancy detection](verification-modes.md#discrepancy-detection).
A filename or destination never overrides a declared content hash during
resolution.

## Security

- install metadata is fetched from the same revision as the installer that
  reads it, and validated before use.
- destinations are normalized and contained below the selected BIOS root.
- downloads are bounded by declared and global size limits, verified with
  SHA256/SHA1, written to unique temporary siblings and atomically replaced.
- ZIP extraction rejects traversal, absolute paths, duplicates, links, special
  files, encryption, excessive expansion and suspicious compression ratios.
- standalone-emulator copies require explicit `--standalone-copies` consent.
- CI writes only what its job needs: `validate.yml` holds `pull-requests: write`
  for the validation comment and labels, and `deploy-site.yml` holds the Pages
  deploy identity. No workflow builds or publishes a release.

- `safe_extract_zip()` prevents zip-slip path traversal attacks
- a pack copies each ZIP of the collection byte for byte, so every member
  hashes to the SHA1 the install list publishes
- `crypto_verify.py` and `sect233r1.py` verify 3DS RSA-2048 signatures and AES-128-CBC integrity
- ZIP inner ROM verification via `checkInsideZip()` replicates Batocera's behavior
- `md5_composite()` replicates Recalbox's composite ZIP hash

## Edge cases

| Case | Handling |
|------|---------|
| MD5 shorter than 32 characters | completed by the Batocera scraper when one MD5 in the collection starts with it, matched by prefix in resolution |
| `zippedFile` entries | MD5 is of the ROM inside the ZIP, not the ZIP itself |
| Regional variants (same filename) | `by_path_suffix` index disambiguates |
| MAME BIOS ZIPs | `contents` field documents inner structure |
| Trees addressed by path (RPG Maker, ScummVM, tzdata, c64-emu and the rest of `NODEDUP_DIRS`) | excluded from dedup to keep files that are equal by design |
| `strip_components` in data dirs | flattens cache prefix to match expected path |
| case-insensitive dedup | prevents `font.rom` + `FONT.ROM` conflicts on Windows/macOS. Where the platform also runs on a filesystem that keeps case (EmuDeck and RetroArch on Linux), the pack README lists each spelling it leaves out, and the installer adds them (`case_variants`) |
| frozen snapshot cores | `.info` may reflect current version while code is pinned to an old one. Only the frozen source at the pinned tag is reliable (e.g. desmume2015, mame2003) |

### File resolution chain

`resolve_local_file` in `common.py` turns a file entry into a local path, and
`verify.py` and `generate_pack.py` both call it. Every declared hash is tried
before a path or a name, so a path never wins over a hash. The steps, in order,
are listed under [file resolution chain](verification-modes.md#file-resolution-chain).

A platform entry with no hash is never answered by name with a file filed under
another maker than the one its system id names. When that leaves nothing, the
profile aliases a primary's name keeps out of `by_name` (`by_shadowed_alias`)
answer, within that maker's folder: AmberELEC's `nec-pc-88` `DISK.ROM` is QUASI88's
`n88sub.rom`, not the MSX disk ROM.

A name whose held file no declaration proves by hash, while declarations of that
name prove another dump in the same directory, answers with that dump
(`by_proven_name`). The collection files the DSi Panda devkit boot ROMs as
`dsi_bios7.bin` and `dsi_bios9.bin`, and every hash declared under those names
designates a retail dump beside them.

## Platform inheritance

Platform configs support `inherits:` to share definitions.
Lakka inherits from RetroArch, RetroPie inherits from RetroArch with `base_destination: BIOS`.
`overrides:` allows child platforms to modify specific systems from the parent.

Which emulator profiles a platform resolves follows its `cores` field, as
[adding a platform](adding-a-platform.md#required-fields) describes.

## Hardware target filtering

`--target TARGET` filters packs and verification by hardware (e.g. `switch`, `rpi4`, `x86_64`).
Target configs are in `platforms/targets/`. Overrides in `_overrides.yml` add aliases and
adjust core lists per target. `filter_systems_by_target` excludes systems whose cores are
not available on the target. Without `--target`, all systems are included.

## MAME clone map

`_mame_clones.json`, beside the `bios/` tree it describes, maps MAME clone ROM names to their canonical parent.
When a clone ZIP was deduplicated, `resolve_local_file` uses this map to find the canonical file.

## Install manifests

`generate_pack.py --manifest` produces JSON manifests in `install/` for each platform.
These contain downloadable file lists with SHA256 and SHA1 hashes, explicit
unsafe/unavailable omissions, platform detection config, and standalone copy
instructions. `install/targets/` contains per-architecture core availability.
The cross-platform installer (`install.py`) uses these manifests to auto-detect the
user's platform, filter files by hardware target, and download with SHA256/SHA1,
size, path-containment and atomic-write checks.

## Tests

The suite is discovered dynamically rather than maintained as a hand-counted
subset:

| File | Coverage |
|------|----------|
| `test_e2e.py` | resolution, verification, packs, inheritance, targets, truth and exporters |
| `test_profile_sync.py`, `test_upstream.py` | source anchoring, forge parsing, revisions, cache and guarded writes |
| `test_install.py`, `test_audit_regressions.py` | automatic wrappers, manifest boundaries, pipeline exits, strong hashes and safe archives |
| `test_region.py` | region vocabulary, ranking, per-system grouping and repository conformance |
| `test_site_exports.py`, `test_site_validation.py` | versioned exports, SQLite, metadata, accessibility structure and complete local-link graph |
| parser/provenance modules | MAME, FBNeo, DAT import, merge and provenance joins |
| artifact modules | deterministic ZIPs, locking, large-file cache, pack integrity and portable paths |

```bash
python -m unittest discover -s tests -t . -v   # full suite
python -m unittest tests.test_e2e -v      # single module
```

`test_e2e.py`, `test_install.py`, `test_provenance.py`, the parser tests,
`test_profile_sync.py` and `test_upstream.py` run on synthetic fixtures with no
network and no real BIOS files. `test_pack_integrity.py`, `test_torrentzip.py` and
`test_no_case_collisions.py` read the working tree and skip when the data they
need is absent. See the [testing guide](testing-guide.md) for the fixture
pattern and how to add a test.

## CI workflows

| Workflow | File | Trigger | Role |
|----------|------|---------|------|
| Deploy Site | `deploy-site.yml` | push to main on any input of the site build, and manual | validate contracts, generate site, build with Astro Starlight, validate rendered HTML, deploy to Pages |
| Validation | `validate.yml` | pull request and push to main on the collection, profiles, schemas, scripts, tests, the installer and every input of the site build | schema check and full test suite on both, BIOS hash validation and auto-label on pull requests |

Each workflow's `paths:` list is the exact set of files that starts it.
`tests/test_workflow_paths.py` holds the Deploy Site list to the scripts the build
imports, and the Validation list to every input of the site build, so a change that
would fail the deploy fails the pull request first. A change to `wiki/`, to
`install.sh` or to any other path in that list runs the full suite.

Releases are not built in CI: the packs are generated and checked on the
maintainer's machine and uploaded with `gh`, see the
[release process](release-process.md).

## License

See `LICENSE` at repo root. Files are provided for personal backup and archival.
