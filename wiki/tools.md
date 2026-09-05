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
python scripts/verify.py --platform recalbox --region us   # regional priority list
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
`--region` narrows the report to the file set a regional pack would carry, and a
mode that cannot apply it refuses it rather than ignoring it: see
[region filtering](advanced-usage.md#region-filtering).

`--db`, `--platforms-dir` and `--emulators-dir` point the run at another
database or source tree, which is how the tests drive it against fixtures.

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

# Regional filtering
python scripts/generate_pack.py --platform retroarch --region us
python scripts/generate_pack.py --platform retroarch --region us,eu,jp
python scripts/generate_pack.py --platform retroarch --region us --one-per-slot

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
python scripts/generate_pack.py --all --offline       # cache-only; never open the network

# Install manifests (consumed by install.py)
python scripts/generate_pack.py --all --manifest --output-dir install/
python scripts/generate_pack.py --manifest-targets --output-dir install/targets/
```

Packs include platform baseline files plus files required by the platform's cores.
When a file passes platform verification but fails emulator validation,
the tool searches for a variant that satisfies both.
If none exists, the platform version is kept and the discrepancy is reported.
What happens when a declared hash and the local dump disagree follows the
platform's own verification mode. A hash platform would reject the file, so it
is omitted and recorded in the pack report and the installer manifest. An
existence platform reads no bytes, so the file is packed and the divergence is
reported instead: an upstream list error must not remove a file the frontend
would have loaded.

**Granular options:**

- `--system` with `--platform`: filter to specific systems within a platform pack
- `--required-only`: exclude optional files, keep only required
- `--split`: generate one ZIP per system instead of one big pack
- `--split --group-by manufacturer`: group split packs by manufacturer (Sony, Nintendo, Sega...)
- `--from-md5`: look up a hash in the database, or build a custom pack with `--platform`/`--emulator`
- `--from-md5-file`: same, reading hashes from a file (one per line, comments with #)
- `--target`: filter by hardware target (e.g. `switch`, `rpi4`, `x86_64`)
- `--region`: ordered priority list, best first. Regions nest, a system with no
  regional split keeps everything, and a group with no candidate in any named
  region is kept whole rather than emptied
- `--one-per-slot`: keep one file per system and declared region, ranked by the
  `priority:` the emulator source states, lowest first
- `--include-extras`: with `--emulator` or `--system`, add the files the cores
  pull in beyond the selection
- `--db`, `--platforms-dir`, `--emulators-dir`: read another database or source
  tree instead of the repository's
- `--source {platform,truth,full}`: select file source (platform YAML only, emulator profiles only, or both)
- `--all-variants`: generate all 6 combinations of source x required_only
- `--refresh-data`: force re-download all data directories before packing

How regions are ordered, what a slot is and what each narrowing adds to the
pack name: [region filtering](advanced-usage.md#region-filtering).

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

Rewrite each platform's own BIOS file, corrected: System.dat, es_bios.xml,
batocera-systems, checkBIOS.sh, FirmwareDatabase.cs, the RetroDECK manifests,
MiSTer's BiosDB, RetroPie's scriptmodules. Every platform in the registry,
archived included.

```bash
python scripts/export_native.py --platform batocera --fetch
python scripts/export_native.py --all --fetch --output-dir dist/upstream/
```

`--fetch` downloads the platform's own file once into
`.cache/upstream-native/`, at the revision the platform YAML's `source:`
names. Formats that carry code are patched from it rather than
regenerated, and the export fails without it.

A list is written in the order the code looks: `priority:` first (lowest
wins), then the profile's own declaration order. What a format cannot
state is reported rather than written — EmuDeck's arrays are shared
between emulators its file does not name, so a hash is corrected in place
and never added.

MAME and FBNeo entries are `.zip` ROM sets: their meaningful hashes belong
to the files inside the archive, so the exported DAT lists those entries
without a container sha1. Anyone submitting the DAT upstream should mention
this.

### fileless_audit.py

Names the profiles that declare no files whose source asks for a directory to
read from.

```bash
python scripts/fileless_audit.py craft dice lutro
```

An empty `files:` list is the one assertion in the repository that ages
unwatched: there is no file to go missing and no ref to drift, so nothing
notices when a core that embedded everything grows a path. virtualjaguar
carried "No external BIOS files are required or loaded by this core" while its
source had grown eleven filenames read from the system directory.

The signal is the request itself, `RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY` and
its spellings, looked for in the sources the profile already cites. Finding one
does not prove a file is loaded, which is why this reports rather than
concludes.

Three answers settle a profile and it is not reported again: it declares files,
it declares `data_directories` (dinothawr reads `system_dir/dinothawr/` and
says so there), or it carries an `exclusion_note` saying what the directory is
for. craft writes its world database in it, dice stores the answer in a
variable no other file names, lutro hands it to the Lua game. What is left is
the set nobody has read yet, which is the only set worth reading.

### mame_ref_audit.py

Checks that each MAME romset ref names the line declaring its own set, at the
profile's pinned revision.

```bash
python scripts/mame_ref_audit.py mame mamearcade mamemess groovymame
python scripts/mame_ref_audit.py mame --write
```

`profile_sync` follows content: a ref that drifted still anchors wherever the
cited text went, which is what drift detection is for. It cannot answer the
only question a MAME ref asks, whether that line declares that set. Asking the
stronger question found nineteen stale refs in one driver file where
profile_sync had flagged five, and ninety-two across the four profiles whose
upstream still moves.

The set name is argument 1 of the machine macro, after the year: matching it
anywhere on the line would also match every clone naming that set as its
parent, which is most of a driver file. Comments are stripped first, since a
declaration can sit behind one, as `/* Naomi */ GAME( 1998, naomi, ...)` does.

A set no machine macro declares is reported as not judgeable rather than
wrong: device ROMs take the shortname of their `DEFINE_DEVICE_TYPE`, and some
archives are bare `ROM_START` blocks. The frozen generations, mame2009 through
mame2016, come out clean, which is the check saying it finds drift only where
drift can happen.

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

Those two writes belong in one pass, because a profile whose refs moved
without its pin describes two revisions at once:

```bash
python scripts/profile_sync.py --all --rebase-refs --bump-commit --dry-run
python scripts/profile_sync.py --all --rebase-refs --bump-commit
```

Asking for both makes the pass atomic. The work happens on a copy, and the
copy is promoted only when the pin follows the refs; a profile whose refs
describe one revision while its pin names another is the state the
all-or-nothing rule exists to prevent, and recaling alone produces it. What
holds a pin back is an annotated ref, one under a mode key, or a prose run the
pass cannot rewrite without guessing: those are repaired first, by hand or
with `--realign-prose`.

The first prints the plan and changes nothing: `would recale` per ref and
`would set source_commit` per profile. It reaches that plan by running the
real write path over a throwaway copy, so the planned bump reads the text
the recale would have left rather than the one on disk; a pin held back by
prose that the same pass would have moved is not reported as blocked. Drop
`--dry-run` and the same pass writes, recale before bump on each profile.

A forge can also go for good. A 451, a 410 or a host that stops resolving
is reported as `upstream gone` in its own bucket rather than retried and
printed as a failure every pass, and the profile leaves the review backlog,
where nothing could be done about it. A 403 is not that: small Forgejo
instances behind anti-bot filters answer 403 to a script and 200 to a
browser, so it stays a refusal.

When no mirror serves it either, `upstream_gone` states why, and the profile
stops being an open problem: the refs describe the last revision anyone could
reach and nothing further is possible. The declaration is guarded rather than
trusted, since a forge can come back: a profile that declares it while the
forge answers is reported as the contradiction it is.

`source_mirror` names a repository carrying the same tree, consulted after
`source` and `upstream` so a live primary always decides attribution. It is
what keeps a profile checkable once its own forge stops answering: eden
reads from its Codeberg copy, which holds the same head and the pinned
commit. A repository that refuses is muted for the rest of the pass instead
of ending it, keyed by host as well as slug, since a mirror carries the same
slug on another forge.

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
| `validate_schemas.py` | Validate the data contracts: schemas and semantic invariants. `--source-only` checks `emulators/` and `platforms/` alone, which is what PR validation runs |
| `auto_fetch.py` | Fetch missing BIOS files from known sources (4-step pipeline) |
| `list_platforms.py` | List active platforms (`--all` includes archived, used by CI) |
| `download.py` | Download a pack from GitHub releases, split volumes joined and checked (Python, stdlib only) |
| `download.sh` | Same, as a shell one-liner (`curl` + `unzip`) |
| `provenance_report.py` | Dump-catalog coverage and acquisition targets (see above) |
| `generate_readme.py` | Generate README.md and CONTRIBUTING.md from database |
| `generate_site.py` | Generate all MkDocs site pages (this documentation) |
| `validate_site.py` | Validate rendered metadata, headings, image alternatives, JSON-LD, local resources, links and fragments |
| `romset_recipes.py` | Identify which emulator version an arcade archive matches, and rebuild a pinned archive from ROMs already held |
| `scraper/romset_dat_importer.py` | Fetch and import per-set recipes from MAME `-listxml` or FBNeo DATs into `recipes/` |
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

# One-line automatic install (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh

# One-line automatic install (Windows PowerShell)
irm https://raw.githubusercontent.com/Abdess/retrobios/main/install.ps1 | iex
```

`install.py` auto-detects the user's platform by checking config files,
downloads the missing files from an immutable release revision, verifies their
SHA-256 and SHA-1, and replaces each destination atomically. The shell and
Both one-liners verify the downloaded Python installer against the SHA-256
embedded in their bootstrap before running it. Copies into standalone-emulator
directories are opt-in through `--standalone-copies`. Manifest entries with no
available payload are reported as safely omitted; they are never replaced by a
same-named file.

`scripts/download.sh` remains available for downloading a prebuilt platform
ZIP when a manually reviewed pack release contains it; it is separate from the
per-file automatic installer above. A pack over 2 GB is published as numbered
volumes: both downloaders group them under one platform name, download each
one, join them and check the result against the release's `SHA256SUMS.txt`.
That list carries a detached signature, `SHA256SUMS.txt.sig`, verifiable
against `allowed_signers` at the repository root; the
[release process](release-process.md#verifying-a-release) gives the commands.
Volumes are staged inside the destination directory rather than the system
temp directory, which is a RAM disk on Batocera, ROCKNIX and RetroDECK.
`RETROBIOS_API` points them at another releases endpoint, HTTPS only, plain
HTTP allowed to loopback for end-to-end tests.

Options, environment overrides, platform detection and the trust boundary are
documented on the [Installer](installer.md) page.

## Romset recipes

A profile's `contents:` block lists the member names and CRC32s one emulator
version expects inside an archive. TorrentZip makes archive bytes a function of
that list alone, so a recipe plus the ROM bytes reproduces the archive exactly.

```bash
python scripts/romset_recipes.py --identify   # which version each archive is
python scripts/romset_recipes.py --missing    # pinned archives we lack
python scripts/romset_recipes.py --missing --write   # write what can be rebuilt
```

Recipes come from two places. Profiles document a few hundred sets by hand. A
DAT documents every set of one emulator version at once, and both upstreams
publish theirs without a browser: MAME ships its `-listxml` as a release asset,
FBNeo keeps its DATs in the repository.

```bash
python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0289
python -m scripts.scraper.romset_dat_importer --source mame --fetch mame0250
python -m scripts.scraper.romset_dat_importer --source fbneo --fetch
```

Snapshots land in `recipes/`, not `provenance/`: the latter holds dump catalogues
and a recipe is not one. Versions accumulate rather than replace each other,
because a platform pins the archive of whichever version its list was built
against. Only sets a profile or platform references are kept, a `romof` parent's
members are merged into the child, and members with no CRC32 are dropped: those
are undumped and a real romset does not carry them.

The store is compacted: 22 MAME versions produce 23,679 entries but only 1,726
distinct recipes, since most sets do not change between releases. Each is kept
once, `dats` listing every version that agrees and `dat` naming the earliest, so
an identification reads as "unchanged since that version".

`--identify` answers what an archive on disk actually is: with 22 MAME versions
and the FBNeo DATs imported, 1,113 archives are reproduced byte for byte. `--missing` takes the container MD5s the platforms pin, keeps those the
collection does not have, and tries every recipe whose ROMs are present.

Reconstruction only works when the pinned archive is itself TorrentZip. An
archive whose bytes carry metadata unrelated to its contents cannot be derived
from ROMs by anyone; those are reported as unreproducible rather than guessed
at. Writing is explicit: the pipeline only ever reports.

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
