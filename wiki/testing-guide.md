# Testing Guide

This page covers how to run, understand, and extend the test suite.

10 modules, 400 tests. No network access anywhere. Most modules build synthetic
fixtures in a temp directory; the three that read the working tree skip cleanly
when the data they need is absent.

## Running tests

Run the full suite:

```bash
python -m unittest discover tests -v
```

Run a single module:

```bash
python -m unittest tests.test_e2e -v
python -m unittest tests.test_install -v
python -m unittest tests.test_provenance -v
python -m unittest tests.test_mame_parser -v
python -m unittest tests.test_hash_merge -v
python -m unittest tests.test_fbneo_parser -v
python -m unittest tests.test_profile_refs -v
python -m unittest tests.test_pack_integrity -v
python -m unittest tests.test_torrentzip -v
python -m unittest tests.test_no_case_collisions -v
```

The only dependency is `pyyaml`. No test framework beyond the standard
library `unittest` module.

## Modules at a glance

| Module | Tests | Fixtures | What it covers |
|--------|-------|----------|----------------|
| `test_e2e.py` | 217 | synthetic | resolution, verification, packs, cross-reference, targets, truth |
| `test_install.py` | 70 | synthetic | `install.py` detection, config parsing, manifest handling |
| `test_provenance.py` | 29 | synthetic | Logiqx/Redump parsing, DAT import, provenance join, coverage report |
| `test_mame_parser.py` | 22 | inline C | BIOS root sets, ROM blocks, macro expansion |
| `test_hash_merge.py` | 17 | synthetic | YAML hash merge, diff, formatting preservation |
| `test_fbneo_parser.py` | 16 | inline C | `BDF_BOARDROM` sets, ROM info parsing |
| `test_profile_refs.py` | 12 | synthetic | `check_profile_refs` pure functions, no network |
| `test_pack_integrity.py` | 8 | real packs | extract each ZIP, verify paths and hashes |
| `test_torrentzip.py` | 8 | real romsets | TorrentZip builder byte-for-byte |
| `test_no_case_collisions.py` | 1 | real `bios/` | no case-colliding paths on Windows/macOS clones |

## Test architecture

### test_e2e.py

The main regression suite. A single `TestE2E` class exercises every code path
through the resolution, verification, pack generation, and cross-reference
logic.

**Fixture pattern.** `setUp` creates a temporary directory tree with:

- Fake BIOS files (deterministic content for hash computation)
- Platform YAML configs (existence mode, MD5 mode, inheritance, shared groups)
- Emulator profile YAMLs (required/optional files, aliases, HLE, standalone)
- A synthetic `database.json` keyed by SHA1

`tearDown` removes the temporary tree.

**Test numbering.** Tests are grouped by category:

| Range | Category |
|-------|----------|
| `test_01`--`test_14` | File resolution (SHA1, MD5, name, alias, truncated MD5, composite, zip contents, variants, hash mismatch) |
| `test_20`--`test_31` | Verification (existence mode, MD5 mode, required/optional severity, zipped file, multi-hash) |
| `test_40`--`test_51` | Cross-reference and platform grouping (undeclared files, standalone skip, alias profiles, data dir suppression, exclusion notes) |
| `test_60`--`test_61` | Storage tiers (external, user-provided) |
| `test_70`--`test_84` | Emulator-level validation (index build, size, CRC32, MD5, SHA1, crypto) |
| `test_90`--`test_125` | Per-emulator and per-system verification, `dest_hint` resolution, registry metadata |
| `test_130`--`test_183` | Pack generation (required-only, split, `--from-md5`, path conflicts, archive extras, truth generation, exporters) |
| `test_200`--`test_227` | Pack source variants, deterministic ZIPs, SHA256/CRC32 resolution, MiSTer scraper, manifests |

Numbers are stable anchors, not an execution order. When a range fills up, a
letter suffix keeps a new test next to the behavior it covers
(`test_130b_existence_pack_reports_hash_mismatch`).

Each test calls the same functions that `verify.py` and `generate_pack.py` use
in production, against the synthetic fixtures.

### Parser tests

**test_mame_parser.** Tests the MAME C source parser that extracts BIOS root
sets from driver files. Fixtures are inline C source snippets containing
`ROM_START`, `ROM_LOAD`, `GAME()`/`COMP()` macros with
`MACHINE_IS_BIOS_ROOT`. Tests cover:

- Standard `GAME` macro detection
- `COMP` macro detection
- `ROM_LOAD` / `ROMX_LOAD` parsing (name, size, CRC32, SHA1)
- `ROM_SYSTEM_BIOS` variant extraction
- Multi-region ROM blocks
- Macro expansion and edge cases

**test_fbneo_parser.** Tests the FBNeo C source parser that identifies
`BDF_BOARDROM` sets. Same inline fixture approach.

**test_hash_merge.** Tests the text-based YAML patching module used to merge
upstream BIOS hashes into emulator profiles. Covers:

- Merge operations (add new hashes, update existing)
- Diff computation (detect what changed)
- Formatting preservation (comments, ordering, flow style)

Fixtures are programmatically generated YAML/JSON files written to a temp
directory.

### Provenance and installer tests

**test_provenance.** Covers the dump-catalog pipeline end to end on synthetic
DATs: the Logiqx XML parser, the Redump scraper's parsing path, the DAT pack
importer, the SHA1-then-MD5+size join performed by `generate_db.py`, and the
coverage report's covered/uncovered DAT accounting.

**test_install.** Covers `install.py` without touching the network: OS
detection, each registry detection method (`config_file`, `path_exists`,
`file_exists`), config-file key parsing, manifest loading, target filtering,
and destination resolution.

**test_profile_refs.** Covers the pure functions of `check_profile_refs`
(anchor matching, line-window search, hash extraction). The GitHub fetching
path is not exercised, so the module runs offline.

### Tests that read the working tree

Three modules assert on real repository data instead of fixtures. Each skips
when its input is missing, so a partial checkout still runs green.

**test_torrentzip.** Rebuilds real MAME romsets through the TorrentZip builder
and asserts the output is byte-identical, which is what keeps arcade ZIP hashes
stable across rebuilds.

**test_no_case_collisions.** Walks `bios/` and fails on two paths that differ
only by case. On Windows and macOS, git can only check out one of them, which
silently corrupts the clone. `.variants/` is exempt: those names are
disambiguated by a hash suffix on purpose.

**test_pack_integrity.** Described below; needs packs in `dist/`.

## How to add a test

1. **Pick the right category.** Find the number range that matches the
   subsystem you are testing. If none fits, start a new range after the last
   existing one.

2. **Create synthetic fixtures.** Write the minimum YAML configs and fake
   files needed to isolate the behavior. Use `tempfile.mkdtemp` for a clean
   workspace. Avoid depending on the repo's real `bios/` or `platforms/`
   directories.

3. **Call production functions.** Import from `common`, `verify`, `validation`,
   or `truth` and call the same entry points that the CLI scripts use. Do not
   re-implement logic in tests.

4. **Assert specific outcomes.** Check `Status`, `Severity`, resolution
   method, file counts, or pack contents. Avoid brittle assertions on log
   output or formatting.

5. **Run the full suite.** After adding your test, run `python -m unittest
   discover tests -v` to verify nothing else broke.

Example skeleton:

```python
def test_42_my_new_behavior(self):
    # Write minimal fixtures to self.root
    profile = {"emulator": "test_core", "files": [...]}
    with open(os.path.join(self.emulators_dir, "test_core.yml"), "w") as f:
        yaml.dump(profile, f)

    # Call production code
    result = verify_platform(self.config, self.db, ...)

    # Assert specific outcomes
    self.assertEqual(result[0]["status"], Status.OK)
```

### test_pack_integrity.py

End-to-end pack verification. Extracts each platform ZIP to `tmp/` (in the
repo, not `/tmp` which is tmpfs on WSL) and verifies that every file declared
in the platform YAML:

1. Exists at the correct path on disk after extraction
2. Has the correct hash per the platform's native verification mode

Handles inner ZIP verification for MAME/FBNeo ROM sets (checkInsideZip,
md5_composite, inner ROM MD5) and path collision deduplication.

8 tests (one per active platform): RetroArch, Batocera, BizHawk, EmuDeck,
Recalbox, RetroBat, RetroDECK, RomM.

```bash
python -m unittest tests.test_pack_integrity -v
# or via CLI:
python scripts/generate_pack.py --all --verify-packs --output-dir dist/
```

Integrated as pipeline step 6/8 (runs after consistency check, before
README generation). Requires packs in `dist/` — skip with `--skip-packs`.

## Verification discipline

The test suite is one layer of verification. The full quality gate is:

1. All unit tests pass (`python -m unittest discover tests`)
2. The full pipeline completes without error (`python scripts/pipeline.py --offline`)
3. No unexpected CRITICAL entries in the verify output
4. Pack file counts match verification file counts (consistency check)
5. Pack integrity passes (every declared file extractable with correct hash)

If a change passes tests but breaks the pipeline, it's worth investigating before merging. Similarly, new CRITICAL entries in the verify output after a change usually indicate something to look into. The pipeline is designed so that all steps agree: if verify reports N files for a platform, the pack should contain exactly N files.

Ideally, tests, code, and documentation ship together. When profiles and platform configs are involved, updating them in the same change helps keep everything in sync.

## CI integration

The `validate.yml` workflow runs `test_e2e` on every pull request that touches
`bios/` or `platforms/` files. The test job (`run-tests`) runs in parallel
with BIOS validation, schema validation, and auto-labeling. `build.yml` runs
the same module before building release packs.

CI runs `test_e2e` only, not the whole suite: the other modules either need
build artifacts (`test_pack_integrity` needs packs in `dist/`) or duplicate
work the workflow already does. Run `python -m unittest discover tests` locally
before pushing.

Tests must pass before merge. If a test fails in CI, reproduce locally with:

```bash
python -m unittest tests.test_e2e -v 2>&1 | head -50
```
