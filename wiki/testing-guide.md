# Testing Guide

This page covers how to run, understand, and extend the test suite.

All tests use synthetic fixtures. No real BIOS files, platform configs, or
network access required.

## Running tests

Run a single test module:

```bash
python -m unittest tests.test_e2e -v
python -m unittest tests.test_pack_integrity -v
python -m unittest tests.test_mame_parser -v
python -m unittest tests.test_fbneo_parser -v
python -m unittest tests.test_hash_merge -v
```

Run the full suite:

```bash
python -m unittest discover tests -v
```

The only dependency is `pyyaml`. No test framework beyond the standard
library `unittest` module.

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
| `test_40`--`test_47` | Cross-reference (undeclared files, standalone skip, alias profiles, data dir suppression, exclusion notes) |
| `test_50`+ | Platform config (inheritance, shared groups, data directories, grouping, core resolution, target filtering, ground truth) |

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
with BIOS validation, schema validation, and auto-labeling.

Tests must pass before merge. If a test fails in CI, reproduce locally with:

```bash
python -m unittest tests.test_e2e -v 2>&1 | head -50
```

The `build.yml` workflow also runs the test suite before building release
packs.
