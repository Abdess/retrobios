---
level: contribute
order: 40
---

# Testing guide

The tests hold what users and platforms rely on: a pack holds what its
platform checks, the site states what the code does, the installer writes only
where it should.

No test needs network access. Most build synthetic fixtures, and every
temporary directory lands under the repository's `tmp/tests/`:
`tests/__init__.py` points `tempfile` and `TMPDIR` there, never at the `/tmp`
tmpfs. Modules that read real artifacts skip when those are absent. The test
runner prints the count.

## Running tests

Run the full suite:

```bash
python -m unittest discover -s tests -t . -v
```

Or run it as parallel processes, one per module, each with its own
scratch folder. A module a host crash kills runs again alone at the end:

```bash
python scripts/run_tests.py            # a few modules at a time
python scripts/run_tests.py --jobs 1   # one at a time
```

Run a single module, or several:

```bash
python -m unittest tests.test_e2e -v
python -m unittest tests.test_install tests.test_install_cores -v
```

The table below says which module covers what.

Running the build needs Python 3.9 or newer and `pyyaml` alone. CI runs the suite on 3.12,
and one test imports every module under `scripts/` with a real `python3.9`, which
needs `pyyaml` and `jsonschema` installed for that interpreter. The
schema contract tests also need `jsonschema[format-nongpl]`, and one site test
renders a wiki line with `markdown`. The CI installs both: without them those
tests are reported as skipped, so install them before a pull request
(`pip install "jsonschema[format-nongpl]" markdown`). The installer's
full-screen tests drive `install.py --tui` on a pseudo-terminal and read the
screen back with `pyte`, and fuzz the key decoder with `hypothesis`: both skip
without them (`pip install pyte hypothesis`). `pip install -e ".[dev]"` from the
checkout installs all of these at once, from the `dev` extra of `pyproject.toml`,
which sets lower bounds only. The contributing guide's checklist reads the exact
versions CI pins from `validate.yml`.
No test framework beyond the standard library `unittest` module.

## Modules at a glance

Every module in `tests/`, by the area it guards.

| Area | Fixtures | Modules |
|------|----------|---------|
| Core regression suites | synthetic | `test_e2e`, `test_audit_regressions`, `test_tool_messages` |
| File resolution and identity | synthetic + collection | `test_adler32_resolution`, `test_agnostic_scan`, `test_agnostic_scan_mode`, `test_agnostic_scope`, `test_agnostic_substitute`, `test_archive_build`, `test_archive_choice`, `test_archive_recipes`, `test_bios_companions`, `test_bundled_identity`, `test_casefold_cache`, `test_db_aliases`, `test_declared_names`, `test_derivations`, `test_directory_entries`, `test_extra_identity`, `test_foreign_tree`, `test_foreign_tree_names`, `test_frontend_digest`, `test_game_data_homonyms`, `test_hashing`, `test_identity`, `test_maker_folder_names`, `test_md5_pack_context`, `test_name_tiebreak`, `test_nec_filing`, `test_np2_fonts`, `test_owner_resolution`, `test_path_suffix`, `test_proven_name`, `test_resolution_evidence`, `test_sega_filing`, `test_shipped_content`, `test_twin_declaration_status`, `test_twin_declarations`, `test_validated_choice`, `test_variant_choice`, `test_variant_identity`, `test_zipped_member` |
| Verification, cross-reference and profile checks | synthetic + profiles | `test_bios_layout`, `test_cache_independent_counts`, `test_case_insensitive_platforms`, `test_checks_have_values`, `test_content_checks`, `test_content_declarations`, `test_core_file_fills_declaration`, `test_core_size_refusal`, `test_cross_reference_sources`, `test_crypto_aes`, `test_crypto_unique_data`, `test_crypto_verify`, `test_data_only_refs`, `test_entry_categories`, `test_file_consumers`, `test_fileless_audit`, `test_flycast_layout`, `test_gap_settlement`, `test_hidden_extras`, `test_launcher_aliases`, `test_launcher_evidence`, `test_launcher_gaps`, `test_launcher_layer`, `test_launcher_paths`, `test_launcher_placement`, `test_native_mode`, `test_no_case_collisions`, `test_path_conflict_status`, `test_path_null_copies`, `test_profile_checks`, `test_profile_names`, `test_profile_paths`, `test_profile_repositories`, `test_romm_hash_rule`, `test_shared_groups`, `test_standalone_links`, `test_standalone_mode`, `test_undeclared_dedup`, `test_unplaced_extras`, `test_validation_scope`, `test_verify_all_dir`, `test_verify_data_dir_notice`, `test_verify_emulator_evidence`, `test_verify_listing`, `test_verify_pack_choice`, `test_verify_release_asset` |
| Packs and manifests | synthetic + real packs | `test_artifact_lock`, `test_atomic_artifacts`, `test_batocera_cores`, `test_core_data_trees`, `test_deterministic_zip`, `test_emulator_pack_counts`, `test_finalize_pack_names`, `test_large_file_cache`, `test_libretro_layout`, `test_manifest_entry`, `test_minui_platform`, `test_no_game_data`, `test_pack_conformance_dirs`, `test_pack_core_extras`, `test_pack_counts`, `test_pack_destinations`, `test_pack_failures`, `test_pack_file_names`, `test_pack_grouping`, `test_pack_integrity`, `test_pack_member_identity`, `test_pack_readme`, `test_platform_inheritance`, `test_platform_keys`, `test_release_packs`, `test_required_only_archives`, `test_required_only_twins`, `test_save_root`, `test_split_extras`, `test_split_names`, `test_split_pack`, `test_system_pack_extras`, `test_system_pack_parity`, `test_torrentzip`, `test_which_pack` |
| Slots and regions | synthetic + profiles | `test_region`, `test_region_agnostic_scan`, `test_region_groups`, `test_region_held`, `test_region_platform_index`, `test_region_required_only`, `test_slot`, `test_slots`, `test_slots_shipped_file` |
| Hardware targets and systems | synthetic + target files | `test_amberelec_targets`, `test_emuelec_targets`, `test_extract_targets`, `test_lakka_targets`, `test_libretro_slugs`, `test_system_ids`, `test_system_selection`, `test_target_names`, `test_target_scrapers`, `test_target_systems`, `test_target_verify` |
| Installer and downloads | loopback server | `test_check_release`, `test_download`, `test_install`, `test_install_cores`, `test_install_experience`, `test_install_expert`, `test_install_filesystems`, `test_install_app`, `test_install_from`, `test_install_games`, `test_install_journeys`, `test_install_offline`, `test_install_pack`, `test_install_removal`, `test_install_selection`, `test_install_tui`, `test_pypi_package` |
| Handheld launchers | a pty as the console, fake installer and firmware tools, stubbed PortMaster dialogs | `test_handheld_launchers`, `test_port`, `test_site_handheld` |
| Running cores | parsers on fixed inputs, a libretro core built from C in the test when a compiler exists | `test_core_probe` |
| Measurement records | synthetic record files, the committed `measurements/` against HEAD, the **Proof** line naming the BIOS a core ran, and that no page shows a Tested block, a region outcome or a time per frame | `test_measurements` |
| Real-condition campaign | synthetic profiles, records and content folders, a fake host for load, disk, clock and commands, and whole passes against a libretro core built from C when a compiler and strace exist | `test_campaign` |
| Region checks | the variants a region game runs under, the outcome read from synthetic records, the outcome sentence that never calls a built-in BIOS boot another region's, and that every system whose BIOS a profile ties to Japan, the US and Europe has a game per region in the content list or a reason | `test_region_check` |
| Standalone emulators | the release asset EmuDeck's rule picks, the AppImage offset, the Xvfb framebuffer reader, the settings written and the oracle the verdicts use, with no emulator run | `test_standalone_probe` |
| Pack probe | the cores a platform runs for a system, staging grown to a fixed point, runs mapped to pack and manifest entries, the line and its schema, the probe lock per run, that no page shows its lines. One class builds a real pack narrowed to PlayStation and lays it out both ways, from the archive and with `install.py --dest`, and skips without the collection | `test_pack_probe` |
| Automation runner, disk cleanup, asset sync and bit-flip repair | fake jobs, git repositories with a bare origin and session worktrees, a committed file with one bit flipped, canned CI runs in place of `gh` | `test_autorun` |
| Truth and native export | synthetic + cached originals | `test_export_counts`, `test_export_native_layer`, `test_export_report`, `test_exporters`, `test_truth_data_dir_readers`, `test_truth_diff`, `test_truth_layout` |
| Scrapers, upstream and provenance | inline sources, synthetic | `test_auto_fetch_lookup`, `test_batocera_md5_list`, `test_find_embedded`, `test_report_excerpt`, `test_check_freshness`, `test_cited_lines`, `test_contributing_text`, `test_coverage_cache`, `test_data_dir_refs`, `test_dataclass_defaults`, `test_dedup`, `test_doc_pages`, `test_doc_surfaces`, `test_elec_scrapers`, `test_fbneo_parser`, `test_find_pinned_revision`, `test_hash_merge`, `test_launchers`, `test_launchers_amberelec`, `test_launchers_emudeck`, `test_launchers_emuelec`, `test_launchers_knulli`, `test_launchers_recalbox`, `test_launchers_retrobat`, `test_launchers_retrodeck`, `test_launchers_retropie`, `test_launchers_rocknix`, `test_mame_devices`, `test_mame_parser`, `test_mame_ref_audit`, `test_optional_dependencies`, `test_pin_build`, `test_profile_sync`, `test_prose_style`, `test_provenance`, `test_refresh_data_dirs`, `test_refresh_failures`, `test_refresh_stale`, `test_retired_files`, `test_retrodeck_scraper_errors`, `test_romset_recipes`, `test_schema_semantic_gate`, `test_scraper_contract`, `test_site_agents`, `test_site_arcade_boards`, `test_site_availability`, `test_site_bootstrap`, `test_site_built_gate`, `test_site_components`, `test_site_console_folders`, `test_site_content_data`, `test_site_copy`, `test_site_cores`, `test_site_css`, `test_site_demo`, `test_site_density_cards`, `test_site_emulator_page`, `test_site_emulators`, `test_site_entry`, `test_site_entry_tables`, `test_site_exports`, `test_site_freshness`, `test_site_funnel`, `test_site_images`, `test_site_inputs`, `test_site_insights`, `test_site_integration`, `test_site_nav`, `test_site_page_text`, `test_site_picker`, `test_site_platform_density`, `test_site_platform_hashes`, `test_site_privacy`, `test_site_pronouns`, `test_site_reference`, `test_site_render`, `test_site_search`, `test_site_steps`, `test_site_system_links`, `test_site_system_names`, `test_site_system_sections`, `test_site_systems`, `test_site_validation`, `test_site_wanted`, `test_site_weight`, `test_site_wiki`, `test_site_write`, `test_source_ref_targets`, `test_upstream`, `test_upstream_index`, `test_validate_pr`, `test_validate_pr_flow`, `test_validate_pr_hashes`, `test_version_basis`, `test_workflow_paths` |
| Games on the card | small DATs, listxml and setup sources, a fake fetcher, fixture install lists, and the committed data against its schemas | `test_arcade_parents`, `test_game_catalogs`, `test_game_headers`, `test_game_regions`, `test_games_index`, `test_romfolders_card`, `test_romfolders_es` |

## Test architecture

### test_e2e.py

The main regression suite. `TestE2E` exercises the resolution, verification,
pack generation and cross-reference logic, and `StandaloneModeRequiresAStandaloneBuild`
sits beside it for the per-emulator build mode.

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

**test_mame_devices.** Tests the device ROM sets read from a MAME `-listxml`
and merged into a profile, on an inline listxml and driver source. Covers:

- Only `isdevice="yes"` sets with a dumped ROM kept, from a plain or zipped listxml
- The `ROM_START` block cited for a set: found through a ROM macro, a block
  inside a comment ignored, one dump under two names told apart, the label
  `device_rom_region` returns, not found and ambiguous
- Merge: a set added under the generated section in name order, a written
  entry's contents refreshed with its manual fields kept, BIOS root sets left
  as written, a second run changing nothing, a new BIOS root placed before the
  section
- Systems: the links the scan keeps (`romof`, `device_ref`, `slotoption`, a
  device's parent ROM device), a set reached through a clone, its parent and
  a slot card, one set under two systems, a machine no entry lists placing
  nothing, seeds read above the generated section only, `system:` or
  `systems:` written and rewritten by a refresh, a written entry's system
  kept, and a `--system` pick reading the entry's own systems through the gap
  report and the core extras
- Seeds a platform file states: a machine of the release under one of the
  profile's systems, a device, an unlisted system or a set stated two ways
  seeding nothing
- Support files: each software list filed under the systems whose machines
  and slot cards declare it, one entry per list of the delivered `hash/`
  tree, a pick keeping its lists and the unfiled ones, floppy samples filed
  through the form factor each drive selects (3" falls back to 3.5", the
  rest to 5.25"), a refresh rewriting the section and a second run changing
  nothing
- An entry's `system:` or `systems:` outside its profile's list refused by
  the semantic check

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

**test_profile_sync.** Covers ref anchoring end to end: the six statuses,
widening a one-line anchor until it is unique, refusing to rebase an ambiguous
one, following a rename, and the guarded YAML writes. Network access is
replaced by an injected fetch function.

**test_upstream.** Covers forge URL parsing for GitHub, GitLab and Forgejo,
the content-addressed cache and its atomic write, revision and tag resolution,
tree comparison and the listing of one directory. The HTTP layer is replaced at
module level, so nothing leaves the machine.

### Tests that read the working tree

Four modules assert on real repository data instead of fixtures. Each skips
when its input is missing, so a partial checkout still runs green.

**test_archive_build.** Reads `database.json` and `recipes/archives.json` and
fails when an archive has no recipe, when a recipe outlives its archive or
names another container, or when a recipe member is held nowhere in the
collection, neither as a loose file nor inside any archive. That list is the
acquisition list, printed by the failure, and it is empty today. With `bios/`
present it also holds each recipe against the archive's central directory:
names in order, sizes and crc32. Its fixture classes build an exact and a
canonical archive, refuse a mismatch without leaving a file, report a member
held nowhere as impossible, and never claim an exact build under zlib-ng.
After adding or changing an archive, `python scripts/romset_recipes.py
--capture` (pipeline step 1c) brings the recipes back in line.

**test_torrentzip.** Rebuilds real MAME romsets through the TorrentZip builder
and asserts the output is byte-identical, which is what keeps arcade ZIP hashes
stable across rebuilds.

**test_no_case_collisions.** Walks `bios/` and fails on two paths that differ
only by case. On Windows and macOS, git can only check out one of them, which
silently corrupts the clone. `.variants/` is exempt: those names are
disambiguated by a hash suffix on purpose.

**test_pack_integrity.** Described below. Needs packs in `dist/`.

## How to add a test

1. **Pick the right category.** Find the number range that matches the
   subsystem under test. If none fits, start a new range after the last
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

5. **Run the full suite.** After adding the test, run `python -m unittest
   discover -s tests -t . -v` to verify nothing else broke.

A new module starts with `import tests` right after
`from __future__ import annotations`. The package import is what keeps a run
offline, puts its scratch under `tmp/` and gives it its own installer cache,
however the module is started: `discover tests`, `python -m unittest
tests.test_e2e` or `python -m tests.test_e2e`. A test fails on any module
without it.

A fix comes with a test that fails without it. Write the test first, watch it
fail on the current code, then fix: a test written after the fix may never
have exercised the case it names. When a reading of the code finds a fact a
script could have established, the script gains that check in the same change.

Example skeleton:

```python
def test_my_new_behavior(self):
    # Minimal fixtures under self.root
    profile = {"emulator": "test_core", "type": "libretro", "files": [...]}
    with open(os.path.join(self.emulators_dir, "test_core.yml"), "w") as f:
        yaml.dump(profile, f)

    # The entry point the CLI uses
    config = load_platform_config("test_md5", self.platforms_dir)
    result = verify_platform(config, self.db, self.emulators_dir)

    # One outcome, read from the per-file details
    by_name = {d["name"]: d for d in result["details"]}
    self.assertEqual(by_name["my_file.bin"]["status"], Status.OK)
```

### test_pack_integrity.py

End-to-end pack verification. Extracts each platform ZIP to `tmp/` (in the
repo, not `/tmp` which is tmpfs on WSL) and verifies that every file declared
in the platform YAML:

1. Exists at the correct path on disk after extraction
2. Has the correct hash per the platform's native verification mode

Handles inner ZIP verification for MAME/FBNeo ROM sets (checkInsideZip,
md5_composite, inner ROM MD5) and path collision deduplication.

One test walks every platform the registry knows, each a subtest, rather than
a list written by hand: eight names were once written out, and ROCKNIX and
MiSTer FPGA, both released, were never checked. A platform with no pack in
`dist/` is skipped, and so is a pack older than a profile it depends on.

```bash
python -m unittest tests.test_pack_integrity -v
# or via CLI:
python scripts/generate_pack.py --all --verify-packs --output-dir dist/
```

The pipeline runs the same check as step 6, after the consistency check and
before the README. It needs packs in `dist/`, and `--skip-packs` skips it.

### test_handheld_launchers.py

The launchers in `ports/`: the PortMaster port, the Batocera and Knulli
port, the muOS app and the Tools entry, all built on `ports/shared/tui.txt`.
`bash -n` and `shellcheck` on every script (skipped where shellcheck is not
installed), the gptokeyb and evmapy mappings decoded by the interface's own
key decoder, and the four archives `scripts/build_port.py` writes (layout,
reproducibility, the bundled `install.py` equal to the one `install.sh`
pins).

Each launcher then runs from its extracted archive on a simulated device: a
pseudo-terminal stands for the console, and fakes stand for `install.py`,
gptokeyb and gptokeyb2 (each killing the way its source does), setfont,
chvt, curl, sudo, foot, xterm, muxterm, PortMaster's `control.txt` and
muOS's `retro.sh`. The checks: gptokeyb's kill reaches only the Start +
Select sentinel and the interface then stops with its result written, the
console's settings and font are put back, an offline run says so at once,
picks the pack of its system from the card or says where to put one, and
each firmware's terminal is the one used. The fakes also fail: a mapper that
dies, a chvt the compositor refuses, a terminal app that cannot open, a
read-only card. None of these may leave a console waiting for a button.
What reaches the screen and the pad on a real device is not exercised.

```bash
python -m unittest tests.test_handheld_launchers -v
```

### test_port.py

The PortMaster port's fallback screens, drawn by pugwash, and its event
reader. The screens run in bash with PortMasterDialog's functions replaced by
stubs that record each command and answer from a script, against a fake
`install.py` whose event streams follow `EVENT_KEYS`: all files present, some
missing (update everything, choose systems), no network with and without a
pack on the card, no BIOS folder detected, Python too old, and an answer that
arrives after the 30-second wait of the older PortMaster releases. Drawing,
the pad, `mount` and the network belong to a device and are not exercised.

```bash
python -m unittest tests.test_port -v
```

## Verification discipline

The test suite is one layer of verification. The full quality gate is:

1. All unit tests pass (`python -m unittest discover -s tests -t .`)
2. The full pipeline completes without error (`python scripts/pipeline.py --offline`)
3. No unexpected CRITICAL entries in the verify output
4. Pack file counts match verification file counts (consistency check)
5. Pack integrity passes (every declared file extractable with correct hash)
6. `npm run build --prefix website` and `python scripts/validate_site.py` pass

A change to the site engine, its version, its search ranking or the page
weights is measured on a served build before it lands, with the scripts in
`website/tools/` (they need `npm install --no-save playwright-core axe-core
lighthouse` and Chrome):

- `search_gate.py`: the queries a visitor types and the page that must answer
  each, read from the site's own search box
- `lighthouse.py`: Lighthouse mobile on a list of pages, the heaviest ones
  included
- `axe.mjs`: WCAG 2.2 AA in light and dark
- `check_tools.mjs`: the hash lookup, the file picker, a hash typed in the
  search, breadcrumbs, previous and next across tabs, glossary terms, tables
  on a phone and the 404 page, in a real browser
- `serve.mjs`: the build served under /retrobios/ with gzip, as GitHub Pages
  serves it

A change that passes the tests but breaks the pipeline is not merged. A new
CRITICAL entry in the verify output after a change is explained before the
change lands. The steps agree with each other: when verify reports N files for
a platform, the pack holds exactly N files.

Tests, code, profiles, platform configs and documentation ship in the same
change.

A run that dies with a segmentation fault or an exception the code cannot
raise is run again once, alone, before anything is investigated. Only a
failure that reproduces is a defect in the code.

## Prose and tone

`tests/test_prose_style.py` holds every tracked file, and the generated site,
to the way the project writes:

- No em-dash or en-dash, no semicolon joining two clauses, no unicode arrows,
  no ellipsis character, no box-drawing banners, no emoji or check marks.
  Rewrite the sentence rather than swapping the character.
- None of the marketing vocabulary the test lists, and no superlatives. A
  number with its criterion says more.
- Headings in sentence case, never repeating the site name.
- In emulator profiles, no verdict on another project's file: "phantom",
  "misleading", "bogus", "typo", "has errors", "incorrectly says", and on a
  line naming a .info, core-info or System.dat no "is correct", "is
  accurate", "still declares", "omits" or "missing". The note states what
  that file declares and what the code reads.
- No pointer at a review in a comment, a docstring or a test name: a review
  number in parentheses, a note file named after one, a test module or class
  named after a review. The comment says what the code does.

Formatting stays: bold labels, lists, tables and admonitions make a page
easier to use. When markup shows raw on the site, the rendering is fixed and
the formatting kept.

Beyond those words the test cannot read tone. Text that names another
project says what changes, not who erred: "hash updated to the emulator source", "files added",
"required flags aligned with the code". No "wrong", "bogus" or "phantom" about
someone else's work. Notes in a profile say what the core does, nothing about
what it is not. A reply on an issue or a pull request thanks once, gives the
facts, describes the script or the file rather than the person, and leaves
the door open.

### Pages for newcomers

The Start here pages and the guide part of each setup page are read by someone
who knows nothing about BIOS files, often on a phone. Each word costs that
reader attention, so `tests/test_site_copy.py` holds them to numbers measured
on the generated pages in `website/src/content/docs/`, code blocks left out:

| Budget | Start here | Setup guide |
|--------|-----------:|------------:|
| Longest sentence | 20 words | 25 words |
| Median sentence | 12 words | 14 words |
| Longest paragraph, list item or definition | 35 words | 40 words |
| Words before the first button or command | 50 (home page 40) | 90 |
| Items in one list | 5 | 6 |
| Heading | 8 words | 8 words |

Each Start here page has its own ceiling (home 220 words, FAQ 450), a setup
guide 220 and the setup index 300. Of a group of tabs only the first counts
toward a page's words, since a reader opens one. A folded block counts toward
the words, not toward what comes before the first command.

The same test refuses filler ("simply", "just", "in order to", "this page",
"what follows") and words a newcomer does not know yet, unless the sentence
explains them: "Termux, a terminal app", "SSH, a terminal over the network",
"its hash, a fingerprint of its contents". A word that needs more than that
(manifest, libretro, revision, standalone) belongs one level down, behind a
link labelled with that level ("Details:", "Reference:"). On Start here pages
a pack is a ZIP and a platform is a setup.

The reasons: a reader holds about four things at once, scans more than reads,
and reads less on a phone. Facts a newcomer does not act on (legal analysis,
source lines, annotated runs) are kept, on the page one level down. To see
the numbers of every page, run
`python -m tests.test_site_copy --report website/src/content/docs`.

### Adding a wiki page

A page in `wiki/` is published as soon as it exists, and its front matter
places it in the navigation. No Python changes.

```yaml
---
level: explore           # its tab: start, setup, explore, reference or contribute
order: 35                # its place in the tab, the smallest first
nav_title: Save files    # only when the menu names it otherwise than its heading
---
```

- `level` picks the tab and the label shown at the top of the page.
- `order` sorts the tab. Pages are spaced by ten, so a new page fits between
  two without renumbering. The generated pages (systems, emulators, the gaps
  and data pages) hold fixed places among them, set in `generate_nav`.
- `nav_title` is the menu label. Without it the menu shows the page's `# `
  heading, which is the rule: a page keeps one name in the menu, its heading
  and the links to it. It is not `title`, which both MkDocs and Astro
  Starlight read as the page's own title.
- `group` places a Reference page under a group of that tab, such as
  `Checking files` or `Data`.
- `nav: false` keeps a page out of the menu on purpose.

`python scripts/generate_site.py` stops with the page's name when `level` or
`order` is missing, or when two pages of a tab take the same `order`.
`tests/test_site_content_data.py` checks the same on every page in `wiki/`.

## Landing a change

A commit subject is English, 50 characters at most, `type: description` with a
lowercase word after the colon. The types are `feat`, `refactor`, `chore`,
`docs` and `fix`. The message does not use bug, regression, revert, dead code,
broken, wrong, hack, workaround or implement (derived forms included), nor the
marketing vocabulary above, and carries no Co-Authored-By trailer. It says
what the change does, never which review asked for it: "review 3", "audit 12"
or "round 5" with its number points at notes no clone holds and is refused. A
body explains the why when the subject cannot: the scenario that failed, the
upstream `file:line` that decides it, what users will see.

```
feat: add retrobat platform support
refactor: extract shared utils to common.py
```

`scripts/commit_rules.py` holds these rules. Git does not copy hooks with a
clone, so the commit-msg hook that runs them is set up once per clone:

```bash
printf '#!/bin/sh\nexec python3 scripts/commit_rules.py "$1"\n' > .git/hooks/commit-msg
chmod +x .git/hooks/commit-msg
```

Files are staged by name, never with `git add -A` or `git add .`, which sweep in
deletions and other people's work. Generated artifacts (`database.json`,
`retired.json`, `derivable.json`, `install/*.json`, `README.md`, `CONTRIBUTING.md`, `exports/`,
the generated tables and run samples of `wiki/installer.md`) are committed
with the data they derive from, never alone: a manifest committed before the
files it points at gives the installer a 404. The run samples count what the
manifests hold, so `generate_installer_doc.py` runs after every manifest
regeneration and its output goes in the same commit.

## CI integration

The `validate.yml` workflow runs `python -m unittest discover -s tests -t . -v` on both
roads into main: every pull request, and every direct push, that touches
`bios/`, `platforms/`, `emulators/`, `schemas/`, `scripts/`, `tests/`,
`ports/`, the installer and its bootstraps, or an input of the site build such
as `wiki/` or `measurements/`. The `paths:` lists of `validate.yml` are the
reference, and `tests/test_workflow_paths.py` holds them to the site's inputs. The same job then
generates the site before the suite, since the tests read its pages, and builds
it with `npm run build --prefix website` after, so a page that would fail the
deploy fails the pull request. Work reaches main by push as often as by pull request, so a suite
wired to pull requests alone would guard the road nobody takes. The test job
(`run-tests`) runs in parallel with schema validation, and on a pull request
with BIOS validation and auto-labeling too. Those two read pull request context
and stay behind an event guard.

The schema job also runs mypy over `install.py` and `scripts/`. The code
carried 993 type errors when the check started, so they sit in
`mypy-baseline.txt` and only a new one fails. An error the change removes fails
too until the baseline is synced, so the file never hides a later error that
reads the same:

```bash
pip install -e ".[dev]"
mypy > tmp/mypy.txt
mypy-baseline filter < tmp/mypy.txt   # what CI runs
mypy-baseline sync < tmp/mypy.txt     # after a fix, commit the new baseline
```

A push series collapses to the tip, so what a green run states is that the head
of main passes, not every commit under it.

Modules that need real artifacts skip themselves when those artifacts are absent,
so `test_pack_integrity` is a no-op in CI (no `dist/`) and a real check locally.
The exporter fidelity cases go the other way: they compare with each platform's
own file, which `python scripts/export_native.py --all --refresh-cache`
downloads into `.cache/upstream-native/`. CI runs it before the suite, and a
clone without that cache skips them.
Run `python -m unittest discover -s tests -t .` before pushing.

Tests must pass before merge. If a test fails in CI, reproduce locally with:

```bash
python -m unittest discover -s tests -t . -v
```
