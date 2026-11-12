# Contributing to RetroBIOS

## Add a BIOS file

Have a file the collection lacks? Add it from the browser. It is checked on arrival.

[Upload it into `bios/`](https://github.com/Abdess/retrobios/upload/main/bios), 25 MB at most per file. GitHub
writes it to a fork and opens the pull request.

The files most wanted are on [what the packs do not hold](https://abdess.github.io/retrobios/gaps/). The
[dump provenance](https://abdess.github.io/retrobios/provenance/) page lists catalogued dumps still
missing from the collection, with their hashes. A file matching one of those is
the most useful contribution.

## What happens next

1. CI hashes the file and looks it up in every platform list and emulator
   profile. For a file it recognises, it names the folder holding the other
   files of its system. The report is in the summary of the pull request's
   Validation run.
2. The file can be moved to that folder in the same pull request. A file whose
   hash differs from the one already held under its name goes to that folder's
   `.variants/`.

A ZIP that no list declares as a whole is read file by file, and the report
says which of them the collection already holds: upload the files
themselves, unzipped.

From a clone, the file goes to `bios/Manufacturer/Console/filename`, and
`python scripts/validate_pr.py path/to/file` names that folder for a file still
outside `bios/`, and `--place` copies it there under its declared name. Given a
folder, such as an old card's BIOS folder, it checks every file under it. A
file over the browser's 25 MB limit goes in that way, up to the 100 MB GitHub
accepts in a push. A larger file stays out of the pull request: [open an
issue](https://github.com/Abdess/retrobios/issues/new?template=missing-bios.yml) with the hashes `validate_pr.py` prints, and a
maintainer adds it to the `large-files` release.

## Add a platform

1. Write a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source to determine how it checks BIOS files
3. Register it in `platforms/_registry.yml`
4. Generate the platform YAML and test: `python scripts/verify.py --platform <name>`

Full walkthrough: [adding a platform](https://abdess.github.io/retrobios/wiki/adding-a-platform/).

## Add an emulator profile

1. Clone the emulator's source code, upstream and libretro port
2. Trace the file loading from the entry point, not from a keyword grep
3. Document every file the code loads, with a `source_ref` line reference
4. Write the YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

Full walkthrough: [profiling guide](https://abdess.github.io/retrobios/wiki/profiling/).

## File conventions

- `bios/Manufacturer/Console/filename` for canonical files
- `bios/Manufacturer/Console/.variants/filename.sha1prefix` for alternate versions
- A file too large for git goes to the `large-files` GitHub release and its
  path into `.gitignore`, the list that decides what is served from the release
- Trees addressed by path are kept out of deduplication (`NODEDUP_DIRS` in
  `scripts/dedup.py`)
- Two paths differing only by case break clones on Windows and macOS,
  and `tests/test_no_case_collisions.py` enforces this

## Before opening a PR

A pull request that only adds files under `bios/` needs none of this: the
validation above is its check. For code, profiles or platform files, these are
the checks CI runs on a pull request (Python 3.12 or newer):

```bash
pip install pyyaml "jsonschema[format-nongpl]==4.26.0" "markdown==3.10.2" "pyte==0.8.2" "hypothesis==6.170.8" "vermin==1.9.2" "setuptools==80.9.0" "uv==0.13.4"
python scripts/pr_checks.py
```

`pr_checks.py` runs these, in CI's order, carries on past a failure as CI
does, and names at the end each check that failed or could not run:

```bash
python scripts/validate_pr.py --changed                  # the BIOS files the branch adds
python scripts/validate_schemas.py --source-only         # profiles and platform files
mypy | mypy-baseline filter --no-colors                  # no type error beyond mypy-baseline.txt
python scripts/profile_sync.py --added --strict          # each profile the branch adds
vermin --no-tips -t=3.8- --violations install.py         # install.py stays on Python 3.8
shellcheck --version                                     # the launcher test runs shellcheck
python scripts/export_native.py --all --refresh-cache    # files the exporter tests compare with
python scripts/refresh_data_dirs.py                      # data directories the pack-building tests read
python scripts/generate_site.py                          # the pages the site tests read
npm ci --prefix website                                  # the site's packages, Node 24
npm run build --prefix website                           # the built site
python scripts/run_tests.py --jobs 4                     # the suite, one process per module
python3.8 -m unittest tests.test_install_tui             # the full screen on the installer's floor
python scripts/validate_site.py --site-dir website/dist  # links and page budgets
```

The versions are the ones CI pins. Three tools come from the system, not from
that line, and the tests that need them skip without them: `shellcheck` for the
handheld launchers, `bwrap` (bubblewrap) for the probe sandbox, and a Python 3.8
with pyte (`python3.8 -m pip install "pyte==0.8.2"`) for the full screen. CI has all three.

`profile_sync.py` compares the branch with this repository's `main`, and
fetches it in a fork's clone. An edited profile is not held to
`--strict`: its older refs are reviewed by hand.

The full pipeline is not needed for a contribution: it rebuilds every pack
in `dist/`, which is why maintainers run it before a release.

## PR validation

CI computes SHA1/MD5/CRC32 for every new file, checks them against the platform
configs, validates the YAML against the schemas, confronts each added profile
with its upstream source and runs the test suite. The BIOS report goes to the
summary of the Validation run, and also to a comment when the branch lives in
this repository: a fork's pull request runs with a read-only token.

Contributors who add platform support are credited in the README,
on the documentation site, and in the BIOS packs.
