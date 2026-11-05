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

From a clone, the file goes to `bios/Manufacturer/Console/filename`, and
`python scripts/validate_pr.py path/to/file` names that folder for a file still
outside `bios/`. Given a folder, such as an old card's BIOS folder, it checks
every file under it. A file over the browser's 25 MB limit goes in that way.

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
pip install pyyaml "jsonschema[format-nongpl]" markdown
python scripts/validate_pr.py --changed          # the BIOS files the branch adds
python scripts/validate_schemas.py --source-only # profiles and platform files
python scripts/profile_sync.py --changed --strict  # each profile the branch adds or edits
python scripts/refresh_data_dirs.py  # data directories the pack-building tests read
python scripts/generate_site.py       # the pages the site tests read
python -m unittest discover -s tests -t .
```

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
