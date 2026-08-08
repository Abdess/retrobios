# Contributing to RetroBIOS

## Add a BIOS file

1. Fork this repository
2. Place the file in `bios/Manufacturer/Console/filename`
3. Variants (alternate hashes for the same file): `bios/Manufacturer/Console/.variants/`
4. Open a Pull Request - hashes are verified automatically and reported as a comment

The [dump provenance](https://abdess.github.io/retrobios/provenance/) page lists catalogued dumps still
missing from the collection, with their hashes. A file matching one of those is
the most useful contribution.

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
- Files >50 MB go in GitHub release assets (`large-files` release)
- RPG Maker and ScummVM directories are excluded from deduplication
- Two paths differing only by case break clones on Windows and macOS;
  `tests/test_no_case_collisions.py` enforces this

## Before opening a PR

```bash
python -m unittest discover tests
python scripts/pipeline.py --offline
```

## PR validation

CI computes SHA1/MD5/CRC32 for every new file, checks them against the platform
configs, validates the YAML against the schemas, runs the test suite, and posts
a report on the PR.

Contributors who add platform support are credited in the README,
on the documentation site, and in the BIOS packs.
