# Release Process

This page documents the CI/CD pipeline: what each workflow does, how releases
are built, and how to run the process manually.

## CI workflows overview

The project uses 2 GitHub Actions workflows. All use only official GitHub
actions (`actions/checkout`, `actions/setup-python`, `actions/upload-pages-artifact`,
`actions/deploy-pages`). No third-party actions.

Budget target: ~175 minutes/month on the GitHub free tier.

| Workflow | File | Trigger |
|----------|------|---------|
| Deploy Site | `deploy-site.yml` | Push to main (platforms, emulators, provenance, wiki, scripts, database.json, mkdocs.yml), manual |
| PR Validation | `validate.yml` | PR touching `bios/**`, `platforms/**` or `emulators/**` |

Upstream BIOS lists are not scraped on a schedule. A maintainer runs the
scrapers by hand (see [adding a scraper](adding-a-scraper.md)), reviews the
diff, and commits the refreshed platform YAML. Releases are built on the
maintainer's machine and uploaded with `gh`, see
[cutting a release](#cutting-a-release): the packs weigh 25 GB, more than a
hosted runner should rebuild and re-upload.

## deploy-site.yml - Deploy Documentation Site

**Trigger.** Push to `main` when any of these paths change: `platforms/`,
`emulators/`, `provenance/`, `wiki/`, `scripts/generate_site.py`,
`scripts/generate_readme.py`, `scripts/verify.py`, `scripts/common.py`,
`database.json`, `mkdocs.yml`. Also manual dispatch.

The list is the set of inputs the site is generated from. Adding a new input to
`generate_site.py` means adding its path here, or the site silently goes stale.

**Steps:**

1. Checkout, Python 3.12
2. Install `pyyaml`, `mkdocs-material>=9.7.5,<10`, `pymdown-extensions>=10.14`
3. Restore large files from the `large-files` release, refresh data directories
4. Run `generate_site.py` (converts YAML data into MkDocs pages and rewrites
   `mkdocs.yml`)
5. Run `generate_readme.py` (rebuilds README.md and CONTRIBUTING.md)
6. `mkdocs build --strict` to produce the static site
7. Run `validate_site.py` on the rendered HTML (metadata, headings, image
   alternatives, duplicate ids, local links and fragments)
8. Require the committed README and CONTRIBUTING to match what the generator
   just produced. `write_if_changed()` compares content with the timestamp line
   stripped, so a run that only moves the clock leaves the files untouched and
   the check stays meaningful
9. Upload artifact, deploy to GitHub Pages

Data contracts are validated with `scripts/validate_schemas.py` before the site
is generated: `database.json`, the install and target manifests, the site API
envelopes and the stats file, plus the semantic invariants those schemas cannot
express (declared totals matching their lists, no destination both installed
and omitted).

The site is deployed via the `github-pages` environment using the official
`actions/deploy-pages` action. Pages deployments are queued rather than
cancelled (`cancel-in-progress: false`): cancelling one mid-flight leaves the
deployment stuck and the next runs time out waiting on it.

`--strict` turns MkDocs warnings into failures, so a broken internal link or a
dangling anchor fails the build instead of shipping. The `validation:` block in
`mkdocs.yml` is what promotes unrecognized links and missing anchors to
warnings in the first place.

The theme version is pinned on both sides: `>=9.7.5` because that is the
release which caps `mkdocs < 2` (MkDocs 2.0 ships without a license), `<10`
so a major theme release cannot change the site without a deliberate bump.

## validate.yml - PR Validation

**Trigger.** Pull requests that modify `bios/**`, `platforms/**`,
`emulators/**`, `schemas/**`, `scripts/**`, `tests/**` or `install.py`.

**Concurrency.** Per-PR group, cancel in-progress.

Four parallel jobs:

**validate-bios.** Diffs the PR to find changed BIOS files, runs
`validate_pr.py --markdown` on each, and posts the validation report as a PR
comment (hash verification, database match status).

**validate-configs.** Runs `python scripts/validate_schemas.py --source-only`,
which validates every platform YAML against `schemas/platform.schema.json` and
every emulator profile against `schemas/emulator.schema.json`. Both schemas set
`additionalProperties: false`, so a typo in a field name fails the job instead
of being silently ignored.

**run-tests.** Runs `python -m unittest discover tests -v`. Must pass before
merge.

**label-pr.** Auto-labels the PR based on changed paths:

| Path pattern | Label |
|-------------|-------|
| `bios/` | `bios` |
| `bios/{Manufacturer}/` | `system:{manufacturer}` |
| `platforms/` | `platform-config` |
| `scripts/` | `automation` |

## Large files management

Files larger than 50 MB are stored as assets on a permanent GitHub release
named `large-files` (to keep the git repository lightweight).

Examples: PS3UPDAT.PUP, PSVUPDAT.PUP, PSP2UPDAT.PUP, the DSi NAND images,
maclc3.zip, Firmware.19.0.0.zip (Switch), the QEMU EDK2 firmware, the ScummVM
data bundle, the EasyRPG soundfont, the Dolphin/Ishiiruka SD card images, and
the arcade sets over 100 MB. `.gitignore` is the authoritative list: every
`bios/` path listed there is a release asset.

**Storage.** Listed in `.gitignore` so they stay out of git history. The
`large-files` release is excluded from cleanup (the build workflow only
deletes version-tagged releases).

**Build-time restore.** The build workflow downloads all assets from
`large-files` into `.cache/large/` and copies them to their expected paths
before pack generation.

**Upload.** To add or update a large file:

```bash
gh release upload large-files "bios/Sony/PS3/PS3UPDAT.PUP#PS3UPDAT.PUP"
```

**Local cache.** `generate_pack.py` calls `fetch_large_file()` which downloads
from the release and caches in `.cache/large/` for subsequent runs.

## Cutting a release

Releasing is deliberate and local. Nothing on GitHub builds a pack: the
pipeline runs here, the archives are checked here, and `gh` uploads them.

```bash
# 1. Full pipeline, online, so data directories and MAME/FBNeo hashes are fresh
python scripts/pipeline.py

# 2. The platform-only packs, and RetroPie, which is archived but still served
python scripts/generate_pack.py --all --source platform --output-dir dist/
python scripts/generate_pack.py --platform retropie --output-dir dist/
python scripts/generate_pack.py --platform retropie --source platform --output-dir dist/

# 3. The standalone emulators that no frontend bundles
python scripts/generate_pack.py --emulator mesence --output-dir dist/
python scripts/generate_pack.py --emulator lexaloffle --output-dir dist/

# 4. Every archive in dist/ extracted and hashed the way its platform checks it
python scripts/generate_pack.py --all --verify-packs --output-dir dist/

# 5. Split anything over 2 GB (GitHub asset cap); 7-Zip and PeaZip open .001 directly
for f in dist/*.zip; do
  [ "$(stat -c%s "$f")" -gt 2000000000 ] || continue
  split --bytes=1900M --numeric-suffixes=1 --suffix-length=3 "$f" "$f." && rm "$f"
done

# 6. Create the release, then keep the three most recent plus large-files
DATE=$(date +%Y.%m.%d)
gh release create "v${DATE}" dist/*.zip* dist/SHA256SUMS.txt \
  --title "BIOS Pack v${DATE}" --notes-file notes.md --latest
gh release list --json tagName,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[].tagName' | grep -v '^large-files$' \
  | tail -n +4 | while read tag; do gh release delete "$tag" --yes --cleanup-tag; done
```

The release notes follow the previous release: the quick install commands, the
full and platform pack tables with file counts and sizes, the standalone
packs, what changed since the previous tag, and the contributors of the
closed issues. `SHA256SUMS.txt` lists the checksums of the full ZIPs before
splitting.
