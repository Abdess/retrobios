# Release Process

This page documents the CI/CD pipeline: what each workflow does, how releases
are built, and how to run the process manually.

## CI workflows overview

The project uses 4 GitHub Actions workflows. All use only official GitHub
actions (`actions/checkout`, `actions/setup-python`, `actions/upload-pages-artifact`,
`actions/deploy-pages`). No third-party actions.

Budget target: ~175 minutes/month on the GitHub free tier.

| Workflow | File | Trigger |
|----------|------|---------|
| Build & Release | `build.yml` | Push to `bios/**` or `platforms/**`, manual dispatch |
| Deploy Site | `deploy-site.yml` | Push to main (platforms, emulators, provenance, wiki, scripts, database.json, mkdocs.yml), manual |
| PR Validation | `validate.yml` | PR touching `bios/**`, `platforms/**` or `emulators/**` |
| Weekly Sync | `watch.yml` | Cron Monday 06:00 UTC, manual dispatch |

## build.yml - Build & Release

Currently disabled (`if: false` on the release job) until pack generation is
validated in production.

**Trigger.** Push to `main` on `bios/**` or `platforms/**` paths, or manual
`workflow_dispatch` with optional `force_release` flag to bypass rate limiting.

**Concurrency.** Group `build`, cancel in-progress.

**Steps:**

1. Checkout, Python 3.12, install `pyyaml`
2. Run `test_e2e`
3. Rate limit check: skip if last release was less than 7 days ago (unless
   `force_release` is set)
4. Restore large files from the `large-files` release into `.cache/large/`
5. Refresh data directories (`refresh_data_dirs.py`)
6. Build packs (`generate_pack.py --all --output-dir dist/`)
7. Split any pack over 2 GB into `.zip.001`, `.zip.002`, ... volumes. GitHub
   caps release assets at 2 GB, and the `.001` convention is what 7-Zip and
   PeaZip open directly (they reject `.partNN` names as corrupt)
8. Create GitHub release with tag `v{YYYY.MM.DD}` (appends `.N` suffix if
   a same-day release already exists)
9. Clean up old releases, keeping the 3 most recent plus `large-files`

**Release notes** include file count, total size, per-pack sizes, the extract
path per platform, and the last 15 non-merge commits touching `bios/` or
`platforms/`.

**Pack variants.** The workflow builds full packs only. Releases that also
carry `*_Platform_BIOS_Pack.zip` had a second `--source platform` run added by
hand, as in the manual process below. See
[advanced usage](advanced-usage.md#pack-source-variants).

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
7. Upload artifact, deploy to GitHub Pages

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

**Trigger.** Pull requests that modify `bios/**`, `platforms/**` or
`emulators/**`.

**Concurrency.** Per-PR group, cancel in-progress.

Four parallel jobs:

**validate-bios.** Diffs the PR to find changed BIOS files, runs
`validate_pr.py --markdown` on each, and posts the validation report as a PR
comment (hash verification, database match status).

**validate-configs.** Validates every platform YAML against
`schemas/platform.schema.json` and every emulator profile against
`schemas/emulator.schema.json`, using `jsonschema`. Fails if any file does not
match. `*.old.yml` files are skipped: they are hash-scraper backups, not
profiles.

**run-tests.** Runs `python -m unittest tests.test_e2e -v`. Must pass before
merge.

**label-pr.** Auto-labels the PR based on changed paths:

| Path pattern | Label |
|-------------|-------|
| `bios/` | `bios` |
| `bios/{Manufacturer}/` | `system:{manufacturer}` |
| `platforms/` | `platform-config` |
| `scripts/` | `automation` |

## watch.yml - Weekly Platform Sync

**Trigger.** Cron schedule every Monday at 06:00 UTC, or manual dispatch.

**Flow:**

1. Scrape live upstream sources (System.dat, batocera-systems, es_bios.xml,
   etc.) and regenerate platform YAML configs
2. Auto-fetch missing BIOS files
3. Refresh data directories
4. Run dedup
5. Regenerate `database.json`
6. Create or update a PR with labels `automated` and `platform-update`

The PR contains all changes from the scrape cycle. A maintainer reviews and
merges.

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

## Manual release process

When `build.yml` is disabled, build and release manually:

```bash
# Run the full pipeline (DB + verify + packs + manifests + integrity + docs)
python scripts/pipeline.py

# Or step by step:
python scripts/generate_db.py --force --bios-dir bios --output database.json
python scripts/verify.py --all
python scripts/generate_pack.py --all --output-dir dist/                    # full packs
python scripts/generate_pack.py --all --source platform --output-dir dist/  # platform packs
python scripts/generate_pack.py --all --verify-packs --output-dir dist/

# Split anything over 2 GB (GitHub asset cap)
for f in dist/*.zip; do
  [ "$(stat -c%s "$f")" -gt 2000000000 ] || continue
  split --bytes=1900M --numeric-suffixes=1 --suffix-length=3 "$f" "$f." && rm "$f"
done

# Create the release
DATE=$(date +%Y.%m.%d)
gh release create "v${DATE}" dist/*.zip* \
  --title "BIOS Pack v${DATE}" \
  --notes "Release notes here" \
  --latest
```

The two `generate_pack.py` runs are what puts both `*_BIOS_Pack.zip` and
`*_Platform_BIOS_Pack.zip` on the release. `--all-variants` builds all six
combinations instead, which is more than a release needs.

Run the pipeline online for a release: `--offline` skips the data directory
refresh and the MAME/FBNeo hash refresh, so the packs would ship stale data
directories.

To re-enable automated releases, remove the `if: false` guard from the
`release` job in `build.yml`.
