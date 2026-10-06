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
| Validation | `validate.yml` | PR and push to main touching `bios/**`, `platforms/**` or `emulators/**` |

Upstream BIOS lists are not scraped on a schedule. A maintainer runs the
scrapers by hand (see [adding a scraper](adding-a-scraper.md)), reviews the
diff, and commits the refreshed platform YAML. Releases are built on the
maintainer's machine and uploaded with `gh`, see
[cutting a release](#cutting-a-release): the packs weigh 25 GB, more than a
hosted runner should rebuild and re-upload.

## deploy-site.yml - Deploy Documentation Site

**Trigger.** Push to `main` when any of these paths change: `platforms/`,
`emulators/`, `provenance/`, `wiki/`, `schemas/`, `tests/`, `docs_assets/`,
`install/`, `install.py`, `database.json`, `release.json`, `mkdocs.yml`, the
workflow itself, and every script the build runs or imports. Also manual
dispatch.

The list is the set of inputs the site is generated from. A script that
`generate_site.py`, `generate_readme.py` or another build step starts to import
must be added to it, or the site silently goes stale;
`tests/test_workflow_paths.py` computes the import closure and fails when one
is missing.

**Steps:**

1. Checkout, Python 3.12
2. Install `pyyaml`, `jsonschema[format-nongpl]==4.26.0`,
   `mkdocs-material>=9.7.5,<10`, `pymdown-extensions>=10.14`
3. Run `validate_schemas.py`: the data contracts, checked before anything is
   generated (see below)
4. Restore large files from the `large-files` release, refresh data directories
5. Run `generate_site.py` (converts YAML data into MkDocs pages and rewrites
   `mkdocs.yml`)
6. Run `generate_readme.py` (rebuilds README.md and CONTRIBUTING.md)
7. `mkdocs build --strict` to produce the static site
8. Run `validate_site.py` on the rendered HTML (metadata, headings, image
   alternatives, duplicate ids, local links and fragments)
9. Require the committed README and CONTRIBUTING to match what the generator
   just produced. `write_if_changed()` compares content with the timestamp line
   stripped, so a run that only moves the clock leaves the files untouched and
   the check stays meaningful
10. Upload artifact, deploy to GitHub Pages

Data contracts are validated with `scripts/validate_schemas.py` at step 3, before
the site is generated. It refuses to run without the checkers for the `date-time`
and `uri` formats the schemas declare, which `jsonschema` only has with the
`format-nongpl` extra. It covers `database.json`, the install and target manifests, the site API
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

## validate.yml - Validation

**Trigger.** Pull requests and direct pushes to main that modify `bios/**`,
`platforms/**`, `emulators/**`, `schemas/**`, `scripts/**`, `tests/**` or
`install.py`. The path lists are spelled out once per event because the
workflow parser reads no YAML anchor.

**Concurrency.** Per-PR group on a pull request, per-ref on a push, cancel
in-progress either way: a push series collapses to the tip.

Four jobs, two of which read pull request context and carry an event guard:

**validate-bios** (pull requests only). Diffs the PR to find changed BIOS
files, runs `validate_pr.py --markdown` on each, and posts the validation
report as a PR comment (hash verification, database match status).

**validate-configs.** Runs `python scripts/validate_schemas.py --source-only`,
which validates every platform YAML against `schemas/platform.schema.json` and
every emulator profile against `schemas/emulator.schema.json`. Both schemas set
`additionalProperties: false`, so a typo in a field name fails the job instead
of being silently ignored.

**run-tests.** Runs `python -m unittest discover tests -v`. Must pass before a
merge, and again on the commit a direct push puts at the head of main.

**label-pr** (pull requests only). Auto-labels the PR based on changed paths:

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

**Asset name.** A gitignored path whose file name no other gitignored path
shares is published under that file name. When two paths share one, each is
published under its location below `bios/`, segments joined by `--` and any
character outside `A-Za-z0-9._-` replaced by `_`
(`Id_Software--Wolfenstein_Enemy_Territory--etmain--pak0.pk3`).
`asset_names()` in `scripts/largefiles.py` is the only place that rule lives;
the manifests, the fetcher and `check_release_assets.py` all read it.

**Upload.** To add or update a large file:

```bash
gh release upload large-files "bios/Sony/PS3/PS3UPDAT.PUP#PS3UPDAT.PUP"
```

The text after `#` is only a display label: the asset takes the uploaded
file's own name. A path whose asset name differs from its file name is
uploaded from a copy carrying the asset name.

**Local cache.** `generate_pack.py` calls `fetch_large_file()` which downloads
from the release and caches in `.cache/large/` for subsequent runs.

**Check.** The installer refuses a download whose `Content-Length` differs
from the manifest size, and the manifest size is that of the local file. A
file rebuilt locally after its upload therefore fails every install until it
is uploaded again (`--clobber`). `python scripts/check_release_assets.py`
compares every gitignored `bios/` path in the database with its asset, and the release page with the one it renders from the collection;
the online pipeline runs it as step 2b2. To refresh the page:

```bash
python scripts/check_release_assets.py --notes tmp/notes.md
gh release edit large-files --notes-file tmp/notes.md
```

An asset no database entry names is listed on the page under "Not indexed",
with its size only: the collection vouches for no hash it does not hold.

## Cutting a release

Releasing is deliberate and local. Nothing on GitHub builds a pack: the
pipeline runs here, the archives are checked here, and `gh` uploads them.

```bash
# 1. Full pipeline, online, so data directories and MAME/FBNeo hashes are fresh
python scripts/pipeline.py

# 2. RetroPie, which is archived but still served
python scripts/generate_pack.py --platform retropie --output-dir dist/
python scripts/generate_pack.py --platform retropie --verify-packs --output-dir dist/

# 3. A release file must be under 2 GiB. A larger pack becomes parts that are
#    each a ZIP of whole files (Pack.part1of2.zip): any tool opens one, and
#    the parts extracted into one folder are the pack. Each part is read back
#    and the set compared with the pack before the pack is removed.
python scripts/split_pack.py dist/

# 4. Checksums of the files as published, then sign the list. The checksums
#    answer corruption; the signature answers a rewritten release, which is
#    the one thing a checksum published beside its own artifacts cannot
#    answer.
(cd dist && sha256sum *.zip > SHA256SUMS.txt)
ssh-keygen -Y sign -f ~/.ssh/retrobios_signing -n file dist/SHA256SUMS.txt

# 5. Record what each pack holds, read from the archives just checked:
#    file count, extracted size, download size, published files. The README
#    and the site print these beside the download links, and the notes table
#    takes its Size and Files columns from the same lines. The command stops
#    if an archive does not hold the count its install manifest expects.
DATE=$(date +%Y.%m.%d)
python scripts/release_record.py dist/ --tag "v${DATE}"
python scripts/generate_readme.py --db database.json --platforms-dir platforms
python scripts/generate_site.py

# 6. Create the release as a DRAFT, upload every asset, and only then publish it.
#    A public release with half its assets is a broken download for everyone
#    during the whole upload.
gh release create "v${DATE}" --draft --title "BIOS Pack v${DATE}" --notes-file notes.md
for f in dist/SHA256SUMS.txt dist/SHA256SUMS.txt.sig dist/*.zip; do
  [ -f "$f" ] && gh release upload "v${DATE}" "$f#$(basename "$f")" --clobber
done
gh release view "v${DATE}" --json assets --jq '.assets | length'   # expect every file
gh release edit "v${DATE}" --draft=false --latest

#    The record and the pages it feeds go to main with the release, so the
#    table never describes a pack other than the one the link serves.
git add release.json README.md mkdocs.yml
git commit -m "chore: record release v${DATE}" && git push

# 7. Keep only the new release plus large-files: an older pack carries hashes
#    the platforms no longer check, so it misleads more than it helps
gh release list --json tagName,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[].tagName' | grep -v '^large-files$' \
  | tail -n +2 | while read tag; do gh release delete "$tag" --yes --cleanup-tag; done
```

## Verifying a release

`SHA256SUMS.txt` is signed with a key used for nothing else. Its public half
is `allowed_signers` at the repository root, so anyone can check a download
without trusting the release page it came from:

```bash
gh release download --pattern 'SHA256SUMS.txt*' --pattern 'RetroArch_BIOS_Pack.zip*'
curl -fsSLO https://raw.githubusercontent.com/Abdess/retrobios/main/allowed_signers

ssh-keygen -Y verify -f allowed_signers -I releases@retrobios -n file \
  -s SHA256SUMS.txt.sig < SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
```

The first command must print `Good "file" signature for releases@retrobios`.
Order matters: verify the list before trusting the sums in it. The list names
every file as published, so a single part checks on its own. Releases up to
v2026.09.04 listed the whole ZIPs instead, and their `.zip.001` volumes have
to be joined before checking.

The signature and the reproducible build answer different questions. The
signature says the list came from the holder of the release key. The build
says the bytes are derivable: packs are deterministic and a part copies its
members as stored, so rebuilding and splitting from the same collection
yields the same files, and their checksums can be compared against the
signed list without trusting either.

The private half lives on the maintainer's machine and is generated with
`ssh-keygen -t ed25519 -f ~/.ssh/retrobios_signing -C releases@retrobios`. Its
public half is registered as a GitHub signing key, so a verifier who would
rather not take `allowed_signers` on trust can cross-check it against
`https://api.github.com/users/Abdess/ssh_signing_keys`: the two carry the same
fingerprint, `SHA256:jUcTBhDS5DhmheXuVhAzh3pb04uI0caOAaiZzWXvrk4`.

Rotating the key means committing the new public half to `allowed_signers`
and keeping the retired line, so signatures on past releases keep verifying.

One pack per platform, the full one: the platform's list plus everything its
cores load. Platform-only and per-emulator packs are build options, not
release assets, since a lighter pack means a core that fails with no message.
The release notes follow the previous release: the quick install commands,
the pack table, what changed since the previous tag, and the contributors of
the closed issues. A pack has two sizes and they are far apart: Batocera
downloads as 2.4 GB and extracts to 4.0 GB. Step 5 prints both, and whichever
one the table carries, the header names it. Someone sizing a USB drive is
reading that column. The README table is the extracted size of the released
pack, from `release.json`. `SHA256SUMS.txt` lists the checksums of the files
as published, parts included.

`release.json` is the record step 5 writes: per pack, the files it holds, its
two sizes and the files it is published in. It exists because the pages are
regenerated on every push while a release is cut every few weeks. Read from
the install manifests, the table gave the count main would build that day:
a commit adding 3 700 files to the RetroArch pack moved it to 8 225 while
the download still held 4 525.

A pack in parts is said so above the table, where the links are: every part
is needed, each is an ordinary ZIP, and they extract into the same folder.
Until v2026.09.04 the parts were byte ranges cut by `split`, named
`.zip.001`, and the sentence explaining them sat under the table. A range
opened alone is not an archive and no tool says a part is missing, so five
reports in six months took one for a broken download (issues 45, 51, 66, 77
and 79). The README, the download page and the troubleshooting page describe
both layouts for as long as a release cut that way is still published; once
step 7 has deleted it, the `.zip.001` paragraph leaves those three pages.

The table carries a Files column, the count step 5 prints, and the
notes never open on the size of the collection. That total covers every
platform and emulator together and no pack holds it: v2026.09.04 led with
"10,330 files" right after "one pack per platform", and someone who extracted
the complete RetroArch pack and counted 4,525 reported half of it missing.
The collection total belongs under "What's new", worded as the collection.
