---
level: contribute
order: 50
---

# Release process

Two GitHub workflows check pull requests and publish the site. Releases are
built, checked and uploaded from the maintainer's machine.

## CI workflows overview

Both workflows use only official GitHub actions (`actions/checkout`,
`actions/setup-python`, `actions/setup-node`, `actions/configure-pages`,
`actions/upload-pages-artifact`, `actions/deploy-pages`), each pinned to a
commit. No third-party actions.

Budget target: ~175 minutes/month on the GitHub free tier.

| Workflow | File | Trigger |
|----------|------|---------|
| Deploy Site | `deploy-site.yml` | Push to main touching an input of the site, manual |
| Validation | `validate.yml` | PR and push to main touching the collection, the code, the tests, the installer, `ports/` or an input of the site |

Each workflow's `paths:` lists are the reference, and
`tests/test_workflow_paths.py` holds them to what the site build reads.

Upstream BIOS lists are not scraped on a schedule. A maintainer runs the
scrapers by hand (see [adding a scraper](adding-a-scraper.md)), reviews the
diff, and commits the refreshed platform YAML. Releases are built on the
maintainer's machine and uploaded with `gh`, see
[cutting a release](#cutting-a-release): the packs weigh 25 GB, more than a
hosted runner should rebuild and re-upload.

## deploy-site.yml - Deploy documentation site

**Trigger.** Push to `main` when an input of the site changes: the data
(`platforms/`, `emulators/`, `provenance/`, `exports/`, `measurements/`,
`database.json`, `release.json`, `derivable.json`, `install/`), the pages and
their assets (`wiki/`, `docs_assets/`, `website/`), the installer and its two
bootstraps the site serves, `tests/campaign/observations.yml` (the Proof lines
of the emulator pages), the workflow itself, and every script the build runs
or imports. Also manual dispatch.

The list is the set of inputs the site is generated from. A script that
`generate_site.py`, `generate_readme.py` or another build step starts to import
must be added to it, or the site silently goes stale.
`tests/test_workflow_paths.py` computes the import closure and fails when one
is missing.

### Steps

1. Checkout, Python 3.12
2. Install `pyyaml` and `jsonschema[format-nongpl]==4.26.0`, then Node 24 with
   the official `actions/setup-node` (npm cache keyed on the lockfile) and
   `npm ci --prefix website`
3. Run `validate_schemas.py`: the data contracts, checked before anything is
   generated (see below)
4. Restore large files from the `large-files` release, refresh data directories
5. Run `generate_site.py`: it writes the pages, the navigation and the data
   files into the Astro Starlight project in `website/`
6. Run `generate_readme.py` (rebuilds README.md and CONTRIBUTING.md)
7. `npm run build --prefix website` to produce the static site in
   `website/dist/`. The build runs `starlight-links-validator` with its
   strict defaults, so a dead link or anchor fails it
8. Run `validate_site.py --site-dir website/dist` on the rendered HTML
   (metadata, headings, image alternatives, duplicate ids, every local link
   and fragment again, page and search index budgets)
9. Run `tests.test_site_bootstrap`: the one-line installers the site serves
   pin their own `install.py`, and a copy that refuses every install stops
   the deploy, the last good pair staying served
10. Run `website/tools/search_gate.py`: the queries a visitor types must reach
    the page that answers them through the site's own search box, and the home
    page must stay under its weight budget
11. Require the committed README and CONTRIBUTING to match what the generator
   just produced. `write_if_changed()` compares content with the timestamp line
   stripped, so a run that only moves the clock leaves the files untouched and
   the check stays meaningful
12. Upload artifact, deploy to GitHub Pages

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

Two link checks run, and both fail the build: Starlight's validator inside
`astro build`, and `validate_site.py` over the rendered files. They read
different things (the content collection, the final HTML with its navigation
and breadcrumbs), and each has caught what the other passed.

Astro, Starlight and their plugins are pinned to exact versions in
`website/package.json`, resolved from the committed `website/package-lock.json`
by `npm ci`. Starlight is below 1.0 and Astro shipped two majors in 2026, so an
upgrade is its own change, built and measured with the scripts in
`website/tools/` (search queries, Lighthouse, axe, screenshots) before it
merges. Node runs only inside the site build: `install.py` and the build
scripts stay Python.

## validate.yml - Validation

**Trigger.** Pull requests and direct pushes to main that modify `bios/**`,
`platforms/**`, `emulators/**`, `schemas/**`, `scripts/**`, `tests/**`,
`install.py`, `install.sh` or `install.ps1` (the bootstraps pin the
installer's SHA-256, so editing one without the other fails the run),
`ports/**` (the handheld port bundles the installer), `packaging/**` (the PyPI
package is built from it), or any input of the site build. The path lists are spelled out once per event because the workflow
parser reads no YAML anchor, and a test holds the two equal.

**Concurrency.** Per-PR group on a pull request, per-ref on a push. A pull
request cancels its run in progress. A push to main does not: GitHub keeps one
pending run per group and replaces it with each newer push, so main always gets
a finished run and then its tip.

Five jobs, two of which read pull request context and carry an event guard:

**validate-bios** (pull requests only). Diffs the PR to find added,
modified or renamed BIOS files, runs `validate_pr.py --markdown` on them and
writes the report (hash verification, database match status) to the job
summary. The report is also posted as a PR comment when the branch lives in
this repository, since a fork's token cannot write one. The job fails after
the report when a file did not validate.

**validate-configs.** Runs `python scripts/validate_schemas.py --source-only`,
which validates every platform YAML against `schemas/platform.schema.json` and
every emulator profile against `schemas/emulator.schema.json`. Both schemas set
`additionalProperties: false`, so a typo in a field name fails the job instead
of being silently ignored.

**check-new-profiles.** Runs `profile_sync.py --added --base BASE --strict`,
which checks each profile the change adds (the files `git diff --diff-filter=A`
names against the pull request base, or against the commit a push moved main
from).
A profile written from a clone can cite lines that do not hold the value it
declares while schemas and tests pass it. This job confronts it with its
upstream. An edited profile is not held to it.

**run-tests.** On Python 3.8, 3.9 and 3.12: holds `install.py` to 3.8 with
`vermin`, sets up bubblewrap for the sandbox tests, fetches the platforms' own
files (`export_native.py --all --refresh-cache`, for the fidelity tests) and the data
directories, generates the site, then runs
`python -m unittest discover -s tests -t . -v` with `RETROBIOS_OFFLINE=1`, the
full-screen installer tests again under 3.8, and the site build
(`npm run build --prefix website`, `validate_site.py`). The site generation,
the suite and the build each run whatever the step before returned, so one
red step does not hide another. Must pass before a merge, and again on the
commit a direct push puts at the head of main.

**label-pr** (pull requests from a branch of this repository). Auto-labels the
PR based on changed paths:

| Path pattern | Label |
|-------------|-------|
| `bios/` | `bios` |
| `bios/{Manufacturer}/` | `system:{manufacturer}` |
| `platforms/` | `platform-config` |
| `scripts/` | `automation` |

## Large files management

Files too large for git are stored as assets on a permanent GitHub release
named `large-files`. Size does not decide it: four committed files are
over 50 MB (`history.xml`, `default-GM.sf3`, `5.avi`, `uqm-remix-disc1.uqm`)
and are served from the repository like any other.

Examples: PS3UPDAT.PUP, PSVUPDAT.PUP, PSP2UPDAT.PUP, the DSi NAND images,
maclc3.zip, Firmware.19.0.0.zip (Switch), the QEMU EDK2 firmware, the ScummVM
data bundle, the EasyRPG soundfont, the Dolphin/Ishiiruka SD card images, and
the arcade sets over 100 MB. `.gitignore` is the authoritative list: every
`bios/` path listed there is a release asset.

**Storage.** Listed in `.gitignore` so they stay out of git history. Old
version-tagged releases are deleted by hand when a new one is published
(see [cutting a release](#cutting-a-release)), and `large-files` is never one of
them.

**Restore.** No workflow builds a pack. `generate_pack.py` fetches an asset
into `.cache/large/` when a pack needs it (`fetch_large_file()`), and
`scripts/restore_large_files.py` puts every registered asset back at its
`bios/` path by the SHA-1 of its content, and `deploy-site.yml` runs it before
generating anything, since the site's coverage reads the disk.

**Asset name.** A gitignored path whose file name no other gitignored path
shares is published under that file name. When two paths share one, each is
published under its location below `bios/`, segments joined by `--` and any
character outside `A-Za-z0-9._-` replaced by `_`
(`Id_Software--Wolfenstein_Enemy_Territory--etmain--pak0.pk3`).
`asset_names()` in `scripts/largefiles.py` is the only place that rule lives:
the manifests, the fetcher and `check_release_assets.py` all read it.

**Upload.** To add or update a large file:

```bash
gh release upload large-files "bios/Sony/PS3/PS3UPDAT.PUP#PS3UPDAT.PUP"
```

The text after `#` is only a display label: the asset takes the uploaded
file's own name. A path whose asset name differs from its file name is
uploaded from a copy carrying the asset name.

**Local cache.** `generate_pack.py` calls `fetch_large_file()` which downloads
from the release and caches in `.cache/large/` for subsequent runs. The path it
returns is a hard link under `.cache/large/.by-sha1/<sha1>/`, never the cached
name: another run that finds the asset re-uploaded replaces the name, and the
first run still reads the bytes it verified. A revision no name holds is
dropped a day later, at the next download. `restore_large_files.py` hashes
each copy before it moves it into place.

**Check.** The installer refuses a download whose `Content-Length` differs
from the manifest size, and the manifest size is that of the local file. A
file rebuilt locally after its upload therefore fails every install until it
is uploaded again (`--clobber`). `python scripts/check_release_assets.py`
compares every gitignored `bios/` path in the database with its asset, and the release page with the one it renders from the collection.
The online pipeline runs it as step 2b2. To refresh the page:

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
# 1. Full pipeline, online, so data directories and MAME/FBNeo hashes are
#    fresh. It builds the packs of the platforms marked release_pack (see
#    "Which platforms get a pack" below) and the install manifests of every
#    platform.
python scripts/pipeline.py

# 2. A release file must be under 2 GiB. A larger pack becomes parts that are
#    each a ZIP of whole files (Pack.part1of2.zip): any tool opens one, and
#    the parts extracted into one folder are the pack. Each part is read back
#    and the set compared with the pack before the pack is removed. Each part
#    also holds a marker (Pack.part1of2.txt) naming every part and its size,
#    which install.py --check reads to name a part missing from a folder.
python scripts/split_pack.py dist/

# 2b. The handheld launchers, each carrying the installer the bootstraps pin:
#     RetroBIOS.zip (the PortMaster port), RetroBIOS-batocera.zip (Batocera
#     and Knulli Ports), RetroBIOS.muxapp (muOS Applications) and
#     RetroBIOS-tools.zip (the Tools menu of ArkOS, dArkOS, ROCKNIX, JELOS,
#     AmberELEC). They are release files, listed in the checksums below, and
#     check_release.py compares each asset with its line there.
python scripts/build_port.py

# 2c. The installer and the file lists step 1 wrote, so a package can pin
#     one release (installer page, "For packagers"). check_release.py
#     refuses a release that lacks one of them.
cp install.py install.sh install.ps1 install/*.json dist/

# 3. Checksums of the files as published, then sign the list. The checksums
#    answer corruption, and the signature answers a rewritten release, which is
#    the one thing a checksum published beside its own artifacts cannot
#    answer.
(cd dist && sha256sum *.zip RetroBIOS.muxapp install.py install.sh install.ps1 \
  $(cd ../install && ls *.json) > SHA256SUMS.txt)
ssh-keygen -Y sign -f ~/.ssh/retrobios_signing -n file dist/SHA256SUMS.txt

# 4. Record what each pack holds, read from the archives just checked:
#    file count, extracted size, download size, published files. The README
#    and the site print these beside the download links, and the notes table
#    takes its Size and Files columns from the same lines. The command stops
#    if an archive does not hold the count its install manifest expects.
DATE=$(date +%Y.%m.%d)
python scripts/release_record.py dist/ --tag "v${DATE}"
python scripts/generate_readme.py --db database.json --platforms-dir platforms
python scripts/generate_site.py

# 5. Write the notes: install commands, the parts sentence and the pack table
#    come from release.json, and what changed since the previous tag is the
#    maintainer's own text in tmp/whats-new.md, appended as written. The
#    script refuses a text that judges another project ("forum list") or
#    promises what the gap analysis contradicts ("never stops"): it says
#    what changed and how it was checked.
python scripts/release_notes.py --whats-new tmp/whats-new.md --output tmp/notes.md

#    Create the release as a DRAFT, upload every asset, and only then publish it.
#    A public release with half its assets is a broken download for everyone
#    during the whole upload.
gh release create "v${DATE}" --draft --title "BIOS Pack v${DATE}" --notes-file tmp/notes.md
for f in dist/SHA256SUMS.txt dist/SHA256SUMS.txt.sig dist/*.zip dist/RetroBIOS.muxapp \
         dist/install.py dist/install.sh dist/install.ps1 $(ls install/*.json | sed 's|^install/|dist/|'); do
  [ -f "$f" ] && gh release upload "v${DATE}" "$f#$(basename "$f")" --clobber
done
#    A count does not see a failed upload beside a stray file, nor a part
#    re-uploaded from an older build. The check holds every asset against
#    release.json and the local checksum list, by the sha256 GitHub computes,
#    and the parts of each pack against the download size the README prints.
#    Publish only on a clean exit, otherwise rerun the upload for what it names.
python scripts/check_release.py --tag "v${DATE}" --sums dist/SHA256SUMS.txt \
  && gh release edit "v${DATE}" --draft=false --latest

#    The record and the pages it feeds go to main with the release, so the
#    table never describes a pack other than the one the link serves. The
#    install manifests go too: step 1 regenerated them, and their pack_files
#    and pack_size describe the packs just built. git status names anything
#    else the run rewrote.
git status --short
git add release.json README.md install/*.json install/targets/*.json
git commit -m "chore: record release v${DATE}" && git push

# 5b. The PyPI package, `uvx retrobios`: install.py and its command. The
#     version is the UTC date of the last commit that changed install.py
#     (2026-11-09 gives 2026.11.9, the third change that day 2026.11.9.3),
#     so an unchanged install.py keeps its version and PyPI refuses it
#     again. Publishing is not tied to a release: any push that changes
#     install.py can be published. The build replaces any earlier one in
#     tmp/pypi-dist. `uv build` builds it with the flit_core backend the
#     project pins, dated by that commit (SOURCE_DATE_EPOCH), so a rebuild
#     gives the same bytes. Build, run the wheel, then upload the two files. The
#     token stays in its file: never in the repository, a script or a log.
python scripts/build_pypi.py --output-dir tmp/pypi-dist
python -m unittest tests.test_pypi_package
uvx --from tmp/pypi-dist/retrobios-*.whl retrobios --help
uv publish --token "$(cat ~/.config/retrobios/pypi-token)" tmp/pypi-dist/*

# 6. Keep only the new release plus large-files: an older pack carries hashes
#    the platforms no longer check, so it misleads more than it helps
gh release list --json tagName,createdAt \
  --jq 'sort_by(.createdAt) | reverse | .[].tagName' | grep -v '^large-files$' \
  | tail -n +2 | while read tag; do gh release delete "$tag" --yes --cleanup-tag; done
```

Before a release, a maintainer runs `python scripts/pack_probe.py run --platform
<name>` on the released platforms it supports (RetroArch, Batocera and RetroBat),
and reads its findings before cutting.

## Which platforms get a pack { #which-platforms-get-a-pack }

`release_pack: true` in `platforms/_registry.yml` is the list. `generate_pack.py
--all` builds those packs and no other, `--verify-packs` and the consistency
step of the pipeline check those, `release_record.py` refuses any other pack
in `dist/`, and `check_release.py` reports a marked platform without a pack.
The README, the download page, each setup page and the release notes read the
same field: a platform without it shows "No ZIP" and the command. Its install
manifest is written all the same, and `generate_pack.py --platform NAME` still
builds its pack for anyone who wants one.

The list follows downloads. In v2026.10.10, part 1 of each pack was fetched
7,251 times for RetroArch, 2,909 for EmuDeck, 1,988 for RetroBat, 1,933 for
Batocera and 1,003 for RomM, then 751 for RetroPie, 642 for Recalbox, 516 for
RetroDECK, 450 for MiSTer, 386 for ROCKNIX and 361 for BizHawk. The first five
are 83% of downloads for 17 GB of the 35 GB all packs weighed. MiSTer stays
for its 17 MB. To revisit the list, read the counts of the latest release,
counting a whole pack or the first part of a split one, so each download
counts once:

```bash
gh api repos/Abdess/retrobios/releases/latest --jq '.assets[]
  | select(.name | test("_BIOS_Pack(\\.part1of[0-9]+)?\\.zip$"))
  | "\(.download_count)\t\(.name)"' | sort -rn
```

Then add or remove the field and regenerate the README and the site.

Every platform has a page at `get/<platform>/` on the site, its permanent
download address. It lists the files of the pack the latest release holds,
read from `release.json`, or gives the command when there is no pack. The
README, the setup pages and the release notes link it, never an asset URL:
step 6 deletes the previous tag, and with it every link to its assets. Six of
the eight links one community wiki had to the packs answered 404 that way.
Committing `release.json` in step 5 rebuilds these pages, so the release
never touches them.

## Verifying a release

`SHA256SUMS.txt` is signed with a key used for nothing else. Its public half
is `allowed_signers` at the repository root, so anyone can check a download
without trusting the release page it came from:

```bash
gh release download -R Abdess/retrobios \
  --pattern 'SHA256SUMS.txt*' --pattern 'RetroArch_*BIOS_Pack*'
curl -fsSLO https://raw.githubusercontent.com/Abdess/retrobios/main/allowed_signers

ssh-keygen -Y verify -f allowed_signers -I releases@retrobios -n file \
  -s SHA256SUMS.txt.sig < SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
```

Run it in any folder, a clone is not needed. On macOS the last line is
`shasum -a 256 --check --ignore-missing SHA256SUMS.txt`, and on Windows
PowerShell `Get-FileHash -Algorithm SHA256 <pack>` gives the value to compare
with the file's line in `SHA256SUMS.txt`.

The `ssh-keygen` command must print `Good "file" signature for releases@retrobios`.
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

One pack per platform marked `release_pack`, the full one: the platform's list
plus everything its cores load. Platform-only and per-emulator packs are build options, not
release assets, since a lighter pack means a core that fails with no message.
The release notes are written by `release_notes.py`: the install commands,
the pack table and its parts sentence come from `release.json`, then what
changed since the previous tag and the contributors of the closed issues,
written by hand. A pack has two sizes and they are far apart: in v2026.10.10,
Batocera downloaded as 5.2 GB and extracted to 7.5 GB. Step 4 prints both, and whichever
one the table carries, the header names it. Someone sizing a USB drive is
reading that column. The README table is the extracted size of the released
pack, from `release.json`. `SHA256SUMS.txt` lists the checksums of the files
as published, parts included.

`release.json` is the record step 4 writes: per pack, the files it holds, its
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
and 79). The README, the download page and the troubleshooting page described
both layouts for as long as a release cut that way was still published.
v2026.09.04 has since been deleted by step 6, and the `.zip.001` paragraph
left those pages.

The table carries a Files column, the count step 4 prints, and the
notes never open on the size of the collection. That total covers every
platform and emulator together and no pack holds it: v2026.09.04 led with
"10,330 files" right after "one pack per platform", and someone who extracted
the complete RetroArch pack and counted 4,525 reported half of it missing.
The collection total belongs under "What's new", worded as the collection.
