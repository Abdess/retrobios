"""The README and CONTRIBUTING texts, from the database, the platforms and the release."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.text import series
from romrecipes import ledger
from devtools import prchecks
from model import releaserecord, siteinputs
from core.artifacts import write_if_changed
from core.paths import DB_FILE, REPO_ROOT
from core.sizes import size_text
from core import upstream
from installer_build.module import installer_module
from model.composition import compute_composition, count_catalog_matched
from model.guides import PACKAGE_COMMAND
from sitegen.guidedata import install_command
from model.largefiles import load_registered_paths
from model.profiles import load_emulator_profiles, unique_emulator_profiles
from model.registry import list_registered_platforms
from model.systems import system_index
from resolve.review import LARGE_FILE_ISSUE_URL
from sitegen.config import REPO_SLUG, REPO_URL, SITE_URL, UPLOAD_ROOT
from sitegen.coverage import platform_coverages
from sitegen.demovariants import demo_description
from sitegen.extraction import extract_targets
from sitegen.releasepacks import download_links, release_totals


def _extract_cells(platforms_dir: str) -> dict[str, str]:
    """The download table's "Extract to" cell, by display name."""
    return {display: f"`{folder}`" for display, folder in extract_targets(platforms_dir)}


def _paragraphs(texts: list[str]) -> list[str]:
    return [line for text in texts for line in ("", text)]


def download_table(
    coverages: dict,
    extract_paths: dict[str, str],
    record: dict,
) -> list[str]:
    """The README's ZIP table: one row per setup the release carries a pack
    for, then the sentence linking every other setup to its get/ page."""
    by_name = sorted(coverages, key=lambda n: coverages[n]["platform"])
    released = [name for name in by_name if release_totals(name, record)[0]]
    lines = [
        "| Setup | Files | Size | Unzip into | Download |",
        "|-------|------:|-----:|------------|----------|",
    ]
    for name in released:
        files, size = release_totals(name, record)
        display = coverages[name]["platform"]
        lines.append(
            f"| {display} | {files:,} | {size_text(size) if size else '-'} |"
            f" {extract_paths.get(display, '')} |"
            f" {download_links(name, record, 'Download', site=SITE_URL)} |"
        )
    others = [name for name in by_name if name not in released]
    return [
        *lines,
        "",
        "ZIPs are made for the setups most people download. The others install with the line"
        " above, and each page gives the command: "
        + ", ".join(f"[{coverages[name]['platform']}]({SITE_URL}get/{name}/)" for name in others)
        + ".",
    ]


def collection_line(total_files: int, comp: dict) -> str:
    """The size of the whole collection, said as such.

    Printed bare beside the download links it read as the content of one
    pack, and a complete extraction looked like a broken one.
    """
    return (
        f"- **{total_files:,} files in the collection**, each with its SHA1,"
        " MD5, SHA256, CRC32 and Adler-32 fingerprints:"
        f" {comp['systems']['files']:,} system files,"
        f" {comp['arcade']['files']:,} arcade ROM sets,"
        f" {comp['game_data']['files']:,} game and engine data files."
        " That is every platform and emulator together, so no pack holds"
        " them all: each carries what its own emulators load, counted in"
        " the download table"
    )


# The installer demo (scripts/make_demo.py): the recording and what it shows.
DEMO_GIF = "docs_assets/demo/install.gif"
REPO = REPO_SLUG
README_PATH = REPO_ROOT / "README.md"
CONTRIBUTING_PATH = REPO_ROOT / "CONTRIBUTING.md"
# GitHub's "Add file > Upload files" page for bios/: a browser upload by
# someone without write access lands on a fork and opens a pull request.
UPLOAD_URL = f"{UPLOAD_ROOT}bios"


def clone_line(db: dict) -> str:
    """How to get the clone the commands below run in, and its size.

    Said bare, "clone the repo" started a multi-gigabyte transfer for a user
    after a 20 MB --required-only pack. The size counts the collection files
    the repository commits, a floor: release assets are fetched only when a
    pack needs them.
    """
    assets = set(load_registered_paths())
    committed = sum(
        entry.get("size", 0) for entry in db.get("files", {}).values()
        if entry.get("path") not in assets
    )
    return (
        "Packs are built from a clone, and the clone carries the collection:"
        f" its checkout alone is over {size_text(committed)}."
        f" `git clone --depth 1 https://github.com/{REPO}.git` leaves the"
        " history out. Files kept as release assets are downloaded when a"
        " pack needs them. Then generate packs for any platform, emulator,"
        " or system:"
    )


def _existing_contributor_block(readme_path: str | Path = README_PATH) -> list[str]:
    """The contributors already published, read back from the file.

    The section is the one part of this document that comes from the network.
    A refused or rate-limited request used to leave the list empty, which
    silently deleted the section from a published README and put the local
    result permanently at odds with what the freshness check regenerates.
    Keeping what is already there makes an offline run additive-only.
    """
    try:
        with open(readme_path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return []
    start = text.find("## Contributors")
    if start == -1:
        return []
    rest = text[start:].splitlines()
    block = []
    for line in rest[1:]:
        if line.startswith("## "):
            break
        block.append(line)
    while block and not block[-1].strip():
        block.pop()
    return ["## Contributors"] + block if block else []


def fetch_contributors() -> list[dict]:
    """Contributors from the GitHub API, bots and the owner left out. Empty
    when the API cannot be read, or under RETROBIOS_OFFLINE: the caller then
    keeps the published list."""
    if upstream.run_is_offline():
        return []
    url = f"https://api.github.com/repos/{REPO}/contributors"
    try:
        body = upstream.fetch_body(url, accept_json=True, timeout=10, user_agent="retrobios-readme/1.0")
        data = json.loads(body) if body is not None else []
    except (upstream.UpstreamError, ValueError) as exc:
        print(f"contributors: {exc}", file=sys.stderr)
        return []
    owner = REPO.split("/")[0]
    return [
        c
        for c in data
        if isinstance(c, dict)
        and not c.get("login", "").endswith("[bot]")
        and c.get("type") == "User"
        and c.get("login") != owner
    ]


_CATALOG_LABELS = {"redump": "Redump", "no-intro": "No-Intro", "tosec": "TOSEC"}


def _catalog_matched_line(db: dict) -> list[str]:
    """Bullet line for files matched to dump-preservation catalogs."""
    matched = count_catalog_matched(db)
    if not matched:
        return []
    sources: set[str] = set()
    for entry in db.get("files", {}).values():
        sources.update(entry.get("provenance") or ())
    system_files = compute_composition(db)["systems"]["files"]
    labels = ", ".join(_CATALOG_LABELS.get(s, s) for s in sorted(sources))
    return [
        f"- **{matched:,} of {system_files:,} system files** matched to"
        f" dump-preservation catalogs ({labels}). Arcade sets and engine data"
        f" fall outside what those catalogs index"
    ]


# The badge row under the links: (alt text, image, link). A badge earns its
# place by saying what the page does not: the Python floor is in the install
# text, and GitHub cannot name the license of LICENSE, which opens on its scope.
BADGES = (
    ("PyPI version", "https://img.shields.io/pypi/v/retrobios", "https://pypi.org/project/retrobios/"),
    ("Validation",
     f"{REPO_URL}/actions/workflows/validate.yml/badge.svg?branch=main",
     f"{REPO_URL}/actions/workflows/validate.yml"),
)


def badge_row() -> str:
    badges = " ".join(f'<a href="{link}"><img src="{image}" alt="{alt}"></a>'
                      for alt, image, link in BADGES)
    return f'<p align="center">{badges}</p>'


def archive_line(counts: dict[str, int]) -> str:
    """The README's line on archive recipes, counted from recipes/archives.json."""
    return (f"- **{counts['total']:,} archives**, each with a recipe that rebuilds it from the"
            f" ROMs the collection holds: {counts['exact']:,} byte for byte,"
            f" {counts['canonical']:,} with the same files inside"
            f" ([rebuilding an archive]({SITE_URL}wiki/archive-recipes/))")


@dataclass(frozen=True)
class ReadmeInputs:
    """Everything the README text is made of, gathered before it is written."""

    total_files: int
    coverages: dict
    profiles: dict
    record: dict
    extract_paths: dict[str, str]
    archive_counts: dict[str, int]
    clone: str
    # The list from the GitHub API, and the published block kept from the
    # README when the request returned nothing.
    contributors: list[dict]
    kept_contributors: list[str]
    generated_at: str


def load_readme_inputs(db: dict, platforms_dir: str, db_path: str = DB_FILE) -> ReadmeInputs:
    """Read the registry, the coverages, the profiles, the release record and the contributors."""
    from model.registry import load_data_dir_registry

    platform_names = list_registered_platforms(platforms_dir)
    data_registry = load_data_dir_registry(platforms_dir)
    coverages = platform_coverages(platform_names, platforms_dir, db, data_registry,
                                   db_path=db_path)
    profiles = unique_emulator_profiles(
        load_emulator_profiles(str(siteinputs.current().emulators), skip_aliases=False)
    )
    contributors = fetch_contributors()
    kept: list[str] = []
    if not contributors:
        # The request failed. Republish what is already there rather than
        # dropping the section: losing it is a worse answer than a stale list.
        kept = _existing_contributor_block(README_PATH)
        if kept:
            print("contributors: request failed, keeping the published list")
    return ReadmeInputs(
        total_files=db.get("total_files", 0),
        coverages=coverages,
        profiles=profiles,
        record=releaserecord.load_advertised(REPO_ROOT / releaserecord.RECORD, platforms_dir),
        extract_paths=_extract_cells(platforms_dir),
        archive_counts=ledger.rebuild_counts(),
        clone=clone_line(db),
        contributors=contributors,
        kept_contributors=kept,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _contributor_lines(inputs: ReadmeInputs) -> list[str]:
    if not inputs.contributors:
        return inputs.kept_contributors + [""] if inputs.kept_contributors else []
    lines = ["## Contributors", ""]
    for c in inputs.contributors:
        login = c["login"]
        avatar = c.get("avatar_url", "")
        url = c.get("html_url", f"https://github.com/{login}")
        lines.append(
            f'<a href="{url}"><img src="{avatar}" width="50" alt="{login}"'
            f' title="{login}"></a>'
        )
    return [*lines, ""]


def render_readme(inputs: ReadmeInputs) -> str:
    """The README text from its gathered inputs."""
    total_files = inputs.total_files
    ts = inputs.generated_at
    coverages = inputs.coverages
    profiles = inputs.profiles
    emulator_count = len(profiles)
    profile_files = [f for prof in profiles.values() for f in prof.get("files") or []
                     if isinstance(f, dict)]
    # A citation counts when it names a line, `file.c:120`: a bare file name
    # or a binary offset does not point at the code that reads the file.
    cited_share = (round(100 * sum(1 for f in profile_files
                                   if re.search(r"\.\w+:\d", str(f.get("source_ref") or "")))
                         / len(profile_files)) if profile_files else 0)
    closed_count = sum(1 for prof in profiles.values()
                       if str(prof.get("upstream") or "").startswith("closed"))

    system_ids = system_index(profiles)

    # The README is the repository's front page and its most read page: a
    # visitor from a search lands here, often new to terminals. It says what
    # the project does, gives the one line that installs, shows it, and leads
    # on to the site, where every detail lives. The figures and the lists it
    # once carried (coverage, collection, build commands) are the site's.
    record = inputs.record
    extract_paths = inputs.extract_paths
    lines = [
        '<p align="center">',
        "  <picture>",
        '    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/banner-dark.svg">',
        '    <img src=".github/assets/banner-light.svg" alt="RetroBIOS" width="400">',
        "  </picture>",
        "</p>",
        "",
        '<p align="center"><strong>The BIOS files emulators need, put in the right folder and checked.</strong></p>',
        "",
        '<p align="center">'
        f'<a href="{SITE_URL}">Website</a> · '
        f'<a href="{SITE_URL}which-pack/">Get the files</a> · '
        f'<a href="{SITE_URL}wiki/troubleshooting/">A game does not start</a> · '
        f'<a href="{SITE_URL}wiki/faq/">Questions</a>'
        "</p>",
        "",
        badge_row(),
        "",
        "Some consoles need a small program, the **BIOS**, to start their games: PlayStation 1"
        " and 2, Saturn, Neo Geo, Dreamcast and more. RetroBIOS installs the BIOS and firmware"
        f" files for {series(sorted(c['platform'] for c in coverages.values()))}, checked the way each one checks them.",
        "",
        "## Install in one line",
        "",
        "**Windows**: open the Start menu, type **PowerShell** and open it. Paste this line"
        " (Ctrl+V or right-click in the window) and press Enter.",
        "",
        "```powershell",
        install_command("powershell"),
        "```",
        "",
        "**Linux, macOS, Steam Deck, Android (Termux)**: open a terminal, paste this line"
        " and press Enter.",
        "",
        "```bash",
        install_command("sh"),
        "```",
        "",
        f"**With Python 3.8 or newer**: `{PACKAGE_COMMAND}` runs the same installer, and so"
        " does `pipx run retrobios`.",
        "",
        f"**A handheld, an SD card, or not sure?** [Pick the device]({SITE_URL}which-pack/):"
        " its page gives the folder and the command. A muOS, Onion, spruceOS, MinUI, KNULLI,"
        " ROCKNIX, Lakka or MiSTer SD card plugged into the computer is found by itself.",
        "",
        f"![{demo_description()}]({DEMO_GIF})",
        "",
        "The installer finds the setup and its BIOS folder, installs the files it needs (only"
        " what the games need when it finds them on the card) and checks each one. Its screen"
        " installs everything, or fewer under **" + installer_module().TUI_SYSTEMS_ROW + "**."
        " Arrow keys and Enter drive it, or a controller on a handheld. It sends no report of"
        f" its own ([what is counted]({SITE_URL}wiki/privacy/)). Options go after the line in the"
        f" form the [installer page]({SITE_URL}wiki/installer/#passing-options) gives.",
        "",
        f"First time? [The first install, step by step]({SITE_URL}wiki/first-install/)."
        f" A game does not start: [what to check]({SITE_URL}wiki/troubleshooting/)."
        f" Other questions: [FAQ]({SITE_URL}wiki/faq/).",
        "",
        "## Or download a ZIP",
        "",
        "The Files column counts what a pack holds once unzipped.",
        "",
        *download_table(coverages, extract_paths, record),
        "",
        "Unzip into the BIOS folder, files straight in it. A big pack comes in parts"
        " (`Pack.part1of2.zip`): download every part"
        f" ([why some setups have no ZIP]({SITE_URL}wiki/faq/#why-is-there-no-zip-for-my-setup))."
        " Each release lists its files' SHA-256 with a signature"
        f" ([verifying a release]({SITE_URL}wiki/release-process/#verifying-a-release)).",
        "",
        "## Help",
        "",
        f"- \"BIOS missing\" or a game does not start: [what to check]({SITE_URL}wiki/troubleshooting/)",
        f"- Have a file? [Check it by its hash]({SITE_URL}files/)",
        f"- Every console and the files it needs: [systems]({SITE_URL}systems/)",
        f"- Asking an AI assistant: it reads the site best from [llms.txt]({SITE_URL}llms.txt)",
        "",
        "## How it is built",
        "",
        f"- **{emulator_count} emulators profiled**, {emulator_count - closed_count} from their"
        f" source code and {closed_count} closed-source builds from their binaries:"
        f" {cited_share}% of the files they load cite the file and line that reads them",
        f"- **{len(coverages)} setups**, each checked its own way: MD5 for Batocera and Recalbox,"
        " the file name for RetroArch, as their own code does",
        f"- **{len(system_ids)} systems**, {total_files:,} files in the collection,"
        f" [what is still missing]({SITE_URL}gaps/) named file by file",
        archive_line(inputs.archive_counts),
        f"- Public data: [JSON, CSV and SQLite]({SITE_URL}data/), the metadata under MIT",
        "",
        "<details>",
        "<summary><strong>For developers: build a pack</strong></summary>",
        "",
        inputs.clone,
        "",
        "```bash",
        "python scripts/generate_pack.py --platform retroarch --output-dir dist/",
        "python scripts/generate_pack.py --emulator dolphin",
        "python scripts/generate_pack.py --platform batocera --required-only",
        "python scripts/verify.py --platform batocera",
        "```",
        "",
        "Requires Python 3.9 or newer and `pyyaml`. The one-line installer alone runs on Python 3.8."
        f" Every tool and option: [tools]({SITE_URL}wiki/tools/). How the lists are built:"
        f" [architecture]({SITE_URL}wiki/architecture/).",
        "",
        "</details>",
        "",
    ]

    lines.extend(_contributor_lines(inputs))

    lines.extend(
        [
            "",
            "## Community tools",
            "",
            "- [BIOS Preservation Tool](https://github.com/monster-penguin/BIOS-Preservation-Tool)"
            " by [monster-penguin](https://github.com/monster-penguin)"
            " - scans, verifies and stages a BIOS collection"
            " using RetroBIOS hash metadata",
            "",
            "## Contributing",
            "",
            "See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.",
            "",
            "## License",
            "",
            "The scripts and tooling are released under the [MIT License](LICENSE).",
            "The BIOS and firmware files are not covered by that license: they are"
            " third-party system software, preserved and provided for personal"
            " backup, archival, and interoperability with emulation software."
            " [NOTICE](NOTICE) sets out their status and how to ask for a file"
            " to be removed.",
            f"The reasoning, and where it is weakest, is in"
            f" [the project's legal position]({SITE_URL}wiki/legal/).",
            "",
            f"*Auto-generated on {ts}*",
        ]
    )

    return "\n".join(lines) + "\n"


def ci_install_lines() -> tuple[str, str]:
    """The pip lines the test job of validate.yml runs, verbatim.

    The guide listed the packages without their versions, so a local run
    could pass on releases CI never installs. Read from the workflow, the
    two cannot disagree. The second line is the Python 3.8 one.
    """
    text = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    main = re.search(r'^\s*run: (pip install pyyaml "jsonschema.*markdown.*)$', text, re.M)
    floor = re.search(r"^\s*run: (python3\.8 -m pip install .*)$", text, re.M)
    if main is None or floor is None:
        raise RuntimeError("validate.yml no longer installs the packages CONTRIBUTING quotes")
    return main.group(1), floor.group(1)


def contributing_text(
    link: Callable[[str], str], title: str, site_words: str
) -> str:
    """The contribution guide, one text for the repository and the site.

    Two copies drifted apart: four steps to add a platform here, five on the
    site. *link* renders a site page (absolute URL for the README, relative
    .md for the site); *site_words* names the site from where the text is read.
    """
    pip_line, floor_line = ci_install_lines()
    width = max(len(prchecks.shown(step)) for step in prchecks.STEPS)
    steps = "\n".join(f"{prchecks.shown(step):<{width}}  # {step.why}" for step in prchecks.STEPS)
    return f"""{title}

## Add a BIOS file

Have a file the collection lacks? Add it from the browser. It is checked on arrival.

Not sure? Drop it on [the wanted page]({link("wanted")}). It reads the file on
the device, says if it is wanted, and opens the upload in the right folder.

[Upload it into `bios/`]({UPLOAD_URL}), 25 MB at most per file. GitHub
writes it to a fork and opens the pull request.

The files most wanted are on [what the packs do not hold]({link("gaps")}). The
[dump provenance]({link("provenance")}) page lists catalogued dumps still
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
issue]({LARGE_FILE_ISSUE_URL}) with the hashes `validate_pr.py` prints, and a
maintainer adds it to the `large-files` release.

## Add a platform

1. Write a scraper in `scripts/scraper/` (inherit `BaseScraper`)
2. Read the platform's upstream source to determine how it checks BIOS files
3. Register it in `platforms/_registry.yml`
4. Generate the platform YAML and test: `python scripts/verify.py --platform <name>`

Full walkthrough: [adding a platform]({link("wiki/adding-a-platform")}).

## Add an emulator profile

1. Clone the emulator's source code, upstream and libretro port
2. Trace the file loading from the entry point, not from a keyword grep
3. Document every file the code loads, with a `source_ref` line reference
4. Write the YAML to `emulators/<name>.yml`
5. Test: `python scripts/cross_reference.py --emulator <name>`

Full walkthrough: [profiling guide]({link("wiki/profiling")}).

## Change the installer

`install.py` is built from the `installer/` package, one module per concern:
edit the module, then run `python scripts/build_installer.py` and
`python scripts/pin_installer.py`. CI fails when `install.py` is not the file
the package builds. [Changing the installer]({link("wiki/installer")}#changing-the-installer)
lists what else a change rewrites.

## File conventions

- `bios/Manufacturer/Console/filename` for canonical files
- `bios/Manufacturer/Console/.variants/filename.sha1prefix` for alternate versions
- A file too large for git goes to the `large-files` GitHub release and its
  path into `.gitignore`, the list that decides what is served from the release
- Trees addressed by path are kept out of deduplication (`NODEDUP_DIRS` in
  `scripts/model/nodedup.py`)
- Two paths differing only by case break clones on Windows and macOS,
  and `tests/test_no_case_collisions.py` enforces this

## Before opening a PR

A pull request that only adds files under `bios/` needs none of this: the
validation above is its check. For code, profiles or platform files, these are
the checks CI runs on a pull request (Python 3.12 or newer):

```bash
{pip_line}
python scripts/pr_checks.py
```

`pr_checks.py` runs these, in CI's order, carries on past a failure as CI
does, and names at the end each check that failed or could not run:

```bash
{steps}
```

The versions are the ones CI pins. Three tools come from the system, not from
that line, and the tests that need them skip without them: `shellcheck` for the
handheld launchers, `bwrap` (bubblewrap) for the probe sandbox, and a Python 3.8
with pyte (`{floor_line}`) for the full screen. CI has all three.

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
{site_words}, and in the BIOS packs.
"""


def generate_contributing() -> str:
    return contributing_text(
        lambda page: f"{SITE_URL}{page}/",
        "# Contributing to RetroBIOS",
        "on the documentation site",
    )


def write_readme(readme: str) -> None:
    status = "Generated" if write_if_changed(str(README_PATH), readme) else "Unchanged"
    print(f"{status} ./README.md")

    contributing = generate_contributing()
    status = (
        "Generated"
        if write_if_changed(str(CONTRIBUTING_PATH), contributing)
        else "Unchanged"
    )
    print(f"{status} ./CONTRIBUTING.md")
