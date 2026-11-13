"""What the README, the site and the wiki tell an end user.

Someone with a game that does not boot runs the one-line installer, not a
clone of this repository: `scripts/verify.py` reads the collection, never
their BIOS folder. A download link names the file to fetch, parts included,
from the release the table describes. Output shown on a page is output the
tool prints, and a size is the one the release record holds.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import contextlib
import re
import sys
import unittest
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_record  # noqa: E402
from generate_readme import (  # noqa: E402
    SITE_URL,
    asset_links,
    contributing_text,
    download_links,
    download_table,
    format_size,
)

RECORD = release_record.load_record(REPO_ROOT / "release.json")
REPO = "https://github.com/Abdess/retrobios"

SPLIT_RECORD = {
    "tag": "v2000.01.01",
    "packs": {
        "Batocera_1_BIOS_Pack.zip": {
            "files": 3,
            "extracted_size": 3 * 1024**3,
            "download_size": 2 * 1024**3,
            "assets": [
                "Batocera_1_BIOS_Pack.part1of2.zip",
                "Batocera_1_BIOS_Pack.part2of2.zip",
            ],
            "platforms": ["batocera"],
        },
        "RomM_1_BIOS_Pack.zip": {
            "files": 1,
            "extracted_size": 1024**2,
            "download_size": 1024**2,
            "assets": ["RomM_1_BIOS_Pack.zip"],
            "platforms": ["romm"],
        },
    },
}


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """The text under a markdown heading, up to the next heading of its level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading + "\n")
    rest = text[start + len(heading) + 1:]
    stop = re.search(rf"^#{{1,{level}}} ", rest, re.MULTILINE)
    return rest[: stop.start()] if stop else rest


def _which_pack() -> str:
    import generate_site

    with contextlib.chdir(REPO_ROOT):
        return generate_site.generate_which_pack()


class TheDownloadTablesFollowTheRegistry(unittest.TestCase):
    """EmuDeck has a Windows edition the installer detects, and the Windows
    table of the download page left it out. The page is grouped by device
    now: the row of each platform names every system it is detected on."""

    def test_every_detected_system_lists_the_platform(self):
        import yaml  # noqa: PLC0415

        from common import load_platform_config  # noqa: PLC0415

        registry = yaml.safe_load(_read("platforms/_registry.yml"))
        page = _which_pack()
        for os_name, label in (("windows", "Windows"), ("darwin", "macOS")):
            for platform, entry in registry["platforms"].items():
                systems = {rule["os"] for rule in (entry.get("install") or {}).get("detect", [])}
                if os_name in systems:
                    name = load_platform_config(platform, "platforms")["platform"]
                    row = next(line for line in page.splitlines()
                               if line.startswith(f"| [{name}]("))
                    with self.subTest(os=os_name, platform=platform):
                        self.assertIn(label, row.split(" | ")[1])


class AssetLinksNameTheFile(unittest.TestCase):
    """The get/ page of a platform links the files of its pack."""

    def test_a_whole_pack_links_its_asset(self):
        self.assertEqual(
            asset_links("romm", SPLIT_RECORD, "../..", "Download"),
            "[Download](../../releases/download/v2000.01.01/RomM_1_BIOS_Pack.zip)",
        )

    def test_a_split_pack_links_every_part(self):
        cell = asset_links("batocera", SPLIT_RECORD, "../..", "Download")
        for part in ("part1of2", "part2of2"):
            self.assertIn(
                f"releases/download/v2000.01.01/Batocera_1_BIOS_Pack.{part}.zip", cell
            )
        self.assertIn("part 1 of 2", cell)

    def test_a_split_pack_says_how_many_files_to_download(self):
        """One link taken for the pack left half of it out of the folder."""
        self.assertIn(
            "Download, 2 files, all needed: ",
            asset_links("batocera", SPLIT_RECORD, "../..", "Download"),
        )
        buttons = asset_links("batocera", SPLIT_RECORD, REPO, "Pack", " { .x }")
        self.assertTrue(buttons.startswith("2 files to download, all needed: "), buttons)

    def test_buttons_carry_their_attributes_on_each_part(self):
        cell = asset_links("batocera", SPLIT_RECORD, REPO, "Pack", " { .x }")
        self.assertEqual(cell.count("{ .x }"), 2)

    def test_without_a_recorded_release_the_link_is_the_release_page(self):
        self.assertEqual(
            asset_links("romm", {}, "../..", "Download"),
            "[Download](../../releases/latest)",
        )


class DownloadLinksKeepTheirAddress(unittest.TestCase):
    """Every release deletes the previous tag and its asset URLs: six of the
    eight links a community wiki had to our packs answered 404. A download
    cell links the platform's get/ page, which outlives the release."""

    def test_a_released_pack_links_its_get_page(self):
        self.assertEqual(
            download_links("romm", SPLIT_RECORD, "Download", site=SITE_URL),
            f"[Download]({SITE_URL}get/romm/)",
        )
        self.assertEqual(
            download_links("batocera", SPLIT_RECORD, "Download", site=SITE_URL),
            f"[Download]({SITE_URL}get/batocera/)",
        )

    def test_a_setup_without_a_release_pack_reads_use_the_command(self):
        self.assertEqual(
            download_links("bizhawk", SPLIT_RECORD, "Download", site=SITE_URL),
            f"[Use the command]({SITE_URL}get/bizhawk/)",
        )

    def test_a_marked_setup_the_release_lacks_has_no_zip_yet(self):
        self.assertEqual(
            download_links("retroarch", SPLIT_RECORD, "Download", site=SITE_URL),
            f"No ZIP yet: [use the command]({SITE_URL}get/retroarch/)",
        )

    def test_without_a_recorded_release_the_get_page_answers(self):
        self.assertEqual(
            download_links("romm", {}, "Download", site=SITE_URL),
            f"[Download]({SITE_URL}get/romm/)",
        )

    def test_the_readme_table_links_get_pages(self):
        coverages = {
            "batocera": {"platform": "Batocera"},
            "bizhawk": {"platform": "BizHawk"},
            "romm": {"platform": "RomM"},
        }
        rows = download_table(coverages, {}, SPLIT_RECORD)[2:]
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertNotIn("/releases/", row)
            self.assertIn(f"{SITE_URL}get/", row)
        self.assertIn("[Use the command]", next(r for r in rows if "BizHawk" in r))

    def test_the_generated_readme_links_every_get_page(self):
        if not RECORD.get("packs"):
            self.skipTest("release.json is not written")
        from common import list_registered_platforms, list_release_pack_platforms

        readme = _read("README.md")
        table = _section(readme, "## Or download a ZIP")
        self.assertNotIn("/releases/download/", table)
        released = set(list_release_pack_platforms("platforms"))
        rows = [line for line in table.splitlines() if line.startswith("| ")]
        for key in list_registered_platforms("platforms"):
            with self.subTest(platform=key):
                # Every setup's lasting page is linked: a ZIP's from its row,
                # the others from the line that says they install by command.
                self.assertIn(f"]({SITE_URL}get/{key}/)", table)
                in_rows = any(f"get/{key}/)" in row for row in rows)
                self.assertEqual(in_rows, key in released)

    def test_the_download_page_rows_link_get_pages(self):
        page = _which_pack()
        rows = [line for line in page.splitlines() if line.startswith("| ")]
        self.assertTrue(rows)
        for row in rows:
            self.assertNotIn("/releases/", row)

    def test_a_platform_without_a_zip_offers_the_command(self):
        """KNULLI, AmberELEC and EmuELEC were registered after the recorded
        release, and the platforms without release_pack never get a ZIP: a
        row for them offers the command."""
        from common import list_registered_platforms, load_platform_config
        import generate_site

        record = release_record.load_advertised()
        page = _which_pack()
        for key in list_registered_platforms("platforms"):
            if release_record.pack_for(key, record) is not None:
                continue
            label = load_platform_config(key, "platforms").get("platform", key)
            row = next(line for line in page.splitlines() if line.startswith(f"| [{label}]("))
            state = "No ZIP yet." if generate_site.has_release_pack(key) else "No ZIP."
            with self.subTest(platform=key):
                self.assertNotIn("/releases/", row)
                self.assertIn(f"{state} [Use the command](platforms/{key}.md#install).", row)


class SlicesLeaveWithTheirRelease(unittest.TestCase):
    """Parts named `.zip.001` were cut by v2026.09.04, deleted since. A page
    explaining a layout no release serves buries the one the user has."""

    PAGES = ("README.md", "wiki/troubleshooting.md")

    def setUp(self):
        assets = [a for p in RECORD.get("packs", {}).values() for a in p["assets"]]
        if any(re.search(r"\.zip\.\d{3}$", a) for a in assets):
            self.skipTest("the recorded release is published in slices")

    def test_user_pages_name_one_layout(self):
        for page in self.PAGES:
            with self.subTest(page=page):
                self.assertNotIn(".zip.001", _read(page))
                self.assertNotIn("copy /b", _read(page))

    def test_the_download_page_names_one_layout(self):
        self.assertNotIn(".zip.001", _which_pack())


class TheReadmeLeadsBeginnersToTheirPages(unittest.TestCase):
    """The README linked the installer reference and the FAQ's no-ZIP anchor
    only: a user stopped by an install error or a BIOS-not-found message had
    no link to the first install or troubleshooting page."""

    def test_quick_install_links_the_start_pages(self):
        # The code block holds `#` comment lines, so the section runs to
        # the next level-two heading.
        section = _read("README.md").split("## Install in one line", 1)[1].split("\n## ", 1)[0]
        for page in ("first-install", "troubleshooting", "faq"):
            with self.subTest(page=page):
                self.assertIn(f"wiki/{page}/)", section)
                self.assertTrue((REPO_ROOT / "wiki" / f"{page}.md").is_file())


class EndUsersCheckTheirOwnFolder(unittest.TestCase):
    """verify.py reads database.json and bios/. Advice about a user's own
    files points at the installer's --check, which hashes their folder."""

    USER_SECTIONS = (
        ("wiki/troubleshooting.md", "## 1. Check the BIOS folder { #checking-what-you-installed }"),
        ("wiki/troubleshooting.md", "## 2. Fix the files"),
        ("wiki/faq.md", "## A game shows a black screen { #my-game-shows-a-black-screen }"),
        ("wiki/faq.md", "## How to tell which BIOS is needed? { #how-do-i-know-which-bios-i-need }"),
    )

    def test_user_sections_never_send_to_verify(self):
        for page, heading in self.USER_SECTIONS:
            with self.subTest(page=page, heading=heading):
                section = _section(_read(page), heading)
                self.assertNotIn("verify.py", section)
                self.assertNotIn("python install.py --check", section)

    def test_the_download_page_gives_the_one_liner_check(self):
        page = _which_pack()
        self.assertNotIn("from a checkout", page)
        self.assertIn("/i | sh -s -- --check", page)

    def test_the_readme_does_not_call_verify_a_check_of_your_bios(self):
        self.assertNotIn("Verify your BIOS collection", _read("README.md"))


class DestIsTheBiosFolder(unittest.TestCase):
    """--dest is used as the BIOS folder as given (install.py), so the root
    of a card puts every file beside the folder the frontend reads."""

    PAGES = (
        "README.md",
        "wiki/installer.md",
        "wiki/faq.md",
        "wiki/first-install.md",
    )

    def test_no_example_installs_to_a_card_root(self):
        for page in self.PAGES:
            for dest in re.findall(r"--dest\s+(\S+)", _read(page)):
                with self.subTest(page=page, dest=dest):
                    self.assertFalse(dest.rstrip("/").endswith("sdcard"), dest)


class ShownOutputIsPrintedOutput(unittest.TestCase):
    """Every line in the troubleshooting page's verify samples has a shape
    verify.py prints, and the shapes are read from its source."""

    SHAPES = (
        (r"^\S.*: \d+/\d+ (OK|present)\b.*\[(md5|sha1|existence)\]$", "}: {', '.join(parts)} [{mode}]"),
        (r"^  (OK|UNTESTED|MISSING) \((required|optional)[^)]*\): \S+/\S+", '"  UNTESTED ({req}{hle}): {key}: {reason}"'),
        (r"^  DISCREPANCY: \S+/\S+: ", '"  DISCREPANCY: {key}: {disc}"'),
        # A count of optional files missing is followed by where to list them:
        # the sample once showed "1 optional missing" with no such suffix.
        (r"^  Core files: \d+ in pack, \d+ required missing, "
         r"(0 optional missing|\d+ optional missing \(--verbose lists them\))$",
         '"  Core files: {core_in_pack} in pack'),
        (r"^  Core files held but not packed: \d+ \(.+\)$", '"  Core files held but not packed: '),
        (r"^  Bundled with their emulator, not collected: \d+( \(.+\))?$",
         '"  Bundled with their emulator, not collected: {len(bundled)}"'),
        (r"^  Game data: \d+ in pack, (0 missing|\d+ missing \(--verbose lists them\))$",
         '"  Game data: {gd_packed} in pack'),
        (r"^  Game data held but not packed: \d+ \(.+\)$", '"  Game data held but not packed: '),
        (r"^  Launcher reads, not held: \d+( \(--verbose lists them\))?$",
         '"  Launcher reads, not held: {len(rows)}{listed}"'),
        (r"^  Launcher records unproven: \d+( \(--verbose lists them\))?$",
         '"  Launcher records unproven: {len(rows)}{listed}"'),
        (r"^  No external files: \d+ cores \(--verbose lists them\)$",
         '"  No external files: {len(exclusions)} cores (--verbose lists them)"'),
        (r"^  Ground truth: \d+/\d+ files have emulator validation \(\d+%\)$",
         '"  Ground truth: {gt_cov[\'with_validation\']}/{gt_cov[\'total\']} files have emulator validation'),
        (r"^    \d+ platform-only \(no emulator profile\)$", '"    {no_profile} platform-only (no emulator profile)"'),
        (r"^    \S", None),
    )

    def test_the_shapes_are_verify_output(self):
        source = _read("scripts/verify.py")
        for _pattern, literal in self.SHAPES:
            if literal:
                with self.subTest(literal=literal):
                    self.assertIn(literal, source)

    def test_samples_match_a_shape(self):
        section = _section(_read("wiki/reading-reports.md"), "### Reading the output")
        blocks = re.findall(r"```\n(.*?)```", section, re.DOTALL)
        self.assertTrue(blocks)
        for block in blocks:
            for line in block.splitlines():
                with self.subTest(line=line):
                    self.assertTrue(
                        any(re.match(pattern, line) for pattern, _ in self.SHAPES), line
                    )

    def test_an_optional_count_without_its_suffix_is_refused(self):
        line = "  Core files: 1495 in pack, 0 required missing, 1 optional missing"
        self.assertFalse(any(re.match(pattern, line) for pattern, _ in self.SHAPES))

    def test_no_severity_column(self):
        self.assertNotIn("[CRITICAL]", _read("wiki/troubleshooting.md"))


class SizesComeFromTheRecord(unittest.TestCase):
    def test_the_quoted_pack_sizes_are_the_recorded_ones(self):
        text = _read("wiki/release-process.md")
        quoted = re.search(
            r"in (v[\d.]+),\s+(\w+) downloaded as ([\d.]+ GB) and extracted to"
            r"\s+([\d.]+ GB)",
            text,
        )
        self.assertIsNotNone(quoted, "the sizes are quoted with their release tag")
        tag, platform, download, extracted = quoted.groups()
        if tag != RECORD.get("tag"):
            self.skipTest(f"release.json records {RECORD.get('tag')}, not {tag}")
        pack = release_record.pack_for(platform.lower(), RECORD)
        self.assertEqual(download, format_size(pack["download_size"]))
        self.assertEqual(extracted, format_size(pack["extracted_size"]))


class ContributorChecksMatchCi(unittest.TestCase):
    """validate.yml fetches the data directories before the suite: the tests
    that build packs exit non-zero without them."""

    def test_the_pr_checklist_fetches_data_directories_before_the_tests(self):
        for text in (
            contributing_text(lambda page: page, "# C", "here"),
            _read("CONTRIBUTING.md"),
        ):
            block = _section(text, "## Before opening a PR")
            self.assertIn("python scripts/refresh_data_dirs.py", block)
            self.assertLess(
                block.index("refresh_data_dirs.py"), block.index("run_tests.py")
            )

    def test_ci_does_the_same(self):
        workflow = _read(".github/workflows/validate.yml")
        self.assertLess(
            workflow.index("python scripts/refresh_data_dirs.py"),
            workflow.index("python scripts/run_tests.py"),
        )

    def test_the_pr_checklist_generates_the_site_before_the_tests(self):
        # validate.yml generates the pages before the suite. Without them
        # the 228 tests that read the gitignored pages fail on a clone.
        workflow = _read(".github/workflows/validate.yml")
        self.assertLess(
            workflow.index("run: python scripts/generate_site.py"),
            workflow.index("python scripts/run_tests.py"),
        )
        for text in (
            contributing_text(lambda page: page, "# C", "here"),
            _read("CONTRIBUTING.md"),
        ):
            block = _section(text, "## Before opening a PR")
            self.assertIn("python scripts/generate_site.py", block)
            self.assertLess(
                block.index("generate_site.py"), block.index("run_tests.py")
            )


class PagesOpenOnTheirContent(unittest.TestCase):
    """The download page said "This page picks the right pack for a setup"
    before saying anything about a pack."""

    def test_no_paragraph_announces_its_page(self):
        import generate_site  # noqa: PLC0415

        text = generate_site.generate_which_pack()
        announcing = [
            line for line in text.splitlines()
            if re.match(r"(This|The) (page|section) ", line)
        ]
        self.assertEqual(announcing, [])


class CoreCountsReadFromTheData(unittest.TestCase):
    """The cores page said "623 cores across 18 platforms": that was every
    profile, and 91 of them no platform runs."""

    def test_the_run_count_is_what_the_platforms_resolve(self):
        import yaml
        from common import load_emulator_profiles, load_platform_config, resolve_platform_cores

        from tests import sitepages

        sitepages.require()
        text = sitepages.page("cross-reference.md").read_text(encoding="utf-8")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        # A test core says so in role, its type staying operational.
        unique = {k: v for k, v in profiles.items()
                  if v.get("type") != "alias" and v.get("role") != "test"}
        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text(
            encoding="utf-8"))["platforms"]
        run = set()
        for name in registry:
            config = load_platform_config(name, str(REPO_ROOT / "platforms"))
            run |= set(resolve_platform_cores(config, unique))
        said = re.search(r"([\d,]+) cores are profiled, ([\d,]+) of them run by the (\d+) platforms",
                         text)
        self.assertIsNotNone(said, "the page says how many profiled cores the platforms run")
        self.assertEqual(int(said[1].replace(",", "")), len(unique))
        self.assertEqual(int(said[2].replace(",", "")), len(run))
        self.assertEqual(int(said[3]), len(registry))


# What the generators write must not bring back what the project retired.
# The generated pages, README.md, CONTRIBUTING.md and the site's components
# are read for a retired command, address or feature term, each listed with
# the reason it was retired, and for every `--option` a generated command
# passes: the script it names must declare it in its parser. The pages copied
# from wiki/ are left to their own tests: the installer page keeps the raw
# one-liner as the documented fallback.


def _sitepages():
    from tests import sitepages

    return sitepages

# (string, why it is retired). Compared case-sensitively against the text.
RETIRED = (
    ("raw.githubusercontent.com/Abdess/retrobios/main/install.sh",
     "the site serves the one-liner at https://abdess.github.io/retrobios/i "
     "since 2026-10-28, pinned to the commit the site was built from"),
    ("raw.githubusercontent.com/Abdess/retrobios/main/install.ps1",
     "served at https://abdess.github.io/retrobios/i.ps1 since 2026-10-28"),
    ("Abdess/retroarch_system",
     "the repository was renamed retrobios in March 2026"),
    ("mkdocs serve", "the MkDocs site was replaced by Astro Starlight on 2026-10-22"),
    ("mkdocs build", "the MkDocs site was replaced by Astro Starlight on 2026-10-22"),
    ("pip install mkdocs", "the site is built by Node from website/package-lock.json"),
    ('class="rb-tested', "the Tested blocks were removed on 2026-10-28: "
     "only Proof lines and the Measurements page remain"),
    ("rb-region-runs", "region outcomes left the system pages on 2026-10-28"),
    ("## Campaign", "the campaign table left the Measurements page on 2026-10-28"),
    ("| Tested by |", "the coverage table left the Measurements page on 2026-10-28"),
    ("ms per frame", "benchmark figures stay in the records and SQLite files, "
     "never on a page, since 2026-10-28"),
    ("with this BIOS folder as", "the Tested block of platform pages, removed on 2026-10-28"),
    ("regenerated in its native format", "the export patches each platform's own "
     "file and never regenerates it (scripts/exporter/base_exporter.py needs_original)"),
)

COMMAND = re.compile(
    r"(?:python3? (?P<script>scripts/[\w/]+\.py|install\.py)"
    r"|python3? -m (?P<module>scripts(?:\.\w+)+)"
    r"|(?P<oneliner>retrobios/i \| sh -s --|retrobios/i\.ps1\)\)\)))"
    r"(?P<args>[^\n`<|]*)"
)
OPTION = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")


def retired_hits(text: str) -> list[str]:
    return [term for term, _why in RETIRED if term in text]


@cache
def parser_options(script: str) -> frozenset[str]:
    """The long options *script* declares through add_argument, with the
    shared ones of scraper_cli for a scraper that hands its parser over."""
    source = (REPO_ROOT / script).read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            found.update(arg.value for arg in node.args
                         if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                         and arg.value.startswith("--"))
    if "scraper_cli(" in source and script != "scripts/scraper/base_scraper.py":
        found |= parser_options("scripts/scraper/base_scraper.py")
    return frozenset(found)


def unknown_options(text: str) -> list[str]:
    """Each `script --option` of a command whose script does not declare it."""
    wrong = []
    for match in COMMAND.finditer(text):
        if match["oneliner"]:
            script = "install.py"
        elif match["module"]:
            script = match["module"].replace(".", "/") + ".py"
        else:
            script = match["script"]
        if not (REPO_ROOT / script).is_file():
            wrong.append(f"{script}: no such script")
            continue
        known = parser_options(script)
        wrong += [f"{script} {option}" for option in OPTION.findall(match["args"])
                  if option not in known]
    return wrong


def _surfaces() -> dict[str, str]:
    content = _sitepages().require()
    texts = {
        str(path.relative_to(REPO_ROOT)): path.read_text(encoding="utf-8")
        for path in sorted(content.rglob("*.md*"))
        if "wiki" not in path.relative_to(content).parts
    }
    for name in ("README.md", "CONTRIBUTING.md"):
        texts[name] = (REPO_ROOT / name).read_text(encoding="utf-8")
    for path in sorted((REPO_ROOT / "website" / "src").glob("*/*")):
        if path.suffix in (".astro", ".ts", ".css", ".mjs"):
            texts[str(path.relative_to(REPO_ROOT))] = path.read_text(encoding="utf-8")
    return texts


class RetiredTermsStayRetired(unittest.TestCase):
    def test_each_retired_term_says_why(self):
        for term, why in RETIRED:
            with self.subTest(term=term):
                self.assertTrue(term.strip())
                self.assertGreater(len(why.split()), 4)

    def test_the_check_finds_what_the_old_output_wrote(self):
        old = (
            "curl -fsSL https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh | sh\n"
            '## Tested\n\n<div class="rb-tested">\n'
            "The same comparison drives `scripts/exporter/`: each platform's own "
            "file can be regenerated in its native format with these differences.\n"
        )
        self.assertEqual(retired_hits(old), [
            "raw.githubusercontent.com/Abdess/retrobios/main/install.sh",
            'class="rb-tested', "regenerated in its native format",
        ])

    def test_no_surface_brings_one_back(self):
        found = {name: hits for name, text in _surfaces().items()
                 if (hits := retired_hits(text))}
        self.assertEqual(found, {})


class EveryOptionExists(unittest.TestCase):
    def test_the_check_reads_each_form_of_command(self):
        text = (
            "python scripts/generate_pack.py --platform retroarch --zip-all\n"
            "curl -fsSL https://abdess.github.io/retrobios/i | sh -s -- --check --frobnicate\n"
            "&([scriptblock]::Create((irm https://abdess.github.io/retrobios/i.ps1))) --dry-run\n"
            "python -m scripts.scraper.libretro_scraper --dry-run\n"
        )
        self.assertEqual(unknown_options(text), [
            "scripts/generate_pack.py --zip-all", "install.py --frobnicate",
        ])

    def test_every_generated_command_names_options_its_script_has(self):
        wrong = {name: bad for name, text in _surfaces().items()
                 if (bad := unknown_options(text))}
        self.assertEqual(wrong, {})


class ContributorChecksFetchThePlatformsFiles(unittest.TestCase):
    """validate.yml fetches each platform's own file before the suite. The
    checklist left it out, so the exporter fidelity cases skipped on a
    contributor's clone and first ran, red, in CI."""

    def test_the_pr_checklist_fetches_them_before_the_tests(self):
        workflow = _read(".github/workflows/validate.yml")
        self.assertLess(
            workflow.index("python scripts/export_native.py --all --refresh-cache"),
            workflow.index("python scripts/run_tests.py"),
        )
        for text in (
            contributing_text(lambda page: page, "# C", "here"),
            _read("CONTRIBUTING.md"),
        ):
            block = _section(text, "## Before opening a PR")
            self.assertIn("python scripts/export_native.py --all --refresh-cache", block)
            self.assertLess(
                block.index("export_native.py"), block.index("run_tests.py")
            )

    def test_the_testing_guide_names_the_command(self):
        self.assertIn("export_native.py --all --refresh-cache", _read("wiki/testing-guide.md"))


class ArchiveRecipesAreCountedFromTheRecipes(unittest.TestCase):
    """Every archive has a recipe in recipes/archives.json: the README and
    the site's page say how many rebuild exact and canonical, counted from
    that file, never typed."""

    def setUp(self) -> None:
        import archive_build  # noqa: PLC0415

        records = archive_build.load_ledger().values()
        self.counts = {
            "total": len(records),
            "exact": sum(r["rebuild"] == "exact" for r in records),
            "canonical": sum(r["rebuild"] == "canonical" for r in records),
        }
        self.assertEqual(archive_build.rebuild_counts(), self.counts)
        self.assertEqual(self.counts["exact"] + self.counts["canonical"], self.counts["total"])

    def test_the_readme_line(self) -> None:
        from generate_readme import archive_line  # noqa: PLC0415

        line = archive_line(self.counts)
        self.assertIn(line, _read("README.md").splitlines())
        self.assertIn(f"**{self.counts['total']:,} archives**", line)
        self.assertIn(f"{self.counts['exact']:,} byte for byte", line)
        self.assertIn(f"{self.counts['canonical']:,} with the same files inside", line)
        self.assertIn(f"({SITE_URL}wiki/archive-recipes/)", line)

    def test_the_page_counts(self) -> None:
        import generate_site  # noqa: PLC0415

        page = _read("wiki/archive-recipes.md")
        self.assertEqual(generate_site.with_archive_counts(page, self.counts), page,
                         "wiki/archive-recipes.md counts are stale: run scripts/generate_site.py")
        for line in generate_site.archive_recipe_lines(self.counts):
            self.assertIn(line, page)

    def test_the_page_command_is_the_tools(self) -> None:
        command = re.search(r"python scripts/romset_recipes.py (.+)", _read("wiki/archive-recipes.md"))
        source = _read("scripts/romset_recipes.py")
        for flag in re.findall(r"--[a-z-]+", command.group(1)):
            with self.subTest(flag=flag):
                self.assertIn(f'"{flag}"', source)


class TheReadmeBadges(unittest.TestCase):
    """One row of two badges under the links, each linking its source."""

    EXPECTED = (
        '<p align="center">'
        '<a href="https://pypi.org/project/retrobios/"><img src="https://img.shields.io/pypi/v/retrobios" alt="PyPI version"></a> '
        f'<a href="{REPO}/actions/workflows/validate.yml"><img src="{REPO}/actions/workflows/validate.yml/badge.svg?branch=main" alt="Validation"></a>'
        "</p>"
    )

    def test_exactly_these_two(self) -> None:
        readme = _read("README.md")
        self.assertEqual(len(re.findall(r"<img src=\"https://(?:img\.shields\.io|github\.com)/", readme)), 2)
        lines = readme.splitlines()
        self.assertIn(self.EXPECTED, lines)
        links = next(i for i, line in enumerate(lines) if ">Get the files</a>" in line)
        self.assertEqual(lines[links + 2], self.EXPECTED)

    def test_the_workflow_and_the_license_exist(self) -> None:
        self.assertTrue((REPO_ROOT / ".github" / "workflows" / "validate.yml").is_file())
        self.assertTrue((REPO_ROOT / "LICENSE").is_file())


if __name__ == "__main__":
    unittest.main()
