"""What the wiki and the generated README state holds against the code.

Each class reads a page and the code it describes. A page that quotes a
function's return shape, a resolution order or a field list drifts when the
code moves, and nothing else notices.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import hashlib
import inspect
import io
import json
import re
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIKI = ROOT / "wiki"
sys.path.insert(0, str(ROOT / "scripts"))

from tests.test_prose_style import _python_prose, _sentence_case  # noqa: E402

FENCED = re.compile(r"^```.*?^```", re.S | re.M)
PUBLISHED = sorted(WIKI.glob("*.md")) + [ROOT / "README.md", ROOT / "CONTRIBUTING.md"]


def _page(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    """Body of a markdown section, up to the next heading of any level."""
    start = re.search(rf"(?m)^#+ {re.escape(heading)}\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    blanked = FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), rest)
    end = re.search(r"(?m)^#+ ", blanked)
    return rest[: end.start()] if end else rest


def _table_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        if line.startswith("|") and not re.match(r"\|\s*-", line):
            rows.append([cell.strip() for cell in line.strip().strip("|").split(" | ")])
    return rows[1:]


class TestSkeletonReadsTheResultShape(unittest.TestCase):
    """The skeleton indexed verify_platform's result as a list, and a test
    copied from it stopped on KeyError: 0 before any assertion."""

    def test_every_key_it_reads_is_one_verify_platform_returns(self):
        from verify import verify_platform

        result = verify_platform(
            {"platform": "x", "verification_mode": "existence", "systems": {}},
            {"files": {}, "indexes": {}},
            emu_profiles={},
        )
        text = _page("testing-guide.md").split("Example skeleton:", 1)[1]
        code = re.search(r"```python\n(.*?)```", text, re.S).group(1)
        read = [
            node.slice
            for node in ast.walk(ast.parse(code))
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "result"
        ]
        self.assertTrue(read, "the skeleton no longer reads the result")
        for key in read:
            self.assertIsInstance(key, ast.Constant)
            self.assertIn(key.value, result)


def _generated(text: str, name: str) -> str:
    """The body scripts/generate_installer_doc.py writes between the markers."""
    return re.search(rf"(?s)<!-- generated: {name} -->\n(.*?)<!-- /generated: {name} -->",
                     text).group(1)


class InstallerOutputExample(unittest.TestCase):
    """The page showed a run with no `Not installable:` line while the
    RetroArch manifest left eleven entries out, and a count that the menu
    example below it no longer shared. Its run samples were then typed by
    hand and compared here, so a new list left the page stale and this test
    red until someone retyped them: scripts/generate_installer_doc.py now
    prints each one with install.py from the committed list."""

    def test_the_samples_are_the_ones_the_installer_prints(self):
        import generate_installer_doc

        page = _page("installer.md")
        self.assertEqual(generate_installer_doc.render(page), page,
                         "run python scripts/generate_installer_doc.py")
        for name in ("dry-run", "run-date", "run-index", "run-download", "run-end", "run-check"):
            with self.subTest(sample=name):
                self.assertIn(f"<!-- generated: {name} -->", page)

    def test_a_retyped_count_fails_the_check(self):
        import generate_installer_doc

        page = _page("installer.md")
        for name in ("dry-run", "run-end", "bulk-hint"):
            with self.subTest(sample=name):
                body = _generated(page, name)
                edited = re.sub(r"\d+", lambda m: str(int(m.group(0)) + 1), body, count=1)
                stale = page.replace(body, edited)
                self.assertNotEqual(stale, page)
                self.assertEqual(generate_installer_doc.render(stale), page)

    def test_a_sample_is_dated_by_its_list_never_by_the_day_it_ran(self):
        import generate_installer_doc

        page = _page("installer.md")
        for name, platform in (("dry-run", "retroarch"), ("run-date", "batocera")):
            with self.subTest(sample=name):
                listed = (ROOT / "install" / f"{platform}.json").read_text(encoding="utf-8")
                date = json.loads(listed)["generated"][:10]
                self.assertIn(f"the list of {date}", _generated(page, name))
        self.assertNotIn(str(ROOT), page)
        home = f"{generate_installer_doc.SHOWN_HOME}/.config/retroarch"
        self.assertIn(home, _generated(page, "dry-run"))

    def test_run_and_menu_show_one_run_of_the_manifest(self):
        import install

        text = _page("installer.md")
        run = _generated(text, "dry-run")
        manifest = json.loads((ROOT / "install" / "retroarch.json").read_text(encoding="utf-8"))
        # The line as the installer writes it (not_installable_words), or
        # its earlier "(1 required, not found: 37)" form.
        omitted = re.search(r"Not installable: \d+ files? (?:\(\d+ required, (.*)\)\.|(?:is|are) "
                            r"not in the collection|.*Why: (.*)\.)", run)
        self.assertEqual(omitted is not None, bool(manifest.get("omitted_files")))
        if omitted and (omitted.group(1) or omitted.group(2)):
            for part in (omitted.group(1) or omitted.group(2)).split(", "):
                self.assertIn(re.split(r":| \(", part)[0], install.OMISSION_REASONS.values())
        count, size = re.search(r"\n  (\d+) files \(([\d.]+ [KMG]B)\)", run).groups()
        self.assertIn(f"0 in place, {count} missing", run)
        self.assertSplitAddsUp(run, count, size)
        menu = re.search(r"RetroArch: (\d+) files, ([\d.]+ [KMG]B)[.,]([^`]*)",
                         _generated(text, "line-menu"))
        self.assertEqual(menu.groups()[:2], (count, size))
        self.assertSplitAddsUp(menu.group(3), count, size)
        games = re.search(r"g\) Game data: kept \((\d+) files, ([\d.]+ [KMG]B)\)",
                          menu.group(3))
        self.assertIsNotNone(games, "the menu offers to leave the game data out")
        split = re.search(r"(\d+) BIOS files \(([\d.]+ [KMG]B)\)(?:,| and) (\d+) game data "
                          r"files \(([\d.]+ [KMG]B)\)", menu.group(3))
        self.assertEqual(games.groups(), split.groups()[2:])

    def assertSplitAddsUp(self, text: str, count: str, size: str) -> None:
        """The run counted 8069 files where its menu counted 3259 BIOS files
        and 5089 game data files: the parts add up to the total they divide,
        the sizes within the rounding of their three figures."""
        # Data files are a third kind, counted beside the two.
        split = re.search(r"(\d+) BIOS files \(([\d.]+) ([KMG]B)\)(?:,| and) (\d+) game data "
                          r"files \(([\d.]+) ([KMG]B)\)", text)
        self.assertIsNotNone(split, "a categorized list says its BIOS files and game data")
        bios, bios_size, bios_unit, games, game_size, game_unit = split.groups()
        # The data files in the one total, the third kind.
        data = re.search(r"and (\d+) data files \(([\d.]+) ([KMG]B)\)", text)
        data_count, data_size, data_unit = data.groups() if data else ("0", "0", "KB")
        self.assertEqual(int(bios) + int(games) + int(data_count), int(count))
        units = {"KB": 1, "MB": 1024, "GB": 1024 ** 2}
        total, unit = size.split()
        added = (float(bios_size) * units[bios_unit] + float(game_size) * units[game_unit]
                 + float(data_size) * units[data_unit])
        self.assertLessEqual(abs(added - float(total) * units[unit]), 0.15 * units[unit])


class InstallerSamplesSayWhatTheCodePrints(unittest.TestCase):
    """Samples typed by hand outside the
    generated blocks, a sentence on a log read as the terminal's, pages that
    described the generator as tables alone, and a sandbox that asked DNS."""

    def test_the_refused_and_from_samples_are_generated(self):
        import install

        page = _page("installer.md")
        refused = _generated(page, "check-refused")
        self.assertRegex(refused, r"\n  \d+ files? [a-z ]+:\n")
        self.assertIn("read by beetle_psx, pcsx_rearmed at", refused)
        self.assertNotRegex(page, r"opened at /\S+ by ")
        self.assertIn('"read by ', inspect.getsource(install.opened_line))
        ending = _generated(page, "from-run")
        self.assertRegex(ending, r"Done\. \d+ files installed\.\n  \d+ files copied from ")
        self.assertNotIn("a line under\n`Done`", page)
        self.assertNotIn("38 files copied from E:\\, 4 downloaded", page)

    def test_one_line_per_file_is_said_of_a_log(self):
        page = _page("installer.md")
        at = page.index("<!-- generated: run-download -->")
        before = page[page.rindex("\n\n", 0, at - 2):at]
        self.assertIn("At a terminal one progress line", before)
        self.assertIn("a pipe or a log gets one\nline per file", before)

    def test_the_generator_pages_name_the_run_samples_and_step_7(self):
        tools = _page("tools.md")
        row = next(line for line in tools.splitlines()
                   if line.startswith("| `generate_installer_doc.py`"))
        self.assertIn("run samples", row)
        self.assertIn("generate_installer_doc.py", next(
            line for line in tools.splitlines() if line.startswith("| 7 |")))
        self.assertIn("run samples", _page("installer.md").split(
            "The tables of options, events, exit codes, keys and card markers", 1)[1][:600])
        self.assertIn("generate_installer_doc.py", next(
            line for line in _page("adding-a-platform.md").splitlines()
            if line.startswith("- 7 ")))

    def test_the_sandbox_looks_nothing_up(self):
        import socket
        from unittest import mock

        import generate_installer_doc

        def no_lookup(*_args: object) -> str:
            raise AssertionError("the sandbox asked for a name")

        with mock.patch.object(socket, "getfqdn", no_lookup), \
                generate_installer_doc.Sandbox() as box:
            self.assertEqual(box.server.server_name, "127.0.0.1")


class OneResolutionChain(unittest.TestCase):
    """architecture.md drew path_suffix as the first step, before SHA1, while
    the code and verification-modes.md try it after every hash."""

    ORDER = ("SHA1", "SHA256", "CRC32", "MD5", "Path suffix")

    def test_the_table_follows_the_code(self):
        import common

        source = inspect.getsource(common.resolve_local_file)
        steps = re.findall(r"# \d+[a-z]?\. (SHA1|SHA256|CRC32|MD5|Path suffix)", source)
        self.assertEqual(tuple(dict.fromkeys(steps)), self.ORDER)
        table = _table_rows(_section(_page("verification-modes.md"), "File resolution chain"))
        methods = [row[1] for row in table[: len(self.ORDER)]]
        self.assertEqual(
            [next(m for m in self.ORDER if method.startswith(m)) for method in methods],
            list(self.ORDER),
        )

    def test_architecture_links_instead_of_drawing_a_second_one(self):
        section = _section(_page("architecture.md"), "File resolution chain")
        self.assertNotIn("```mermaid", section)
        self.assertIn("verification-modes.md#file-resolution-chain", section)


class ReleaseRefPromise(unittest.TestCase):
    """RETROBIOS_REF was said to pin a reproducible file set, while every
    release deletes the previous tags and large files come from one fixed
    release whatever the ref."""

    def test_the_page_says_what_a_tag_does_not_pin(self):
        import install

        self.assertIn("/large-files/", install.RELEASE_URL)
        self.assertIn("--cleanup-tag", _page("release-process.md"))
        row = next(
            line for line in _page("installer.md").splitlines()
            if line.startswith("| `RETROBIOS_REF`")
        )
        self.assertIn("`large-files`", row)
        self.assertIn("next release", row)
        for page in PUBLISHED:
            for paragraph in page.read_text(encoding="utf-8").split("\n\n"):
                if "RETROBIOS_REF" in paragraph:
                    self.assertNotIn("reproducible", paragraph, page.name)


class RequirementFieldsTable(unittest.TestCase):
    """The table stopped at native_id: native_path, mirror_of, alt_md5 and
    the native dict, the fields that make a platform YAML reversible, were
    named nowhere a scraper author reads first."""

    def test_every_field_and_native_key_is_listed(self):
        from dataclasses import fields

        from scraper.base_scraper import BiosRequirement

        section = _section(_page("adding-a-platform.md"), "BiosRequirement fields")
        listed = {row[0].strip("`") for row in _table_rows(section)}
        self.assertEqual(listed, {f.name for f in fields(BiosRequirement)})
        native_row = next(row for row in _table_rows(section) if row[0] == "`native`")[2]
        keys: set[str] = set()
        for path in (ROOT / "scripts" / "scraper").glob("*_scraper.py"):
            source = path.read_text(encoding="utf-8")
            keys |= set(re.findall(r'native\["(\w+)"\]', source))
            keys |= set(re.findall(r'native(?:: dict\[str, object\])?\s*=\s*\{"(\w+)"', source))
        self.assertTrue(keys)
        for key in keys:
            self.assertIn(f"`{key}`", native_row)


class ReleaseCommitCarriesTheManifests(unittest.TestCase):
    """The documented release commit left out install/*.json, which the
    release pipeline regenerates: v2026.10.10 added three by hand."""

    def test_the_commit_step_adds_what_the_pipeline_rewrites(self):
        pipeline = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn('"--manifest"', pipeline)
        block = _section(_page("release-process.md"), "Cutting a release")
        add = next(line for line in block.splitlines() if line.startswith("git add "))
        self.assertIn("install/*.json", add.split())


class PublishedHeadings(unittest.TestCase):
    """README.md kept '## Quick Install', the one Title Case heading left,
    because the casing test read wiki/ only."""

    def test_readme_and_contributing_use_sentence_case(self):
        offenders = []
        for page in (ROOT / "README.md", ROOT / "CONTRIBUTING.md"):
            text = FENCED.sub("", page.read_text(encoding="utf-8"))
            for title in re.findall(r"(?m)^#{1,4} (.+)$", text):
                if _sentence_case(title) != title:
                    offenders.append(f"{page.name}: {title}")
        self.assertEqual(offenders, [], "\n".join(offenders))


class FilesColumnParagraph(unittest.TestCase):
    """'Files is how many the pack holds' was glued to the paragraph above
    it, two paragraphs before the table whose column it described."""

    def test_it_names_the_column_in_its_own_paragraph_before_the_table(self):
        import generate_readme

        source = inspect.getsource(generate_readme)
        self.assertNotIn("Files is how many", source)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        paragraph = next(p for p in readme.split("\n\n") if "The Files column" in p)
        self.assertNotIn("\n", paragraph.strip())
        after = readme.split(paragraph, 1)[1].lstrip("\n")
        self.assertTrue(after.startswith("| Setup | Files |"))


class PageOpenings(unittest.TestCase):
    """Four pages opened by announcing what they cover."""

    META = re.compile(r"(?i)\bthis (page|guide) (covers|documents|explains|describes|picks)\b|^Diagnosis guide")

    def test_no_page_announces_itself(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in FENCED.sub("", page.read_text(encoding="utf-8")).splitlines()
            if self.META.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class NoHedgedRules(unittest.TestCase):
    """The profiling guide and the verification discipline turned rules into
    wishes ("it's worth", "Ideally", "something to look into")."""

    FILLER = re.compile(
        r"(?i)\bit'?s worth\b|\bworth noting\b|\bit helps to\b|^Ideally\b"
        r"|\bsomething to look into\b|\busually indicate\b"
    )

    def test_published_pages(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in FENCED.sub("", page.read_text(encoding="utf-8")).splitlines()
            if self.FILLER.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class DocstringsWithoutInsistence(unittest.TestCase):
    """truth.py shouted ONE and NEVER in an eighteen-line docstring, and
    generate_pack.py listed three guarantees under 'This ensures:' of which
    two said the same thing."""

    TICS = re.compile(r"\b(NEVER|ALWAYS|ONE|MUST)\b|This ensures:")

    def test_scripts_and_installer(self):
        offenders = []
        paths = sorted((ROOT / "scripts").rglob("*.py")) + [ROOT / "install.py"]
        for path in paths:
            for line in _python_prose(path.read_text(encoding="utf-8")).splitlines():
                if self.TICS.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}: {line.strip()[:80]}")
        self.assertEqual(offenders, [], "\n".join(offenders))


class PeerToneTowardPlatforms(unittest.TestCase):
    """Platform lists were called wrong, stale or corrected on public pages
    that their maintainers read."""

    WORDS = re.compile(
        r"(?i)\bgets wrong\b|\bstale (hash|entries|entry)\b|<their file>|\bpatch their\b"
        r"|, corrected\b|\bcorrected in place\b|\bdeclare incorrectly\b|\blist error\b"
        r"|\btheir syntax\b|\bthe platform lacks\b|\bthe odd one\b|\bmay not match reality\b"
        r"|\ball their code does\b|\bcan drift from\b"
    )

    def test_published_pages(self):
        offenders = [
            f"{page.name}: {line[:80]}"
            for page in PUBLISHED
            for line in page.read_text(encoding="utf-8").splitlines()
            if self.WORDS.search(line)
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


class RecalboxSeverity(unittest.TestCase):
    """The table gave verify.py a mapping from hashMatchMandatory that the
    code never reads, and called a missing optional file GREEN."""

    def test_the_verify_column_is_what_compute_severity_returns(self):
        from verify import Status, compute_severity

        section = _section(_page("verification-modes.md"), "Mandatory levels (Recalbox)")
        rows = _table_rows(section)
        self.assertTrue(rows)
        status = {"hash matches": Status.OK, "missing": Status.MISSING, "hash differs": Status.UNTESTED}
        for state, mandatory, _hash_match, _colour, expected in rows:
            for required in ((True, False) if mandatory == "(any)" else (mandatory == "true",)):
                self.assertEqual(
                    compute_severity(status[state], required, "md5").upper(), expected,
                    f"{state} mandatory={mandatory}",
                )
        self.assertNotIn("severity levels", _page("tools.md"))


class Md5CompositeDefinition(unittest.TestCase):
    """The page described the MD5 of the members' MD5s, the code hashes the
    members' contents in name order."""

    def test_page_and_code_agree(self):
        from hashing import md5_composite_of

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("b.rom", b"BBBB")
            zf.writestr("a.rom", b"AAAA")
        buffer.seek(0)
        self.assertEqual(md5_composite_of(buffer), hashlib.md5(b"AAAABBBB").hexdigest())
        section = _section(_page("verification-modes.md"), "md5_composite (Recalbox ZIP verification)")
        self.assertIn("contents of every member", section)
        self.assertNotIn("inner file MD5s", section)

    def test_composite_only_is_read_by_both_checks(self):
        """The page said the direct MD5 is tried before the composite, which
        Recalbox never does for a .zip, and the pack check did the same."""
        import common
        import validation

        section = _section(_page("verification-modes.md"), "md5_composite (Recalbox ZIP verification)")
        self.assertIn("zip_digest: composite", section)
        self.assertNotIn("is tried before reporting a mismatch", section)
        for function in (common.resolve_local_file, validation.digest_verdict):
            self.assertIn('get("zip_digest") == "composite"', inspect.getsource(function))


class ValidationIndexScope(unittest.TestCase):
    """The page said the index reads every profile. verify and the builder
    pass it only the profiles the platform resolves."""

    def test_page_names_the_scope_the_code_uses(self):
        import verify

        source = inspect.getsource(verify.verify_platform)
        self.assertRegex(source, r"plat_cores = resolve_platform_cores\(config, profiles\)")
        self.assertIn("_build_validation_index(platform_profiles)", source)
        section = _section(_page("verification-modes.md"), "Validation index")
        self.assertIn("resolve_platform_cores", section)
        self.assertNotIn("reads all emulator profiles", section)


class CoreResolutionWrittenOnce(unittest.TestCase):
    """architecture.md and adding-a-platform.md each stated the core
    resolution rule, and only one knew that a list naming retroarch takes
    every libretro profile. Neither said built_by profiles stay out."""

    def test_one_statement_matching_the_platforms_and_the_code(self):
        import yaml

        import common

        self.assertNotIn("cores: [list]", _page("architecture.md"))
        source = inspect.getsource(common.resolve_platform_cores)
        self.assertIn('not p.get("built_by")', source)
        self.assertIn('"retroarch" in core_set', source)
        naming = set()
        for path in (ROOT / "platforms").glob("*.yml"):
            config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            cores = config.get("cores")
            if isinstance(cores, list) and "retroarch" in map(str, cores):
                naming.add(str(config.get("platform") or path.stem).lower())
        section = _section(_page("adding-a-platform.md"), "Required fields")
        bullet = next(p for p in section.split("\n- ") if p.startswith("**Explicit list**"))
        used_by = re.search(r"Used by ([^.]+)\.", bullet.replace("\n", " ")).group(1)
        names = [n.strip().lower() for n in used_by.split(",")]
        self.assertIn("the last\n  four", bullet)
        self.assertEqual(set(names[-4:]), naming)
        libretro = next(p for p in section.split("\n- ") if p.startswith("**all_libretro**"))
        self.assertIn("built_by", libretro)


class ExitStatusTable(unittest.TestCase):
    """Code 2 was documented as 'every file failed' only, while argparse
    exits 2 on every refused option, and the 141 example named an option
    that does not exist."""

    def test_codes_and_options_are_the_installers(self):
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        section = _section(_page("installer.md"), "Exit status")
        documented = {int(row[0].strip("`")) for row in _table_rows(section)}
        raised = {int(code) for code in re.findall(r"sys\.exit\((\d+)\)", source)}
        # 0 is a run that returns, 2 the code argparse leaves with.
        self.assertEqual(documented, raised | {0, 2})
        self.assertIn("install.py: error:", section)
        for option in set(re.findall(r"(--[a-z][a-z-]+)", section)):
            self.assertIn(f'"{option}"', source, option)


class ProfileFieldsRequired(unittest.TestCase):
    """The table marked source, profiled_date, core_version and systems as
    required and called the schema authoritative, which requires none."""

    def test_yes_matches_the_schema(self):
        schema = json.loads((ROOT / "schemas" / "emulator.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        for rule in schema.get("allOf", []):
            for branch in ("then", "else"):
                required |= set(rule.get(branch, {}).get("required", []))
        section = _section(_page("profiling.md"), "Profile fields")
        marked = {
            row[0].strip("`") for row in _table_rows(section)
            if row[1].startswith(("yes", "for `type", "with `"))
        }
        self.assertEqual(marked, required)


class PythonFloorOnRetroPie(unittest.TestCase):
    """The page offered `apt install python3` to a RetroPie 4.8 image, where
    python3 is 3.7.3 and apt has nothing newer."""

    def test_both_pages_name_the_case(self):
        install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("(3, 8)", install_sh)
        first = _section(_page("first-install.md"), "Error: Python 3.8 or newer is required.")
        self.assertIn("RetroPie 4.8", first)
        self.assertIn("3.7.3", first)
        changing = _section(_page("installer.md"), "Changing the installer")
        self.assertIn("3.7.3", changing)


class ToolsRunOnTheStatedFloor(unittest.TestCase):
    """tools.md and testing-guide.md state Python 3.9 for every script, and
    check_release_assets.py built `int | None` at import: a TypeError on 3.9
    before any argument was read, in check_release.py too. CI runs 3.12 only,
    so this test reads the source for what 3.9 cannot evaluate."""

    TYPES = {"int", "str", "float", "bytes", "bool", "dict", "list", "tuple", "set", "type"}

    def _type_like(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        if isinstance(node, ast.Subscript):
            node = node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._type_like(node.left) or self._type_like(node.right)
        return isinstance(node, ast.Name) and node.id in self.TYPES

    def _runtime_unions(self, tree: ast.AST) -> list[int]:
        annotations = set()
        for node in ast.walk(tree):
            for field in ("annotation", "returns"):
                value = getattr(node, field, None)
                if value is not None:
                    annotations.update(id(n) for n in ast.walk(value))
        return [
            node.lineno for node in ast.walk(tree)
            if id(node) not in annotations
            and (isinstance(node, ast.Match)
                 or isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)
                 and (self._type_like(node.left) or self._type_like(node.right)))
        ]

    def test_pages_state_the_floor(self):
        self.assertIn("Python 3.9 or newer", _page("tools.md"))
        self.assertIn("Python 3.9 or newer", _page("testing-guide.md"))

    def test_no_script_evaluates_310_syntax(self):
        offenders = [
            f"{path.relative_to(ROOT)}:{line}"
            for path in sorted((ROOT / "scripts").rglob("*.py"))
            for line in self._runtime_unions(ast.parse(path.read_text(encoding="utf-8")))
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_check_catches_the_alias(self):
        self.assertTrue(self._runtime_unions(ast.parse("F = tuple[str, int | None]")))
        self.assertFalse(self._runtime_unions(ast.parse("def f(x: int | None) -> str | None: ...")))
        self.assertFalse(self._runtime_unions(ast.parse("mask = flags | other")))


class DeriveFiguresLiveWithTheTool(unittest.TestCase):
    """tools.md gave --derive about 90 s and 67 entries while its --help said
    about 35 s: two hand-kept figures for one run, measured at 33 s."""

    def test_the_page_carries_no_duration_or_count(self):
        paragraph = next(
            p for p in _page("tools.md").split("\n\n") if "`--derive` reads" in p
        )
        self.assertNotRegex(paragraph, r"\d+ ?s\b|\d+ entries")
        self.assertIn("derivable.json", paragraph)


class EmulatorVerboseSample(unittest.TestCase):
    """advanced-usage.md showed `handy validates size=512 crc32=0x0d973c9d
    [src/handy/system.h:45]`, a format verify.py does not print and a
    reference handy.yml does not cite."""

    def test_every_sample_line_is_printed(self):
        import subprocess

        section = _section(_page("advanced-usage.md"), "Per-emulator checks")
        sample = [body for lang, body in re.findall(r"(?ms)^```(\w*)\n(.*?)^```", section) if not lang][-1]
        printed = subprocess.run(
            [sys.executable, "scripts/verify.py", "--emulator", "handy", "--verbose"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines()
        for line in sample.splitlines():
            with self.subTest(line=line):
                self.assertIn(line, printed)


class ShortMd5Handling(unittest.TestCase):
    """Three pages said some Batocera entries carry 29-character MD5s and show
    as untested. No platform YAML holds one, since the Batocera scraper
    completes them, and adding-a-scraper.md said to store them as-is."""

    def test_no_page_claims_short_md5_entries(self):
        offenders = [
            page.name for page in PUBLISHED
            if re.search(r"(?i)29[- ]char|truncated md5 hashes in some entries|store the hash as-is",
                         page.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

    def test_the_page_names_what_the_code_does(self):
        import common
        from scraper import batocera_scraper

        scraper = inspect.getsource(batocera_scraper)
        self.assertIn("_resolve_truncated_md5(value, md5_index) for value in values", scraper)
        resolver = inspect.getsource(common.resolve_local_file)
        self.assertIn("cut_md5_owner(cut, by_md5)", resolver)
        self.assertIn("_md5_name_ok(path)", resolver)
        section = _section(_page("verification-modes.md"), "MD5 shorter than 32 characters (Batocera)")
        self.assertIn("_resolve_truncated_md5", section)
        self.assertIn("cut_md5_owner", section)


class RegistryKeysDocumented(unittest.TestCase):
    """zip_digest, firmware_folder_flat and extract_to were read from the
    registry by the resolver, the pack and the README, and the page that
    adds a platform named none of them while saying runtime behaviour lives
    in the platform YAML only."""

    def test_every_registry_key_is_on_the_page(self):
        import yaml

        registry = yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))
        keys = {key for entry in registry["platforms"].values() for key in entry}
        page = _page("adding-a-platform.md")
        self.assertEqual(sorted(k for k in keys if not re.search(rf"\b{k}\b", page)), [])

    def test_the_page_says_the_registry_reaches_the_config(self):
        import common

        source = inspect.getsource(common.load_platform_config)
        self.assertIn("config[key] = val", source)
        section = _section(_page("adding-a-platform.md"), "Step 2: Register the platform")
        self.assertIn("copies every registry key", section)
        self.assertNotIn("belongs to the platform\nYAML", section)


class ResolutionSkipsNamesForUnheldFiles(unittest.TestCase):
    """The resolution table promised name_exact to any entry without a hash,
    while an unsourceable entry, or one whose indexed path is absent from
    disk, skips every step that answers by name and returns not_found."""

    def test_the_page_names_both_cases_the_code_guards(self):
        import common

        source = inspect.getsource(common.resolve_local_file)
        self.assertIn('unsourceable = bool(file_entry.get("unsourceable")) or own_file_absent', source)
        for guard in (
            "if not has_strong_hash and not unsourceable:",
            "elif not unsourceable:",
            "if _depth < 3 and not has_strong_hash and not unsourceable:",
            "if data_dir_registry and (has_strong_hash or not unsourceable):",
        ):
            self.assertIn(guard, source)
        section = _section(_page("verification-modes.md"), "File resolution chain")
        self.assertIn("`unsourceable:`", section)
        self.assertIn("restore_large_files.py", section)


class CiTriggersPointToTheirLists(unittest.TestCase):
    """The CI table listed six directories for validate.yml, which also runs
    on the installer, wiki/ and every other site input: a contributor
    touching only wiki/ read that no check would run."""

    def test_the_table_does_not_copy_a_path_list(self):
        import yaml

        section = _section(_page("architecture.md"), "CI workflows")
        self.assertNotRegex(section, r"on bios/, platforms/|\(platforms, emulators, wiki, scripts\)")
        self.assertIn("`paths:`", section)
        self.assertIn("test_workflow_paths.py", section)
        workflow = yaml.safe_load((ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8"))
        paths = workflow.get("on", workflow.get(True))["pull_request"]["paths"]
        for named in ("wiki/**", "install.sh"):
            self.assertIn(named, paths)
            self.assertIn(f"`{named.rstrip('*')}`", section)


class ScratchFilesGoToRepoTmp(unittest.TestCase):
    """adding-a-scraper.md wrote its comparison to /tmp while two other
    pages say /tmp is a RAM disk and send scratch files to the repo's tmp/."""

    @staticmethod
    def _code_lines(text: str) -> list[str]:
        lines, inside = [], False
        for line in text.splitlines():
            if line.strip().startswith("```"):
                inside = not inside
            elif inside:
                lines.append(line)
        return lines

    def test_no_command_writes_to_slash_tmp(self):
        offenders = [
            f"{page.name}: {line.strip()}"
            for page in PUBLISHED
            for line in self._code_lines(page.read_text(encoding="utf-8"))
            if re.search(r"(?<![\w.])/tmp/", line)
        ]
        self.assertEqual(offenders, [])
        old = "   ```bash\n   python x.py --output /tmp/test.yml\n   ```\n"
        self.assertEqual(self._code_lines(old), ["   python x.py --output /tmp/test.yml"])
        self.assertIn("tmp/", (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())


class ReadmeInstallerOptions(unittest.TestCase):
    """The README named --system, --region and --check but showed options
    only after `sh -s --`. Appended to `irm ... | iex`, PowerShell rejects
    them, and the form that works was on the installer page alone, which the
    README never linked."""

    def test_quick_install_gives_the_powershell_form_and_the_page(self):
        import generate_readme

        source = inspect.getsource(generate_readme.generate_readme)
        self.assertIn("wiki/installer/#passing-options", source)
        self.assertIn("## Passing options", _page("installer.md"))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quick = _section(readme, "Install in one line")
        # The README gives the bare line and sends options to the page that
        # writes their PowerShell form: an option after `| iex` reaches iex.
        self.assertIn("wiki/installer/#passing-options", quick)
        self.assertNotRegex(readme, r"(?m)^irm \S+ \| iex \S")


class PublishedNumbersShareOneFormat(unittest.TestCase):
    """The README gave the collection as `16011 MB` beside `19,526 files`,
    the site home as 15.6 GB, and the emulators page `10095 files`."""

    def test_generators_format_counts_and_sizes_alike(self):
        import generate_readme
        import generate_site

        readme_source = inspect.getsource(generate_readme.generate_readme)
        self.assertNotIn("size_mb", readme_source)
        self.assertIn("format_size(size)", readme_source)
        self.assertIn("{total_files:,}", inspect.getsource(generate_site))
        self.assertEqual(generate_readme.format_size(16011 * 1024 * 1024), "15.6 GB")

    def test_the_readme_has_no_bare_large_count(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"\*\*\d{4,}\b[^*]*\*\*", readme), [])


class FirstInstallWalkthrough(unittest.TestCase):
    """First install showed a Batocera run of 12893 files with no omission
    line and said any other ending meant work left undone, while every
    Batocera run printed 399 files not installed. Its disk sizes (Batocera
    4.0 GB) contradicted its own example (8.6 GB), and its no-platform case
    said a piped command cannot ask, where install.sh hands it the terminal
    and the installer shows a menu. The annotated run now lives in the
    installer page, under Reading a run: First install keeps the steps."""

    def setUp(self):
        self.text = _page("first-install.md")
        self.run = _page("installer.md")

    def test_the_stop_keys_are_the_ones_the_screen_names(self):
        """The page said "B or Ctrl+C stops it" for a computer, whose screen
        says Esc or Ctrl-C, and where the b key does nothing."""
        import install

        section = _section(self.text, "4. Wait")
        computer = install.TUI_ROUTES["keys"].stop[0].replace("Ctrl-C", "Ctrl+C")
        self.assertIn(f"{computer} stops", section)
        self.assertIn(f"{install.TUI_ROUTES['gptokeyb'].stop[0]} on a handheld", section)

    def test_no_hand_kept_size_before_the_run(self):
        import install

        section = _section(self.run, "Before the run")
        # The confirmation threshold is a constant of the installer, not a pack size.
        self.assertEqual(install.CONFIRM_FROM_BYTES, 1024 ** 3)
        self.assertIn("reaches 1 GB", section)
        self.assertNotRegex(section.replace("reaches 1 GB", ""), r"\d+(\.\d+)? ?[KMG]B\b")

    def test_the_run_is_one_run_of_the_manifest(self):
        """The counts are printed by the generator, so they are not retyped
        here: what is checked is that the five samples are one run."""
        import install

        # First install names the three endings the full screen shows as
        # its title, and no count: a figure from one setup read as the size
        # of every install.
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        for ending in ("Done", "Finished with errors", "Nothing installed"):
            with self.subTest(ending=ending):
                self.assertIn(f"**{ending}**", _section(self.text, "5. Read the result"))
                self.assertIn(f'title = "{ending}"', source)
        self.assertNotRegex(self.text, r"\d+ (in place|missing|files installed)")
        self.assertIn(f"  {install.EVERYTHING_IN_PLACE}", self.text)
        step3 = _generated(self.run, "run-index")
        count = re.search(r"\n  (\d+) files \([\d.]+ [KMG]B\)", step3).group(1)
        self.assertIn(f"0 in place, {count} missing", step3)
        # The data trees are fetched after the files, from their archives:
        # the download line counts the files alone.
        trees = re.search(r" and (\d+) data files", step3)
        downloaded = int(count) - (int(trees.group(1)) if trees else 0)
        self.assertRegex(_generated(self.run, "run-download"),
                         rf"Downloading {downloaded} files \([\d.]+ [KMG]B\)")
        step4 = _generated(self.run, "run-end")
        self.assertIn(f"Done. {count} files installed", step4)
        self.assertIn(f"{count} in place, 0 missing", _generated(self.run, "run-check"))
        manifest = json.loads((ROOT / "install" / "batocera.json").read_text(encoding="utf-8"))
        omitted = manifest.get("omitted_files") or []
        self.assertEqual("Not installable:" in step3, bool(omitted))
        # The prose under the end of the run names both lines a required
        # omission can take, whichever this list prints.
        section = _section(self.run, "The end of the run")
        for words in ("Not available here", "Needed to start an emulator"):
            self.assertIn(f"`{words}`", section)
        needed = [entry for entry in omitted if entry.get("required")]
        if any(entry.get("category") == install.GAME_DATA for entry in needed):
            self.assertIn("Not available here:", step4)
        if any(entry.get("category") != install.GAME_DATA for entry in needed):
            self.assertIn("Needed to start an emulator", step4)

    def test_nothing_found_reads_like_the_installer(self):
        # The one-liner hands the terminal to the installer, which opens the
        # full screen: its first screen says the heading and offers the row.
        import install

        self.assertIn('"$INSTALLER" "$@" </dev/tty', (ROOT / "install.sh").read_text(encoding="utf-8"))
        state = install.TuiState()
        screen = "\n".join(install.tui_view(state, 80, 24))
        self.assertIn("Nothing was found here.", screen)
        section = _section(self.text, "Nothing was found here.")
        self.assertIn(f"**{install.tui_rows(state)[-1].label}**", section)
        self.assertNotIn("cannot stop and ask", section)


class RetroArchWindowsSystemFolder(unittest.TestCase):
    """Getting started gave %APPDATA%\\RetroArch\\system for the Windows
    installer. RetroArch's default is `:\\system`, the folder of
    retroarch.exe (platform_win32.c). %APPDATA% is where a retroarch.cfg
    can live, and install.py reads it there. The RetroArch page of the site
    states the folder now, from the guide data."""

    def test_page_and_installer_agree(self):
        import install

        source = inspect.getsource(install)
        self.assertIn('ra_dir or exe_dir / "system"', source)
        self.assertTrue(str(install._os_default_dests("windows")["retroarch"]).replace("\\", "/").endswith("/system"))
        from siteguides import GUIDES

        guide = GUIDES["retroarch"]
        section = "\n".join([*(path for _label, path in guide.folders), *guide.notes])
        self.assertNotIn("%APPDATA%\\RetroArch\\system", section)
        self.assertIn("`system\\` next to `retroarch.exe`", section)

    def test_the_macos_folder_is_the_installers(self):
        """The site gave Application Support/RetroArch/system for macOS. A
        RetroArch left at its defaults reads ~/Documents/RetroArch/system
        (platform_darwin.m), Application Support only for a portable or
        Steam build, and install.py looks there in that order."""
        import install
        from siteguides import GUIDES

        source = inspect.getsource(install._macos_retroarch_base)
        self.assertIn('Path.home() / "Documents" / "RetroArch"', source)
        folders = dict(GUIDES["retroarch"].folders)
        self.assertEqual(folders["macOS"], "`~/Documents/RetroArch/system/`")


# The contributor and reference pages state fields, scripts, options, paths,
# platform lists and examples that the code and the data already hold. Each
# check below reads both sides, so a page falls out of step the day the code
# moves rather than the day a reader trips on it.

CONTRIBUTOR_PAGES = (
    "profiling.md", "adding-a-platform.md", "adding-a-scraper.md", "architecture.md",
    "verification-modes.md", "reference-terms.md", "glossary.md", "legal.md", "index.md",
    "what-are-bios-files.md", "community-tools.md",
)
REPO_DIRS = (
    "scripts/", "platforms/", "emulators/", "schemas/", "tests/", "wiki/", "install/",
    "provenance/", "recipes/", "exports/", "measurements/", "website/", "automation/",
    "ports/", "docs_assets/", "docs/",
)
PLACEHOLDER = re.compile(r"[<>*{}]|myplatform|\bNAME\b|\.\.\.")


def _schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text(encoding="utf-8"))


def _schema_keys(schema: object, keys: set[str]) -> set[str]:
    if isinstance(schema, dict):
        keys.update(schema.get("properties", {}))
        for value in schema.values():
            _schema_keys(value, keys)
    elif isinstance(schema, list):
        for value in schema:
            _schema_keys(value, keys)
    return keys


def _registry() -> dict:
    import yaml

    return yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))["platforms"]


def _table_fields(section: str) -> set[str]:
    fields = set()
    for line in section.splitlines():
        cell = re.match(r"^\| ((?:`[a-z_0-9]+`(?:, )?)+) \|", line)
        if cell:
            fields |= set(re.findall(r"`([a-z_0-9]+)`", cell.group(1)))
    return fields


def _code_spans(text: str) -> list[str]:
    """Inline code and every line of fenced code."""
    spans = re.findall(r"`([^`\n]+)`", FENCED.sub("", text))
    for block in FENCED.findall(text):
        spans.extend(block.splitlines()[1:-1])
    return spans


def missing_repo_paths(text: str) -> list[str]:
    missing = []
    for span in _code_spans(text):
        for token in re.findall(r"[\w./-]+", span):
            if PLACEHOLDER.search(span) and "myplatform" in token:
                continue
            path = re.sub(r":[\d,-]+$", "", token).rstrip(".,")
            if path.startswith(REPO_DIRS) and not PLACEHOLDER.search(path):
                if not (ROOT / path).exists():
                    missing.append(path)
            elif re.fullmatch(r"test_\w+\.py", path) and not (ROOT / "tests" / path).exists():
                missing.append(path)
    return sorted(set(missing))


def _script_source(line: str) -> tuple[str, str] | None:
    """The command a line runs and the source its options must come from."""
    match = re.search(r"python3? (scripts/[\w/]+\.py)", line)
    if match:
        return match.group(1), (ROOT / match.group(1)).read_text(encoding="utf-8") \
            if (ROOT / match.group(1)).is_file() else ""
    match = re.search(r"python3? -m (scripts\.scraper\.[\w.]+)", line)
    if match:
        module = match.group(1)
        path = ROOT / (module.replace(".", "/") + ".py")
        source = path.read_text(encoding="utf-8") if path.is_file() else ""
        if "scraper_cli" in source or "myplatform" in module:
            source += (ROOT / "scripts/scraper/base_scraper.py").read_text(encoding="utf-8")
        return module, source
    return None


def unknown_commands(text: str) -> list[str]:
    wrong = []
    for span in _code_spans(text):
        for command in re.split(r"\||&&|;", span):
            found = _script_source(command)
            if found is None:
                continue
            name, source = found
            if not source:
                wrong.append(name)
                continue
            for option in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", command):
                if f'"{option}"' not in source:
                    wrong.append(f"{name} {option}")
    return sorted(set(wrong))


def fields_of_colon_tokens(text: str) -> set[str]:
    """`key:` and `key: value` spans: the page naming a YAML key."""
    return {
        m.group(1) for span in re.findall(r"`([^`\n]+)`", FENCED.sub("", text))
        if (m := re.fullmatch(r"([a-z][a-z0-9_]*):(?:\s.*)?", span))
    }


class PagesNameWhatExists(unittest.TestCase):
    """The pages named a target scraper PLATFORM_NAME the discovery does
    not use, a docs/ folder the site left, exporter methods that no longer
    exist and profile fields in the wrong table. Every path, script and
    option a page names is looked up."""

    def test_every_repository_path_exists(self):
        for name in CONTRIBUTOR_PAGES:
            with self.subTest(page=name):
                self.assertEqual(missing_repo_paths(_page(name)), [])

    def test_every_command_and_option_exists(self):
        for name in CONTRIBUTOR_PAGES:
            with self.subTest(page=name):
                self.assertEqual(unknown_commands(_page(name)), [])

    def test_the_checks_catch_the_old_text(self):
        self.assertEqual(missing_repo_paths("`scripts/scraper/targets/foo_targets.py`"),
                         ["scripts/scraper/targets/foo_targets.py"])
        self.assertEqual(unknown_commands("```bash\npython scripts/verify.py --no-such-flag\n```"),
                         ["scripts/verify.py --no-such-flag"])

    def test_every_yaml_key_a_page_names_is_a_schema_key(self):
        keys = set()
        for name in ("emulator", "platform", "registry"):
            _schema_keys(_schema(name), keys)
        keys |= {key for entry in _registry().values() for key in entry}
        for name in ("profiling.md", "reference-terms.md", "verification-modes.md"):
            with self.subTest(page=name):
                self.assertEqual(sorted(fields_of_colon_tokens(_page(name)) - keys), [])
        self.assertEqual(fields_of_colon_tokens("`bios_md5: abc`"), {"bios_md5"})


class ProfileFieldTables(unittest.TestCase):
    """Seven profile-level fields (pin_frozen, data_root, version_source and
    four more) sat in the file entry table, where a reader wrote them on a
    file and the schema refused it."""

    def test_each_table_holds_its_level_of_the_schema(self):
        schema = _schema("emulator")
        top = set(schema["properties"])
        entry = set(schema["properties"]["files"]["items"]["properties"])
        page = _page("profiling.md")
        profile_section = page.split("### Profile fields")[1].split("\n### ")[0]
        described = _table_fields(profile_section)
        described |= set(re.findall(r"`([a-z_0-9]+)`", profile_section.split("Descriptive fields")[1]))
        self.assertEqual(sorted(described ^ top), [])
        file_section = page.split("### File entry fields")[1].split("\n## ")[0]
        self.assertEqual(sorted(_table_fields(file_section) ^ entry), [])
        self.assertIn("pin_frozen", _table_fields("| `pin_frozen` | why |") - entry)


class PlatformListsFollowTheRegistry(unittest.TestCase):
    """The mode lists and the list of platforms naming their cores were
    written by hand: KNULLI, AmberELEC, EmuELEC and the MinUI family were
    missing from the core list."""

    def _names(self) -> dict[str, str]:
        import yaml

        names = {}
        for key, entry in _registry().items():
            config = yaml.safe_load((ROOT / "platforms" / entry["config"]).read_text(encoding="utf-8"))
            names[str(config.get("platform") or key)] = key
        return names

    def _modes(self) -> dict[str, str]:
        import common

        return {key: common.load_platform_config(key, str(ROOT / "platforms")).get("verification_mode")
                for key in _registry()}

    def _split(self, text: str) -> set[str]:
        names = self._names()
        listed = {n.strip() for n in re.split(r",|\band\b", text) if n.strip()}
        unknown = listed - set(names)
        self.assertEqual(unknown, set(), "not in platforms/_registry.yml")
        return {names[n] for n in listed}

    def test_verification_mode_sections(self):
        page = _page("verification-modes.md")
        modes = self._modes()
        seen = set()
        for mode, heading in (("existence", "Existence mode"), ("md5", "MD5 mode"), ("sha1", "SHA1 mode")):
            line = re.search(r"\*\*Platforms\*\*: (.+)", _section(page, heading)).group(1)
            keys = self._split(line)
            self.assertEqual({k for k in keys if modes[k] != mode}, set(), mode)
            seen |= keys
        self.assertEqual(seen, set(_registry()))

    def test_adding_a_platform_mode_table(self):
        section = _section(_page("adding-a-platform.md"), "Step 4: Add verification logic")
        modes = self._modes()
        seen = set()
        for row in _table_rows(section):
            keys = self._split(row[2])
            self.assertEqual({k for k in keys if modes[k] != row[0].strip("`")}, set(), row[0])
            seen |= keys
        self.assertEqual(seen, set(_registry()))

    def test_the_explicit_core_lists(self):
        import yaml

        section = _section(_page("adding-a-platform.md"), "Required fields")
        bullet = next(p for p in section.split("\n- ") if p.startswith("**Explicit list**"))
        used_by = re.search(r"Used by ([^.]+)\.", bullet.replace("\n", " ")).group(1)
        listing = set()
        for key, entry in _registry().items():
            config = yaml.safe_load((ROOT / "platforms" / entry["config"]).read_text(encoding="utf-8"))
            cores = entry.get("cores", config.get("cores"))
            if isinstance(cores, list) and cores:
                listing.add(key)
        self.assertEqual(self._split(used_by), listing)

    def test_the_check_refuses_an_unknown_platform(self):
        with self.assertRaises(AssertionError):
            self._split("RetroArch, Lakka, Batocera Plus")


class ListsFollowTheCode(unittest.TestCase):
    """The detection table named three of the eight methods the registry
    uses, the pipeline list stopped at eleven of its steps and the target
    scraper table at four of seven scrapers."""

    def test_install_detection_methods(self):
        used = {rule["method"] for entry in _registry().values()
                for rule in (entry.get("install") or {}).get("detect") or []}
        section = _section(_page("adding-a-platform.md"), "Step 7: Add install detection (optional)")
        self.assertEqual({row[0].strip("`") for row in _table_rows(section)}, used)

    def test_pipeline_steps(self):
        from pipeline import STEP_LABELS

        section = _section(_page("adding-a-platform.md"), "Step 8: Validate the full pipeline")
        listed = re.findall(r"^- (\d\w*) ", section, re.M)
        self.assertEqual(listed, [label.split(" ", 1)[0] for label in STEP_LABELS.values()])

    def test_target_scrapers(self):
        modules = {p.stem.removesuffix("_scraper") for p in (ROOT / "scripts/scraper/targets").glob("*_targets_scraper.py")}
        section = _section(_page("adding-a-scraper.md"), "Existing target scrapers")
        self.assertEqual({row[0].strip("`") for row in _table_rows(section)}, modules)
        for path in (ROOT / "scripts/scraper/targets").glob("*_targets_scraper.py"):
            name = re.search(r'^PLATFORM_NAME = "(\w+)"', path.read_text(encoding="utf-8"), re.M).group(1)
            self.assertIn(name, _registry())
        for page in ("adding-a-platform.md", "adding-a-scraper.md"):
            self.assertNotIn('PLATFORM_NAME = "myplatform_targets"', _page(page))

    def test_exporter_contract(self):
        from exporter.base_exporter import BaseExporter

        section = _page("adding-a-platform.md").split("## Step 5: Create an exporter")[1].split("### Round-trip")[0]
        for method in set(re.findall(r"def (\w+)\(", section)) | set(re.findall(r"`(\w+)\(\)`", section)):
            self.assertTrue(hasattr(BaseExporter, method), method)
        self.assertTrue(BaseExporter.__abstractmethods__ <= set(re.findall(r"def (\w+)\(", section)))


class ExamplesComeFromTheData(unittest.TestCase):
    """The Dolphin example carried a source_ref, an Adler-32 and a region
    the profile never had, the launcher paragraph said 22 names per region
    for 22 in all, and two pages cited Beetle PSX as a required HLE file
    after the profile made it optional."""

    def _profile(self, name: str) -> dict:
        import yaml

        return yaml.safe_load((ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))

    def _yaml_blocks(self, page: str) -> list[str]:
        return [b.split("\n", 1)[1].rsplit("```", 1)[0] for b in FENCED.findall(_page(page)) if b.startswith("```yaml")]

    def _subset(self, shown: dict, actual: dict) -> None:
        for key, value in shown.items():
            self.assertEqual(value, actual.get(key), key)

    def test_profile_excerpts(self):
        import yaml

        blocks = self._yaml_blocks("profiling.md")
        duck = yaml.safe_load(blocks[0])[0]
        entry = next(f for f in self._profile("duckstation")["files"] if f["name"] == duck["name"])
        self._subset(duck, entry)
        dolphin = yaml.safe_load(next(b for b in blocks if b.startswith("emulator: Dolphin")))
        profile = self._profile("dolphin")
        self._subset({k: v for k, v in dolphin.items() if k != "files"}, profile)
        for shown in dolphin["files"]:
            actual = next(f for f in profile["files"] if f.get("path") == shown["path"])
            self._subset(shown, actual)

    def test_launcher_excerpt(self):
        import yaml

        shown = yaml.safe_load(next(b for b in self._yaml_blocks("adding-a-platform.md")
                                    if b.startswith("launchers:")))["launchers"][0]
        config = yaml.safe_load((ROOT / "platforms/batocera.yml").read_text(encoding="utf-8"))
        record = next(r for r in config["launchers"]
                      if r["emulator"] == shown["emulator"] and r.get("slot") == shown["slot"])
        self._subset({k: v for k, v in shown.items() if k != "source_ref"}, record)
        self.assertTrue(record["source_ref"].endswith(shown["source_ref"].split("...")[-1]))

    def test_required_hle_examples(self):
        for page in ("profiling.md", "reference-terms.md"):
            text = _page(page).replace("\n", " ")
            match = re.search(r"among them (\w+)'s +`([^`]+)`", text)
            entry = next(f for f in self._profile(match.group(1).lower())["files"]
                         if f["name"] == match.group(2))
            self.assertTrue(entry.get("required") and entry.get("hle_fallback"), page)

    def test_reference_terms_source_ref(self):
        text = _section(_page("reference-terms.md"), "Terms of the reference pages").replace("\n", " ")
        cited = re.search(r"lists `scph5501.bin` at\s+`([^`]+)`", text).group(1)
        entry = next(f for f in self._profile("duckstation")["files"] if f["name"] == "scph5501.bin")
        self.assertEqual(cited, entry["source_ref"])




# A command a page gives: `python scripts/X.py ...` or `python -m scripts.x.y ...`,
# up to a comment, a pipe or the end of the line. A placeholder module
# (`myplatform_scraper`) is what a guide asks the reader to write.
_COMMAND = re.compile(
    r"python3? (?:(scripts/[\w/]+\.py)|-m (scripts(?:\.\w+)+)(?![.*\w]))((?:[ \t]+[^\s#|&;`]+)*)"
)
_OPTION = re.compile(r"(?<![\w-])--[a-z0-9][a-z0-9-]*")
_PLACEHOLDER = ("myplatform",)


def _commands(text: str):
    for number, line in enumerate(text.splitlines(), 1):
        for match in _COMMAND.finditer(line):
            target = match.group(1) or match.group(2)
            if any(word in target for word in _PLACEHOLDER):
                continue
            yield number, target, bool(match.group(2)), match.group(3).split()


class CitedScriptsExist(unittest.TestCase):
    """The wiki names scripts by path. A script renamed or removed leaves a
    command that fails, and the page says nothing until a reader runs it."""

    @staticmethod
    def missing(text: str) -> list[str]:
        found = []
        for number, target, module, _args in _commands(text):
            path = ROOT / (target.replace(".", "/") + ".py" if module else target)
            # `python -m` also runs a package by its __main__.py.
            package = ROOT / target.replace(".", "/") / "__main__.py" if module else None
            if not path.is_file() and not (package and package.is_file()):
                found.append(f"{number}: {target}")
        found += [
            f"{number}: {name}"
            for number, line in enumerate(text.splitlines(), 1)
            for name in re.findall(r"(?<![\w./-])scripts/[\w/]+\.py", line)
            if not (ROOT / name).is_file()
        ]
        return found

    def test_every_cited_script_exists(self):
        for page in sorted(WIKI.glob("*.md")):
            with self.subTest(page=page.name):
                self.assertEqual(self.missing(page.read_text(encoding="utf-8")), [])

    def test_a_removed_script_is_named(self):
        self.assertEqual(self.missing("python scripts/no_such_tool.py --all\n"),
                         ["1: scripts/no_such_tool.py", "1: scripts/no_such_tool.py"])


class CitedOptionsExist(unittest.TestCase):
    """Every option a command on a wiki page passes is one the script's own
    parser lists, read from its --help (a subcommand's when the command names
    one). A renamed flag otherwise survives on the page as a command that
    exits 2."""

    _helps: dict[tuple[str, str], str] = {}

    @classmethod
    def help_text(cls, target: str, module: bool, sub: str = "") -> str:
        key = (target, sub)
        if key not in cls._helps:
            import subprocess  # noqa: PLC0415

            argv = [sys.executable, *(["-m", target] if module else [target])]
            proc = subprocess.run(
                [*argv, *([sub] if sub else []), "--help"],
                cwd=ROOT, capture_output=True, text=True, timeout=120,
            )
            cls._helps[key] = proc.stdout if proc.returncode == 0 else ""
        return cls._helps[key]

    @classmethod
    def subcommands(cls, target: str, module: bool) -> list[str]:
        usage = cls.help_text(target, module).split("\n\n", 1)[0]
        choice = re.search(r"\{([\w,-]+)\}", usage)
        return choice.group(1).split(",") if choice else []

    @classmethod
    def unknown(cls, text: str) -> list[str]:
        found = []
        for number, target, module, args in _commands(text):
            subs = cls.subcommands(target, module)
            sub = args[0] if args and args[0] in subs else ""
            known = set(_OPTION.findall(cls.help_text(target, module, sub)))
            if not sub:
                for other in subs:
                    if not other.startswith("_"):
                        known |= set(_OPTION.findall(cls.help_text(target, module, other)))
            if not known:
                found.append(f"{number}: {target} prints no --help")
                continue
            found += [
                f"{number}: {target} {sub} {option}".replace("  ", " ")
                for arg in args
                for option in _OPTION.findall(arg.split("=", 1)[0])
                if arg.startswith(option) and option not in known
            ]
        return found

    def test_every_cited_option_is_in_the_parser(self):
        for page in sorted(WIKI.glob("*.md")):
            with self.subTest(page=page.name):
                self.assertEqual(self.unknown(page.read_text(encoding="utf-8")), [])

    def test_an_unknown_option_is_named(self):
        self.assertEqual(
            self.unknown("python scripts/campaign.py status --budget 6h\n"),
            ["1: scripts/campaign.py status --budget"],
        )


class PipelineStepsMatchTheRun(unittest.TestCase):
    """The step numbers the pages give are the ones pipeline.py prints. The
    testing guide called the integrity check "step 6/8" in a run of 24 steps
    numbered by label, and the tools table can lose or keep a step the run
    no longer has."""

    @staticmethod
    def labels() -> list[str]:
        import pipeline  # noqa: PLC0415

        return [pipeline.step_number(key) for key in pipeline.STEP_LABELS]

    @staticmethod
    def cited(text: str) -> list[str]:
        """Step numbers a sentence attributes to the pipeline."""
        found = []
        for match in re.finditer(
            r"(?i)pipeline steps? ((?:\d[a-z0-9]*(?:/\d+)?(?:, | and | or )?)+)"
            r"|steps? (\d[a-z0-9]*(?:/\d+)?) of the pipeline",
            text,
        ):
            found += re.findall(r"\d[a-z0-9]*(?:/\d+)?", match.group(1) or match.group(2))
        return found

    def test_the_table_lists_every_step_in_order(self):
        section = _section(_page("tools.md"), "Pipeline")
        table = re.findall(r"^\| (\d[a-z0-9]*) \|", section, re.M)
        self.assertEqual(table, self.labels())

    def test_steps_named_in_the_pipeline_section_exist(self):
        section = _section(_page("tools.md"), "Pipeline")
        labels = set(self.labels())
        named = [
            step
            for clause in re.findall(r"(?i)\bsteps? ((?:\(?\d[a-z0-9]*\)?(?:, | and |, and )?)+)", section)
            for step in re.findall(r"\d[a-z0-9]*", clause)
        ]
        named += [step for group in re.findall(r"\(((?:\d[a-z0-9]*, )+\d[a-z0-9]*)\)", section)
                  for step in group.split(", ")]
        self.assertTrue(named)
        self.assertEqual(sorted(set(named) - labels), [])

    def test_every_page_cites_a_step_the_run_has(self):
        labels = set(self.labels())
        for page in sorted(WIKI.glob("*.md")):
            with self.subTest(page=page.name):
                self.assertEqual(
                    [step for step in self.cited(page.read_text(encoding="utf-8"))
                     if step not in labels], [])

    def test_a_fraction_of_steps_is_refused(self):
        self.assertEqual(self.cited("Integrated as pipeline step 6/8 (runs after"), ["6/8"])
        self.assertEqual(self.cited("pipeline steps 3a and 4d"), ["3a", "4d"])


class SiteOutputIsTheStarlightProject(unittest.TestCase):
    """generate_site.py writes into website/ since the move to Starlight,
    while tools.md still gave `docs/` as the default of --docs-dir and as a
    path the pipeline holds, and the testing guide measured pages in `docs/`."""

    PAGES = ("tools.md", "testing-guide.md", "release-process.md",
             "reading-reports.md", "measurements.md")
    BARE_DOCS = re.compile(r"(?<![\w/.-])docs/(?!\w)")

    def test_no_page_names_a_docs_folder(self):
        for name in self.PAGES:
            with self.subTest(page=name):
                self.assertEqual(self.BARE_DOCS.findall(_page(name)), [])

    def test_the_old_wording_is_caught(self):
        self.assertTrue(self.BARE_DOCS.search("| `--docs-dir` (output, `docs/` by default) |"))
        self.assertFalse(self.BARE_DOCS.search("`website/src/content/docs/`"))




# The pages that describe the installer, and the ones that cite its options.
INSTALLER_PAGES = ("installer.md", "first-install.md", "troubleshooting.md", "faq.md")
OPTION_PAGES = INSTALLER_PAGES + ("advanced-usage.md", "technical-faq.md")
INSTALLER_SOURCES = ("install.py", "install.sh", "install.ps1")
OPTION = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]+)")
SCRIPT = re.compile(r"(?<![\w/.-])(?:scripts/)?([a-z_]+\.(?:py|sh))\b")
# Programs whose own options a page quotes: what follows them is theirs.
FOREIGN_COMMANDS = ("curl --", "xcode-select", "wget", "git ", "npm ", "gh ", "uvx ", "sha256sum")
# Variables the standard library reads for the installer, which install.py
# never spells: NO_PROXY reaches urllib through getproxies().
STDLIB_VARIABLES = {"NO_PROXY": "urllib.request"}
# Messages a page quotes from another program, with the program.
FOREIGN_MESSAGES = {"A positional parameter cannot be found": "PowerShell, on `irm ... | iex --x`"}
# Words the operating system hands the installer to print (strerror).
OS_WORDS = ("Permission denied",)


def _prose(text: str) -> str:
    """A page without its fenced blocks and comments."""
    return re.sub(r"<!--.*?-->", "", FENCED.sub("", text), flags=re.S)


def _parser_options() -> set[str]:
    import install

    return {name for action in install.build_parser()._actions
            for name in action.option_strings if name.startswith("--")}


def _script_options(name: str) -> set[str]:
    """The options a build script spells, in its file or a module beside it
    that it imports."""
    path = next((p for p in (ROOT / "scripts" / name, ROOT / name) if p.is_file()), None)
    if path is None:
        return set()
    text = path.read_text(encoding="utf-8")
    for module in re.findall(r"(?m)^(?:from|import) (\w+)", text):
        beside = path.parent / f"{module}.py"
        if beside.is_file() and beside != path:
            text += beside.read_text(encoding="utf-8")
    if path.suffix == ".sh":
        return set(OPTION.findall(text))
    return set(re.findall(r"""["'](--[a-z][a-z0-9-]+)["'=]""", text)) | {"--help"}


def _owner(command: str) -> str | None:
    """The program a command line runs: install.py for the one-liners."""
    if re.search(r"install\.py|\| *sh\b|scriptblock|install\.(?:sh|ps1)\b", command):
        return "install.py"
    named = SCRIPT.search(command)
    return named.group(1) if named else None


def stale_options(text: str, default: str | None) -> list[str]:
    """Options a page cites that the program it names does not have.

    A command line answers for the program it runs. An option in prose
    answers for the scripts its paragraph names, for default (the
    installer, on its own pages) and for the scripts the page runs."""
    known = {"install.py": _parser_options()}

    def has(program: str, option: str) -> bool:
        if program not in known:
            known[program] = _script_options(program)
        return option in known[program]

    commands = []
    for block in FENCED.findall(text):
        commands += [line for line in block.splitlines()[1:-1] if not line.lstrip().startswith("#")]
    page_scripts = {_owner(command) for command in commands} - {None}
    stale = []
    for line in commands:
        for part in re.split(r"\s+&&\s+|;\s+|\|\s+(?!sh\b)", line):
            if not part or part.lstrip().startswith(FOREIGN_COMMANDS):
                continue
            program = _owner(part) or default
            for option in OPTION.findall(part):
                if program is None or not has(program, option):
                    stale.append(f"{option} ({program}): {part.strip()}")
    for paragraph in re.split(r"\n\s*\n", _prose(text)):
        named = {m.group(1) for m in SCRIPT.finditer(paragraph)} - {"install.sh", "install.ps1"}
        owners = named | page_scripts | ({default} if default else set())
        for span in re.findall(r"`([^`]+)`", paragraph.replace("\n", " ")):
            if span.startswith(FOREIGN_COMMANDS):
                continue
            own = _owner(span)
            candidates = {own} if own else owners
            for option in OPTION.findall(span):
                if not any(has(program, option) for program in candidates):
                    stale.append(f"{option} ({', '.join(sorted(candidates))}): {span}")
    return stale


def stale_variables(text: str) -> list[str]:
    """Environment variables a page names that neither the installer nor
    its bootstraps and launchers read."""
    sources = "".join((ROOT / name).read_text(encoding="utf-8") for name in INSTALLER_SOURCES)
    sources += "".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in sorted((ROOT / "ports").rglob("*")) if path.is_file())
    found: set[str] = set()
    for span in re.findall(r"`([^`]+)`", _prose(text)):
        found |= set(re.findall(r"(?<![\w$%.-])([A-Z][A-Z0-9]*_[A-Z0-9_]+|NO_COLOR|TERM|ACCESSIBLE)"
                                r"(?![\w.(])", span))
    return sorted(name for name in found if name not in sources and name not in STDLIB_VARIABLES)


def _literals() -> str:
    """Every string the installer and its bootstraps print, a placeholder
    (\\x01) where an f-string or the shell inserts a value, joined by \\x00."""
    texts = []
    for node in ast.walk(ast.parse((ROOT / "install.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.JoinedStr):
            texts.append("".join(value.value if isinstance(value, ast.Constant) else "\x01"
                                 for value in node.values))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            texts.append(node.value)
    for name in ("install.sh", "install.ps1"):
        for match in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'',
                                 (ROOT / name).read_text(encoding="utf-8")):
            quoted = match.group(1) if match.group(1) is not None else match.group(2)
            texts.append(re.sub(r"\$\{[^}]*\}|\$\([^)]*\)|\$\w+", "\x01", quoted))
    return "\x00".join(re.sub(r"\s+", " ", text) for text in texts)


# A word a message fills in: a number, a path, a name in capitals, an option.
VALUE = re.compile(r"^(?:\S*[\d/\\~<>{}=]\S*|--?[\w-]+\S*|\S*[A-Z]{2,}\S*|\.\.\.|"
                   r"\S*\.\w{2,4}[,.:;)]?|[A-Z][a-z]+[A-Z]\S*|\(\S*)$")
# A code span that is a command, a path or a shape, not a message.
NOT_A_MESSAGE = re.compile(r"^(?:\{|-|\.|/|~|<|\$|%|python|py |curl|irm|uvx |pipx |pip |sh |pkg |sudo|ls |"
                           r"xcode|winget|termux|install\.py|scripts/|generate_|&\()")


def unprinted_messages(text: str, corpus: str) -> list[str]:
    """Code spans that read as installer messages and that no string of
    the installer prints.

    The values a message fills in (counts, paths, names) are free. Between
    them, the words must be printed together by one string, each pair of
    them at least, or beside a value that string inserts."""

    def pair_printed(first: str, second: str) -> bool:
        pair = f"{first} {second}".rstrip(".,:;")
        forms = {pair, re.sub(r"s\b", "", pair), re.sub(r"s( |$)", r"\1", pair),
                 f"{first} \x01", f"\x01 {second}".rstrip(".,:;")}
        return any(form in corpus for form in forms)

    stale = []
    for span in sorted({re.sub(r"\s+", " ", s) for s in re.findall(r"`([^`]+)`", _prose(text))}):
        if NOT_A_MESSAGE.match(span) or len(span.split()) < 3 or span in FOREIGN_MESSAGES:
            continue
        words = span
        for given in OS_WORDS:
            words = words.replace(given, "1")
        run: list[str] = []
        for word in [*words.split(" "), "1"]:
            if word and not VALUE.match(word):
                run.append(word)
                continue
            joined = " ".join(run)
            if len(run) > 1 and joined.rstrip(".,:;") not in corpus and not all(
                    pair_printed(a, b) for a, b in zip(run, run[1:])):
                stale.append(f"{span!r}: {joined!r}")
            run = []
    return stale


def unserved_one_liners(page: str, text: str) -> list[str]:
    """One-line commands whose address the site does not serve. The raw
    address of the repository stays as the fallback of the One line
    section, and must name a bootstrap the repository holds."""
    import sitebootstrap
    from siteguides import INSTALL_BASE

    served = {f"{INSTALL_BASE}/{name}" for name in sitebootstrap.SOURCES}
    fallback = _section(text, "One line") if page == "installer.md" else ""
    stale = []
    for line in text.splitlines():
        if not re.search(r"\|\s*(?:sh|iex)\b|\\$|scriptblock\]::Create", line):
            continue
        for url in re.findall(r"https?://[^\s)`'\"]+", line):
            if url in served:
                continue
            raw = re.fullmatch(rf"{re.escape(sitebootstrap.REPO_RAW)}/main/(install\.(?:sh|ps1))", url)
            if raw and line in fallback and (ROOT / raw.group(1)).is_file():
                continue
            stale.append(f"{url}: {line.strip()}")
    return stale


class InstallerPagesFollowTheCode(unittest.TestCase):
    """The installer page described an installer that had moved on, and
    nothing failed. Options, variables, messages and addresses are words
    the code owns, so each page is read against the code here."""

    def test_every_option_is_the_programs(self):
        for name in OPTION_PAGES:
            default = "install.py" if name in INSTALLER_PAGES else None
            with self.subTest(page=name):
                self.assertEqual(stale_options(_page(name), default), [])

    def test_an_option_the_program_lacks_fails(self):
        old = "Add `--resume` to carry on.\n\n```bash\npython install.py --keep-going\n```\n"
        self.assertEqual(len(stale_options(old, "install.py")), 2)
        self.assertEqual(stale_options("`curl --tlsv1.2` and `--check`.\n", "install.py"), [])
        self.assertEqual(stale_options("```bash\npython scripts/verify.py --all\n```\n", None), [])
        self.assertEqual(len(stale_options("```bash\npython scripts/verify.py --sideways\n```\n",
                                           None)), 1)

    def test_every_variable_is_read(self):
        import urllib.request

        for variable in STDLIB_VARIABLES:
            self.assertIn(variable.lower(), inspect.getsource(urllib.request.proxy_bypass_environment))
        for name in INSTALLER_PAGES:
            with self.subTest(page=name):
                self.assertEqual(stale_variables(_page(name)), [])

    def test_a_variable_nothing_reads_fails(self):
        self.assertEqual(stale_variables("Set `RETROBIOS_MIRROR` to another host.\n"),
                         ["RETROBIOS_MIRROR"])

    def test_every_quoted_message_is_printed(self):
        corpus = _literals()
        for name in INSTALLER_PAGES:
            with self.subTest(page=name):
                self.assertEqual(unprinted_messages(_page(name), corpus), [])

    def test_a_message_the_installer_does_not_print_fails(self):
        corpus = _literals()
        self.assertEqual(unprinted_messages("It ends `Every file on the list is in place.` here.\n", corpus), [])
        self.assertEqual(len(unprinted_messages("It says `All BIOS files are present.`\n", corpus)), 1)
        self.assertEqual(unprinted_messages(
            "`E:\\ holds 38 of these files: a run without --check copies them.`\n", corpus), [])

    def test_every_one_liner_is_served(self):
        for name in OPTION_PAGES:
            with self.subTest(page=name):
                self.assertEqual(unserved_one_liners(name, _page(name)), [])

    def test_a_one_liner_the_site_does_not_serve_fails(self):
        """Before the site served `i`, every page gave the raw address."""
        old = ("## One line\n\nIntro.\n\n## Passing options\n\n```bash\ncurl -fsSL "
               "https://raw.githubusercontent.com/Abdess/retrobios/main/install.sh \\\n"
               "  | sh -s -- --platform retroarch\n```\n\n"
               "```bash\ncurl -fsSL https://abdess.github.io/retrobios/install | sh\n```\n")
        self.assertEqual(len(unserved_one_liners("installer.md", old)), 2)


class InstallerVariablesAreDocumented(unittest.TestCase):
    """RETROBIOS_CACHE moved a cache that --for-games writes, even under
    --dry-run, and no page named it or the folder it defaults to."""

    # Set by the full-screen interface for the runs it starts, never by a user.
    INTERNAL = {"RETROBIOS_TUI_LIST"}

    def test_every_variable_install_py_reads_is_in_the_table(self):
        source = (ROOT / "install.py").read_text(encoding="utf-8")
        page = (WIKI / "installer.md").read_text(encoding="utf-8")
        table = page[page.index("## Environment overrides"):]
        table = table[:table.index("\n## ", 1)]
        for name in sorted(set(re.findall(r'"(RETROBIOS_[A-Z_]+)"', source)) - self.INTERNAL):
            with self.subTest(variable=name):
                self.assertIn(f"`{name}`", table)

    def test_the_faq_names_the_cache(self):
        faq = (WIKI / "faq.md").read_text(encoding="utf-8")
        section = faq[faq.index("## Is the command safe?"):]
        self.assertIn("cache", section[:section.index("\n## ", 1)])


class ReadmeKeepsItsPointers(unittest.TestCase):
    def test_the_bare_minimum_is_built_below(self):
        """The README sent a reader to 'build your own pack below' for a bare
        minimum, and the block below never named --required-only."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        block = readme[readme.index("<summary><strong>For developers"):readme.index("</details>")]
        self.assertIn("--required-only", block)

    def test_unsourceable_files_are_not_said_to_exist_nowhere(self):
        """The README said 138 files 'cannot be sourced at all (... dumps
        nobody has made)', while most of their reasons read 'retail data the
        collection does not hold'."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("sourced at all", readme)
        self.assertNotIn("nobody has made", readme)
        # The README names no count: the gap analysis it links does, by reason.
        self.assertIn("gaps/", readme)


class ArchitectureStatesTheArbitration(unittest.TestCase):
    """architecture.md said the profile takes precedence for pack generation,
    while slots.arbitrate() keeps the platform's file where its frontend
    checks the content: RetroBat's ATARIOSB.ROM."""

    def test_the_page_says_what_arbitrate_decides(self):
        import slots  # noqa: PLC0415

        page = (WIKI / "architecture.md").read_text(encoding="utf-8")
        self.assertNotIn("the profile takes precedence for pack generation", page)
        section = page[page.index("### When both layers claim one destination"):]
        section = section[:section.index("\n## ")]
        self.assertIn("`slots.arbitrate()`", section)
        # The pack, the manifest and verify decide through slot_choices, and
        # a test in test_slots forbids them to call arbitrate: the page names
        # the function they read, not only the one the report prints.
        self.assertIn("`slots.slot_choices()`", section)
        self.assertIn("`slots.pack_overrides()`", section)
        self.assertNotIn("both decide through `slots.arbitrate()`", section)
        source = inspect.getsource(slots.arbitrate)
        # The three outcomes the section describes.
        for outcome in ("ADDRESSEE", "SERVES_BOTH", "FRONTEND_CHECKS_CONTENT"):
            self.assertIn(outcome, source)
        for said in ("--emulator", "`existence`", "the platform's file stays"):
            self.assertIn(said, section)


class VersionBasisReferenceIsTheSchema(unittest.TestCase):
    """profiling.md listed five kinds of version_basis: `unverified`, its
    `why` and the `url`, `commit` and `match` keys 18 profiles use were in
    the schema alone."""

    def test_the_row_names_every_kind_reason_and_key(self):
        schema = json.loads((ROOT / "schemas" / "emulator.schema.json").read_text(encoding="utf-8"))
        basis = schema["$defs"]["version_basis"]["properties"]
        page = (WIKI / "profiling.md").read_text(encoding="utf-8")
        row = next(line for line in page.splitlines() if line.startswith("| `version_basis` |"))
        for word in [*basis["kind"]["enum"], *basis["why"]["enum"], *basis]:
            with self.subTest(word=word):
                self.assertIn(f"`{word}`", row)
        tools = (WIKI / "tools.md").read_text(encoding="utf-8")
        self.assertIn("`unverified`", tools)


class ProfilingStatesTheHashRuleOnce(unittest.TestCase):
    """profiling.md let an .info MD5 in ('source confirmation makes it more
    reliable') and a file the code never loads stay ('can be left out'),
    beside the strict rule of the same paragraph."""

    def test_no_permissive_form_remains(self):
        page = (WIKI / "profiling.md").read_text(encoding="utf-8")
        self.assertNotIn("source confirmation makes it more reliable", page)
        self.assertNotIn("it can be left out of the profile", page)
        self.assertIn("An MD5 the .info or\n  the docs alone give is not written", page)


class ReportExcerptIsTheRun(unittest.TestCase):
    """reading-reports.md quoted 'From python scripts/verify.py --platform
    retrodeck' a run that said 0 required missing after the command had started
    naming one, and never showed the line that names it."""

    def test_every_quoted_line_is_printed(self):
        import subprocess  # noqa: PLC0415

        from restore_large_files import gitignored_paths  # noqa: PLC0415

        # The excerpt is a run over the whole collection. A checkout without
        # the release assets (the PR workflow restores none) prints other
        # counts, which says nothing about the page.
        absent = [p for p in gitignored_paths(str(ROOT / ".gitignore"))
                  if not any(ROOT.glob(p))]
        if absent:
            self.skipTest(f"{len(absent)} release assets absent from this checkout, e.g. {absent[0]}")
        page = (WIKI / "reading-reports.md").read_text(encoding="utf-8")
        intro = "From `python scripts/verify.py --platform retrodeck`:"
        start = page.index("```\n", page.index(intro)) + 4
        quoted = page[start:page.index("```", start)].splitlines()
        run = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify.py"), "--platform", "retrodeck"],
            capture_output=True, text=True, cwd=ROOT, check=False,
        )
        printed = run.stdout.splitlines()
        if not any(line.startswith("RetroDECK:") for line in printed):
            self.skipTest(f"verify did not run: {run.stderr[-200:]}")
        for line in quoted:
            with self.subTest(line=line):
                self.assertIn(line, printed)


class ClaimRuleNamesTheSizeProof(unittest.TestCase):
    """architecture.md said a file found by its name claims nothing, while
    slots.py has counted a name-found copy at the declared size against a
    platform file of another size since 2b535525e."""

    def test_the_page_states_what_slots_counts(self):
        import slots

        self.assertIn(slots.SIZE_EXACT, slots.PROVEN_STATUSES)
        page = " ".join((ROOT / "wiki" / "architecture.md").read_text(encoding="utf-8").split())
        section = page.split("### When both layers claim one destination", 1)[1].split("###", 1)[0]
        self.assertIn(f"(`{slots.SIZE_EXACT}`)", section)
        self.assertIn("Two files of equal size are revisions", section)


class CrossReferenceSettlesBySlotAndSize(unittest.TestCase):
    """reading-reports.md said the cross-reference checks whether a profile's
    files "appear in the platform config", a by-name rule, while verify
    settles a file only at its slot or at a size the core accepts."""

    def test_the_page_states_the_rule_verify_reads(self):
        from validation import declaration_settles

        rom1 = {"name": "ROM1.BIN", "size": 32768, "validation": ["size"]}
        self.assertFalse(declaration_settles(rom1, "ROM1.BIN", {"ROM1.BIN": [(4096, "rom1.bin")]},
                                             dest="dosbox/ROM1.BIN"))
        self.assertTrue(declaration_settles(rom1, "ROM1.BIN", {"ROM1.BIN": [(32768, "rom1.bin")]},
                                            dest="dosbox/ROM1.BIN"))
        page = " ".join((ROOT / "wiki" / "reading-reports.md").read_text(encoding="utf-8").split())
        section = page.split("### Cross-reference section", 1)[1].split("###", 1)[0]
        self.assertIn("declaration_settles()", section)
        self.assertIn("A name alone is not enough", section)
        self.assertNotIn("appear in the platform config", section)


class CommittedLargeFilesAreTheOnesNamed(unittest.TestCase):
    """release-process.md named tbblue.mmc among the committed files over
    50 MB two weeks after it left bios/, and not uqm-remix-disc1.uqm."""

    def test_the_list_is_the_tree(self):
        import subprocess

        listed = subprocess.run(["git", "ls-files", "-z", "bios"], cwd=ROOT, capture_output=True,
                                check=True).stdout.decode("utf-8").split("\0")
        large = sorted(Path(path).name for path in listed
                       if path and (ROOT / path).is_file()
                       and (ROOT / path).stat().st_size > 50_000_000)
        page = " ".join((ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8").split())
        said = re.search(r"Size does not decide it: (\w+) committed files are over 50 MB \(([^)]*)\)",
                         page)
        self.assertIsNotNone(said)
        self.assertEqual(sorted(re.findall(r"`([^`]+)`", said.group(2))), large)
        self.assertEqual(said.group(1), {3: "three", 4: "four", 5: "five"}.get(len(large)))


class SkipFlagsNameTheSteps(unittest.TestCase):
    """--skip-packs said "add --skip-docs to stop after verify" while 4d and
    4e still ran, and the flag table left 8b out of --skip-docs."""

    STEP = r"\b\d[a-z]?\d?\b"

    def test_the_flag_row_the_help_and_the_usage_agree_with_the_step_table(self):
        page = (ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        table = page.split("Pipeline steps:", 1)[1].split("Pipeline flags:", 1)[0]
        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        helps = {}
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_argument"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                helps.update({node.args[0].value: ast.literal_eval(kw.value)
                              for kw in node.keywords if kw.arg == "help"})
        for flag in ("--skip-packs", "--skip-docs"):
            steps = set()
            for row in table.splitlines():
                cells = [c.strip() for c in row.split("|")]
                if len(cells) > 3 and cells[3].startswith(f"`{flag}`"):
                    steps.add(cells[1])
            self.assertTrue(steps)
            row = re.search(rf"^\| `{flag}` \| skip steps ([^.|]*)", page, re.M).group(1)
            usage = re.search(rf"pipeline\.py {flag} +# skip steps (.*)$", source, re.M).group(1)
            said = helps[flag].split(":", 1)[0]
            for text in (row, usage, said):
                with self.subTest(flag=flag, text=text):
                    self.assertEqual(set(re.findall(self.STEP, text)), steps)


class TheInstallerSamplesTravelWithTheManifests(unittest.TestCase):
    """A manifest refresh (c624a820f) went out without the run samples of
    wiki/installer.md, which count what the manifests hold, and CI turned
    red. The rule lived in no page, and the nightly's commit rules had no
    place for the samples the gate's pipeline rewrites."""

    def test_the_pages_and_the_nightly_carry_them(self):
        import autorun  # noqa: PLC0415

        guide = (WIKI / "testing-guide.md").read_text(encoding="utf-8")
        for name in ("wiki/installer.md", "derivable.json", "generate_installer_doc.py"):
            self.assertIn(name, guide)
        tools = (WIKI / "tools.md").read_text(encoding="utf-8")
        manifests = tools.index("--all --manifest --output-dir install/")
        self.assertIn("generate_installer_doc.py", tools[manifests:manifests + 300])
        nightly = autorun.load_jobs()["nightly"]
        patterns = [p for rule in nightly.commits for p in rule.paths]
        for path in ("wiki/installer.md", "derivable.json", "install/retroarch.json"):
            with self.subTest(path=path):
                self.assertTrue(any(autorun.path_matches(p, path) for p in patterns))


class TheRemovalProofsAreTheExportersOwn(unittest.TestCase):
    """tools.md listed the proofs that keep an entry out of
    removal_candidates without the platform's launcher records, which
    candidates.py checks right after a path."""

    WORDS = {"path": "`path:`", "launcher": "`launchers:`", "name": "by name or alias",
             "hash": "by any hash", "directory": "`type: directory`",
             "data_directory": "a data directory"}

    def test_the_page_names_each_proof_in_order(self):
        from exporter.candidates import _PROOF_ORDER  # noqa: PLC0415

        page = (WIKI / "tools.md").read_text(encoding="utf-8")
        start = page.index("No entry the platform declares is removed.")
        section = page[start:page.index("removal_candidates", start)]
        self.assertEqual(set(self.WORDS), set(_PROOF_ORDER))
        positions = [section.index(self.WORDS[kind]) for kind in _PROOF_ORDER]
        self.assertEqual(positions, sorted(positions))


class APlatformListIsDescribedNotJudged(unittest.TestCase):
    """adding-a-platform opened on files a platform's own list "leaves out",
    read first by the maintainer of that platform: "does not name" says the
    same without imputing an omission."""

    def test_no_page_says_a_list_leaves_files_out(self):
        pattern = re.compile(r"\blists? (?:leaves|left|leave) out\b")
        for page in sorted(WIKI.glob("*.md")):
            with self.subTest(page=page.name):
                self.assertIsNone(pattern.search(page.read_text(encoding="utf-8")))


class NoTextClaimsAScheduledScrape(unittest.TestCase):
    """The README and the setup pages said a platform is scraped on a
    schedule, and adding-a-platform said the registry feeds a CI matrix and
    the scrapers. No workflow calls list_platforms.py and no tool reads
    `schedule:`."""

    def test_no_text_ties_the_registry_to_automation(self):
        import generate_pack  # noqa: PLC0415
        import generate_readme  # noqa: PLC0415
        import generate_site  # noqa: PLC0415
        import list_platforms  # noqa: PLC0415

        texts = {
            "adding-a-platform.md": (WIKI / "adding-a-platform.md").read_text(encoding="utf-8"),
            "generate_readme": inspect.getsource(generate_readme),
            "generate_site": inspect.getsource(generate_site),
            "generate_pack": inspect.getsource(generate_pack),
            "list_platforms": inspect.getsource(list_platforms),
            "_guides.yml": (ROOT / "platforms" / "_guides.yml").read_text(encoding="utf-8"),
        }
        for name, text in texts.items():
            with self.subTest(name):
                for claim in ("scraped on a schedule", "read again on a schedule",
                              "CI matrix", "without the automation"):
                    self.assertNotIn(claim, text)
        for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
            self.assertNotIn("list_platforms", workflow.read_text(encoding="utf-8"))


class TheCatalogRowsStateFacts(unittest.TestCase):
    """tools.md said "redump.org serves stale DATs" and "Dat-o-Matic blocks
    automation", verdicts on two preservation projects, and gave Redump's
    /static/bios links, which the scraper no longer reads."""

    def test_dates_and_routes_not_verdicts(self):
        text = (WIKI / "tools.md").read_text(encoding="utf-8")
        rows = [line for line in text.splitlines()
                if line.startswith(("| Redump |", "| No-Intro |"))]
        self.assertEqual(len(rows), 2)
        for word in ("stale", "blocks"):
            self.assertNotIn(word, " ".join(rows))
        scraper = (ROOT / "scripts" / "scraper" / "redump_dat_scraper.py").read_text(encoding="utf-8")
        self.assertIn("/bios/<CODE>", scraper)
        self.assertIn("`/bios/<CODE>`", rows[0])


class RegionFreeRuleNamesWhereItDoesNotHold(unittest.TestCase):
    """advanced-usage.md said psxonpsp660.bin is declared [world] and always
    survives --region. PCSX ReARMed declares it [japan], and on the platforms
    where it is the only PlayStation core the filter drops it."""

    def test_every_platform_that_drops_a_named_file_is_named(self):
        from common import (list_registered_platforms, load_emulator_profiles,
                            load_platform_config)
        from region import WORLD, platform_region_index

        section = _section(_page("advanced-usage.md"), "Region filtering")
        bullet = next(p for p in section.split("\n- ") if "Region-free" in p)
        files = re.findall(r"`([^`]+\.bin)`", bullet)
        self.assertTrue(files)
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        for platform in list_registered_platforms(str(ROOT / "platforms")):
            config = load_platform_config(platform, str(ROOT / "platforms"))
            index = platform_region_index(config, profiles)
            for name in files:
                entry = index.get(name)
                drops = bool(entry and entry["regions"] and WORLD not in entry["regions"]
                             and not entry["has_untagged"])
                if drops:
                    with self.subTest(platform=platform, file=name):
                        self.assertRegex(bullet, rf"(?i)\b{re.escape(platform)}\b")


class BuildYourOwnPackSaysWhatTheCloneCosts(unittest.TestCase):
    """The README sent a user after a minimal pack to "Clone the repo", with no
    command and no size, and the clone runs to several gigabytes."""

    def test_readme_gives_the_clone_command_and_its_size(self):
        import generate_readme

        db = json.loads((ROOT / "database.json").read_text(encoding="utf-8"))
        line = generate_readme.clone_line(db)
        self.assertIn("git clone --depth 1", line)
        self.assertRegex(line, r"over \d+(\.\d)? GB")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        section = readme[readme.index("<summary><strong>For developers"):readme.index("</details>")]
        self.assertIn("git clone --depth 1", section)

    def test_advanced_usage_names_the_shallow_clone(self):
        self.assertIn("--depth 1", _page("advanced-usage.md").split("## Custom packs")[0])


class LandingAChangeNamesTheCommitRules(unittest.TestCase):
    """The page left out the review-tag rule scripts/commit_rules.py
    enforces, and never said where the rules live or how a clone runs them:
    the hook is not versioned."""

    def _landing(self) -> str:
        return _section(_page("testing-guide.md"), "Landing a change")

    def test_every_refusal_is_on_the_page(self):
        import commit_rules

        section = self._landing()
        words = re.search(r"\\b\((.*?)\)", commit_rules.REFUSED_WORDS.pattern).group(1)
        from tests.test_prose_style import NoMarketingVocabulary

        for word in words.replace("|", " ").split():
            if NoMarketingVocabulary.WORDS.search(word):
                # Named by "the marketing vocabulary above": spelled out,
                # the page would fail that test.
                continue
            with self.subTest(word=word):
                self.assertIn(word, section.lower())
        self.assertIn("which review asked for it", section)
        self.assertIn("scripts/commit_rules.py", section)

    def test_the_hook_command_on_the_page_refuses_a_review_tag(self):
        import subprocess
        import tempfile

        block = re.search(r"```bash\n(.*?)```", self._landing(), re.S).group(1)
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as scratch:
            clone = Path(scratch)
            (clone / ".git" / "hooks").mkdir(parents=True)
            (clone / "scripts").mkdir()
            (clone / "scripts" / "commit_rules.py").write_bytes(
                (ROOT / "scripts" / "commit_rules.py").read_bytes())
            subprocess.run(["sh", "-c", block], cwd=clone, check=True)
            message = clone / "MSG"
            message.write_text("fix: address review 3 notes\n", encoding="utf-8")
            refused = subprocess.run([str(clone / ".git" / "hooks" / "commit-msg"), "MSG"],
                                     cwd=clone, capture_output=True, text=True)
            message.write_text("fix: say what the change does\n", encoding="utf-8")
            accepted = subprocess.run([str(clone / ".git" / "hooks" / "commit-msg"), "MSG"],
                                      cwd=clone, capture_output=True, text=True)
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertIn("which review asked for it", refused.stderr)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)


if __name__ == "__main__":
    unittest.main()
