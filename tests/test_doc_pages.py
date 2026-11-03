"""What the wiki and the generated README state holds against the code.

Each class reads a page and the code it describes. A page that quotes a
function's return shape, a resolution order or a field list drifts when the
code moves, and nothing else notices.
"""

from __future__ import annotations

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
        # Data files are a third kind, counted beside the two (tui_audit_12 P2-3).
        split = re.search(r"(\d+) BIOS files \(([\d.]+) ([KMG]B)\)(?:,| and) (\d+) game data "
                          r"files \(([\d.]+) ([KMG]B)\)", text)
        self.assertIsNotNone(split, "a categorized list says its BIOS files and game data")
        bios, bios_size, bios_unit, games, game_size, game_unit = split.groups()
        # The data files in the one total, the third kind (code_audit_21 P3-8).
        data = re.search(r"and (\d+) data files \(([\d.]+) ([KMG]B)\)", text)
        data_count, data_size, data_unit = data.groups() if data else ("0", "0", "KB")
        self.assertEqual(int(bios) + int(games) + int(data_count), int(count))
        units = {"KB": 1, "MB": 1024, "GB": 1024 ** 2}
        total, unit = size.split()
        added = (float(bios_size) * units[bios_unit] + float(game_size) * units[game_unit]
                 + float(data_size) * units[data_unit])
        self.assertLessEqual(abs(added - float(total) * units[unit]), 0.15 * units[unit])


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
        self.assertTrue(after.startswith("| Platform | Files |"))


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
            if row[1].startswith(("yes", "for `type"))
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
        self.assertIn("if len(md5_candidate) < 32:", resolver)
        self.assertIn("_md5_name_ok(path)", resolver)
        section = _section(_page("verification-modes.md"), "MD5 shorter than 32 characters (Batocera)")
        self.assertIn("_resolve_truncated_md5", section)


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
        self.assertIn('install_command("powershell", "--check")', source)
        self.assertIn("wiki/installer/#passing-options", source)
        self.assertIn("## Passing options", _page("installer.md"))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quick = _section(readme, "Quick install")
        from siteguides import INSTALL_PS1

        self.assertIn(f"&([scriptblock]::Create((irm {INSTALL_PS1}))) --check", quick)
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
        self.assertIn("format_size(total_size)", readme_source)
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
        count, size = re.search(r"\n  (\d+) files \(([\d.]+ [KMG]B)\)", step3).groups()
        self.assertIn(f"0 in place, {count} missing", step3)
        self.assertIn(f"Downloading {count} files ({size})", _generated(self.run, "run-download"))
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
NOT_A_MESSAGE = re.compile(r"^(?:\{|-|\.|/|~|<|\$|%|python|py |curl|irm|sh |pkg |sudo|ls |"
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
        self.assertEqual(unprinted_messages("It ends `Everything is in place.` here.\n", corpus), [])
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


if __name__ == "__main__":
    unittest.main()
