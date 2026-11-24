"""What the wiki states about the tools holds against them.

Cited scripts and options exist, pipeline steps and skip flags match the
run, samples and excerpts come from a real run.
"""

from __future__ import annotations

import tests
from tests.mdsections import FENCED
from tests.sources import declared_options

import ast
import re
import sys
import unittest
from pathlib import Path

from tests.docpagessupport import PUBLISHED, ROOT, WIKI, _page, _registry, _schema, _section


class TestSkeletonReadsTheResultShape(unittest.TestCase):
    """The skeleton indexed verify_platform's result as a list, and a test
    copied from it stopped on KeyError: 0 before any assertion."""

    def test_every_key_it_reads_is_one_verify_platform_returns(self):
        from packs.coverage import verify_platform

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
        annotations: set[int] = set()
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


def _schema_keys(schema: object, keys: set[str]) -> set[str]:
    if isinstance(schema, dict):
        keys.update(schema.get("properties", {}))
        for value in schema.values():
            _schema_keys(value, keys)
    elif isinstance(schema, list):
        for value in schema:
            _schema_keys(value, keys)
    return keys


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
            wrong.extend(
                f"{name} {option}"
                for option in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", command)
                if f'"{option}"' not in source and option not in declared_options(source)
            )
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
            import subprocess

            argv = [sys.executable, *(["-m", target] if module else [target])]
            proc = subprocess.run(
                [*argv, *([sub] if sub else []), "--help"],
                cwd=ROOT, capture_output=True, text=True, timeout=120,
                check=False,
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
        from orchestrate.labels import STEP_LABELS, step_number

        return [step_number(key) for key in STEP_LABELS]

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


class ReportExcerptIsTheRun(unittest.TestCase):
    """reading-reports.md quoted 'From python scripts/verify.py --platform
    retrodeck' a run that said 0 required missing after the command had started
    naming one, and never showed the line that names it."""

    def test_every_quoted_line_is_printed(self):
        import subprocess

        from release.restore import gitignored_paths

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
                for kw in node.keywords:
                    if kw.arg == "help":
                        helps[node.args[0].value] = ast.literal_eval(kw.value)
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


class TheRemovalProofsAreTheExportersOwn(unittest.TestCase):
    """tools.md listed the proofs that keep an entry out of
    removal_candidates without the platform's launcher records, which
    candidates.py checks right after a path."""

    WORDS = {"path": "`path:`", "launcher": "`launchers:`", "name": "by name or alias",
             "hash": "by any hash", "directory": "`type: directory`",
             "data_directory": "a data directory"}

    def test_the_page_names_each_proof_in_order(self):
        from resolve.categories import _PROOF_ORDER

        page = (WIKI / "tools.md").read_text(encoding="utf-8")
        start = page.index("No entry the platform declares is removed.")
        section = page[start:page.index("removal_candidates", start)]
        self.assertEqual(set(self.WORDS), set(_PROOF_ORDER))
        positions = [section.index(self.WORDS[kind]) for kind in _PROOF_ORDER]
        self.assertEqual(positions, sorted(positions))


class LandingAChangeNamesTheCommitRules(unittest.TestCase):
    """The page left out the review-tag rule scripts/commit_rules.py
    enforces, and never said where the rules live or how a clone runs them:
    the hook is not versioned."""

    def _landing(self) -> str:
        return _section(_page("testing-guide.md"), "Landing a change")

    def test_every_refusal_is_on_the_page(self):
        from devtools import commitrules

        section = self._landing()
        words = re.search(r"\\b\((.*?)\)", commitrules.REFUSED_WORDS.pattern).group(1)
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
        with tempfile.TemporaryDirectory() as scratch:
            clone = Path(scratch)
            (clone / ".git" / "hooks").mkdir(parents=True)
            (clone / "scripts").mkdir()
            for name in ("commit_rules.py", "devtools/__init__.py", "devtools/commitrules.py"):
                (clone / "scripts" / name).parent.mkdir(exist_ok=True)
                (clone / "scripts" / name).write_bytes((ROOT / "scripts" / name).read_bytes())
            subprocess.run(["sh", "-c", block], cwd=clone, check=True)
            message = clone / "MSG"
            message.write_text("fix: address review 3 notes\n", encoding="utf-8")
            refused = subprocess.run([str(clone / ".git" / "hooks" / "commit-msg"), "MSG"],
                                     cwd=clone, capture_output=True, text=True, check=False)
            message.write_text("fix: say what the change does\n", encoding="utf-8")
            accepted = subprocess.run([str(clone / ".git" / "hooks" / "commit-msg"), "MSG"],
                                      cwd=clone, capture_output=True, text=True, check=False)
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertIn("which review asked for it", refused.stderr)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)


if __name__ == "__main__":
    unittest.main()
