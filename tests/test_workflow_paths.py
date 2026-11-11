"""The site redeploys whenever a script it runs changes.

Deploy Site listed five scripts by hand while the build imports forty:
a change to siterender.py, which writes every page, published nothing
until some unrelated file moved.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import fnmatch
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _module_file(name: str) -> Path | None:
    name = name.removeprefix("scripts.")
    for candidate in (
        SCRIPTS / (name.replace(".", "/") + ".py"),
        SCRIPTS / name.replace(".", "/") / "__init__.py",
    ):
        if candidate.exists():
            return candidate
    return None


def _imports(path: Path) -> set[Path]:
    found: set[Path] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
        elif isinstance(node, ast.ImportFrom):
            base = path.parent / (node.module or "").replace(".", "/")
            candidates = [base / f"{a.name}.py" for a in node.names]
            candidates += [base.with_suffix(".py"), base / "__init__.py"]
            found.update(c for c in candidates if c.is_file())
            continue
        else:
            continue
        found.update(f for f in map(_module_file, names) if f)
    return found


def closure(entry_points: list[str]) -> set[str]:
    seen: set[Path] = set()
    stack = [SCRIPTS / name for name in entry_points]
    while stack:
        path = stack.pop()
        if path not in seen:
            seen.add(path)
            stack.extend(_imports(path))
    return {str(p.relative_to(REPO_ROOT)) for p in seen}


class DeploySiteTriggers(unittest.TestCase):
    def test_every_script_the_build_imports_triggers_it(self):
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github/workflows/deploy-site.yml").read_text(encoding="utf-8")
        )
        on = workflow.get("on", workflow.get(True))
        patterns = on["push"]["paths"]
        run = "\n".join(
            step.get("run", "") for job in workflow["jobs"].values() for step in job["steps"]
        )
        # The Astro build runs scripts of its own (site_markdown.py writes
        # each page's Markdown once the pages are built): they are the
        # build's entry points as much as a workflow step's.
        astro = (REPO_ROOT / "website" / "astro.config.mjs").read_text(encoding="utf-8")
        entry_points = sorted(
            {
                word.removeprefix("scripts/")
                for word in run.split()
                if word.startswith("scripts/") and word.endswith(".py")
            }
            | set(re.findall(r"\.\./scripts/([\w]+\.py)", astro))
        )
        self.assertIn("generate_site.py", entry_points)
        # The Starlight project is an input of its own build.
        self.assertIn("website/**", patterns)
        uncovered = sorted(
            path
            for path in closure(entry_points)
            if not any(fnmatch.fnmatch(path, p.replace("**", "*")) for p in patterns)
        )
        self.assertEqual(uncovered, [])
        # And no script the build no longer reaches: generate_pack.py and six
        # others stayed listed after the site stopped importing the builder,
        # and a push touching only them rebuilt the site for nothing.
        listed = {p for p in patterns if p.startswith("scripts/") and p.endswith(".py")}
        self.assertEqual(sorted(listed - closure(entry_points)), [])
        self.assertNotIn("tests/**", patterns)

    def test_the_site_reads_the_ref_grammar_not_the_checker(self):
        """sitesources imported two parsing functions from profile_sync, so
        every change to the comparison tool rebuilt an unchanged site."""
        self.assertNotIn("scripts/profile_sync.py", closure(["generate_site.py"]))
        self.assertIn("scripts/sourceref.py", closure(["generate_site.py"]))


class ThePullRequestBuildsTheSite(unittest.TestCase):
    """The site build ran in deploy-site.yml alone, after the merge, and
    validate.yml did not watch wiki/: a dead link or a line read as a second
    heading passed every check and failed the deploy on main."""

    @staticmethod
    def _workflow(name: str) -> dict:
        return yaml.safe_load(
            (REPO_ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        )

    def test_the_test_job_runs_the_deploy_build(self):
        steps = self._workflow("validate.yml")["jobs"]["run-tests"]["steps"]
        runs = "\n".join(str(step.get("run", "")) for step in steps)
        for command in (
            "python scripts/generate_site.py",
            "npm ci --prefix website",
            "npm run build --prefix website",
            "python scripts/validate_site.py --site-dir website/dist",
        ):
            with self.subTest(command=command):
                self.assertIn(command, runs)
        # The same Node, from the official action pinned by commit, in both.
        uses = {str(step.get("uses", "")) for step in steps}
        deploy = {str(step.get("uses", ""))
                  for step in self._workflow("deploy-site.yml")["jobs"]["build"]["steps"]}
        node = {use for use in uses if use.startswith("actions/setup-node@")}
        self.assertEqual(len(node), 1)
        self.assertTrue(node <= deploy)
        self.assertRegex(next(iter(node)), r"@[0-9a-f]{40}$")

    def test_the_pages_exist_before_the_suite_reads_them(self):
        """The pages are gitignored. Built after the suite, the tests that read
        the rendered pages found none and skipped on every CI run."""
        steps = self._workflow("validate.yml")["jobs"]["run-tests"]["steps"]
        runs = [str(step.get("run", "")) for step in steps]
        generate = next(
            i for i, run in enumerate(runs) if "scripts/generate_site.py" in run
        )
        suite = next(i for i, run in enumerate(runs) if "unittest discover" in run)
        self.assertLess(generate, suite)
        # The built pages too: about fifty tests read website/dist.
        build = next(i for i, run in enumerate(runs) if "npm run build" in run)
        self.assertLess(generate, build)
        self.assertLess(build, suite)
        self.assertEqual(steps[build].get("if"), "${{ !cancelled() }}")
        self.assertEqual(steps[suite].get("if"), "${{ !cancelled() }}")
        # A failed data fetch skipped the generator, and all 228 site tests
        # then failed under it: the generator runs whatever came before.
        self.assertEqual(steps[generate].get("if"), "${{ !cancelled() }}")

    def test_a_failed_sandbox_step_skips_nothing_after_it(self):
        """No Ubuntu mirror resolved on 2026-11-11: the bubblewrap step
        failed, the steps after it were skipped, and the suite failed on
        absent data trees and astro. Those steps do not need bubblewrap."""
        steps = self._workflow("validate.yml")["jobs"]["run-tests"]["steps"]
        sandbox = next(step for step in steps if "bubblewrap" in str(step.get("name", "")))
        self.assertNotIn("continue-on-error", sandbox)
        self.assertNotIn("if", sandbox)
        self.assertIn("Acquire::Retries=5", sandbox["run"])
        self.assertIn("sleep 30", sandbox["run"])
        after = steps[steps.index(sandbox) + 1:]
        for key in ("actions/setup-node@", "npm ci --prefix website",
                    "export_native.py --all --refresh-cache", "refresh_data_dirs.py"):
            step = next(s for s in after
                        if key in str(s.get("uses", "")) or key in str(s.get("run", "")))
            with self.subTest(step=key):
                self.assertEqual(step.get("if"), "${{ !cancelled() }}")

    def test_every_site_input_triggers_validation(self):
        deploy = self._workflow("deploy-site.yml")
        validate = self._workflow("validate.yml")
        watched = set(validate.get("on", validate.get(True))["push"]["paths"])
        inputs = {
            path
            for path in deploy.get("on", deploy.get(True))["push"]["paths"]
            if not path.startswith(("scripts/", ".github/"))
        }
        self.assertIn("wiki/**", inputs)
        # A path the deploy names inside a folder validate.yml watches
        # whole (tests/campaign/observations.yml under tests/**) is watched.
        unwatched = [path for path in inputs - watched
                     if not any(fnmatch.fnmatch(path, pattern) for pattern in watched)]
        self.assertEqual(sorted(unwatched), [])
        self.assertIn("scripts/**", watched)


class DocumentedSteps(unittest.TestCase):
    def test_the_profiling_reference_names_every_profile_field(self):
        """built_by, source_branch, bios_mode, standalone_path and
        on_mismatch change what the tools do and no page named them."""
        import json  # noqa: PLC0415

        schema = json.loads((REPO_ROOT / "schemas/emulator.schema.json").read_text(encoding="utf-8"))
        item = schema["properties"]["files"]["items"]
        if "$ref" in item:
            item = schema.get("$defs", schema.get("definitions", {}))[item["$ref"].split("/")[-1]]
        page = (REPO_ROOT / "wiki/profiling.md").read_text(encoding="utf-8")
        fields = [*schema["properties"], *item.get("properties", {})]
        self.assertEqual(sorted(f for f in fields if f"`{f}`" not in page), [])

    def test_every_option_says_what_it_does(self):
        """--all-variants, and 95 others, showed in
        --help with no text: their constraints surfaced only as errors."""
        sources = [*SCRIPTS.rglob("*.py"), REPO_ROOT / "install.py"]
        silent = []
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "attr", None) == "add_argument"
                    and not any(k.arg == "help" for k in node.keywords)
                ):
                    first = next((a.value for a in node.args if isinstance(a, ast.Constant)), "?")
                    silent.append(f"{path.relative_to(REPO_ROOT)}: {first}")
        self.assertEqual(silent, [])

    def test_the_scraper_recipe_names_every_abstract_method(self):
        """tools.md said implement fetch_requirements(), but validate_format() is
        abstract too, and a scraper written from the page could not be built."""
        source = (SCRIPTS / "scraper" / "base_scraper.py").read_text(encoding="utf-8")
        abstract = re.findall(r"@abstractmethod\s+def (\w+)", source)
        self.assertTrue(abstract)
        for page in ("tools.md", "adding-a-scraper.md"):
            text = (REPO_ROOT / "wiki" / page).read_text(encoding="utf-8")
            with self.subTest(page=page):
                self.assertEqual([m for m in abstract if f"{m}(" not in text], [])

    def test_every_function_the_pages_name_exists(self):
        """verification-modes described _find_best_variant(), deleted on
        2026-10-05, and an algorithm the code no longer follows."""
        # Names the pages cite from the platforms' and emulators' own code,
        # or from Python itself.
        upstream = {"casefold", "checkInsideZip", "path_is_valid", "GAME", "COMP"}
        sources = [*SCRIPTS.rglob("*.py"), REPO_ROOT / "install.py"]
        defined = {
            match
            for path in sources
            for match in re.findall(
                r"^\s*(?:def|class)\s+(\w+)", path.read_text(encoding="utf-8", errors="replace"), re.M
            )
        }
        stale = sorted(
            {
                (page.name, name)
                for page in (REPO_ROOT / "wiki").glob("*.md")
                for name in re.findall(r"`(\w+)\(\)`", page.read_text(encoding="utf-8"))
                if name not in defined and name not in upstream
            }
        )
        self.assertEqual(stale, [])

    def test_the_release_page_names_every_validation_job(self):
        """check-new-profiles ran on every pull request and push while the
        page said four jobs and named none of it."""
        workflow = yaml.safe_load(
            (REPO_ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        )
        page = (REPO_ROOT / "wiki/release-process.md").read_text(encoding="utf-8")
        missing = sorted(job for job in workflow["jobs"] if f"**{job}" not in page)
        self.assertEqual(missing, [])
        words = {2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven"}
        self.assertIn(f"{words[len(workflow['jobs'])]} jobs", page)

    def test_the_release_page_names_every_installed_package(self):
        """The page listed pyyaml and mkdocs and left out jsonschema: a
        maintainer following it could not run the contract check."""
        sys.path.insert(0, str(SCRIPTS))
        from check_freshness import parse_pip_pins  # noqa: PLC0415

        workflow = (REPO_ROOT / ".github/workflows/deploy-site.yml").read_text(encoding="utf-8")
        page = (REPO_ROOT / "wiki/release-process.md").read_text(encoding="utf-8")
        missing = sorted(name for name in parse_pip_pins(workflow) if name not in page)
        self.assertEqual(missing, [])
        self.assertIn("validate_schemas.py", page)


if __name__ == "__main__":
    unittest.main()
