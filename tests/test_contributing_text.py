"""CONTRIBUTING.md and the site's contributing page say the same thing.

Two generators wrote the page and drifted: four steps to add a platform in
the repository, five on the site, under two different titles.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_readme  # noqa: E402
import generate_site  # noqa: E402


def _normalized(text: str) -> str:
    # The site ends each page with its next step in the reading order. That
    # is navigation, not contributing text, and a repository file has none.
    text = text.split("\n## Next steps\n", 1)[0].rstrip("\n")
    text = re.sub(r"\]\([^)]*\)", "](link)", text)
    return "\n".join(text.splitlines()[1:]).replace("on this site", "on the documentation site")


class OneContributingText(unittest.TestCase):
    def test_repository_and_site_pages_match(self):
        self.assertEqual(
            _normalized(generate_readme.generate_contributing()),
            _normalized(generate_site.generate_contributing()),
        )


class CoverageReadsTheGivenProfiles(unittest.TestCase):
    """generate_site --emulators-dir changed the emulator pages but not the
    platform coverage, which read ./emulators whatever was given."""

    def test_the_directory_reaches_verify(self):
        seen: list[str] = []

        def fake_verify(_config, _db, emulators_dir, **_kwargs):
            seen.append(emulators_dir)
            return {"status_counts": {}, "total_files": 0, "undeclared_files": [], "details": []}

        with mock.patch.object(generate_readme, "verify_platform", fake_verify), \
                mock.patch.object(generate_readme, "load_emulator_profiles", return_value={}):
            generate_readme.compute_coverage(
                "retroarch", str(REPO_ROOT / "platforms"), {"files": {}}, emulators_dir="elsewhere"
            )
        self.assertEqual(seen, ["elsewhere"])


class BeforeOpeningAPullRequest(unittest.TestCase):
    """The section asked for the full pipeline: on a fresh fork, without
    data/, it rebuilt 35 GB of packs and then failed on the data
    directories, while CI asks for three checks."""

    def test_it_lists_the_checks_ci_runs_and_not_the_pipeline(self):
        import re as _re

        text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        block = "".join(_re.findall(r"```bash\n(.*?)```", section, _re.S))
        for command in ("validate_pr.py --changed", "validate_schemas.py --source-only",
                        "run_tests.py"):
            self.assertIn(command, block)
        self.assertNotIn("pipeline.py", block)
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("validate_schemas.py --source-only", workflow)
        # CI holds added profiles to their upstream, not edited ones: --changed
        # failed a contributor on refs they never wrote.
        self.assertIn("profile_sync.py --added --base", workflow)
        self.assertIn("profile_sync.py --added --strict", block)
        self.assertNotIn("upstream/main", section)
        self.assertNotIn("--changed --strict", block)

    def test_it_names_the_site_build_and_the_packages_ci_runs(self):
        """A wiki-only change passed every listed check and failed CI on
        validate_site.py, which the list did not name."""
        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        for command in ("npm ci --prefix website", "npm run build --prefix website",
                        "validate_site.py --site-dir website/dist",
                        "vermin --no-tips -t=3.8- --violations install.py"):
            with self.subTest(command=command):
                self.assertIn(command, workflow)
                self.assertIn(command, section)
        installed = re.search(r'^\s*run: pip install (pyyaml "jsonschema.*markdown.*)$',
                              workflow, re.M).group(1)
        pip_line = next(line for line in section.splitlines() if line.startswith("pip install"))
        for package in (re.split(r"[\[=]", token.strip('"'))[0] for token in installed.split()):
            with self.subTest(package=package):
                self.assertRegex(pip_line, rf"\b{package}\b")

    def test_a_file_too_large_for_git_has_a_route(self):
        """The guide sent any file over 25 MB through a clone, which GitHub
        refuses past 100 MB, and only a maintainer can write to the release."""
        import validate_pr

        text = generate_readme.generate_contributing()
        section = text.split("## What happens next", 1)[1].split("\n## ", 1)[0]
        self.assertEqual(validate_pr.MAX_FILE_SIZE, 100 * 1024 * 1024)
        self.assertIn("100 MB", section)
        self.assertIn(f"]({validate_pr.LARGE_FILE_ISSUE_URL})", section)

    def test_it_installs_what_the_checks_need_and_no_site_package(self):
        """The site is built by Node from website/package-lock.json: a pip
        line naming the old theme installed packages nothing reads."""
        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        self.assertIn('pip install pyyaml "jsonschema[format-nongpl]==', section)
        self.assertNotIn("mkdocs", section)
        self.assertTrue((REPO_ROOT / "website" / "package-lock.json").is_file())


class TheChecklistInstallsWhatCiInstalls(unittest.TestCase):
    """The pip line named the packages without versions, and nothing said
    that shellcheck, bubblewrap and a Python 3.8 with pyte come from the
    system: their tests skipped locally and failed first in CI."""

    def test_the_pip_lines_are_the_workflow_lines(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        pinned = [line.split("run: ", 1)[1] for line in workflow.splitlines()
                  if re.match(r"\s*run: (python3\.8 -m )?pip install .*==", line)
                  and "pyte" in line]
        self.assertEqual(len(pinned), 2)
        for line in pinned:
            with self.subTest(line=line):
                self.assertIn(line, section)

    def test_it_names_the_system_tools_ci_installs(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        for tool, step in (("shellcheck", "shellcheck --version"),
                           ("bwrap", "bwrap --ro-bind"),
                           ("python3.8 -m unittest tests.test_install_tui",
                            "python3.8 -m unittest tests.test_install_tui")):
            with self.subTest(tool=tool):
                self.assertIn(step, workflow)
                self.assertIn(tool, section)


class OneFileThroughTheBrowser(unittest.TestCase):
    """Adding one BIOS asked for a fork, a 5.5 GB clone, five pip packages,
    the data directories and the whole suite, and promised a PR comment that
    a fork's read-only token cannot post. The browser upload into bios/ and
    the CI report already did the work."""

    def test_the_guide_and_the_issue_chooser_offer_the_upload(self):
        import yaml

        text = generate_readme.generate_contributing()
        section = text.split("## Add a BIOS file", 1)[1].split("\n## ", 1)[0]
        self.assertIn(generate_readme.UPLOAD_URL, section)
        self.assertNotIn("Fork this repository", section)
        self.assertNotIn("reported in a comment", text)
        chooser = yaml.safe_load(
            (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
        )
        self.assertIn(generate_readme.UPLOAD_URL, [link["url"] for link in chooser["contact_links"]])

    def test_ci_comments_only_on_branches_of_this_repository(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
        self.assertIn('>> "$GITHUB_STEP_SUMMARY"', workflow)
        self.assertIn("summary of the Validation run", generate_readme.generate_contributing())

    def test_an_upload_at_the_bios_root_is_told_its_folder(self):
        import os
        import tempfile

        import validate_pr

        scratch = REPO_ROOT / "tmp" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            (Path(directory) / "bios").mkdir()
            (Path(directory) / "bios" / "boot.rom").write_bytes(b"boot")
            from common import compute_hashes

            sha1 = compute_hashes(str(Path(directory) / "bios" / "boot.rom"))["sha1"]
            hashes = {"sha1": {sha1}, "folders": {sha1: {"bios/Maker/Console/"}}}
            cwd = os.getcwd()
            os.chdir(directory)
            try:
                result = validate_pr.validate_file("bios/boot.rom", None, hashes)
            finally:
                os.chdir(cwd)
        self.assertTrue(result.passed)
        self.assertTrue(any(
            "bios/ root" in message and "`bios/Maker/Console/`" in message
            for _status, message in result.checks
        ))


class TheGuideRebuildsWhenItsPinsMove(unittest.TestCase):
    """The checklist quotes validate.yml, so a pin bump there must redeploy
    the guide and meet the README/CONTRIBUTING freshness check."""

    def test_deploy_site_watches_the_validation_workflow(self):
        import yaml

        deploy = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8"))
        paths = deploy[True]["push"]["paths"]
        self.assertIn(".github/workflows/validate.yml", paths)


class TheDevPinsAreTheOnesCiInstalls(unittest.TestCase):
    """Dependabot bumped uv in pyproject.toml alone, while validate.yml and
    CONTRIBUTING kept the older pin: a contributor and CI ran two builds."""

    PIN = re.compile(r'"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==([^"]+)"')

    def test_a_package_both_pin_has_one_version(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        project = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        ci = {name.lower(): version for name, version in self.PIN.findall(workflow)}
        dev = {name.lower(): version for name, version in self.PIN.findall(project)}
        shared = sorted(set(ci) & set(dev))
        self.assertIn("uv", shared)
        for name in shared:
            with self.subTest(package=name):
                self.assertEqual(dev[name], ci[name])


class OneCommandRunsTheChecks(unittest.TestCase):
    """A contributor copied ten commands by hand before a pull request, and
    skipping one (refresh_data_dirs) failed the pack tests with no hint."""

    CHECK = re.compile(r"(?:xargs -0 |run: |^\s*)((?:python3?\.?8? -m unittest|python scripts/\w+\.py"
                       r"|vermin|npm (?:ci|run build)|mypy-baseline filter|mypy|shellcheck))")

    def test_every_check_ci_runs_is_a_step(self):
        import pr_checks

        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        ran = {m.group(1) for line in workflow.splitlines()
               if not line.strip().startswith("#") for m in [self.CHECK.search(line)] if m}
        self.assertGreaterEqual(len(ran), 10)
        steps = [c for step in pr_checks.STEPS for c in (step.command, step.then) if c]
        for check in sorted(ran):
            with self.subTest(check=check):
                self.assertTrue(any(command.startswith(check) for command in steps))

    def test_a_step_ci_lets_fail_does_not_fail_the_run(self):
        import pr_checks

        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        tolerated = set(re.findall(r"continue-on-error: true\n\s*run: (\S+ \S+)", workflow))
        for step in pr_checks.STEPS:
            with self.subTest(step=step.command):
                self.assertEqual(step.may_fail, " ".join(step.command.split()[:2]) in tolerated)

    def test_steps_keep_ci_order(self):
        import pr_checks

        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        order = [workflow.index(key) for key in (
            "refresh_data_dirs.py", "run: python scripts/generate_site.py",
            "npm run build --prefix website", "python scripts/run_tests.py",
            "validate_site.py")]
        self.assertEqual(order, sorted(order))
        commands = [step.command for step in pr_checks.STEPS]
        positions = [next(i for i, c in enumerate(commands) if key in c) for key in (
            "refresh_data_dirs.py", "generate_site.py", "npm run build",
            "run_tests.py", "validate_site.py")]
        self.assertEqual(positions, sorted(positions))

    def test_the_guide_gives_the_runner_and_what_it_runs(self):
        import pr_checks

        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        self.assertIn("python scripts/pr_checks.py\n", section)
        for step in pr_checks.STEPS:
            with self.subTest(step=step.command):
                self.assertIn(step.command, section)

    def test_a_missing_tool_is_reported_and_a_failure_does_not_stop_the_run(self):
        import contextlib
        import io

        import pr_checks

        steps = (
            pr_checks.Step("python -c raise(SystemExit(3))", "fails"),
            pr_checks.Step("no-such-tool-here --x", "absent", needs="no-such-tool-here",
                           provider="nothing"),
            pr_checks.Step("python -c pass", "passes"),
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pr_checks.run(steps)
        self.assertEqual(code, 1)
        self.assertIn("FAILED   python -c raise(SystemExit(3)) (exit 3)", out.getvalue())
        self.assertIn("NOT RUN  no-such-tool-here --x", out.getvalue())
        self.assertIn("1/3 checks passed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
