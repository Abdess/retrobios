"""CONTRIBUTING.md and the site's contributing page say the same thing.

Two generators wrote the page and drifted: four steps to add a platform in
the repository, five on the site, under two different titles.
"""

from __future__ import annotations

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
        block = _re.search(r"```bash\n(.*?)```", section, _re.S).group(1)
        for command in ("validate_pr.py --changed", "validate_schemas.py --source-only",
                        "unittest discover"):
            self.assertIn(command, block)
        self.assertNotIn("pipeline.py", block)
        workflow = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("validate_schemas.py --source-only", workflow)
        # CI holds added profiles to their upstream, not edited ones: --changed
        # failed a contributor on refs they never wrote.
        self.assertIn("profile_sync.py --added --base", workflow)
        self.assertIn("profile_sync.py --added --base upstream/main --strict", block)
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

    def test_it_installs_what_the_checks_need_and_no_site_package(self):
        """The site is built by Node from website/package-lock.json: a pip
        line naming the old theme installed packages nothing reads."""
        text = generate_readme.generate_contributing()
        section = text.split("## Before opening a PR", 1)[1].split("\n## ", 1)[0]
        self.assertIn('pip install pyyaml "jsonschema[format-nongpl]" markdown', section)
        self.assertNotIn("mkdocs", section)
        self.assertTrue((REPO_ROOT / "website" / "package-lock.json").is_file())


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


if __name__ == "__main__":
    unittest.main()
