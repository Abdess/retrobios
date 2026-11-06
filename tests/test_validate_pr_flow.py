"""What a contributor gets back after adding a BIOS file.

A pull request from a fork runs with a read-only token, so the hash report
has to reach the contributor without one. And the advice for a file git
cannot hold has to be an action the contributor can take.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_pr  # noqa: E402

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "validate.yml"
SAME_REPO = "github.event.pull_request.head.repo.full_name == github.repository"


def _workflow() -> dict:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML resolves the bare `on:` key to the boolean True.
    document["on"] = document.pop(True, document.get("on"))
    return document


def _steps(job: str) -> list[dict]:
    return _workflow()["jobs"][job]["steps"]


class ForkPullRequestsGetTheReport(unittest.TestCase):
    def test_the_report_goes_to_the_job_summary_whatever_the_outcome(self):
        summary = [
            s for s in _steps("validate-bios")
            if "GITHUB_STEP_SUMMARY" in str(s.get("run", ""))
        ]
        self.assertTrue(summary, "the report never reaches the job summary")
        self.assertIn("report.md", str(summary[0]["run"]))
        self.assertIn("always()", str(summary[0].get("if", "")))

    def test_the_summary_is_written_before_the_failing_gate(self):
        steps = _steps("validate-bios")
        names = [str(s.get("run", "")) for s in steps]
        summary = next(i for i, r in enumerate(names) if "GITHUB_STEP_SUMMARY" in r)
        gate = next(i for i, s in enumerate(steps) if "rc != " in str(s.get("if", "")))
        self.assertLess(summary, gate)

    def test_the_comment_is_posted_only_where_the_token_can_write(self):
        for step in _steps("validate-bios"):
            if "gh pr comment" in str(step.get("run", "")):
                self.assertIn(SAME_REPO, str(step.get("if", "")))

    def test_labels_are_not_attempted_from_a_fork(self):
        for step in _steps("label-pr"):
            run = str(step.get("run", ""))
            if "gh pr edit" in run:
                self.assertIn(SAME_REPO, str(step.get("if", "")))
                self.assertNotIn("|| true", run, "a refused label vanishes in silence")

    def test_no_run_gets_a_write_token_for_fork_code(self):
        triggers = _workflow()["on"]
        self.assertNotIn("pull_request_target", triggers)
        self.assertNotIn("workflow_run", triggers)
        for path in (REPO_ROOT / ".github" / "workflows").glob("*.yml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            # PyYAML reads the bare key `on` as True.
            events = data.get("on", data.get(True)) or {}
            self.assertNotIn("pull_request_target", events, path.name)

    def test_the_workflow_uses_no_third_party_action(self):
        for job in _workflow()["jobs"].values():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses:
                    self.assertTrue(uses.startswith("actions/"), uses)


class OversizedFileAdvice(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, self._cwd)
        self._max = validate_pr.MAX_FILE_SIZE
        self.addCleanup(setattr, validate_pr, "MAX_FILE_SIZE", self._max)

    def _message(self) -> str:
        path = self.tmp / "bios" / "Sony" / "PlayStation 3" / "PS3UPDAT.PUP"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"PUP" * 4)
        validate_pr.MAX_FILE_SIZE = 4
        result = validate_pr.validate_file(
            str(path.relative_to(self.tmp)), None,
            {"sha1": set(), "md5": set(), "names": set()},
        )
        self.assertFalse(result.passed)
        return next(m for s, m in result.checks if s == "FAIL" and "too large" in m)

    def test_the_advice_is_an_issue_for_the_large_files_release(self):
        message = self._message()
        self.assertNotIn("storage: external", message)
        self.assertIn("large-files", message)
        self.assertIn("open an issue", message)
        self.assertIn(validate_pr.LARGE_FILE_ISSUE_URL, message)

    def test_the_issue_form_is_filled_and_nothing_points_to_the_pr(self):
        """The link opened an empty form, and the same report said to put the
        file in the pull request and under bios/."""
        import urllib.parse  # noqa: PLC0415

        path = self.tmp / "big.bin"
        path.write_bytes(b"x" * 8)
        validate_pr.MAX_FILE_SIZE = 4
        result = validate_pr.validate_file(
            "big.bin", None, {"sha1": set(), "md5": set(), "names": set()},
        )
        message = next(m for s, m in result.checks if s == "FAIL" and "too large" in m)
        url = message.split("(", 2)[2].split(")", 1)[0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        template = (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "missing-bios.yml").read_text()
        for field, value in (("filename", "big.bin"), ("sha1", result.sha1),
                             ("md5", result.md5), ("size", "8")):
            with self.subTest(field=field):
                self.assertIn(f"id: {field}\n", template)
                self.assertEqual(query[field], [value])
        others = " ".join(m for _s, m in result.checks)
        self.assertNotIn("pull request which", others)
        self.assertNotIn("not under bios/", others)

    def test_the_linked_issue_template_exists(self):
        template = validate_pr.LARGE_FILE_ISSUE_URL.rsplit("template=", 1)[1]
        self.assertTrue(
            (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / template).is_file(), template
        )


class RunFromAnyDirectory(unittest.TestCase):
    """database.json, platforms/ and emulators/ were read from the current
    directory. Run from elsewhere, scph5501.bin came back referenced by no
    platform and not under bios/, with rc 0."""

    def test_the_report_is_the_one_the_root_gives(self):
        path = REPO_ROOT / "bios" / "Sony" / "PlayStation" / "scph5501.bin"
        self.assertTrue(path.is_file(), path)
        reports = {}
        with tempfile.TemporaryDirectory() as elsewhere:
            for cwd, arg in ((REPO_ROOT, "bios/Sony/PlayStation/scph5501.bin"),
                             (Path(elsewhere), str(path))):
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "scripts" / "validate_pr.py"),
                     "--json", arg],
                    cwd=cwd, capture_output=True, text=True, timeout=120, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                reports[cwd == REPO_ROOT] = json.loads(proc.stdout)[0]["checks"]
        self.assertEqual(reports[False], reports[True])
        messages = [c["message"] for c in reports[False]]
        self.assertIn("SHA1 matches known platform requirement", messages)
        self.assertIn("Already in the database at this path", messages)


class AnUnfetchedUpstreamIsFetched(unittest.TestCase):
    """CONTRIBUTING has the project added as `upstream` with no fetch. The
    remote named the project, so nothing was fetched, upstream/main did not
    exist, origin/main was the pushed branch, and --changed found nothing."""

    def _git(self, cwd: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)

    def test_the_branch_file_is_found(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            root = Path(tmp)
            project = root / "Abdess" / "retrobios.git"
            fork = root / "fork.git"
            clone = root / "clone"
            for bare in (project, fork):
                bare.mkdir(parents=True)
                self._git(bare, "init", "-q", "--bare", "-b", "main")
            clone.mkdir()
            self._git(clone, "init", "-q", "-b", "main")
            self._git(clone, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                      "--allow-empty", "-m", "base")
            self._git(clone, "push", "-q", str(project), "main")
            (clone / "bios").mkdir()
            (clone / "bios" / "new.bin").write_bytes(b"x")
            self._git(clone, "add", "bios/new.bin")
            self._git(clone, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                      "-m", "add")
            self._git(clone, "remote", "add", "origin", str(fork))
            self._git(clone, "push", "-q", "origin", "main")
            self._git(clone, "fetch", "-q", "origin")
            self._git(clone, "remote", "add", "upstream", str(project))
            cwd = os.getcwd()
            os.chdir(clone)
            try:
                with mock.patch.object(validate_pr, "PROJECT_URLS", (str(project),)):
                    self.assertEqual(validate_pr.get_changed_files(), ["bios/new.bin"])
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
