"""A step that could not do its job says so with its exit code.

validate_pr --changed answered "No changed BIOS files detected" and exited
0 when git itself had failed (no origin, or no repository), and
check_buildbot_system --update exited 0 after a refresh it launched had
failed, the cache left at the old version.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_buildbot_system  # noqa: E402


class GitThatCannotAnswer(unittest.TestCase):
    def test_outside_a_repository_is_an_error_not_an_empty_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "validate_pr.py"), "--changed"],
                cwd=tmp, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("No changed BIOS files detected", proc.stdout)

    def test_a_clone_without_origin_reads_the_index_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            Path(tmp, "bios").mkdir()
            Path(tmp, "bios", "x.bin").write_bytes(b"x")
            subprocess.run(["git", "-C", tmp, "add", "bios/x.bin"], check=True)
            proc = subprocess.run(
                [sys.executable, "-c", (
                    f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r}); "
                    "import validate_pr; print(validate_pr.get_changed_files())"
                )],
                cwd=tmp, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("bios/x.bin", proc.stdout)
        self.assertIn("staged changes only", proc.stderr)


class RefreshFailuresAreFailures(unittest.TestCase):
    def test_a_failed_refresh_is_returned_and_exits_nonzero(self):
        report = {"entries": [{"status": "UPDATED", "key": "dolphin-sys"},
                              {"status": "OK", "key": "ppsspp-assets"}]}
        with mock.patch.object(
            check_buildbot_system.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            self.assertEqual(check_buildbot_system.update_changed(report), ["dolphin-sys"])
        source = (REPO_ROOT / "scripts" / "check_buildbot_system.py").read_text(encoding="utf-8")
        self.assertIn("failed = update_changed(report)", source)
        self.assertIn("sys.exit(1)", source[source.index("failed = update_changed(report)"):])


if __name__ == "__main__":
    unittest.main()
