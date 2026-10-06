"""verify.py lists what generate_pack.py lists for the same request."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *argv], capture_output=True, check=False, text=True, cwd=REPO_ROOT, timeout=300
    )


class ListingsAgree(unittest.TestCase):
    def test_list_systems_honours_platform(self):
        verify = _run("scripts/verify.py", "--list-systems", "--platform", "bizhawk")
        pack = _run("scripts/generate_pack.py", "--list-systems", "--platform", "bizhawk")
        self.assertEqual(verify.returncode, 0)
        self.assertEqual(verify.stdout, pack.stdout)

    def test_listing_refuses_a_narrowing_flag(self):
        result = _run("scripts/verify.py", "--list-emulators", "--region", "us")
        self.assertNotEqual(result.returncode, 0)


class VerifyRefusesWhatAModeDoesNotRead(unittest.TestCase):
    """The mode x flag matrix generate_pack has, for verify.

    --list-emulators --standalone printed the full list, --list-systems --json
    printed columns, --platform --include-archived covered nothing more: each
    with rc 0, each letting the caller believe the flag applied.
    """

    MATRIX = (
        (("--list-emulators",), "--standalone"),
        (("--list-systems",), "--json"),
        (("--list-targets", "--platform", "retroarch"), "--include-archived"),
        (("--platform", "retroarch"), "--include-archived"),
        (("--emulator", "handy"), "--include-archived"),
        (("--platform", "retroarch"), "--standalone"),
    )

    def test_each_combination_is_refused(self):
        for mode, flag in self.MATRIX:
            with self.subTest(mode=mode, flag=flag):
                result = _run("scripts/verify.py", *mode, flag)
                self.assertEqual(result.returncode, 2, result.stdout[-300:])
                self.assertIn(flag, result.stderr)

    def test_emulator_mode_reads_the_given_platforms_dir(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import verify  # noqa: PLC0415

        seen: list[str] = []

        def registry(path: str) -> dict:
            seen.append(str(path))
            return {}

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}}}
        with mock.patch.object(verify, "load_data_dir_registry", registry):
            verify.verify_emulator(
                ["handy"], str(REPO_ROOT / "emulators"), db, platforms_dir="elsewhere"
            )
        self.assertEqual(seen, ["elsewhere"])


if __name__ == "__main__":
    unittest.main()
