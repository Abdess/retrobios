#!/usr/bin/env python3
"""The gate that inspects contributor files before a PR is reviewed.

validate.yml runs this on every added or modified file under bios/, and its
output is posted to the PR. It reads paths chosen by whoever opened the PR, so
it is an untrusted-input boundary with nothing behind it.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validate_pr  # noqa: E402

EMPTY_HASHES: dict = {"sha1": set(), "md5": set(), "names": set()}


class _Fixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _bios_file(self, relative: str, data: bytes = b"BIOS") -> str:
        path = self.tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return relative


class FileShapeChecks(_Fixture):
    def test_missing_file_fails_without_hashing(self):
        result = validate_pr.validate_file("bios/nope.bin", None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertEqual(result.sha1, "")

    def test_empty_file_fails(self):
        rel = self._bios_file("bios/Sony/PS/empty.bin", b"")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertIn("empty", result.to_markdown().lower())

    def test_executable_extension_is_refused(self):
        rel = self._bios_file("bios/Sony/PS/payload.exe")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertFalse(result.passed)
        self.assertIn("Blocked file extension", result.to_markdown())

    def test_oversized_file_is_refused(self):
        rel = self._bios_file("bios/Sony/PS/big.bin")
        original = validate_pr.MAX_FILE_SIZE
        validate_pr.MAX_FILE_SIZE = 2
        try:
            result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        finally:
            validate_pr.MAX_FILE_SIZE = original
        self.assertFalse(result.passed)
        self.assertIn("too large", result.to_markdown())

    def test_ordinary_file_passes(self):
        rel = self._bios_file("bios/Sony/PlayStation/scph.bin")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        self.assertTrue(result.passed, result.to_markdown())
        self.assertEqual(len(result.sha1), 40)


class SymlinksAreRefusedBeforeReading(_Fixture):
    """A symlink must be rejected without its target being read.

    The check used to run after compute_hashes, so a link to an endless
    device would be read until the CI job timed out, and a link outside the
    checkout would be hashed and reported as though it were contributed.
    """

    def test_symlink_is_refused(self):
        self._bios_file("bios/Sony/PS/real.bin")
        link = self.tmp / "bios" / "Sony" / "PS" / "link.bin"
        link.symlink_to(self.tmp / "bios" / "Sony" / "PS" / "real.bin")
        result = validate_pr.validate_file(
            "bios/Sony/PS/link.bin", None, EMPTY_HASHES
        )
        self.assertFalse(result.passed)
        self.assertIn("Symlink", result.to_markdown())

    def test_symlink_target_is_never_hashed(self):
        self._bios_file("bios/Sony/PS/real.bin")
        link = self.tmp / "bios" / "Sony" / "PS" / "link.bin"
        link.symlink_to(self.tmp / "bios" / "Sony" / "PS" / "real.bin")
        calls = []
        real = validate_pr.compute_hashes
        validate_pr.compute_hashes = lambda p, *a, **k: (
            calls.append(p) or real(p, *a, **k)
        )
        try:
            validate_pr.validate_file("bios/Sony/PS/link.bin", None, EMPTY_HASHES)
        finally:
            validate_pr.compute_hashes = real
        self.assertEqual(calls, [], "a symlink target must not be read")

    @unittest.skipUnless(os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_a_link_to_an_endless_device_does_not_hang(self):
        link = self.tmp / "bios" / "Sony" / "PS" / "zero.bin"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("/dev/zero")
        result = validate_pr.validate_file(
            "bios/Sony/PS/zero.bin", None, EMPTY_HASHES
        )
        self.assertFalse(result.passed)


class HashRecognition(_Fixture):
    def test_a_declared_sha1_is_recognised(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        known = {"sha1": {probe.sha1}, "md5": set(), "names": set()}
        result = validate_pr.validate_file(rel, None, known)
        self.assertIn("SHA1 matches known platform requirement", result.to_markdown())

    def test_a_declared_md5_is_recognised(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        known = {"sha1": set(), "md5": {probe.md5}, "names": set()}
        self.assertIn(
            "MD5 matches known platform requirement",
            validate_pr.validate_file(rel, None, known).to_markdown(),
        )

    def test_a_known_name_with_another_hash_is_flagged_as_a_variant(self):
        rel = self._bios_file("bios/Sony/PS/known.bin")
        known = {"sha1": set(), "md5": set(), "names": {"known.bin"}}
        markdown = validate_pr.validate_file(rel, None, known).to_markdown()
        self.assertIn("may be a variant", markdown)
        self.assertIn(".variants/known.bin.", markdown)

    def test_an_unreferenced_file_asks_for_review(self):
        rel = self._bios_file("bios/Sony/PS/mystery.bin")
        markdown = validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown()
        self.assertIn("needs manual review", markdown)

    def test_a_duplicate_of_a_known_file_is_reported(self):
        rel = self._bios_file("bios/Sony/PS/dupe.bin")
        probe = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        db = {"files": {probe.sha1: {"path": "bios/Sony/PS/original.bin"}}}
        markdown = validate_pr.validate_file(rel, db, EMPTY_HASHES).to_markdown()
        self.assertIn("Duplicate", markdown)
        self.assertIn("original.bin", markdown)
        # A duplicate is worth saying out loud but must not block the PR.
        self.assertTrue(validate_pr.validate_file(rel, db, EMPTY_HASHES).passed)


class Placement(_Fixture):
    def test_manufacturer_and_console_directories_are_accepted(self):
        rel = self._bios_file("bios/Sega/Saturn/sega_101.bin")
        self.assertIn(
            "Correct placement: bios/Sega/Saturn/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )

    def test_a_file_at_the_bios_root_is_flagged(self):
        rel = self._bios_file("bios/loose.bin")
        self.assertIn(
            "bios/Manufacturer/Console/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )

    def test_a_file_outside_bios_is_flagged(self):
        rel = self._bios_file("elsewhere/loose.bin")
        self.assertIn(
            "not under bios/",
            validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown(),
        )


class Reporting(_Fixture):
    def test_markdown_carries_every_digest_and_the_verdict(self):
        rel = self._bios_file("bios/Sega/Saturn/sega.bin")
        result = validate_pr.validate_file(rel, None, EMPTY_HASHES)
        markdown = result.to_markdown()
        for value in (result.sha1, result.md5, result.crc32):
            self.assertIn(value, markdown)
        self.assertIn("✅", markdown)

    def test_a_failure_is_marked_in_the_heading(self):
        rel = self._bios_file("bios/Sega/Saturn/bad.exe")
        self.assertIn("❌", validate_pr.validate_file(rel, None, EMPTY_HASHES).to_markdown())


class PlatformHashLoading(_Fixture):
    def test_missing_directory_yields_empty_sets(self):
        known = validate_pr.load_platform_hashes(str(self.tmp / "absent"))
        self.assertEqual(known, {"sha1": set(), "md5": set(), "names": set()})

    def test_declared_hashes_and_names_are_collected(self):
        platforms = self.tmp / "platforms"
        platforms.mkdir()
        (platforms / "_registry.yml").write_text(
            "platforms:\n  demo:\n    status: active\n"
        )
        (platforms / "demo.yml").write_text(
            "platform: Demo\n"
            "systems:\n"
            "  test-sys:\n"
            "    files:\n"
            "      - name: boot.bin\n"
            f"        sha1: {'a' * 40}\n"
            f"        md5: {'b' * 32}\n"
        )
        known = validate_pr.load_platform_hashes(str(platforms))
        self.assertIn("a" * 40, known["sha1"])
        self.assertIn("b" * 32, known["md5"])
        self.assertIn("boot.bin", known["names"])


if __name__ == "__main__":
    unittest.main()
