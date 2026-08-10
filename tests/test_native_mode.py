#!/usr/bin/env python3
"""The native-mode policy verify.py and generate_pack.py must share.

CLAUDE.md states the invariant as "verify.py and generate_pack.py must
produce identical results; any divergence is a critical bug". It used to rest
on both files spelling out `mode == "existence"` in their own words. Routing
both through scripts/nativemode.py makes the rule single-sourced, and these
tests make the agreement checkable instead of reviewable.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import nativemode  # noqa: E402


class ModeVocabulary(unittest.TestCase):
    def test_modes_match_the_platform_schema(self):
        """A mode added to one side and not the other is the bug this catches."""
        schema = json.loads(
            (REPO_ROOT / "schemas" / "platform.schema.json").read_text()
        )
        enum = schema["properties"]["verification_mode"]["enum"]
        self.assertEqual(sorted(nativemode.MODES), sorted(enum))

    def test_schema_default_matches_the_module_default(self):
        schema = json.loads(
            (REPO_ROOT / "schemas" / "platform.schema.json").read_text()
        )
        self.assertEqual(
            schema["properties"]["verification_mode"]["default"],
            nativemode.DEFAULT_MODE,
        )

    def test_unknown_or_missing_mode_falls_back_to_the_default(self):
        for value in (None, "", "sha256", "MD5"):
            self.assertEqual(nativemode.normalize(value), nativemode.DEFAULT_MODE)

    def test_every_declared_platform_mode_is_known(self):
        import yaml

        for path in sorted((REPO_ROOT / "platforms").glob("*.yml")):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text()) or {}
            mode = data.get("verification_mode")
            if mode is None:
                continue
            self.assertIn(mode, nativemode.MODES, f"{path.name} declares {mode!r}")


class ContentReadingPolicy(unittest.TestCase):
    def test_existence_reads_nothing(self):
        self.assertFalse(nativemode.reads_file_contents("existence"))
        self.assertIsNone(nativemode.digest_algorithm("existence"))

    def test_digest_modes_read_their_digest(self):
        self.assertEqual(nativemode.digest_algorithm("md5"), "md5")
        self.assertEqual(nativemode.digest_algorithm("sha1"), "sha1")
        self.assertTrue(nativemode.reads_file_contents("md5"))
        self.assertTrue(nativemode.reads_file_contents("sha1"))

    def test_exclusion_follows_content_reading_for_every_mode(self):
        """The builder omits exactly what the frontend would reject."""
        for mode in nativemode.MODES:
            self.assertEqual(
                nativemode.hash_mismatch_excludes_file(mode),
                nativemode.reads_file_contents(mode),
                f"mode {mode} disagrees with itself",
            )


class BothConsumersAgree(unittest.TestCase):
    """verify.py and generate_pack.py must answer the same for every mode."""

    def test_builder_and_verifier_share_one_predicate(self):
        from generate_pack import _intentional_hash_exclusion
        from verify import compute_severity  # noqa: F401  (import proves wiring)

        for mode in nativemode.MODES:
            # No entries is never an exclusion, whatever the mode.
            self.assertFalse(_intentional_hash_exclusion([], {}, verification_mode=mode))

        # The builder must refuse to exclude under existence even when asked.
        self.assertFalse(
            _intentional_hash_exclusion(
                [{"name": "x.bin"}], {}, verification_mode="existence"
            )
        )

    def test_severity_uses_the_shared_predicate(self):
        from verify import Severity, Status, compute_severity

        # Existence mode: a missing required file is a warning, not critical.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "existence"),
            Severity.WARNING,
        )
        # Digest mode: the same absence is critical.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "md5"),
            Severity.CRITICAL,
        )
        # An unknown mode must fall back to existence, not to the strictest
        # reading: a typo in a platform YAML should not invent CRITICALs.
        self.assertEqual(
            compute_severity(Status.MISSING, True, "sha256"),
            Severity.WARNING,
        )


if __name__ == "__main__":
    unittest.main()
