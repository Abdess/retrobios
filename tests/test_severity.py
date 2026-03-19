"""Exhaustive severity mapping tests across all modes and statuses."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from verify import Status, Severity, compute_severity


class TestSeverityMappingExistence(unittest.TestCase):
    """Existence mode: RetroArch/Lakka/RetroPie behavior.

    - OK = OK
    - UNTESTED = OK (existence doesn't care about hash)
    - MISSING + required = WARNING
    - MISSING + optional = INFO
    """

    MODE = "existence"

    def test_ok_required(self):
        self.assertEqual(compute_severity(Status.OK, True, self.MODE), Severity.OK)

    def test_ok_optional(self):
        self.assertEqual(compute_severity(Status.OK, False, self.MODE), Severity.OK)

    def test_untested_required(self):
        self.assertEqual(compute_severity(Status.UNTESTED, True, self.MODE), Severity.OK)

    def test_untested_optional(self):
        self.assertEqual(compute_severity(Status.UNTESTED, False, self.MODE), Severity.OK)

    def test_missing_required(self):
        self.assertEqual(compute_severity(Status.MISSING, True, self.MODE), Severity.WARNING)

    def test_missing_optional(self):
        self.assertEqual(compute_severity(Status.MISSING, False, self.MODE), Severity.INFO)


class TestSeverityMappingMd5(unittest.TestCase):
    """MD5 mode: Batocera/RetroBat/EmuDeck behavior.

    - OK = OK
    - UNTESTED + required = WARNING
    - UNTESTED + optional = WARNING
    - MISSING + required = CRITICAL
    - MISSING + optional = WARNING

    Batocera has no required/optional distinction in practice,
    but the severity function handles it for Recalbox compatibility.
    """

    MODE = "md5"

    def test_ok_required(self):
        self.assertEqual(compute_severity(Status.OK, True, self.MODE), Severity.OK)

    def test_ok_optional(self):
        self.assertEqual(compute_severity(Status.OK, False, self.MODE), Severity.OK)

    def test_untested_required(self):
        self.assertEqual(compute_severity(Status.UNTESTED, True, self.MODE), Severity.WARNING)

    def test_untested_optional(self):
        self.assertEqual(compute_severity(Status.UNTESTED, False, self.MODE), Severity.WARNING)

    def test_missing_required(self):
        self.assertEqual(compute_severity(Status.MISSING, True, self.MODE), Severity.CRITICAL)

    def test_missing_optional(self):
        self.assertEqual(compute_severity(Status.MISSING, False, self.MODE), Severity.WARNING)


class TestSeverityBatoceraBehavior(unittest.TestCase):
    """Batocera has no required distinction: all files are treated equally.

    In practice, Batocera YAMLs don't set required=True/False,
    so the default (True) applies. Both required and optional
    untested files get WARNING severity.
    """

    def test_batocera_no_required_distinction_for_untested(self):
        sev_req = compute_severity(Status.UNTESTED, True, "md5")
        sev_opt = compute_severity(Status.UNTESTED, False, "md5")
        self.assertEqual(sev_req, sev_opt)
        self.assertEqual(sev_req, Severity.WARNING)


class TestSeverityRecalboxBehavior(unittest.TestCase):
    """Recalbox has mandatory field: missing mandatory = CRITICAL (RED).

    Recalbox uses md5 mode with mandatory (required) distinction.
    Missing mandatory = CRITICAL (Bios.cpp RED)
    Missing optional = WARNING (Bios.cpp YELLOW)
    """

    def test_recalbox_mandatory_missing_is_critical(self):
        self.assertEqual(
            compute_severity(Status.MISSING, True, "md5"),
            Severity.CRITICAL,
        )

    def test_recalbox_optional_missing_is_warning(self):
        self.assertEqual(
            compute_severity(Status.MISSING, False, "md5"),
            Severity.WARNING,
        )

    def test_recalbox_ok_is_ok(self):
        self.assertEqual(
            compute_severity(Status.OK, True, "md5"),
            Severity.OK,
        )


class TestSeverityRetroArchBehavior(unittest.TestCase):
    """RetroArch existence mode: required missing = WARNING, optional = INFO."""

    def test_retroarch_required_missing_is_warning(self):
        self.assertEqual(
            compute_severity(Status.MISSING, True, "existence"),
            Severity.WARNING,
        )

    def test_retroarch_optional_missing_is_info(self):
        self.assertEqual(
            compute_severity(Status.MISSING, False, "existence"),
            Severity.INFO,
        )

    def test_retroarch_untested_ignored(self):
        """Existence mode ignores untested (hash doesn't matter)."""
        self.assertEqual(
            compute_severity(Status.UNTESTED, True, "existence"),
            Severity.OK,
        )


class TestSeverityAllCombinations(unittest.TestCase):
    """Exhaustive matrix: all status x required x mode combinations."""

    EXPECTED = {
        # (status, required, mode): severity
        (Status.OK, True, "existence"): Severity.OK,
        (Status.OK, False, "existence"): Severity.OK,
        (Status.OK, True, "md5"): Severity.OK,
        (Status.OK, False, "md5"): Severity.OK,
        (Status.UNTESTED, True, "existence"): Severity.OK,
        (Status.UNTESTED, False, "existence"): Severity.OK,
        (Status.UNTESTED, True, "md5"): Severity.WARNING,
        (Status.UNTESTED, False, "md5"): Severity.WARNING,
        (Status.MISSING, True, "existence"): Severity.WARNING,
        (Status.MISSING, False, "existence"): Severity.INFO,
        (Status.MISSING, True, "md5"): Severity.CRITICAL,
        (Status.MISSING, False, "md5"): Severity.WARNING,
    }

    def test_all_combinations(self):
        for (status, required, mode), expected_severity in self.EXPECTED.items():
            with self.subTest(status=status, required=required, mode=mode):
                actual = compute_severity(status, required, mode)
                self.assertEqual(
                    actual,
                    expected_severity,
                    f"compute_severity({status!r}, {required}, {mode!r}) = "
                    f"{actual!r}, expected {expected_severity!r}",
                )

    def test_all_12_combinations_covered(self):
        statuses = [Status.OK, Status.UNTESTED, Status.MISSING]
        requireds = [True, False]
        modes = ["existence", "md5"]
        all_combos = {
            (s, r, m) for s in statuses for r in requireds for m in modes
        }
        self.assertEqual(all_combos, set(self.EXPECTED.keys()))


if __name__ == "__main__":
    unittest.main()
