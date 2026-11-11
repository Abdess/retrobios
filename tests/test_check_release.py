"""A dated release is checked against what was built before it is published.

The upload loop has no `set -e`: a part that failed to upload, or a part
re-uploaded from an older build, left a release whose count looked right and
whose checksums every user's `sha256sum --check` rejected.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build_port  # noqa: E402
from check_release import SIGNATURE, SUMS, Asset, compare_release, parse_sums

A = "a" * 64
B = "b" * 64
C = "c" * 64
S = "d" * 64

RECORD = {
    "tag": "v2026.10.10",
    "packs": {
        "Big_BIOS_Pack.zip": {
            "download_size": 300,
            "assets": ["Big_BIOS_Pack.part1of2.zip", "Big_BIOS_Pack.part2of2.zip"],
        },
        "Small_BIOS_Pack.zip": {"download_size": 50, "assets": ["Small_BIOS_Pack.zip"]},
    },
}
SUMS_LIST = {
    "Big_BIOS_Pack.part1of2.zip": A,
    "Big_BIOS_Pack.part2of2.zip": B,
    "Small_BIOS_Pack.zip": C,
}


def _assets() -> dict[str, Asset]:
    return {
        "Big_BIOS_Pack.part1of2.zip": Asset(200, A),
        "Big_BIOS_Pack.part2of2.zip": Asset(100, B),
        "Small_BIOS_Pack.zip": Asset(50, C),
        SUMS: Asset(300, S),
        SIGNATURE: Asset(10, "e" * 64),
    }


def _kinds(findings) -> set[tuple[str, str]]:
    return {(f.kind, f.name) for f in findings}


class ReleaseMatchesWhatWasBuilt(unittest.TestCase):
    def test_a_complete_release_passes(self):
        self.assertEqual(
            compare_release(RECORD, SUMS_LIST, _assets(), "v2026.10.10", {SUMS: S}), []
        )

    def test_a_part_that_failed_to_upload_is_missing(self):
        assets = _assets()
        del assets["Big_BIOS_Pack.part2of2.zip"]
        self.assertIn(
            ("missing", "Big_BIOS_Pack.part2of2.zip"),
            _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
        )

    def test_a_part_from_an_older_build_is_caught_at_the_same_count(self):
        assets = _assets()
        assets["Big_BIOS_Pack.part1of2.zip"] = Asset(200, "f" * 64)
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
            {("content", "Big_BIOS_Pack.part1of2.zip")},
        )

    def test_a_checksum_list_other_than_the_local_one_is_caught(self):
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, _assets(), "v2026.10.10", {SUMS: "0" * 64})),
            {("content", SUMS)},
        )

    def test_an_asset_nobody_recorded_is_extra(self):
        assets = _assets()
        assets["Big_BIOS_Pack.zip.001"] = Asset(1, "1" * 64)
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
            {("extra", "Big_BIOS_Pack.zip.001")},
        )

    def test_record_and_list_must_name_the_same_files(self):
        sums = {k: v for k, v in SUMS_LIST.items() if k != "Small_BIOS_Pack.zip"}
        sums["Other_BIOS_Pack.zip"] = C
        kinds = _kinds(compare_release(RECORD, sums, _assets(), "v2026.10.10"))
        self.assertIn(("unlisted", "Small_BIOS_Pack.zip"), kinds)
        self.assertIn(("unrecorded", "Other_BIOS_Pack.zip"), kinds)
        self.assertIn(("missing", "Other_BIOS_Pack.zip"), kinds)

    def test_a_handheld_launcher_is_no_release_file(self):
        """The site serves the launchers built from its own commit: one in
        the checksum list or among the assets is refused."""
        for name in build_port.ARCHIVES:
            with self.subTest(name=name):
                sums = {**SUMS_LIST, name: A}
                assets = _assets()
                assets[name] = Asset(70, A)
                self.assertEqual(_kinds(compare_release(RECORD, sums, assets, "v2026.10.10")),
                                 {("unrecorded", name)})
                assets = _assets()
                assets[name] = Asset(70, A)
                self.assertEqual(
                    _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
                    {("extra", name)})

    def test_parts_must_add_up_to_the_printed_download_size(self):
        assets = _assets()
        assets["Big_BIOS_Pack.part2of2.zip"] = Asset(99, B)
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
            {("size", "Big_BIOS_Pack.zip")},
        )

    def test_an_asset_without_a_digest_is_not_taken_on_trust(self):
        assets = _assets()
        assets["Small_BIOS_Pack.zip"] = Asset(50, None)
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, assets, "v2026.10.10")),
            {("unverified", "Small_BIOS_Pack.zip")},
        )

    def test_another_tag_than_the_record_is_named(self):
        self.assertEqual(
            _kinds(compare_release(RECORD, SUMS_LIST, _assets(), "v2026.10.11")),
            {("tag", "v2026.10.11")},
        )


class SumsParsing(unittest.TestCase):
    def test_text_and_binary_mode_lines(self):
        text = f"{A}  Small_BIOS_Pack.zip\n{B} *Big BIOS.zip\n\n"
        self.assertEqual(parse_sums(text), {"Small_BIOS_Pack.zip": A, "Big BIOS.zip": B})

    def test_a_line_that_is_not_a_checksum_stops(self):
        with self.assertRaises(ValueError):
            parse_sums("<html>Not Found</html>\n")


if __name__ == "__main__":
    unittest.main()
