"""Slot arbitration: who decides what goes at a destination."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import slots  # noqa: E402


def _db(entries: dict[str, dict]) -> dict:
    """Minimal database shaped like the generated one, keyed by sha1.

    The resolver reads the disk before it answers, so the fixture writes the
    files it indexes and the caller runs from the directory holding them.
    """
    files, by_md5, by_name, by_path_suffix = {}, {}, {}, {}
    for sha1, info in entries.items():
        path = info["path"]
        name = path.rsplit("/", 1)[-1]
        files[sha1] = {
            "path": path,
            "md5": info.get("md5", ""),
            "name": name,
            "crc32": info.get("crc32", ""),
            "size": info.get("size", 0),
            "sha1": sha1,
        }
        if info.get("md5"):
            by_md5[info["md5"]] = sha1
        by_name.setdefault(name, []).append(sha1)
        parts = path.split("/")
        for depth in range(1, len(parts)):
            by_path_suffix.setdefault("/".join(parts[-depth:]), []).append(sha1)
    return {
        "files": files,
        "indexes": {
            "by_md5": by_md5,
            "by_name": by_name,
            "by_crc32": {},
            "by_path_suffix": by_path_suffix,
        },
    }


_ROOT = Path(tempfile.mkdtemp(prefix="slots-"))
_ENTRIES = {
    "a" * 40: {"path": "bios/Console/GC/USA/IPL.bin", "md5": "m" * 32, "size": 3},
    "b" * 40: {"path": "bios/Console/GC/JAP/IPL.bin", "md5": "n" * 32, "size": 3},
}
for _info in _ENTRIES.values():
    _target = _ROOT / _info["path"]
    _target.parent.mkdir(parents=True, exist_ok=True)
    _target.write_bytes(b"rom")

REGIONS_DB = _db(_ENTRIES)


def setUpModule():
    global _PREVIOUS_CWD
    _PREVIOUS_CWD = os.getcwd()
    os.chdir(_ROOT)


def tearDownModule():
    os.chdir(_PREVIOUS_CWD)
    shutil.rmtree(_ROOT, ignore_errors=True)


class TestClaimIndex(unittest.TestCase):
    """Keyed by destination and by name, the name carrying the union."""

    def _claims(self):
        return [
            slots.Claim("profile", "GC/USA/IPL.bin", "IPL.bin", emulator="dolphin"),
            slots.Claim("profile", "GC/JAP/IPL.bin", "IPL.bin", emulator="dolphin"),
        ]

    def test_destination_key_separates_same_named_entries(self):
        index = slots.build_claim_index(self._claims())
        self.assertEqual(len(index["gc/usa/ipl.bin"]), 1)
        self.assertEqual(len(index["gc/jap/ipl.bin"]), 1)

    def test_bare_name_answers_with_the_union(self):
        index = slots.build_claim_index(self._claims())
        self.assertEqual(len(index["ipl.bin"]), 2)

    def test_lookup_ignores_case_and_leading_separator(self):
        index = slots.build_claim_index(
            [slots.Claim("platform", "/BIOS/Disk.rom", "Disk.rom")]
        )
        self.assertIn("bios/disk.rom", index)


class TestConflicts(unittest.TestCase):
    """A proven profile claim contradicting what the baseline would ship."""

    def _config(self, md5: str) -> dict:
        return {
            "systems": {
                "console": {
                    "files": [
                        {
                            "name": "IPL.bin",
                            "destination": "GC/JAP/IPL.bin",
                            "md5": md5,
                        }
                    ]
                }
            }
        }

    def _profile(self, *paths: str) -> dict:
        return {
            "dolphin": {
                "files": [{"name": "IPL.bin", "path": p} for p in paths]
            }
        }

    def test_wrong_region_under_a_region_slot_is_reported(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].destination, "GC/JAP/IPL.bin")
        self.assertTrue(conflicts[0].platform_claim.local_path.endswith("USA/IPL.bin"))
        self.assertTrue(
            conflicts[0].profile_claims[0].local_path.endswith("JAP/IPL.bin")
        )
        self.assertEqual(conflicts[0].emulators, ["dolphin"])

    def test_agreement_is_not_a_conflict(self):
        conflicts = slots.find_conflicts(
            self._config("n" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        self.assertEqual(conflicts, [])

    def test_one_matching_revision_among_several_settles_the_slot(self):
        # A profile listing every acceptable revision agrees with the platform
        # as soon as one of them is what ships.
        profile = {
            "dosbox": {
                "files": [
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "n" * 32},
                    {"name": "IPL.bin", "path": "GC/JAP/IPL.bin", "md5": "m" * 32},
                ]
            }
        }
        conflicts = slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB)
        self.assertEqual(conflicts, [])

    def test_a_name_only_resolution_asserts_nothing(self):
        # No hash and no path that the repository carries: the entry is
        # answered by filename alone and cannot contradict anything.
        config = {
            "systems": {
                "console": {
                    "files": [{"name": "IPL.bin", "destination": "slot/IPL.bin"}]
                }
            }
        }
        profile = {"dolphin": {"files": [{"name": "IPL.bin", "path": "slot/IPL.bin"}]}}
        self.assertEqual(slots.find_conflicts(config, profile, REGIONS_DB), [])

    def test_launchers_and_aliases_never_claim(self):
        profile = {
            "launcher": {
                "type": "launcher",
                "files": [{"name": "IPL.bin", "path": "GC/JAP/IPL.bin"}],
            }
        }
        self.assertEqual(
            slots.find_conflicts(self._config("m" * 32), profile, REGIONS_DB), []
        )

    def test_base_destination_prefixes_both_sides(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32),
            self._profile("GC/JAP/IPL.bin"),
            REGIONS_DB,
            base_dest="bios",
        )
        self.assertEqual(conflicts[0].destination, "bios/GC/JAP/IPL.bin")

    def test_report_line_names_both_answers(self):
        conflicts = slots.find_conflicts(
            self._config("m" * 32), self._profile("GC/JAP/IPL.bin"), REGIONS_DB
        )
        line = slots.format_conflict(conflicts[0])
        self.assertIn("USA/IPL.bin", line)
        self.assertIn("JAP/IPL.bin", line)
        self.assertIn("dolphin", line)


class TestArbitration(unittest.TestCase):
    """A pack answers to whoever asked for it, and serves both when it can."""

    def _conflict(self):
        platform = slots.Claim(
            "platform", "GC/JAP/IPL.bin", "IPL.bin",
            local_path="bios/Console/GC/USA/IPL.bin", status="md5_exact",
        )
        profile = slots.Claim(
            "profile", "GC/JAP/IPL.bin", "IPL.bin", emulator="dolphin",
            local_path="bios/Console/GC/JAP/IPL.bin", status="path_exact",
        )
        return slots.Conflict("GC/JAP/IPL.bin", platform, [profile])

    def test_existence_mode_serves_both(self):
        decision = slots.arbitrate(self._conflict(), "existence")
        self.assertEqual(decision.winner.origin, "profile")
        self.assertTrue(decision.serves_both)

    def test_md5_mode_keeps_the_frontend_green(self):
        decision = slots.arbitrate(self._conflict(), "md5")
        self.assertEqual(decision.winner.origin, "platform")
        self.assertFalse(decision.serves_both)

    def test_sha1_mode_is_content_checking_too(self):
        decision = slots.arbitrate(self._conflict(), "sha1")
        self.assertEqual(decision.winner.origin, "platform")

    def test_an_emulator_pack_answers_to_the_emulator(self):
        decision = slots.arbitrate(self._conflict(), "md5", addressee="emulator")
        self.assertEqual(decision.winner.origin, "profile")
        self.assertFalse(decision.serves_both)

    def test_the_reported_line_gives_the_ground_for_the_decision(self):
        kept = slots.format_decision(slots.arbitrate(self._conflict(), "md5"))
        self.assertIn("verifies content", kept)
        served = slots.format_decision(slots.arbitrate(self._conflict(), "existence"))
        self.assertIn("both are satisfied", served)


class TestProvenEvidence(unittest.TestCase):
    """What counts as proof that a claim is about content, not about a name."""

    def test_hash_evidence_is_proof(self):
        self.assertTrue(slots.Claim("profile", "d", "n", status="sha1_exact").is_proven)
        self.assertTrue(slots.Claim("profile", "d", "n", status="md5_exact").is_proven)

    def test_path_evidence_is_proof(self):
        # Dolphin declares no checksum for the GameCube boot ROM because its
        # source declares none; the path is then the whole assertion.
        self.assertTrue(slots.Claim("profile", "d", "n", status="path_exact").is_proven)

    def test_a_name_is_not_proof(self):
        self.assertFalse(slots.Claim("profile", "d", "n", status="name_exact").is_proven)
        self.assertFalse(
            slots.Claim("profile", "d", "n", status="hash_mismatch").is_proven
        )


if __name__ == "__main__":
    unittest.main()
