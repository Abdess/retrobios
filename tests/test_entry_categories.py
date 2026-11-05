"""What a platform entry is: firmware, a game's data, or unread.

Strict verification fails on firmware gaps only, so the category has to come
from what the cores the platform runs open, never from the entry's name.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import verify  # noqa: E402
from exporter.candidates import (  # noqa: E402
    BIOS,
    GAME_DATA,
    UNREAD,
    EntryCategories,
    ProofIndex,
    ReadEvidence,
)

PROFILES = {
    "bluemsx": {
        "emulator": "blueMSX", "type": "libretro", "cores": ["bluemsx"],
        "systems": ["microsoft-msx"],
        "files": [{"name": "MSX.ROM", "path": "Machines/Shared Roms/MSX.ROM"}],
    },
    "devilutionx": {
        "emulator": "DevilutionX", "type": "game", "cores": ["devilutionx"],
        "systems": ["diablo"],
        "files": [{"name": "diabdat.mpq", "category": "game_data",
                   "source_ref": "Source/init.cpp:120"}],
    },
}


def _config(cores: list[str], files: list[dict], system: str = "s") -> dict:
    return {"platform": "P", "verification_mode": "md5", "cores": cores,
            "systems": {system: {"files": files}}}



class EachProfileEntryIsHashedOnce(unittest.TestCase):
    """verify --all hashed 9,058 profile entries 2.9 million times: each
    platform entry with a proof walked its reader's profile from scratch."""

    def test_two_platform_entries_read_one_profile_entry_once(self):
        from unittest import mock

        import exporter.candidates as candidates

        profiles = {"core": {"emulator": "Core", "type": "libretro", "cores": ["core"],
                             "systems": ["s"],
                             "files": [{"name": "a.bin", "md5": "a" * 32,
                                        "contents": [{"name": "m", "crc32": "12345678"}]}]}}
        cats = EntryCategories(_config(["core"], []), profiles)
        real = candidates._entry_hashes
        with mock.patch.object(candidates, "_entry_hashes", side_effect=real) as counted:
            for md5 in ("a" * 32, "a" * 29):
                self.assertEqual(cats.category({"name": "a.bin", "md5": md5}, "a.bin", "s"), BIOS)
        self.assertEqual(counted.call_count, 1)
        self.assertTrue(candidates._accepts({"a" * 32}, {"md5": {"a" * 29}}))
        self.assertFalse(candidates._accepts({"a" * 32}, {"md5": {"b" * 32}}))

class Category(unittest.TestCase):
    def test_each_category(self):
        cats = EntryCategories(_config(["bluemsx", "devilutionx"], []), PROFILES)
        self.assertEqual(cats.category({"name": "MSX.ROM"}, "bios/Machines/MSX/MSX.ROM", "microsoft-msx"), BIOS)
        self.assertEqual(cats.category({"name": "diabdat.mpq"}, "ports/diablo/diabdat.mpq", "diablo"),
                         GAME_DATA)
        self.assertEqual(
            cats.category({"name": "hardwareconfig.xml"}, "bios/Machines/MSX/hardwareconfig.xml", "microsoft-msx"),
            UNREAD)

    def test_a_core_without_profile_leaves_unread_open(self):
        cats = EntryCategories(_config(["bluemsx", "devilutionx", "mystery"], []), PROFILES)
        self.assertEqual(
            cats.category({"name": "hardwareconfig.xml"}, "bios/Machines/MSX/hardwareconfig.xml", "microsoft-msx"),
            BIOS)
        self.assertEqual(cats.category({"name": "diabdat.mpq"}, "ports/diablo/diabdat.mpq", "diablo"),
                         GAME_DATA)

    def test_a_system_no_examined_core_emulates_stays_firmware(self):
        cats = EntryCategories(_config(["bluemsx", "devilutionx"], []), PROFILES)
        self.assertEqual(cats.category({"name": "syscard3.pce"}, "syscard3.pce", "nec-pc-engine"),
                         BIOS)

    def test_cores_guessed_from_system_ids_prove_nothing(self):
        config = _config([], [])
        del config["cores"]
        cats = EntryCategories(config, PROFILES)
        self.assertEqual(
            cats.category({"name": "hardwareconfig.xml"}, "bios/Machines/MSX/hardwareconfig.xml",
                          "microsoft-msx"),
            BIOS)

    def test_a_platform_with_no_core_is_all_firmware(self):
        cats = EntryCategories(_config([], []), PROFILES)
        self.assertEqual(cats.category({"name": "anything.bin"}, "anything.bin", "s"), BIOS)


class Evidence(unittest.TestCase):
    """Each category says what establishes it, so the report documents it."""

    def setUp(self):
        self.cats = EntryCategories(_config(["bluemsx", "devilutionx"], []), PROFILES)

    def test_game_data_names_its_reader_and_reference(self):
        found = self.cats.explain({"name": "diabdat.mpq"}, "ports/diablo/diabdat.mpq", "diablo")
        self.assertEqual(found["category"], GAME_DATA)
        # The platform entry declares no hash: the reader is matched by name.
        self.assertEqual(found["read_by"], [{
            "emulator": "devilutionx", "proof": "name", "runs_system": True,
            "entries": [{"name": "diabdat.mpq", "source_ref": "Source/init.cpp:120",
                         "by": "name"}]}])
        self.assertEqual(verify.category_evidence_text(found),
                         "read by devilutionx (diabdat.mpq at Source/init.cpp:120)")

    def test_unread_names_the_cores_examined(self):
        found = self.cats.explain({"name": "hardwareconfig.xml"},
                                  "bios/Machines/MSX/hardwareconfig.xml", "microsoft-msx")
        self.assertEqual(found, {"category": UNREAD, "cores_examined": ["bluemsx"]})

    def test_the_system_s_own_core_reads_first(self):
        profiles = {**PROFILES, "other": {
            "emulator": "Other", "type": "game", "cores": ["other"], "systems": ["elsewhere"],
            "files": [{"name": "diabdat.mpq", "category": "game_data"}]}}
        cats = EntryCategories(_config(["bluemsx", "devilutionx", "other"], []), profiles)
        found = cats.explain({"name": "diabdat.mpq"}, "ports/diablo/diabdat.mpq", "diablo")
        self.assertEqual([r["emulator"] for r in found["read_by"]], ["devilutionx", "other"])
        self.assertEqual(verify.category_evidence_text(found),
                         "read by devilutionx (diabdat.mpq at Source/init.cpp:120), "
                         "also named by other (diabdat.mpq)")

    def test_a_system_s_own_cores_settle_it(self):
        config = _config(["bluemsx", "devilutionx", "mystery"], [], system="microsoft-msx")
        config["systems"]["microsoft-msx"]["cores"] = ["bluemsx"]
        found = EntryCategories(config, PROFILES).explain(
            {"name": "hardwareconfig.xml"}, "bios/Machines/MSX/hardwareconfig.xml",
            "microsoft-msx")
        self.assertEqual(found, {"category": UNREAD, "cores_examined": ["bluemsx"]})
        self.assertEqual(verify.category_evidence_text(found),
                         "no reader found (cores examined: bluemsx)")

    def test_an_unsettled_entry_says_why(self):
        cats = EntryCategories(_config(["bluemsx", "devilutionx", "mystery"], []), PROFILES)
        found = cats.explain({"name": "hardwareconfig.xml"},
                             "bios/Machines/MSX/hardwareconfig.xml", "microsoft-msx")
        self.assertEqual(found["category"], BIOS)
        self.assertIn("mystery", found["unsettled"])
        self.assertIn("not settled", verify.category_evidence_text(found))


class StrictCountsFirmwareOnly(unittest.TestCase):
    def test_missing_game_data_and_unread_carry_no_severity(self):
        config = _config(["bluemsx", "devilutionx"], [
            {"name": "diabdat.mpq", "destination": "ports/diablo/diabdat.mpq", "required": True},
            {"name": "hardwareconfig.xml",
             "destination": "bios/Machines/MSX/hardwareconfig.xml", "required": True},
            {"name": "MSX.ROM", "destination": "bios/Machines/MSX/MSX.ROM", "required": True},
        ], system="microsoft-msx")
        db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}, "by_crc32": {},
                                       "by_path_suffix": {}}}
        result = verify.verify_platform(config, db, emu_profiles=PROFILES)
        self.assertEqual(result["severity_counts"][verify.Severity.CRITICAL], 1)
        self.assertEqual(result["missing_not_firmware"], {
            "game_data": ["ports/diablo/diabdat.mpq"],
            "unread": ["bios/Machines/MSX/hardwareconfig.xml"],
        })
        self.assertEqual(result["status_counts"][verify.Status.MISSING], 3)
        evidence = {d["name"]: d.get("category_evidence") for d in result["details"]}
        self.assertEqual(evidence["hardwareconfig.xml"]["cores_examined"], ["bluemsx"])
        self.assertEqual(evidence["diabdat.mpq"]["read_by"][0]["emulator"], "devilutionx")


class IndexedProof(unittest.TestCase):
    """ProofIndex answers what ReadEvidence.proof answers, reader by reader."""

    def test_every_kind_matches_the_direct_proof(self):
        md5 = "490f666e1afb15b7362b406ed1cea246"
        readers = []
        for profile in (
            {"files": [{"name": "a.bin", "path": "sys/dir/a.bin"}]},
            {"files": [{"name": "other.rom", "aliases": ["B.ROM"]}]},
            {"files": [{"name": "c.bin", "md5": md5}]},
            {"files": [{"name": "tree/", "type": "directory", "path": "data/tree/"}]},
            {"files": [], "data_directories": [{"ref": "x", "destination": "assets/sys"}]},
            {"files": [{"name": "d.bin", "sha1": "ab" * 20, "crc32": "12345678"}]},
        ):
            evidence = ReadEvidence()
            evidence.add_profile(profile, {})
            readers.append(evidence)
        launcher = ReadEvidence()
        launcher.add_launchers([{"names": ["scph101.bin"]}])
        readers.append(launcher)
        index = ProofIndex(readers)
        cases = [
            ({"name": "a.bin"}, "bios/sys/dir/a.bin"),
            ({"name": "a.bin"}, "elsewhere/a.bin"),
            ({"name": "x", "aliases": ["b.rom"]}, "x"),
            ({"name": "y", "md5": md5[:29]}, "y"),
            ({"name": "y", "md5": md5.upper()}, "y"),
            ({"name": "z", "md5": md5[:28]}, "z"),
            ({"name": "z"}, "root/data/tree/deep/z"),
            ({"name": "z"}, "data/tree"),
            ({"name": "z"}, "a/assets/sys/z.png"),
            ({"name": "scph101.bin"}, "bios/scph101.bin"),
            ({"name": "q", "crc32": "12345678, 9"}, "q"),
            ({"name": "q"}, ""),
        ]
        for entry, destination in cases:
            expected = {
                position: proof for position, evidence in enumerate(readers)
                if (proof := evidence.proof(entry, destination)) is not None
            }
            with self.subTest(entry=entry, destination=destination):
                self.assertEqual(index.proofs(entry, destination), expected)


class AProfileIsIndexedOncePerKind(unittest.TestCase):
    """_matching walked the reader's whole profile for each platform entry:
    2,135 scans of the MAME profile took 2 s of verify --all."""

    FILES = [
        {"name": "zero.bin", "md5": "0" * 32, "source_ref": "a.c:1"},
        {"name": "one.bin", "md5": "1" * 32, "source_ref": "a.c:2"},
        {"name": "one.bin", "md5": "2" * 32, "source_ref": "a.c:3"},
        {"name": "two.bin", "aliases": ["TWO.ROM"], "source_ref": "a.c:4"},
        {"name": "data.pak", "category": "game_data", "source_ref": "a.c:5"},
    ]

    def setUp(self):
        profiles = {"core": {"emulator": "Core", "type": "libretro", "cores": ["core"],
                             "systems": ["s"], "files": self.FILES}}
        self.cats = EntryCategories(_config(["core"], []), profiles)

    def test_the_index_answers_as_the_scan_did(self):
        cases = [
            ({"name": "one.bin", "md5": "2" * 32}, BIOS, [{"name": "one.bin", "source_ref": "a.c:3"}]),
            # A cut md5 (Batocera's 29 characters) matches by prefix.
            ({"name": "x", "md5": "1" * 29}, BIOS, [{"name": "one.bin", "source_ref": "a.c:2"}]),
            ({"name": "one.bin"}, BIOS, [
                {"name": "one.bin", "source_ref": "a.c:2", "by": "name"},
                {"name": "one.bin", "source_ref": "a.c:3", "by": "name"},
            ]),
            ({"name": "one.bin", "md5": "9" * 32}, BIOS, []),
            ({"name": "two.rom"}, BIOS, [{"name": "two.bin", "source_ref": "a.c:4", "by": "name"}]),
            ({"name": "data.pak"}, BIOS, []),
            ({"name": "data.pak"}, GAME_DATA, [{"name": "data.pak", "source_ref": "a.c:5", "by": "name"}]),
        ]
        for entry, kind, expected in cases:
            with self.subTest(entry=entry, kind=kind):
                self.assertEqual(self.cats._matching("core", kind, entry), expected)

    def test_the_profile_is_walked_once_per_kind(self):
        from unittest import mock

        with mock.patch.object(self.cats, "_accepted_by", wraps=self.cats._accepted_by) as hashed:
            for _ in range(50):
                self.cats._matching("core", BIOS, {"name": "zero.bin", "md5": "0" * 32})
        self.assertEqual(hashed.call_count, 4)


if __name__ == "__main__":
    unittest.main()
