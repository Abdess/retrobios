"""An export writes what its summary announces, and nothing else.

RetroDECK announced 1474 additions and wrote none, counted 161 requirement
corrections while keeping the platform's prose labels, and wrote one
system's ATARIOSB.ROM over another's. RetroBat and EmuDeck turned empty or
partial hash lists into content checks nobody counted, and a size was taken
from a file other than the one the hash describes.
"""

from __future__ import annotations

import json
import sys
import unittest
from collections import OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from exporter.baseline import NativeFile, NativeSystem, build_native_model  # noqa: E402
from exporter.emudeck_exporter import Exporter as EmuDeck  # noqa: E402
from exporter.retrobat_exporter import Exporter as RetroBat  # noqa: E402
from exporter.retrodeck_exporter import Exporter as RetroDeck  # noqa: E402
from exporter.recalbox_exporter import Exporter as Recalbox  # noqa: E402
from exporter.retropie_exporter import Exporter as RetroPie  # noqa: E402

A = "a" * 32
B = "b" * 32
C = "c" * 32


class RetroDeckWritesWhatItCounts(unittest.TestCase):
    def test_same_name_in_two_systems_stays_two_entries(self):
        existing = [
            {"filename": "ATARIOSB.ROM", "system": "atari5200", "md5": f"{A},{B}"},
            {"filename": "ATARIOSB.ROM", "system": "atari800", "md5": B},
        ]
        ours = [
            OrderedDict(filename="ATARIOSB.ROM", system="atari800", md5=C),
        ]
        merged = RetroDeck._merge(existing, ours)
        by_system = {e["system"]: e["md5"] for e in merged}
        self.assertEqual(by_system, {"atari5200": f"{A},{B}", "atari800": C})
        self.assertEqual(len(merged), 2)

    def test_revisions_under_one_name_keep_their_own_hash(self):
        existing = [
            {"filename": "64DD_IPL.bin", "system": "n64dd", "md5": A},
            {"filename": "64DD_IPL.bin", "system": "n64dd", "md5": B},
        ]
        ours = [OrderedDict(filename="64DD_IPL.bin", system="n64dd", md5=f"{A},{C}")]
        merged = RetroDeck._merge(existing, ours)
        self.assertEqual([e["md5"] for e in merged], [f"{A},{C}", B])

    def test_a_list_of_systems_is_kept(self):
        existing = [{"filename": "neogeo.zip", "system": ["neogeo", "fbneo"], "md5": A}]
        ours = [OrderedDict(filename="neogeo.zip", system="fbneo", md5=B)]
        merged = RetroDeck._merge(existing, ours)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["system"], ["neogeo", "fbneo"])
        self.assertEqual(merged[0]["md5"], B)

    def test_prose_label_is_neither_rewritten_nor_counted(self):
        exporter = RetroDeck()
        prose = NativeFile(
            "x.bin", "bios/x.bin", "psx",
            platform={"required": True, "required_label": "At least one BIOS file required"},
            truth={"required": False},
        )
        plain = NativeFile(
            "y.bin", "bios/y.bin", "psx",
            platform={"required": True, "required_label": "Required"},
            truth={"required": False},
        )
        self.assertFalse(exporter.states(prose, "required"))
        self.assertEqual(RetroDeck._entry(prose)["required"], "At least one BIOS file required")
        self.assertTrue(exporter.states(plain, "required"))
        self.assertEqual(RetroDeck._entry(plain)["required"], "Optional")

    def test_addition_goes_to_the_system_component(self):
        declared = NativeFile("a.bin", "bios/a.bin", "psx",
                              platform={"component": "duckstation", "md5": A})
        added = NativeFile("b.bin", "bios/b.bin", "psx", truth={"md5": B})
        spread = NativeSystem("amiga", files=[
            NativeFile("k1", "bios/k1", "amiga", platform={"component": "retroarch"}),
            NativeFile("k2", "bios/k2", "amiga", platform={"component": "puae"}),
            NativeFile("k3", "bios/k3", "amiga", truth={"md5": C}),
        ])
        systems = {"psx": NativeSystem("psx", files=[declared, added]), "amiga": spread}
        manifest = json.dumps({"duckstation": {"name": "DuckStation", "bios": []}})
        produced = RetroDeck().render(
            systems, None, {"duckstation/component_manifest.json": manifest}
        )
        written = json.loads(produced["duckstation/component_manifest.json"])
        names = [e["filename"] for e in written["duckstation"]["bios"]]
        self.assertIn("b.bin", names)
        self.assertFalse(RetroDeck.writable(spread.files[2]))


class HashesTheFormatCannotHold(unittest.TestCase):
    def test_retrobat_fills_only_a_single_accepted_value(self):
        exporter = RetroBat()
        single = NativeFile("s.bin", "s.bin", "nds", platform={"md5": ""},
                            truth={"md5": A}, filled=["md5"])
        several = NativeFile("m.bin", "m.bin", "nds", platform={"md5": ""},
                             truth={"md5": [A, B]}, filled=["md5"])
        self.assertEqual(RetroBat._md5(single), A)
        self.assertTrue(exporter.states(single, "md5"))
        self.assertEqual(RetroBat._md5(several), "")
        self.assertFalse(exporter.states(several, "md5"))

    def test_emudeck_never_grows_an_array(self):
        unhashed = NativeFile("scph5501.bin", "scph5501.bin", "psx",
                              platform={"md5": ""}, truth={"md5": C}, filled=["md5"])
        extra = NativeFile("scph1001.bin", "scph1001.bin", "psx",
                           platform={"md5": A}, truth={"md5": [A, B]})
        corrected = NativeFile("scph7001.bin", "scph7001.bin", "psx",
                               platform={"md5": B}, truth={"md5": C},
                               corrections=["md5"])
        systems = {"psx": NativeSystem("psx", files=[unhashed, extra, corrected])}
        self.assertEqual(EmuDeck._md5s(systems, "psx"), [A, C])
        self.assertFalse(EmuDeck().states(unhashed, "md5"))


class ModelKeepsOneFileOneEntry(unittest.TestCase):
    def test_size_describes_the_hash_written(self):
        fe = NativeFile("boot.bin", "dc/boot.bin", "dc",
                        platform={"size": 2097152, "md5": A}, truth={"size": 480})
        self.assertEqual(fe.size(), 2097152)
        hashed = NativeFile("boot.bin", "dc/boot.bin", "dc",
                            platform={"size": 2097152, "md5": A},
                            truth={"size": 480, "md5": B})
        self.assertEqual(hashed.size(), 480)

    def test_second_core_entry_for_a_declared_file_adds_nothing(self):
        scraped = {"systems": {"psx": {"files": [
            {"name": "scph101.bin", "destination": "bios/scph101.bin", "md5": A},
        ]}}}
        truth = {"systems": {"psx": {"files": [
            {"name": "scph101.bin", "path": "scph101.bin", "md5": A},
            {"name": "scph101.bin", "path": "scph101.bin", "md5": B},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        self.assertEqual(report.files_added, 0)
        self.assertEqual(len(systems["psx"].files), 1)


class OneFileOneIdentity(unittest.TestCase):
    def test_a_contradicting_truth_does_not_borrow_platform_fields(self):
        fe = NativeFile("boot.bin", "dc/boot.bin", "dc",
                        platform={"size": 2097152, "md5": A, "sha1": "1" * 40, "crc32": "aaaaaaaa"},
                        truth={"size": 480, "crc32": "bbbbbbbb"})
        self.assertEqual(fe.hashes("sha1"), [])
        self.assertEqual(fe.hashes("crc32"), ["bbbbbbbb"])
        self.assertEqual(fe.size(), 480)

    def test_different_fields_are_not_a_contradiction(self):
        """bios7.bin: the truth's crc32 beside Batocera's md5 is one dump."""
        fe = NativeFile("bios7.bin", "bios/bios7.bin", "nds",
                        platform={"md5": A}, truth={"crc32": "1280f0d5"})
        self.assertEqual(fe.hashes("md5"), [A])
        self.assertEqual(fe.hashes("crc32"), ["1280f0d5"])

    def test_different_sizes_still_contradict(self):
        fe = NativeFile("boot.bin", "dc/boot.bin", "dc",
                        platform={"size": 2097152, "md5": A}, truth={"size": 480, "crc32": "bbbbbbbb"})
        self.assertEqual(fe.hashes("md5"), [])

    def test_agreeing_sides_still_merge(self):
        fe = NativeFile("x.bin", "x.bin", "s",
                        platform={"md5": A, "sha1": "1" * 40}, truth={"md5": A})
        self.assertEqual(fe.hashes("sha1"), ["1" * 40])

    def test_a_name_with_another_size_is_another_file(self):
        scraped = {"systems": {"dc": {"files": [
            {"name": "boot.bin", "destination": "dc/boot.bin", "size": 2097152, "md5": A},
        ]}}}
        truth = {"systems": {"dc": {"files": [
            {"name": "boot.bin", "path": "fbneo/boot.bin", "size": 480, "crc32": "bbbbbbbb"},
        ]}}}
        systems, _report = build_native_model(truth, scraped)
        declared = next(f for f in systems["dc"].files if f.platform is not None)
        self.assertIsNone(declared.truth)

class RecalboxKeepsItsOwnNotes(unittest.TestCase):
    def test_no_profile_prose_reaches_a_note(self):
        fe = NativeFile("bios.bin", "bios.bin", "psx", platform={"md5": A},
                        truth={"md5": A, "note": "Loaded at libretro.c:120"})
        self.assertNotIn("note=", Recalbox()._bios_element(fe, "psx"))

class RetroPieProposals(unittest.TestCase):
    def test_required_is_read_for_the_package_core(self):
        fe = NativeFile("scph5501.bin", "scph5501.bin", "psx",
                        truth={"required": True, "_required_by": ["beetle_psx"],
                               "_cores": ["beetle_psx", "pcsx_rearmed"]})
        self.assertTrue(RetroPie._required_for(fe, "beetle_psx"))
        self.assertFalse(RetroPie._required_for(fe, "pcsx_rearmed"))

    def test_a_list_of_alternatives_is_not_extended(self):
        alternatives = "Copy the required BIOS file a.rom or b.rom to $biosdir"
        enumeration = "Copy the required BIOS files a.rom and b.rom to $biosdir"
        self.assertIsNone(RetroPie._insertion_point(alternatives))
        self.assertIsNotNone(RetroPie._insertion_point(enumeration))

if __name__ == "__main__":
    unittest.main()
