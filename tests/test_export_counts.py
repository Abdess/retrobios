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
from exporter.bizhawk_exporter import Exporter as BizHawk  # noqa: E402
from exporter.misterfpga_exporter import Exporter as Mister  # noqa: E402
from exporter.romm_exporter import Exporter as Romm  # noqa: E402
from scraper.emudeck_scraper import FUNCTION_HASH_MAP  # noqa: E402
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

    def test_an_addition_at_another_path_is_written(self):
        """melonDS: RetroDECK declares firmware.bin at the root; the truth adds
        SkyEmu/firmware.bin. Keyed by name and system, the addition vanished
        and the report still counted it."""
        existing = [{"filename": "firmware.bin", "system": "nds", "md5": A}]
        addition = OrderedDict(filename="firmware.bin", system="nds", md5=B,
                               paths="$bios_path/SkyEmu")
        merged = RetroDeck._merge(existing, [], [addition])
        self.assertEqual(
            [(e["md5"], e.get("paths")) for e in merged],
            [(A, None), (B, "$bios_path/SkyEmu")],
        )

    def test_an_addition_never_corrects_a_platform_entry(self):
        existing = [{"filename": "firmware.bin", "system": "nds", "md5": A}]
        addition = OrderedDict(filename="firmware.bin", system="nds", md5=B,
                               paths="$bios_path/SkyEmu")
        merged = RetroDeck._merge(existing, [], [addition, addition])
        self.assertEqual(merged[0]["md5"], A)
        self.assertEqual(len(merged), 2)

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


class EmuDeckWritesItsCorrections(unittest.TestCase):
    """A correction replaced nothing: every withdrawal was refused, the run
    counted the correction anyway and validate failed on it."""

    SCRIPT = "checkPS1BIOS(){\n  local hashes=(%s)\n}\n"

    def _systems(self, corrected: NativeFile, other: NativeFile) -> dict:
        system_id = FUNCTION_HASH_MAP["checkPS1BIOS"]
        corrected.native_system = other.native_system = system_id
        return {system_id: NativeSystem(system_id, files=[corrected, other])}

    def test_a_correction_replaces_its_value(self):
        corrected = NativeFile("scph5501.bin", "scph5501.bin", "psx",
                               platform={"md5": A}, truth={"md5": B}, corrections=["md5"])
        other = NativeFile("scph1001.bin", "scph1001.bin", "psx", platform={"md5": C})
        systems = self._systems(corrected, other)
        exporter = EmuDeck()
        produced = exporter.render(systems, None, {"checkBIOS.sh": self.SCRIPT % f"{A} {C}"})
        text = produced["checkBIOS.sh"]
        self.assertIn(B, text)
        self.assertNotIn(A, text)
        self.assertTrue(exporter.states(corrected, "md5"))
        self.assertEqual(
            [i for i in exporter.validate(systems, produced) if "checkPS1BIOS" in i], []
        )

    def test_a_withdrawal_is_refused_and_not_counted(self):
        corrected = NativeFile("scph5501.bin", "scph5501.bin", "psx",
                               platform={"md5": A}, truth={"md5": B}, corrections=["md5"])
        other = NativeFile("scph1001.bin", "scph1001.bin", "psx", platform={"md5": C})
        systems = self._systems(corrected, other)
        exporter = EmuDeck()
        d = "d" * 32
        produced = exporter.render(systems, None, {"checkBIOS.sh": self.SCRIPT % f"{A} {C} {d}"})
        self.assertIn(d, produced["checkBIOS.sh"])
        self.assertFalse(exporter.states(corrected, "md5"))
        self.assertEqual(
            [i for i in exporter.validate(systems, produced) if "checkPS1BIOS" in i], []
        )


class BizHawkCountsWhatItWrites(unittest.TestCase):
    def test_an_ambiguous_name_is_not_counted(self):
        sha_a, sha_b, sha_c = "a" * 40, "b" * 40, "c" * 40
        first = NativeFile("bios.bin", "bios.bin", "S1", platform={"sha1": sha_a},
                           truth={"sha1": sha_b}, corrections=["sha1"])
        second = NativeFile("bios.bin", "bios.bin", "S2", platform={"sha1": sha_c})
        systems = {"S1": NativeSystem("S1", files=[first]), "S2": NativeSystem("S2", files=[second])}
        exporter = BizHawk()
        source = f'File("{sha_a.upper()}", 16, "bios.bin")\n'
        exporter.render(systems, None, {exporter.native_filename(): source})
        self.assertFalse(exporter.states(first, "sha1"))


class MisterCountsWhatItWrites(unittest.TestCase):
    def test_a_path_the_database_lacks_is_not_counted(self):
        held = NativeFile("boot.rom", "NES/boot.rom", "nes", platform={"md5": A},
                          truth={"md5": B}, corrections=["md5"])
        absent = NativeFile("boot.rom", "SNES/boot.rom", "snes", platform={"md5": A},
                            truth={"md5": C}, corrections=["md5"])
        systems = {"nes": NativeSystem("nes", files=[held]), "snes": NativeSystem("snes", files=[absent])}
        database = {"db_id": "x", "files": {"games/NES/boot.rom": {"hash": A, "url": "u"}}}
        exporter = Mister()
        exporter.render(systems, None, {"bios_db.json": json.dumps(database)})
        self.assertTrue(exporter.states(held, "md5"))
        self.assertFalse(exporter.states(absent, "md5"))


class OneMd5FormatsAddWhole(unittest.TestCase):
    def test_an_addition_with_several_md5_is_refused(self):
        from exporter.batocera_exporter import Exporter as Batocera  # noqa: PLC0415

        several = NativeFile("boot.bin", "boot.bin", "dc", truth={"md5": [A, B, C]})
        single = NativeFile("boot2.bin", "boot2.bin", "dc", truth={"md5": A})
        self.assertFalse(Batocera.writable(several))
        self.assertTrue(Batocera.writable(single))


class BizHawkKeepsItsOwnHashes(unittest.TestCase):
    def test_a_declared_sha1_is_not_replaced(self):
        """FBNeo's MSX.rom replaced the SHA1 MSXHawk accepts in BizHawk's code."""
        sha_bizhawk, sha_fbneo = "4" * 40, "e" * 40
        fe = NativeFile("MSX.rom", "MSX.rom", "MSX", platform={"sha1": sha_bizhawk},
                        truth={"sha1": sha_fbneo}, corrections=["sha1"])
        exporter = BizHawk()
        source = f'FirmwareAndOption("{sha_bizhawk.upper()}", 32768, "MSX", "b", "MSX.rom", "d");\n'
        produced = exporter.render({"MSX": NativeSystem("MSX", files=[fe])}, None,
                                   {exporter.native_filename(): source})
        self.assertIn(sha_bizhawk.upper(), produced[exporter.native_filename()])
        self.assertFalse(exporter.states(fe, "sha1"))


class SystemDatKeepsItsQuoting(unittest.TestCase):
    def test_a_name_the_original_quotes_stays_quoted(self):
        from exporter.systemdat_exporter import _quote  # noqa: PLC0415

        quoted = frozenset({"dolphin-emu/Sys/GC/USA/IPL.bin"})
        self.assertEqual(_quote("dolphin-emu/Sys/GC/USA/IPL.bin", quoted),
                         '"dolphin-emu/Sys/GC/USA/IPL.bin"')
        self.assertEqual(_quote("bk/B11M_BOS.ROM", quoted), "bk/B11M_BOS.ROM")
        self.assertEqual(_quote("a b.bin"), '"a b.bin"')


class ModelKeepsOneFileOneEntry(unittest.TestCase):
    def test_a_list_of_sizes_is_not_one_size(self):
        """A profile may accept several revisions; int() on the list crashed."""
        several = NativeFile("a.bin", "a.bin", "s", truth={"size": [1024, 2048], "crc32": "aaaaaaaa"})
        single = NativeFile("b.bin", "b.bin", "s", truth={"size": [1024], "crc32": "aaaaaaaa"})
        self.assertIsNone(several.size())
        self.assertEqual(single.size(), 1024)

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

class RommKeepsItsOwnKeys(unittest.TestCase):
    def test_a_same_named_addition_does_not_replace_their_entry(self):
        """fbneo's 480-byte boot.bin overwrote RomM's Dreamcast boot.bin."""
        theirs = NativeFile("boot.bin", "dc/boot.bin", "dc",
                            platform={"size": 2097152, "md5": A})
        ours = NativeFile("boot.bin", "fbneo/boot.bin", "dc",
                          truth={"size": 480, "crc32": "f0774fc2"})
        exporter = Romm()
        produced = exporter.render({"dc": NativeSystem("dc", files=[theirs, ours])}, None, {})
        written = json.loads(produced[exporter.native_filename()])
        self.assertEqual(written["dc:boot.bin"]["size"], "2097152")
        self.assertFalse(exporter.writable(ours))

class NamesInAnotherDirectory(unittest.TestCase):
    def test_a_truth_path_in_another_directory_does_not_match(self):
        scraped = {"systems": {"pc98": {"files": [
            {"name": "bios.rom", "destination": "np2kai/bios.rom", "md5": A},
        ]}}}
        truth = {"systems": {"pc98": {"files": [
            {"name": "bios.rom", "path": "BeebFile/BIOS.rom", "md5": B},
        ]}}}
        systems, _report = build_native_model(truth, scraped)
        declared = next(f for f in systems["pc98"].files if f.platform is not None)
        self.assertIsNone(declared.truth)

    def test_a_destination_ending_in_the_path_matches(self):
        scraped = {"systems": {"gc": {"files": [
            {"name": "IPL.bin", "destination": "dolphin-emu/Sys/GC/USA/IPL.bin", "md5": A},
            {"name": "IPL.bin", "destination": "dolphin-emu/Sys/GC/EUR/IPL.bin", "md5": B},
        ]}}}
        truth = {"systems": {"gc": {"files": [
            {"name": "IPL.bin", "path": "GC/EUR/IPL.bin", "md5": B},
            {"name": "IPL.bin", "path": "GC/USA/IPL.bin", "md5": A},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        self.assertEqual(report.hashes_corrected, [])


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


class BizHawkRewritesOnlyWhatItDeclares(unittest.TestCase):
    def test_a_truth_only_homonym_does_not_rewrite_a_declared_call(self):
        """opera's panafz10-norsa.bin, absent from BizHawk's list, would have
        rewritten the 3DO call of the same name by index on the name alone."""
        sha_bizhawk, sha_other = "4" * 40, "e" * 40
        declared = NativeFile("bios.bin", "bios.bin", "SYSB", platform={"sha1": sha_bizhawk})
        truth_only = NativeFile("bios.bin", "bios.bin", "sys-a", truth={"sha1": sha_other})
        exporter = BizHawk()
        source = f'File("{sha_bizhawk.upper()}", 10, "bios.bin")\n'
        produced = exporter.render(
            {"SYSB": NativeSystem("SYSB", files=[declared]),
             "sys-a": NativeSystem("sys-a", files=[truth_only])},
            None, {exporter.native_filename(): source},
        )
        self.assertIn(sha_bizhawk.upper(), produced[exporter.native_filename()])
        self.assertNotIn(sha_other.upper(), produced[exporter.native_filename()])


class RetroDeckCorrectsOnlyWhatItCarries(unittest.TestCase):
    def test_paths_and_description_stay_the_maintainers(self):
        """neogeo.zip lost its four search directories to a path that does
        not exist, and 26 descriptions were rewritten."""
        from collections import OrderedDict  # noqa: PLC0415

        existing = [{"filename": "neogeo.zip", "system": "neogeo", "md5": A,
                     "paths": ["$roms_path/neogeo", "$roms_path/fbneo", "$bios_path"],
                     "description": "Neo Geo BIOS"}]
        ours = [OrderedDict([("filename", "neogeo.zip"), ("md5", B), ("system", "neogeo"),
                             ("description", "generated"), ("paths", "$bios_path/roms/neogeo")])]
        merged = RetroDeck._merge(existing, ours)
        self.assertEqual(merged[0]["md5"], B)
        self.assertEqual(merged[0]["paths"], ["$roms_path/neogeo", "$roms_path/fbneo", "$bios_path"])
        self.assertEqual(merged[0]["description"], "Neo Geo BIOS")

    def test_a_hash_no_revision_shares_is_appended(self):
        """IPL.n64 declared twice, both contradicted: counted corrected,
        written nowhere."""
        from collections import OrderedDict  # noqa: PLC0415

        existing = [{"filename": "IPL.n64", "system": "n64dd", "md5": A},
                    {"filename": "IPL.n64", "system": "n64dd", "md5": B}]
        ours = [OrderedDict([("filename", "IPL.n64"), ("md5", C), ("system", "n64dd")])]
        merged = RetroDeck._merge(existing, ours)
        self.assertEqual([e["md5"] for e in merged], [A, B, C])


class BatoceraKeepsTheRunnerKeys(unittest.TestCase):
    def test_emulator_and_core_travel_with_a_rewritten_entry(self):
        """checkBios skips a BIOS whose emulator or core is not installed;
        rewritten without the keys, vectrex's MAME BIOS was wanted by every
        build."""
        from exporter.batocera_exporter import Exporter as Batocera  # noqa: PLC0415

        fe = NativeFile("bios.bin", "bios.bin", "vectrex", platform={"md5": A},
                        truth={"md5": B}, corrections=["md5"])
        fe.native_data = {"native_path": "bios/bios.bin"}
        system = NativeSystem("vectrex", files=[fe])
        original = (
            '    "vectrex": { "name": "Vectrex", "emulator": "libretro", "core": "mame", '
            '"biosFiles": [ { "md5": "' + A + '", "file": "bios/bios.bin", '
            '"emulator": "libretro", "core": "mame" } ] },'
        )
        exporter = Batocera()
        line = exporter._entry_line(system, [fe], exporter._parse_entry([original]))
        parsed = exporter._parse_entry([line])["vectrex"]
        self.assertEqual((parsed["emulator"], parsed["core"]), ("libretro", "mame"))
        self.assertEqual(parsed["biosFiles"][0]["core"], "mame")
        self.assertEqual(parsed["biosFiles"][0]["md5"], B)


if __name__ == "__main__":
    unittest.main()
