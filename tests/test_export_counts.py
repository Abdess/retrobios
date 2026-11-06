"""An export writes what its summary announces, and nothing else.

RetroDECK announced 1474 additions and wrote none, counted 161 requirement
corrections while keeping the platform's prose labels, and wrote one
system's ATARIOSB.ROM over another's. RetroBat and EmuDeck turned empty or
partial hash lists into content checks nobody counted, and a size was taken
from a file other than the one the hash describes.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import sys
import unittest
from collections import OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from exporter.baseline import NativeFile, NativeSystem, Report, build_native_model  # noqa: E402
from exporter.bizhawk_exporter import Exporter as BizHawk  # noqa: E402
from exporter.misterfpga_exporter import Exporter as Mister  # noqa: E402
from exporter.romm_exporter import Exporter as Romm  # noqa: E402
from scraper.emudeck_scraper import FUNCTION_HASH_MAP  # noqa: E402
from exporter.emudeck_exporter import Exporter as EmuDeck  # noqa: E402
from exporter.retrobat_exporter import Exporter as RetroBat  # noqa: E402
from exporter.retrodeck_exporter import Exporter as RetroDeck  # noqa: E402
from exporter.recalbox_exporter import Exporter as Recalbox  # noqa: E402
from exporter.retropie_exporter import Exporter as RetroPie  # noqa: E402
from exporter.systemdat_exporter import Exporter as SystemDat  # noqa: E402

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

    def test_an_appended_revision_is_not_counted_corrected(self):
        # 64DD_IPL.bin declared twice (A, B), truth C: the render keeps both
        # and appends C, and the summary said "1 hashes corrected".
        from export_native import landed_changes  # noqa: PLC0415

        appended: set = set()
        merged = RetroDeck._merge(
            [{"filename": "64DD_IPL.bin", "system": "n64dd", "md5": A},
             {"filename": "64DD_IPL.bin", "system": "n64dd", "md5": B}],
            [OrderedDict(filename="64DD_IPL.bin", system="n64dd", md5=C)],
            None, appended,
        )
        self.assertEqual([e["md5"] for e in merged], [A, B, C])
        self.assertEqual(appended, {("64DD_IPL.bin", "n64dd")})
        fe = NativeFile("64DD_IPL.bin", "64DD_IPL.bin", "n64dd",
                        platform={"md5": A}, truth={"md5": C}, corrections=["md5"])
        exporter = RetroDeck()
        exporter._appended = {id(fe)}
        changes = landed_changes(exporter, {"n64dd": NativeSystem("n64dd", files=[fe])})
        self.assertEqual(changes.applied, [])

    def test_an_addition_at_another_path_is_written(self):
        """melonDS: RetroDECK declares firmware.bin at the root and the truth adds
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
        added = NativeFile("b.bin", "bios/b.bin", "psx", truth={"md5": B},
                           runners=[(True, "duckstation")])
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
        self.assertEqual(RetroBat.single_value(single, "md5"), A)
        self.assertTrue(exporter.states(single, "md5"))
        self.assertEqual(RetroBat.single_value(several, "md5"), "")
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


class RetroBatKeepsWhatWeDoNotModel(unittest.TestCase):
    """RetroBat renamed chihiro/ic10_g24lc64 to ic10_g24lc64.bin after our
    scrape. The export was rebuilt from our model and read the original only
    for its key order, so the renamed entry vanished from RetroBat's file,
    and a system we do not carry would have vanished whole."""

    def test_an_unmodelled_file_and_system_stay_as_written(self):
        modelled = NativeFile(
            "ic11_24lc024.bin", "chihiro/ic11_24lc024.bin", "chihiro",
            platform={"md5": "", "native_path": "bios/chihiro/ic11_24lc024.bin"},
            truth={"md5": A}, filled=["md5"],
        )
        systems = {"chihiro": NativeSystem("chihiro", files=[modelled])}
        original = {
            "chihiro": {"name": "Sega Chihiro", "biosFiles": [
                {"md5": "", "file": "bios/chihiro/ic10_g24lc64.bin"},
                {"md5": "", "file": "bios/chihiro/ic11_24lc024.bin"},
            ]},
            "newsys": {"name": "New", "biosFiles": [{"md5": B, "file": "bios/new.bin"}]},
        }
        from exporter.baseline import Report

        produced = json.loads(RetroBat().render(
            systems, Report(), {"batocera-systems.json": json.dumps(original)},
        )["batocera-systems.json"])
        self.assertEqual(list(produced), ["chihiro", "newsys"])
        self.assertEqual(produced["newsys"], original["newsys"])
        self.assertEqual(produced["chihiro"]["biosFiles"], [
            {"md5": "", "file": "bios/chihiro/ic10_g24lc64.bin"},
            {"md5": A, "file": "bios/chihiro/ic11_24lc024.bin"},
        ])


class RetroBatCountsOneAdditionPerPath(unittest.TestCase):
    """Two cores each gave the truth a psx/scph5501.bin at one destination.
    The render writes one biosFiles item per path, yet both were counted
    added: 78 additions announced for 75 items written."""

    def test_an_addition_at_a_held_path_does_not_land(self):
        from export_native import landed_changes  # noqa: PLC0415

        theirs = NativeFile("scph1001.bin", "scph1001.bin", "psx",
                            platform={"md5": A}, truth={"md5": A})
        first = NativeFile("scph5501.bin", "scph5501.bin", "psx", truth={"md5": B})
        second = NativeFile("scph5501.bin", "scph5501.bin", "psx", truth={"md5": B})
        over = NativeFile("scph1001.bin", "scph1001.bin", "psx", truth={"md5": C})
        systems = {"psx": NativeSystem("psx", files=[first, theirs, second, over])}
        original = {"psx": {"name": "Sony Playstation", "biosFiles": [
            {"md5": A, "file": "bios/scph1001.bin"},
        ]}}
        exporter = RetroBat()
        produced = json.loads(exporter.render(
            systems, Report(), {"batocera-systems.json": json.dumps(original)},
        )["batocera-systems.json"])
        self.assertEqual(produced["psx"]["biosFiles"], [
            {"md5": A, "file": "bios/scph1001.bin"},
            {"md5": B, "file": "bios/scph5501.bin"},
        ])
        added = [r for r in landed_changes(exporter, systems).records
                 if r["kind"] == "added"]
        self.assertEqual([r["name"] for r in added], ["scph5501.bin"])
        self.assertEqual(
            [exporter.lands(fe) for fe in (first, theirs, second, over)],
            [True, True, False, False],
        )


class PureDataExportsKeepWhatWeDoNotModel(unittest.TestCase):
    """Recalbox's es_bios.xml and libretro's System.dat were rebuilt from our
    model too: an entry the platform added or renamed after our scrape left
    the platform's own file."""

    @staticmethod
    def _file(name, system, **platform):
        return NativeFile(name, name, system, platform={"md5": A, **platform},
                          truth={"md5": A, "crc32": "1234abcd", "sha1": "f" * 40,
                                 "size": 4},
                          filled=[])

    def test_recalbox(self):
        from exporter.baseline import Report
        from exporter.recalbox_exporter import Exporter as Recalbox

        fe = self._file("a.bin", "nes", destination="nes/a.bin", core="libretro:fceumm")
        systems = {"nes": NativeSystem("nes", files=[fe])}
        original = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<biosList>\n'
            '  <system fullname="NES" platform="nes">\n'
            f'    <bios path="nes/new.bin" md5="{B}" core="libretro:fceumm" />\n'
            f'    <bios path="nes/a.bin" md5="{C}" core="libretro:fceumm" />\n'
            '  </system>\n'
            '  <system fullname="New" platform="newsys">\n'
            f'    <bios path="n.bin" md5="{B}" core="libretro:x" mandatory="false" />\n'
            '  </system>\n</biosList>\n'
        )
        produced = Recalbox().render(systems, Report(), {"es_bios.xml": original})["es_bios.xml"]
        from xml.etree import ElementTree

        root = ElementTree.fromstring(produced)
        found = [(s.get("platform"), b.get("path"), b.get("md5"))
                 for s in root.iter("system") for b in s.iter("bios")]
        self.assertEqual(found, [("nes", "nes/new.bin", B), ("nes", "nes/a.bin", A),
                                 ("newsys", "n.bin", B)])
        self.assertIn('mandatory="false"', produced)

    def test_system_dat(self):
        from exporter.baseline import Report

        fe = self._file("a.bin", "Nintendo - NES")
        systems = {"Nintendo - NES": NativeSystem("Nintendo - NES", files=[fe])}
        original = "\n".join([
            "clrmamepro (", '\tname "System"', ")", "", "game (", '\tname "System"',
            '\tcomment "System"', "",
            '\tcomment "Nintendo - NES"',
            "\trom ( name new.bin size 2 crc 00000000 )",
            "\trom ( name a.bin size 4 crc DEADBEEF )", "",
            '\tcomment "New - System"',
            "\trom ( name n.bin size 1 crc 11111111 )", ")", "",
        ])
        produced = SystemDat().render(systems, Report(), {"System.dat": original})["System.dat"]
        roms = [line for line in produced.splitlines() if line.startswith("\trom")]
        self.assertEqual(roms[0], "\trom ( name new.bin size 2 crc 00000000 )")
        self.assertIn("name a.bin size 4 crc 1234ABCD", roms[1])
        self.assertEqual(roms[2], "\trom ( name n.bin size 1 crc 11111111 )")
        self.assertIn('\tcomment "New - System"', produced)


    def test_two_additions_differing_by_directory_are_two_lines(self):
        """PCSX2's vulkan and opengl convert.glsl were both written under the
        bare name, so the second was dropped and still counted as added."""
        from exporter.baseline import Report

        shaders = [
            NativeFile("convert.glsl", f"pcsx2/resources/shaders/{api}/convert.glsl",
                       "Sony - PlayStation 2", truth={"md5": digest * 32})
            for api, digest in (("vulkan", "a"), ("opengl", "b"))
        ]
        systems = {"Sony - PlayStation 2": NativeSystem("Sony - PlayStation 2", files=shaders)}
        original = ('clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n'
                    '\tcomment "Sony - PlayStation 2"\n)\n')
        produced = SystemDat().render(systems, Report(), {"System.dat": original})["System.dat"]
        self.assertIn("name pcsx2/resources/shaders/vulkan/convert.glsl md5 " + "a" * 32, produced)
        self.assertIn("name pcsx2/resources/shaders/opengl/convert.glsl md5 " + "b" * 32, produced)
        self.assertEqual(SystemDat().validate(systems, {"System.dat": produced}), [])

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
        # Refused and named: the run said only "0 hashes corrected", which
        # reads the same as nothing to correct.
        withheld = exporter.withheld()
        self.assertEqual(len(withheld), 1)
        self.assertIn("checkPS1BIOS", withheld[0])
        self.assertIn(d, withheld[0])

    def test_the_summary_reads_the_hook(self):
        source = (Path(__file__).resolve().parents[1] / "scripts" / "export_native.py").read_text()
        self.assertIn("withheld = exporter.withheld()", source)


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

    def test_a_truth_without_md5_leaves_the_record_whole(self):
        # The truth took the entry on a size contradiction and has no md5:
        # the render kept MiSTer's hash, wrote the new size, and the summary
        # announced the hash cleared.
        from export_native import landed_changes  # noqa: PLC0415

        fe = NativeFile("boot.rom", "NES/boot.rom", "nes",
                        platform={"md5": A, "size": 100},
                        truth={"sha1": "f" * 40, "size": 200})
        systems = {"nes": NativeSystem("nes", files=[fe])}
        database = {"db_id": "x", "files": {
            "games/NES/boot.rom": {"hash": A, "size": 100, "url": "u"}}}
        exporter = Mister()
        produced = exporter.render(systems, None, {"bios_db.json": json.dumps(database)})
        written = json.loads(produced["bios_db.json"])["files"]["games/NES/boot.rom"]
        self.assertEqual((written["hash"], written["size"]), (A, 100))
        changes = landed_changes(exporter, systems)
        self.assertEqual((changes.cleared, changes.resized), ([], []))


class OneMd5FormatsAddWhole(unittest.TestCase):
    def test_an_addition_with_several_md5_is_refused(self):
        from exporter.batocera_exporter import Exporter as Batocera  # noqa: PLC0415

        several = NativeFile("boot.bin", "boot.bin", "dc", truth={"md5": [A, B, C]},
                           runners=[(False, "flycast")])
        single = NativeFile("boot2.bin", "boot2.bin", "dc", truth={"md5": A},
                          runners=[(False, "flycast")])
        # A checker that compares one md5, as every cached pin does.
        self.assertFalse(Batocera().writable(several))
        self.assertTrue(Batocera().writable(single))

    def test_retrobat_refuses_it_too(self):
        # RetroBat's batocera-systems.json holds one md5 per entry: the
        # addition was written with the first and counted added.
        from exporter.retrobat_exporter import Exporter as RetroBat  # noqa: PLC0415

        several = NativeFile("boot.bin", "boot.bin", "dc", truth={"md5": [A, B, C]})
        single = NativeFile("boot2.bin", "boot2.bin", "dc", truth={"md5": A})
        self.assertFalse(RetroBat.writable(several))
        self.assertTrue(RetroBat.writable(single))


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
        """A profile may accept several revisions, and int() on the list crashed."""
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

    def test_a_normalised_value_is_counted(self):
        """known_bios_files.json writes PLUTONIA.WAD's sha1 with a leading
        space, which RomM compares as stored and never matches. The export
        wrote it stripped and the summary named no change for it."""
        from export_native import landed_changes  # noqa: PLC0415

        sha1 = "8" * 40
        fe = NativeFile("PLUTONIA.WAD", "doom/PLUTONIA.WAD", "doom",
                        platform={"size": 1024, "sha1": sha1})
        exporter = Romm()
        original = json.dumps({"doom:PLUTONIA.WAD": {"size": "1024", "sha1": " " + sha1}})
        produced = exporter.render({"doom": NativeSystem("doom", files=[fe])}, None,
                                   {exporter.native_filename(): original})
        written = json.loads(produced[exporter.native_filename()])
        self.assertEqual(written["doom:PLUTONIA.WAD"]["sha1"], sha1)
        changes = landed_changes(exporter, {"doom": NativeSystem("doom", files=[fe])})
        self.assertEqual(changes.applied, ["doom/PLUTONIA.WAD sha1"])

    def test_the_shared_helper_reads_every_exporter_the_same_way(self):
        """RomM's writable is per instance, but the base helper bound fe as self."""
        from exporter import discover_exporters  # noqa: PLC0415

        theirs = NativeFile("boot.bin", "dc/boot.bin", "dc",
                            platform={"size": 2097152, "md5": A, "core": "libretro/flycast"})
        systems = {"dc": NativeSystem("dc", files=[theirs], from_platform=True)}
        for name, cls in sorted(discover_exporters().items()):
            with self.subTest(exporter=name):
                pairs = cls().exportable(systems)
                self.assertEqual([fe for _, files in pairs for fe in files], [theirs])

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

class RommWritesOneEntryPerKey(unittest.TestCase):
    """Two additions under one slug:filename key: the second overwrote the
    first in RomM's dict and both were counted landed."""

    def test_the_second_addition_under_a_key_is_not_writable(self):
        from exporter.romm_exporter import Exporter as Romm  # noqa: PLC0415

        first = NativeFile("basic.rom", "Acorn/basic.rom", "acpc",
                           truth={"size": 16384, "md5": A})
        second = NativeFile("basic.rom", "Electron/basic.rom", "acpc",
                            truth={"size": 16384, "md5": B})
        exporter = Romm()
        produced = exporter.render(
            {"acpc": NativeSystem("acpc", files=[first, second])}, None, {}, None
        )
        data = json.loads(produced[exporter.native_filename()])
        self.assertEqual(list(data), ["acpc:basic.rom"])
        self.assertEqual(
            [exporter.writable(first), exporter.writable(second)], [True, False]
        )


class RommKeysHoldABareFileName(unittest.TestCase):
    """fuse declares fuse/48.rom: the export wrote zxs:fuse/48.rom, a key
    RomM never looks up, since it lists the platform folder without
    recursing and looks each file up as slug:file_name."""

    def test_an_addition_named_with_a_directory_is_not_written(self):
        nested = NativeFile("fuse/48.rom", "fuse/48.rom", "zxs",
                            truth={"size": 16384, "md5": A})
        bare = NativeFile("plus2.rom", "plus2.rom", "zxs",
                          truth={"size": 32768, "md5": B})
        exporter = Romm()
        produced = exporter.render(
            {"zxs": NativeSystem("zxs", files=[nested, bare])}, None, {}, None
        )
        self.assertEqual(
            list(json.loads(produced[exporter.native_filename()])), ["zxs:plus2.rom"]
        )
        self.assertEqual(
            [exporter.writable(nested), exporter.writable(bare)], [False, True]
        )


class RetroPieProposals(unittest.TestCase):
    def test_required_is_read_for_the_package_core(self):
        fe = NativeFile("scph5501.bin", "scph5501.bin", "psx",
                        truth={"required": True, "_required_by": ["beetle_psx"],
                               "_cores": ["beetle_psx", "pcsx_rearmed"]})
        self.assertTrue(RetroPie._required_for(fe, "beetle_psx"))
        self.assertFalse(RetroPie._required_for(fe, "pcsx_rearmed"))

    def test_a_file_the_package_installs_is_not_proposed(self):
        """gngeopi's help asked to copy gngeo_data.zip, which make install
        puts in the package's data directory (gngeopi.yml)."""
        installed = NativeFile("gngeo_data.zip", "gngeo_data.zip", "neogeo",
                               truth={"required": True, "_required_by": ["gngeopi"],
                                      "_cores": ["gngeopi"], "_brought_by": [],
                                      "bundled": True})
        brought = NativeFile("neogeo.zip", "neogeo.zip", "neogeo",
                             truth={"required": True, "_required_by": ["gngeopi"],
                                    "_cores": ["gngeopi"],
                                    "_brought_by": ["gngeopi:standalone"]})
        self.assertFalse(RetroPie._required_for(installed, "gngeopi"))
        self.assertTrue(RetroPie._required_for(brought, "gngeopi"))

    @staticmethod
    def _module(module_id: str, help_text: str) -> dict[str, str]:
        script = f'rp_module_id="{module_id}"\nrp_module_help="{help_text}"\n'
        return {f"scriptmodules/emulators/{module_id}.sh": script}

    @staticmethod
    def _wanting(core: str, *names: str) -> dict:
        files = [NativeFile(n, n, "sys", truth={
            "required": True, "_required_by": [core], "_cores": [core],
            "_brought_by": [f"{core}:standalone"]}) for n in names]
        return {"sys": NativeSystem("sys", files=files)}

    def test_a_lowercase_bios_sentence_is_read(self):
        """Eight scriptmodules write "bios" in lower case (xm7, np2pi,
        quasi88, minivmac, px68k...) and none of them was examined."""
        module = self._module("xm7", "Copy bios files a.rom and b.rom to $biosdir/xm7")
        self.assertEqual(len(RetroPie().modules(module)), 1)

    def test_a_module_left_as_is_is_not_written(self):
        """minivmac was reported "left as is" for a name no profile documents
        and written all the same: the skip had no continue after it."""
        from unittest import mock

        exporter = RetroPie()
        module = self._module("vmac", "Copy the required BIOS file vMac.ROM to $biosdir")
        with mock.patch.object(RetroPie, "_core_index",
                               return_value={"standalone": {"vmac": "vmac"}, "libretro": {}}):
            produced = exporter.render(self._wanting("vmac", "MacII.ROM"), Report(), module)
        self.assertEqual(produced, {})

    def test_a_standalone_package_does_not_borrow_a_libretro_profile(self):
        """lr- was stripped whatever the build: RetroPie's standalone
        minivmac package matched the libretro profile, which reads
        MacII.ROM where Mini vMac 37 reads vMac.ROM."""
        from unittest import mock

        module = self._module("minivmac", "Copy the required BIOS file vMac.ROM to $biosdir")
        index = {"libretro": {"minivmac": "minivmac"}, "standalone": {}}
        with mock.patch.object(RetroPie, "_core_index", return_value=index):
            exporter = RetroPie()
            produced = exporter.render(self._wanting("minivmac", "MacII.ROM"), Report(), module)
        self.assertEqual(produced, {})
        self.assertIn("minivmac", sum(exporter._skipped.values(), []))

    def test_a_list_is_capped_by_retropies_longest_not_a_constant(self):
        """The cap of six came from the longest list read, case-sensitively:
        xm7 writes thirteen names."""
        from unittest import mock

        names = [f"n{i}.rom" for i in range(8)]
        modules = {
            **self._module("long", "Copy bios files " + ", ".join(names[:7]) + " and "
                           + names[7] + " to $biosdir"),
            **self._module("short", "Copy the required BIOS files a.rom and b.rom to $biosdir"),
        }
        index = {"standalone": {"short": "short"}, "libretro": {}}
        with mock.patch.object(RetroPie, "_core_index", return_value=index):
            exporter = RetroPie()
            produced = exporter.render(
                self._wanting("short", "a.rom", "b.rom", "c.rom", "d.rom", "e.rom",
                              "f.rom", "g.rom"), Report(), modules)
        self.assertEqual(len(produced), 1)
        self.assertEqual(exporter.validate({}, produced), [])

    def test_a_file_of_a_system_retropie_lacks_is_not_proposed(self):
        """lr-geargrafx adds pcengine only (addSystem, lr-geargrafx.sh:42),
        and its sentence was extended with the LaserActive's pac-n1.bin and
        pac-n10.bin, a system RetroPie does not have."""
        from unittest import mock

        files = [NativeFile(n, n, sys_id, truth={
            "required": True, "_required_by": ["geargrafx"], "_cores": ["geargrafx"],
            "_brought_by": ["geargrafx:libretro"]}, foreign_system=foreign)
            for n, sys_id, foreign in (("gexpress.pce", "pce", False),
                                       ("pac-n1.bin", "laseractive", True))]
        listed = NativeFile("syscard3.pce", "syscard3.pce", "pce", platform={"name": "syscard3.pce"})
        systems = {"pce": NativeSystem("pce", files=[listed, files[0]]),
                   "laseractive": NativeSystem("laseractive", files=[files[1]])}
        module = {
            **self._module("lr-geargrafx", "Copy the required BIOS file syscard3.pce to $biosdir"),
            **self._module("xm7", "Copy bios files a.rom, b.rom and c.rom to $biosdir"),
        }
        with mock.patch.object(RetroPie, "_core_index",
                               return_value={"libretro": {"geargrafx": "geargrafx"},
                                             "standalone": {}}):
            produced = RetroPie().render(systems, Report(), module)
        (text,) = produced.values()
        self.assertIn("gexpress.pce", text)
        self.assertNotIn("pac-n1.bin", text)

    def test_an_extended_list_keeps_its_own_final_comma(self):
        """quasi88 writes "N88KNJ2.ROM, and N88SUB.ROM": the list came back
        without its comma before the final and."""
        help_text = "Copy bios files A.ROM, B.ROM, and C.ROM to $biosdir/pc88"
        enumeration = RetroPie._enumeration(help_text)
        self.assertEqual(
            RetroPie._extended(help_text, enumeration, ["D.ROM"]),
            "Copy bios files A.ROM, B.ROM, C.ROM, and D.ROM to $biosdir/pc88",
        )

    def test_a_list_of_alternatives_is_not_extended(self):
        alternatives = "Copy the required BIOS file a.rom or b.rom to $biosdir"
        enumeration = "Copy the required BIOS files a.rom and b.rom to $biosdir"
        self.assertIsNone(RetroPie._enumeration(alternatives))
        self.assertIsNotNone(RetroPie._enumeration(enumeration))

    def test_an_extended_list_keeps_retropies_idiom(self):
        """lr-geargrafx read "syscard3.pce and gexpress.pce, pac-n1.bin and
        pac-n10.bin to $biosdir"."""
        cases = (
            ("Copy the required BIOS files syscard3.pce and gexpress.pce to $biosdir",
             ["pac-n1.bin", "pac-n10.bin"],
             "Copy the required BIOS files syscard3.pce, gexpress.pce, pac-n1.bin"
             " and pac-n10.bin to $biosdir"),
            ("Copy the required BIOS file saturn_bios.bin to $biosdir",
             ["mpr-17933.bin"],
             "Copy the required BIOS file saturn_bios.bin and mpr-17933.bin to $biosdir"),
            ("requires the BIOS files a.bin, b.bin copied to $biosdir",
             ["c.bin"],
             "requires the BIOS files a.bin, b.bin and c.bin copied to $biosdir"),
        )
        for help_text, missing, expected in cases:
            with self.subTest(help_text=help_text):
                enumeration = RetroPie._enumeration(help_text)
                self.assertEqual(
                    RetroPie._extended(help_text, enumeration, missing), expected
                )

    def test_a_list_of_examples_is_not_extended(self):
        # lr-neocd: "a minimum of two BIOS files (eg. ng-lo.rom,
        # uni-bioscd.rom)" became "(eg. ng-lo.rom, uni-bioscd.rom and
        # neocd.bin)": two announced, three named, read as all required.
        help_text = (
            "You will need a minimum of two BIOS files (eg. ng-lo.rom, "
            "uni-bioscd.rom) which should be copied to $biosdir/neocd"
        )
        self.assertIsNone(RetroPie._enumeration(help_text))
        self.assertIsNone(RetroPie._enumeration(
            "Copy BIOS files such as a.bin and b.bin to $biosdir"
        ))

    def test_words_between_names_are_not_rewritten(self):
        self.assertIsNone(
            RetroPie._enumeration("BIOS files a.bin (US) and b.bin to $biosdir")
        )


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
        """checkBios skips a BIOS whose emulator or core is not installed.
        Rewritten without the keys, vectrex's MAME BIOS was wanted by every
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


class SummaryCountsWhatTheTruthRewrites(unittest.TestCase):
    """A size and a dropped hash are in the diff, so they are counted."""

    def _entry(self):
        # The sha1s contradict, so the truth describes the file alone: its
        # size replaces the platform's and the platform's crc32 is dropped.
        return NativeFile(
            "neocdz.zip", "neocdz.zip", "neocd",
            platform={"size": 953078, "crc32": "a034e470", "sha1": "2" * 40},
            truth={"size": 955352, "sha1": "7" * 40},
            corrections=["sha1"],
        )

    def test_a_format_with_the_fields_counts_them(self):
        from export_native import landed_changes  # noqa: PLC0415

        entry = self._entry()
        changes = landed_changes(SystemDat(), {"neocd": NativeSystem("neocd", files=[entry])})
        self.assertEqual(changes.resized, ["neocd/neocdz.zip"])
        self.assertEqual(changes.cleared, ["neocd/neocdz.zip crc32"])
        self.assertEqual(changes.applied, ["neocd/neocdz.zip sha1"])

    def test_a_format_without_them_does_not(self):
        from export_native import landed_changes  # noqa: PLC0415
        from exporter.batocera_exporter import Exporter as Batocera  # noqa: PLC0415

        entry = self._entry()
        changes = landed_changes(Batocera(), {"neocd": NativeSystem("neocd", files=[entry])})
        self.assertEqual((changes.resized, changes.cleared), ([], []))



class AStaleTruthIsRefused(unittest.TestCase):
    """export_native read dist/truth/<platform>.yml at any age: a model from
    before `_required_by` existed made RetroPie's guard fall back on the
    merged `required`, and the export wrote pcsx_rearmed's optional BIOS
    as required."""

    def test_a_truth_that_no_longer_matches_is_refused(self):
        import shutil
        import tempfile

        import export_native  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        truth_dir = Path(tempfile.mkdtemp(dir=root / "tmp"))
        self.addCleanup(shutil.rmtree, truth_dir, True)
        (truth_dir / "retropie.yml").write_text("platform: retropie\nsystems: {}\n")
        with self.assertRaises(export_native.StaleTruth):
            export_native.load_inputs("retropie", truth_dir, str(root / "platforms"))



class ACorruptOriginalIsRefused(unittest.TestCase):
    """A truncated es_bios.xml in the cache was ignored: the export was
    rebuilt from our model alone, losing the systems we do not transcribe
    and the maintainer's comments, and the run ended in success."""

    def test_recalbox_refuses_it(self):
        fe = NativeFile("bios.bin", "bios.bin", "nes", platform={"md5": A})
        exporter = Recalbox()
        with self.assertRaises(ValueError) as caught:
            exporter.render({"nes": NativeSystem("nes", files=[fe])}, None,
                            {exporter.native_filename(): "<biosList><system platform="})
        self.assertIn("does not parse", str(caught.exception))

    def test_retrobat_refuses_it(self):
        from exporter.retrobat_exporter import Exporter as RetroBat  # noqa: PLC0415

        fe = NativeFile("bios.bin", "bios.bin", "nes", platform={"md5": A})
        exporter = RetroBat()
        with self.assertRaises(ValueError):
            exporter.render({"nes": NativeSystem("nes", files=[fe])}, None,
                            {exporter.native_filename(): '{"nes": {'})


class TheSummaryCountsWhatTheFileCarries(unittest.TestCase):
    """RomM kept the sha1 and crc the truth contradicts beside the corrected
    md5, and RomM accepts any one hash. RetroDECK kept a cleared md5 and
    Recalbox an element it could not rewrite, both counted cleared. RomM and
    System.dat counted a sha1 filled that no record could hold."""

    def _contradicted(self):
        return NativeFile(
            "scph5501.bin", "scph5501.bin", "psx",
            platform={"size": 524288, "crc32": "deadbeef", "md5": A, "sha1": "1" * 40},
            # With a size of its own: without one, RomM keeps its entry whole.
            truth={"md5": B, "size": 524288},
        )

    def test_romm_drops_the_hashes_it_counts_cleared(self):
        from export_native import landed_changes  # noqa: PLC0415
        from exporter.baseline import Report  # noqa: PLC0415

        fe = self._contradicted()
        systems = {"psx": NativeSystem("psx", files=[fe])}
        original = json.dumps({"psx:scph5501.bin": {
            "size": "524288", "crc": "deadbeef", "md5": A, "sha1": "1" * 40}})
        exporter = Romm()
        written = json.loads(exporter.render(
            systems, Report(), {exporter.native_filename(): original},
        )[exporter.native_filename()])["psx:scph5501.bin"]
        self.assertEqual(written.get("md5"), B)
        self.assertNotIn("sha1", written)
        self.assertNotIn("crc", written)
        cleared = landed_changes(exporter, systems).cleared
        self.assertEqual(sorted(cleared), ["psx/scph5501.bin crc32", "psx/scph5501.bin sha1"])

    def test_a_fill_no_record_holds_is_not_counted(self):
        from export_native import landed_changes  # noqa: PLC0415

        fe = NativeFile(
            "scph5501.bin", "scph5501.bin", "psx",
            platform={"md5": A},
            truth={"md5": [A, B], "sha1": ["1" * 40, "2" * 40]},
            filled=["sha1"],
        )
        systems = {"psx": NativeSystem("psx", files=[fe])}
        for exporter in (Romm(), SystemDat()):
            with self.subTest(exporter=type(exporter).__module__):
                self.assertEqual(landed_changes(exporter, systems).filled, [])

    def test_retrodeck_drops_a_cleared_md5(self):
        merged = RetroDeck._merge(
            [{"filename": "scph5501.bin", "system": "psx", "md5": A}],
            [OrderedDict(filename="scph5501.bin", system="psx",
                         sha256="e" * 64)],
        )
        self.assertNotIn("md5", merged[0])

    def test_recalbox_counts_nothing_on_an_element_it_keeps(self):
        from export_native import landed_changes  # noqa: PLC0415

        fe = NativeFile(
            "scph5501.bin", "scph5501.bin", "psx",
            platform={"md5": A, "size": 1, "core": "libretro/pcsx_rearmed"},
            truth={"sha1": "1" * 40, "size": 2},
        )
        changes = landed_changes(Recalbox(), {"psx": NativeSystem("psx", files=[fe])})
        self.assertEqual(changes.cleared, [])


class BatoceraEntriesParseAsWritten(unittest.TestCase):
    """gba ends in '] }, # Optional': the comment swallowed the closing
    brace, the entry read as unparsable and was rewritten with its emulator
    gate and runner keys lost. The text was also run through exec."""

    def test_a_trailing_comment_and_no_execution(self):
        from exporter.batocera_exporter import Exporter as Batocera  # noqa: PLC0415

        entry = Batocera._parse_entry([
            '"gba": { "name": "GBA", "emulator": "libretro", "biosFiles": [',
            '  { "md5": "a", "file": "bios/gba_bios.bin" } ] }, # Optional',
        ])
        self.assertEqual(entry["gba"]["emulator"], "libretro")
        self.assertIsNone(Batocera._parse_entry(['"x": __import__("os").getcwd()']))
        source = (REPO_ROOT / "scripts" / "exporter" / "batocera_exporter.py").read_text()
        self.assertNotIn("exec(", source)


class ARemovedSizeIsReported(unittest.TestCase):
    """System.dat's neocdz.zip went out without size 953078 when the truth
    took the entry over with no size: no counter named the removal."""

    def test_the_removal_is_counted(self):
        from export_native import landed_changes
        from exporter.systemdat_exporter import Exporter as SystemDat

        fe = NativeFile("neocdz.zip", "neocdz.zip", "SNK - NeoGeo CD",
                        platform={"md5": A, "size": 953078}, truth={"md5": B})
        changes = landed_changes(SystemDat(), {"SNK - NeoGeo CD": NativeSystem(
            "SNK - NeoGeo CD", files=[fe])})
        self.assertEqual(changes.unsized, ["SNK - NeoGeo CD/neocdz.zip"])


class AnExtendedListIsReported(unittest.TestCase):
    """The truth adds an accepted md5 the platform lacks without
    contradicting it: RetroDECK wrote [A, B] where the manifest had A and
    Recalbox md5="A,B" where es_bios.xml had A, and the report listed
    nothing. Only Batocera named the list it writes."""

    def _records(self, exporter):
        from export_native import landed_changes  # noqa: PLC0415

        platform = {"name": "f.bin", "md5": A, "core": "libretro/mesen"}
        fe = NativeFile("f.bin", "f.bin", "s", platform=platform,
                        truth={"md5": [A, B], "validation": ["md5"]})
        return landed_changes(exporter, {"s": NativeSystem("s", files=[fe])}).records, fe

    def test_both_formats_report_the_list_they_write(self):
        for exporter in (RetroDeck(), Recalbox()):
            with self.subTest(exporter=exporter.platform_name()):
                records, fe = self._records(exporter)
                self.assertEqual(fe.hashes("md5"), [A, B])
                self.assertEqual(
                    [(r["kind"], r["field"], r["old"], r["new"]) for r in records],
                    [("hash_updated", "md5", A, [A, B])],
                )

    def test_an_unchanged_value_reports_nothing(self):
        from export_native import landed_changes  # noqa: PLC0415

        for exporter in (RetroDeck(), Recalbox()):
            fe = NativeFile("f.bin", "f.bin", "s",
                            platform={"name": "f.bin", "md5": A, "core": "libretro/mesen"},
                            truth={"md5": A})
            with self.subTest(exporter=exporter.platform_name()):
                changes = landed_changes(exporter, {"s": NativeSystem("s", files=[fe])})
                self.assertEqual(changes.records, [])


if __name__ == "__main__":
    unittest.main()
