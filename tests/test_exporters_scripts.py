"""Native exporters that patch code and manifests: the Batocera and ROCKNIX
systems scripts and the RetroDECK component manifests.
"""

from __future__ import annotations

import tests

import json
import unittest
from collections import OrderedDict

from model.platforms import load_platform_config, native_layer
from exporter import discover_exporters
from resolve.nativemodel import NativeFile, NativeSystem, Report
from resolve.reconcile import build_native_model
from tests.exporterssupport import PROFILES, REPO_ROOT, SCRAPED, TRUTH, UPSTREAM_CACHE, model


class RetrodeckManifestsComeBackAsWritten(unittest.TestCase):
    """With nothing to correct, a manifest is the platform's own bytes. The
    export added a final newline to nine of ten, wrote "md5": null where no
    md5 key was, and turned PPSSPP's single bios object into a list."""

    def test_an_empty_truth_hands_back_every_manifest(self):
        cache = UPSTREAM_CACHE / "retrodeck"
        manifests = sorted(cache.glob("*/component_manifest.json"))
        if not manifests:
            self.skipTest("upstream cache not populated")
        exporter = discover_exporters()["retrodeck"]()
        config = native_layer(load_platform_config("retrodeck", str(REPO_ROOT / "platforms")))
        systems, report = build_native_model({"systems": {}}, config)
        originals = {f"{m.parent.name}/component_manifest.json": m.read_text(encoding="utf-8")
                     for m in manifests}
        produced = exporter.render(systems, report, originals, config)
        for path, text in produced.items():
            with self.subTest(manifest=path):
                self.assertEqual(text, originals[path])

    def test_no_md5_key_is_made_up(self):
        from exporter.retrodeck_exporter import Exporter

        mine = OrderedDict([("filename", "bios.bin"), ("system", "xbox"), ("required", "Yes")])
        (merged,) = Exporter._merge([OrderedDict(mine)], [OrderedDict(mine)])
        self.assertNotIn("md5", merged)

    def test_a_single_bios_object_stays_an_object(self):
        from exporter.retrodeck_exporter import Exporter

        theirs = OrderedDict([("filename", "ppge_atlas.zim"), ("system", "psp"),
                              ("md5", "a" * 32)])
        merged = Exporter._merge(OrderedDict(theirs), [])
        self.assertEqual(merged, [theirs])


class RetrodeckExport(unittest.TestCase):
    A, B, C = "a" * 32, "b" * 32, "c" * 32

    def _render(self, declared, accepted):
        """Export one file RetroDECK lists as an md5 array."""
        truth = {
            "systems": {
                "atari-400-800": {
                    "files": [
                        {
                            "name": "ATARIOSB.ROM",
                            "path": "ATARIOSB.ROM",
                            "md5": accepted,
                            "required": True,
                            "_cores": ["atari800"],
                        }
                    ]
                }
            }
        }
        scraped = {
            "systems": {
                "atari-400-800": {
                    "native_id": "atari800",
                    "files": [
                        {
                            "name": "ATARIOSB.ROM",
                            "destination": "bios/ATARIOSB.ROM",
                            "native_system": "atari800",
                            "md5": ",".join(declared),
                            "component": "retroarch",
                            "required": True,
                        }
                    ],
                }
            }
        }
        original = json.dumps({
            "retroarch": {
                "bios": [
                    {
                        "filename": "ATARIOSB.ROM",
                        "md5": declared,
                        "system": "atari800",
                        "required": "Required",
                    }
                ]
            }
        })
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["retrodeck"]()
        produced = exporter.render(
            systems, report, {"retroarch/component_manifest.json": original}, None
        )
        (entry,) = json.loads(produced["retroarch/component_manifest.json"])[
            "retroarch"
        ]["bios"]
        return entry["md5"]

    def test_an_unchanged_md5_array_is_left_as_written(self):
        """The same dumps in another order are no correction."""
        self.assertEqual(
            self._render([self.A, self.B], [self.B, self.A]), [self.A, self.B]
        )

    def test_a_corrected_md5_array_stays_an_array(self):
        """A comma-joined string reads back as one value that is no md5."""
        written = self._render([self.A, self.B], [self.A, self.C])
        self.assertIsInstance(written, list)
        self.assertEqual(set(written), {self.A, self.B, self.C})


class BatoceraPatchesValuesNotEntries(unittest.TestCase):
    """An entry with one md5 to correct was written again whole: atarist's
    eight blank lines went, each '"x"},' became '"x" },', and 941 lines of
    Batocera's diff were layout."""

    ORIGINAL = (
        "#!/usr/bin/env python\n"
        "systems = {\n"
        '    "atarist": { "name": "Atari ST", "biosFiles": [\n'
        '        # ST\n'
        '        { "md5": "' + "1" * 32 + '", "file": "bios/tos102.img"},\n'
        "\n"
        '        { "md5": "' + "2" * 32 + '", "file": "bios/tos104.img"}\n'
        "    ] },\n"
        "}\n"
        "def checkBios(systems, prefix, filterROMs):\n"
        "    return {}\n"
    )

    def render(self, truth_files, original=None):
        scraped = {"cores": ["hatari"], "systems": {"atari-st": {"native_id": "atarist", "files": [
            {"name": "tos102.img", "destination": "tos102.img", "native_system": "atarist",
             "native_name": "Atari ST", "native_path": "bios/tos102.img", "md5": "1" * 32},
            {"name": "tos104.img", "destination": "tos104.img", "native_system": "atarist",
             "native_name": "Atari ST", "native_path": "bios/tos104.img", "md5": "2" * 32},
        ]}}}
        systems, report = build_native_model({"systems": {"atari-st": {"files": truth_files}}},
                                             scraped)
        exporter = discover_exporters()["batocera"]()
        original = original or self.ORIGINAL
        return exporter.render(systems, report, {"batocera-systems": original}, scraped)[
            "batocera-systems"]

    def test_a_corrected_md5_changes_that_value_only(self):
        produced = self.render([{"name": "tos104.img", "path": "tos104.img",
                                 "md5": "3" * 32, "_cores": ["hatari"]}])
        expected = self.ORIGINAL.replace("2" * 32, "3" * 32)
        self.assertEqual(produced, expected)

    def test_an_addition_follows_the_last_item_in_its_form(self):
        produced = self.render([{"name": "tos206.img", "path": "tos206.img",
                                 "md5": "4" * 32, "_cores": ["hatari"]}])
        self.assertIn('"file": "bios/tos104.img"},\n'
                      '        { "md5": "' + "4" * 32 + '", "file": "bios/tos206.img",'
                      ' "emulator": "libretro", "core": "hatari"}\n'
                      "    ] },", produced)
        self.assertIn("# ST\n", produced)
        self.assertIn('"file": "bios/tos102.img"},\n\n', produced)

    def test_a_commented_item_does_not_stop_the_patch(self):
        """atarist keeps seven TOS items behind '#'. Read as live items they
        matched nothing in the model, and the entry was written again whole
        for three additions."""
        commented = '        #{ "md5": "' + "5" * 32 + '", "file": "bios/tos102us.img"},\n'
        original = self.ORIGINAL.replace("\n\n", "\n" + commented + "\n", 1)
        produced = self.render([{"name": "tos206.img", "path": "tos206.img",
                                 "md5": "4" * 32, "_cores": ["hatari"]}], original)
        self.assertEqual(
            produced,
            original.replace(
                '"file": "bios/tos104.img"}\n',
                '"file": "bios/tos104.img"},\n'
                '        { "md5": "' + "4" * 32 + '", "file": "bios/tos206.img",'
                ' "emulator": "libretro", "core": "hatari"}\n',
            ),
        )


class BatoceraExport(unittest.TestCase):
    def _render(self, originals):
        systems, report = model()
        exporter = discover_exporters()["batocera"]()
        return exporter, systems, exporter.render(systems, report, originals, None)

    SKELETON = (
        "#!/usr/bin/env python\n"
        "systems = {\n"
        "}\n"
        "def checkBios(systems, prefix, filterROMs):\n"
        "    return {}\n"
    )

    def test_an_unhashed_entry_is_written_with_an_empty_md5(self):
        scraped = {
            "systems": {
                "nintendo-ds": {
                    "native_id": "nds",
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "native_system": "nds",
                        }
                    ],
                }
            }
        }
        systems, report = build_native_model({"systems": {}}, scraped)
        exporter = discover_exporters()["batocera"]()
        produced = exporter.render(
            systems, report, {"batocera-systems": self.SKELETON}, None
        )
        self.assertIn('"md5": ""', produced["batocera-systems"])

    def test_a_blank_md5_is_not_filled_with_one_of_several_dumps(self):
        """checkBios compares one md5: the first of two refuses the other.

        The empty field checks by existence, so a user holding the second
        dump the core accepts would turn from OK to UNTESTED.
        """
        first, second = "1" * 32, "2" * 32
        truth = {
            "systems": {
                "nintendo-ds": {
                    "files": [
                        {
                            "name": "firmware.bin",
                            "path": "firmware.bin",
                            "md5": [first, second],
                            "required": True,
                            "_cores": ["melonds"],
                        }
                    ]
                }
            }
        }
        scraped = {
            "systems": {
                "nintendo-ds": {
                    "native_id": "nds",
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "native_system": "nds",
                            "md5": "",
                        }
                    ],
                }
            }
        }
        for platform, filename in (
            ("batocera", "batocera-systems"),
            ("rocknix", "rocknix-systems"),
        ):
            with self.subTest(platform=platform):
                systems, report = build_native_model(truth, scraped)
                (entry,) = systems["nds"].files
                self.assertIn("md5", entry.filled)
                exporter = discover_exporters()[platform]()
                produced = exporter.render(
                    systems, report, {filename: self.SKELETON}, None
                )
                self.assertIn('"md5": ""', produced[filename])
                self.assertNotIn(first, produced[filename])
                self.assertFalse(exporter.states(entry, "md5"))

    def test_a_system_the_platform_does_not_name_gets_no_entry(self):
        """checkBios walks the systems es_systems declares, not our slugs.

        An addition filed under nintendo-snes beside Batocera's own snes is
        never checked, so it is counted as one the format cannot state.
        """
        truth = {
            "systems": {
                **TRUTH["systems"],
                "nintendo-snes": {
                    "files": [
                        {
                            "name": "st010.zip",
                            "path": "st010.zip",
                            "md5": "2" * 32,
                            "required": False,
                            "_cores": ["snes9x"],
                        }
                    ]
                },
            }
        }
        systems, report = build_native_model(truth, SCRAPED, PROFILES)
        (foreign,) = systems["nintendo-snes"].files
        self.assertTrue(foreign.foreign_system)
        own = next(fe for fe in systems["psx"].files if fe.name == "scph7001.bin")
        self.assertFalse(own.foreign_system)
        self.assertEqual(own.runners, [(True, "duckstation")])
        for platform in ("batocera", "rocknix", "retrobat", "recalbox"):
            with self.subTest(platform=platform):
                exporter = discover_exporters()[platform]
                self.assertFalse(exporter().writable(foreign))
                self.assertTrue(exporter().writable(own))
        produced = discover_exporters()["batocera"]().render(
            systems, report, {"batocera-systems": self.SKELETON}, None
        )
        self.assertNotIn('"nintendo-snes"', produced["batocera-systems"])

    def test_a_system_the_platform_names_without_files_is_its_own(self):
        """A system the platform declares empty still has the platform's id."""
        scraped = {"cores": ["snes9x"],
                   "systems": {"nintendo-snes": {"native_id": "snes", "files": []}}}
        truth = {"systems": {"nintendo-snes": {"files": [{
            "name": "st010.zip", "path": "st010.zip", "md5": "2" * 32,
            "required": False, "_cores": ["snes9x"],
        }]}}}
        systems, _ = build_native_model(truth, scraped)
        (entry,) = systems["snes"].files
        self.assertFalse(entry.foreign_system)
        self.assertTrue(discover_exporters()["batocera"]().writable(entry))

    def test_writing_without_the_platform_file_is_refused(self):
        """A systems dict alone is not the script Batocera runs."""
        systems, report = model()
        exporter = discover_exporters()["batocera"]()
        with self.assertRaises(ValueError):
            exporter.render(systems, report, {}, None)

    def test_the_code_around_the_data_survives(self):
        original = (
            "#!/usr/bin/env python\n"
            "systems = {\n"
            '    "psx": { "name": "PS1", "biosFiles": [ '
            '{ "md5": "deadbeefdeadbeefdeadbeefdeadbeef", '
            '"file": "bios/psx/scph5501.bin" } ] },\n'
            "}\n"
            "def checkBios(systems, prefix, filterROMs):\n"
            "    return {}\n"
        )
        _, _, produced = self._render({"batocera-systems": original})
        output = produced["batocera-systems"]
        self.assertIn("def checkBios(", output)
        self.assertIn("#!/usr/bin/env python", output)

    def test_a_note_beside_a_file_is_not_lost_when_the_entry_changes(self):
        original = (
            "systems = {\n"
            '    "psx": { "name": "PS1", "biosFiles": [\n'
            '        # ideally the other revision\n'
            '        { "md5": "deadbeefdeadbeefdeadbeefdeadbeef", '
            '"file": "bios/psx/scph5501.bin" } ] },\n'
            "}\n"
            "def checkBios(systems, prefix, filterROMs):\n"
            "    return {}\n"
        )
        _, _, produced = self._render({"batocera-systems": original})
        self.assertIn("# ideally the other revision", produced["batocera-systems"])


class RocknixNamesRunnersItsOwnWay(unittest.TestCase):
    """ROCKNIX's es_systems comes from add_emu_core in its emulators package:
    libretro cores under `retroarch`, standalones under their emulator. The
    `libretro` pair Batocera writes names nothing there."""

    ORIGINAL = (
        "#!/usr/bin/env python\n"
        "systems = {\n"
        '    "psx": { "name": "PS1", "biosFiles": [ { "md5": "", "file": "bios/scph5501.bin" } ] },\n'
        "}\n"
        "def checkBios(systems, prefix, filterROMs):\n"
        "    return {}\n"
    )
    PACKAGE = (
        "  add_emu_core psx retroarch beetle_psx false\n"
        "  add_emu_core psx duckstation duckstation-sa false\n"
    )

    def test_the_package_names_the_runner(self):
        exporter = discover_exporters()["rocknix"]()
        psx = NativeSystem("psx", "PS1", from_platform=True, files=[
            NativeFile("scph5501.bin", "scph5501.bin", "psx", platform={"md5": ""}),
            NativeFile("a.bin", "a.bin", "psx", truth={"md5": "1" * 32},
                       runners=[(False, "beetle_psx")]),
            NativeFile("b.bin", "b.bin", "psx", truth={"md5": "2" * 32},
                       runners=[(True, "duckstation-sa")]),
            NativeFile("c.bin", "c.bin", "psx", truth={"md5": "3" * 32},
                       runners=[(False, "unknown_core")]),
        ])
        text = exporter.render(
            {"psx": psx}, Report(),
            {"rocknix-systems": self.ORIGINAL, "emulators/package.mk": self.PACKAGE},
        )["rocknix-systems"]
        self.assertIn('"file": "bios/a.bin", "emulator": "retroarch", "core": "beetle_psx" }', text)
        self.assertIn('"file": "bios/b.bin", "emulator": "duckstation", "core": "duckstation-sa" }', text)
        self.assertNotIn("c.bin", text)


class RocknixRunnersFollowTheBuild(unittest.TestCase):
    """ROCKNIX registers DuckStation twice: as the libretro core under
    retroarch, and as duckstation-sa under its own emulator. The exporter
    looked a standalone runner up as a core name, gating standalone
    DuckStation's 98 files on the libretro core, and refused ARMSX2."""

    MK = (
        "add_emu_core psx retroarch duckstation false\n"
        "add_emu_core psx duckstation duckstation-sa false\n"
        "add_emu_core ps2 armsx2 armsx2-sa true\n"
    )

    def test_each_build_answers_with_its_own_pair(self):
        from exporter.rocknix_exporter import EMULATORS_MK, Exporter

        exporter = Exporter()
        exporter._pairs = {
            (emulator, core)
            for _s, emulator, core in __import__("re").findall(
                r"add_emu_core\s+(\S+)\s+(\S+)\s+(\S+)", self.MK
            )
        }
        self.assertEqual(exporter._runner_pair((False, "duckstation")), ("retroarch", "duckstation"))
        self.assertEqual(exporter._runner_pair((True, "duckstation")), ("duckstation", "duckstation-sa"))
        self.assertEqual(exporter._runner_pair((True, "armsx2")), ("armsx2", "armsx2-sa"))
        self.assertIsNone(exporter._runner_pair((False, "armsx2")))
        self.assertTrue(EMULATORS_MK)


class RetroDeckAdditionsFollowTheirCore(unittest.TestCase):
    """Every RetroDECK ps2 entry sits in the pcsx2 component, so every ps2
    addition went into PCSX2's manifest, armsx2's flash.dat included: a file
    PCSX2 never opens, asked of PCSX2 users and counted as added."""

    def test_only_the_components_emulator_places_a_file(self):
        exporter = discover_exporters()["retrodeck"]()
        own = NativeFile("scph39001.bin", "bios/scph39001.bin", "ps2",
                         platform={"md5": "0" * 32, "component": "pcsx2"})
        read_by_pcsx2 = NativeFile("rom1.bin", "bios/rom1.bin", "ps2",
                                   truth={"md5": "1" * 32}, runners=[(True, "pcsx2")])
        read_by_armsx2 = NativeFile("flash.dat", "bios/flash.dat", "ps2",
                                    truth={"md5": "2" * 32}, runners=[(False, "armsx2")])
        system = NativeSystem("ps2", "PS2", from_platform=True,
                              files=[own, read_by_pcsx2, read_by_armsx2])
        exporter._place_additions({"ps2": system})
        self.assertEqual(read_by_pcsx2.native("component", ""), "pcsx2")
        self.assertEqual(read_by_armsx2.native("component", ""), "")


class BatoceraNotesStayWithTheirItem(unittest.TestCase):
    """Keyed by path, bk's '# MAME' came back before each of twelve items
    reading bios/bk0010.zip, and enterprise's '"biosFiles": [# ep128emu-core'
    was dropped."""

    def test_notes_are_kept_once_per_item(self):
        from exporter.batocera_exporter import Exporter

        lines = [
            '    "bk": { "name": "BK", "biosFiles": [# head note',
            "        # MAME",
            '        { "md5": "a", "file": "bios/bk0010.zip", "zippedFile": "one.rom" },',
            '        { "md5": "b", "file": "bios/bk0010.zip", "zippedFile": "two.rom" }, # tail',
            "    ] },",
        ]
        trailing, leading = Exporter._item_notes(lines)
        self.assertEqual(leading, {("bios/bk0010.zip", "one.rom"): ["# head note", "# MAME"]})
        self.assertEqual(trailing, {("bios/bk0010.zip", "two.rom"): "# tail"})

    def test_hash_inside_a_quoted_path_is_no_note(self):
        from exporter.batocera_exporter import Exporter

        lines = ['        { "md5": "", "file": "ports/opentyrian/newsh#.shp" },']
        self.assertEqual(Exporter._item_notes(lines), ({}, {}))


class BatoceraEntriesAtAnyIndent(unittest.TestCase):
    """EmuELEC indents 23 of its systems with one tab. The entry pattern
    required four spaces, so each was appended again whole and the export
    carried 21 duplicated keys that ast.literal_eval kept silently."""

    def test_a_tab_indented_entry_is_located(self):
        from exporter.batocera_exporter import Exporter

        body = [
            '    "atari5200": { "name": "5200", "biosFiles": [ { "md5": "a", "file": "bios/5200.rom" } ] },',
            '\t"amiga": { "name": "Amiga", "biosFiles": [ { "md5": "b", "file": "bios/kick.rom" },',
            '\t\t{ "md5": "c", "file": "bios/kick2.rom" } ] },',
        ]
        self.assertEqual(
            Exporter._entry_spans(body), {"atari5200": (0, 0), "amiga": (1, 2)}
        )


if __name__ == "__main__":
    unittest.main()
