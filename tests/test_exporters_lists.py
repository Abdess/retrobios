"""Native exporters for list formats: Recalbox es_bios.xml, the RomM fixture,
System.dat, BizHawk, RetroBat and the MiSTer database.
"""

from __future__ import annotations

import tests

import difflib
import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict
from pathlib import Path

from model.platforms import load_platform_config, native_layer
from exporter import discover_exporters
from exporter.landed import landed_changes
from resolve.reconcile import build_native_model
from tests.exporterssupport import REPO_ROOT, SCRAPED, TRUTH, UPSTREAM_CACHE, model


class RecalboxExport(unittest.TestCase):
    def _render(self):
        systems, report = model()
        exporter = discover_exporters()["recalbox"]()
        return exporter, systems, exporter.render(systems, report, {}, None)

    def test_output_is_well_formed_xml_in_recalbox_shape(self):
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        self.assertEqual(root.tag, "biosList")
        self.assertTrue(list(root.iter("system")))

    def test_every_element_carries_what_the_schema_requires(self):
        """es_bios.xsd makes path, md5 and core required on every bios."""
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        for element in root.iter("bios"):
            for attribute in ("path", "md5", "core"):
                self.assertTrue(element.get(attribute), attribute)

    def test_mandatory_is_only_stated_when_it_is_false(self):
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        by_path = {e.get("path"): e for e in root.iter("bios")}
        self.assertIsNone(by_path["psx/scph5501.bin"].get("mandatory"))
        self.assertEqual(by_path["psx/scph7001.bin"].get("mandatory"), "false")

    def test_hash_match_mandatory_does_not_follow_mandatory(self):
        """They are separate axes: Recalbox uses all four combinations."""
        _, _, produced = self._render()
        root = ET.fromstring(produced["es_bios.xml"])
        optional = next(
            e for e in root.iter("bios") if e.get("mandatory") == "false"
        )
        self.assertIsNone(optional.get("hashMatchMandatory"))

    def test_the_export_passes_its_own_validator(self):
        exporter, systems, produced = self._render()
        self.assertEqual(exporter.validate(systems, produced), [])

    def test_an_addition_goes_where_the_core_reads_it(self):
        """DuckStation reads scph5000.bin at the BIOS root, but the export wrote
        psx/scph5000.bin, a path no core opens."""
        import copy

        truth = copy.deepcopy(TRUTH)
        truth["systems"]["sony-playstation"]["files"].append({
            "name": "scph5000.bin", "md5": "57a06303dfa9cf9351222dfcbb4a29d9",
            "size": 524288, "required": False, "_cores": ["duckstation"],
        })
        systems, report = build_native_model(truth, SCRAPED)
        produced = discover_exporters()["recalbox"]().render(systems, report, {}, None)
        paths = {e.get("path") for e in ET.fromstring(produced["es_bios.xml"]).iter("bios")}
        self.assertIn("scph5000.bin", paths)
        self.assertNotIn("psx/scph5000.bin", paths)

    def test_two_blocks_of_one_platform_stay_two(self):
        """Recalbox files Pentagon and Scorpion under zxspectrum, apart.

        Merged, the Scorpion ROMs sat under the Pentagon name and the BIOS
        manager lost a section, and the line the maintainer commented out went
        with the rewrite.
        """
        old, new = "1" * 32, "2" * 32

        def declared(name, label, md5):
            return {
                "name": name, "destination": f"fuse/{name}",
                "native_system": "zxspectrum", "native_name": label,
                "native_path": f"fuse/{name}", "md5": md5,
                "core": "libretro/fuse", "required": False,
            }

        pentagon = "Pentagon 128/512/1024 (ZX Spectrum clone)"
        scorpion = "Scorpion 256K (ZX Spectrum clone)"
        scraped = {"systems": {"sinclair-zxspectrum": {
            "native_id": "zxspectrum",
            "files": [
                declared("128p-0.rom", pentagon, "3" * 32),
                declared("256s-0.rom", scorpion, old),
            ],
        }}}
        truth = {"systems": {"sinclair-zxspectrum": {"files": [{
            "name": "256s-0.rom", "path": "fuse/256s-0.rom", "md5": new,
            "required": False, "_cores": ["fuse"],
        }]}}}
        original = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<biosList>\n'
            f'  <system fullname="{pentagon}" platform="zxspectrum">\n'
            f'    <bios path="fuse/128p-0.rom" md5="{"3" * 32}" core="libretro/fuse" />\n'
            '    <!--bios path="fuse/gluck.rom" md5="x" core="libretro/fuse" /-->\n'
            "  </system>\n"
            f'  <system fullname="{scorpion}" platform="zxspectrum">\n'
            f'    <bios path="fuse/256s-0.rom" md5="{old}" core="libretro/fuse" />\n'
            "  </system>\n</biosList>\n"
        )
        systems, report = build_native_model(truth, scraped)
        produced = discover_exporters()["recalbox"]().render(
            systems, report, {"es_bios.xml": original}, None
        )["es_bios.xml"]
        self.assertIn('<!--bios path="fuse/gluck.rom"', produced)
        blocks = {
            s.get("fullname"): [b.get("md5") for b in s.iter("bios")]
            for s in ET.fromstring(produced).iter("system")
        }
        self.assertEqual(blocks, {pentagon: ["3" * 32], scorpion: [new]})

    COMPOSITE_SCRAPED = {
        "zip_digest": "composite",
        "systems": {"snk-neogeo-cd": {"native_id": "neogeocd", "files": [{
            "name": "neocdz.zip", "destination": "neocdz.zip", "md5": "a" * 32,
            "native_system": "neogeocd", "core": "libretro/fbneo",
            "required": True, "zip_digest": "composite",
        }]}},
    }

    def test_a_composite_md5_is_not_replaced_by_a_container_md5(self):
        """Recalbox hashes a .zip by its members (Bios.cpp:64-68,
        Zip::Md5Composite): the truth's container md5 is another digest."""
        truth = {"systems": {"snk-neogeo-cd": {"files": [
            {"name": "neocdz.zip", "md5": "b" * 32, "required": True, "_cores": ["geolith"]},
            {"name": "boot-data.zip", "md5": "c" * 32, "required": False, "_cores": ["geolith"]},
        ]}}}
        systems, report = build_native_model(truth, self.COMPOSITE_SCRAPED)
        exporter = discover_exporters()["recalbox"]()
        produced = exporter.render(systems, report, {}, None)["es_bios.xml"]
        md5_of = {b.get("path"): b.get("md5") for b in ET.fromstring(produced).iter("bios")}
        self.assertEqual(md5_of, {"neocdz.zip": "a" * 32})
        self.assertEqual(landed_changes(exporter, systems).records, [])

    def test_a_container_md5_never_pairs_with_a_composite(self):
        """neocd.bin's md5 equals the composite of a neocdz.zip: by hash the
        two would be read as one renamed file."""
        truth = {"systems": {"snk-neogeo-cd": {"files": [
            {"name": "neocd.bin", "md5": "a" * 32, "required": True, "_cores": ["neocd"]},
        ]}}}
        systems, _ = build_native_model(truth, self.COMPOSITE_SCRAPED)
        declared = next(fe for s in systems.values() for fe in s.files if fe.platform)
        self.assertIsNone(declared.truth)

    def test_the_live_export_keeps_every_zip_md5(self):
        """No element of es_bios.xml names a .zip under a new md5: none can
        be stated as the composite Recalbox computes."""
        path = REPO_ROOT / "exports" / "recalbox" / "es_bios.xml"
        original = UPSTREAM_CACHE / "recalbox" / "es_bios.xml"
        if not original.is_file():
            self.skipTest("no cached original for recalbox")

        def zips(text: str) -> dict[tuple[str | None, str | None], str]:
            return {
                (s.get("platform"), b.get("path")): ",".join(sorted(
                    v.strip().lower() for v in b.get("md5", "").split(",")
                ))
                for s in ET.fromstring(text).iter("system")
                for b in s.iter("bios")
                if b.get("path", "").lower().endswith(".zip")
            }

        before = zips(original.read_text(encoding="utf-8"))
        after = zips(path.read_text(encoding="utf-8"))
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)
        self.assertEqual(set(after) - set(before), set())

    def test_mandatory_follows_the_cores_the_element_names(self):
        """cdi/cdibios.zip names libretro/same_cdi, which does not read the
        set: MAME requiring it says nothing about that element."""
        scraped = {"systems": {"philips-cdi": {"native_id": "cdi", "files": [
            {"name": "cdibios.zip", "destination": "cdi/cdibios.zip", "md5": "a" * 32,
             "native_system": "cdi", "core": "libretro/same_cdi", "required": False},
            {"name": "cdimono1.zip", "destination": "cdi/cdimono1.zip", "md5": "b" * 32,
             "native_system": "cdi", "core": "libretro/same_cdi", "required": False},
        ]}}}
        truth = {"systems": {"philips-cdi": {"files": [
            {"name": "cdibios.zip", "required": True, "_cores": ["mame0278"],
             "_required_by": ["mame0278"]},
            {"name": "cdimono1.zip", "required": True, "_cores": ["same_cdi", "mame0278"],
             "_required_by": ["same_cdi"]},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"]({
            "same_cdi": {"type": "libretro", "cores": ["same_cdi"]},
            "mame0278": {"type": "libretro", "cores": ["mame0278"],
                         "built_by": ["recalbox"]},
        })
        produced = exporter.render(systems, report, {}, None)["es_bios.xml"]
        mandatory = {
            b.get("path"): b.get("mandatory") for b in ET.fromstring(produced).iter("bios")
        }
        self.assertEqual(mandatory, {"cdi/cdibios.zip": "false", "cdi/cdimono1.zip": None})
        changes = landed_changes(exporter, systems).records
        self.assertEqual(
            [(c["name"], c["old"], c["new"]) for c in changes],
            [("cdimono1.zip", False, True)],
        )

    def test_mandatory_reads_the_named_cores_not_the_hash_pairing(self):
        """saturn/saturn_bios.bin names yabause, yabasanshiro and kronos,
        which require it. Its md5 paired it with the beetle_saturn entry,
        which does not, and the element went out mandatory="false"."""
        md5 = "af5828fdff51384f99b3c4926be27762"
        scraped = {"systems": {"sega-saturn": {"native_id": "saturn", "files": [{
            "name": "saturn_bios.bin", "destination": "saturn/saturn_bios.bin",
            "md5": md5, "native_system": "saturn", "required": True,
            "core": "libretro/yabause,libretro/kronos",
        }]}}}
        truth = {"systems": {"sega-saturn": {"files": [
            {"name": "saturn_bios.bin", "path": "saturn_bios.bin", "md5": md5,
             "required": True, "_cores": ["beetle_saturn", "kronos", "yabause"],
             "_required_by": ["beetle_saturn"]},
            {"name": "saturn_bios.bin", "path": "kronos/saturn_bios.bin",
             "required": True, "_cores": ["kronos", "yabause"],
             "_required_by": ["kronos", "yabause"]},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"]()
        declared = next(fe for s in systems.values() for fe in s.files if fe.platform)
        self.assertEqual(declared.truth["_required_by"], ["beetle_saturn"])
        produced = exporter.render(systems, report, {}, None)["es_bios.xml"]
        element = next(
            b for b in ET.fromstring(produced).iter("bios")
            if b.get("path") == "saturn/saturn_bios.bin"
        )
        self.assertNotEqual(element.get("mandatory"), "false")
        self.assertEqual(
            [c for c in landed_changes(exporter, systems).records
             if c["kind"] == "required_aligned"],
            [],
        )

    def test_a_namesake_elsewhere_in_the_same_tree_is_another_file(self):
        """bluemsx reads Machines/Shared Roms/KANJI.rom, not Recalbox's
        Machines/MSX2+ - European/KANJI.rom."""
        scraped = {"systems": {"msx": {"native_id": "msx2", "files": [{
            "name": "KANJI.rom", "destination": "Machines/MSX2+ - European/KANJI.rom",
            "md5": "a" * 32, "native_system": "msx2", "required": True,
            "core": "libretro/bluemsx",
        }]}}}
        truth = {"systems": {"msx": {"files": [{
            "name": "KANJI.rom", "path": "Machines/Shared Roms/KANJI.rom",
            "md5": "b" * 32, "required": False, "_cores": ["bluemsx"], "_required_by": [],
        }]}}}
        systems, _ = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"]()
        declared = next(fe for s in systems.values() for fe in s.files if fe.platform)
        self.assertTrue(exporter.required_value(declared))

    def test_a_core_name_means_recalboxs_own_build(self):
        """libretro/pcsx2 is Recalbox's PCSX2 1.7 fork. The first profile
        loaded under the name was the LRPS2 revision Batocera builds, and its
        requirement stood for Recalbox's core."""
        scraped = {"systems": {"ps2": {"native_id": "ps2", "files": [{
            "name": "ps2.bin", "destination": "ps2/ps2.bin", "md5": "a" * 32,
            "native_system": "ps2", "required": True, "core": "libretro/pcsx2",
        }]}}}
        truth = {"systems": {"ps2": {"files": [{
            "name": "ps2.bin", "path": "ps2/ps2.bin", "md5": "a" * 32, "required": True,
            "_cores": ["lrps2-416291a", "pcsx2-libretro-408e3b2"],
            "_required_by": ["lrps2-416291a"],
        }]}}}
        profiles = {
            "lrps2-416291a": {"type": "libretro", "cores": ["pcsx2"], "built_by": ["batocera"]},
            "pcsx2-libretro-408e3b2": {"type": "libretro", "cores": ["pcsx2"],
                                       "built_by": ["recalbox"]},
        }
        systems, _ = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"](profiles)
        declared = next(fe for s in systems.values() for fe in s.files if fe.platform)
        self.assertFalse(exporter.required_value(declared))

    def test_a_prefix_no_profile_of_that_build_claims_names_the_emulator(self):
        """es_bios.xml writes libretro/fba2x for piFBA, a standalone binary:
        the element's reader is still piFBA."""
        scraped = {"systems": {"neogeo": {"native_id": "neogeo", "files": [{
            "name": "neogeo.zip", "destination": "neogeo.zip", "md5": "a" * 32,
            "native_system": "neogeo", "required": False, "core": "libretro/fba2x",
        }]}}}
        truth = {"systems": {"neogeo": {"files": [{
            "name": "neogeo.zip", "md5": "a" * 32, "required": True,
            "_cores": ["fba2x"], "_required_by": ["fba2x"],
        }]}}}
        profiles = {"fba2x": {"type": "standalone", "cores": ["fba2x", "pifba"]}}
        systems, _ = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"](profiles)
        declared = next(fe for s in systems.values() for fe in s.files if fe.platform)
        self.assertTrue(exporter.required_value(declared))

    def test_an_element_kept_as_written_is_not_counted_lost(self):
        """The truth takes the entry on sha1 and size and names no md5: the
        element is written back whole, and the run counted it a platform
        entry the format cannot keep."""
        scraped = {"systems": {"x": {"native_id": "x", "files": [{
            "name": "a.bin", "destination": "x/a.bin", "md5": "a" * 32, "size": 100,
            "native_system": "x", "core": "libretro/foo", "required": True,
        }]}}}
        truth = {"systems": {"x": {"files": [{
            "name": "a.bin", "path": "x/a.bin", "sha1": "b" * 40, "size": 200,
            "required": True, "_cores": ["foo"],
        }]}}}
        element = f'    <bios path="x/a.bin" md5="{"a" * 32}" core="libretro/foo" />'
        original = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<biosList>\n'
            f'  <system fullname="X" platform="x">\n{element}\n  </system>\n</biosList>\n'
        )
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["recalbox"]()
        produced = exporter.render(systems, report, {"es_bios.xml": original}, None)
        self.assertIn(element, produced["es_bios.xml"])
        fe = next(fe for s in systems.values() for fe in s.files)
        self.assertTrue(exporter.lands(fe))
        self.assertEqual(landed_changes(exporter, systems).records, [])
        self.assertEqual(len(exporter.withheld()), 1)

    def test_a_truncated_export_is_reported(self):
        exporter, systems, _ = self._render()
        empty = {
            "es_bios.xml": '<?xml version="1.0"?>\n<biosList></biosList>\n',
        }
        self.assertTrue(exporter.validate(systems, empty))


class RommExport(unittest.TestCase):
    def _render(self):
        systems, report = model()
        exporter = discover_exporters()["romm"]()
        return exporter, systems, exporter.render(systems, report, {}, None)

    def test_every_entry_can_actually_verify(self):
        """RomM matches on size and then on one hash: without both, never.
        An entry no source gives a size to carries none and validate() names
        it: this test passed for one only because it held the string
        "None"."""
        exporter, systems, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertTrue(data)
        issues = exporter.validate(systems, produced)
        for key, entry in data.items():
            with self.subTest(key=key):
                if "size" in entry:
                    self.assertTrue(entry["size"].isdigit())
                else:
                    self.assertIn(f"entry without a size, never verifiable: {key}", issues)
                self.assertTrue(
                    any(entry.get(h) for h in ("md5", "sha1", "crc"))
                )

    def test_size_is_written_as_the_fixture_writes_it(self):
        _, _, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertIsInstance(next(iter(data.values()))["size"], str)

    def test_keys_are_the_platform_slug_the_file_belongs_to(self):
        _, _, produced = self._render()
        data = json.loads(produced["known_bios_files.json"])
        self.assertTrue(all(k.startswith("psx:") for k in data))


class RommKeepsItsFixture(unittest.TestCase):
    """The export rebuilt known_bios_files.json from our model in our order:
    3 hash corrections came out as a 3116-line diff, and a key RomM had that
    our transcription lacked was deleted."""

    def test_order_unknown_keys_and_untouched_entries_survive(self):
        theirs = OrderedDict([
            ("psx:zzz_first.bin", OrderedDict([("size", "1024"), ("md5", "a" * 32)])),
            ("psx:only_theirs.bin", OrderedDict([("size", "16"), ("crc", "deadbeef")])),
            ("psx:scph5501.bin", OrderedDict([("size", "524288"), ("md5", "b" * 32)])),
        ])
        original = json.dumps(theirs, indent=2) + "\n"
        scraped = {"systems": {"sony-playstation": {"native_id": "psx", "files": [
            {"name": "zzz_first.bin", "destination": "psx/zzz_first.bin",
             "native_system": "psx", "md5": "a" * 32, "size": 1024},
            {"name": "scph5501.bin", "destination": "psx/scph5501.bin",
             "native_system": "psx", "md5": "b" * 32, "size": 524288},
        ]}}}
        truth = {"systems": {"sony-playstation": {"files": [{
            "name": "scph5501.bin", "path": "scph5501.bin", "md5": "c" * 32,
            "size": 524288, "required": True, "_cores": ["beetle_psx"],
        }]}}}
        systems, report = build_native_model(truth, scraped)
        produced = discover_exporters()["romm"]().render(
            systems, report, {"known_bios_files.json": original}, None
        )["known_bios_files.json"]
        data = json.loads(produced, object_pairs_hook=OrderedDict)
        self.assertEqual(
            list(data), ["psx:zzz_first.bin", "psx:only_theirs.bin", "psx:scph5501.bin"]
        )
        self.assertEqual(data["psx:only_theirs.bin"], theirs["psx:only_theirs.bin"])
        self.assertEqual(data["psx:scph5501.bin"]["md5"], "c" * 32)
        changed = [
            line for line in difflib.unified_diff(
                original.splitlines(), produced.splitlines(), lineterm="", n=0
            ) if line[:1] in "+-" and line[:3] not in ("+++", "---")
        ]
        self.assertEqual(len(changed), 2, changed)


class SystemDatNamesNoSectionItself(unittest.TestCase):
    """libretro titles each section with the system as it spells it,
    "Commodore - Amiga". An addition for a system it has no section for
    opened one under our slug: 20 such sections, commodore-c64, quake,
    laseractive."""

    def test_an_addition_without_a_libretro_section_is_left_out(self):
        amiga = "Commodore - Amiga"
        original = (
            'clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n'
            f'\tcomment "{amiga}"\n'
            f"\trom ( name kick34005.A500 size 262144 md5 {'2' * 32} )\n"
            ")\n"
        )
        scraped = {"systems": {"commodore-amiga": {"native_id": amiga, "files": [
            {"name": "kick34005.A500", "destination": "kick34005.A500",
             "native_system": amiga, "md5": "2" * 32, "size": 262144}]}}}
        truth = {"systems": {
            "commodore-amiga": {"files": [{"name": "kick40068.A1200", "md5": "3" * 32}]},
            "laseractive": {"files": [{"name": "pac-n1.bin", "crc32": "a8cb694c"}]},
        }}
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["retroarch"]()
        produced = exporter.render(systems, report, {"System.dat": original}, None)["System.dat"]
        self.assertNotIn('comment "laseractive"', produced)
        self.assertNotIn("pac-n1.bin", produced)
        self.assertIn("kick40068.A1200", produced)
        self.assertEqual(exporter.validate(systems, {"System.dat": produced}), [])
        added = systems["laseractive"].files[0]
        self.assertFalse(exporter.lands(added))


class SystemDatKeepsSpaceIndentedLines(unittest.TestCase):
    """libretro indents 39 rom lines with four spaces. Read with a tab only,
    they left the base and came back last in their section, re-indented."""

    def test_order_and_indentation_survive(self):
        amiga = "Commodore - Amiga"
        a, b = "1" * 32, "2" * 32
        original = (
            'clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n'
            '\tcomment "System"\n\n'
            f'\tcomment "{amiga}"\n'
            f"    rom ( name kick33180.A500 size 262144 md5 {a} )\n"
            f"\trom ( name kick34005.A500 size 262144 md5 {b} )\n"
            ")\n"
        )
        scraped = {"systems": {"commodore-amiga": {"native_id": amiga, "files": [
            {"name": "kick33180.A500", "destination": "kick33180.A500",
             "native_system": amiga, "md5": a, "size": 262144},
            {"name": "kick34005.A500", "destination": "kick34005.A500",
             "native_system": amiga, "md5": b, "size": 262144},
        ]}}}
        systems, report = build_native_model({"systems": {}}, scraped)
        produced = discover_exporters()["retroarch"]().render(
            systems, report, {"System.dat": original}, None
        )["System.dat"]
        body = produced[produced.index(f'comment "{amiga}"'):].splitlines()[1:3]
        self.assertTrue(body[0].startswith("    rom ( name kick33180.A500"), body)
        self.assertTrue(body[1].startswith("\trom ( name kick34005.A500"), body)
        self.assertEqual(produced.count("kick33180.A500"), 1)


class SystemDatComesBackAsWritten(unittest.TestCase):
    """libretro writes one crc in lower case, Dinothawr.zip's 683ed4ad, and
    the 513 others in upper case. Rendered upper case without condition,
    that line changed with no correction behind it."""

    SECTION = "Dinothawr"
    ORIGINAL = (
        'clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n'
        '\tcomment "System"\n\n'
        '\tcomment "Dinothawr"\n'
        f"\trom ( name lower.zip size 10 crc 683ed4ad md5 {'1' * 32} sha1 {'1' * 40} )\n"
        f"\trom ( name upper.zip size 10 crc 0BCDEF12 md5 {'2' * 32} sha1 {'2' * 40} )\n"
        ")\n"
    )

    def _render(self, truth_files: list[dict]) -> str:
        scraped = {"systems": {"dinothawr": {"native_id": self.SECTION, "files": [
            {"name": "lower.zip", "destination": "lower.zip", "native_system": self.SECTION,
             "size": 10, "crc32": "683ed4ad", "md5": "1" * 32, "sha1": "1" * 40},
            {"name": "upper.zip", "destination": "upper.zip", "native_system": self.SECTION,
             "size": 10, "crc32": "0BCDEF12", "md5": "2" * 32, "sha1": "2" * 40},
        ]}}}
        truth = {"systems": {"dinothawr": {"files": truth_files}}} if truth_files else {"systems": {}}
        systems, report = build_native_model(truth, scraped)
        return discover_exporters()["retroarch"]().render(
            systems, report, {"System.dat": self.ORIGINAL}, None
        )["System.dat"]

    def test_an_empty_truth_hands_back_the_lines(self):
        self.assertEqual(self._render([]), self.ORIGINAL)

    def test_a_corrected_crc_follows_the_case_of_its_line(self):
        produced = self._render([
            {"name": "lower.zip", "size": 10, "crc32": "abcdef01", "md5": "3" * 32, "sha1": "3" * 40},
            {"name": "upper.zip", "size": 10, "crc32": "fedcba98", "md5": "4" * 32, "sha1": "4" * 40},
        ])
        self.assertIn(" crc abcdef01 ", produced)
        self.assertIn(" crc FEDCBA98 ", produced)

    def test_an_added_line_takes_the_case_of_the_file(self):
        produced = self._render([
            {"name": "new.zip", "size": 10, "crc32": "abcdef01", "md5": "5" * 32, "sha1": "5" * 40},
        ])
        self.assertIn("name new.zip size 10 crc ABCDEF01 ", produced)

    def test_an_empty_truth_hands_back_system_dat(self):
        for platform in ("retroarch", "lakka"):
            original_path = UPSTREAM_CACHE / platform / "System.dat"
            if not original_path.exists():
                self.skipTest("upstream cache not populated")
            original = original_path.read_bytes()
            exporter = discover_exporters()[platform]()
            config = native_layer(load_platform_config(platform, str(REPO_ROOT / "platforms")))
            systems, report = build_native_model({"systems": {}}, config)
            produced = exporter.render(
                systems, report, {"System.dat": original.decode("utf-8")}, config
            )
            with self.subTest(platform=platform):
                self.assertEqual(produced["System.dat"].encode("utf-8"), original)


class RommSizeIsNeverNone(unittest.TestCase):
    """size() is None where the truth contradicts RomM's hash without a size
    or names several sizes. str(None) went out as "None", validate() passed
    it as truthy, and RomM's int("None") raised."""

    def _export(self, platform_size):
        entry = {"name": "scph5501.bin", "destination": "psx/scph5501.bin",
                 "native_system": "psx", "md5": "a" * 32}
        if platform_size is not None:
            entry["size"] = platform_size
        scraped = {"systems": {"sony-playstation": {"native_id": "psx", "files": [entry]}}}
        truth = {"systems": {"sony-playstation": {"files": [{
            "name": "scph5501.bin", "path": "scph5501.bin", "md5": "b" * 32,
            "required": True, "_cores": ["beetle_psx"],
        }]}}}
        systems, report = build_native_model(truth, scraped)
        exporter = discover_exporters()["romm"]()
        produced = exporter.render(systems, report, {}, None)
        return exporter, systems, produced, json.loads(produced["known_bios_files.json"])

    def test_an_entry_the_truth_takes_without_a_size_stays_whole(self):
        """RomM compares the size before any hash: the new md5 beside the
        old size never verified, and the report said the size was removed."""
        from exporter.landed import landed_changes

        exporter, systems, _, data = self._export(524288)
        self.assertEqual(
            data["psx:scph5501.bin"], {"size": "524288", "md5": "a" * 32}
        )
        self.assertEqual(landed_changes(exporter, systems).records, [])
        self.assertEqual(len(exporter.withheld()), 1)

    def test_no_size_is_written_rather_than_none(self):
        exporter, systems, produced, data = self._export(None)
        self.assertNotIn("size", data["psx:scph5501.bin"])
        self.assertTrue(any("without a size" in i for i in exporter.validate(systems, produced)))

    def test_validate_refuses_the_string_none(self):
        exporter, systems, _, _ = self._export(524288)
        broken = {"known_bios_files.json": json.dumps(
            {"psx:scph5501.bin": {"size": "None", "md5": "b" * 32}})}
        self.assertTrue(any("without a size" in i for i in exporter.validate(systems, broken)))


class BizhawkExport(unittest.TestCase):
    SHA1 = "a" * 40

    def _export(self, name, call):
        scraped = {"systems": {"nintendo-ds": {"native_id": "NDS", "files": [{
            "name": name, "destination": name, "native_system": "NDS",
        }]}}}
        truth = {"systems": {"nintendo-ds": {"files": [{
            "name": name, "path": name, "sha1": self.SHA1,
            "required": True, "_cores": ["melonds"],
        }]}}}
        systems, report = build_native_model(truth, scraped)
        (entry,) = systems["NDS"].files
        self.assertIn("sha1", entry.filled)
        exporter = discover_exporters()["bizhawk"]()
        source = f"class FirmwareDatabase {{\n    {call}\n}}\n"
        produced = exporter.render(
            systems, report, {"FirmwareDatabase.cs": source}, None
        )["FirmwareDatabase.cs"]
        return exporter, entry, source, produced

    def test_a_fill_a_dummy_call_cannot_hold_is_not_counted(self):
        """BizHawk states DSi_Firmware.bin with SHA1Checksum.Dummy."""
        exporter, entry, source, produced = self._export(
            "DSi_Firmware.bin",
            'FirmwareAndOption(SHA1Checksum.Dummy, 131072, "NDS", "firmwarei", '
            '"DSi_Firmware.bin", "DSi Firmware");',
        )
        self.assertEqual(produced, source)
        self.assertFalse(exporter.states(entry, "sha1"))

    def test_a_homonym_in_another_system_keeps_bizhawks_hash(self):
        """A Dummy entry the truth gained a SHA1 for (DSi_Firmware.bin) could
        only be rewritten through a same-named File call of another system,
        which then took the NDS hash and refused the dump it accepted."""
        call = f'File("{"0" * 40}", 131072, "DSi_Firmware.bin", "Other system");'
        exporter, entry, source, produced = self._export("DSi_Firmware.bin", call)
        self.assertEqual(produced, source)
        self.assertFalse(exporter.states(entry, "sha1"))


class RecalboxPatchesAttributesNotElements(unittest.TestCase):
    """A changed element was rendered again, losing its alignment and the
    place of its attributes, and an element whose md5 list was only
    reordered (neogeo.zip, the same 24 digests) was rewritten too."""

    def test_an_empty_truth_hands_back_the_file(self):
        path = UPSTREAM_CACHE / "recalbox" / "es_bios.xml"
        if not path.exists():
            self.skipTest("upstream cache not populated")
        original = path.read_text(encoding="utf-8")
        exporter = discover_exporters()["recalbox"]()
        config = native_layer(load_platform_config("recalbox", str(REPO_ROOT / "platforms")))
        systems, report = build_native_model({"systems": {}}, config)
        produced = exporter.render(systems, report, {"es_bios.xml": original}, config)
        self.assertEqual(produced["es_bios.xml"], original)

    def test_a_reordered_md5_list_states_the_same(self):
        from exporter.recalbox_exporter import _stated

        self.assertEqual(_stated('<bios path="a" md5="1,2" />'),
                         _stated('<bios path="a" md5="2,1" />'))

    def test_an_empty_md5_item_states_nothing(self):
        from exporter.recalbox_exporter import _stated

        self.assertEqual(_stated('<bios path="a" md5="B,,a, " />')["md5"], "a,b")

    def test_retrodeck_compares_md5_lists_as_sets(self):
        from core.hashing import parse_hash_list

        self.assertEqual(set(parse_hash_list(["A", "b"])), set(parse_hash_list("b, a")))

    def test_one_attribute_changes_in_place(self):
        from exporter.recalbox_exporter import patch_element

        kept = '    <bios path="kick.rom"          md5="aa" core="libretro/puae" />'
        mine = '    <bios path="kick.rom" md5="aa" core="libretro/puae" mandatory="false" />'
        self.assertEqual(patch_element(kept, mine),
                         '    <bios path="kick.rom"          md5="aa" core="libretro/puae"'
                         ' mandatory="false" />')
        dropped = patch_element(
            '    <bios path="x"   md5="aa" mandatory="false" core="c" />',
            '    <bios path="x" md5="bb" core="c" />')
        self.assertEqual(dropped, '    <bios path="x"   md5="bb" core="c" />')


class RetrobatListComesBackAsWritten(unittest.TestCase):
    """RetroBat separates each system with a blank line. json.dumps dropped
    all 100 of them, 100 hunks of noise in a diff meant to show
    corrections."""

    def test_an_empty_truth_hands_back_the_list(self):
        original_path = UPSTREAM_CACHE / "retrobat" / "batocera-systems.json"
        if not original_path.exists():
            self.skipTest("upstream cache not populated")
        original = original_path.read_text(encoding="utf-8")
        exporter = discover_exporters()["retrobat"]()
        config = native_layer(load_platform_config("retrobat", str(REPO_ROOT / "platforms")))
        systems, report = build_native_model({"systems": {}}, config)
        produced = exporter.render(systems, report, {"batocera-systems.json": original}, config)
        self.assertEqual(produced["batocera-systems.json"], original)

    def test_an_added_system_takes_the_same_separator(self):
        from exporter.retrobat_exporter import keep_blank_lines

        original = '{\n  "a": {},\n\n  "b": {}\n}\n'
        produced = '{\n  "a": {},\n  "b": {},\n  "c": {}\n}\n'
        self.assertEqual(keep_blank_lines(original, produced),
                         '{\n  "a": {},\n\n  "b": {},\n\n  "c": {}\n}\n')


class MisterDatabaseComesBackAsWritten(unittest.TestCase):
    """The BiosDB is one line of JSON. Written with indent=2 it came out as
    1499 changed lines for a database whose content had not changed."""

    def _render(self, truth: dict):
        archive = UPSTREAM_CACHE / "misterfpga" / "bios_db.json.zip"
        if not archive.exists():
            self.skipTest("upstream cache not populated")
        raw = archive.read_bytes()
        exporter = discover_exporters()["misterfpga"]()
        exporter.keep_archive("bios_db.json.zip", raw)
        originals = exporter.unpack(raw)
        config = native_layer(load_platform_config("misterfpga", str(REPO_ROOT / "platforms")))
        systems, report = build_native_model(truth, config)
        return raw, exporter.render(systems, report, originals, config)

    def test_the_archive_mister_fetches_is_published_as_it_came(self):
        """The Downloader fetches bios_db.json.zip, and the export gave only
        the JSON inside it."""
        raw, produced = self._render({"systems": {}})
        self.assertEqual(produced["bios_db.json.zip"], raw)

    def test_a_rebuilt_archive_keeps_the_member_as_mister_writes_it(self):
        raw, _ = self._render({"systems": {}})
        from exporter.misterfpga_exporter import rebuild_archive

        rebuilt = rebuild_archive(raw, "bios_db.json", '{"changed": true}')
        with zipfile.ZipFile(io.BytesIO(raw)) as before, \
                zipfile.ZipFile(io.BytesIO(rebuilt)) as after:
            old, new = before.infolist()[0], after.infolist()[0]
            self.assertEqual(after.read("bios_db.json"), b'{"changed": true}')
            self.assertEqual(
                (old.filename, old.date_time, old.compress_type, old.external_attr),
                (new.filename, new.date_time, new.compress_type, new.external_attr),
            )

    def test_bytes_are_written_untouched(self):
        from exporter.native import _write_produced

        with tempfile.TemporaryDirectory() as tmp:
            _write_produced(Path(tmp), {"a.zip": b"PK\x03\x04\xff"}, {})
            self.assertEqual((Path(tmp) / "a.zip").read_bytes(), b"PK\x03\x04\xff")

    def test_a_new_hash_without_a_size_leaves_the_entry_whole(self):
        """The Downloader checks each entry by size (fetch_file_worker.py:127):
        the old size beside the new hash described no file, and the report
        announced a size removal the database did not carry."""
        from exporter.landed import landed_changes

        database = {"db_id": "bios_db", "files": {
            "games/X/boot.rom": {"hash": "a" * 32, "size": 100, "url": "u"},
        }}
        original = json.dumps(database)
        scraped = {"systems": {"x": {"files": [{
            "name": "boot.rom", "destination": "X/boot.rom",
            "md5": "a" * 32, "size": 100,
        }]}}}
        truth = {"systems": {"x": {"files": [{
            "name": "boot.rom", "path": "X/boot.rom", "md5": "b" * 32, "_cores": ["x"],
        }]}}}
        exporter = discover_exporters()["misterfpga"]()
        systems, report = build_native_model(truth, scraped)
        produced = exporter.render(systems, report, {"bios_db.json": original}, scraped)
        self.assertEqual(produced["bios_db.json"], original)
        self.assertEqual(landed_changes(exporter, systems).records, [])
        self.assertEqual(len(exporter.withheld()), 1)
        self.assertEqual(exporter.validate(systems, produced), [])

    def test_a_kept_size_is_not_reported_removed(self):
        """The truth accepts MiSTer's hash and states other sizes, so no
        size of its own fits the entry. The render keeps MiSTer's size, and
        the report counted it removed."""
        database = {"db_id": "bios_db", "files": {
            "games/X/boot.rom": {"hash": "a" * 32, "size": 1000, "url": "u"},
        }}
        original = json.dumps(database)
        scraped = {"systems": {"x": {"files": [{
            "name": "boot.rom", "destination": "X/boot.rom", "md5": "a" * 32,
            "size": 1000,
        }]}}}
        truth = {"systems": {"x": {"files": [{
            "name": "boot.rom", "path": "X/boot.rom", "md5": "a" * 32,
            "size": [2000, 3000], "_cores": ["x"],
        }]}}}
        exporter = discover_exporters()["misterfpga"]()
        systems, report = build_native_model(truth, scraped)
        produced = exporter.render(systems, report, {"bios_db.json": original}, scraped)
        written = json.loads(produced["bios_db.json"])["files"]["games/X/boot.rom"]
        self.assertEqual(written["size"], 1000)
        self.assertNotIn(
            "size_removed",
            [c["kind"] for c in landed_changes(exporter, systems).records],
        )

    def test_an_accepted_hash_is_not_swapped_for_another(self):
        """The url serves MiSTer's dump, and the truth accepts it among two.
        The first accepted md5 went in its place with no change reported,
        and the Downloader refused every install of the file."""
        database = {"db_id": "bios_db", "files": {
            "games/X/boot.rom": {"hash": "b" * 32, "size": 10, "url": "u"},
        }}
        original = json.dumps(database)
        scraped = {"systems": {"x": {"files": [{
            "name": "boot.rom", "destination": "X/boot.rom", "md5": "b" * 32, "size": 10,
        }]}}}
        truth = {"systems": {"x": {"files": [{
            "name": "boot.rom", "path": "X/boot.rom", "md5": ["a" * 32, "b" * 32],
            "size": 10, "_cores": ["x"],
        }]}}}
        exporter = discover_exporters()["misterfpga"]()
        systems, report = build_native_model(truth, scraped)
        produced = exporter.render(systems, report, {"bios_db.json": original}, scraped)
        self.assertEqual(produced["bios_db.json"], original)
        self.assertEqual(exporter.validate(systems, produced), [])

    def test_an_empty_truth_hands_back_the_database(self):
        archive = UPSTREAM_CACHE / "misterfpga" / "bios_db.json.zip"
        if not archive.exists():
            self.skipTest("upstream cache not populated")
        exporter = discover_exporters()["misterfpga"]()
        originals = exporter.unpack(archive.read_bytes())
        config = native_layer(load_platform_config("misterfpga", str(REPO_ROOT / "platforms")))
        systems, report = build_native_model({"systems": {}}, config)
        produced = exporter.render(systems, report, originals, config)
        self.assertEqual(produced, originals)


class RecalboxKeepsUnchangedText(unittest.TestCase):
    """Every element the model held was re-rendered: attribute order,
    alignment, line breaks inside md5 and digest case changed in 222
    elements that said the same thing, 180 lines of diff nobody was told of."""

    def test_an_element_that_says_the_same_keeps_its_text(self):
        scraped = {"systems": {"sinclair-zxspectrum": {
            "native_id": "zxspectrum",
            "files": [{
                "name": "128p-0.rom", "destination": "fuse/128p-0.rom",
                "native_system": "zxspectrum", "native_name": "Pentagon",
                "native_path": "fuse/128p-0.rom", "md5": "a" * 32,
                "core": "libretro/fuse", "required": True,
            }],
        }}}
        written = f'    <bios path="fuse/128p-0.rom"    md5="{"A" * 32}"\n          core="libretro/fuse" />'
        original = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<biosList>\n'
            '  <system fullname="Pentagon" platform="zxspectrum">\n'
            f"{written}\n"
            "  </system>\n</biosList>\n"
        )
        systems, report = build_native_model({"systems": {}}, scraped)
        produced = discover_exporters()["recalbox"]().render(
            systems, report, {"es_bios.xml": original}, None
        )["es_bios.xml"]
        self.assertIn(written, produced)


if __name__ == "__main__":
    unittest.main()
