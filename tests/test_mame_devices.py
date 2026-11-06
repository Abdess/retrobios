"""Device ROM sets read from a MAME -listxml and merged into a profile.

Synthetic listxml and driver source, no network: the scan keeps only device
sets with dumped ROMs, the source line is the ROM_START block holding them,
and the merge adds sets, refreshes the contents of written ones without
touching what a reader wrote, and leaves BIOS root sets alone. Each set is
filed under the systems of the machines that can load it, never guessed.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.common import yaml_load
from scripts.scraper._hash_merge import (
    DEVICE_SECTION,
    SOFTLIST_SECTION,
    mame_ref_role,
    merge_mame_devices,
    merge_mame_profile,
    merge_mame_support,
)
from scripts.scraper.mame_devices import (
    ABSENT,
    AMBIGUOUS,
    NO_FILE,
    MachineLinks,
    attribute_softlists,
    attribute_systems,
    default_floppy_samples,
    device_systems,
    drive_form_factor,
    find_rom_block,
    floppy_drives,
    floppy_sample_systems,
    locate_sources,
    open_listxml,
    platform_seeds,
    profile_seeds,
    scan_device_sets,
    scan_release,
    selected_form_factor,
    source_path,
)

LISTXML = b"""<?xml version="1.0"?>
<!DOCTYPE mame [
<!ELEMENT mame (machine+)>
]>
<mame build="0.289 (mame0289)" debug="no" mameconfig="10">
\t<machine name="neogeo" sourcefile="snk/neogeo.cpp" isbios="yes">
\t\t<description>Neo-Geo MV-6F</description>
\t\t<rom name="sp-s2.sp1" size="131072" crc="9036d879" sha1="4f5ed7105b7128794654ce82b51723e16e389543" region="mainbios" offset="0"/>
\t</machine>
\t<machine name="qsound" sourcefile="devices/sound/qsound.cpp" isdevice="yes" runnable="no">
\t\t<description>QSound</description>
\t\t<rom name="dl-1425.bin" size="24576" crc="d6cf5ef5" sha1="555f50fe5cdf127619da7d854c03f4a244a0c501" region="dsp" offset="0"/>
\t</machine>
\t<machine name="kbd_new" sourcefile="devices/kbd.cpp" isdevice="yes" runnable="no">
\t\t<description>Keyboard &amp; Mouse - New</description>
\t\t<biosset name="v2" description="Version 2"/>
\t\t<rom name="6570-036" bios="v2" size="2048" crc="4a3fc332" sha1="83b21d0c8b93fc9b9b3b287fde4ec8f3badac5a2" region="mcu" offset="0"/>
\t\t<rom name="bad.bin" size="16" crc="00000011" sha1="0000000000000000000000000000000000000011" status="baddump" region="mcu" offset="0"/>
\t</machine>
\t<machine name="nodump_dev" sourcefile="devices/kbd.cpp" isdevice="yes" runnable="no">
\t\t<description>Undumped</description>
\t\t<rom name="missing.bin" size="1024" status="nodump" region="mcu" offset="0"/>
\t</machine>
\t<machine name="empty_dev" sourcefile="devices/kbd.cpp" isdevice="yes" runnable="no">
\t\t<description>No ROM</description>
\t</machine>
</mame>
"""

KBD_SOURCE = """// keyboards
ROM_START(kbd_old)
\tROM_REGION(0x0800, "mcu", 0)
\tROM_LOAD("6500-1", 0x0000, 0x0800, CRC(4a3fc332) SHA1(83b21d0c8b93fc9b9b3b287fde4ec8f3badac5a2) BAD_DUMP)
\tROM_LOAD("bad.bin", 0x0800, 0x0010, CRC(00000011) SHA1(0000000000000000000000000000000000000011))
ROM_END

ROM_START(kbd_new)
\tROM_REGION(0x0800, "mcu", 0)
\tROM_LOAD("6570-036", 0x0000, 0x0800, CRC(4a3fc332) SHA1(83b21d0c8b93fc9b9b3b287fde4ec8f3badac5a2))
\tROM_LOAD("bad.bin", 0x0800, 0x0010, CRC(00000011) SHA1(0000000000000000000000000000000000000011))
ROM_END
""".splitlines()

QSOUND_SOURCE = """#define QSOUND_ROMS \\
\tROM_LOAD16_WORD_SWAP("dl-1425.bin", 0x0000, 0x6000, CRC(d6cf5ef5) SHA1(555f50fe5cdf127619da7d854c03f4a244a0c501))

// ROM_START( commented ) CRC(d6cf5ef5)
ROM_START( qsound )
\tROM_REGION16_BE( 0x2000, "dsp", 0 )
\tQSOUND_ROMS
ROM_END
""".splitlines()

PROFILE = """emulator: MAME
source: "https://github.com/libretro/mame"
upstream: "https://github.com/mamedev/mame"
upstream_commit: "f34f02505e32c1993c6a782b6814232cbfc74e36"
core_version: "0.289"
files:
  # SNK Neo Geo
  - name: neogeo.zip
    required: true
    category: bios_zip
    system: snk-neogeo-mvs
    source_ref: "upstream src/mame/snk/neogeo.cpp:2400"
    contents:
      - name: "sp-s2.sp1"
        description: "Europe MVS (Ver. 2)"
        size: 131072
        crc32: "oldcrc32"

  - name: qsound.zip
    required: true
    category: bios_zip
    system: capcom-cps2
    source_ref: "upstream src/devices/sound/qsound.cpp:121-125"
    note: >-
      Written by hand.
    contents:
      - name: "dl-1425.bin"
        description: "QSound DSP microcode"
        size: 24576
        crc32: "d6cf5ef5"
"""


def _devices() -> dict[str, dict]:
    tag, devices = scan_device_sets(io.BytesIO(LISTXML))
    assert tag == "mame0289"
    return devices


def _fetch(path: str) -> list[str] | None:
    return {
        "src/devices/kbd.cpp": KBD_SOURCE,
        "src/devices/sound/qsound.cpp": QSOUND_SOURCE,
    }.get(path)


class ScanKeepsDeviceSetsWithDumpedRoms(unittest.TestCase):

    def test_only_devices_with_a_crc_are_kept(self):
        devices = _devices()
        self.assertEqual(sorted(devices), ["kbd_new", "qsound"])

    def test_rom_fields_bios_description_and_bad_dump(self):
        kbd = _devices()["kbd_new"]
        self.assertEqual(kbd["description"], "Keyboard & Mouse - New")
        self.assertEqual(kbd["sourcefile"], "devices/kbd.cpp")
        first, second = kbd["roms"]
        self.assertEqual(
            (first["name"], first["size"], first["crc32"], first["bios_description"]),
            ("6570-036", 2048, "4a3fc332", "Version 2"),
        )
        self.assertTrue(second["bad_dump"])

    def test_a_document_without_a_build_is_refused(self):
        with self.assertRaises(ValueError):
            scan_device_sets(io.BytesIO(b"<mame><machine name='x'></machine></mame>"))

    def test_the_release_zip_is_read(self):
        import zipfile

        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / "mame0289lx.zip"
            with zipfile.ZipFile(pack, "w") as archive:
                archive.writestr("mame0289.xml", LISTXML)
            with open_listxml(pack) as stream:
                tag, devices = scan_device_sets(stream)
        self.assertEqual((tag, sorted(devices)), ("mame0289", ["kbd_new", "qsound"]))

    def test_source_paths(self):
        self.assertEqual(source_path("devices/sound/qsound.cpp"), "src/devices/sound/qsound.cpp")
        self.assertEqual(source_path("snk/neogeo.cpp"), "src/mame/snk/neogeo.cpp")


class SourceLinesAreTheBlockHoldingTheRoms(unittest.TestCase):

    def test_found_through_a_rom_macro_past_a_comment(self):
        self.assertEqual(
            find_rom_block(QSOUND_SOURCE, "qsound", [("dl-1425.bin", "d6cf5ef5")]),
            ("5-8", ""),
        )

    def test_a_block_inside_a_comment_is_not_a_block(self):
        source = [
            "/* ROM_START( old )",
            '\tROM_LOAD("dl-1425.bin", 0, 0x6000, CRC(d6cf5ef5) SHA1(555f50fe5cdf127619da7d854c03f4a244a0c501))',
            "ROM_END */",
            "ROM_START( current )",
            '\tROM_LOAD("dl-1425.bin", 0, 0x6000, CRC(d6cf5ef5) SHA1(555f50fe5cdf127619da7d854c03f4a244a0c501))',
            "ROM_END",
        ]
        self.assertEqual(
            find_rom_block(source, "dsp", [("dl-1425.bin", "d6cf5ef5")]), ("4-6", "")
        )

    def test_same_dump_under_two_names_is_told_apart_by_name(self):
        line, _ = find_rom_block(
            KBD_SOURCE, "kbd_new", [("6570-036", "4a3fc332"), ("bad.bin", "00000011")]
        )
        self.assertEqual(line, "8-12")

    def test_not_found(self):
        self.assertEqual(
            find_rom_block(KBD_SOURCE, "x", [("x.bin", "deadbeef")]), (None, ABSENT)
        )

    def test_two_blocks_and_no_way_to_choose(self):
        self.assertEqual(
            find_rom_block(KBD_SOURCE, "other", [("bad.bin", "00000011")]),
            (None, AMBIGUOUS),
        )

    def test_the_label_device_rom_region_returns_settles_it(self):
        source = KBD_SOURCE + [
            'DEFINE_DEVICE_TYPE(KBD_X, kbd_x_device, "kbd_x", "Keyboard X")',
            "const tiny_rom_entry *kbd_x_device::device_rom_region() const",
            "{",
            "\treturn ROM_NAME(kbd_old);",
            "}",
        ]
        self.assertEqual(
            find_rom_block(source, "kbd_x", [("bad.bin", "00000011")]), ("2-6", "")
        )

    def test_locate_sources_reports_what_it_cannot_place(self):
        devices = _devices()
        devices["ghost"] = {
            "description": "Ghost", "sourcefile": "devices/ghost.cpp",
            "roms": [{"name": "g.bin", "size": 1, "crc32": "00000001", "sha1": ""}],
        }
        unplaced = locate_sources(devices, _fetch, workers=2)
        self.assertEqual(unplaced, {"ghost": NO_FILE})
        self.assertEqual(devices["qsound"]["source_file"], "src/devices/sound/qsound.cpp")
        self.assertEqual(devices["kbd_new"]["source_line"], "8-12")


class MergeIntoTheProfile(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "mame.yml"
        self.path.write_text(PROFILE, encoding="utf-8")
        self.devices = _devices()
        locate_sources(self.devices, _fetch, workers=2)

    def tearDown(self):
        self._tmp.cleanup()

    def _merge(self) -> dict[str, list[str]]:
        return merge_mame_devices(str(self.path), self.devices, write=True)

    def _entries(self) -> dict[str, dict]:
        data = yaml_load(self.path.read_text(encoding="utf-8"))
        return {f["name"]: f for f in data["files"]}

    def test_a_device_with_roms_is_added_under_the_section(self):
        report = self._merge()
        self.assertEqual(report["added"], ["kbd_new"])
        text = self.path.read_text(encoding="utf-8")
        self.assertLess(text.index(DEVICE_SECTION), text.index("- name: kbd_new.zip"))
        entry = self._entries()["kbd_new.zip"]
        self.assertIs(entry["required"], False)
        self.assertEqual(entry["category"], "bios_zip")
        self.assertEqual(entry["source_ref"], "upstream src/devices/kbd.cpp:8-12")
        self.assertEqual(
            entry["note"],
            "Device ROM set, loaded when a machine instantiates `Keyboard & Mouse - New`.",
        )
        self.assertEqual(entry["contents"][0]["description"], "`Version 2`")
        self.assertEqual(entry["contents"][0]["sha1"], "83b21d0c8b93fc9b9b3b287fde4ec8f3badac5a2")
        self.assertIs(entry["contents"][1]["bad_dump"], True)

    def test_devices_without_roms_are_not_written(self):
        self._merge()
        entries = self._entries()
        self.assertNotIn("nodump_dev.zip", entries)
        self.assertNotIn("empty_dev.zip", entries)

    def test_an_unplaced_set_is_written_without_a_line(self):
        del self.devices["kbd_new"]["source_line"]
        self._merge()
        self.assertNotIn("source_ref", self._entries()["kbd_new.zip"])

    def test_a_written_entry_gets_its_contents_and_keeps_the_rest(self):
        report = self._merge()
        self.assertEqual(report["updated"], ["qsound"])
        entry = self._entries()["qsound.zip"]
        self.assertIs(entry["required"], True)
        self.assertEqual(entry["system"], "capcom-cps2")
        self.assertEqual(entry["note"], "Written by hand.")
        self.assertEqual(entry["source_ref"], "upstream src/devices/sound/qsound.cpp:121-125")
        member = entry["contents"][0]
        self.assertEqual(member["description"], "QSound DSP microcode")
        self.assertEqual(member["sha1"], "555f50fe5cdf127619da7d854c03f4a244a0c501")

    def test_a_written_entry_without_a_ref_gets_the_found_one(self):
        self.path.write_text(
            PROFILE.replace('    source_ref: "upstream src/devices/sound/qsound.cpp:121-125"\n', ""),
            encoding="utf-8",
        )
        self._merge()
        self.assertEqual(
            self._entries()["qsound.zip"]["source_ref"],
            "upstream src/devices/sound/qsound.cpp:5-8",
        )

    def test_bios_roots_are_left_as_written(self):
        before = PROFILE[PROFILE.index("  # SNK"):PROFILE.index("  - name: qsound.zip")]
        self._merge()
        self.assertIn(before, self.path.read_text(encoding="utf-8"))

    def test_a_second_run_changes_nothing(self):
        self._merge()
        first = self.path.read_text(encoding="utf-8")
        report = self._merge()
        self.assertEqual((report["added"], report["updated"]), ([], []))
        self.assertEqual(self.path.read_text(encoding="utf-8"), first)

    def test_new_sets_keep_name_order_inside_the_section(self):
        self._merge()
        self.devices["aaa_dev"] = dict(self.devices["kbd_new"])
        self.devices["zzz_dev"] = dict(self.devices["kbd_new"])
        self._merge()
        text = self.path.read_text(encoding="utf-8")
        order = [text.index(f"- name: {n}.zip") for n in ("aaa_dev", "kbd_new", "zzz_dev")]
        self.assertEqual(order, sorted(order))
        self.assertTrue(text.endswith('        bad_dump: true\n'))

    def test_another_category_under_a_device_name_is_reported(self):
        self.path.write_text(
            PROFILE + "\n  - name: kbd_new.zip\n    category: game_data\n", encoding="utf-8"
        )
        report = self._merge()
        self.assertEqual(report["conflict"], ["kbd_new"])

    def test_a_new_bios_root_lands_before_the_device_section(self):
        self._merge()
        hashes = Path(self._tmp.name) / "h.json"
        hashes.write_text(json.dumps({
            "version": "0.289",
            "commit": "f34f02505e32c1993c6a782b6814232cbfc74e36",
            "bios_sets": {"newbios": {
                "source_file": "src/mame/x/x.cpp", "source_line": 7,
                "roms": [{"name": "n.bin", "size": 4, "crc32": "12345678"}],
            }},
        }), encoding="utf-8")
        merge_mame_profile(str(self.path), str(hashes), write=True)
        text = self.path.read_text(encoding="utf-8")
        self.assertLess(text.index("newbios.zip"), text.index(DEVICE_SECTION))
        self.assertEqual(self._entries()["newbios.zip"]["source_ref"], "upstream src/mame/x/x.cpp:7")
        self.assertIn("kbd_new.zip", self._entries())


class RefRole(unittest.TestCase):

    def test_a_port_cites_mamedev_as_upstream(self):
        self.assertEqual(mame_ref_role({
            "source": "https://github.com/libretro/mame",
            "upstream": "https://github.com/mamedev/mame",
        }), "upstream ")

    def test_a_profile_with_one_tree_cites_it_bare(self):
        self.assertEqual(mame_ref_role({"emulator": "MAME"}), "")


GRAPH_LISTXML = b"""<?xml version="1.0"?>
<mame build="0.289 (mame0289)" debug="no" mameconfig="10">
\t<machine name="neogeo" sourcefile="snk/neogeo.cpp" isbios="yes">
\t\t<device_ref tag=":ymsnd" name="ym2610"/>
\t</machine>
\t<machine name="mslug" sourcefile="snk/neogeo.cpp" romof="neogeo">
\t\t<device_ref tag=":ymsnd" name="ym2610"/>
\t\t<device_ref tag=":ng_memcard" name="ng_memcard"/>
\t</machine>
\t<machine name="mslugj" sourcefile="snk/neogeo.cpp" cloneof="mslug" romof="mslug">
\t\t<device_ref tag=":cart" name="cart_dev"/>
\t</machine>
\t<machine name="aes" sourcefile="snk/neogeo.cpp" isbios="yes">
\t\t<device_ref tag=":ymsnd" name="ym2610"/>
\t</machine>
\t<machine name="apple2gs" sourcefile="apple/apple2gs.cpp">
\t\t<slot name="sl1">
\t\t\t<slotoption name="disk2" devname="a2diskii"/>
\t\t\t<slotoption name="ser" devname="a2ssc" default="yes"/>
\t\t</slot>
\t</machine>
\t<machine name="a2diskii" sourcefile="devices/bus/a2bus/a2diskii.cpp" isdevice="yes" runnable="no">
\t\t<rom name="341-0027.bin" size="256" crc="ce7144f6" sha1="d4181c9f046aafc3fb326b381baac809d9e38d16" region="diskii_rom" offset="0"/>
\t\t<device_ref tag=":fdc" name="diskii_fdc"/>
\t</machine>
\t<machine name="diskii_fdc" sourcefile="devices/machine/wozfdc.cpp" isdevice="yes" runnable="no">
\t\t<rom name="341-0028.bin" size="256" crc="b72a2c70" sha1="bc39fbd5b9a8d2287ac5d0a42e639fc4d3c2f9d4" region="p6" offset="0"/>
\t</machine>
\t<machine name="a2ssc" sourcefile="devices/bus/a2bus/ssc.cpp" isdevice="yes" runnable="no">
\t\t<rom name="341-0065-a.bin" size="2048" crc="67dcf3f0" sha1="8d4ed4ee4d8fc2b8b0c09e7b23b7c1f4e1d4aa51" region="ssc_rom" offset="0"/>
\t</machine>
\t<machine name="ym2610" sourcefile="devices/sound/ymopn.cpp" isdevice="yes" runnable="no">
\t\t<rom name="ym2610.bin" size="16" crc="00000001" sha1="0000000000000000000000000000000000000001" region="r" offset="0"/>
\t</machine>
\t<machine name="ng_memcard" sourcefile="devices/machine/ng_memcard.cpp" isdevice="yes" runnable="no">
\t\t<rom name="mc.bin" size="16" crc="00000002" sha1="0000000000000000000000000000000000000002" region="r" offset="0"/>
\t</machine>
\t<machine name="cart_dev" sourcefile="devices/bus/neogeo/cart.cpp" isdevice="yes" runnable="no" romof="cart_base">
\t\t<rom name="c.bin" size="16" crc="00000003" sha1="0000000000000000000000000000000000000003" region="r" offset="0"/>
\t</machine>
\t<machine name="cart_base" sourcefile="devices/bus/neogeo/cart.cpp" isdevice="yes" runnable="no">
\t\t<rom name="b.bin" size="16" crc="00000004" sha1="0000000000000000000000000000000000000004" region="r" offset="0"/>
\t</machine>
\t<machine name="pc_kbd" sourcefile="devices/bus/pc_kbd/kbd.cpp" isdevice="yes" runnable="no">
\t\t<rom name="k.bin" size="16" crc="00000005" sha1="0000000000000000000000000000000000000005" region="r" offset="0"/>
\t</machine>
\t<machine name="ibm5150" sourcefile="ibm/ibmpc.cpp">
\t\t<device_ref tag=":kbd" name="pc_kbd"/>
\t</machine>
</mame>
"""

SEEDS = {"neogeo": "snk-neogeo-mvs", "apple2gs": "apple2gs"}


def _release():
    return scan_release(io.BytesIO(GRAPH_LISTXML))


class TheListxmlSaysWhoLoadsASet(unittest.TestCase):
    """infoxml.cpp writes romof, device_ref and slotoption: the scan keeps
    them for every element, device or machine."""

    def test_links(self):
        machines = _release().machines
        self.assertEqual(
            machines["mslugj"],
            MachineLinks("mslug", False, ("cart_dev",), (), "snk/neogeo.cpp"),
        )
        self.assertEqual(machines["apple2gs"].uses, ("a2diskii", "a2ssc"))
        # A device's ROMs are searched in its parent ROM device's set too.
        self.assertEqual(machines["cart_dev"].uses, ("cart_base",))
        self.assertTrue(machines["cart_dev"].isdevice)

    def test_scan_device_sets_is_the_same_scan(self):
        release = _release()
        self.assertEqual(
            scan_device_sets(io.BytesIO(GRAPH_LISTXML)), (release.tag, release.devices)
        )


class DeviceSetsFollowTheMachinesThatLoadThem(unittest.TestCase):

    def setUp(self):
        self.systems = attribute_systems(_release().machines, SEEDS)

    def test_a_clone_reaches_the_bios_through_its_parent(self):
        self.assertEqual(self.systems["cart_dev"], ["snk-neogeo-mvs"])
        self.assertEqual(self.systems["ng_memcard"], ["snk-neogeo-mvs"])

    def test_a_parent_rom_device_goes_with_its_child(self):
        self.assertEqual(self.systems["cart_base"], ["snk-neogeo-mvs"])

    def test_slot_cards_and_their_own_devices(self):
        self.assertEqual(self.systems["a2ssc"], ["apple2gs"])
        self.assertEqual(self.systems["a2diskii"], ["apple2gs"])
        self.assertEqual(self.systems["diskii_fdc"], ["apple2gs"])

    def test_a_machine_no_entry_places_files_nothing(self):
        # aes shares neogeo.cpp with the MVS but no entry lists it: the
        # driver file is not a system, so ym2610 gets the MVS only through
        # the MVS machines, and pc_kbd nothing at all.
        self.assertEqual(self.systems["ym2610"], ["snk-neogeo-mvs"])
        self.assertNotIn("pc_kbd", self.systems)

    def test_several_systems(self):
        systems = attribute_systems(_release().machines, {**SEEDS, "aes": "snk-neogeo-aes"})
        self.assertEqual(systems["ym2610"], ["snk-neogeo-aes", "snk-neogeo-mvs"])
        self.assertEqual(systems["ng_memcard"], ["snk-neogeo-mvs"])

    def test_a_device_seed_passes_to_what_it_uses_never_up_its_romof(self):
        systems = attribute_systems(
            _release().machines, {"a2diskii": "apple2gs", "cart_base": "x-system"}
        )
        self.assertEqual(systems["diskii_fdc"], ["apple2gs"])
        self.assertNotIn("cart_dev", systems)

    def test_seeds_are_the_written_entries_only(self):
        text = (
            PROFILE + "\n" + DEVICE_SECTION + "\n  - name: ym2610.zip\n"
            "    required: false\n    category: bios_zip\n    system: snk-neogeo-mvs\n"
        )
        self.assertEqual(
            profile_seeds(text), {"neogeo": "snk-neogeo-mvs", "qsound": "capcom-cps2"}
        )


class MachinesNoEntryPlacesCountUnderArcade(unittest.TestCase):
    """MAME starts any machine from its set name: a machine no seed places
    is one an arcade folder can pass it, so its devices go under arcade."""

    def test_a_set_only_unplaced_machines_load(self):
        systems = device_systems(_release().machines, SEEDS, "arcade")
        # ibm5150 is no system of the profile, and pc_kbd only it loads.
        self.assertEqual(systems["pc_kbd"], ["arcade"])

    def test_a_set_both_kinds_load_keeps_both(self):
        # aes is placed by no seed and loads ym2610, as the MVS does.
        systems = device_systems(_release().machines, SEEDS, "arcade")
        self.assertEqual(systems["ym2610"], ["arcade", "snk-neogeo-mvs"])
        self.assertEqual(systems["a2diskii"], ["apple2gs"])
        self.assertEqual(systems["cart_dev"], ["snk-neogeo-mvs"])

    def test_a_set_no_machine_instantiates_keeps_none(self):
        machines = {
            **_release().machines,
            "orphan": MachineLinks("", True, ()),
        }
        systems = device_systems(machines, SEEDS, "arcade")
        self.assertNotIn("orphan", systems)

    def test_no_fallback_listed_is_attribute_systems(self):
        machines = _release().machines
        self.assertEqual(
            device_systems(machines, SEEDS, ""), attribute_systems(machines, SEEDS)
        )


class TheMergeWritesTheSystems(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "mame.yml"
        self.path.write_text(PROFILE, encoding="utf-8")
        self.devices = _release().devices
        self.devices["qsound"] = _devices()["qsound"]
        systems = attribute_systems(_release().machines, SEEDS)
        for name, device in self.devices.items():
            device["systems"] = systems.get(name, [])

    def tearDown(self):
        self._tmp.cleanup()

    def _merge(self) -> dict[str, list[str]]:
        return merge_mame_devices(str(self.path), self.devices, write=True)

    def _entries(self) -> dict[str, dict]:
        data = yaml_load(self.path.read_text(encoding="utf-8"))
        return {f["name"]: f for f in data["files"]}

    def test_one_system_several_or_none(self):
        self.devices["ym2610"]["systems"] = ["snk-neogeo-aes", "snk-neogeo-mvs"]
        self._merge()
        entries = self._entries()
        self.assertEqual(entries["a2diskii.zip"]["system"], "apple2gs")
        self.assertNotIn("systems", entries["a2diskii.zip"])
        self.assertEqual(entries["ym2610.zip"]["systems"], ["snk-neogeo-aes", "snk-neogeo-mvs"])
        self.assertNotIn("system", entries["ym2610.zip"])
        self.assertNotIn("system", entries["pc_kbd.zip"])
        self.assertNotIn("systems", entries["pc_kbd.zip"])
        text = self.path.read_text(encoding="utf-8")
        block = text[text.index("- name: a2diskii.zip"):]
        self.assertLess(block.index("category: bios_zip"), block.index("system: apple2gs"))

    def test_a_written_entry_keeps_its_system(self):
        self.devices["qsound"]["systems"] = ["apple2gs"]
        self._merge()
        self.assertEqual(self._entries()["qsound.zip"]["system"], "capcom-cps2")

    def test_a_refresh_rewrites_the_generated_systems(self):
        self._merge()
        self.devices["a2diskii"]["systems"] = ["apple2gs", "coco"]
        self.devices["cart_dev"]["systems"] = []
        report = self._merge()
        self.assertIn("a2diskii", report["updated"])
        entries = self._entries()
        self.assertEqual(entries["a2diskii.zip"]["systems"], ["apple2gs", "coco"])
        self.assertNotIn("system", entries["cart_dev.zip"])
        self.devices["a2diskii"]["systems"] = ["coco"]
        self._merge()
        entries = self._entries()
        self.assertEqual(entries["a2diskii.zip"]["system"], "coco")
        self.assertNotIn("systems", entries["a2diskii.zip"])
        # The list items of systems: went with it, the member list did not.
        self.assertEqual(entries["a2diskii.zip"]["contents"][0]["name"], "341-0027.bin")

    def test_a_second_run_changes_nothing(self):
        self._merge()
        first = self.path.read_text(encoding="utf-8")
        report = self._merge()
        self.assertEqual(report["updated"], [])
        self.assertEqual(self.path.read_text(encoding="utf-8"), first)


class APickReadsTheEntrySystems(unittest.TestCase):
    """--system on a pack and on the installer selects by the entry's own
    systems: before the profile's."""

    SYSTEMS = ["apple2gs", "coco", "snk-neogeo-mvs"]

    def test_entry_system_ids(self):
        from scripts.common import entry_system_ids

        profile = {"systems": self.SYSTEMS}
        self.assertEqual(entry_system_ids({"system": "coco"}, profile), ["coco"])
        self.assertEqual(
            entry_system_ids({"systems": ["apple2gs", "coco"]}, profile), ["apple2gs", "coco"]
        )
        self.assertEqual(entry_system_ids({}, profile), self.SYSTEMS)

    def test_entry_serves_systems(self):
        from scripts.common import entry_serves_systems

        profile = {"systems": self.SYSTEMS}
        entry = {"systems": ["apple2gs", "coco"]}
        self.assertTrue(entry_serves_systems(entry, profile, ["coco"]))
        self.assertFalse(entry_serves_systems(entry, profile, ["snk-neogeo-mvs"]))
        self.assertTrue(entry_serves_systems({}, profile, ["snk-neogeo-mvs"]))

    def test_the_gap_report_and_the_extras_carry_them(self):
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from packextras import _collect_emulator_extras, _extra_system_ids
        from verify import find_undeclared_files

        profile = {
            "emulator": "MAME", "type": "libretro", "systems": self.SYSTEMS,
            "files": [{"name": "a2diskii.zip", "category": "bios_zip",
                       "systems": ["apple2gs", "coco"]}],
        }
        config = {"cores": ["mame"], "systems": {}}
        db = {
            "files": {"s1": {"name": "a2diskii.zip", "path": "bios/Apple/a2diskii.zip",
                             "size": 10, "sha1": "s1", "md5": "m1", "crc32": "12345678"}},
            "indexes": {"by_name": {"a2diskii.zip": ["s1"]}, "by_md5": {"m1": "s1"},
                        "by_crc32": {"12345678": "s1"}},
        }
        (gap,) = find_undeclared_files(config, "emulators", db, emu_profiles={"mame": profile})
        self.assertEqual(gap["systems"], ["apple2gs", "coco"])
        (extra,) = _collect_emulator_extras(
            config, "emulators", db, set(), "", {"mame": profile}, include_all=True
        )
        self.assertEqual(_extra_system_ids(extra), ["apple2gs", "coco"])

    def test_the_schema_and_the_profile_list(self):
        try:
            from scripts import validate_schemas
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")
        validator = validate_schemas._validator("emulator.schema.json")
        root = Path(__file__).resolve().parents[1]
        base = {"emulator": "x", "type": "libretro", "systems": ["a", "b"]}
        both = {**base, "files": [{"name": "x.zip", "system": "a", "systems": ["a", "b"]}]}
        self.assertTrue(list(validator.iter_errors(both)))
        one = {**base, "files": [{"name": "x.zip", "systems": ["a"]}]}
        self.assertTrue(list(validator.iter_errors(one)))
        fine = {**base, "files": [{"name": "x.zip", "systems": ["a", "b"]}]}
        self.assertEqual(list(validator.iter_errors(fine)), [])
        outside = {**base, "files": [{"name": "x.zip", "systems": ["a", "c"]}]}
        found = validate_schemas._systems_outside_profile(root / "emulators" / "x.yml", outside)
        self.assertEqual(len(found), 1)
        self.assertIn("system c", found[0])
        single = {**base, "files": [{"name": "x.zip", "system": "c"}]}
        found = validate_schemas._systems_outside_profile(root / "emulators" / "x.yml", single)
        self.assertEqual(len(found), 1)
        self.assertIn("system c", found[0])
        listed = {**base, "files": [{"name": "x.zip", "system": "a"}]}
        self.assertEqual(
            validate_schemas._systems_outside_profile(root / "emulators" / "x.yml", listed), []
        )


SUPPORT_LISTXML = b"""<?xml version="1.0"?>
<mame build="0.289 (mame0289)" debug="no" mameconfig="10">
\t<machine name="bbcb" sourcefile="acorn/bbcb.cpp">
\t\t<device_ref tag=":fdc:0:525qd" name="floppy_525_qd"/>
\t\t<softwarelist tag="flop_ls" name="bbc_flop" status="original"/>
\t</machine>
\t<machine name="bbcbus" sourcefile="acorn/bbcb.cpp" cloneof="bbcb" romof="bbcb">
\t\t<softwarelist tag="flop_ls" name="bbc_flop_us" status="original"/>
\t</machine>
\t<machine name="apple2gs" sourcefile="apple/apple2gs.cpp">
\t\t<slot name="sl6">
\t\t\t<slotoption name="disk" devname="a2disk35"/>
\t\t</slot>
\t</machine>
\t<machine name="a2disk35" sourcefile="devices/bus/a2bus/a2disk35.cpp" isdevice="yes" runnable="no">
\t\t<device_ref tag=":0:35dd" name="floppy_35_dd"/>
\t\t<softwarelist tag="flop35" name="apple2gs_flop" status="original"/>
\t</machine>
\t<machine name="pcw" sourcefile="amstrad/pcw.cpp">
\t\t<device_ref tag=":0:3" name="floppy_3_sssd"/>
\t</machine>
\t<machine name="ibm5150" sourcefile="ibm/ibmpc.cpp">
\t\t<device_ref tag=":0:8" name="floppy_8_sssd"/>
\t\t<softwarelist tag="flop" name="ibm5150" status="original"/>
\t</machine>
\t<machine name="floppy_525_qd" sourcefile="devices/imagedev/floppy.cpp" isdevice="yes" runnable="no">
\t\t<device_ref tag=":flopsnd" name="flopsnd"/>
\t</machine>
\t<machine name="floppy_35_dd" sourcefile="devices/imagedev/floppy.cpp" isdevice="yes" runnable="no">
\t\t<device_ref tag=":flopsnd" name="flopsnd"/>
\t</machine>
\t<machine name="floppy_3_sssd" sourcefile="devices/imagedev/floppy.cpp" isdevice="yes" runnable="no">
\t\t<device_ref tag=":flopsnd" name="flopsnd"/>
\t</machine>
\t<machine name="floppy_8_sssd" sourcefile="devices/imagedev/floppy.cpp" isdevice="yes" runnable="no">
\t\t<device_ref tag=":flopsnd" name="flopsnd"/>
\t</machine>
\t<machine name="flopsnd" sourcefile="devices/imagedev/floppy.cpp" isdevice="yes" runnable="no">
\t</machine>
</mame>
"""

SUPPORT_SEEDS = {"bbcb": "acorn-bbc-micro", "apple2gs": "apple2gs", "pcw": "pcw"}

FLOPPY_CPP = """\
floppy_sound_device::floppy_sound_device(const machine_config &mconfig, const char *tag)
\t: samples_device(mconfig, FLOPPYSOUND, tag, owner, clock),
\tm_spin_kind(floppy_sound_samples::QUIET)
{
\t// m_default_samples.add_spin_sample("commented_out", 0);
\tm_default_samples.set_form_factor(floppy_image::FF_35, "floppy");
\tm_default_samples.add_spin_sample("35_spin", floppy_sound_samples::START_EMPTY);
\tm_default_samples.add_seek_sample("35_seek", 2, 3);
\tm_default_samples.set_form_factor(floppy_image::FF_525, "floppy");
\tm_default_samples.add_step_sample("525_step");
}

DEFINE_DEVICE_TYPE(FLOPPY_35_DD, floppy_35_dd, "floppy_35_dd", "3.5 inch drive")
DEFINE_DEVICE_TYPE(FLOPPY_525_QD, floppy_525_qd, "floppy_525_qd", "5.25 inch drive")
DEFINE_DEVICE_TYPE(FLOPPY_3_SSSD, floppy_3_sssd, "floppy_3_sssd", "3 inch drive")
DEFINE_DEVICE_TYPE(FLOPPY_8_SSSD, floppy_8_sssd, "floppy_8_sssd", "8 inch drive")

void floppy_35_dd::setup_characteristics()
{
\tm_form_factor = floppy_image::FF_35;
}

void floppy_525_qd::setup_characteristics()
{
\tm_form_factor = floppy_image::FF_525;
}

void floppy_3_sssd::setup_characteristics()
{
\tm_form_factor = floppy_image::FF_3;
}

void floppy_8_sssd::setup_characteristics()
{
\tm_form_factor = floppy_image::FF_8;
}
"""


def _support():
    machines = scan_release(io.BytesIO(SUPPORT_LISTXML)).machines
    return machines, attribute_systems(machines, SUPPORT_SEEDS)


class SoftwareListsFollowTheMachinesThatDeclareThem(unittest.TestCase):
    """software_list_device::parse opens <list>.xml for each list a machine
    declares: a --system pick needs the lists of that system's machines."""

    def test_the_scan_keeps_lists_and_source_files(self):
        machines = scan_release(io.BytesIO(SUPPORT_LISTXML)).machines
        self.assertEqual(machines["bbcb"].softlists, ("bbc_flop",))
        self.assertEqual(machines["a2disk35"].sourcefile, "devices/bus/a2bus/a2disk35.cpp")

    def test_lists_of_machines_clones_and_slot_cards(self):
        lists = attribute_softlists(*_support())
        self.assertEqual(lists["bbc_flop"], ["acorn-bbc-micro"])
        self.assertEqual(lists["bbc_flop_us"], ["acorn-bbc-micro"])
        self.assertEqual(lists["apple2gs_flop"], ["apple2gs"])
        # No entry places the PC: its list serves no system of the profile.
        self.assertNotIn("ibm5150", lists)


class FloppySamplesFollowTheDrives(unittest.TestCase):
    """Every drive adds a floppy sound device that loads the default list of
    the form factor its drive selects (floppy.cpp:1428-1473, 1709-1738)."""

    def test_default_list_by_form_factor(self):
        self.assertEqual(
            default_floppy_samples(FLOPPY_CPP),
            {"35_spin": "FF_35", "35_seek": "FF_35", "525_step": "FF_525"},
        )

    def test_drive_form_factor(self):
        self.assertEqual(drive_form_factor(FLOPPY_CPP, "floppy_35_dd"), "FF_35")
        self.assertEqual(drive_form_factor(FLOPPY_CPP, "floppy_3_sssd"), "FF_3")
        self.assertEqual(drive_form_factor(FLOPPY_CPP, "missing"), "")

    def test_select_falls_back_like_the_code(self):
        available = {"FF_35", "FF_525"}
        self.assertEqual(selected_form_factor("FF_35", available), "FF_35")
        self.assertEqual(selected_form_factor("FF_3", available), "FF_35")
        self.assertEqual(selected_form_factor("FF_8", available), "FF_525")
        self.assertEqual(selected_form_factor("FF_TWIG", available), "FF_525")
        self.assertEqual(selected_form_factor("FF_3", {"FF_525"}), "FF_525")
        self.assertEqual(selected_form_factor("FF_35", set()), "")

    def test_samples_go_to_the_systems_of_the_drives(self):
        machines, systems = _support()
        self.assertEqual(
            floppy_drives(machines),
            ["floppy_35_dd", "floppy_3_sssd", "floppy_525_qd", "floppy_8_sssd"],
        )
        samples = default_floppy_samples(FLOPPY_CPP)
        form_factors = {d: drive_form_factor(FLOPPY_CPP, d) for d in floppy_drives(machines)}
        found = floppy_sample_systems(machines, systems, samples, form_factors)
        self.assertEqual(found["35_spin"], ["apple2gs", "pcw"])
        self.assertEqual(found["525_step"], ["acorn-bbc-micro"])

    def test_an_unread_form_factor_loads_every_list(self):
        machines, systems = _support()
        samples = default_floppy_samples(FLOPPY_CPP)
        found = floppy_sample_systems(machines, systems, samples, {})
        self.assertEqual(found["525_step"], ["acorn-bbc-micro", "apple2gs", "pcw"])


class PlatformFilesSeedMachines(unittest.TestCase):

    def test_a_platform_statement_seeds_a_machine(self):
        machines = scan_release(io.BytesIO(SUPPORT_LISTXML)).machines
        seeds, conflicts = platform_seeds(
            [
                ("bbcb.zip", "acorn-bbc-micro"),
                ("bbcb.zip", "bbcmicro"),  # not a system of the profile
                ("ibm5150.zip", "ibm-pc"),  # idem
                ("a2disk35.zip", "apple2gs"),  # a device, not a machine
                ("pcw.zip", "pcw"),  # written by the profile
                ("apple2gs.zip", "apple2gs"),
                ("apple2gs.zip", "acorn-bbc-micro"),
                ("missing.zip", "pcw"),
                ("bbcb.rom", "acorn-bbc-micro"),
            ],
            machines,
            ["acorn-bbc-micro", "apple2gs", "pcw"],
            {"pcw": "pcw"},
        )
        self.assertEqual(seeds, {"bbcb": "acorn-bbc-micro"})
        self.assertEqual(conflicts, {"apple2gs": ["acorn-bbc-micro", "apple2gs"]})


SUPPORT_PROFILE = """emulator: MAME
source: "https://github.com/libretro/mame"
upstream: "https://github.com/mamedev/mame"
systems:
  - acorn-bbc-micro
  - apple2gs
files:
  - name: "hash/"
    path: "mame/hash/"
    type: directory
    mode: libretro
    category: game_data
    required: false

  - name: "hash/"
    path: "hash/"
    type: directory
    mode: standalone
    category: game_data
    required: false
    bundled: true

  - name: "35_spin.wav"
    path: "mame/samples/floppy/35_spin.wav"
    mode: libretro
    category: game_data
    required: false
    size: 4

  - name: "525_step.wav"
    path: "mame/samples/floppy/525_step.wav"
    mode: libretro
    category: game_data
    system: pcw
    required: false

  - name: neogeo.zip
    required: true
    category: bios_zip
    system: acorn-bbc-micro
"""


class TheSupportMergeWritesListsAndSamples(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "mame.yml"
        self.path.write_text(
            SUPPORT_PROFILE + "\n" + DEVICE_SECTION + "\n\n  - name: ym2610.zip\n"
            "    required: false\n    category: bios_zip\n",
            encoding="utf-8",
        )
        self.lists = {"bbc_flop": ["acorn-bbc-micro"], "apple2gs_flop": ["acorn-bbc-micro", "apple2gs"]}
        self.samples = {"35_spin": ["apple2gs"]}

    def tearDown(self):
        self._tmp.cleanup()

    def _merge(self) -> dict:
        return merge_mame_support(str(self.path), self.lists, self.samples, write=True)

    def _entries(self) -> list[dict]:
        return yaml_load(self.path.read_text(encoding="utf-8"))["files"]

    def test_one_entry_per_list_under_the_delivered_tree(self):
        self._merge()
        text = self.path.read_text(encoding="utf-8")
        self.assertLess(text.index(SOFTLIST_SECTION), text.index(DEVICE_SECTION))
        lists = [e for e in self._entries() if str(e["name"]).endswith(".xml")]
        self.assertEqual(
            [(e["name"], e["mode"], e.get("system"), e.get("systems")) for e in lists],
            [
                ("apple2gs_flop.xml", "libretro", None, ["acorn-bbc-micro", "apple2gs"]),
                ("bbc_flop.xml", "libretro", "acorn-bbc-micro", None),
            ],
        )
        self.assertFalse(any(str(e.get("path")).startswith("hash/") and e["name"] != "hash/"
                             for e in self._entries()))
        self.assertIn("upstream src/emu/softlist_dev.cpp:281-313", text)

    def test_samples_get_the_systems_of_their_drives(self):
        self._merge()
        entries = {e["name"]: e for e in self._entries()}
        self.assertEqual(entries["35_spin.wav"]["system"], "apple2gs")
        self.assertEqual(entries["35_spin.wav"]["size"], 4)
        # No drive of a profile system loads it any more: it serves them all.
        self.assertNotIn("system", entries["525_step.wav"])
        self.assertEqual(entries["neogeo.zip"]["system"], "acorn-bbc-micro")

    def test_a_refresh_rewrites_the_section(self):
        self._merge()
        self.lists = {"bbc_flop": ["apple2gs"]}
        self._merge()
        names = [e["name"] for e in self._entries()]
        self.assertNotIn("apple2gs_flop.xml", names)
        self.assertEqual(names.count("bbc_flop.xml"), 1)
        self.assertEqual(names[-1], "ym2610.zip")
        self.lists = {}
        self._merge()
        self.assertNotIn(SOFTLIST_SECTION, self.path.read_text(encoding="utf-8"))

    def test_a_second_run_changes_nothing(self):
        self._merge()
        first = self.path.read_text(encoding="utf-8")
        report = self._merge()
        self.assertEqual(report["changed"], [])
        self.assertEqual(report["samples"], [])
        self.assertEqual(self.path.read_text(encoding="utf-8"), first)

    def test_new_bios_roots_and_seeds_stay_ahead_of_the_sections(self):
        self._merge()
        text = self.path.read_text(encoding="utf-8")
        self.assertEqual(profile_seeds(text), {"neogeo": "acorn-bbc-micro"})

    def test_a_pick_takes_its_lists_and_leaves_the_others(self):
        from scripts.common import entry_serves_systems, expand_directory_entries

        self._merge()
        profile = yaml_load(self.path.read_text(encoding="utf-8"))
        db = {"files": {}, "indexes": {"by_path_suffix": {}}}
        for index, dest in enumerate(
            ["mame/hash/bbc_flop.xml", "mame/hash/apple2gs_flop.xml", "mame/hash/nes.xml"]
        ):
            sha1 = f"{index:040d}"
            db["files"][sha1] = {"path": f"bios/Other/{dest}", "name": dest.rsplit("/", 1)[1]}
            db["indexes"]["by_path_suffix"][dest] = [sha1]
        files = [e for e in profile["files"] if e.get("mode") != "standalone"]
        files = expand_directory_entries(files, db)
        picked = sorted(
            str(e.get("path"))
            for e in files
            if str(e.get("path", "")).startswith("mame/hash/")
            and entry_serves_systems(e, profile, ["apple2gs"])
        )
        self.assertEqual(picked, ["mame/hash/apple2gs_flop.xml", "mame/hash/nes.xml"])


class TheRepositoryProfile(unittest.TestCase):
    """mame.yml as committed: every list filed is one the hash tree holds."""

    def test_generated_lists_sit_inside_the_hash_tree(self):
        path = Path(__file__).resolve().parents[1] / "emulators" / "mame.yml"
        text = path.read_text(encoding="utf-8")
        start = text.find(SOFTLIST_SECTION)
        self.assertNotEqual(start, -1)
        section = yaml_load("files:\n" + text[start:text.index(DEVICE_SECTION)])["files"]
        self.assertTrue(section)
        for entry in section:
            self.assertEqual(entry["path"], "mame/hash/" + entry["name"])
            self.assertTrue(entry.get("system") or entry.get("systems"), entry["name"])


class Cli(unittest.TestCase):

    def test_devices_needs_a_listxml(self):
        from scripts.scraper.mame_hash_scraper import build_parser, main  # noqa: F401
        import sys
        from unittest import mock

        with mock.patch.object(sys, "argv", ["x", "--devices"]), \
                mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main()
        self.assertEqual(raised.exception.code, 2)


class TheDevicesFollowTheRelease(unittest.TestCase):
    """Pipeline step 2a moved mame.yml to a new release and left the device
    sets on the lines of the previous one: the profile named two releases."""

    def _run(self, moves: bool, dry_run: bool = False) -> list:
        import argparse
        from unittest import mock

        from scripts.scraper import mame_hash_scraper as scraper

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "mame.yml"
            profile.write_text('core_version: "0.289"\nfiles: []\n')

            def merge(path, *_args, **_kwargs):
                if moves:
                    profile.write_text('core_version: "0.290"\nfiles: []\n')

            merged = []
            with mock.patch.multiple(
                scraper,
                _EMULATORS_DIR=Path(directory),
                _fetch_hashes=lambda force: {"bios_sets": {}, "version": "0.290"},
                _find_mame_profiles=lambda: [profile],
                compute_diff=lambda *a, **k: {"updated": ["x"], "added": []},
                _format_diff=lambda *a, **k: [],
                merge_mame_profile=merge,
                fetch_release_listxml=lambda version: Path(f"mame{version}lx.zip"),
                _merge_devices=merged.append,
            ), mock.patch("sys.stdout", new=io.StringIO()):
                scraper._run(argparse.Namespace(force=False, json=False, dry_run=dry_run))
            return merged

    def test_a_moved_pin_merges_that_release_devices(self):
        (args,) = self._run(moves=True)
        self.assertEqual(args.listxml, Path("mame0.290lx.zip"))
        self.assertFalse(args.dry_run)

    def test_an_unmoved_pin_leaves_the_devices(self):
        self.assertEqual(self._run(moves=False), [])
        self.assertEqual(self._run(moves=True, dry_run=True), [])


if __name__ == "__main__":
    unittest.main()
