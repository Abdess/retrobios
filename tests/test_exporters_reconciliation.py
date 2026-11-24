"""Native export reconciliation: platform entries against the truth.

An entry the platform declares is never removed, additions follow the
search order of the code, and each addition carries the runner that wants it.
"""

from __future__ import annotations

import tests

import io
import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from exporter import discover_exporters
from exporter.base_exporter import BaseExporter
from exporter.landed import landed_changes
from resolve.nativemodel import NativeFile, NativeSystem, Report
from resolve.reconcile import build_native_model
from tests.exporterssupport import PROFILES, model


class Reconciliation(unittest.TestCase):
    """The platform's file corrected, not replaced by ours."""

    def test_a_bare_truth_name_is_not_a_path_suffix(self):
        """fbneo's boot.bin has no path, while libretro's dc/boot.bin ends in
        /boot.bin. The suffix paired them past the size guard and wrote the
        480-byte file's size and hashes over the 2 MB Dreamcast BIOS."""
        truth = {"systems": {"sega-dreamcast": {"files": [
            {"name": "boot.bin", "size": 480, "crc32": "f0774fc2"}]}}}
        scraped = {"systems": {"sega-dreamcast": {"native_id": "dc", "files": [
            {"name": "boot.bin", "destination": "dc/boot.bin", "native_system": "dc",
             "size": 2097152, "crc32": "89f2b1a1"}]}}}
        systems, report = build_native_model(truth, scraped)
        platform_entry = next(
            fe for fe in systems["dc"].files if fe.destination == "dc/boot.bin"
        )
        self.assertIsNone(platform_entry.truth)
        self.assertEqual(report.hashes_corrected, [])

    def test_a_contradicted_hash_takes_no_platform_size(self):
        """geolith's neocdz.zip md5 contradicts System.dat's: the export
        wrote that md5 beside System.dat's 953078 bytes."""
        entry = NativeFile(
            "neocdz.zip", "neocdz.zip", "neocd",
            platform={"md5": "a" * 32, "size": 953078},
            truth={"md5": "b" * 32},
        )
        self.assertEqual((entry.hash("md5"), entry.size()), ("b" * 32, None))
        agreeing = NativeFile(
            "neocdz.zip", "neocdz.zip", "neocd",
            platform={"md5": "b" * 32, "size": 955352}, truth={"md5": "b" * 32},
        )
        self.assertEqual(agreeing.size(), 955352)

    def test_a_size_list_keeps_the_platform_size_it_accepts(self):
        """geargrafx accepts syscard3.pce headerless or headered, and System.dat
        states 262144 for the same dump. The list came first, stated no
        single size, and the rom line went out with none."""
        both = NativeFile(
            "syscard3.pce", "syscard3.pce", "pce",
            platform={"md5": "c" * 32, "size": 262144},
            truth={"md5": "c" * 32, "size": [262144, 262656]},
        )
        self.assertEqual(both.size(), 262144)
        refused = NativeFile(
            "syscard3.pce", "syscard3.pce", "pce",
            platform={"md5": "c" * 32, "size": 131072},
            truth={"md5": "c" * 32, "size": [262144, 262656]},
        )
        self.assertIsNone(refused.size())

    def test_a_file_the_truth_says_nothing_about_is_kept(self):
        systems, _ = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertIn("unknown-to-truth.bin", names)

    def test_the_truth_overrides_a_hash_the_platform_got_wrong(self):
        systems, report = model()
        entry = next(fe for fe in systems["psx"].files if fe.name == "scph5501.bin")
        self.assertEqual(entry.hash("md5"), "490f666e1afb15b7362b406ed1cea246")
        self.assertTrue(any("scph5501" in c for c in report.hashes_corrected))

    def test_a_file_only_the_truth_knows_is_added(self):
        systems, report = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertIn("scph7001.bin", names)
        self.assertEqual(report.files_added, 1)

    def test_a_placeholder_is_never_added(self):
        systems, _ = model()
        names = {fe.name for fe in systems["psx"].files}
        self.assertNotIn("<user-selected>.bin", names)

    def test_a_name_match_does_not_take_a_later_entrys_destination(self):
        """dosbox-x's system.rom (alias bios.rom, no path) came before
        np2kai's np2kai/bios.rom in the truth, took Batocera's
        np2kai/BIOS.ROM by name and wrote an IBM PCjr md5 on it."""
        truth = {"systems": {"nec-pc-98": {"files": [
            {"name": "system.rom", "aliases": ["bios.rom"], "md5": "c" * 32},
            {"name": "bios.rom", "path": "np2kai/bios.rom"},
        ]}}}
        scraped = {"systems": {"nec-pc-98": {"native_id": "pc98", "files": [
            {"name": "BIOS.ROM", "destination": "np2kai/BIOS.ROM",
             "native_system": "pc98", "md5": "e" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        entry = systems["pc98"].files[0]
        self.assertEqual(entry.truth["path"], "np2kai/bios.rom")
        self.assertEqual(entry.hash("md5"), "e" * 32)
        self.assertEqual(report.hashes_corrected, [])
        self.assertEqual(report.files_added, 0)

    def test_a_path_does_not_outrank_the_hash_another_line_carries(self):
        """The truth's MSX.rom joins bluemsx's path and fmsx's md5. Paired by
        path, fmsx's md5 replaced the blueMSX dump on Recalbox's
        Machines/Shared Roms/MSX.rom line while fmsx's own line held it."""
        truth = {"systems": {"microsoft-msx": {"files": [
            {"name": "MSX.rom", "path": "Machines/Shared Roms/MSX.rom",
             "md5": "a" * 32},
        ]}}}
        scraped = {"systems": {"microsoft-msx": {"native_id": "msx", "files": [
            {"name": "MSX.rom", "destination": "Machines/Shared Roms/MSX.rom",
             "native_system": "msx", "md5": "b" * 32},
            {"name": "MSX.ROM", "destination": "MSX.ROM",
             "native_system": "msx", "md5": "a" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        bluemsx, fmsx = systems["msx"].files
        self.assertIsNone(bluemsx.truth)
        self.assertEqual(bluemsx.hash("md5"), "b" * 32)
        self.assertIs(fmsx.truth, truth["systems"]["microsoft-msx"]["files"][0])
        self.assertEqual(report.hashes_corrected, [])

    def test_a_name_the_core_opens_is_added_beside_its_content(self):
        """fuse opens fuse/128-1.rom and fuse/128p-1.rom, one dump. Recalbox
        declares only 128p-1.rom. Paired entry by entry, 128-1.rom took that
        line by hash and was never added. A core that opens a name is not
        served by the same bytes under another one."""
        truth = {"systems": {"sinclair-zx-spectrum": {"files": [
            {"name": "128p-1.rom", "path": "fuse/128p-1.rom", "md5": "d" * 32},
            {"name": "128-1.rom", "path": "fuse/128-1.rom", "md5": "d" * 32},
        ]}}}
        scraped = {"systems": {"sinclair-zx-spectrum": {"native_id": "zx", "files": [
            {"name": "128p-1.rom", "destination": "fuse/128p-1.rom",
             "native_system": "zx", "md5": "d" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        own, added = systems["zx"].files
        self.assertEqual(own.truth["name"], "128p-1.rom")
        self.assertEqual(added.destination, "fuse/128-1.rom")
        self.assertEqual(report.files_added, 1)

    def test_a_hash_the_code_does_not_check_corrects_nothing(self):
        """dosbox checks MT32_CONTROL.ROM by sha1 and size. The truth accepts
        System.dat's sha1 but carries the md5 and crc of another revision,
        and the export wrote those beside System.dat's sha1: a record no
        file satisfies, counted as a correction."""
        truth = {"systems": {"dos": {"files": [
            {"name": "MT32_CONTROL.ROM", "sha1": ["1" * 40, "2" * 40],
             "md5": "a" * 32, "crc32": "aaaaaaaa", "size": 65536,
             "validation": ["sha1", "size"]},
        ]}}}
        scraped = {"systems": {"dos": {"native_id": "dos", "files": [
            {"name": "MT32_CONTROL.ROM", "destination": "MT32_CONTROL.ROM",
             "native_system": "dos", "sha1": "2" * 40, "md5": "b" * 32,
             "crc32": "bbbbbbbb", "size": 65536},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        entry = systems["dos"].files[0]
        self.assertEqual(
            [entry.record_hash(f) for f in ("crc32", "md5", "sha1")],
            ["bbbbbbbb", "b" * 32, "2" * 40],
        )
        self.assertEqual(entry.hashes("md5"), ["b" * 32])
        self.assertEqual(report.hashes_corrected, [])

    def test_a_size_checked_file_keeps_the_dump_the_platform_names(self):
        """pcsx_rearmed and DuckStation check scph1001.bin by size. The
        truth's md5 is v4.1's, Batocera names v2.0: the export replaced it
        and the frontend then refused the v2.0 the cores load. Nor is a
        blank md5 filled with one revision the code does not require."""
        truth = {"systems": {"sony-playstation": {"files": [
            {"name": "scph1001.bin", "md5": "a" * 32, "size": 524288,
             "validation": ["size"]},
            {"name": "scph5500.bin", "md5": "c" * 32, "size": 524288,
             "validation": ["size"]},
        ]}}}
        scraped = {"systems": {"sony-playstation": {"native_id": "psx", "files": [
            {"name": "scph1001.bin", "destination": "scph1001.bin",
             "native_system": "psx", "md5": "b" * 32},
            {"name": "scph5500.bin", "destination": "scph5500.bin",
             "native_system": "psx"},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        v20, blank = systems["psx"].files
        self.assertEqual(v20.hash("md5"), "b" * 32)
        self.assertEqual(blank.hash("md5"), "")
        self.assertEqual((report.hashes_corrected, blank.filled), ([], []))

    def test_a_hash_beside_one_checked_value_still_corrects(self):
        """A core that checks one crc32 pins one dump, and the md5 of that
        dump is no less true: a platform md5 against it is corrected."""
        truth = {"systems": {"coco": {"files": [
            {"name": "bas12.rom", "crc32": "aaaaaaaa", "md5": "a" * 32,
             "validation": ["crc32"]},
        ]}}}
        scraped = {"systems": {"coco": {"native_id": "coco", "files": [
            {"name": "bas12.rom", "destination": "bas12.rom",
             "native_system": "coco", "md5": "b" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        self.assertEqual(systems["coco"].files[0].hash("md5"), "a" * 32)
        self.assertEqual(report.hashes_corrected, ["coco/bas12.rom md5"])

    def test_a_hash_the_cores_disagree_on_corrects_nothing(self):
        """armsx2 and yaps2 declare different revisions of GameIndex.yaml.
        The truth kept armsx2's, and the export wrote it over System.dat's
        line for LRPS2 as a hash and size correction."""
        import contextlib

        from resolve import truth as truth_module

        entry = {"name": "GameIndex.yaml", "sha1": "1" * 40, "size": 2690355}
        with contextlib.redirect_stderr(io.StringIO()):
            truth_module._merge_hashes(
                entry, {"name": "GameIndex.yaml", "sha1": "2" * 40}, "yaps2"
            )
        self.assertEqual(entry["hash_conflict"], ["sha1"])
        truth = {"systems": {"sony-playstation-2": {"files": [entry]}}}
        scraped = {"systems": {"sony-playstation-2": {"native_id": "ps2", "files": [
            {"name": "GameIndex.yaml", "destination": "pcsx2/resources/GameIndex.yaml",
             "native_system": "ps2", "sha1": "3" * 40, "size": 1737799},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        line = systems["ps2"].files[0]
        self.assertEqual((line.hash("sha1"), line.size()), ("3" * 40, 1737799))
        self.assertEqual(report.hashes_corrected, [])

    def test_the_diff_names_no_mismatch_the_code_does_not_check(self):
        from resolve.platformdiff import _diff_system
        truth_sys = {"files": [{"name": "scph1001.bin", "md5": "a" * 32,
                                "validation": ["size"]}]}
        scraped_sys = {"files": [{"name": "scph1001.bin", "md5": "b" * 32}]}
        self.assertNotIn("hash_mismatch", _diff_system(truth_sys, scraped_sys))

    def test_a_label_is_never_added(self):
        """A name only a content-scanning core gives is no file to hold."""
        truth = {"systems": {"sony-playstation": {"files": [
            {"name": "scph1001_v20.bin", "md5": "a" * 32,
             "_cores": ["duckstation"], "_named_by": []},
            {"name": "scph5903.bin", "md5": "c" * 32,
             "_cores": ["beetle_psx"], "_named_by": ["beetle_psx"]},
        ]}}}
        scraped = {"systems": {"sony-playstation": {"native_id": "psx", "files": [
            {"name": "scph5501.bin", "destination": "scph5501.bin",
             "native_system": "psx", "md5": "d" * 32}]}}}
        systems, report = build_native_model(truth, scraped)
        self.assertEqual([fe.name for fe in systems["psx"].files],
                         ["scph5501.bin", "scph5903.bin"])
        self.assertEqual(report.files_added, 1)

    def test_a_label_pairs_by_content_only(self):
        """DuckStation's and rustation's scph5000.bin labels carried another
        dump's md5 and, paired by name, replaced System.dat's scph5000.bin."""
        truth = {"systems": {"sony-playstation": {"files": [
            {"name": "scph5000.bin", "md5": "a" * 32,
             "_cores": ["duckstation"], "_named_by": []},
            {"name": "other_label.bin", "md5": "e" * 32, "sha256": "f" * 64,
             "_cores": ["duckstation"], "_named_by": []},
        ]}}}
        scraped = {"systems": {"sony-playstation": {"native_id": "psx", "files": [
            {"name": "scph5000.bin", "destination": "scph5000.bin",
             "native_system": "psx", "md5": "b" * 32},
            {"name": "scph7001.bin", "destination": "scph7001.bin",
             "native_system": "psx", "md5": "e" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        scph5000, scph7001 = systems["psx"].files
        self.assertIsNone(scph5000.truth)
        self.assertEqual(scph7001.truth["name"], "other_label.bin")
        self.assertEqual(report.hashes_corrected, [])

    def test_the_diff_names_no_missing_label(self):
        from resolve.platformdiff import _diff_system
        truth_sys = {"files": [{"name": "scph1001_v20.bin", "md5": "a" * 32,
                                "_cores": ["duckstation"], "_named_by": []}]}
        self.assertNotIn("missing", _diff_system(truth_sys, {"files": []}))

    def test_a_bundled_truth_entry_is_never_added(self):
        truth = {"systems": {"neogeo": {"files": [
            {"name": "gngeo_data.zip", "md5": "a" * 32, "bundled": True,
             "_cores": ["gngeopi"], "_named_by": ["gngeopi"], "_brought_by": []},
            {"name": "neogeo.zip", "md5": "b" * 32,
             "_cores": ["gngeopi"], "_named_by": ["gngeopi"],
             "_brought_by": ["gngeopi:standalone"]},
        ]}}}
        systems, report = build_native_model(truth, {"systems": {}})
        self.assertEqual([fe.name for fe in systems["neogeo"].files], ["neogeo.zip"])
        self.assertEqual(report.files_added, 1)

    def test_a_bundled_entry_the_platform_declares_is_kept(self):
        truth = {"systems": {"neogeo": {"files": [
            {"name": "gngeo_data.zip", "md5": "a" * 32, "bundled": True,
             "_cores": ["gngeopi"], "_named_by": ["gngeopi"], "_brought_by": []}]}}}
        scraped = {"systems": {"neogeo": {"native_id": "neogeo", "files": [
            {"name": "gngeo_data.zip", "destination": "gngeo_data.zip",
             "native_system": "neogeo", "md5": "c" * 32}]}}}
        systems, _ = build_native_model(truth, scraped)
        (kept,) = systems["neogeo"].files
        self.assertIsNotNone(kept.truth)

    def test_the_runner_is_the_build_that_needs_the_file(self):
        """ROCKNIX runs ARMSX2 standalone only, and the libretro build's
        pcsx2/resources entries went out as armsx2-sa files."""
        truth = {"systems": {"sony-playstation-2": {"files": [
            {"name": "GameIndex.yaml", "md5": "a" * 32,
             "_cores": ["armsx2"], "_named_by": ["armsx2"],
             "_brought_by": ["armsx2:libretro"]}]}}}
        scraped = {"cores": ["armsx2"], "standalone_cores": ["armsx2"], "systems": {}}
        systems, _ = build_native_model(truth, scraped)
        (added,) = systems["sony-playstation-2"].files
        self.assertEqual(added.runners, [(False, "armsx2")])

    def test_the_diff_names_no_missing_bundled_file(self):
        from resolve.platformdiff import _diff_system
        truth_sys = {"files": [{"name": "gngeo_data.zip", "md5": "a" * 32, "bundled": True,
                                "_cores": ["gngeopi"], "_named_by": ["gngeopi"],
                                "_brought_by": []}]}
        self.assertNotIn("missing", _diff_system(truth_sys, {"files": []}))

    def test_the_diff_pairs_by_the_same_rule(self):
        """diff_truth reads the same pairing, or it names a mismatch the
        export does not correct."""
        from resolve.platformdiff import _diff_system
        truth_sys = {"files": [
            {"name": "system.rom", "aliases": ["bios.rom"], "md5": "c" * 32},
            {"name": "bios.rom", "path": "np2kai/bios.rom"},
        ]}
        scraped_sys = {"files": [
            {"name": "BIOS.ROM", "destination": "np2kai/BIOS.ROM", "md5": "e" * 32},
        ]}
        self.assertNotIn("hash_mismatch", _diff_system(truth_sys, scraped_sys))

    def test_systems_are_keyed_by_the_name_the_platform_uses(self):
        systems, _ = model()
        self.assertEqual(sorted(systems), ["psx"])

    def test_the_platform_own_grouping_survives_a_collapsed_slug(self):
        """Several native systems can share one of our slugs.

        Recalbox files pcengine, pcenginecd and supergrafx under one slug.
        Grouping on the slug would publish one of the three and drop the
        rest, which is how eleven Recalbox platforms went missing.
        """
        scraped = {
            "systems": {
                "nec-pc-engine": {
                    "native_id": "pcengine",
                    "files": [
                        {
                            "name": "syscard3.pce",
                            "destination": "pcengine/syscard3.pce",
                            "native_system": "pcengine",
                            "md5": "38179df8f4ac870017db21ebcbf53114",
                        },
                        {
                            "name": "syscard3.pce",
                            "destination": "supergrafx/syscard3.pce",
                            "native_system": "supergrafx",
                            "md5": "38179df8f4ac870017db21ebcbf53114",
                        },
                    ],
                },
            },
        }
        systems, _ = build_native_model({"systems": {}}, scraped)
        self.assertEqual(sorted(systems), ["pcengine", "supergrafx"])

    def test_a_container_md5_leaves_a_zipped_file_md5_alone(self):
        """Batocera's checkInsideZip compares a zippedFile item's md5 with
        the member's. A profile's container md5 was written in its place
        and counted as a hash updated to the emulator source."""
        scraped = {"systems": {"pc6001": {"native_id": "pc6001", "files": [
            {"name": "pc6001.zip", "destination": "pc6001.zip", "md5": "1" * 32,
             "zipped_file": "basicrom.60"},
        ]}}}
        truth = {"systems": {"pc6001": {"files": [
            {"name": "pc6001.zip", "md5": "2" * 32},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        entry = systems["pc6001"].files[0]
        self.assertEqual(entry.corrections, [])
        self.assertEqual(report.hashes_corrected, [])
        self.assertEqual(entry.hashes("md5"), ["1" * 32])

    def test_an_addition_joins_the_native_id_its_cores_read(self):
        """RetroDECK's arcade spans mame and fbneo with no primary id. Every
        addition went under fbneo, the first sorted, MAME device archives
        included. One the cores do not settle is not written."""
        scraped = {"systems": {"arcade": {"files": [
            {"name": "neogeo.zip", "destination": "neogeo.zip", "native_system": "mame"},
            {"name": "pgm.zip", "destination": "pgm.zip", "native_system": "fbneo"},
        ]}}}
        truth = {"systems": {"arcade": {"files": [
            {"name": "neogeo.zip", "_cores": ["mame"]},
            {"name": "pgm.zip", "_cores": ["fbneo"]},
            {"name": "a2autokbd.zip", "_cores": ["mame"]},
            {"name": "dkong.zip", "_cores": ["mame", "fbneo"]},
        ]}}}
        systems, report = build_native_model(truth, scraped)
        self.assertEqual(
            [fe.name for fe in systems["mame"].files if fe.platform is None],
            ["a2autokbd.zip"],
        )
        self.assertFalse([fe for fe in systems["fbneo"].files if fe.platform is None])
        self.assertEqual(report.unattributed, ["arcade/dkong.zip"])

    def test_an_entry_the_platform_declares_without_a_hash_is_still_written(self):
        """Batocera and RetroBat both ship entries with an empty md5."""
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
        systems, _ = build_native_model({"systems": {}}, scraped)
        entry = systems["nds"].files[0]
        self.assertTrue(_BaseRule().writable(entry, require="md5"))

    def test_no_format_drops_what_the_platform_already_declares(self):
        """An export poorer than the file it corrects is not usable."""
        systems, _ = model()
        for name, cls in discover_exporters().items():
            for system in systems.values():
                for entry in system.files:
                    if entry.platform is None:
                        continue
                    with self.subTest(platform=name, file=entry.name):
                        self.assertTrue(cls().writable(entry))

    def test_an_addition_the_format_cannot_express_is_refused(self):
        truth = {
            "systems": {
                "nintendo-ds": {"files": [{"name": "no-hash.bin", "required": True}]}
            }
        }
        systems, _ = build_native_model(truth, None)
        entry = systems["nintendo-ds"].files[0]
        self.assertFalse(_BaseRule().writable(entry, require="md5"))


class _BaseRule(BaseExporter):
    """A concrete exporter that keeps every rule of the base class."""

    @staticmethod
    def platform_name() -> str:
        return "base"

    @staticmethod
    def native_filename() -> str:
        return "base"

    def render(self, systems, report, originals, scraped=None):
        return {}

    def validate(self, systems, produced):
        return []


class SearchOrder(unittest.TestCase):
    """A list is read in the order the code looks, best first."""

    @staticmethod
    def _entry(name, priority=None, position=0):
        truth = {"name": name, "required": True, "md5": f"{position:032x}"}
        if priority is not None:
            truth["priority"] = priority
        return NativeFile(
            name=name, destination=name, native_system="psx", truth=truth
        )

    def test_the_declared_rank_orders_the_names(self):
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("scph5502.bin", 5, 0),
            self._entry("scph5501.bin", 2, 1),
            self._entry("scph7001.bin", 10, 2),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates),
            ["scph5501.bin", "scph5502.bin", "scph7001.bin"],
        )

    def test_without_a_rank_the_order_the_code_walks_is_kept(self):
        """An undeclared order is the profile's own, not the alphabet."""
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("zzz.bin", None, 0),
            self._entry("aaa.bin", None, 1),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates), ["zzz.bin", "aaa.bin"]
        )

    def test_a_ranked_file_is_read_before_an_unranked_one(self):
        exporter = discover_exporters()["retropie"]()
        candidates = [
            self._entry("unranked.bin", None, 0),
            self._entry("ranked.bin", 9, 1),
        ]
        self.assertEqual(
            exporter._in_search_order(candidates), ["ranked.bin", "unranked.bin"]
        )

    def test_a_region_the_help_already_fills_gets_no_alternative(self):
        """PicoDrive loads the first file of each region's list. RetroPie
        names one per region, but the export appended three more, which the
        sentence reads as three more required files."""
        from resolve.nativemodel import NativeSystem

        def cd(name, region, rank):
            return NativeFile(name=name, destination=name, native_system="segacd", truth={
                "name": name, "required": True, "md5": "0" * 32, "_cores": ["picodrive"],
                "region": [region], "priority": rank})

        files = [cd("us_scd2_9306.bin", "north-america", 1),
                 cd("us_scd1_9210.bin", "north-america", 3),
                 cd("eu_mcd2_9306.bin", "europe", 1),
                 cd("eu_mcd1_9210.bin", "europe", 3),
                 cd("jp_mcd2_921222.bin", "japan", 1),
                 cd("jp_mcd1_9112.bin", "japan", 2)]
        script = ('rp_module_id="lr-picodrive"\nrp_module_help="The Sega CD requires the '
                  'BIOS files us_scd1_9210.bin, eu_mcd1_9210.bin copied to $biosdir"\n')
        exporter = discover_exporters()["retropie"](
            {"picodrive": {"type": "libretro", "cores": ["picodrive"]}}
        )
        # The cap is the longest list RetroPie writes: xm7 names thirteen.
        longest = ('rp_module_id="xm7"\nrp_module_help="Copy bios files '
                   + ", ".join(f"n{i}.rom" for i in range(12)) + ' and n12.rom to $biosdir"\n')
        produced = exporter.render(
            {"segacd": NativeSystem("segacd", files=files)}, None,
            {"scriptmodules/libretrocores/lr-picodrive.sh": script,
             "scriptmodules/emulators/xm7.sh": longest},
        )["scriptmodules/libretrocores/lr-picodrive.sh"]
        self.assertIn("us_scd1_9210.bin, eu_mcd1_9210.bin and jp_mcd2_921222.bin copied",
                      produced)
        self.assertNotIn("us_scd2_9306", produced)
        self.assertNotIn("jp_mcd1_9112", produced)

    def test_a_file_joins_the_list_of_its_own_system(self):
        """flycast's help names the Dreamcast BIOS, then the Naomi/Atomiswave
        ones. naomi2.zip, an arcade archive, went into the Dreamcast list:
        only the first BIOS clause was read."""
        from resolve.nativemodel import NativeSystem

        def entry(name, system):
            return NativeFile(name=name, destination=f"dc/{name}", native_system=system,
                              truth={"name": name, "required": True, "md5": "0" * 32,
                                     "_cores": ["flycast"], "_required_by": ["flycast"]})

        dc, arcade = "Sega - Dreamcast", "Sega - Dreamcast-based Arcade"
        systems = {
            dc: NativeSystem(dc, files=[entry("dc_boot.bin", dc)]),
            arcade: NativeSystem(arcade, files=[entry("naomi.zip", arcade),
                                                entry("awbios.zip", arcade),
                                                entry("naomi2.zip", arcade)]),
            "other": NativeSystem("other", files=[entry("other.zip", "other")]),
        }
        script = ('rp_module_id="lr-flycast"\nrp_module_help="Copy the required Dreamcast '
                  'BIOS file dc_boot.bin to $biosdir/dc\\n\\nCopy the required '
                  'Naomi/Atomiswave BIOS files naomi.zip and awbios.zip to $biosdir/dc"\n')
        longest = ('rp_module_id="xm7"\nrp_module_help="Copy bios files '
                   + ", ".join(f"n{i}.rom" for i in range(12)) + ' and n12.rom to $biosdir"\n')
        exporter = discover_exporters()["retropie"](
            {"flycast": {"type": "libretro", "cores": ["flycast"]}}
        )
        written = exporter.render(
            systems, None,
            {"scriptmodules/libretrocores/lr-flycast.sh": script,
             "scriptmodules/emulators/xm7.sh": longest},
        )
        produced = written["scriptmodules/libretrocores/lr-flycast.sh"]
        self.assertIn("Dreamcast BIOS file dc_boot.bin to", produced)
        self.assertIn("BIOS files naomi.zip, awbios.zip and naomi2.zip to", produced)
        self.assertNotIn("other.zip", produced)
        # Rewritten for naomi2.zip, other.zip left out: the summary said
        # "Left as is" of a package in the diff.
        outcome = exporter.outcome(systems, written)
        self.assertIn("Updated in part: lr-flycast,", outcome)
        self.assertNotIn("Left as is: lr-flycast", outcome)

    def test_cores_that_disagree_keep_the_best_rank(self):
        """Nothing is dropped on the rank here, so the best one wins.

        slot.py voids the choice when cores disagree because it keeps one
        file, while ordering keeps them all, and a file that is some core's first
        choice belongs early.
        """
        merged = {"name": "scph5501.bin", "priority": 2, "priority_conflict": True}
        entry = NativeFile(
            name="scph5501.bin",
            destination="scph5501.bin",
            native_system="psx",
            truth=merged,
        )
        self.assertEqual(entry.priority, 2)


class TwoAdditionsAtOnePath(unittest.TestCase):
    """Two cores declaring two dumps of one file the platform lacks: both
    were counted added while the render wrote one. Recalbox's md5 list takes
    both, a System.dat name and a RetroDECK path hold one."""

    A, B = "615a" + "0" * 28, "ef49" + "0" * 28

    def _addition(self, md5: str, core: str, system: str = "dos") -> NativeFile:
        return NativeFile(
            name="MT32_CONTROL.ROM", destination="mt32/MT32_CONTROL.ROM", native_system=system,
            truth={"name": "MT32_CONTROL.ROM", "path": "mt32/MT32_CONTROL.ROM", "md5": md5,
                   "crc32": md5[:8], "required": True, "_cores": [core]},
            runners=[(False, core)],
        )

    def _added(self, exporter, systems) -> list[str]:
        return [c["name"] for c in landed_changes(exporter, systems).records
                if c["kind"] == "added"]

    def test_recalbox_writes_both_md5_in_one_element(self):
        systems = {"dos": NativeSystem("dos", files=[
            self._addition(self.A, "dosbox_pure"), self._addition(self.B, "dosbox_core")])}
        exporter = discover_exporters()["recalbox"]()
        produced = exporter.render(systems, Report(), {})["es_bios.xml"]
        elements = [e for e in ET.fromstring(produced).iter("bios")]
        self.assertEqual(len(elements), 1)
        self.assertEqual(elements[0].get("md5").split(","), [self.A, self.B])
        self.assertEqual(elements[0].get("core"), "libretro/dosbox_pure,libretro/dosbox_core")
        self.assertEqual(exporter.validate(systems, {"es_bios.xml": produced}), [])
        self.assertEqual(len(self._added(exporter, systems)), 2)

    def test_system_dat_counts_the_line_it_wrote(self):
        systems = {"DOS": NativeSystem("DOS", files=[
            self._addition(self.A, "dosbox_pure", "DOS"),
            self._addition(self.B, "dosbox_core", "DOS")])}
        exporter = discover_exporters()["retroarch"]()
        original = 'clrmamepro (\n\tname "System"\n)\n\ngame (\n\tname "System"\n' \
                   '\tcomment "System"\n\n\tcomment "DOS"\n\trom ( name a.bin size 1 crc 00000000 )\n)\n'
        produced = exporter.render(systems, Report(), {"System.dat": original})["System.dat"]
        self.assertEqual(produced.count("MT32_CONTROL.ROM"), 1)
        self.assertEqual(len(self._added(exporter, systems)), 1)

    def test_retrodeck_counts_the_entry_it_appended(self):
        theirs = NativeFile(
            name="scph1001.bin", destination="scph1001.bin", native_system="psx",
            platform={"name": "scph1001.bin", "md5": "1" * 32, "component": "duckstation"})

        def addition(md5: str) -> NativeFile:
            return NativeFile(
                name="scph5501.bin", destination="scph5501.bin", native_system="psx",
                truth={"name": "scph5501.bin", "md5": md5, "required": True,
                       "_cores": ["duckstation"]},
                runners=[(True, "duckstation")])

        systems = {"psx": NativeSystem("psx", files=[theirs, addition(self.A), addition(self.B)])}
        manifest = json.dumps({"duckstation": {"name": "DuckStation", "bios": [
            {"filename": "scph1001.bin", "md5": "1" * 32, "system": "psx"}]}})
        exporter = discover_exporters()["retrodeck"]()
        produced = exporter.render(systems, Report(), {"duckstation/component_manifest.json": manifest})
        bios = json.loads(produced["duckstation/component_manifest.json"])["duckstation"]["bios"]
        self.assertEqual([e["filename"] for e in bios], ["scph1001.bin", "scph5501.bin"])
        self.assertEqual(self._added(exporter, systems), ["scph5501.bin"])


class AdditionOrder(unittest.TestCase):
    """What we add is listed the way the code looks for it."""

    TRUTH = {
        "systems": {
            "sony-playstation": {
                "files": [
                    {
                        "name": "third.bin",
                        "md5": "c" * 32,
                        "required": True,
                        "priority": 10,
                    },
                    {
                        "name": "first.bin",
                        "md5": "a" * 32,
                        "required": True,
                        "priority": 1,
                    },
                    {"name": "unranked.bin", "md5": "b" * 32, "required": True},
                ]
            }
        }
    }

    def test_a_ranked_addition_is_named_before_a_later_one(self):
        systems, _ = build_native_model(self.TRUTH, None)
        names = [fe.name for fe in systems["sony-playstation"].files]
        self.assertEqual(names, ["first.bin", "third.bin", "unranked.bin"])

    def test_what_the_platform_wrote_keeps_its_place(self):
        """Reordering their own entries would be churn, not a correction."""
        scraped = {
            "systems": {
                "sony-playstation": {
                    "native_id": "psx",
                    "files": [
                        {
                            "name": "theirs-b.bin",
                            "destination": "theirs-b.bin",
                            "native_system": "psx",
                            "md5": "d" * 32,
                        },
                        {
                            "name": "theirs-a.bin",
                            "destination": "theirs-a.bin",
                            "native_system": "psx",
                            "md5": "e" * 32,
                        },
                    ],
                }
            }
        }
        systems, _ = build_native_model(self.TRUTH, scraped)
        names = [fe.name for fe in systems["psx"].files]
        self.assertEqual(names[:2], ["theirs-b.bin", "theirs-a.bin"])
        self.assertEqual(names[2], "first.bin")


class ARecordDescribesOneDump(unittest.TestCase):
    """syscard2.pce: System.dat states v2.1 (crc 283b74e0, md5, sha1),
    geargrafx accepts three crcs with v2.0's first. Field by field, the
    export wrote v2.0's crc beside v2.1's md5 and sha1."""

    def test_the_platform_record_stays_whole_when_the_truth_accepts_it(self):
        from resolve.nativemodel import NativeFile

        fe = NativeFile(
            name="syscard2.pce", destination="syscard2.pce", native_system="pce",
            platform={"crc32": "283b74e0", "md5": "3cdd6614" + "0" * 24,
                      "sha1": "88da02e2" + "0" * 32},
            truth={"crc32": ["52520bc6", "283b74e0", "ff2a5ec3"]},
        )
        self.assertEqual(fe.hash("crc32"), "52520bc6")
        self.assertEqual(fe.record_hash("crc32"), "283b74e0")
        self.assertEqual(fe.record_hash("md5"), "3cdd6614" + "0" * 24)

    def test_a_field_only_the_truth_names_is_written_when_unambiguous(self):
        from resolve.nativemodel import NativeFile

        one = NativeFile(name="a", destination="a", native_system="s",
                         platform={"crc32": "11111111"},
                         truth={"crc32": "11111111", "md5": "a" * 32})
        two = NativeFile(name="a", destination="a", native_system="s",
                         platform={"crc32": "11111111"},
                         truth={"crc32": "11111111", "md5": ["a" * 32, "b" * 32]})
        self.assertEqual(one.record_hash("md5"), "a" * 32)
        self.assertEqual(two.record_hash("md5"), "")

    def test_single_record_writers_use_it(self):
        for module in ("systemdat_exporter.py", "romm_exporter.py"):
            source = (Path(__file__).resolve().parent.parent / "scripts" / "exporter" / module).read_text()
            with self.subTest(module=module):
                self.assertNotRegex(source, r'= fe\.hash\("(crc32|md5|sha1)"\)')


class AnAdditionCarriesItsRunner(unittest.TestCase):
    """Batocera's apple2 entry is gated on libretro/mame, so Clock Signal's
    apple2.rom written inside it was asked of mame users and never of clk
    users. Recalbox got core="libretro/duckstation", a core it never runs."""

    ORIGINAL = (
        "#!/usr/bin/env python\n"
        "systems = {\n"
        '    "apple2": { "name": "Apple II", "emulator": "libretro", "core": "mame", '
        '"biosFiles": [ { "md5": "", "file": "bios/apple2e.zip" } ] },\n'
        '    "macintosh": { "name": "Macintosh", "biosFiles": [ '
        '{ "md5": "", "file": "bios/MacII.ROM", "emulator": "libretro", "core": "minivmac" } ] },\n'
        "}\n"
        "def checkBios(systems, prefix, filterROMs):\n"
        "    return {}\n"
    )

    def _systems(self):
        def add(native, name, runners):
            return NativeFile(name, name, native, truth={"md5": "1" * 32}, runners=runners)

        apple2 = NativeSystem("apple2", "Apple II", from_platform=True, files=[
            NativeFile("apple2e.zip", "apple2e.zip", "apple2", platform={"md5": ""}),
            add("apple2", "apple2.rom", [(True, "clk")]),
            add("apple2", "apple2e.rom", [(False, "mame")]),
        ])
        mac = NativeSystem("macintosh", "Macintosh", from_platform=True, files=[
            NativeFile("MacII.ROM", "MacII.ROM", "macintosh", platform={"md5": ""}),
            add("macintosh", "macplus.rom", [(True, "clk")]),
            add("macintosh", "nothing.rom", []),
        ])
        return {"apple2": apple2, "macintosh": mac}

    def test_batocera_writes_the_runner_or_counts_the_file_out(self):
        exporter = discover_exporters()["batocera"]()
        systems = self._systems()
        out = exporter.render(systems, Report(), {"batocera-systems": self.ORIGINAL})
        text = out["batocera-systems"]
        self.assertNotIn("apple2.rom", text)
        self.assertIn('"file": "bios/apple2e.rom" }', text)
        self.assertIn('"file": "bios/macplus.rom", "emulator": "clk" }', text)
        self.assertNotIn("nothing.rom", text)
        landed = {fe.name for s in systems.values() for fe in s.files
                  if fe.platform is None and exporter.lands(fe)}
        self.assertEqual(landed, {"apple2e.rom", "macplus.rom"})

    def test_recalbox_names_cores_as_it_runs_them(self):
        fe = NativeFile("scph5000.bin", "scph5000.bin", "psx", truth={"md5": "1" * 32},
                        runners=[(True, "duckstation"), (False, "mednafen_psx")])
        self.assertEqual(fe.cores(), ["duckstation", "libretro/mednafen_psx"])
        self.assertEqual(NativeFile("x", "x", "psx", truth={"md5": "1" * 32}).cores(), [])

    def test_runners_use_the_platform_name_of_the_profile(self):
        scraped = {"cores": ["mednafen_psx", "duckstation"],
                   "standalone_cores": ["duckstation"],
                   "systems": {"sony-playstation": {"native_id": "psx", "files": []}}}
        truth = {"systems": {"sony-playstation": {"files": [
            {"name": "a.bin", "md5": "1" * 32, "_cores": ["beetle_psx"]},
            {"name": "b.bin", "md5": "2" * 32, "_cores": ["duckstation"]},
            {"name": "c.bin", "md5": "3" * 32, "_cores": ["no-such-core"]},
        ]}}}
        systems, _ = build_native_model(truth, scraped, PROFILES)
        runners = {fe.name: fe.runners for fe in systems["psx"].files}
        self.assertEqual(runners["a.bin"], [(False, "mednafen_psx")])
        self.assertEqual(runners["b.bin"], [(True, "duckstation")])
        self.assertEqual(runners["c.bin"], [])


if __name__ == "__main__":
    unittest.main()
