#!/usr/bin/env python3
"""Native-format exporters.

export_native.py rewrites each platform's own file, corrected: Recalbox's
es_bios.xml, Batocera's systems list, RetroDECK's manifests. The point is
that a maintainer can take the output and use it, so what matters is
whether the platform would still read it, and whether anything it already
declared went missing on the way through.

The fidelity cases read the platforms' real files from the upstream cache
and skip when it has not been populated (python scripts/export_native.py
--all --fetch), because a test that needs the network is not a test.
"""

from __future__ import annotations

import difflib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    list_registered_platforms,
    load_platform_config,
    native_layer,
    parse_untrusted_xml,
)
from exporter import discover_exporters  # noqa: E402
from exporter.base_exporter import BaseExporter  # noqa: E402
from export_native import (  # noqa: E402
    SOURCES_INDEX,
    collect_originals,
    fetch,
    landed_changes,
    pinned_base,
    source_key,
)
from exporter.baseline import (  # noqa: E402
    NativeFile,
    NativeSystem,
    Report,
    build_native_model,
)

UPSTREAM_CACHE = REPO_ROOT / ".cache" / "upstream-native"


def _without_native_list() -> set[str]:
    """Registered platforms whose code names no BIOS file to hand back."""
    import yaml  # noqa: PLC0415

    registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
    return {
        name for name, entry in registry["platforms"].items()
        if entry.get("native_list") == "none"
    }

TRUTH = {
    "systems": {
        "sony-playstation": {
            "files": [
                {
                    "name": "scph5501.bin",
                    "path": "psx/scph5501.bin",
                    "md5": "490f666e1afb15b7362b406ed1cea246",
                    "size": 524288,
                    "required": True,
                    "_cores": ["duckstation"],
                },
                {
                    "name": "scph7001.bin",
                    "path": "psx/scph7001.bin",
                    "md5": "1e68c231d0896b7eadcad1d7d8e76129",
                    "size": 524288,
                    "required": False,
                    "_cores": ["duckstation"],
                },
                # Carries an md5 on purpose: without one it would be dropped
                # for being incomplete, and the placeholder guard would never
                # be the reason it stayed out.
                {
                    "name": "<user-selected>.bin",
                    "path": "psx/PLACEHOLDER-MUST-NOT-SHIP.bin",
                    "md5": "00000000000000000000000000000000",
                    "size": 1,
                    "required": False,
                    "_cores": ["duckstation"],
                },
            ],
        },
    },
}

SCRAPED = {
    # The cores the platform runs, by its own names: an addition is written
    # with the runner that wants it.
    "cores": ["atari800", "duckstation", "fuse", "melonds", "o2em", "picodrive",
              "snes9x", "beetle_psx"],
    "standalone_cores": ["duckstation"],
    "systems": {
        "sony-playstation": {
            "native_id": "psx",
            "files": [
                {
                    "name": "scph5501.bin",
                    "destination": "psx/scph5501.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "core": "libretro/duckstation",
                    "required": True,
                },
                {
                    "name": "unknown-to-truth.bin",
                    "destination": "psx/unknown-to-truth.bin",
                    "native_system": "psx",
                    "native_name": "Sony PlayStation",
                    "md5": "11111111111111111111111111111111",
                    "core": "libretro/duckstation",
                    "required": True,
                },
            ],
        },
    },
}


def model(truth: dict = TRUTH, scraped: dict | None = SCRAPED):
    return build_native_model(truth, scraped)


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
        import contextlib  # noqa: PLC0415

        import truth as truth_module  # noqa: PLC0415

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
        from truth import _diff_system
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
        from truth import _diff_system
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
        from truth import _diff_system
        truth_sys = {"files": [{"name": "gngeo_data.zip", "md5": "a" * 32, "bundled": True,
                                "_cores": ["gngeopi"], "_named_by": ["gngeopi"],
                                "_brought_by": []}]}
        self.assertNotIn("missing", _diff_system(truth_sys, {"files": []}))

    def test_the_diff_pairs_by_the_same_rule(self):
        """diff_truth reads the same pairing, or it names a mismatch the
        export does not correct."""
        from truth import _diff_system
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
        self.assertTrue(BaseExporter.writable(entry, require="md5"))

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
        self.assertFalse(BaseExporter.writable(entry, require="md5"))


class ExporterRegistry(unittest.TestCase):
    """Every registered platform has an exporter, and it declares itself."""

    def test_every_exporter_declares_a_platform_and_a_filename(self):
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                self.assertTrue(cls.platform_name())
                self.assertTrue(cls.native_filename())
                self.assertTrue(issubclass(cls, BaseExporter))

    def test_every_registered_platform_can_be_exported(self):
        """A platform with no exporter is a platform we cannot hand back.

        Archived included: the export is a correction we offer, not a
        release artefact, and RetroPie's users are not fewer for it.
        """
        exporters = discover_exporters()
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms"), include_archived=True
            )
        )
        self.assertEqual(registered - set(exporters) - _without_native_list(), set())

    def test_a_run_over_a_platform_without_a_native_list_passes(self):
        """export_native --all ran over MinUI, NextUI and MyMinUI and failed
        the pipeline step for three platforms the registry says have nothing
        to export. A platform with no exporter and no such mark still fails."""
        import contextlib

        import export_native

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as directory:
            platforms = Path(directory)
            (platforms / "_registry.yml").write_text(
                "platforms:\n  cardonly:\n    native_list: none\n  unwritten: {}\n",
                encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(export_native.run(
                    ["cardonly"], directory, directory, str(platforms), directory, False), 0)
                self.assertEqual(export_native.run(
                    ["unwritten"], directory, directory, str(platforms), directory, False), 1)
            self.assertIn("SKIP cardonly: names no BIOS file of its own", out.getvalue())

    def test_a_platform_without_a_native_list_declares_no_file(self):
        """`native_list: none` says the platform's code names no BIOS file
        (MinUI hands each core a folder and opens nothing in it). A platform
        whose file declares one has a list to hand back."""
        for name in _without_native_list():
            config = load_platform_config(name, str(REPO_ROOT / "platforms"))
            with self.subTest(platform=name):
                self.assertNotIn(name, discover_exporters())
                self.assertFalse(any(
                    system.get("files") for system in (config.get("systems") or {}).values()
                ))

    def test_no_exporter_is_registered_for_an_unregistered_platform(self):
        """A dead exporter is one nobody will notice has stopped working."""
        exporters = set(discover_exporters())
        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms"), include_archived=True
            )
        )
        self.assertEqual(exporters - registered, set())

    def test_every_exporter_says_what_its_format_can_state(self):
        """A correction to a field the file has no place for is not delivered."""
        for name, cls in discover_exporters().items():
            with self.subTest(platform=name):
                carried = cls.carries()
                self.assertTrue(carried)
                self.assertTrue(
                    carried
                    <= {"size", "crc32", "md5", "sha1", "sha256", "required", "name"},
                    f"{name} claims a field that is not one of ours: {carried}",
                )

    def test_only_a_format_with_the_field_claims_to_carry_it(self):
        """Recalbox writes mandatory, while RetroBat's entries are md5 and file."""
        exporters = discover_exporters()
        self.assertIn("required", exporters["recalbox"].carries())
        self.assertNotIn("required", exporters["retrobat"].carries())
        self.assertNotIn("required", exporters["retroarch"].carries())

    def test_an_exporter_that_patches_code_says_it_needs_the_original(self):
        """Regenerating a script from data alone drops the code around it."""
        for name in ("batocera", "rocknix", "emudeck", "retrodeck", "bizhawk",
                     "misterfpga", "knulli", "amberelec", "emuelec"):
            with self.subTest(platform=name):
                self.assertTrue(discover_exporters()[name].needs_original())

    def test_every_exporter_with_an_original_needs_it(self):
        """System.dat, RomM, Recalbox and RetroBat were rebuilt from our data
        when their file was not cached: libretro's quoted names, Recalbox's
        comments and its second zxspectrum block were lost, and the run
        said OK."""
        for name, exporter in discover_exporters().items():
            if exporter.native_sources():
                with self.subTest(platform=name):
                    self.assertTrue(exporter.needs_original())

    def test_an_export_without_its_original_writes_nothing(self):
        import export_native  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            output = Path(tmp) / "out"
            ok, messages = export_native.export_platform(
                "retroarch", discover_exporters()["retroarch"],
                REPO_ROOT / "dist" / "truth", output,
                str(REPO_ROOT / "platforms"), Path(tmp) / "no-cache", False,
            )
            if not (REPO_ROOT / "dist" / "truth" / "retroarch.yml").exists():
                self.skipTest("dist/truth not generated")
            self.assertFalse(ok, messages)
            self.assertFalse(output.exists())


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
        from exporter.baseline import NativeSystem  # noqa: PLC0415

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
        exporter = discover_exporters()["retropie"]()
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
        from exporter.baseline import NativeSystem  # noqa: PLC0415

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
        exporter = discover_exporters()["retropie"]()
        produced = exporter.render(
            systems, None,
            {"scriptmodules/libretrocores/lr-flycast.sh": script,
             "scriptmodules/emulators/xm7.sh": longest},
        )["scriptmodules/libretrocores/lr-flycast.sh"]
        self.assertIn("Dreamcast BIOS file dc_boot.bin to", produced)
        self.assertIn("BIOS files naomi.zip, awbios.zip and naomi2.zip to", produced)
        self.assertNotIn("other.zip", produced)

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


class PinnedRevision(unittest.TestCase):
    """The file we patch is the revision our transcription came from."""

    def test_the_tag_the_scraper_pinned_wins_over_the_branch_tip(self):
        wanted = {"batocera-systems": "https://example.invalid/master/batocera-systems"}
        scraped = {
            "source": "https://raw.githubusercontent.com/batocera-linux"
            "/batocera.linux/batocera-43.1/package/batocera-systems"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/batocera-linux/batocera.linux"
            "/batocera-43.1/package/",
        )

    def test_a_blob_page_is_read_as_raw(self):
        """github.com/.../blob/... names a revision but serves HTML."""
        wanted = {"System.dat": "https://example.invalid/System.dat"}
        scraped = {
            "source": "https://github.com/libretro/libretro-database"
            "/blob/master/dat/System.dat"
        }
        self.assertEqual(
            pinned_base(wanted, scraped),
            "https://raw.githubusercontent.com/libretro/libretro-database"
            "/master/dat/",
        )

    def test_a_source_that_names_no_wanted_file_changes_nothing(self):
        wanted = {"component_manifest.json": "https://example.invalid/x.json"}
        scraped = {"source": "https://github.com/RetroDECK/components"}
        self.assertEqual(pinned_base(wanted, scraped), "")

    def test_every_platform_that_records_its_source_pins_the_export(self):
        """A scraped platform states the revision, and the export follows it."""
        exporters = discover_exporters()
        for name in ("batocera", "recalbox", "bizhawk", "romm", "retroarch"):
            with self.subTest(platform=name):
                config = load_platform_config(name, str(REPO_ROOT / "platforms"))
                base = pinned_base(dict(exporters[name].native_sources()), config)
                self.assertTrue(base.startswith("https://"), base)

    def test_every_file_of_every_platform_is_read_at_the_pinned_revision(self):
        """Checked on five platforms by their base only: ROCKNIX's second
        file, RetroDECK's manifests and RetroPie's tarball were never
        looked at, and a URL that fell back to a branch passed."""
        import export_native  # noqa: PLC0415

        for name, exporter_class in discover_exporters().items():
            with self.subTest(platform=name):
                config = native_layer(load_platform_config(name, str(REPO_ROOT / "platforms")))
                systems, _ = build_native_model({}, config)
                wanted = export_native.wanted_sources(exporter_class(), systems, config)
                self.assertTrue(wanted)
                self.assertEqual(export_native.unpinned(wanted, config), [])

    def test_a_file_read_off_the_pinned_revision_is_named(self):
        import export_native  # noqa: PLC0415

        pinned = {"source": "https://raw.githubusercontent.com/o/r/v1.0/list.txt"}
        self.assertEqual(export_native.unpinned(
            {"list.txt": "https://raw.githubusercontent.com/o/r/v1.0/list.txt"}, pinned), [])
        moved = export_native.unpinned(
            {"list.txt": "https://raw.githubusercontent.com/o/r/master/list.txt"}, pinned)
        self.assertEqual(len(moved), 1)
        self.assertIn("v1.0", moved[0])
        bare = export_native.unpinned(
            {"x.json": "https://raw.githubusercontent.com/o/r/main/x.json"},
            {"source": "https://github.com/RetroDECK/components"})
        self.assertIn("names no revision", bare[0])


class _OneFileExporter:
    """An exporter reduced to what collect_originals reads."""

    def __init__(self, url: str):
        self._url = url

    def platform_name(self) -> str:
        return "plat"

    def native_sources(self) -> dict[str, str]:
        return {"list.txt": self._url}


class _ArchiveExporter(_OneFileExporter):
    """One whose original is an archive it unpacks, as MiSTer's is."""

    def native_sources(self) -> dict[str, str]:
        return {"db.zip": self._url}

    @staticmethod
    def unpack(raw: bytes) -> dict[str, str]:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return {"db.json": archive.read("db.json").decode("utf-8")}


class CachedOriginal(unittest.TestCase):
    """The cached original is the file the platform data was read from."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.cache = self.root / "cache"
        self.index = self.cache / SOURCES_INDEX

    def _upstream(self, name: str, text: str) -> str:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path.as_uri()

    def test_the_same_url_is_served_from_the_cache(self):
        url = self._upstream("v1.txt", "one")
        target = self.cache / "plat" / "list.txt"
        self.assertEqual(fetch(url, target, self.index), b"one")
        self._upstream("v1.txt", "moved")
        self.assertEqual(fetch(url, target, self.index), b"one")

    def test_refresh_reads_a_branch_url_again(self):
        """A branch URL keeps its name while the platform moves."""
        url = self._upstream("branch.txt", "one")
        target = self.cache / "plat" / "list.txt"
        fetch(url, target, self.index)
        self._upstream("branch.txt", "two")
        self.assertEqual(fetch(url, target, self.index, refresh=True), b"two")
        self.assertEqual(target.read_bytes(), b"two")

    def test_a_new_pin_refetches_an_existing_file(self):
        """Reading the file straight from disk served the old pin forever."""
        old = self._upstream("tag-1.txt", "one")
        new = self._upstream("tag-2.txt", "two")
        originals, missing = collect_originals(
            _OneFileExporter(old), {}, self.cache, True
        )
        self.assertEqual((originals, missing), ({"list.txt": "one"}, []))
        originals, missing = collect_originals(
            _OneFileExporter(new), {}, self.cache, True
        )
        self.assertEqual((originals, missing), ({"list.txt": "two"}, []))

    def test_an_empty_or_html_original_fails_the_platform(self):
        """A System.dat served as an HTML page with 200, or a 0-byte cache,
        was parsed as a file with no entries: four exporters rebuilt it from
        our data and reported OK."""
        for body in ("", "  \n", "<html><body>Too Many Requests</body></html>",
                     "<!DOCTYPE html>\n<html></html>"):
            with self.subTest(body=body):
                url = self._upstream("served.txt", body)
                originals, missing = collect_originals(
                    _OneFileExporter(url), {}, self.cache, True, refresh=True
                )
                self.assertEqual(originals, {})
                self.assertEqual(len(missing), 1)
                cached = self.cache / "plat" / "list.txt"
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_text(body, encoding="utf-8")
                _, missing = collect_originals(
                    _OneFileExporter(url), {}, self.cache, False
                )
                self.assertEqual(len(missing), 1)
                cached.unlink()

    def test_offline_serves_what_is_cached_and_names_what_is_not(self):
        url = self._upstream("v1.txt", "one")
        _, missing = collect_originals(_OneFileExporter(url), {}, self.cache, False)
        self.assertEqual(missing, [
            f"list.txt: not in {self.cache / 'plat'}; rerun with --fetch to download it"
        ])
        collect_originals(_OneFileExporter(url), {}, self.cache, True)
        originals, missing = collect_originals(
            _OneFileExporter("file:///nowhere/else.txt"), {}, self.cache, False
        )
        self.assertEqual((originals, missing), ({"list.txt": "one"}, []))

    def test_the_bytes_are_written_under_the_index_lock(self):
        """Written under two locks, two runs wanting two URLs for one path
        could leave one's bytes beside the other's index entry."""
        import fcntl  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415

        import export_native  # noqa: PLC0415

        url = self._upstream("v1.txt", "one")
        target = self.cache / "plat" / "list.txt"
        lock = self.index.with_name(f".{self.index.name}.lock")
        held: list[bool] = []
        write = export_native.write_bytes_atomic

        def probing(path, data):
            with open(lock, "a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    held.append(True)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                    held.append(False)
            write(path, data)

        with mock.patch.object(export_native, "write_bytes_atomic", probing):
            fetch(url, target, self.index)
        self.assertEqual(held, [True])

    def test_an_unreadable_cached_archive_fails_its_platform_only(self):
        """A cached bios_db.json.zip that was not a zip raised BadZipFile
        out of run(): --all stopped and the next platforms were never
        exported."""
        target = self.cache / "plat" / "db.zip"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"<html>not a zip</html>")
        originals, missing = collect_originals(
            _ArchiveExporter("file:///nowhere/db.zip"), {}, self.cache, False
        )
        self.assertEqual(originals, {})
        self.assertEqual(len(missing), 1)
        self.assertIn("--refresh-cache", missing[0])

    def test_a_download_that_is_not_the_archive_keeps_the_cache(self):
        """fetch() cached any 200 reply, so an error page replaced a good
        archive and was served on every later run."""
        good = self.root / "db.zip"
        with zipfile.ZipFile(good, "w") as archive:
            archive.writestr("db.json", "{}")
        url = good.as_uri()
        exporter = _ArchiveExporter(url)
        collect_originals(exporter, {}, self.cache, True)
        cached = (self.cache / "plat" / "db.zip").read_bytes()
        good.write_bytes(b"<html>error</html>")
        originals, missing = collect_originals(exporter, {}, self.cache, True, refresh=True)
        self.assertEqual(originals, {})
        self.assertIn("--refresh-cache", missing[0])
        self.assertEqual((self.cache / "plat" / "db.zip").read_bytes(), cached)

    def test_an_incomplete_read_is_reported(self):
        import http.client  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415

        import export_native  # noqa: PLC0415

        def cut(*_args, **_kwargs):
            raise http.client.IncompleteRead(b"par")

        with mock.patch.object(export_native, "fetch", cut):
            originals, missing = collect_originals(
                _OneFileExporter("https://example.invalid/list.txt"), {}, self.cache, True
            )
        self.assertEqual((originals, len(missing)), ({}, 1))

    def test_the_index_names_a_file_the_same_from_any_directory(self):
        target = self.cache / "plat" / "list.txt"
        self.assertEqual(source_key(target, self.index), "plat/list.txt")
        relative = Path(os.path.relpath(target, Path.cwd()))
        self.assertEqual(source_key(relative, self.index), "plat/list.txt")


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
        import copy  # noqa: PLC0415

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

        def zips(text: str) -> dict[tuple[str, str], str]:
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
        exporter = discover_exporters()["recalbox"]()
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
             if c["kind"] == "requirement_corrected"],
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


class AnExportLeavesNoStaleFile(unittest.TestCase):
    """RetroPie writes one scriptmodule per corrected package. A second run on
    a fresher truth printed "2 packages corrected" over a directory still
    holding the six files of the first run."""

    def test_files_this_run_does_not_write_are_removed(self):
        import export_native  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "retropie"
            (root / "scriptmodules" / "libretrocores").mkdir(parents=True)
            kept = root / "scriptmodules" / "libretrocores" / "lr-mgba.sh"
            stale = root / "scriptmodules" / "libretrocores" / "lr-pcsx-rearmed.sh"
            gone_dir = root / "scriptmodules" / "emulators"
            gone_dir.mkdir()
            for path in (kept, stale, gone_dir / "pcsx-rearmed.sh"):
                path.write_text("old", encoding="utf-8")
            export_native._remove_stale(root, {"scriptmodules/libretrocores/lr-mgba.sh"})
            self.assertTrue(kept.exists())
            self.assertFalse(stale.exists())
            self.assertFalse(gone_dir.exists())

    def test_the_export_clears_before_it_writes(self):
        source = (REPO_ROOT / "scripts" / "export_native.py").read_text()
        body = source[source.index("def export_platform("):]
        self.assertLess(body.index("_remove_stale("), body.index("_write_produced("))


class AnExportIsWrittenAsItsBytes(unittest.TestCase):
    """write_text translated line ends on Windows (FirmwareDatabase.cs is
    CRLF, it would have become CR CR LF), replaced the published file in
    place, and dropped the mode: rocknix-systems is 100755 upstream."""

    def test_bytes_mode_and_atomicity(self):
        import stat  # noqa: PLC0415

        import export_native  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            root = Path(tmp)
            export_native._write_produced(root, {
                "FirmwareDatabase.cs": "a\r\nb\r\n",
                "rocknix-systems": "#!/usr/bin/python\n",
            }, {"rocknix-systems": 0o755})
            self.assertEqual((root / "FirmwareDatabase.cs").read_bytes(), b"a\r\nb\r\n")
            mode = lambda name: stat.S_IMODE((root / name).stat().st_mode)  # noqa: E731
            self.assertEqual(mode("rocknix-systems"), 0o755)
            self.assertEqual(mode("FirmwareDatabase.cs"), 0o644)
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             ["FirmwareDatabase.cs", "rocknix-systems"])

    def test_rocknix_says_its_script_is_executable(self):
        self.assertEqual(discover_exporters()["rocknix"].file_modes(),
                         {"rocknix-systems": 0o755})


class AnExportWithoutTruthIsRefused(unittest.TestCase):
    """dist/ is not committed and exports/ is. On a fresh clone, or with a
    mistyped --truth-dir, the export copied each platform's file back
    uncorrected, said OK, and replaced the corrected export in exports/."""

    def test_nothing_is_written_and_the_run_fails(self):
        import export_native  # noqa: PLC0415

        exporter = discover_exporters()["batocera"]
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            output = Path(tmp) / "out"
            published = output / "batocera" / "batocera-systems"
            published.parent.mkdir(parents=True)
            published.write_text("corrected", encoding="utf-8")
            ok, messages = export_native.export_platform(
                "batocera", exporter, Path(tmp) / "no-truth", output,
                str(REPO_ROOT / "platforms"), Path(tmp) / "no-cache", False,
            )
            self.assertFalse(ok)
            self.assertIn("generate_truth.py", messages[0])
            self.assertEqual(published.read_text(encoding="utf-8"), "corrected")
            self.assertEqual(sorted(p.name for p in output.rglob("*")),
                             ["batocera", "batocera-systems"])


class AnInvalidExportIsNotWritten(unittest.TestCase):
    """validate() ran after the files were written: an export its own
    validator refused still replaced the published one, and only the exit
    code said so."""

    def test_the_published_file_stays(self):
        from unittest import mock  # noqa: PLC0415

        import export_native  # noqa: PLC0415

        if not (UPSTREAM_CACHE / "romm").exists():
            self.skipTest("upstream cache not populated")
        exporter = discover_exporters()["romm"]
        config = native_layer(load_platform_config("romm", str(REPO_ROOT / "platforms")))
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            output = Path(tmp) / "out"
            published = output / "romm" / "known_bios_files.json"
            published.parent.mkdir(parents=True)
            published.write_text("published", encoding="utf-8")
            with mock.patch.object(export_native, "load_inputs",
                                   return_value=({"systems": {}}, config)), \
                 mock.patch.object(exporter, "validate", return_value=["bad entry"]):
                ok, messages = export_native.export_platform(
                    "romm", exporter, Path(tmp), output,
                    str(REPO_ROOT / "platforms"), UPSTREAM_CACHE, False,
                )
            self.assertFalse(ok)
            self.assertIn("INVALID: bad entry", messages)
            self.assertEqual(published.read_text(encoding="utf-8"), "published")


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
        from export_native import landed_changes  # noqa: PLC0415

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
        from exporter.recalbox_exporter import _stated  # noqa: PLC0415

        self.assertEqual(_stated('<bios path="a" md5="1,2" />'),
                         _stated('<bios path="a" md5="2,1" />'))

    def test_one_attribute_changes_in_place(self):
        from exporter.recalbox_exporter import patch_element  # noqa: PLC0415

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
        from exporter.retrobat_exporter import keep_blank_lines  # noqa: PLC0415

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
        from exporter.misterfpga_exporter import rebuild_archive  # noqa: PLC0415

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
        import export_native  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            export_native._write_produced(Path(tmp), {"a.zip": b"PK\x03\x04\xff"}, {})
            self.assertEqual((Path(tmp) / "a.zip").read_bytes(), b"PK\x03\x04\xff")

    def test_a_new_hash_without_a_size_leaves_the_entry_whole(self):
        """The Downloader checks each entry by size (fetch_file_worker.py:127):
        the old size beside the new hash described no file, and the report
        announced a size removal the database did not carry."""
        from export_native import landed_changes  # noqa: PLC0415

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
        from exporter.retrodeck_exporter import Exporter  # noqa: PLC0415

        mine = OrderedDict([("filename", "bios.bin"), ("system", "xbox"), ("required", "Yes")])
        (merged,) = Exporter._merge([OrderedDict(mine)], [OrderedDict(mine)])
        self.assertNotIn("md5", merged)

    def test_a_single_bios_object_stays_an_object(self):
        from exporter.retrodeck_exporter import Exporter  # noqa: PLC0415

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
        systems, report = build_native_model(truth, SCRAPED)
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


class UpstreamFidelity(unittest.TestCase):
    """The real files, compared against what we hand back.

    Nothing a platform declares today may be missing from the export: an
    export that loses systems is one no maintainer can apply.
    """

    @classmethod
    def setUpClass(cls):
        if not UPSTREAM_CACHE.is_dir():
            raise unittest.SkipTest(
                "no upstream cache, run scripts/export_native.py --all --fetch"
            )

    def _export(self, platform: str, truth: dict | None = None) -> dict[str, str]:
        cache = UPSTREAM_CACHE / platform
        if not cache.is_dir():
            self.skipTest(f"no cached original for {platform}")
        scraped = load_platform_config(platform, str(REPO_ROOT / "platforms"))
        systems, report = build_native_model(truth or {"systems": {}}, scraped)
        exporter = discover_exporters()[platform]()
        originals: dict[str, str] = {}
        for path in cache.rglob("*"):
            if not path.is_file():
                continue
            relative = str(path.relative_to(cache))
            if relative.endswith((".zip", ".tar.gz")) and hasattr(exporter, "unpack"):
                originals.update(exporter.unpack(path.read_bytes()))
            else:
                originals[relative] = path.read_text(
                    encoding="utf-8", errors="replace"
                )
        produced = exporter.render(systems, report, originals, scraped)
        self.assertEqual(exporter.validate(systems, produced), [])
        return produced, originals

    def test_retrodeck_keeps_every_bios_entry_it_declares(self):
        """The component list is corrected in place, never replaced.

        Assigning our entries wholesale dropped 114 distinct filenames that
        RetroDECK's own manifests declare.
        """
        produced, originals = self._export("retrodeck")

        def names(text: str) -> set[str]:
            manifest = json.loads(text)
            for value in manifest.values():
                if not isinstance(value, dict):
                    continue
                listing = value.get("bios")
                if listing is None:
                    for key in ("preset_actions", "cores"):
                        nested = value.get(key)
                        if isinstance(nested, dict) and "bios" in nested:
                            listing = nested["bios"]
                            break
                if listing is None:
                    continue
                return {
                    str(e.get("filename", ""))
                    for e in listing
                    if isinstance(e, dict)
                }
            return set()

        lost: set[str] = set()
        compared = 0
        for path, text in produced.items():
            if path not in originals:
                continue
            compared += 1
            lost |= names(originals[path]) - names(text)
        self.assertGreater(compared, 0, "no component manifest was compared")
        self.assertEqual(
            lost, set(), "the export dropped entries RetroDECK declares"
        )

    def test_recalbox_keeps_every_system_and_every_path(self):
        produced, originals = self._export("recalbox")
        before = parse_untrusted_xml(originals["es_bios.xml"], "es_bios.xml")
        after = ET.fromstring(produced["es_bios.xml"])
        self.assertEqual(
            {s.get("platform") for s in before.iter("system")}
            - {s.get("platform") for s in after.iter("system")},
            set(),
        )
        self.assertEqual(
            {b.get("path") for b in before.iter("bios")}
            - {b.get("path") for b in after.iter("bios")},
            set(),
        )

    def test_the_recalbox_export_satisfies_the_schema_recalbox_ships(self):
        schema_path = UPSTREAM_CACHE / "recalbox" / "es_bios.xsd"
        if not schema_path.exists():
            self.skipTest("es_bios.xsd not cached")
        required = self._required_attributes(schema_path.read_text())
        produced, _ = self._export("recalbox")
        root = ET.fromstring(produced["es_bios.xml"])
        for tag, attributes in required.items():
            for element in root.iter(tag):
                for attribute in attributes:
                    with self.subTest(tag=tag, attribute=attribute):
                        self.assertTrue(element.get(attribute))

    @staticmethod
    def _required_attributes(schema: str) -> dict[str, set[str]]:
        """Read the required attributes straight out of the platform's XSD.

        Scoped to each element's own type: a nested declaration belongs to
        the child, and folding it into the parent would demand md5 on
        <system>.
        """
        namespace = "{http://www.w3.org/2001/XMLSchema}"
        root = parse_untrusted_xml(schema, "es_bios.xsd")
        required: dict[str, set[str]] = {}

        def own_attributes(node: ET.Element) -> set[str]:
            found: set[str] = set()
            for child in node:
                if child.tag == f"{namespace}element":
                    continue
                if child.tag == f"{namespace}attribute":
                    if child.get("use") == "required" and child.get("name"):
                        found.add(child.get("name"))
                    continue
                found |= own_attributes(child)
            return found

        for element in root.iter(f"{namespace}element"):
            name = element.get("name")
            if not name:
                continue
            names = own_attributes(element)
            if names:
                required[name] = names
        return required

    def test_batocera_keeps_every_system_and_still_runs(self):
        produced, originals = self._export("batocera")
        before = set(
            re.findall(r'^\s{4}"([^"]+)":\s*\{\s*"name"', originals["batocera-systems"],
                       re.M)
        )
        after = set(
            re.findall(r'^\s{4}"([^"]+)":\s*\{\s*"name"',
                       produced["batocera-systems"], re.M)
        )
        self.assertEqual(before - after, set())

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "batocera-systems"
            script.write_text(produced["batocera-systems"], encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--createReadme"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip())

    def test_batocera_keeps_the_zip_member_checks(self):
        """checkInsideZip verifies a ROM inside the archive, not the archive."""
        produced, originals = self._export("batocera")
        self.assertEqual(
            produced["batocera-systems"].count("zippedFile"),
            originals["batocera-systems"].count("zippedFile"),
        )

    def test_rocknix_still_runs(self):
        produced, _ = self._export("rocknix")
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "rocknix-systems"
            script.write_text(produced["rocknix-systems"], encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--createReadme"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_emudeck_keeps_every_check_and_still_parses(self):
        produced, originals = self._export("emudeck")
        pattern = re.compile(r"^(\w+)\(\)\{", re.M)
        before = set(pattern.findall(originals["checkBIOS.sh"]))
        after = set(pattern.findall(produced["checkBIOS.sh"]))
        self.assertEqual(before - after, set())

        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "checkBIOS.sh"
            script.write_text(produced["checkBIOS.sh"], encoding="utf-8")
            result = subprocess.run(
                ["bash", "-n", str(script)], capture_output=True, text=True, timeout=60
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_emudeck_keeps_every_md5_it_declares(self):
        """An md5 the platform holds is never withdrawn from its array.

        The array was assigned wholesale, so any value our model did not
        carry disappeared and a user whose dump matched it stopped passing
        EmuDeck's own check.
        """
        produced, originals = self._export("emudeck")
        pattern = re.compile(r"local\s+hashes=\(([^)]*)\)")
        before = pattern.findall(originals["checkBIOS.sh"])
        after = pattern.findall(produced["checkBIOS.sh"])
        self.assertEqual(len(before), len(after), "an md5 array vanished")
        for index, (was, now) in enumerate(zip(before, after)):
            with self.subTest(array=index):
                self.assertEqual(
                    set(was.split()) - set(now.split()),
                    set(),
                    "the export withdrew an md5 EmuDeck declares",
                )

    def test_retrobat_keeps_every_system_and_every_file(self):
        produced, originals = self._export("retrobat")
        before = json.loads(originals["batocera-systems.json"])
        after = json.loads(produced["batocera-systems.json"])
        self.assertEqual(set(before) - set(after), set())
        self.assertEqual(
            {(s, f["file"]) for s, d in before.items() for f in d["biosFiles"]}
            - {(s, f["file"]) for s, d in after.items() for f in d["biosFiles"]},
            set(),
        )

    def test_retroarch_keeps_every_rom_name_the_dat_declares(self):
        produced, originals = self._export("retroarch")
        pattern = re.compile(r"^\trom \( name (\"[^\"]+\"|\S+)", re.M)
        before = {n.strip('"') for n in pattern.findall(originals["System.dat"])}
        after = {n.strip('"') for n in pattern.findall(produced["System.dat"])}
        self.assertEqual(before - after, set())

    def test_the_dat_keeps_the_system_names_libretro_writes(self):
        """The comment is the name the DAT spells, separator included."""
        produced, originals = self._export("retroarch")
        comments = re.compile(r'^\tcomment "([^"]+)"', re.M)
        before = set(comments.findall(originals["System.dat"]))
        after = set(comments.findall(produced["System.dat"]))
        self.assertEqual(before - after, set())

    def test_the_dat_never_states_a_rom_it_cannot_hash(self):
        produced, _ = self._export("retroarch")
        for line in re.findall(r"^\trom \( (.*) \)$", produced["System.dat"], re.M):
            with self.subTest(line=line[:60]):
                self.assertTrue(
                    any(f" {h} " in line for h in ("crc", "md5", "sha1"))
                )

    def test_misterfpga_keeps_the_download_urls_it_installs_from(self):
        produced, _ = self._export("misterfpga")
        database = json.loads(produced["bios_db.json"])
        self.assertTrue(database.get("db_id"))
        for path, entry in database["files"].items():
            with self.subTest(path=path):
                self.assertTrue(entry.get("url"))

    def test_bizhawk_stays_compilable(self):
        produced, originals = self._export("bizhawk")
        source = produced["FirmwareDatabase.cs"]
        self.assertEqual(source.count("{"), source.count("}"))
        self.assertEqual(
            source.count("FirmwareAndOption("),
            originals["FirmwareDatabase.cs"].count("FirmwareAndOption("),
        )

    # A core RetroPie packages, with a file its help does not yet name.
    RETROPIE_TRUTH = {
        "systems": {
            "magnavox-odyssey2": {
                "files": [
                    {
                        "name": "c52.bin",
                        "required": True,
                        "md5": "f1071cdb0b6b10dde94d3bc8a6146387",
                        "_cores": ["o2em"],
                    }
                ]
            }
        }
    }

    def test_retropie_keeps_every_name_its_packages_already_list(self):
        """RetroPie's BIOS list is prose, and a name it writes is never removed."""
        produced, originals = self._export("retropie", self.RETROPIE_TRUTH)
        exporter = discover_exporters()["retropie"]()
        help_of = re.compile(r'rp_module_help="((?:[^"\\]|\\.)*)"')
        for relative, text in produced.items():
            with self.subTest(module=relative):
                before = help_of.search(originals[relative])
                after = help_of.search(text)
                self.assertIsNotNone(after, "the help string is not closed")
                self.assertEqual(
                    exporter._listed(before.group(1))
                    - exporter._listed(after.group(1)),
                    set(),
                )
                self.assertIn("BIOS", after.group(1))

    def test_a_patched_scriptmodule_still_parses_as_bash(self):
        produced, _ = self._export("retropie", self.RETROPIE_TRUTH)
        self.assertTrue(produced)
        with tempfile.TemporaryDirectory() as tmp:
            for relative, text in produced.items():
                script = Path(tmp) / Path(relative).name
                script.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    ["bash", "-n", str(script)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                with self.subTest(module=relative):
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_retropie_never_drafts_a_sentence_nobody_wrote(self):
        """A package with no BIOS list is a docs change, not a correction."""
        produced, originals = self._export("retropie", self.RETROPIE_TRUTH)
        for relative in produced:
            with self.subTest(module=relative):
                self.assertIn("BIOS", originals[relative])

    def test_retrodeck_writes_a_manifest_per_component(self):
        produced, _ = self._export("retrodeck")
        self.assertTrue(produced)
        for path, content in produced.items():
            with self.subTest(path=path):
                self.assertTrue(path.endswith("component_manifest.json"))
                manifest = json.loads(content)
                component = next(iter(manifest.values()))
                self.assertTrue(
                    component.get("name") or component.get("system"),
                    "the component lost its identity",
                )



class ARecordDescribesOneDump(unittest.TestCase):
    """syscard2.pce: System.dat states v2.1 (crc 283b74e0, md5, sha1),
    geargrafx accepts three crcs with v2.0's first. Field by field, the
    export wrote v2.0's crc beside v2.1's md5 and sha1."""

    def test_the_platform_record_stays_whole_when_the_truth_accepts_it(self):
        from exporter.baseline import NativeFile

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
        from exporter.baseline import NativeFile

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
        systems, _ = build_native_model(truth, scraped)
        runners = {fe.name: fe.runners for fe in systems["psx"].files}
        self.assertEqual(runners["a.bin"], [(False, "mednafen_psx")])
        self.assertEqual(runners["b.bin"], [(True, "duckstation")])
        self.assertEqual(runners["c.bin"], [])


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
