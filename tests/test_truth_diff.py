#!/usr/bin/env python3
"""Rename detection in the truth-vs-platform diff.

A platform may call a file whatever it likes: Batocera ships the same Sega CD
ROM as ROM1. A name that matches nothing in the profile is therefore not yet a
gap, and reporting it as both a missing file and an extra one would invent a
discrepancy that does not exist. Content decides, as everywhere else here.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import pathlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from exporter.baseline import pair_entries  # noqa: E402
from truth import (  # noqa: E402
    _diff_system,
    _merge_file_into_system,
    generate_platform_truth,
)


def _entry(name: str, **hashes) -> dict:
    return {"name": name, **hashes}


class ATargetedModelIsItsOwnArtifact(unittest.TestCase):
    """A narrowed truth model must not take the full model's place.

    generate_truth wrote dist/truth/<platform>.yml whatever --target said, so
    a targeted run overwrote the full model and diff_truth then compared a
    narrowed model against the whole scrape.
    """

    def test_a_target_writes_beside_the_full_model(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=str(repo / "tmp")) as directory:
            for extra in ([], ["--target", "browser"]):
                proc = subprocess.run(
                    [sys.executable, "scripts/generate_truth.py", "--platform",
                     "romm", *extra, "--output-dir", directory],
                    capture_output=True, check=False, text=True, cwd=str(repo), timeout=400,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            produced = sorted(
                str(p.relative_to(directory))
                for p in pathlib.Path(directory).rglob("*.yml")
            )
            self.assertEqual(
                produced,
                ["browser/romm.yml", "romm.yml"],
                "the targeted model did not land beside the full one",
            )


    def test_a_named_platform_without_the_target_is_refused(self):
        """bizhawk --target switch printed "skipped", then Done., exit 0,
        and wrote no model: the diff after it failed instead."""
        repo = pathlib.Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=str(repo / "tmp")) as directory:
            proc = subprocess.run(
                [sys.executable, "scripts/generate_truth.py", "--platform", "bizhawk",
                 "--target", "switch", "--output-dir", directory],
                capture_output=True, check=False, text=True, cwd=str(repo), timeout=400,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("bizhawk has no hardware targets", proc.stderr)
            self.assertNotIn("Done.", proc.stdout)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])


class ADiffThatComparedNothingFails(unittest.TestCase):
    """diff_truth --all skipped every platform without a model and exited 0."""

    def test_an_empty_truth_directory_is_an_error(self):
        repo = pathlib.Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=str(repo / "tmp")) as directory:
            for selection in (["--all"], ["--platform", "retroarch"]):
                proc = subprocess.run(
                    [sys.executable, "scripts/diff_truth.py", *selection,
                     "--truth-dir", directory, "--json"],
                    capture_output=True, check=False, text=True, cwd=str(repo), timeout=120,
                )
                self.assertEqual(proc.returncode, 1, selection)
                self.assertIn("skip", proc.stderr)


class OneNameSeveralFiles(unittest.TestCase):
    """Dolphin's three IPL.bin differ only by path, and the model kept one."""

    REGIONS = {"USA": "a" * 32, "EUR": "b" * 32, "JAP": "c" * 32}

    def _system(self) -> dict:
        system: dict = {}
        for core in ("dolphin", "ishiiruka"):
            for region, md5 in self.REGIONS.items():
                _merge_file_into_system(
                    system,
                    {"name": "IPL.bin", "path": f"GC/{region}/IPL.bin", "md5": md5},
                    core,
                    None,
                )
        _merge_file_into_system(system, {"name": "IPL.bin"}, "other", None)
        return system

    def test_a_core_declaring_a_name_twice_declares_two_files(self):
        files = self._system()["files"]
        self.assertEqual(
            sorted(f["path"] for f in files),
            ["GC/EUR/IPL.bin", "GC/JAP/IPL.bin", "GC/USA/IPL.bin"],
        )
        for entry in files:
            self.assertEqual(entry["_cores"] - {"other"}, {"dolphin", "ishiiruka"})

    def test_revisions_under_one_name_and_no_path_stay_one_file(self):
        system: dict = {}
        for md5 in ("a" * 32, "b" * 32):
            _merge_file_into_system(
                system, {"name": "MT32_CONTROL.ROM", "md5": md5}, "dosbox", None
            )
        self.assertEqual(len(system["files"]), 1)

    def test_the_diff_pairs_each_by_destination(self):
        scraped = {"files": [
            {"name": "IPL.bin", "destination": f"dolphin-emu/Sys/GC/{region}/IPL.bin",
             "md5": md5}
            for region, md5 in self.REGIONS.items()
        ]}
        self.assertEqual(_diff_system(self._system(), scraped), {})


class ADestinationIsThePath(unittest.TestCase):
    def test_a_profile_destination_reaches_the_truth(self):
        """redream names its BIOS dc_bios.bin and reads it at dc/boot.bin.
        The truth dropped `destination:`, so the export never saw that
        System.dat declares dc/boot.bin and added a dc_bios.bin line."""
        system: dict = {}
        _merge_file_into_system(system, {"name": "dc_bios.bin",
                                         "destination": "dc/boot.bin",
                                         "md5": "a" * 32}, "redream", None)
        self.assertEqual(system["files"][0]["path"], "dc/boot.bin")
        scraped = {"files": [{"name": "dc/boot.bin", "destination": "dc/boot.bin",
                              "md5": "a" * 32}]}
        self.assertEqual(_diff_system(system, scraped), {})


class DifferentContentsStayApart(unittest.TestCase):
    def test_two_cores_same_name_different_contents(self):
        """beebem's BBC BIOS.rom and np2kai's PC-98 bios.rom merged into one."""
        system: dict = {}
        _merge_file_into_system(system, {"name": "bios.rom", "path": "np2kai/bios.rom",
                                         "md5": "a" * 32}, "np2kai", None)
        _merge_file_into_system(system, {"name": "bios.rom", "path": "BeebFile/BIOS.rom",
                                         "md5": "b" * 32, "size": 16384}, "beebem", None)
        self.assertEqual(len(system["files"]), 2)


class RenameMatching(unittest.TestCase):
    """A platform may call a file anything (Batocera ships a ROM as ROM1):
    a shared hash pairs the two names, through the rule export_native uses."""

    @staticmethod
    def _pair(truth, scraped):
        return pair_entries([truth], scraped).get(0)

    def test_a_shared_sha1_pairs_the_two_names(self):
        self.assertEqual(
            self._pair(_entry("bios_CD_U.bin", sha1="a" * 40),
                       [_entry("ROM1.bin", sha1="a" * 40)]),
            0,
        )

    def test_md5_crc32_and_sha256_pair_them_too(self):
        for algorithm, value in (("md5", "b" * 32), ("crc32", "b" * 8), ("sha256", "c" * 64)):
            with self.subTest(algorithm=algorithm):
                self.assertEqual(
                    self._pair(_entry("a.bin", **{algorithm: value}),
                               [_entry("b.bin", **{algorithm: value})]),
                    0,
                )

    def test_hash_comparison_ignores_case(self):
        self.assertEqual(
            self._pair(_entry("a.bin", sha1="AbCdEf" + "0" * 34),
                       [_entry("b.bin", sha1="abcdef" + "0" * 34)]),
            0,
        )

    def test_different_content_is_not_a_rename(self):
        self.assertIsNone(
            self._pair(_entry("a.bin", sha1="a" * 40), [_entry("b.bin", sha1="b" * 40)])
        )

    def test_files_with_no_hashes_never_pair(self):
        """Two unknowns are not evidence of the same file."""
        self.assertIsNone(self._pair(_entry("a.bin"), [_entry("b.bin")]))

    def test_a_hash_yaml_made_a_number_reads_as_its_digits(self):
        # A digit-only crc32 written unquoted: the export writes it back.
        self.assertEqual(
            self._pair(_entry("a.bin", crc32=12345678), [_entry("b.bin", crc32="12345678")]),
            0,
        )

    def test_a_claimed_entry_never_answers_twice(self):
        scraped = [_entry("b.bin", sha1="a" * 40)]
        truth = [_entry("a.bin", sha1="a" * 40), _entry("c.bin", sha1="a" * 40)]
        self.assertEqual(pair_entries(truth, scraped), {0: 0})

    def test_the_diff_reads_no_gap_for_a_rename(self):
        truth = {"files": [_entry("a.bin", sha1="a" * 40)]}
        scraped = {"files": [_entry("b.bin", sha1="a" * 40)]}
        self.assertEqual(_diff_system(truth, scraped), {})



class PlatformMultiHash(unittest.TestCase):
    """Recalbox and RetroDECK write accepted md5s as one comma string.

    Read as one value, scph1001.bin was a mismatch the export (which splits
    them) never corrected: diff_truth reported 15 for Recalbox, 9 for
    RetroDECK, against the 4 and 3 the content supports.
    """

    TRUTH = "924e392ed05558ffdb115408c263dccf"
    SCRAPED = "dc2b9bf8da62ec93e868cfd29f0d067d,924e392ed05558ffdb115408c263dccf"

    def test_a_shared_value_is_no_mismatch(self):
        truth = {"files": [{"name": "scph1001.bin", "md5": self.TRUTH}]}
        scraped = {"files": [{"name": "scph1001.bin", "md5": self.SCRAPED}]}
        self.assertEqual(_diff_system(truth, scraped), {})

    def test_a_rename_is_found_through_the_list(self):
        truth = [_entry("scph1001.bin", md5=self.TRUTH)]
        scraped = {"psx.bin": _entry("psx.bin", md5=self.SCRAPED)}
        self.assertEqual(pair_entries(truth, list(scraped.values())), {0: 0})


class ACompositeZipMd5IsNoContainerMd5(unittest.TestCase):
    """Recalbox hashes a .zip by its members. Its neocdz.zip md5 was set
    against geolith's container md5 and reported as a mismatch the export,
    which reads the same mark, never corrects."""

    TRUTH = {"files": [{"name": "neocdz.zip", "md5": "b31a246b69493c35194fe0bac120dc37"}]}

    def _scraped(self, **mark):
        return {"files": [{"name": "neocdz.zip", "md5": "f39572af7584cb5b3f70ae8cc848aba2",
                           **mark}]}

    def test_a_composite_md5_contradicts_nothing(self):
        self.assertEqual(_diff_system(self.TRUTH, self._scraped(zip_digest="composite")), {})

    def test_a_container_md5_still_does(self):
        result = _diff_system(self.TRUTH, self._scraped())
        self.assertEqual([m["name"] for m in result["hash_mismatch"]], ["neocdz.zip"])


class OneSlotUnderSeveralNames(unittest.TestCase):
    """kronos opens saturn_bios.bin, then sega_101.bin as a fallback. Ymir
    reads either name, so the sega_101.bin entry answers for saturn_bios.bin
    too. kronos sat in that entry's _cores and out of its _required_by while
    its saturn_bios.bin entry had it requiring the file."""

    PROFILES = {
        "kronos": {
            "emulator": "Kronos", "type": "libretro", "systems": ["sega-saturn"],
            "files": [
                {"name": "saturn_bios.bin", "path": "kronos/saturn_bios.bin",
                 "required": True, "size": 524288},
                {"name": "sega_101.bin", "required": False, "size": 524288},
            ],
        },
        "ymir": {
            "emulator": "Ymir", "type": "libretro", "systems": ["sega-saturn"],
            "files": [
                {"name": "sega_101.bin", "required": True, "size": 524288,
                 "aliases": ["saturn_bios.bin"]},
            ],
        },
        "other": {
            "emulator": "Other", "type": "libretro", "systems": ["sega-saturn"],
            "files": [{"name": "saturn_bios.bin", "required": True, "size": 524288}],
        },
    }

    def _files(self) -> dict[str, dict]:
        cores = ["kronos", "ymir", "other"]
        model = generate_platform_truth("p", {"cores": cores}, {}, self.PROFILES)
        return {f["name"]: f for f in model["systems"]["sega-saturn"]["files"]}

    def test_a_reader_requiring_an_alias_requires_the_entry(self):
        sega = self._files()["sega_101.bin"]
        self.assertEqual(sega["_cores"], ["kronos", "ymir"])
        self.assertEqual(sega["_required_by"], ["kronos", "ymir"])

    def test_no_reader_is_added(self):
        """other requires saturn_bios.bin but never opens sega_101.bin."""
        sega = self._files()["sega_101.bin"]
        self.assertNotIn("other", sega["_required_by"])
        self.assertTrue(set(sega["_required_by"]) <= set(sega["_cores"]))


class OnlySystemDirectoryEntries(unittest.TestCase):
    """The truth kept files read from the save, content or working directory:
    diff_truth listed Cemu's mlc01 certificates, panda3ds's seeddb.bin and
    neo-emu's neogeo.zip as missing from platform lists that the pack and
    verify deliberately leave them out of."""

    def test_a_file_read_elsewhere_is_not_asked_of_the_platform(self):
        profiles = {
            "core": {
                "emulator": "Core",
                "type": "libretro",
                "systems": ["sys"],
                "files": [
                    {"name": "bios.bin", "sha1": "a" * 40},
                    {"name": "explicit.bin", "sha1": "b" * 40, "load_from": "system_dir"},
                    {"name": "cert.der", "sha1": "c" * 40, "load_from": "save_dir"},
                    {"name": "game.zip", "sha1": "d" * 40, "load_from": "content_dir"},
                ],
            }
        }
        result = generate_platform_truth("p", {"cores": ["core"]}, {}, profiles)
        names = sorted(f["name"] for f in result["systems"]["sys"]["files"])
        self.assertEqual(names, ["bios.bin", "explicit.bin"])


if __name__ == "__main__":
    unittest.main()
