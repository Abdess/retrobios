"""Truth lays a core out the way verify and the pack builder do.

truth.py kept its own rule: with no standalone_cores it read the profile
type, called a dual profile "both" and a standalone one "standalone", and
kept `mode: standalone` files that runs_standalone, and so the pack, leave
out on RetroBat, EmuDeck and RetroDECK.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from truth import generate_platform_truth  # noqa: E402


def _names(truth: dict) -> set[str]:
    return {
        f["name"]
        for system in truth.get("systems", {}).values()
        for f in system.get("files", [])
    }


class TruthFollowsRunsStandalone(unittest.TestCase):
    PROFILE = {
        "emulator": "Dual",
        "type": "standalone + libretro",
        "systems": ["sony-playstation"],
        "files": [
            {"name": "both.bin", "system": "sony-playstation", "md5": "a" * 32},
            {"name": "only_sa.bin", "system": "sony-playstation", "md5": "b" * 32,
             "mode": "standalone"},
            {"name": "only_lr.bin", "system": "sony-playstation", "md5": "c" * 32,
             "mode": "libretro"},
        ],
    }

    def test_no_standalone_cores_means_libretro_layout(self):
        config = {"cores": ["dual"], "systems": {}}
        truth = generate_platform_truth("p", config, {}, {"dual": self.PROFILE})
        self.assertEqual(_names(truth), {"both.bin", "only_lr.bin"})

    def test_named_standalone_core_gets_its_files(self):
        config = {"cores": ["dual"], "standalone_cores": ["dual"], "systems": {}}
        truth = generate_platform_truth("p", config, {}, {"dual": self.PROFILE})
        self.assertEqual(_names(truth), {"both.bin", "only_sa.bin"})



class AnArchiveStandsForItsMembers(unittest.TestCase):
    """fbneo declares bubsys.zip as the ROMs inside it. As loose truth files
    the members were added to RetroArch's System.dat, and the 480-byte
    boot.bin, filed under the Dreamcast by its bare name, merged with
    RetroDream's 2 MB BIOS."""

    PROFILES = {
        "fbneo": {
            "emulator": "FBNeo", "type": "libretro", "systems": ["konami-bubsys"],
            "files": [
                {"name": "boot.bin", "archive": "bubsys.zip", "system": "konami-bubsys",
                 "required": True, "size": 480, "crc32": "f0774fc2"},
                {"name": "400b03.8g", "archive": "bubsys.zip", "system": "konami-bubsys",
                 "required": True, "size": 8192, "crc32": "85c2afc5"},
            ],
        },
        "retrodream": {
            "emulator": "RetroDream", "type": "libretro", "systems": ["sega-dreamcast"],
            "files": [{"name": "boot.bin", "path": "boot.bin", "system": "sega-dreamcast",
                       "size": 2097152, "md5": "e10c53c2f8b90bab96ead2d368858623"}],
        },
    }
    CONFIG = {
        "cores": ["fbneo", "retrodream"],
        "systems": {"sega-dreamcast": {"files": [
            {"name": "boot.bin", "destination": "dc/boot.bin"}]}},
    }

    def test_the_archive_is_the_file(self):
        truth = generate_platform_truth("p", self.CONFIG, {}, self.PROFILES)
        bubsys = truth["systems"]["konami-bubsys"]["files"]
        self.assertEqual([f["name"] for f in bubsys], ["bubsys.zip"])
        self.assertEqual(
            sorted(m["name"] for m in bubsys[0]["contents"]), ["400b03.8g", "boot.bin"]
        )
        self.assertTrue(bubsys[0]["required"])

    def test_a_member_name_claims_no_other_system(self):
        truth = generate_platform_truth("p", self.CONFIG, {}, self.PROFILES)
        dreamcast = truth["systems"]["sega-dreamcast"]["files"]
        self.assertEqual([(f["name"], f["size"]) for f in dreamcast], [("boot.bin", 2097152)])
        self.assertEqual(dreamcast[0]["_cores"], ["retrodream"])


class AnUnattributedEntryIsNotGuessed(unittest.TestCase):
    """CLK names twenty-three machines and none of its ROMs says which: all
    of them went under amstrad-cpc, its first system, and the RomM export
    listed Apple, Mac, ZX and Amiga firmware as Amstrad CPC firmware."""

    PROFILE = {
        "emulator": "CLK", "type": "libretro",
        "systems": ["amstrad-cpc", "apple-ii", "sinclair-zx81"],
        "files": [{"name": "apple2gs.rom", "size": 131072},
                  {"name": "zx81.rom", "size": 8192}],
    }

    def truth(self, systems):
        config = {"cores": ["clk"], "systems": systems}
        return generate_platform_truth("p", config, {}, {"clk": self.PROFILE})

    def test_several_candidate_systems_file_nothing(self):
        truth = self.truth({"amstrad-cpc": {"files": []}, "apple-ii": {"files": []}})
        self.assertEqual(_names(truth), set())
        self.assertEqual(truth["_coverage"]["unattributed"], {"clk": 2})

    def test_the_platform_declaration_decides(self):
        truth = self.truth({"amstrad-cpc": {"files": []},
                            "apple-ii": {"files": [{"name": "apple2gs.rom"}]}})
        self.assertEqual(
            [f["name"] for f in truth["systems"]["apple-ii"]["files"]], ["apple2gs.rom"]
        )

    def test_one_candidate_system_takes_them(self):
        truth = self.truth({"sinclair-zx81": {"files": []}})
        self.assertEqual(
            sorted(f["name"] for f in truth["systems"]["sinclair-zx81"]["files"]),
            ["apple2gs.rom", "zx81.rom"],
        )


class EveryRevisionACoreAcceptsStays(unittest.TestCase):
    """dosbox lists each MT-32 control ROM it accepts under one name. The
    truth kept the first sha1 and dropped the others, so a frontend holding
    1.07 read as a mismatch against a core that loads it."""

    def truth(self, profiles):
        config = {"cores": list(profiles), "systems": {}}
        return generate_platform_truth("p", config, {}, profiles)

    @staticmethod
    def entry(name, sha1):
        return {"name": name, "system": "dos", "sha1": sha1}

    def test_one_core_keeps_the_union(self):
        profile = {"emulator": "DOSBox", "type": "libretro", "systems": ["dos"],
                   "files": [self.entry("MT32_CONTROL.ROM", "a" * 40),
                             self.entry("MT32_CONTROL.ROM", "b" * 40)]}
        files = self.truth({"dosbox": profile})["systems"]["dos"]["files"]
        self.assertEqual([f["sha1"] for f in files], [["a" * 40, "b" * 40]])

    def test_two_cores_that_disagree_are_two_files(self):
        """fMSX's 16640-byte RS232.ROM merged into blueMSX's 8192-byte one,
        and the export wrote one core's size beside the other's md5."""
        first = {"emulator": "A", "type": "libretro", "systems": ["dos"],
                 "files": [self.entry("x.rom", "a" * 40)]}
        second = {"emulator": "B", "type": "libretro", "systems": ["dos"],
                  "files": [{**self.entry("x.rom", "b" * 40), "path": "x.rom"}]}
        files = self.truth({"a": first, "b": second})["systems"]["dos"]["files"]
        self.assertEqual(sorted(f["sha1"] for f in files), ["a" * 40, "b" * 40])
        sizes = {"emulator": "S", "type": "libretro", "systems": ["dos"],
                 "files": [{"name": "y.rom", "system": "dos", "path": "y.rom", "size": 8192}]}
        hashed = {"emulator": "H", "type": "libretro", "systems": ["dos"],
                  "files": [{"name": "y.rom", "system": "dos", "size": 16640, "md5": "c" * 32}]}
        files = self.truth({"s": sizes, "h": hashed})["systems"]["dos"]["files"]
        self.assertEqual(
            sorted((f.get("size"), f.get("md5")) for f in files),
            [(8192, None), (16640, "c" * 32)],
        )

    def test_a_revision_known_by_one_hash_is_no_mismatch(self):
        """1.04 carries md5 and sha1, 1.07 only its sha1: a platform entry
        giving 1.07's sha1 and md5 is that revision, not a mismatch."""
        from truth import _hash_mismatch

        truth = {"name": "MT32_CONTROL.ROM", "md5": "c" * 32, "sha1": ["a" * 40, "b" * 40]}
        scraped = {"name": "MT32_CONTROL.ROM", "md5": "d" * 32, "sha1": "b" * 40}
        self.assertIsNone(_hash_mismatch(truth, scraped))
        self.assertEqual(
            _hash_mismatch(truth, {**scraped, "sha1": "e" * 40})["hash_type"], "sha1"
        )



def _filed(truth: dict, name: str) -> list[str]:
    """The systems an entry of that name was filed under."""
    return sorted(
        sid for sid, system in truth.get("systems", {}).items()
        for f in system.get("files", []) if f["name"] == name
    )


class ADeclarationOnlyAttributesTheSameFile(unittest.TestCase):
    """A name the platform declares filed an entry under that system before
    anything else, and the last declaration of a name won. fmsx's 16 KB
    DISK.ROM went to nec-pc-88 for quasi88's 2 KB disk.rom, and dosbox's
    SC-55 ROM1.BIN to galaksija, whatever their own system said."""

    @staticmethod
    def truth(platform_systems: dict, profiles: dict) -> dict:
        config = {"cores": list(profiles), "systems": platform_systems}
        return generate_platform_truth("p", config, {}, profiles)

    def test_a_same_named_rom_of_another_size_does_not_take_the_entry(self):
        fmsx = {"type": "libretro", "systems": ["microsoft-msx", "microsoft-msx2"],
                "files": [{"name": "DISK.ROM", "size": 16384}]}
        truth = self.truth({
            "microsoft-msx": {"files": [{"name": "DISK.ROM", "size": 16384}]},
            "nec-pc-88": {"files": [{"name": "disk.rom", "size": 2048}]},
        }, {"fmsx": fmsx})
        self.assertEqual(_filed(truth, "DISK.ROM"), ["microsoft-msx"])

    def test_a_refuted_declaration_leaves_the_profile_system(self):
        dosbox = {"type": "libretro", "systems": ["dos"],
                  "files": [{"name": "ROM1.BIN", "size": 32768}]}
        truth = self.truth({
            "dos": {"files": []},
            "galaksija": {"files": [{"name": "ROM1.BIN", "size": 4096}]},
        }, {"dosbox": dosbox})
        self.assertEqual(_filed(truth, "ROM1.BIN"), ["dos"])

    def test_an_explicit_system_is_not_moved_by_a_homonym(self):
        clk = {"type": "libretro", "systems": ["oric", "amstrad-cpc"],
               "files": [{"name": "basic10.rom", "system": "oric", "size": 16384}]}
        truth = self.truth({
            "elektronika-bk": {"files": [{"name": "BASIC10.ROM", "size": 24576}]},
        }, {"clk": clk})
        self.assertEqual(_filed(truth, "basic10.rom"), ["oric"])

    def test_a_multi_system_entry_refuted_everywhere_is_unattributed(self):
        oricutron = {"type": "libretro", "systems": ["oric", "oric-atmos"],
                     "files": [{"name": "basic10.rom", "max_size": 16384}]}
        truth = self.truth({
            "elektronika-bk": {"files": [{"name": "BASIC10.ROM", "size": 24576}]},
        }, {"oricutron": oricutron})
        self.assertEqual(_filed(truth, "basic10.rom"), [])
        self.assertEqual(truth["_coverage"]["unattributed"], {"oricutron": 1})

    def test_a_rom_declared_under_two_systems_is_filed_under_both(self):
        atari800 = {"type": "libretro", "systems": ["atari-400-800", "atari-5200"],
                    "files": [{"name": "ATARIXL.ROM", "md5": "a" * 32}]}
        truth = self.truth({
            "atari-400-800": {"files": [{"name": "ATARIXL.ROM", "md5": "a" * 32}]},
            "atari-5200": {"files": [{"name": "ATARIXL.ROM", "md5": "a" * 32}]},
        }, {"atari800": atari800})
        self.assertEqual(_filed(truth, "ATARIXL.ROM"), ["atari-400-800", "atari-5200"])

    def test_an_equal_size_revision_is_still_the_file(self):
        """Two md5 at one size are two revisions of one slot, as slots.py
        reads them: atari800's ATARIOSB.ROM against System.dat's."""
        atari800 = {"type": "libretro", "systems": ["atari-400-800", "atari-5200"],
                    "files": [{"name": "ATARIOSB.ROM", "md5": "a" * 32, "size": 10240}]}
        truth = self.truth({
            "atari-400-800": {"files": [{"name": "ATARIOSB.ROM", "md5": "b" * 32,
                                         "size": 10240}]},
        }, {"atari800": atari800})
        self.assertEqual(_filed(truth, "ATARIOSB.ROM"), ["atari-400-800"])

    def test_a_systemless_profile_does_not_file_a_refuted_name_as_unknown(self):
        """mess2015 declares no system. Its hiscore.dat is not the arcade
        one the platform declares, and filing it under the placeholder put
        an "unknown" section into System.dat."""
        mess = {"type": "libretro", "systems": [],
                "files": [{"name": "hiscore.dat", "size": 216250},
                          {"name": "only_mine.dat", "size": 10}]}
        truth = self.truth({"arcade": {"files": [{"name": "hiscore.dat", "size": 324575}]}},
                           {"mess2015": mess})
        self.assertEqual(_filed(truth, "hiscore.dat"), [])
        self.assertEqual(_filed(truth, "only_mine.dat"), ["unknown"])

    def test_a_bare_declaration_still_translates(self):
        """The platform's own id for our slug, from a declaration that
        states no content: nothing contradicts it."""
        pcsx = {"type": "libretro", "systems": ["sony-playstation"],
                "files": [{"name": "scph1001.bin", "md5": "a" * 32}]}
        truth = self.truth({"psx": {"files": [{"name": "scph1001.bin"}]}}, {"pcsx": pcsx})
        self.assertEqual(_filed(truth, "scph1001.bin"), ["psx"])


class ASizeOutsideARangeIsAnotherFile(unittest.TestCase):
    def test_two_cores_do_not_merge_across_a_declared_range(self):
        """bk's 24 KB BASIC10.ROM and oricutron's basic10.rom (max_size
        16384) merged into one entry, which took the Oric md5."""
        from truth import _merge_file_into_system  # noqa: PLC0415

        system: dict = {}
        _merge_file_into_system(system, {"name": "BASIC10.ROM", "size": 24576,
                                         "md5": "a" * 32}, "bk", None)
        _merge_file_into_system(system, {"name": "basic10.rom", "max_size": 16384},
                                "oricutron", None)
        self.assertEqual(len(system["files"]), 2)


class TruthRecordsWhoOpensByName(unittest.TestCase):
    """DuckStation finds its BIOS by MD5 in a folder it scans (bios.cpp:208,
    397-427): its names are labels. The export wrote them into Batocera's
    list as files to hold, and a user with only scph5501.bin read 104
    missing BIOS where DuckStation boots."""

    DUCK = {"type": "libretro", "systems": ["sony-playstation"], "found_by": "content",
            "files": [{"name": "scph1001_v20.bin", "md5": "a" * 32},
                      {"name": "scph1001.bin", "md5": "b" * 32}]}
    PCSX = {"type": "libretro", "systems": ["sony-playstation"],
            "files": [{"name": "scph1001.bin", "size": 524288}]}

    def truth(self, profiles: dict) -> dict:
        config = {"cores": list(profiles), "systems": {"sony-playstation": {"files": []}}}
        return generate_platform_truth("p", config, {}, profiles)

    def entries(self, truth: dict) -> list[dict]:
        return truth["systems"]["sony-playstation"]["files"]

    def test_a_content_scanning_core_names_nothing(self):
        truth = self.truth({"duckstation": self.DUCK})
        self.assertEqual({f["name"]: f["_named_by"] for f in self.entries(truth)},
                         {"scph1001_v20.bin": [], "scph1001.bin": []})

    def test_a_label_lends_no_hash_to_a_name_another_core_opens(self):
        """pcsx_rearmed opens scph1001.bin by name, with no hash: it took the
        md5 of DuckStation's label of that name."""
        truth = self.truth({"duckstation": self.DUCK, "pcsx": self.PCSX})
        named = [f for f in self.entries(truth) if f["_named_by"] == ["pcsx"]]
        self.assertEqual(len(named), 1)
        self.assertNotIn("md5", named[0])

    def test_the_build_decides(self):
        ymir = {"type": "standalone + libretro", "systems": ["sega-saturn"],
                "found_by": {"standalone": "content"},
                "files": [{"name": "sega_101.bin", "md5": "c" * 32}]}
        config = {"cores": ["ymir"], "standalone_cores": [],
                  "systems": {"sega-saturn": {"files": []}}}
        libretro = generate_platform_truth("p", config, {}, {"ymir": ymir})
        self.assertEqual(libretro["systems"]["sega-saturn"]["files"][0]["_named_by"], ["ymir"])
        config["standalone_cores"] = ["ymir"]
        standalone = generate_platform_truth("p", config, {}, {"ymir": ymir})
        self.assertEqual(standalone["systems"]["sega-saturn"]["files"][0]["_named_by"], [])


class TruthKnowsWhatTheEmulatorInstalls(unittest.TestCase):
    """The pack leaves out a file the emulator installs itself (validation.
    deliverable). The truth did not, so RetroPie's gngeopi help asked users
    to copy gngeo_data.zip, which make install puts beside the package, and
    RetroDECK's manifests listed xemu's xbox_hdd.qcow2."""

    @staticmethod
    def truth(files: list[dict], platform: str = "p", standalone: list | None = None,
              profile_type: str = "libretro") -> dict:
        profile = {"type": profile_type, "systems": ["neogeo"], "files": files}
        config = {"cores": ["emu"], "standalone_cores": standalone or [],
                  "systems": {"neogeo": {"files": []}}}
        return generate_platform_truth(platform, config, {}, {"emu": profile})

    @staticmethod
    def entry(truth: dict, name: str) -> dict:
        return next(f for f in truth["systems"]["neogeo"]["files"] if f["name"] == name)

    def test_a_bundled_entry_is_kept_and_marked(self):
        truth = self.truth([{"name": "data.zip", "md5": "a" * 32, "bundled": True},
                            {"name": "bios.zip", "md5": "b" * 32}])
        self.assertTrue(self.entry(truth, "data.zip")["bundled"])
        self.assertNotIn("bundled", self.entry(truth, "bios.zip"))
        self.assertEqual(self.entry(truth, "bios.zip")["_brought_by"], ["emu:libretro"])

    def test_installed_on_scopes_to_the_platform(self):
        files = [{"name": "data.zip", "md5": "a" * 32, "installed_on": ["retropie"]}]
        self.assertTrue(self.entry(self.truth(files, "retropie"), "data.zip")["bundled"])
        self.assertNotIn("bundled", self.entry(self.truth(files, "batocera"), "data.zip"))

    def test_not_bundled_on_brings_it_back(self):
        files = [{"name": "data.zip", "md5": "a" * 32, "bundled": True,
                  "not_bundled_on": ["batocera"]}]
        self.assertNotIn("bundled", self.entry(self.truth(files, "batocera"), "data.zip"))

    def test_bundled_for_one_build_only(self):
        """PPSSPP's standalone release ships its assets, the core does not."""
        files = [{"name": "assets.zip", "md5": "a" * 32, "bundled": True, "mode": "standalone"},
                 {"name": "assets.zip", "md5": "a" * 32, "mode": "libretro"}]
        standalone = self.truth(files, standalone=["emu"], profile_type="standalone + libretro")
        self.assertTrue(self.entry(standalone, "assets.zip")["bundled"])
        libretro = self.truth(files, profile_type="standalone + libretro")
        self.assertNotIn("bundled", self.entry(libretro, "assets.zip"))

    def test_an_archive_is_installed_when_every_member_is(self):
        """gngeopi declares gngeo_data.zip and its members, all bundled. The
        archive rebuilt from its members carried no mark, counted as brought,
        and RetroPie's help named it as a file to copy."""
        files = [{"name": "data.zip", "md5": "a" * 32, "bundled": True},
                 {"name": "cmc42.xor", "archive": "data.zip", "crc32": "11111111",
                  "bundled": True}]
        self.assertTrue(self.entry(self.truth(files), "data.zip")["bundled"])
        files[1] = {**files[1], "bundled": False}
        self.assertNotIn("bundled", self.entry(self.truth(files), "data.zip"))

    def test_unread_on_leaves_the_entry_out(self):
        files = [{"name": "cdbios.bin", "md5": "a" * 32, "unread_on": ["retrobat"]}]
        names = [f["name"] for f in self.truth(files, "retrobat")["systems"]["neogeo"].get("files", [])]
        self.assertEqual(names, [])


class TheModelIsAFunctionOfItsInputs(unittest.TestCase):
    """Two runs on the same inputs wrote dist/truth/<platform>.yml with its
    systems in two orders. The systems a core covers without a file were
    added by walking a set, so the hash seed decided where each was written.
    """

    NAMES = [f"core{i:02d}" for i in range(16)]
    SCRIPT = (
        "import json, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from truth import generate_platform_truth\n"
        "names = [f'core{i:02d}' for i in range(16)]\n"
        "profiles = {n: {'emulator': n, 'type': 'libretro',\n"
        "                'systems': [f'maker-system-{n}'], 'files': []} for n in names}\n"
        "config = {'cores': names,\n"
        "          'systems': {f'maker-system-{n}': {'files': []} for n in names}}\n"
        "print(json.dumps(generate_platform_truth('p', config, {}, profiles)))\n"
    )

    def _model(self, seed: str) -> str:
        proc = subprocess.run(
            [sys.executable, "-c", self.SCRIPT, str(REPO_ROOT / "scripts")],
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True, text=True, timeout=120, check=True,
        )
        return proc.stdout

    def test_the_hash_seed_changes_nothing(self):
        first = self._model("0")
        for seed in ("1", "2", "3", "4"):
            with self.subTest(seed=seed):
                self.assertEqual(self._model(seed), first)

    def test_the_profile_order_changes_nothing(self):
        profiles = {
            n: {"emulator": n, "type": "libretro", "systems": [f"maker-system-{n}"],
                "files": [{"name": f"{n}.bin", "system": f"maker-system-{n}",
                           "md5": f"{i:032x}"}]}
            for i, n in enumerate(self.NAMES)
        }
        config = {"cores": self.NAMES,
                  "systems": {f"maker-system-{n}": {"files": []} for n in self.NAMES}}
        expected = json.dumps(generate_platform_truth("p", config, {}, profiles))
        shuffled = list(profiles.items())
        random.Random(7).shuffle(shuffled)
        self.assertEqual(
            json.dumps(generate_platform_truth("p", config, {}, dict(shuffled))), expected
        )


class RegionFollowsEveryReader(unittest.TestCase):
    """The first core to tag a file set its region in the truth: the ST-V
    BIOS kept beetle_saturn's Americas and lost mednafen_stv's Korea, and
    psxonpsp660.bin read japan although beetle_psx declares it untagged.
    The pack's region index takes the union and voids it on an untagged
    reader, and the truth now says the same."""

    @staticmethod
    def _profile(name: str, region: list[str] | None) -> dict:
        entry = {"name": "bios.bin", "system": "sega-stv", "md5": "a" * 32}
        if region is not None:
            entry["region"] = region
        return {"emulator": name, "type": "libretro", "systems": ["sega-stv"],
                "files": [entry]}

    def _region(self, profiles: dict) -> object:
        config = {"cores": sorted(profiles), "systems": {"sega-stv": {"files": []}}}
        truth = generate_platform_truth("p", config, {}, profiles)
        (entry,) = truth["systems"]["sega-stv"]["files"]
        self.assertNotIn("_region_void", entry)
        return entry.get("region")

    def test_tags_of_every_reader_are_kept(self):
        region = self._region({"a": self._profile("a", ["north-america"]),
                               "b": self._profile("b", ["south-korea", "north-america"])})
        self.assertEqual(region, ["north-america", "south-korea"])

    def test_an_untagged_reader_leaves_no_region(self):
        for order in (("a", "b"), ("b", "a")):
            profiles = {"a": self._profile("a", ["japan"]), "b": self._profile("b", None)}
            self.assertIsNone(self._region({k: profiles[k] for k in order}))


if __name__ == "__main__":
    unittest.main()
