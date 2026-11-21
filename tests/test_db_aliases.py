"""A profile's aliases attach to the file its name designates, or to none.

generate_db matched an alias-carrying entry by name through a dict that
kept the last file of that name. quasi88's disk.rom aliases (N88SUB.ROM,
n88sub.rom) went to a Tandy CoCo disk.rom, and a name lookup for the PC-88
disk ROM then served the CoCo one.
"""

from __future__ import annotations

import tests

import tempfile
import unittest
from pathlib import Path

from collection.aliases import collect_all_aliases
from collection.declared import Declarations, UnreadableSource, read_declarations
from collection.scan import scan_bios_dir
from tests.sources import script_source

REPO_ROOT = Path(__file__).resolve().parents[1]


class AliasesNeedAnUnambiguousName(unittest.TestCase):
    def _aliases(self, files: dict) -> dict:
        profile = [{"name": "disk.rom", "aliases": ["n88sub.rom"]}]
        return collect_all_aliases(files, Declarations(profile_entries=[profile]))

    @staticmethod
    def _file(name: str, path: str, md5: str) -> dict:
        return {"name": name, "path": path, "md5": md5}

    def test_homonyms_take_no_alias(self):
        files = {
            "a": self._file("disk.rom", "bios/NEC/PC-98/disk.rom", "m1"),
            "b": self._file("disk.rom", "bios/Tandy/CoCo/disk.rom", "m2"),
        }
        aliases = self._aliases(files)
        named = {a["name"] for entries in aliases.values() for a in entries}
        self.assertNotIn("n88sub.rom", named)

    def test_homonyms_differing_in_case_take_no_alias(self):
        """dosbox's SC-55 ROM2.BIN: Galaksija's ROM2.BIN was the only exact
        holder, and ROM2_ST.BIN went to it beside SC-55's rom2.bin."""
        files = {
            "a": self._file("DISK.ROM", "bios/NEC/PC-98/DISK.ROM", "m1"),
            "b": self._file("disk.rom", "bios/Tandy/CoCo/disk.rom", "m2"),
        }
        aliases = self._aliases(files)
        named = {a["name"] for entries in aliases.values() for a in entries}
        self.assertNotIn("n88sub.rom", named)

    def test_a_primary_and_its_variant_are_one_file(self):
        files = {
            "a": self._file("disk.rom", "bios/NEC/PC-88/disk.rom", "m1"),
            "b": self._file("DISK.ROM", "bios/NEC/PC-88/.variants/DISK.ROM.0123abcd", "m2"),
        }
        aliases = self._aliases(files)
        self.assertEqual([a["name"] for a in aliases.get("a", [])], ["n88sub.rom"])

    def test_a_unique_name_still_carries_its_aliases(self):
        files = {"a": self._file("disk.rom", "bios/NEC/PC-88/disk.rom", "m1")}
        aliases = self._aliases(files)
        self.assertEqual([a["name"] for a in aliases.get("a", [])], ["n88sub.rom"])


class NoNetworkInTheBuild(unittest.TestCase):
    def test_generate_db_reads_no_remote_source(self):
        """core-info was fetched on every run, offline ones included."""
        source = script_source("generate_db.py")
        self.assertNotIn("coreinfo_scraper", source)
        self.assertNotIn("urllib.request", source)

    def test_hash_proven_entry_registers_its_own_name(self):
        aliases = collect_all_aliases(
            {"s1": {"name": "WRITER.ROM", "path": "bios/WRITER.ROM", "md5": "m"}},
            Declarations(profile_entries=[[{"name": "writer.rom", "sha1": "s1"}]]),
        )
        self.assertEqual([a["name"] for a in aliases.get("s1", [])], ["writer.rom"])

class AcceptedRevisionLists(unittest.TestCase):
    def test_a_list_of_sha1_names_every_held_revision(self):
        """A profile accepting several revisions writes sha1 as a list."""
        profile = [{"name": "MT32_CONTROL.ROM", "sha1": ["s1", "s2", "absent"]}]
        aliases = collect_all_aliases({
            "s1": {"name": "ctrl_1_04.rom", "path": "a", "md5": "m1"},
            "s2": {"name": "ctrl_1_05.rom", "path": "b", "md5": "m2"},
        }, Declarations(profile_entries=[profile]))
        for sha in ("s1", "s2"):
            self.assertEqual([a["name"] for a in aliases.get(sha, [])], ["MT32_CONTROL.ROM"])

class CrossNamingStaysInItsProfile(unittest.TestCase):
    def test_an_alias_naming_a_sibling_entry_is_not_indexed(self):
        """dosbox-x aliases MT32_CONTROL.ROM and CM32L_CONTROL.ROM to each other."""
        profile = [
            {"name": "MT32_CONTROL.ROM", "sha1": "mt", "aliases": ["CM32L_CONTROL.ROM"]},
            {"name": "CM32L_CONTROL.ROM", "sha1": "cm", "aliases": ["MT32_CONTROL.ROM"]},
        ]
        aliases = collect_all_aliases({
            "mt": {"name": "mt32_control.rom", "path": "a", "md5": "m1"},
            "cm": {"name": "cm32l_control.rom", "path": "b", "md5": "m2"},
        }, Declarations(profile_entries=[profile]))
        self.assertEqual([a["name"] for a in aliases["mt"]], ["MT32_CONTROL.ROM"])
        self.assertEqual([a["name"] for a in aliases["cm"]], ["CM32L_CONTROL.ROM"])

class AnUnreadableSourceStopsTheRun(unittest.TestCase):
    """A profile with a YAML error was skipped in silence: the database was
    written without its aliases and the command exited 0."""

    def test_the_file_is_named_and_nothing_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            emulators = Path(tmp) / "emulators"
            emulators.mkdir()
            (emulators / "broken.yml").write_text("files: [\n  - name: a\n")
            (emulators / "good.yml").write_text('files:\n  - name: "b"\n')
            with self.assertRaises(UnreadableSource) as caught:
                read_declarations(Path(tmp) / "platforms", emulators)
        self.assertIn("broken.yml", str(caught.exception))
        self.assertNotIn("good.yml", str(caught.exception))


class TheBuildReadsTheDeclarationsOnce(unittest.TestCase):
    """The alias pass and the proven-name index each walked platforms/ and
    emulators/, the first from paths fixed to the working directory."""

    def test_entries_keep_each_profile_apart(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "platforms").mkdir()
            (root / "platforms/_registry.yml").write_text("platforms:\n  p:\n    config: p.yml\n")
            (root / "platforms/p.yml").write_text(
                'systems:\n  s:\n    files:\n      - name: "a.bin"\n'
            )
            (root / "emulators").mkdir()
            (root / "emulators/x.yml").write_text('files:\n  - name: "b.bin"\n')
            (root / "emulators/y.yml").write_text('files:\n  - name: "c.bin"\n')
            declared = read_declarations(root / "platforms", root / "emulators")
        self.assertEqual([e["name"] for e in declared.platform_entries], ["a.bin"])
        self.assertEqual(
            [[e["name"] for e in entries] for entries in declared.profile_entries],
            [["b.bin"], ["c.bin"]],
        )
        self.assertEqual([e["name"] for e in declared.entries()], ["a.bin", "b.bin", "c.bin"])

    def test_the_build_takes_the_directories_from_its_options(self):
        source = script_source("generate_db.py")
        self.assertIn("read_declarations(Path(args.platforms_dir), Path(args.emulators_dir))", source)
        self.assertNotIn('Path("platforms")', source)
        self.assertNotIn('Path("emulators")', source)


class DrasticNamesTheDSDumps(unittest.TestCase):
    """DraStic opens nds_bios_arm9.bin, nds_bios_arm7.bin and nds_firmware.bin
    and checks their size only. Its profile listed nine other names none of
    its binaries contains, which were the only way the collection answered
    its own three names."""

    def _aliases(self, files: dict) -> dict:
        return collect_all_aliases(files, Declarations())

    def test_the_collection_answers_drastic_names(self):
        files = {
            "a9": {"name": "NDS_Bios9.bin", "path": "bios/Nintendo/DS/NDS_Bios9.bin", "md5": "m9"},
            "a7": {"name": "NDS_Bios7.bin", "path": "bios/Nintendo/DS/NDS_Bios7.bin", "md5": "m7"},
            "fw": {"name": "NDS_Lite_Firmware.bin",
                   "path": "bios/Nintendo/DS/NDS_Lite_Firmware.bin", "md5": "mf"},
        }
        aliases = self._aliases(files)
        named = {sha: {a["name"] for a in entries} for sha, entries in aliases.items()}
        self.assertIn("nds_bios_arm9.bin", named["a9"])
        self.assertIn("nds_bios_arm7.bin", named["a7"])
        self.assertIn("nds_firmware.bin", named["fw"])

    def test_the_profile_carries_no_name_drastic_never_opens(self):
        import yaml

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "drastic.yml").read_text())
        self.assertEqual(
            [e["name"] for e in profile["files"] if e.get("aliases")], [],
        )


class AliasesFollowContentNotPrimaryCopy(unittest.TestCase):
    """Two copies of one IPL dump: 64DD_IPL.bin and 64DD_IPL_v12_JPN.bin.
    The scan keeps the first by path order as primary and lists the other as
    a copy. project64 names the second and declares no hash, so its aliases
    attached only while that copy happened to be primary."""

    PROFILE = [{"name": "64DD_IPL_v12_JPN.bin", "aliases": ["64DD_IPL_JP.n64", "64dd_ipl_J.bin"]}]

    def _aliases(self, primary: str, copy: str) -> dict:
        files = {"s": {"name": primary, "path": f"bios/N64DD/{primary}", "md5": "m"}}
        copies = {"s": [{"name": copy, "path": f"bios/N64DD/{copy}"}]}
        return collect_all_aliases(files, Declarations(profile_entries=[self.PROFILE]), copies)

    def test_either_copy_primary_gives_the_same_names(self):
        names = []
        for primary, copy in (
            ("64DD_IPL.bin", "64DD_IPL_v12_JPN.bin"),
            ("64DD_IPL_v12_JPN.bin", "64DD_IPL.bin"),
        ):
            aliases = self._aliases(primary, copy)
            names.append({a["name"] for a in aliases.get("s", [])})
        self.assertEqual(names[0], names[1])
        self.assertEqual(names[0], {"64DD_IPL_JP.n64", "64dd_ipl_J.bin"})

    def test_a_copy_of_other_content_makes_the_name_ambiguous(self):
        files = {
            "a": {"name": "BS-X.bin", "path": "bios/SNES/BS-X.bin", "md5": "m1"},
            "b": {"name": "Satellaview_BS-X.sfc", "path": "bios/SNES/x.sfc", "md5": "m2"},
        }
        copies = {"b": [{"name": "BS-X.bin", "path": "bios/Satellaview/BS-X.bin"}]}
        profile = [{"name": "BS-X.bin", "aliases": ["BS-X.bios"]}]
        aliases = collect_all_aliases(files, Declarations(profile_entries=[profile]), copies)
        self.assertEqual(aliases, {})

    def test_the_build_passes_the_scan_copies(self):
        source = script_source("generate_db.py")
        self.assertIn("collect_all_aliases(files, declared, aliases, shadowed)", source)


class TheSmsBiosKeepsItsNames(unittest.TestCase):
    """RetroArch pins bios_E.sms and bios_U.sms to the v1.3 BIOS. Its only
    path was ZEsarUX's sms.rom, which sorted before bios/Sega/Master System/,
    and the two names were refused because .variants/ copies carried them.
    Genesis Plus GX then got the Store Display Unit BIOS as bios_U.sms."""

    @staticmethod
    def _platform() -> Declarations:
        with tempfile.TemporaryDirectory() as tmp:
            platforms = Path(tmp)
            (platforms / "_registry.yml").write_text("platforms:\n  p:\n    config: p.yml\n")
            (platforms / "p.yml").write_text(
                "systems:\n  sms:\n    files:\n"
                '      - name: "bios_U.sms"\n        sha1: "v13"\n'
            )
            return read_declarations(platforms, platforms / "emulators")

    def test_a_name_only_variants_carry_is_registered_for_the_pinned_content(self):
        files = {
            "v13": {"name": "SMS_us_1.3.sms", "path": "bios/Sega/MS/SMS_us_1.3.sms", "md5": "m13"},
            "kiosk": {"name": "bios_U.sms", "path": "bios/Sega/MS/.variants/bios_U.sms.ee2c29ba",
                      "md5": "mk"},
        }
        aliases = collect_all_aliases(files, self._platform())
        self.assertIn("bios_U.sms", {a["name"] for a in aliases.get("v13", [])})

    def test_a_primary_name_still_refuses_another_content(self):
        files = {
            "v13": {"name": "SMS_us_1.3.sms", "path": "bios/Sega/MS/SMS_us_1.3.sms", "md5": "m13"},
            "other": {"name": "bios_U.sms", "path": "bios/Sega/MS/bios_U.sms", "md5": "mo"},
        }
        aliases = collect_all_aliases(files, self._platform())
        self.assertEqual(aliases, {})

    def test_a_copy_under_its_machine_is_the_path_over_an_emulator_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            bios = Path(tmp) / "bios"
            for rel in ("Other/zesarux/sms.rom", "Sega/Master System/SMS_us_1.3.sms"):
                (bios / rel).parent.mkdir(parents=True, exist_ok=True)
                (bios / rel).write_bytes(b"v1.3")
            (bios / "Other/zesarux/own.rom").write_bytes(b"only zesarux")
            files, copies, _cache = scan_bios_dir(bios, {}, True)
        paths = {entry["path"] for entry in files.values()}
        self.assertIn("bios/Sega/Master System/SMS_us_1.3.sms", paths)
        self.assertIn("bios/Other/zesarux/own.rom", paths)
        self.assertNotIn("bios/Other/zesarux/sms.rom", paths)
        self.assertIn(
            "bios/Other/zesarux/sms.rom",
            {copy["path"] for entries in copies.values() for copy in entries},
        )


if __name__ == "__main__":
    unittest.main()
