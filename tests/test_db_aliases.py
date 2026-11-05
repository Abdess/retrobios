"""A profile's aliases attach to the file its name designates, or to none.

generate_db matched an alias-carrying entry by name through a dict that
kept the last file of that name. quasi88's disk.rom aliases (N88SUB.ROM,
n88sub.rom) went to a Tandy CoCo disk.rom, and a name lookup for the PC-88
disk ROM then served the CoCo one.
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import generate_db  # noqa: E402


class _NoCoreInfo:
    def fetch_requirements(self):
        return []


class AliasesNeedAnUnambiguousName(unittest.TestCase):
    def _aliases(self, files: dict) -> dict:
        stub = types.ModuleType("scraper.coreinfo_scraper")
        stub.Scraper = _NoCoreInfo
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/x.yml").write_text(
                    'files:\n  - name: "disk.rom"\n    aliases: ["n88sub.rom"]\n'
                )
                with mock.patch.dict(sys.modules, {"scraper.coreinfo_scraper": stub}):
                    return generate_db._collect_all_aliases(files)
            finally:
                os.chdir(previous)

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

    def test_a_unique_name_still_carries_its_aliases(self):
        files = {"a": self._file("disk.rom", "bios/NEC/PC-88/disk.rom", "m1")}
        aliases = self._aliases(files)
        self.assertEqual([a["name"] for a in aliases.get("a", [])], ["n88sub.rom"])


class NoNetworkInTheBuild(unittest.TestCase):
    def test_generate_db_reads_no_remote_source(self):
        """core-info was fetched on every run, offline ones included."""
        source = (REPO_ROOT / "scripts" / "generate_db.py").read_text(encoding="utf-8")
        self.assertNotIn("coreinfo_scraper", source)
        self.assertNotIn("urllib.request", source)

    def test_hash_proven_entry_registers_its_own_name(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/g.yml").write_text(
                    'files:\n  - name: "writer.rom"\n    sha1: "s1"\n'
                )
                aliases = generate_db._collect_all_aliases(
                    {"s1": {"name": "WRITER.ROM", "path": "bios/WRITER.ROM", "md5": "m"}}
                )
            finally:
                os.chdir(previous)
        self.assertEqual([a["name"] for a in aliases.get("s1", [])], ["writer.rom"])

class AcceptedRevisionLists(unittest.TestCase):
    def test_a_list_of_sha1_names_every_held_revision(self):
        """A profile accepting several revisions writes sha1 as a list."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/m.yml").write_text(
                    'files:\n  - name: "MT32_CONTROL.ROM"\n'
                    '    sha1: ["s1", "s2", "absent"]\n'
                )
                aliases = generate_db._collect_all_aliases({
                    "s1": {"name": "ctrl_1_04.rom", "path": "a", "md5": "m1"},
                    "s2": {"name": "ctrl_1_05.rom", "path": "b", "md5": "m2"},
                })
            finally:
                os.chdir(previous)
        for sha in ("s1", "s2"):
            self.assertEqual([a["name"] for a in aliases.get(sha, [])], ["MT32_CONTROL.ROM"])

class CrossNamingStaysInItsProfile(unittest.TestCase):
    def test_an_alias_naming_a_sibling_entry_is_not_indexed(self):
        """dosbox-x aliases MT32_CONTROL.ROM and CM32L_CONTROL.ROM to each other."""
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/d.yml").write_text(
                    'files:\n'
                    '  - name: "MT32_CONTROL.ROM"\n    sha1: "mt"\n    aliases: ["CM32L_CONTROL.ROM"]\n'
                    '  - name: "CM32L_CONTROL.ROM"\n    sha1: "cm"\n    aliases: ["MT32_CONTROL.ROM"]\n'
                )
                aliases = generate_db._collect_all_aliases({
                    "mt": {"name": "mt32_control.rom", "path": "a", "md5": "m1"},
                    "cm": {"name": "cm32l_control.rom", "path": "b", "md5": "m2"},
                })
            finally:
                os.chdir(previous)
        self.assertEqual([a["name"] for a in aliases["mt"]], ["MT32_CONTROL.ROM"])
        self.assertEqual([a["name"] for a in aliases["cm"]], ["CM32L_CONTROL.ROM"])

class AnUnreadableSourceStopsTheRun(unittest.TestCase):
    """A profile with a YAML error was skipped in silence: the database was
    written without its aliases and the command exited 0."""

    def test_the_file_is_named_and_nothing_collected(self):
        import os
        import shutil
        import tempfile

        import generate_db

        tmp_root = Path(__file__).resolve().parents[1] / "tmp"
        tmp_root.mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=tmp_root))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        Path("emulators").mkdir()
        Path("emulators/broken.yml").write_text("files: [\n  - name: a\n")
        with self.assertRaises(generate_db.UnreadableSource) as caught:
            generate_db._collect_all_aliases({})
        self.assertIn("broken.yml", str(caught.exception))


class DrasticNamesTheDSDumps(unittest.TestCase):
    """DraStic opens nds_bios_arm9.bin, nds_bios_arm7.bin and nds_firmware.bin
    and checks their size only. Its profile listed nine other names none of
    its binaries contains, which were the only way the collection answered
    its own three names."""

    def _aliases(self, files: dict) -> dict:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                return generate_db._collect_all_aliases(files)
            finally:
                os.chdir(previous)

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

    PROFILE = (
        'files:\n  - name: "64DD_IPL_v12_JPN.bin"\n'
        '    aliases: ["64DD_IPL_JP.n64", "64dd_ipl_J.bin"]\n'
    )

    def _aliases(self, primary: str, copy: str) -> dict:
        files = {"s": {"name": primary, "path": f"bios/N64DD/{primary}", "md5": "m"}}
        copies = {"s": [{"name": copy, "path": f"bios/N64DD/{copy}"}]}
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/p.yml").write_text(self.PROFILE)
                return generate_db._collect_all_aliases(files, copies)
            finally:
                os.chdir(previous)

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
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("emulators").mkdir()
                Path("emulators/s.yml").write_text(
                    'files:\n  - name: "BS-X.bin"\n    aliases: ["BS-X.bios"]\n'
                )
                aliases = generate_db._collect_all_aliases(files, copies)
            finally:
                os.chdir(previous)
        self.assertEqual(aliases, {})

    def test_the_build_passes_the_scan_copies(self):
        source = (REPO_ROOT / "scripts" / "generate_db.py").read_text(encoding="utf-8")
        self.assertIn("_collect_all_aliases(files, aliases, shadowed)", source)


class TheSmsBiosKeepsItsNames(unittest.TestCase):
    """RetroArch pins bios_E.sms and bios_U.sms to the v1.3 BIOS. Its only
    path was ZEsarUX's sms.rom, which sorted before bios/Sega/Master System/,
    and the two names were refused because .variants/ copies carried them.
    Genesis Plus GX then got the Store Display Unit BIOS as bios_U.sms."""

    def test_a_name_only_variants_carry_is_registered_for_the_pinned_content(self):
        files = {
            "v13": {"name": "SMS_us_1.3.sms", "path": "bios/Sega/MS/SMS_us_1.3.sms", "md5": "m13"},
            "kiosk": {"name": "bios_U.sms", "path": "bios/Sega/MS/.variants/bios_U.sms.ee2c29ba",
                      "md5": "mk"},
        }
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("platforms").mkdir()
                Path("platforms/_registry.yml").write_text("platforms:\n  p:\n    status: active\n")
                Path("platforms/p.yml").write_text(
                    "systems:\n  sms:\n    files:\n"
                    '      - name: "bios_U.sms"\n        sha1: "v13"\n'
                )
                aliases = generate_db._collect_all_aliases(files)
            finally:
                os.chdir(previous)
        self.assertIn("bios_U.sms", {a["name"] for a in aliases.get("v13", [])})

    def test_a_primary_name_still_refuses_another_content(self):
        files = {
            "v13": {"name": "SMS_us_1.3.sms", "path": "bios/Sega/MS/SMS_us_1.3.sms", "md5": "m13"},
            "other": {"name": "bios_U.sms", "path": "bios/Sega/MS/bios_U.sms", "md5": "mo"},
        }
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                Path("platforms").mkdir()
                Path("platforms/_registry.yml").write_text("platforms:\n  p:\n    status: active\n")
                Path("platforms/p.yml").write_text(
                    "systems:\n  sms:\n    files:\n"
                    '      - name: "bios_U.sms"\n        sha1: "v13"\n'
                )
                aliases = generate_db._collect_all_aliases(files)
            finally:
                os.chdir(previous)
        self.assertEqual(aliases, {})

    def test_a_copy_under_its_machine_is_the_path_over_an_emulator_tree(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            bios = Path(tmp) / "bios"
            for rel in ("Other/zesarux/sms.rom", "Sega/Master System/SMS_us_1.3.sms"):
                (bios / rel).parent.mkdir(parents=True, exist_ok=True)
                (bios / rel).write_bytes(b"v1.3")
            (bios / "Other/zesarux/own.rom").write_bytes(b"only zesarux")
            files, copies, _cache = generate_db.scan_bios_dir(bios, {}, True)
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
