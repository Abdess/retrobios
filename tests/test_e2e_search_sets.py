"""Standalone layouts, search lists and archive sets, end to end."""

from __future__ import annotations

import tests
import contextlib
import hashlib
import io
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
import yaml
from model.profiles import load_emulator_profiles
from packs.verdicts import Severity
from packs.gaps import find_undeclared_files
from packs.emulatorcheck import verify_emulator


try:
    import jsonschema
except ImportError:
    jsonschema = None


HAS_JSONSCHEMA = jsonschema is not None


class StandaloneModeRequiresAStandaloneBuild(unittest.TestCase):
    """A platform names its standalone emulators by its own names, which can
    equal the key of a libretro-only profile (Recalbox and Batocera both
    call their standalone ScummVM ``scummvm``). Laid out standalone, such a
    profile loses every ``path:`` and drops its files at the root."""

    def test_libretro_only_profile_keeps_its_layout(self):
        from resolve.launches import PlatformLaunches

        libretro_only = {"type": "libretro", "cores": ["scummvm"]}
        dual = {"type": "standalone + libretro", "cores": ["dolphin"]}
        standalone = {"type": "standalone", "cores": ["xemu"]}
        named = PlatformLaunches(standalone=frozenset({"scummvm", "dolphin", "xemu", "hatari"}))
        self.assertFalse(named.runs_standalone("scummvm", libretro_only))
        self.assertTrue(named.runs_standalone("dolphin", dual))
        self.assertTrue(named.runs_standalone("xemu", standalone))
        self.assertTrue(named.runs_standalone("other-key", {"type": "standalone", "cores": ["hatari"]}))
        self.assertFalse(PlatformLaunches().runs_standalone("dolphin", dual))
        self.assertFalse(
            PlatformLaunches(standalone=frozenset({"pcsx2"})).runs_standalone("dolphin", dual)
        )


class OneOfASearchList(unittest.TestCase):
    """Entries a core takes the first of are one need (``group:``).

    Yabause tries saturn_bios.bin, sega_101.bin, mpr-17933.bin and loads the
    first it finds. Written as required on the first name only, verify and
    the gap report called saturn_bios.bin a missing required file while
    sega_101.bin was held, and a set held through an optional-looking name
    passed for the wrong reason. Synthetic: set ``first`` holds only its
    second member, set ``none`` holds nothing.
    """

    def setUp(self):
        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {},
                                            "by_crc32": {}, "by_path_suffix": {}}}
        for name in ("second.bin", "third.bin", "plain.bin"):
            data = name.encode() * 8
            rel = f"bios/Test/Console/{name}"
            Path(rel).parent.mkdir(parents=True, exist_ok=True)
            Path(rel).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            self.db["files"][sha1] = {"path": rel, "name": name, "size": len(data),
                                      "md5": hashlib.md5(data).hexdigest(), "crc32": ""}
            self.db["indexes"]["by_name"][name] = [sha1]
        Path("emulators").mkdir()
        Path("platforms").mkdir()

        def member(name: str, group: str, rank: int) -> dict:
            return {"name": name, "system": "console-a", "group": group,
                    "priority": rank}

        raw = {
            "emulator": "Seq", "type": "libretro", "cores": ["seq"],
            "systems": ["console-a"],
            "groups": {"first": {"required": True}, "none": {"required": True}},
            "files": [
                member("first.bin", "first", 1),
                member("second.bin", "first", 2),
                member("third.bin", "first", 3),
                member("none_a.bin", "none", 1),
                member("none_b.bin", "none", 2),
                {"name": "plain.bin", "system": "console-a", "required": True},
            ],
        }
        Path("emulators/seq.yml").write_text(yaml.safe_dump(raw))
        self.raw = raw
        # What every reader sees: the profile as load_emulator_profiles gives it.
        self.profile = load_emulator_profiles("emulators")["seq"]
        self.config = {
            "platform": "Seqs", "verification_mode": "existence",
            "base_destination": "system", "cores": ["seq"],
            "systems": {"console-a": {"files": []}},
        }

    def _verify(self) -> dict:
        return verify_emulator(["seq"], "emulators", self.db, platforms_dir="platforms")

    def test_one_member_held_leaves_no_missing_report_for_its_set(self):
        result = self._verify()
        reported = {d["name"]: d["status"] for d in result["details"]}
        self.assertEqual(reported["second.bin"], "ok")
        self.assertEqual(reported["third.bin"], "ok")
        self.assertNotIn("first.bin", reported)
        self.assertEqual(
            sorted(d["name"] for d in result["set_members"]),
            ["first.bin", "none_b.bin"],
        )

    def test_a_set_none_holds_is_one_gap(self):
        result = self._verify()
        missing = [d for d in result["details"] if d["status"] == "missing"]
        self.assertEqual([d["name"] for d in missing], ["none_a.bin"])
        self.assertEqual(missing[0]["alternatives"], ["none_b.bin"])
        # Required and missing, judged as the core judges: one warning.
        self.assertEqual(result["severity_counts"][Severity.WARNING], 1)
        self.assertEqual(result["severity_counts"][Severity.INFO], 0)
        self.assertEqual(result["status_counts"].get("missing"), 1)
        self.assertEqual(result["total_files"], 4)

    def test_a_required_set_held_through_a_later_member_is_satisfied(self):
        """second.bin used to read required: false beside a required
        first.bin: the set is required and held, so nothing is critical
        for it, and the strict exit names only the set nobody holds."""
        from packs.strictgate import emulator_strict_failure

        result = self._verify()
        critical = [d["name"] for d in result["details"]
                    if d["status"] == "missing" and d["required"]]
        self.assertEqual(critical, ["none_a.bin"])
        self.assertIn("1 required file(s) missing: none_a.bin",
                      emulator_strict_failure(result) or "")

    def test_pack_and_verify_agree(self):
        from packs.emulatorpack import generate_emulator_pack

        result = self._verify()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            zip_path = generate_emulator_pack(
                ["seq"], "emulators", self.db, "bios", "out", offline=True,
                platforms_dir="platforms",
            )
        with zipfile.ZipFile(zip_path) as zf:
            packed = sorted(n for n in zf.namelist() if n != "README.txt")
        self.assertEqual(packed, ["plain.bin", "second.bin", "third.bin"])
        self.assertEqual(result["severity_counts"]["ok"], len(packed))
        lines = out.getvalue().splitlines()
        self.assertEqual(
            [line.split(": ", 1)[1] for line in lines if line.strip().startswith("MISSING:")],
            ["none_a.bin"],
        )
        self.assertIn("3 files packed, 1 missing", out.getvalue())

    def test_core_complement_reports_one_gap_per_set(self):
        undeclared = find_undeclared_files(
            self.config, "emulators", self.db, {"seq": self.profile}
        )
        by_name = {u["name"]: u for u in undeclared}
        self.assertEqual(
            sorted(by_name), ["none_a.bin", "plain.bin", "second.bin", "third.bin"]
        )
        self.assertTrue(by_name["second.bin"]["in_repo"])
        self.assertFalse(by_name["none_a.bin"]["in_repo"])
        self.assertEqual(by_name["none_a.bin"]["alternatives"], ["none_b.bin"])

    def test_a_platform_declaration_speaks_for_the_set(self):
        """The platform declares first.bin and reports it in its own check:
        the core's other names are not gaps on top of it."""
        config = {**self.config, "systems": {"console-a": {"files": [
            {"name": "first.bin", "destination": "first.bin", "required": True},
            {"name": "none_b.bin", "destination": "none_b.bin", "required": True},
        ]}}}
        undeclared = find_undeclared_files(
            config, "emulators", self.db, {"seq": self.profile}
        )
        self.assertEqual(
            sorted(u["name"] for u in undeclared), ["plain.bin", "second.bin", "third.bin"]
        )

    def test_gap_report_counts_the_set_once(self):
        from packs import crossref

        index = {
            "by_name": self.db["indexes"]["by_name"],
            "by_name_lower": {k.lower(): k for k in self.db["indexes"]["by_name"]},
            "by_path_suffix": {}, "by_md5": {}, "by_sha256": {}, "by_crc32": {},
            "data_names": set(), "all_declared": set(), "db_files": self.db["files"],
        }
        report: dict = {}
        crossref._cross_reference_profile("seq", self.profile, {}, report, index)
        gaps = {g["name"]: g for g in report["seq"]["gap_details"]}
        self.assertEqual(sorted(gaps), ["none_a.bin", "plain.bin", "second.bin", "third.bin"])
        self.assertEqual(gaps["none_a.bin"]["alternatives"], ["none_b.bin"])
        self.assertEqual(report["seq"]["set_aside"]["other_versions"], 2)

    def test_truth_names_no_member_required_on_its_own(self):
        from resolve.truth import _fold_into, _new_truth_entry

        entry = _new_truth_entry(dict(self.profile["files"][0]), "seq", None)
        self.assertNotIn("required", entry)
        self.assertEqual(entry["_required_by"], set())
        self.assertTrue(entry["one_of_required"])
        _fold_into(entry, {"name": "first.bin", "required": True}, "other")
        self.assertTrue(entry["required"])
        self.assertEqual(entry["_required_by"], {"other"})

    def test_ranks_order_one_set_and_never_two(self):
        """px68k-sdl ranks its IPL list and its font list each from 1:
        --one-per-slot keeps the first of each, not one file of the two."""
        from resolve.slot import build_slot_index, resolve_slot_drops

        profile = {"type": "standalone", "files": [
            {"name": "ipl_a.dat", "group": "ipl", "priority": 1},
            {"name": "ipl_b.dat", "group": "ipl", "priority": 2},
            {"name": "font_a.dat", "group": "font", "priority": 1},
            {"name": "font_b.dat", "group": "font", "priority": 2},
        ]}
        index = build_slot_index({"x68": profile})
        groups = {"sharp-x68000": [(n, n) for n in
                                   ("ipl_a.dat", "ipl_b.dat", "font_a.dat", "font_b.dat")]}
        drops, undecidable = resolve_slot_drops(groups, index)
        self.assertEqual(drops, {"ipl_b.dat", "font_b.dat"})
        self.assertEqual(undecidable, [])

    def test_an_archive_needs_one_member_of_a_set(self):
        import zlib

        from resolve.archives import holds_required_members

        path = self.root / "set.zip"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("boot_b.ic94", b"B")
            zf.writestr("eeprom.ic1", b"E")
        crc = {n: f"{zlib.crc32(d):08x}" for n, d in (("a", b"A"), ("b", b"B"), ("e", b"E"))}
        members = [
            {"crc32": crc["a"], "required": True, "group": "boot"},
            {"crc32": crc["b"], "required": True, "group": "boot"},
            {"crc32": crc["e"], "required": True},
        ]
        self.assertTrue(holds_required_members(str(path), members))
        self.assertFalse(holds_required_members(str(path), members[:1] + members[2:]))

    @unittest.skipUnless(HAS_JSONSCHEMA, "validate_schemas needs jsonschema")
    def test_schema_refuses_a_set_split_on_required(self):
        from schemas.profilechecks import group_requirement_split
        from core.paths import REPO_ROOT

        path = REPO_ROOT / "emulators" / "seq.yml"
        own_value = {"groups": {"g": {"required": True}},
                     "files": [{"name": "a", "group": "g", "required": False},
                               {"name": "b", "group": "g"}]}
        self.assertEqual(len(group_requirement_split(path, own_value)), 1)
        undeclared_set = {"files": [{"name": "a", "group": "g"}]}
        self.assertEqual(len(group_requirement_split(path, undeclared_set)), 1)
        unused = {"groups": {"g": {"required": True}}, "files": [{"name": "a"}]}
        self.assertEqual(len(group_requirement_split(path, unused)), 1)
        self.assertEqual(group_requirement_split(path, self.raw), [])

    def test_a_shared_fallback_takes_its_requirement_from_its_sets(self):
        """pom2 falls back on apple2e.rom for the //e it boots by default
        and for the unenhanced //e it may be switched to. One value on the
        file cannot say both: the sets carry it."""
        from model.alternatives import derive_member_requirements

        profile = {"groups": {"iie": {"required": True}, "iie-u": {"required": False}},
                   "files": [{"name": "apple2e_unenh.rom", "group": "iie-u"},
                             {"name": "apple2e.rom", "group": ["iie", "iie-u"]}]}
        derive_member_requirements(profile)
        self.assertEqual([f["required"] for f in profile["files"]], [False, True])

    def test_required_only_keeps_one_held_member_per_required_set(self):
        """second.bin and third.bin are both held: a --required-only pack
        carries second.bin, the first the code reads among those held, and
        verify reports the same single file."""
        from packs.emulatorpack import generate_emulator_pack

        result = verify_emulator(["seq"], "emulators", self.db,
                                 platforms_dir="platforms", required_only=True)
        held = sorted(d["name"] for d in result["details"] if d["status"] == "ok")
        self.assertEqual(held, ["plain.bin", "second.bin"])
        with contextlib.redirect_stdout(io.StringIO()):
            zip_path = generate_emulator_pack(
                ["seq"], "emulators", self.db, "bios", "out", offline=True,
                platforms_dir="platforms", required_only=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            packed = sorted(n for n in zf.namelist() if n != "README.txt")
        self.assertEqual(packed, held)

    def test_required_only_core_files_keep_one_member(self):
        from model.alternatives import core_file_spares

        undeclared = find_undeclared_files(
            self.config, "emulators", self.db, {"seq": self.profile}
        )
        spares = core_file_spares(undeclared)
        kept = sorted(u["name"] for u in undeclared if id(u) not in spares)
        self.assertEqual(kept, ["none_a.bin", "plain.bin", "second.bin"])


class AnArchiveIsAMemberOfASet(unittest.TestCase):
    """Kronos reads kronos/stvbios.zip, else stvbios.zip at the root: one
    archive under two paths, a first-found pair. The archive unit and the
    root copy settle as members of one set, and a --required-only pack
    carries the first, while the members inside still settle the archive
    by its contents."""

    def _fixture(self, held: bool) -> dict:
        import zlib

        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        self.db: dict = {"files": {}, "indexes": {"by_md5": {}, "by_name": {},
                                            "by_crc32": {}, "by_path_suffix": {}}}
        rom = b"STV" * 64
        if held:
            rel = "bios/Sega/STV/set.zip"
            Path(rel).parent.mkdir(parents=True)
            with zipfile.ZipFile(rel, "w") as zf:
                zf.writestr("epr.ic8", rom)
            data = Path(rel).read_bytes()
            sha1 = hashlib.sha1(data).hexdigest()
            self.db["files"][sha1] = {"path": rel, "name": "set.zip", "size": len(data),
                                      "md5": hashlib.md5(data).hexdigest(), "crc32": ""}
            self.db["indexes"]["by_name"]["set.zip"] = [sha1]
        Path("emulators").mkdir()
        Path("platforms").mkdir()
        Path("emulators/stv.yml").write_text(yaml.safe_dump({
            "emulator": "Stv", "type": "libretro", "cores": ["stv"],
            "systems": ["sega-stv"], "archive_prefix": "stv",
            "groups": {"stv-bios": {"required": True}},
            "files": [
                {"name": "set.zip", "system": "sega-stv", "group": "stv-bios"},
                {"name": "epr.ic8", "archive": "set.zip", "system": "sega-stv",
                 "required": True, "crc32": f"{zlib.crc32(rom):08x}"},
            ],
        }))
        return load_emulator_profiles("emulators")["stv"]

    def test_the_archive_and_its_root_copy_are_one_need(self):
        self._fixture(held=False)
        result = verify_emulator(["stv"], "emulators", self.db, platforms_dir="platforms")
        missing = [d for d in result["details"] if d["status"] == "missing"]
        self.assertEqual([d["destination"] for d in missing], ["stv/set.zip"])
        self.assertEqual(missing[0]["alternatives"], ["set.zip"])
        self.assertEqual(result["status_counts"].get("missing"), 1)

    def test_required_only_carries_the_archive_the_code_reads_first(self):
        from packs.emulatorpack import generate_emulator_pack

        self._fixture(held=True)
        full = verify_emulator(["stv"], "emulators", self.db, platforms_dir="platforms")
        self.assertEqual(
            sorted(d["destination"] for d in full["details"] if d["status"] == "ok"),
            ["set.zip", "stv/set.zip"],
        )
        result = verify_emulator(["stv"], "emulators", self.db,
                                 platforms_dir="platforms", required_only=True)
        held = sorted(d["destination"] for d in result["details"] if d["status"] == "ok")
        self.assertEqual(held, ["stv/set.zip"])
        with contextlib.redirect_stdout(io.StringIO()):
            zip_path = generate_emulator_pack(
                ["stv"], "emulators", self.db, "bios", "out", offline=True,
                platforms_dir="platforms", required_only=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            packed = sorted(n for n in zf.namelist() if n != "README.txt")
        self.assertEqual(packed, held)

    def test_core_files_report_the_pair_once(self):
        profile = self._fixture(held=False)
        config = {"platform": "Stvs", "verification_mode": "existence",
                  "base_destination": "system", "cores": ["stv"],
                  "systems": {"sega-stv": {"files": []}}}
        undeclared = find_undeclared_files(config, "emulators", self.db, {"stv": profile})
        self.assertEqual([u["name"] for u in undeclared], ["set.zip"])
        self.assertTrue(undeclared[0].get("archive"))


if __name__ == "__main__":
    unittest.main()
