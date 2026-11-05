"""The pack and the install manifest place the same bytes at a destination.

The builder replaced a file an emulator rejects by a held variant both
accept, but the manifest kept the first resolution. install.py then placed the
PS2 ROM2.BIN at galaksija/ROM2.BIN where the pack carried the Galaksija ROM,
across 14 destinations on six platforms.
"""

from __future__ import annotations

import ast
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validation import (  # noqa: E402
    _build_validation_index,
    destination_owners,
    validated_choice,
)


class ValidatedChoice(unittest.TestCase):
    def test_a_rejected_file_gives_way_to_an_accepted_variant(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wrong = Path(tmp) / "ps2" / "ROM2.BIN"
            right = Path(tmp) / "galaksija" / "ROM2.BIN"
            wrong.parent.mkdir()
            right.parent.mkdir()
            wrong.write_bytes(b"p" * 64)
            right.write_bytes(b"g" * 4096)
            db = {
                "files": {
                    hashlib.sha1(p.read_bytes()).hexdigest(): {
                        "path": str(p),
                        "name": "ROM2.BIN",
                        "size": p.stat().st_size,
                        "md5": hashlib.md5(p.read_bytes()).hexdigest(),
                    }
                    for p in (wrong, right)
                },
                "indexes": {"by_name": {}, "by_md5": {}},
            }
            db["indexes"]["by_name"]["ROM2.BIN"] = list(db["files"])
            index = _build_validation_index({
                "galaksija": {
                    "emulator": "galaksija",
                    "files": [{"name": "ROM2.BIN", "size": 4096, "validation": ["size"]}],
                }
            })
            chosen, disagreement = validated_choice(
                {"name": "ROM2.BIN"}, str(wrong), db, index, tmp, None
            )
            self.assertEqual(chosen, str(right))
            self.assertIsNone(disagreement)

    def test_a_destination_another_emulator_owns_is_not_judged(self):
        """ZEsarUX's 48 KB cpc6128.rom check gave ep128emu the composite image."""
        profiles = {
            "zesarux": {"files": [
                {"name": "cpc6128.rom", "size": 49152, "validation": ["size"]},
            ]},
            "ep128emu": {"files": [
                {"name": "cpc6128.rom", "path": "ep128emu/roms/cpc6128.rom"},
            ]},
        }
        index = _build_validation_index(profiles)
        owners = destination_owners(profiles)
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            rom = Path(tmp) / "cpc6128.rom"
            rom.write_bytes(b"c" * 32768)
            db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}}}
            for destination, judged in (
                ("ep128emu/roms/cpc6128.rom", False),
                ("cpc6128.rom", True),
            ):
                with self.subTest(destination=destination):
                    _chosen, disagreement = validated_choice(
                        {"name": "cpc6128.rom"}, str(rom), db, index, tmp, None,
                        destination, owners,
                    )
                    self.assertEqual(disagreement is not None, judged)

    def test_pack_and_manifest_both_read_it(self):
        tree = ast.parse((REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8"))
        callers = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(call, ast.Call) and getattr(call.func, "id", None) == "validated_choice"
                for call in ast.walk(node)
            )
        }
        self.assertLessEqual({"generate_pack", "generate_manifest"}, callers)
        # The manifest's core extras go through the builder's own lookup,
        # which reads validated_choice (packextras.ExtraResolver).
        resolvers = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and any(
                isinstance(call, ast.Call) and getattr(call.func, "id", None) == "ExtraResolver"
                for call in ast.walk(node)
            )
        }
        self.assertLessEqual({"generate_pack", "_manifest_core_entries"}, resolvers)
        extras = ast.parse((REPO_ROOT / "scripts" / "packextras.py").read_text(encoding="utf-8"))
        resolve = next(
            node for node in ast.walk(extras)
            if isinstance(node, ast.FunctionDef) and node.name == "resolve"
        )
        self.assertTrue(any(
            isinstance(call, ast.Call) and getattr(call.func, "id", None) == "validated_choice"
            for call in ast.walk(resolve)
        ))

    def test_core_extras_are_judged_too(self):
        """The baseline loop judged a platform's own files while the core-extras loop
        shipped whatever the name found. Both loops live in generate_pack."""
        tree = ast.parse((REPO_ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8"))
        builder = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "generate_pack"
        )
        calls = [
            call for call in ast.walk(builder)
            if isinstance(call, ast.Call) and getattr(call.func, "id", None) == "validated_choice"
        ]
        self.assertGreaterEqual(len(calls), 1)
        # The core extras go through the lookup verify shares, which judges.
        self.assertTrue(any(
            isinstance(call, ast.Call) and getattr(call.func, "attr", None) == "resolve"
            and getattr(call.func.value, "id", None) == "extra_resolver"
            for call in ast.walk(builder)
        ))
        extras = ast.parse((REPO_ROOT / "scripts" / "packextras.py").read_text(encoding="utf-8"))
        resolve = next(
            node for node in ast.walk(extras)
            if isinstance(node, ast.FunctionDef) and node.name == "resolve"
        )
        self.assertTrue(any(
            isinstance(call, ast.Call) and getattr(call.func, "id", None) == "validated_choice"
            for call in ast.walk(resolve)
        ))


class ManifestsServeWhatTheCoreAccepts(unittest.TestCase):
    """RetroArch's GC/dsp_rom.bin was Dolphin's obsolete v0.3.1 free ROM while
    Nintendo's dump, which Dolphin's check accepts, sat in .variants/."""

    def test_no_served_core_file_fails_its_check_beside_a_passing_variant(self):
        import json  # noqa: PLC0415

        from common import load_emulator_profiles, load_platform_config  # noqa: PLC0415
        from generate_pack import _platform_cores  # noqa: PLC0415
        from validation import check_file_validation  # noqa: PLC0415

        manifest_path = REPO_ROOT / "install" / "retroarch.json"
        if not (REPO_ROOT / "database.json").is_file() or not manifest_path.is_file():
            self.skipTest("database.json or the manifest is not built")
        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        config = load_platform_config("retroarch", str(REPO_ROOT / "platforms"))
        cores = {n: profiles[n] for n in _platform_cores(config, profiles)}
        index = _build_validation_index(cores)
        owners = destination_owners(cores)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        wrong = []
        for entry in manifest["files"]:
            name = entry["dest"].rsplit("/", 1)[-1]
            path = entry.get("repo_path")
            if not entry.get("cores") or not path or name not in index:
                continue
            local = str(REPO_ROOT / path)
            if not Path(local).is_file() or not check_file_validation(local, name, index):
                continue
            chosen, _ = validated_choice(
                {"name": name}, local, db, index, str(REPO_ROOT / "bios"), None,
                entry["dest"], owners,
            )
            if chosen != local:
                wrong.append(entry["dest"])
        self.assertEqual(wrong, [])



class EachReaderJudgesWithItsOwnRules(unittest.TestCase):
    """Merged by name, Azahar's 256-byte 3DS otp.bin rule judged Cemu's 1 KiB
    Wii U otp.bin, and the variant search gave Cemu the 3DS file."""

    def test_rules_of_another_emulator_do_not_judge(self):
        from validation import check_file_validation  # noqa: PLC0415

        index = _build_validation_index({
            "azahar": {"files": [{"name": "otp.bin", "path": "sysdata/otp.bin",
                                  "size": 256, "validation": ["size"]}]},
            "cemu": {"files": [{"name": "otp.bin", "path": "Cemu/otp.bin",
                                "size": 1024, "validation": ["size"]}]},
        })
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            wiiu = Path(tmp) / "otp.bin"
            wiiu.write_bytes(b"w" * 1024)
            self.assertIsNone(check_file_validation(str(wiiu), "otp.bin", index, tmp, {"cemu"}))
            self.assertIsNotNone(check_file_validation(str(wiiu), "otp.bin", index, tmp, {"azahar"}))

    def test_one_of_an_emulators_entries_is_enough(self):
        from validation import check_file_validation  # noqa: PLC0415

        index = _build_validation_index({"raze": {"files": [
            {"name": "SW.GRP", "size": 100, "validation": ["size"]},
            {"name": "SW.GRP", "size": 200, "validation": ["size"]},
        ]}})
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            grp = Path(tmp) / "SW.GRP"
            grp.write_bytes(b"s" * 200)
            self.assertIsNone(check_file_validation(str(grp), "SW.GRP", index, tmp, {"raze"}))


class DolphinForksJudgeTheirOwnDspTable(unittest.TestCase):
    """VerifyRoms (Source/Core/Core/DSP/DSPCore.cpp) accepts, without a prompt,
    Nintendo's pair and the newest free pair its table knows: v0.4 in
    Dolphin, PrimeHack, MMJR2 and Triforce, v0.3.1 in MMJR and Ishiiruka,
    whose table stops there. Adler-32 over the byte-swapped words."""

    FREE_V04 = REPO_ROOT / "data" / "dolphin-sys" / "GC" / "dsp_rom.bin"
    FREE_V031 = REPO_ROOT / "bios" / "Nintendo" / "GameCube" / "Sys" / "GC" / "dsp_rom.bin"

    def test_each_fork_accepts_its_own_free_rom(self):
        from common import load_emulator_profiles  # noqa: PLC0415
        from validation import check_file_validation  # noqa: PLC0415

        if not self.FREE_V04.is_file() or not self.FREE_V031.is_file():
            self.skipTest("free DSP ROMs not present")
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        expect = {"dolphin": "v04", "primehack": "v04", "dolphin-mmjr2": "v04",
                  "triforce": "v04", "dolphin-mmjr": "v031", "ishiiruka": "v031"}
        for name, accepted in expect.items():
            index = _build_validation_index({name: profiles[name]})
            with self.subTest(emulator=name):
                for label, path in (("v04", self.FREE_V04), ("v031", self.FREE_V031)):
                    verdict = check_file_validation(
                        str(path), "dsp_rom.bin", index, "bios", {name}
                    )
                    self.assertEqual(verdict is None, label == accepted, label)


class AWarningRejectsNothing(unittest.TestCase):
    """BeebEm warns about a short ROM and runs it. Azahar warns about a bad
    signature and runs the file. A warn-level check never refuses a file, yet
    a held file that passes it is preferred."""

    def _setup(self, tmp, held_good: bool):
        short = Path(tmp) / "a" / "OS12.rom"
        good = Path(tmp) / "b" / "OS12.rom"
        short.parent.mkdir()
        good.parent.mkdir()
        short.write_bytes(b"s" * 8192)
        good.write_bytes(b"g" * 16384)
        files = [short] + ([good] if held_good else [])
        db = {"files": {}, "indexes": {"by_name": {"OS12.rom": []}, "by_md5": {}}}
        for f in files:
            sha1 = hashlib.sha1(f.read_bytes()).hexdigest()
            db["files"][sha1] = {"path": str(f), "name": "OS12.rom", "size": f.stat().st_size}
            db["indexes"]["by_name"]["OS12.rom"].append(sha1)
        index = _build_validation_index({"beebem": {"files": [
            {"name": "OS12.rom", "size": 16384, "validation": ["size"], "on_mismatch": "warn"},
        ]}})
        return short, good, db, index

    def test_the_core_runs_a_file_that_only_warns(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            short, _good, db, index = self._setup(tmp, held_good=False)
            chosen, disagreement = validated_choice(
                {"name": "OS12.rom"}, str(short), db, index, tmp, None, emulators={"beebem"}
            )
            self.assertEqual((chosen, disagreement), (str(short), None))

    def test_a_file_passing_the_warned_check_is_preferred(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            short, good, db, index = self._setup(tmp, held_good=True)
            chosen, disagreement = validated_choice(
                {"name": "OS12.rom"}, str(short), db, index, tmp, None, emulators={"beebem"}
            )
            self.assertEqual((chosen, disagreement), (str(good), None))

    def test_the_merged_view_rejects_nothing_for_it(self):
        from validation import check_file_validation  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            short, _good, _db, index = self._setup(tmp, held_good=False)
            self.assertIsNone(check_file_validation(str(short), "OS12.rom", index, tmp))


class AlternativesAreLookedUpBySlot(unittest.TestCase):
    """Each extra scanned its whole profile for the versions of its slot:
    33 million entries visited in one verify --all."""

    def test_same_answer_one_pass_per_profile(self):
        from unittest import mock

        import packextras
        import validation

        files = [{"name": "DUKE3D.GRP", "size": n} for n in (1, 2)] + [
            {"name": "a.bin", "path": "dir/a.bin"}, {"name": "a.bin"}, "not an entry",
        ]
        profiles = {"raze": {"files": files}}
        resolver = packextras.ExtraResolver({}, "bios", None, None, {}, None, profiles=profiles)
        extras = [
            {"source_profile": "raze", "name": "DUKE3D.GRP"},
            {"source_profile": "raze", "name": "a.bin", "source_path": "dir/a.bin"},
            {"source_profile": "raze", "source_name": "a.bin", "name": "renamed"},
            {"source_profile": "other", "name": "a.bin"},
        ]
        with mock.patch.object(validation, "slot_index", side_effect=validation.slot_index) as built:
            for fe in extras:
                self.assertEqual(resolver.alternatives(fe),
                                 validation.extra_alternatives(fe, profiles))
        self.assertEqual(built.call_count, 2)


if __name__ == "__main__":
    unittest.main()
