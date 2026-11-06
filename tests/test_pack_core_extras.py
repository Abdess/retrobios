"""The pack integrity check counts the core files the builder places.

It rebuilt the core extras with an empty set of taken paths and tested
presence alone. On a Recalbox pack it credited 68 core files at a path the
platform's own file holds, 15 of them other bytes (fuse/trdos.rom, the PS1
BIOS DuckStation reads), and printed a core count that contradicted the
builder's in the same run.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import packverify  # noqa: E402


def _held(files: dict, by_name: dict, path: str, payload: bytes) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(payload)
    sha1 = hashlib.sha1(payload).hexdigest()
    name = Path(path).name
    files[sha1] = {"path": path, "name": name, "sha1": sha1,
                   "md5": hashlib.md5(payload).hexdigest(), "size": len(payload)}
    by_name.setdefault(name, []).append(sha1)
    return sha1


class CoreFilesAsTheBuilderPlacesThem(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        files: dict = {}
        by_name: dict = {}
        _held(files, by_name, "bios/plat/trdos.rom", b"platform dump")
        core_trdos = _held(files, by_name, "bios/core/trdos.rom", b"core dump")
        _held(files, by_name, "bios/core/other.rom", b"core file")
        self.db = {"files": files, "indexes": {
            "by_name": by_name, "by_md5": {e["md5"]: s for s, e in files.items()},
            "by_path_suffix": {}, "by_crc32": {}, "by_sha256": {}}}
        Path("platforms").mkdir()
        config = {"platform": "P", "verification_mode": "existence", "cores": ["fuse"],
                  "systems": {"zx": {"files": [
                      {"name": "trdos.rom", "destination": "fuse/trdos.rom"}]}}}
        Path("platforms/p.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        Path("emulators").mkdir()
        self.profiles = {"fuse": {
            "emulator": "fuse", "type": "libretro", "systems": ["zx"], "files": [
                {"name": "trdos.rom", "path": "fuse/trdos.rom", "sha1": core_trdos},
                {"name": "other.rom", "path": "core/other.rom"},
            ]}}

    def _check(self, other: bytes) -> tuple:
        with zipfile.ZipFile("pack.zip", "w") as zf:
            zf.writestr("fuse/trdos.rom", b"platform dump")
            zf.writestr("core/other.rom", other)
        return packverify.verify_pack_against_platform(
            "pack.zip", "p", "platforms", self.db, emulators_dir="emulators",
            emu_profiles=self.profiles,
        )

    def test_a_path_the_platform_file_holds_is_not_a_core_file(self):
        ok, _checked, _present, errors, _bc, _bp, core_checked, core_present, _ex, _absent = (
            self._check(b"core file")
        )
        self.assertTrue(ok, errors)
        self.assertEqual((core_checked, core_present), (1, 1))

    def test_other_bytes_at_a_core_path_are_an_error(self):
        ok, _checked, _present, errors, *_rest = self._check(b"something else")
        self.assertFalse(ok)
        self.assertTrue(
            any(e.startswith("core file differs: core/other.rom") for e in errors), errors
        )


class ARefusedPinLeavesItsPathToTheCore(unittest.TestCase):
    """EmuELEC pins naomi.zip by an md5 the collection does not hold: the
    builder refuses the held copy and ships the core's file at that path.
    The check marked the path taken by the refused platform file, so the
    core file the pack carries there was never compared."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        files: dict = {}
        by_name: dict = {}
        _held(files, by_name, "bios/dc/naomi.zip", b"the core's naomi")
        self.db = {"files": files, "indexes": {
            "by_name": by_name, "by_md5": {e["md5"]: s for s, e in files.items()},
            "by_path_suffix": {}, "by_crc32": {}, "by_sha256": {}}}
        Path("platforms").mkdir()
        config = {"platform": "P", "verification_mode": "md5", "cores": ["flycast"],
                  "systems": {"dc": {"files": [{
                      "name": "naomi.zip", "destination": "dc/naomi.zip",
                      "md5": hashlib.md5(b"a bundle nobody holds").hexdigest(),
                  }]}}}
        Path("platforms/p.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        Path("emulators").mkdir()
        self.profiles = {"flycast": {
            "emulator": "flycast", "type": "libretro", "systems": ["dc"], "files": [
                {"name": "naomi.zip", "path": "dc/naomi.zip"}]}}

    def _check(self, member: bytes) -> tuple:
        with zipfile.ZipFile("pack.zip", "w") as zf:
            zf.writestr("dc/naomi.zip", member)
        return packverify.verify_pack_against_platform(
            "pack.zip", "p", "platforms", self.db, emulators_dir="emulators",
            emu_profiles=self.profiles,
        )

    def test_the_core_file_at_the_refused_path_is_compared(self):
        _ok, _c, _p, errors, *_mid, core_checked, _cp, _ex, _ab = self._check(b"other")
        self.assertEqual(core_checked, 1)
        self.assertTrue(
            any(e.startswith("core file differs: dc/naomi.zip") for e in errors), errors
        )

    def test_the_right_core_file_passes(self):
        _ok, _c, _p, errors, *_mid, core_checked, core_present, _ex, _ab = (
            self._check(b"the core's naomi")
        )
        self.assertEqual((core_checked, core_present), (1, 1))
        self.assertFalse([e for e in errors if e.startswith("core")], errors)


class NarrowedPacksAgainstTheirOwnList(unittest.TestCase):
    """--verify-packs after --all-variants said "hashes checked during the
    build" for the five narrowed packs and compared none of them: a narrowed
    pack missing a file its narrowed list requires passed. Each variant is
    now held to the platform list narrowed the way it was built."""

    def setUp(self):
        import common
        import generate_db
        import generate_pack

        self.gp = generate_pack
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(tmp.cleanup)
        previous = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, previous)
        files: dict = {}
        for rel in ("bios/p/req.bin", "bios/p/opt.bin", "bios/c/core.bin", "bios/c/extra.bin"):
            payload = rel.encode()
            Path(rel).parent.mkdir(parents=True, exist_ok=True)
            Path(rel).write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": rel, "name": Path(rel).name, "size": len(payload),
                           "sha1": sha1, "md5": hashlib.md5(payload).hexdigest(),
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "crc32": "00000001"}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        Path("platforms").mkdir()
        config = {"platform": "P", "verification_mode": "existence", "cores": ["c"],
                  "systems": {"s": {"files": [
                      {"name": "req.bin", "destination": "req.bin", "required": True},
                      {"name": "opt.bin", "destination": "opt.bin", "required": False},
                  ]}}}
        Path("platforms/p.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        Path("platforms/_registry.yml").write_text(
            yaml.safe_dump({"platforms": {"p": {"config": "p.yml"}}}), encoding="utf-8"
        )
        Path("emulators").mkdir()
        Path("emulators/c.yml").write_text(yaml.safe_dump({
            "emulator": "c", "type": "libretro", "systems": ["s"], "files": [
                {"name": "core.bin", "path": "core.bin", "required": True},
                {"name": "extra.bin", "path": "extra.bin", "required": False},
            ]}), encoding="utf-8")
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        self.addCleanup(common._emulator_profiles_cache.clear)
        self.profiles = common.load_emulator_profiles("emulators")

    def _build(self, source: str, required: bool) -> tuple[str, set[str]]:
        zip_path = self.gp.generate_pack(
            "p", "platforms", self.db, "bios", "out", emulators_dir="emulators",
            emu_profiles=self.profiles, source=source, required_only=required,
            offline=True,
        )
        with zipfile.ZipFile(zip_path) as zf:
            return zip_path, set(zf.namelist()) - {"README.txt"}

    def _check(self, zip_path: str, source: str, required: bool) -> tuple:
        return packverify.verify_pack_against_platform(
            zip_path, "p", "platforms", self.db, emulators_dir="emulators",
            emu_profiles=self.profiles, source=source, required_only=required,
        )

    def test_every_variant_passes_as_built(self):
        expected = {
            ("full", False): {"req.bin", "opt.bin", "core.bin", "extra.bin"},
            ("full", True): {"req.bin", "core.bin"},
            ("platform", False): {"req.bin", "opt.bin"},
            ("platform", True): {"req.bin"},
            ("truth", False): {"core.bin", "extra.bin"},
            ("truth", True): {"core.bin"},
        }
        for (source, required), members in expected.items():
            with self.subTest(source=source, required=required):
                zip_path, held = self._build(source, required)
                self.assertEqual(held, members)
                ok, _c, _p, errors, *_rest = self._check(zip_path, source, required)
                self.assertTrue(ok, errors)
                self.assertEqual(
                    self.gp._pack_variant(os.path.basename(zip_path)), (source, required)
                )

    def test_a_narrowed_pack_missing_a_required_file_fails(self):
        for source, required, lost in (
            ("full", True, "core.bin"), ("platform", True, "req.bin"),
            ("truth", False, "extra.bin"), ("truth", True, "core.bin"),
        ):
            with self.subTest(source=source, required=required):
                zip_path, held = self._build(source, required)
                with zipfile.ZipFile(zip_path) as zf:
                    kept = {n: zf.read(n) for n in held if n != lost}
                with zipfile.ZipFile(zip_path, "w") as zf:
                    for name, data in kept.items():
                        zf.writestr(name, data)
                ok, _c, _p, errors, *_rest = self._check(zip_path, source, required)
                self.assertFalse(ok)
                self.assertTrue(any(lost in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
