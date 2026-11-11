"""A files[] source_ref must cite the code that reads the file."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

try:
    import validate_schemas
except ImportError as exc:
    validate_schemas = None
    IMPORT_ERROR = str(exc)
else:
    IMPORT_ERROR = ""


def _profile(ref: object) -> dict:
    return {"files": [{"name": "doom.wad", "source_ref": ref}]}


@unittest.skipIf(validate_schemas is None, f"validate_schemas unavailable: {IMPORT_ERROR}")
class DataOnlySourceRefs(unittest.TestCase):
    path = REPO_ROOT / "emulators" / "synthetic.yml"

    def errors(self, ref: object) -> list[str]:
        return validate_schemas._data_only_source_refs(self.path, _profile(ref))

    def test_a_data_table_alone_is_refused(self):
        self.assertEqual(len(self.errors("wadsrc_extra/static/iwadinfo.txt:420, 437")), 1)

    def test_a_build_file_alone_is_refused(self):
        for ref in ("pc-bios/meson.build:30", "wadsrc/CMakeLists.txt:1",
                    "dists/engine-data/engine_data.mk (ENABLE_KYRA)", "src/configure:1933"):
            with self.subTest(ref=ref):
                self.assertEqual(len(self.errors(ref)), 1)

    def test_a_file_in_the_tree_alone_is_refused(self):
        self.assertEqual(len(self.errors("fMSX/ROMs/MSX.ROM")), 1)

    def test_the_table_with_its_reader_passes(self):
        self.assertEqual(self.errors(
            "wadsrc_extra/static/iwadinfo.txt:420, wadsrc_extra/CMakeLists.txt:1, "
            "src/d_iwad.cpp:286-296, 502-531"), [])

    def test_a_role_prefix_is_read_through(self):
        self.assertEqual(self.errors("source pc-bios/meson.build:30, source hw/i386/pc_piix.c:466"), [])

    def test_a_binary_with_an_address_passes(self):
        for ref in ("libemucore.so 0x1a2b3c", "Fusion.exe 0x00401000",
                    "bigpemu FUN_006d8be0 (BootROM read)",
                    "CSpect.exe 3.3.1.0 a.H::e() IL_00bd-IL_00c9",
                    "GameAssembly.dll DSP1..ctor (name and CRC32)",
                    "libpizzaboy-jni.so pizza.c:931-937 (path buffer)"):
            with self.subTest(ref=ref):
                self.assertEqual(self.errors(ref), [])

    def test_a_binary_named_without_a_place_in_it_is_refused(self):
        for ref in ("ArcadeFlashWeb v1.0.2 pepflashplayer.dll string table",
                    "Future Pinball.exe 1.9.1.20101231 import directory",
                    "Main.java:27302, libfpse.so readelf -d",
                    "nethersx2 v2.2n classes.dex icons/star-%d.png",
                    "Fusion.exe 0x00401000, PS3Eye.dll .rdata"):
            with self.subTest(ref=ref):
                self.assertEqual(len(self.errors(ref)), 1)

    def test_a_binary_file_of_a_source_tree_is_a_path(self):
        self.assertEqual(self.errors(
            "src/loader/elfLoader/elfLoader.cpp:365, libs/win32/ll-deps/zlib1.dll"), [])
        self.assertEqual(self.errors(
            "src/emu/kernel/src/libmanager.cpp:549-566, src/patch/ecam/group/ecam.dll.map:190-193"), [])

    def test_each_build_mode_is_judged(self):
        self.assertEqual(len(self.errors({"standalone": "src/main.cpp:10", "libretro": "data/list.txt:3"})), 1)

    def test_an_excepted_profile_is_not_judged(self):
        path = REPO_ROOT / "emulators" / "synthetic.yml"
        exceptions = validate_schemas.DATA_ONLY_REF_EXCEPTIONS
        exceptions["synthetic"] = "binary found nowhere"
        try:
            self.assertEqual(validate_schemas._data_only_source_refs(path, _profile("history.txt:38")), [])
        finally:
            del exceptions["synthetic"]

    def test_every_exception_names_a_profile_and_a_reason(self):
        for name, reason in validate_schemas.DATA_ONLY_REF_EXCEPTIONS.items():
            with self.subTest(profile=name):
                self.assertTrue((REPO_ROOT / "emulators" / f"{name}.yml").is_file())
                self.assertTrue(reason.strip())

    def test_the_profiles_cite_their_readers(self):
        errors: list[str] = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            errors.extend(validate_schemas._data_only_source_refs(
                path, validate_schemas._load_source(path)))
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
