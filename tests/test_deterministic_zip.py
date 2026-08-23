"""Tests for deterministic ZIP rebuilding."""

from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from scripts.deterministic_zip import (
    _FIXED_DATE_TIME,
    rebuild_zip_deterministic,
    verify_zip_determinism,
)

CONTENT = {
    "03.wav": b"\x00\x01\x02" * 500,
    "01.wav": b"sample one",
    "sub/02.wav": b"sample two",
}


def _make_source(path: Path, date_time=(2021, 6, 5, 4, 3, 2), compression=None) -> None:
    """Write a ZIP with deliberately non-deterministic metadata."""
    comp = zipfile.ZIP_STORED if compression is None else compression
    with zipfile.ZipFile(path, "w", comp) as zf:
        for name in ("sub/02.wav", "03.wav", "01.wav"):  # unsorted on purpose
            info = zipfile.ZipInfo(filename=name, date_time=date_time)
            info.compress_type = comp
            info.external_attr = 0o100777 << 16
            info.create_system = 3  # Unix
            zf.writestr(info, CONTENT[name])


class TestRebuild(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.src = self.tmp / "src.zip"
        _make_source(self.src)

    def tearDown(self):
        self._tmp.cleanup()

    def _rebuild(self, out_name="out.zip", src=None):
        out = self.tmp / out_name
        sha1 = rebuild_zip_deterministic(src or self.src, out)
        return out, sha1

    def test_content_is_preserved(self):
        out, _ = self._rebuild()
        with zipfile.ZipFile(out) as zf:
            for name, data in CONTENT.items():
                self.assertEqual(zf.read(name), data)

    def test_entries_sorted_by_name(self):
        out, _ = self._rebuild()
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.namelist(), ["01.wav", "03.wav", "sub/02.wav"])

    def test_metadata_is_normalized(self):
        out, _ = self._rebuild()
        with zipfile.ZipFile(out) as zf:
            for info in zf.infolist():
                self.assertEqual(info.date_time, _FIXED_DATE_TIME)
                self.assertEqual(info.create_system, 0)
                self.assertEqual(info.external_attr, 0o100644 << 16)
                self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)

    def test_same_input_gives_same_hash(self):
        _, first = self._rebuild("a.zip")
        _, second = self._rebuild("b.zip")
        self.assertEqual(first, second)

    def test_source_metadata_does_not_affect_hash(self):
        """Different timestamps and compression, identical rebuild."""
        other = self.tmp / "other.zip"
        _make_source(other, date_time=(1999, 1, 1, 1, 1, 2), compression=zipfile.ZIP_DEFLATED)
        _, from_first = self._rebuild("a.zip")
        _, from_other = self._rebuild("b.zip", src=other)
        self.assertEqual(from_first, from_other)

    def test_returns_sha1_of_output(self):
        import hashlib

        out, sha1 = self._rebuild()
        self.assertEqual(sha1, hashlib.sha1(out.read_bytes()).hexdigest())

    def test_directory_entries_are_dropped(self):
        src = self.tmp / "withdir.zip"
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr(zipfile.ZipInfo("adir/"), b"")
            zf.writestr("adir/file.bin", b"x")
        out, _ = self._rebuild("nodir.zip", src=src)
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.namelist(), ["adir/file.bin"])

    def test_corrupt_entry_raises(self):
        """A tampered payload must fail the source CRC, not copy through."""
        raw = bytearray(self.src.read_bytes())
        marker = CONTENT["01.wav"]
        idx = raw.find(marker)
        self.assertGreater(idx, 0)
        raw[idx : idx + len(marker)] = b"tampered!!"
        corrupt = self.tmp / "corrupt.zip"
        corrupt.write_bytes(bytes(raw))
        with self.assertRaises(zipfile.BadZipFile):
            rebuild_zip_deterministic(corrupt, self.tmp / "never.zip")

    def test_empty_zip(self):
        src = self.tmp / "empty.zip"
        with zipfile.ZipFile(src, "w"):
            pass
        out, sha1 = self._rebuild("emptyout.zip", src=src)
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.namelist(), [])
        self.assertTrue(sha1)

    def test_larger_than_copy_chunk(self):
        """Streaming path must handle payloads bigger than one chunk."""
        src = self.tmp / "big.zip"
        payload = bytes(range(256)) * 8192  # 2 MiB, two chunks
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("big.bin", payload)
        out, _ = self._rebuild("bigout.zip", src=src)
        with zipfile.ZipFile(out) as zf:
            self.assertEqual(zf.read("big.bin"), payload)


class TestVerifyDeterminism(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_non_deterministic_source_reported(self):
        src = self.tmp / "src.zip"
        _make_source(src)
        ok, original, rebuilt = verify_zip_determinism(src)
        self.assertFalse(ok)
        self.assertNotEqual(original, rebuilt)

    def test_already_deterministic_source_reported(self):
        src = self.tmp / "src.zip"
        _make_source(src)
        normalized = self.tmp / "norm.zip"
        rebuild_zip_deterministic(src, normalized)
        ok, original, rebuilt = verify_zip_determinism(normalized)
        self.assertTrue(ok)
        self.assertEqual(original, rebuilt)


class TestPackDeterminism(unittest.TestCase):
    """A pack is a function of its inputs, not of the clock it was built on."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bios = self.tmp / "bios"
        self.platforms = self.tmp / "platforms"
        self.bios.mkdir()
        self.platforms.mkdir()

        payload = b"DETERMINISM_PAYLOAD"
        (self.bios / "boot.rom").write_bytes(payload)
        sha1 = hashlib.sha1(payload).hexdigest()
        # A romset goes through the deterministic rebuild, which stages the
        # archive in a temporary file. Copying that file into the pack took
        # its mtime -the wall clock -so 348 members of the real Recalbox
        # pack moved between two builds while every byte matched. Without a
        # romset here the fixture never reaches that path.
        romset = self.bios / "romset.zip"
        with zipfile.ZipFile(romset, "w") as archive:
            archive.writestr("rom_a.bin", b"ROM A CONTENT")
            archive.writestr("rom_b.bin", b"ROM B CONTENT")
        rom_bytes = romset.read_bytes()
        rom_sha1 = hashlib.sha1(rom_bytes).hexdigest()
        self.db = {
            "generated_at": "2026-01-02T03:04:05Z",
            "files": {
                sha1: {
                    "path": str(self.bios / "boot.rom"),
                    "name": "boot.rom",
                    "size": len(payload),
                    "sha1": sha1,
                    "md5": hashlib.md5(payload).hexdigest(),
                },
                rom_sha1: {
                    "path": str(romset),
                    "name": "romset.zip",
                    "size": len(rom_bytes),
                    "sha1": rom_sha1,
                    "md5": hashlib.md5(rom_bytes).hexdigest(),
                },
            },
            "indexes": {
                "by_md5": {hashlib.md5(payload).hexdigest(): sha1},
                "by_name": {"boot.rom": [sha1], "romset.zip": [rom_sha1]},
                "by_crc32": {},
                "by_sha256": {},
                "by_path_suffix": {},
            },
        }
        (self.platforms / "detplat.yml").write_text(
            "platform: DetPlat\n"
            "verification_mode: existence\n"
            "base_destination: system\n"
            "systems:\n"
            "  test-sys:\n"
            "    files:\n"
            "      - name: boot.rom\n"
            "        destination: boot.rom\n"
            "        required: true\n"
            "      - name: romset.zip\n"
            "        destination: romset.zip\n"
            "        required: true\n"
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _build(self, out_name: str) -> Path:
        from scripts.generate_pack import generate_pack

        out = self.tmp / out_name
        out.mkdir()
        path = generate_pack(
            "detplat", str(self.platforms), self.db, str(self.bios), str(out),
            offline=True,
        )
        self.assertIsNotNone(path)
        return Path(path)

    def test_two_builds_are_byte_identical(self):
        first = self._build("out1")
        time.sleep(2.1)  # ZIP mtimes are 2s-granular: cross a whole tick
        second = self._build("out2")
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).hexdigest(),
            hashlib.sha256(second.read_bytes()).hexdigest(),
        )

    def test_the_rebuild_path_ran(self):
        """Guard the guard: a fixture without a romset proves nothing."""
        pack = self._build("out1")
        with zipfile.ZipFile(pack) as zf:
            names = {i.filename.rsplit("/", 1)[-1] for i in zf.infolist()}
        self.assertIn("romset.zip", names)

    def test_every_member_carries_the_fixed_epoch(self):
        """A member's date must come from the build's inputs, not its clock.

        ZipFile.write copies the source file's mtime, which is the checkout
        time for a collection file and the wall clock for one staged in tmp/.
        """
        pack = self._build("out1")
        with zipfile.ZipFile(pack) as zf:
            dates = {i.date_time for i in zf.infolist()}
        self.assertEqual(dates, {_FIXED_DATE_TIME})

    def test_generated_members_carry_the_fixed_epoch(self):
        pack = self._build("out1")
        with zipfile.ZipFile(pack) as zf:
            generated = [
                i for i in zf.infolist()
                if i.filename.rsplit("/", 1)[-1].startswith(
                    ("README.txt", "INSTRUCTIONS_", "RENAMED_")
                )
            ]
            self.assertTrue(generated, "pack should carry a generated README")
            for info in generated:
                self.assertEqual(info.date_time, _FIXED_DATE_TIME)

    def _build_emulator(self, out_name: str) -> Path:
        from scripts.generate_pack import generate_emulator_pack

        out = self.tmp / out_name
        out.mkdir()
        (self.tmp / "emulators").mkdir(exist_ok=True)
        (self.tmp / "emulators" / "detcore.yml").write_text(
            "emulator: detcore\n"
            "type: libretro\n"
            "display_name: DetCore\n"
            "systems: [test-sys]\n"
            "cores: [detcore]\n"
            "files:\n"
            "  - name: boot.rom\n"
            "    system: test-sys\n"
            "    required: true\n"
            "  - name: romset.zip\n"
            "    system: test-sys\n"
            "    required: true\n"
        )
        import common

        common._emulator_profiles_cache.clear()
        path = generate_emulator_pack(
            ["detcore"], str(self.tmp / "emulators"), self.db, str(self.bios),
            str(out), offline=True,
        )
        common._emulator_profiles_cache.clear()
        self.assertIsNotNone(path)
        return Path(path)

    def test_an_emulator_pack_is_byte_identical_too(self):
        """A distinct build path, and one the platform packs do not cover."""
        first = self._build_emulator("emu1")
        time.sleep(2.1)
        second = self._build_emulator("emu2")
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).hexdigest(),
            hashlib.sha256(second.read_bytes()).hexdigest(),
        )

    def test_every_emulator_pack_member_carries_the_fixed_epoch(self):
        pack = self._build_emulator("emu1")
        with zipfile.ZipFile(pack) as zf:
            self.assertEqual({i.date_time for i in zf.infolist()}, {_FIXED_DATE_TIME})

    def test_injected_manifest_is_pinned_to_the_database(self):
        from scripts.generate_pack import inject_manifest, verify_pack

        pack = self._build("out1")
        ok, manifest = verify_pack(str(pack), self.db)
        self.assertTrue(ok, manifest.get("errors"))
        self.assertEqual(manifest["generated"], self.db["generated_at"])
        inject_manifest(str(pack), manifest)
        with zipfile.ZipFile(pack) as zf:
            info = zf.getinfo("manifest.json")
        self.assertEqual(info.date_time, _FIXED_DATE_TIME)


if __name__ == "__main__":
    unittest.main()
