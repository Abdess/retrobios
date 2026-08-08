"""Tests for deterministic ZIP rebuilding."""

from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
