"""Tests for the TorrentZip builder against real MAME romsets."""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

from torrentzip import (  # noqa: E402
    build_torrentzip,
    identify_romset,
    is_torrentzip,
    rebuild_torrentzip,
)


class TorrentZipTest(unittest.TestCase):
    """The format is deterministic: same members always give the same bytes."""

    def test_deterministic_output(self):
        members = [("b.rom", b"second"), ("a.rom", b"first")]
        self.assertEqual(build_torrentzip(members), build_torrentzip(members))

    def test_member_order_is_irrelevant(self):
        a = build_torrentzip([("a.rom", b"one"), ("b.rom", b"two")])
        b = build_torrentzip([("b.rom", b"two"), ("a.rom", b"one")])
        self.assertEqual(a, b)

    def test_case_insensitive_sorting(self):
        data = build_torrentzip([("B.rom", b"x"), ("a.rom", b"y")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual([i.filename for i in zf.infolist()], ["a.rom", "B.rom"])

    def test_fixed_timestamp_and_signature(self):
        data = build_torrentzip([("a.rom", b"payload")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual(zf.infolist()[0].date_time, (1996, 12, 24, 23, 32, 0))
            self.assertTrue(zf.comment.decode().startswith("TORRENTZIPPED-"))

    def test_roundtrip_readable_content(self):
        data = build_torrentzip([("a.rom", b"hello"), ("b.rom", b"world")])
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertEqual(zf.read("a.rom"), b"hello")
            self.assertEqual(zf.read("b.rom"), b"world")

    def test_rebuild_matches_real_mame_set(self):
        """Rebuilding a shipped MAME romset reproduces it byte for byte."""
        candidates = [
            os.path.join(REPO_ROOT, "bios", "Arcade", "Arcade", "naomi2.zip"),
            os.path.join(REPO_ROOT, "bios", "Arcade", "MAME", "naomi2.zip"),
        ]
        checked = 0
        for path in candidates:
            if not os.path.exists(path) or not is_torrentzip(path):
                continue
            with open(path, "rb") as fh:
                original = fh.read()
            self.assertEqual(rebuild_torrentzip(path), original, path)
            checked += 1
        if not checked:
            self.skipTest("no TorrentZip romset available")

    def test_source_renamed_sets_stay_reproducible(self):
        """Archives whose member names we corrected must rebuild identically.

        Renaming a ROM by hand produced archives that matched no upstream set
        and could not be regenerated from their contents either. The corrected
        primaries carry the MAME 0.289 names and TorrentZip bytes, so anyone
        holding the ROMs reproduces them exactly.
        """
        corrected = [
            os.path.join(REPO_ROOT, "bios", "Arcade", "MAME", "manager.zip"),
            os.path.join(REPO_ROOT, "bios", "Arcade", "Arcade", "sys573.zip"),
            os.path.join(REPO_ROOT, "bios", "Arcade", "Arcade", "cedmag.zip"),
            os.path.join(
                REPO_ROOT, "bios", "Entex", "Adventure Vision", "advision.zip"
            ),
        ]
        checked = 0
        for path in corrected:
            if not os.path.exists(path):
                continue
            self.assertTrue(is_torrentzip(path), path)
            with open(path, "rb") as fh:
                original = fh.read()
            self.assertEqual(rebuild_torrentzip(path), original, path)
            checked += 1
        if not checked:
            self.skipTest("corrected romsets not present in this checkout")

    def test_source_renamed_sets_carry_the_source_names(self):
        """The member names come from MAME, not from a YAML round-trip."""
        expected = {
            os.path.join(REPO_ROOT, "bios", "Arcade", "MAME", "manager.zip"): {
                "01", "23",
            },
            os.path.join(
                REPO_ROOT, "bios", "Entex", "Adventure Vision", "advision.zip"
            ): {"ins8048-11kdp_n.u5", "cop411l-kcn_n.u8"},
        }
        checked = 0
        for path, names in expected.items():
            if not os.path.exists(path):
                continue
            with zipfile.ZipFile(path) as archive:
                members = {
                    info.filename
                    for info in archive.infolist()
                    if not info.is_dir()
                }
            self.assertEqual(members, names, path)
            checked += 1
        if not checked:
            self.skipTest("corrected romsets not present in this checkout")

    def test_identify_romset_selects_matching_recipe(self):
        atoms = {"3610a686": b"alpha", "9d0d1b46": b"beta"}
        import zlib

        atoms = {
            f"{zlib.crc32(b'alpha') & 0xffffffff:08x}": b"alpha",
            f"{zlib.crc32(b'beta') & 0xffffffff:08x}": b"beta",
        }
        crc_a, crc_b = list(atoms)
        wanted = hashlib.md5(
            build_torrentzip([("a.rom", b"alpha"), ("b.rom", b"beta")])
        ).hexdigest()
        recipes = {
            "v1": [("a.rom", crc_a)],
            "v2": [("a.rom", crc_a), ("b.rom", crc_b)],
        }
        self.assertEqual(identify_romset(recipes, atoms, wanted), "v2")
        self.assertIsNone(identify_romset(recipes, atoms, "0" * 32))

    def test_identify_romset_skips_recipes_with_absent_atoms(self):
        atoms = {"aaaaaaaa": b"x"}
        recipes = {"v1": [("a.rom", "ffffffff")]}
        self.assertIsNone(identify_romset(recipes, atoms, "0" * 32))


def _as_file(test: unittest.TestCase, data: bytes) -> str:
    """Write bytes to a temp file cleaned up with the test."""
    fd, path = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(data)
    test.addCleanup(os.unlink, path)
    return path


class StreamingWriter(unittest.TestCase):
    """Members stream through in chunks, one in memory at a time."""

    def _members(self) -> list[tuple[str, bytes]]:
        import random

        noise = random.Random(7).randbytes(70_000)
        return [("b.rom", noise + bytes(50_000) + noise[:9_000]), ("A.rom", b"x" * 1_000)]

    def test_chunked_input_gives_the_one_shot_bytes(self):
        """Deflate output does not depend on how its input is cut."""
        import io
        import torrentzip

        members = self._members()
        whole = torrentzip.build_torrentzip(members)
        saved = torrentzip.CHUNK
        try:
            for chunk in (1, 333, 4096):
                torrentzip.CHUNK = chunk
                self.assertEqual(torrentzip.build_torrentzip(members), whole, chunk)
        finally:
            torrentzip.CHUNK = saved
        sink = io.BytesIO()
        written = torrentzip.write_torrentzip(
            sink, [(name, lambda d=data: io.BytesIO(d)) for name, data in members]
        )
        self.assertEqual(sink.getvalue(), whole)
        self.assertEqual(
            [(w.name, w.size, w.sha1) for w in written],
            [(name, len(data), hashlib.sha1(data).hexdigest())
             for name, data in sorted(members, key=lambda m: m[0].lower())],
        )

    def test_a_member_past_32_bits_takes_a_zip64_field(self):
        """cspect-next-8gb.zip holds an 8 GiB image: its size needs ZIP64."""
        import torrentzip

        members = self._members()
        saved = torrentzip.ZIP32_LIMIT
        torrentzip.ZIP32_LIMIT = 60_000
        try:
            data = torrentzip.build_torrentzip(members)
        finally:
            torrentzip.ZIP32_LIMIT = saved
        with zipfile.ZipFile(_as_file(self, data)) as zf:
            self.assertIsNone(zf.testzip())
            self.assertEqual(
                {info.filename: zf.read(info) for info in zf.infolist()}, dict(members)
            )
        self.assertNotEqual(data, build_torrentzip(members))

    def test_zlib_ng_is_recognised(self):
        """python.org 3.14 on Windows links zlib-ng, which gives other bytes."""
        from types import SimpleNamespace

        from torrentzip import zlib_ng_version

        stock = SimpleNamespace(ZLIB_RUNTIME_VERSION="1.3.1")
        windows = SimpleNamespace(ZLIB_RUNTIME_VERSION="1.3.1.zlib-ng")
        binding = SimpleNamespace(ZLIB_RUNTIME_VERSION="1.3.1", ZLIBNG_VERSION="2.2.4")
        self.assertIsNone(zlib_ng_version(stock))
        self.assertEqual(zlib_ng_version(windows), "1.3.1.zlib-ng")
        self.assertEqual(zlib_ng_version(binding), "2.2.4")


class CheckModeExitCode(unittest.TestCase):
    """--check printed `conform: False` and exited 0, so no script could use it."""

    def test_the_exit_code_follows_conformance(self):
        import subprocess

        with tempfile.TemporaryDirectory(dir=os.path.join(REPO_ROOT, "tmp")) as directory:
            plain = os.path.join(directory, "plain.zip")
            with zipfile.ZipFile(plain, "w") as zf:
                zf.writestr("a.bin", b"rom")
            torrent = os.path.join(directory, "torrent.zip")
            with open(torrent, "wb") as handle:
                handle.write(build_torrentzip([("a.bin", b"rom")]))
            script = os.path.join(REPO_ROOT, "scripts", "torrentzip.py")
            codes = [
                subprocess.run(
                    [sys.executable, script, "--check", path],
                    capture_output=True, check=False, timeout=60,
                ).returncode
                for path in (plain, torrent)
            ]
        self.assertEqual(codes, [1, 0])


if __name__ == "__main__":
    unittest.main()
