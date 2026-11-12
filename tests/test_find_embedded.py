"""find_embedded.py finds a file stored inside others by a rolling crc32:
the offset of every window that holds it, in a file or a ZIP member."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import os
import random
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import find_embedded  # noqa: E402

ROM = bytes(random.Random(8039).randrange(256) for _ in range(2048))
CRC = zlib.crc32(ROM)
SHA1 = hashlib.sha1(ROM).hexdigest()


class RollingWindow(unittest.TestCase):
    def test_every_offset_matches_a_direct_crc(self):
        noise = random.Random(1).randbytes(5000)
        data = noise[:777] + ROM + noise[777:3000] + ROM + noise[3000:]
        self.assertEqual(find_embedded.offsets(data, CRC, len(ROM)), [777, 777 + 2048 + 2223])

    def test_the_file_itself_and_a_short_file(self):
        self.assertEqual(find_embedded.offsets(ROM, CRC, len(ROM)), [0])
        self.assertEqual(find_embedded.offsets(ROM[:100], CRC, len(ROM)), [])


class Command(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.cwd)
        (self.root / "emu.exe").write_bytes(b"MZ" * 300 + ROM + b"\0" * 64)
        with zipfile.ZipFile(self.root / "pack.zip", "w") as archive:
            archive.writestr("data/blob.bin", b"x" * 10 + ROM)

    def run_cli(self, *argv: str) -> tuple[int, str]:
        with mock.patch.object(sys, "argv", ["find_embedded.py", *argv]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = find_embedded.main()
        return code, out.getvalue()

    def test_a_confirmed_hit_in_a_file_and_in_a_zip_member_is_extracted(self):
        code, out = self.run_cli(str(self.root), "--crc32", f"{CRC:08x}", "--size", "2048",
                                 "--sha1", SHA1, "--extract")
        self.assertEqual(code, 0, out)
        self.assertIn("emu.exe at 600: sha1", out)
        self.assertIn("pack.zip!data/blob.bin at 10", out)
        self.assertEqual((self.root / "tmp" / "acquire" / SHA1).read_bytes(), ROM)

    def test_nothing_found_and_extract_without_sha1_are_refused(self):
        code, out = self.run_cli(str(self.root / "emu.exe"), "--crc32", "deadbeef",
                                 "--size", "2048")
        self.assertEqual((code, out.strip()), (1, "Not found."))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.run_cli(str(self.root), "--crc32", f"{CRC:08x}", "--size", "2048", "--extract")


if __name__ == "__main__":
    unittest.main()
