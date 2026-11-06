"""NP2kai and meowPC98 read font.bmp and FONT.ROM as two files.

font_load reads the PC-98 bitmap (font.bmp, FONT.BMP) and then the V98 ROM
(FONT.ROM, font.rom), each through its own reader (NP2kai font/font.c:192-195,
meowPC98 font/font.c:180-181). Hung on font.bmp as aliases, the V98 names let
a collection without font.bmp serve the PC-88's 2 KB font.rom as np2kai/font.bmp,
which fontpc98_read cannot parse, and FONT.ROM was never placed under its name.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import resolve_local_file  # noqa: E402

V98_SIZE = 0x46800


def _entry(profile: str, name: str) -> dict:
    with open(REPO_ROOT / "emulators" / f"{profile}.yml") as handle:
        files = yaml.safe_load(handle)["files"]
    entry = next(f for f in files if f.get("name") == name)
    return {**entry, "source_profile": profile}


class FontFormatsAreSeparateFiles(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.root)
        self.db = {"files": {}, "indexes": {
            "by_md5": {}, "by_name": {}, "by_crc32": {}, "by_path_suffix": {},
        }}
        self.pc88 = self._hold("bios/NEC/PC-88/font.rom", b"8" * 2048)
        self.v98 = self._hold("bios/NEC/PC-98/font.rom", b"V" * V98_SIZE)

    def _hold(self, rel: str, data: bytes) -> str:
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        name = rel.rsplit("/", 1)[-1]
        self.db["files"][sha1] = {
            "path": rel, "name": name, "size": len(data),
            "md5": hashlib.md5(data).hexdigest(), "crc32": "",
        }
        self.db["indexes"]["by_name"].setdefault(name, []).append(sha1)
        return rel

    def test_no_v98_name_answers_for_the_bitmap(self):
        for profile in ("np2kai", "nekop2"):
            with self.subTest(profile=profile):
                entry = _entry(profile, "font.bmp")
                self.assertEqual(resolve_local_file(entry, self.db), (None, "not_found"))

    def test_the_v98_font_is_its_own_entry_and_skips_the_pc88_font(self):
        for profile in ("np2kai", "nekop2"):
            with self.subTest(profile=profile):
                entry = _entry(profile, "FONT.ROM")
                self.db["indexes"]["by_name"]["FONT.ROM"] = (
                    self.db["indexes"]["by_name"]["font.rom"]
                )
                path, _status = resolve_local_file(entry, self.db)
                self.assertEqual(path, self.v98)


if __name__ == "__main__":
    unittest.main()
