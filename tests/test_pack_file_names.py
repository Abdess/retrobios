"""A display name never becomes a path inside the output directory.

fbneo_cps12 is called 'FinalBurn Neo (CPS-1/CPS-2)': the slash made the
emulator and system packs write into a directory that does not exist, while
verify reported the same scope OK.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from generate_pack import _name_part, generate_emulator_pack  # noqa: E402


class PackFileNames(unittest.TestCase):
    def test_separators_and_reserved_characters_are_replaced(self):
        self.assertEqual(_name_part("FinalBurn Neo (CPS-1/CPS-2)"), "FinalBurnNeo(CPS-1-CPS-2)")
        self.assertEqual(_name_part('a\\b:c*d?"e<f>g|h', "_"), "a-b-c-d--e-f-g-h")

    def test_an_emulator_named_with_a_slash_writes_its_pack(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            emulators = Path(tmp) / "emulators"
            out = Path(tmp) / "out"
            emulators.mkdir()
            out.mkdir()
            rom = Path(tmp) / "demo.bin"
            rom.write_bytes(b"demo")
            sha1 = hashlib.sha1(b"demo").hexdigest()
            (emulators / "demo.yml").write_text(
                'emulator: "Demo (A/B)"\ntype: libretro\nsystems: [demo]\n'
                f'files:\n  - name: demo.bin\n    sha1: "{sha1}"\n'
            )
            db = {
                "files": {sha1: {"path": str(rom), "name": "demo.bin", "size": 4,
                                 "md5": hashlib.md5(b"demo").hexdigest()}},
                "indexes": {"by_name": {"demo.bin": [sha1]}, "by_md5": {}},
            }
            result = generate_emulator_pack(
                ["demo"], str(emulators), db, "bios", str(out), zip_contents={},
            )
            self.assertTrue(result and Path(result).parent == out, result)


class SystemPackLeavesTheEmulatorPack(unittest.TestCase):
    """--system built under the emulator pack's name and renamed it away."""

    def test_both_packs_stay(self):
        import subprocess  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            for mode in (["--emulator", "emuscv"], ["--system", "scv"]):
                subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", *mode, "--offline",
                     "--output-dir", tmp],
                    cwd=REPO_ROOT, capture_output=True, check=True, timeout=600,
                )
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertIn("EmuSCV_BIOS_Pack.zip", names)
            self.assertIn("Scv_BIOS_Pack.zip", names)
            self.assertFalse([n for n in names if n.startswith(".system-")])


if __name__ == "__main__":
    unittest.main()
