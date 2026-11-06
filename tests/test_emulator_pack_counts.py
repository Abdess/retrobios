"""An emulator pack and verify --emulator count the same slots the same way.

Accepted alternatives on one destination (raze's SW.GRP), unsourceable
entries and user-provided ones were counted one way by the pack and another
by verify: raze was "10 packed, 29 missing, 4 refused" against "10/23 OK,
1 untested, 12 missing", xash3d's thirteen unsourceable slots were three
names and ten "missing".
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# kronos: an archive unit under its archive_prefix and a loose same-named file.
# speccy,zesarux: the pack keeps speccy's PENTAGON.ROM and drops zesarux's
# 32 KB pentagon.rom, which verify called covered.
# dinothawr, cemu: data directories, whose members the pack counted among
# "files packed" (110 against verify's 0/0, 303 against 67/68).
CASES = (
    "raze", "rust_dos", "hatari", "xash3d_fwgs", "catacombgl", "openjk", "sonic2013",
    "kronos", "speccy,zesarux", "dinothawr", "cemu",
)


def _count(text: str, word: str) -> int:
    match = re.search(rf"(\d+) {word}", text)
    return int(match.group(1)) if match else 0


class PackAndReportAgree(unittest.TestCase):
    def test_each_emulator_pack_counts_as_verify_does(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json is not built")
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        for emulator in CASES:
            with self.subTest(emulator=emulator), tempfile.TemporaryDirectory(
                dir=REPO_ROOT / "tmp"
            ) as out:
                pack = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", "--emulator", emulator,
                     "--offline", "--output-dir", out],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=900, check=True,
                ).stdout
                report = subprocess.run(
                    [sys.executable, "scripts/verify.py", "--emulator", emulator],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=900, check=False,
                ).stdout
                summary = next(line for line in pack.splitlines() if "_BIOS_Pack.zip:" in line)
                label = emulator.replace(",", " + ")
                verdict = next(line for line in report.splitlines() if line.startswith(f"{label}:"))
                ok = int(re.search(r"(\d+)/\d+ OK", verdict).group(1))
                self.assertEqual(_count(summary, "files packed"), ok, (summary, verdict))
                self.assertEqual(_count(summary, "missing"), _count(verdict, "missing"))
                self.assertEqual(_count(summary, "unsourceable"), _count(verdict, "unsourceable"))
                self.assertEqual(_count(summary, "refused"), _count(verdict, "untested"))


class APlaceholderIsAnsweredByEvidence(unittest.TestCase):
    """LRPS2 declares only <bios>.bin: no name to look up, so its emulator
    pack shipped no PS2 BIOS and verify said missing. Another profile of the
    system proves the folder by hash, and the images there of the declared
    size are what the core reads."""

    def test_pack_and_report_carry_the_images(self):
        import hashlib
        import io
        import os
        import shutil
        import zipfile
        from contextlib import redirect_stdout

        import yaml

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from common import _emulator_profiles_cache  # noqa: PLC0415
        from generate_pack import generate_emulator_pack  # noqa: PLC0415
        from verify import verify_emulator  # noqa: PLC0415

        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        previous = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, previous)
        db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}, "by_crc32": {},
                                      "by_path_suffix": {}}}
        hashes = {}
        for name, data in (("proven.bin", b"P" * 64), ("other.bin", b"O" * 64),
                           ("small.bin", b"S" * 8)):
            rel = f"bios/Sony/PS2/{name}"
            Path(rel).parent.mkdir(parents=True, exist_ok=True)
            Path(rel).write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()
            hashes[name] = sha1
            db["files"][sha1] = {"path": rel, "name": name, "size": len(data),
                                 "md5": hashlib.md5(data).hexdigest(), "crc32": ""}
            db["indexes"]["by_name"][name] = [sha1]
        Path("emulators").mkdir()
        Path("emulators/named.yml").write_text(yaml.safe_dump({
            "emulator": "Named", "type": "libretro", "systems": ["sony-playstation-2"],
            "files": [{"name": "proven.bin", "sha1": hashes["proven.bin"], "size": 64}],
        }))
        Path("emulators/free.yml").write_text(yaml.safe_dump({
            "emulator": "Free", "type": "libretro", "bios_mode": "agnostic",
            "systems": ["sony-playstation-2"],
            "files": [{"name": "<bios>.bin", "path": "pcsx2/bios/<bios>.bin",
                       "min_size": 32, "max_size": 128, "required": True}],
        }))
        report = verify_emulator(["free"], "emulators", db, platforms_dir="platforms")
        with redirect_stdout(io.StringIO()):
            zip_path = generate_emulator_pack(
                ["free"], "emulators", db, "bios", "out", offline=True,
                platforms_dir="platforms",
            )
        with zipfile.ZipFile(zip_path) as zf:
            packed = sorted(zf.namelist())
        self.assertEqual(
            [n for n in packed if n != "README.txt"],
            ["pcsx2/bios/other.bin", "pcsx2/bios/proven.bin"],
        )
        self.assertEqual(report["total_files"], 2)


if __name__ == "__main__":
    unittest.main()
