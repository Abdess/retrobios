"""A custom pack built from hashes follows the emulator it names, or refuses.

`--from-md5 --emulator` accepted any name: an unknown one produced a generic
pack in the layout of no emulator, rc 0, where `--emulator` alone refuses it.
With a known one and `--standalone`, a profile without pack_structure kept
the bare file names under a pack called Standalone.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _pack(*options: str) -> tuple[subprocess.CompletedProcess, list[str]]:
    with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as out:
        proc = subprocess.run(
            [sys.executable, "scripts/generate_pack.py", *options, "--offline",
             "--output-dir", out],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
        )
        names = []
        for archive in Path(out).glob("*.zip"):
            with zipfile.ZipFile(archive) as zf:
                names.extend(zf.namelist())
    return proc, names


class TheEmulatorContextIsChecked(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            raise unittest.SkipTest("database.json is not built")
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        cls.db = json.loads(db_path.read_text(encoding="utf-8"))

    def test_an_unknown_emulator_is_refused(self):
        md5 = next(iter(self.db["files"].values()))["md5"]
        proc, names = _pack("--from-md5", md5, "--emulator", "no_such_core")
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("not found", proc.stderr)
        self.assertEqual(names, [])


    def test_the_standalone_layout_reaches_a_profile_without_structure(self):
        """BBKEmu has no pack_structure; its A4980 8.BIN goes to
        system/BBKEmu/A4980/ standalone. The hash pack kept the bare name,
        then, once laid out, sent it to the A4988 folder whose entry shares
        the name."""
        md5 = "ddfc001a6859d63ed46368ea7fe9f20c"
        if not any(record.get("md5") == md5 for record in self.db["files"].values()):
            self.skipTest("the A4980 8.BIN is not collected")
        proc, names = _pack("--from-md5", md5, "--emulator", "bbkemu", "--standalone")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(names, ["system/BBKEmu/A4980/8.BIN"])


class SystemAndEmulatorPacksKeepTheirNames(unittest.TestCase):
    """`--system sega-triforce` and `--emulator triforce` both wrote
    Triforce_BIOS_Pack.zip: whichever ran second replaced the other."""

    def test_the_two_selections_write_two_files(self):
        import hashlib

        import yaml

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import common
        import generate_db
        import generate_pack as gp

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as directory:
            root = Path(directory)
            (root / "bios").mkdir()
            (root / "emulators").mkdir()
            out = root / "dist"
            payload = b"triforce bios"
            (root / "bios" / "segaboot.gcm").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files = {sha1: {
                "path": str(root / "bios" / "segaboot.gcm"), "name": "segaboot.gcm",
                "size": len(payload), "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "0",
            }}
            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            (root / "emulators" / "triforce.yml").write_text(yaml.dump({
                "emulator": "Triforce", "type": "libretro", "cores": ["triforce"],
                "systems": ["sega-triforce"],
                "files": [{"name": "segaboot.gcm", "required": True}],
            }))
            common._emulator_profiles_cache.clear()
            try:
                emulator_pack = gp.generate_emulator_pack(
                    ["triforce"], str(root / "emulators"), db, str(root / "bios"),
                    str(out), offline=True,
                )
                system_pack = gp.generate_system_pack(
                    ["sega-triforce"], str(root / "emulators"), db,
                    str(root / "bios"), str(out), offline=True,
                )
            finally:
                common._emulator_profiles_cache.clear()
            self.assertNotEqual(Path(emulator_pack).name, Path(system_pack).name)
            self.assertTrue(Path(emulator_pack).exists())
            self.assertTrue(Path(system_pack).exists())

if __name__ == "__main__":
    unittest.main()
