"""A digest frontend withholds a file only when ITS digest disagrees.

RomM's list declares md5, sha1 and crc32 per file and RomM accepts any of
them. The resolver calls a file `hash_mismatch` when any declared hash
disagrees, so a mistyped crc32 beside the right md5 dropped the file from
the pack and the manifest while verify, comparing md5, called it OK.
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

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from common import load_platform_config  # noqa: E402
from generate_pack import generate_manifest, generate_pack  # noqa: E402
from verify import verify_platform  # noqa: E402


class FrontendDigestDecides(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.bios = root / "bios"
        self.bios.mkdir()
        payload = b"psx bios " * 64
        held = self.bios / "scph5501.bin"
        held.write_bytes(payload)
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        self.platforms = root / "platforms"
        self.platforms.mkdir()
        (root / "emulators").mkdir()
        self.emulators = root / "emulators"
        (self.platforms / "_registry.yml").write_text(
            yaml.safe_dump({"platforms": {"digestplat": {"status": "active"}}})
        )
        (self.platforms / "digestplat.yml").write_text(yaml.safe_dump({
            "platform": "DigestPlat",
            "verification_mode": "md5",
            "base_destination": "bios",
            "systems": {"psx": {"files": [{
                "name": "scph5501.bin", "destination": "scph5501.bin",
                "md5": md5, "crc32": "00000000", "required": True,
            }]}},
        }))
        self.db = {
            "files": {sha1: {"path": str(held), "name": "scph5501.bin", "size": len(payload),
                             "sha1": sha1, "md5": md5, "crc32": "deadbeef"}},
            "indexes": {"by_md5": {md5: sha1}, "by_name": {"scph5501.bin": [sha1]},
                        "by_crc32": {}, "by_path_suffix": {}},
        }
        self.root = root

    def test_pack_manifest_and_verify_agree(self):
        os.chdir(self.root)
        self.addCleanup(os.chdir, REPO_ROOT)
        zip_path = generate_pack(
            "digestplat", str(self.platforms), self.db, str(self.bios),
            str(self.root / "out"), emulators_dir=str(self.emulators),
            emu_profiles={}, offline=True,
        )
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("scph5501.bin", {Path(n).name for n in zf.namelist()})
        manifest = generate_manifest(
            "digestplat", str(self.platforms), self.db, str(self.bios),
            str(self.platforms / "_registry.yml"), emulators_dir=str(self.emulators),
            emu_profiles={}, offline=True,
        )
        self.assertEqual([f["dest"] for f in manifest["files"]], ["scph5501.bin"])
        config = load_platform_config("digestplat", str(self.platforms))
        result = verify_platform(config, self.db, str(self.emulators), emu_profiles={})
        self.assertEqual(result["details"][0]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
