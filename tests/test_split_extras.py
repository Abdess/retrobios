"""Split packs add up to the full pack.

Core extras went only to the part of a system the platform declares: an
extra for a system it does not declare, or with none, was in the full pack
and in no part (4507 of RetroArch's 5430).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_zip_contents_index, compute_hashes, load_emulator_profiles  # noqa: E402
from generate_pack import generate_split_packs  # noqa: E402


class SplitPartsCoverTheExtras(unittest.TestCase):
    def test_an_extra_of_an_undeclared_system_has_a_part(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            root = Path(tmp)
            (root / "platforms").mkdir()
            (root / "emulators").mkdir()
            files = {}
            for name in ("bios_a.bin", "core_c.bin"):
                path = root / "bios" / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(name.encode())
                files[name] = (str(path), compute_hashes(str(path)))
            db = {
                "files": {
                    h["sha1"]: {"name": n, "md5": h["md5"], "sha1": h["sha1"],
                                "sha256": h["sha256"], "path": p, "size": len(n)}
                    for n, (p, h) in files.items()
                },
                "indexes": {
                    "by_md5": {h["md5"]: h["sha1"] for _p, h in files.values()},
                    "by_name": {n: [h["sha1"]] for n, (_p, h) in files.items()},
                    "by_crc32": {}, "by_path_suffix": {},
                },
            }
            (root / "platforms" / "_registry.yml").write_text(
                yaml.dump({"platforms": {"plat": {"status": "active"}}})
            )
            (root / "platforms" / "plat.yml").write_text(yaml.dump({
                "platform": "Plat", "verification_mode": "existence",
                "cores": ["corec"],
                "systems": {"sys-a": {"files": [
                    {"name": "bios_a.bin", "sha1": files["bios_a.bin"][1]["sha1"]}
                ]}},
            }))
            (root / "emulators" / "corec.yml").write_text(yaml.dump({
                "emulator": "CoreC", "type": "libretro", "systems": ["sys-other"],
                "files": [{"name": "core_c.bin", "required": True}],
            }))
            parts = generate_split_packs(
                "plat", str(root / "platforms"), db, str(root / "bios"), str(root / "dist"),
                emulators_dir=str(root / "emulators"),
                zip_contents=build_zip_contents_index(db),
                emu_profiles=load_emulator_profiles(str(root / "emulators")),
            )
            members = {n for p in parts for n in zipfile.ZipFile(p).namelist()}
            self.assertIn("core_c.bin", members)


if __name__ == "__main__":
    unittest.main()
