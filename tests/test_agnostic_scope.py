"""What a filename-agnostic core's scan may emit, and where.

yaps2 declares its BIOS under pcsx2/bios/ with a free name and its shaders,
sounds and fonts under pcsx2/resources/ with fixed names. Every sized entry
seeded the scan and every find went to the pack root: 189 resources landed
flat in RetroArch's system/, and the BIOS the core reads from pcsx2/bios/
was not where it looks.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class AgnosticScan(unittest.TestCase):
    def test_only_the_bios_directory_seeds_and_finds_keep_its_folder(self):
        from packextras import _agnostic_scan_extras

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            files, by_name = {}, {}
            for path, data in (
                ("bios/PS2/scph1.bin", b"a" * 64),
                ("bios/PS2/scph2.bin", b"b" * 64),
                ("bios/PS2/res/message.wav", b"c" * 8),
                ("bios/PS2/res/other.wav", b"d" * 8),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(data)
                sha1 = hashlib.sha1(data).hexdigest()
                name = path.rsplit("/", 1)[1]
                files[sha1] = {"path": path, "name": name, "size": len(data), "sha1": sha1}
                by_name.setdefault(name, []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {}, "by_crc32": {},
                                              "by_path_suffix": {}}}
            profile = {"emulator": "Y", "type": "libretro", "bios_mode": "agnostic",
                       "bios_directory": "pcsx2/bios/", "systems": ["ps2"], "files": [
                           {"name": "scph1.bin", "path": "pcsx2/bios/scph1.bin", "size": 64},
                           {"name": "message.wav", "path": "pcsx2/resources/message.wav", "size": 8},
                       ]}
            extras = _agnostic_scan_extras({"y": profile}, {"y"}, db, by_name, set(), "")
            self.assertEqual(sorted(e["destination"] for e in extras),
                             ["pcsx2/bios/scph1.bin", "pcsx2/bios/scph2.bin"])


class BundledHashIsProof(unittest.TestCase):
    """A bundled file with a declared hash is served by those bytes or flagged.

    Four NetherSX2-Turnip entries named their own sha1; the collection held
    NetherSX2's copies, which the builder shipped in their place.
    """

    def test_no_bundled_entry_resolves_to_other_bytes(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("no database.json")
        from common import (
            build_zip_contents_index,
            load_data_dir_registry,
            load_database,
            load_emulator_profiles,
            resolve_local_file,
        )

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = load_database("database.json")
        zips = build_zip_contents_index(db)
        registry = load_data_dir_registry("platforms")
        wrong = []
        for name, profile in sorted(load_emulator_profiles("emulators", skip_aliases=False).items()):
            for entry in profile.get("files") or []:
                if not entry.get("bundled") or entry.get("unsourceable"):
                    continue
                if not any(entry.get(k) for k in ("sha1", "md5", "sha256", "crc32")):
                    continue
                dest = entry.get("path") or entry.get("name") or ""
                local, status = resolve_local_file(
                    {**entry, "source_profile": name}, db, zips, dest_hint=dest,
                    data_dir_registry=registry)
                if local and status == "hash_mismatch":
                    wrong.append((name, dest, local))
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
