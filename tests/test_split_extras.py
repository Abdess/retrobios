"""Split packs add up to the full pack.

Core extras went only to the part of a system the platform declares: an
extra for a system it does not declare, or with none, was in the full pack
and in no part (4507 of RetroArch's 5430).
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import build_zip_contents_index, compute_hashes, load_emulator_profiles  # noqa: E402
from generate_pack import PackRecord, generate_pack, generate_split_packs  # noqa: E402


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


class SplitPartsHoldWhatTheFullPackHolds(unittest.TestCase):
    """A part sees neither the other systems' declarations nor their extras.

    RetroDECK's Other_Cores part wrote bios/SGB1.sfc/program.rom beside the
    SNES part's file bios/SGB1.sfc, a file/directory clash the full pack
    refuses. RetroBat's ColecoVision part wrote openmsx/... beside the MSX
    part's openMSX/..., case twins the full pack folds. A path two systems
    declare got each system's file, one per part.
    """

    def _build(self, platform: dict, profiles: dict[str, dict], blobs: dict[str, bytes]):
        tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "platforms").mkdir()
        (root / "emulators").mkdir()
        files = {}
        for rel, payload in blobs.items():
            path = root / "bios" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            files[rel] = (str(path), compute_hashes(str(path)))
        by_name: dict[str, list[str]] = {}
        for rel, (_p, h) in files.items():
            by_name.setdefault(Path(rel).name, []).append(h["sha1"])
        db = {
            "files": {
                h["sha1"]: {"name": Path(rel).name, "md5": h["md5"], "sha1": h["sha1"],
                            "sha256": h["sha256"], "path": p, "size": 1}
                for rel, (p, h) in files.items()
            },
            "indexes": {
                "by_md5": {h["md5"]: h["sha1"] for _p, h in files.values()},
                "by_name": by_name, "by_crc32": {}, "by_path_suffix": {},
            },
        }
        (root / "platforms" / "_registry.yml").write_text(
            yaml.dump({"platforms": {"plat": {"status": "active"}}})
        )
        (root / "platforms" / "plat.yml").write_text(yaml.dump(platform))
        for name, profile in profiles.items():
            (root / "emulators" / f"{name}.yml").write_text(yaml.dump(profile))
        args = dict(
            emulators_dir=str(root / "emulators"),
            zip_contents=build_zip_contents_index(db),
            emu_profiles=load_emulator_profiles(str(root / "emulators")),
            offline=True,
        )
        full = PackRecord()
        generate_pack(
            "plat", str(root / "platforms"), db, str(root / "bios"), "", record=full, **args
        )
        parts: dict[str, PackRecord] = {}
        generate_split_packs(
            "plat", str(root / "platforms"), db, str(root / "bios"), str(root / "dist"),
            records=parts, **args,
        )
        self.assertFalse((root / "dist").exists())
        return full, parts

    def _assert_parts_add_up(self, full: PackRecord, parts: dict[str, PackRecord]) -> None:
        notes = {"README.txt"}
        union = {m for r in parts.values() for m in r.members} - notes
        self.assertEqual(union, set(full.members) - notes)
        for record in parts.values():
            for member, source in record.sources.items():
                self.assertEqual(
                    compute_hashes(source)["sha1"],
                    compute_hashes(full.sources[member])["sha1"], member,
                )

    def test_a_file_directory_conflict_stays_out_of_every_part(self):
        full, parts = self._build(
            {
                "platform": "Plat", "verification_mode": "existence", "cores": ["sgb"],
                "systems": {"snes": {"files": [{"name": "SGB1.sfc"}]}},
            },
            {"sgb": {
                "emulator": "SGB", "type": "libretro", "systems": ["sgb-other"],
                "files": [{"name": "program.rom", "path": "SGB1.sfc/program.rom"}],
            }},
            {"SGB1.sfc": b"cartridge", "sgb/program.rom": b"program"},
        )
        self.assertNotIn("SGB1.sfc/program.rom", full.members)
        self._assert_parts_add_up(full, parts)

    def test_a_case_twin_is_written_once(self):
        full, parts = self._build(
            {
                "platform": "Plat", "verification_mode": "existence",
                "case_insensitive_fs": True, "cores": ["msxcore"],
                "systems": {
                    "msx": {"files": [{"name": "disk.rom", "destination": "openMSX/disk.rom"}]},
                    "coleco": {"files": []},
                },
            },
            {"msxcore": {
                "emulator": "MSX Core", "type": "libretro", "systems": ["msx", "coleco"],
                "files": [{"name": "disk.rom", "path": "openmsx/disk.rom"}],
            }},
            {"MSX/disk.rom": b"disk"},
        )
        self.assertNotIn("openmsx/disk.rom", full.members)
        self._assert_parts_add_up(full, parts)

    def test_a_path_two_systems_declare_holds_one_file(self):
        full, parts = self._build(
            {
                "platform": "Plat", "verification_mode": "existence",
                "systems": {
                    "coco": {"files": [{
                        "name": "disk.rom", "sha1": hashlib.sha1(b"coco disk").hexdigest(),
                    }]},
                    "pc88": {"files": [{
                        "name": "disk.rom", "sha1": hashlib.sha1(b"pc-88 disk").hexdigest(),
                    }]},
                },
            },
            {},
            {"CoCo/disk.rom": b"coco disk", "PC88/disk.rom": b"pc-88 disk"},
        )
        self._assert_parts_add_up(full, parts)


if __name__ == "__main__":
    unittest.main()
