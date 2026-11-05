"""A hashless platform entry takes no file filed under another maker.

AmberELEC's nec-pc-88 declares DISK.ROM with an empty md5. QUASI88 reads that
name as n88sub.rom, the 2 KB PC-88 disk ROM (libretro.c:1085), but the name
step served the 16 KB MSX disk ROM, the only primary called DISK.ROM. The
quasi88 alias could not point the name at the PC-88 file, since by_name
refuses an alias a primary already carries. by_shadowed_alias keeps it, and
the resolver reads it only once the system's own maker folder is all that
remains.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
import generate_site  # noqa: E402
from verify import verify_platform  # noqa: E402

MSX_DISK = b"M" * 16384
PC88_DISK = b"N" * 2048

QUASI88 = """\
emulator: QUASI88
type: libretro
systems: [nec-pc-88]
cores: [quasi88]
files:
  - name: n88sub.rom
    path: quasi88/n88sub.rom
    required: false
    aliases: [N88SUB.ROM, DISK.ROM]
"""

PLATFORM = {
    "platform": "Handheld",
    "version": "1",
    "verification_mode": "md5",
    "base_destination": "",
    "cores": ["quasi88"],
    "systems": {
        "nec-pc-88": {
            "files": [
                {"name": "DISK.ROM", "destination": "bios/quasi88/DISK.ROM",
                 "required": True},
            ],
        },
        "microsoft-msx": {
            "files": [
                {"name": "DISK.ROM", "destination": "bios/Machines/DISK.ROM",
                 "required": True},
            ],
        },
    },
}


class _Collection(unittest.TestCase):
    def setUp(self):
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        for relative, payload in (
            ("bios/Microsoft/MSX/DISK.ROM", MSX_DISK),
            ("bios/NEC/PC-88/n88sub.rom", PC88_DISK),
        ):
            Path(relative).parent.mkdir(parents=True, exist_ok=True)
            Path(relative).write_bytes(payload)
        Path("emulators").mkdir()
        Path("platforms").mkdir()
        Path("emulators/quasi88.yml").write_text(QUASI88)
        Path("platforms/handheld.yml").write_text(yaml.dump(PLATFORM))
        Path("platforms/_registry.yml").write_text(
            yaml.dump({"platforms": {"handheld": {"status": "active"}}})
        )
        subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts/generate_db.py"), "--force",
             "--bios-dir", "bios", "--output", "database.json"],
            check=True, capture_output=True,
        )
        self.db = common.load_database("database.json")
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        self.config = common.load_platform_config("handheld", "platforms")
        self.profiles = common.load_emulator_profiles("emulators")

    def tearDown(self):
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _entry(self, system: str) -> dict:
        return self.config["systems"][system]["files"][0]

    def _manifest(self) -> dict:
        return builder.generate_manifest(
            "handheld", "platforms", self.db, "bios", "platforms/_registry.yml",
            emulators_dir="emulators", emu_profiles=self.profiles, offline=True,
        )


class ShadowedAliasIndex(_Collection):
    def test_the_alias_a_primary_carries_is_kept_apart(self):
        sha1 = hashlib.sha1(PC88_DISK).hexdigest()
        indexes = self.db["indexes"]
        self.assertEqual(indexes["by_shadowed_alias"]["DISK.ROM"], [sha1])
        self.assertNotIn(sha1, indexes["by_name"]["DISK.ROM"])

    def test_an_entry_with_no_single_content_designates_nothing(self):
        shadowed = [("a.rom", set(), ["B.ROM"]), ("c.rom", {"1" * 40}, ["B.ROM"])]
        by_name = {"a.rom": ["2" * 40, "3" * 40], "B.ROM": ["4" * 40]}
        self.assertEqual(
            generate_db.shadowed_alias_index(shadowed, by_name), {"B.ROM": ["1" * 40]}
        )


class DiskRomGoesToThePc88File(_Collection):
    def test_the_entry_knows_its_system(self):
        self.assertEqual(self._entry("nec-pc-88")["platform_system"], "nec-pc-88")

    def test_resolution(self):
        entry = self._entry("nec-pc-88")
        path, status = common.resolve_local_file(
            entry, self.db, dest_hint=entry["destination"]
        )
        self.assertEqual((path, status), ("bios/NEC/PC-88/n88sub.rom", "name_exact"))

    def test_the_msx_system_keeps_the_msx_file(self):
        entry = self._entry("microsoft-msx")
        path, _status = common.resolve_local_file(
            entry, self.db, dest_hint=entry["destination"]
        )
        self.assertEqual(path, "bios/Microsoft/MSX/DISK.ROM")

    def test_a_declared_hash_still_decides(self):
        entry = {**self._entry("nec-pc-88"), "md5": hashlib.md5(MSX_DISK).hexdigest()}
        path, status = common.resolve_local_file(entry, self.db)
        self.assertEqual((path, status), ("bios/Microsoft/MSX/DISK.ROM", "md5_exact"))

    def test_an_emulator_entry_is_not_narrowed(self):
        entry = {**self._entry("nec-pc-88"), "source_profile": "msx-emu"}
        path, _status = common.resolve_local_file(entry, self.db)
        self.assertEqual(path, "bios/Microsoft/MSX/DISK.ROM")

    def test_no_pc88_copy_leaves_it_missing_not_mismatched(self):
        Path("bios/NEC/PC-88/n88sub.rom").unlink()
        entry = self._entry("nec-pc-88")
        self.assertEqual(
            common.resolve_local_file(entry, self.db, dest_hint=entry["destination"]),
            (None, "not_found"),
        )

    def test_verify(self):
        report = verify_platform(self.config, self.db, "emulators", self.profiles)
        paths = {d["name"]: set() for d in report["details"]}
        for d in report["details"]:
            paths[d["name"]].add(d.get("path"))
        self.assertEqual(
            paths["DISK.ROM"],
            {"bios/NEC/PC-88/n88sub.rom", "bios/Microsoft/MSX/DISK.ROM"},
        )

    def test_pack(self):
        zip_path = builder.generate_pack(
            "handheld", "platforms", self.db, "bios", "out",
            emulators_dir="emulators", emu_profiles=self.profiles, offline=True,
        )
        with zipfile.ZipFile(zip_path) as zf:
            self.assertEqual(zf.read("bios/quasi88/DISK.ROM"), PC88_DISK)
            self.assertEqual(zf.read("bios/Machines/DISK.ROM"), MSX_DISK)

    def test_the_manifest_changes_only_that_row(self):
        manifest = self._manifest()
        original = (common.load_platform_config, common.system_makers)

        def untagged(*args, **kwargs):
            config = original[0](*args, **kwargs)
            for system in config["systems"].values():
                for f in system.get("files") or []:
                    f.pop("platform_system", None)
            return config

        common._platform_config_cache.clear()
        builder.load_platform_config = common.load_platform_config = untagged
        common.system_makers = lambda *args: frozenset()
        try:
            before = self._manifest()
        finally:
            builder.load_platform_config = common.load_platform_config = original[0]
            common.system_makers = original[1]
            common._platform_config_cache.clear()
        rows = {f["dest"]: f for f in manifest["files"]}
        old_rows = {f["dest"]: f for f in before["files"]}
        self.assertEqual(rows["bios/quasi88/DISK.ROM"]["size"], len(PC88_DISK))
        self.assertEqual(old_rows["bios/quasi88/DISK.ROM"]["size"], len(MSX_DISK))
        del rows["bios/quasi88/DISK.ROM"], old_rows["bios/quasi88/DISK.ROM"]
        self.assertEqual(rows, old_rows)
        moved = len(MSX_DISK) - len(PC88_DISK)
        for key in ("total_size", "pack_size"):
            self.assertEqual(before[key] - manifest[key], moved)
        changed = {"files", "total_size", "pack_size", "generated"}
        self.assertEqual(
            json.dumps({k: v for k, v in manifest.items() if k not in changed}, sort_keys=True),
            json.dumps({k: v for k, v in before.items() if k not in changed}, sort_keys=True),
        )


class SiteSharesTheMakerTest(unittest.TestCase):
    def test_one_copy(self):
        self.assertIs(generate_site.names_manufacturer, common.names_manufacturer)
        self.assertIs(generate_site.BUCKET_FOLDERS, common.BUCKET_FOLDERS)


class NoHashlessNameMatchCrossesMakers(unittest.TestCase):
    """Every registered platform: a name match never lands on another maker."""

    def test_registry(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(REPO_ROOT)
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json not built")
        db = common.load_database(str(db_path))
        registry = common.load_data_dir_registry("platforms")
        folders = {
            parts[1]
            for entry in db["files"].values()
            if len(parts := entry["path"].split("/")) >= 3 and parts[0] == "bios"
        } - common.BUCKET_FOLDERS
        crossings = []
        for platform in common.list_registered_platforms("platforms", include_archived=True):
            config = common.load_platform_config(platform, "platforms")
            for sys_id, system in config.get("systems", {}).items():
                makers = {f for f in folders if common.names_manufacturer(sys_id, f)}
                if not makers:
                    continue
                for entry in system.get("files") or []:
                    if any(entry.get(k) for k in ("sha1", "md5", "sha256", "crc32")):
                        continue
                    path, status = common.resolve_local_file(
                        entry, db, dest_hint=entry.get("destination", ""),
                        data_dir_registry=registry,
                    )
                    parts = (path or "").split("/")
                    if (
                        status.startswith("name")
                        and len(parts) >= 3
                        and parts[0] == "bios"
                        and parts[1] not in common.BUCKET_FOLDERS
                        and parts[1] not in makers
                    ):
                        crossings.append(f"{platform} {sys_id} {entry.get('name')}: {path}")
        self.assertEqual(crossings, [])


if __name__ == "__main__":
    unittest.main()
