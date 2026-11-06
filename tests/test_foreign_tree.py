"""A file in another emulator's tree does not answer for this one.

bios/Other/<emulator>/ holds what that emulator ships. The path step took a
shortened tail that only NetherSX2's tree answered as proof for EmuCoreX's
unlock.wav, and broke a full-tail tie between EmuCoreX's GameIndex.yaml and
the system directory's copy by index order, serving a fork's game database
to upstream PCSX2.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_db  # noqa: E402
from common import resolve_local_file  # noqa: E402


class ForeignTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        files = {}
        for rel, payload in (
            ("bios/Other/forkemu/resources/GameIndex.yaml", b"fork db"),
            ("bios/Sony/PlayStation 2/resources/GameIndex.yaml", b"system copy"),
            ("bios/Other/forkemu/resources/sounds/unlock.wav", b"fork sound"),
        ):
            path = Path(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {
                "path": rel, "name": path.name, "size": len(payload), "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001",
            }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _resolve(self, owner: str, path: str):
        entry = {"name": path.rsplit("/", 1)[-1], "path": path, "source_profile": owner}
        return resolve_local_file(entry, self.db, {}, dest_hint=path)

    def test_a_full_tail_tie_goes_to_the_system_directory(self):
        local, status = self._resolve("pcsx2", "resources/GameIndex.yaml")
        self.assertEqual(status, "path_exact")
        self.assertTrue(local.startswith("bios/Sony/"), local)

    def test_the_fork_still_gets_its_own_copy(self):
        local, status = self._resolve("forkemu", "resources/GameIndex.yaml")
        self.assertEqual(status, "path_exact")
        self.assertTrue(local.startswith("bios/Other/forkemu/"), local)

    def test_a_shortened_tail_in_a_foreign_tree_is_not_path_evidence(self):
        _local, status = self._resolve("otheremu", "assets/sounds/unlock.wav")
        self.assertNotEqual(status, "path_exact")


class AReleaseNamedAfterTheTree(unittest.TestCase):
    """cxbx-reloaded-2023 asks for EEPROM.bin. Its emulator's tree holds the
    decrypted dump Cxbx reads, xemu's aliases name the encrypted retail one
    eeprom.bin. The tree read as foreign to the suffixed profile, so the
    case-folded fallback served the encrypted dump."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        files = {}
        for rel, payload in (
            ("bios/Other/cxbx-reloaded/EEPROM.bin", b"decrypted"),
            ("bios/Microsoft/Xbox/eeprom.bin", b"encrypted"),
        ):
            path = Path(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {"path": rel, "name": path.name, "size": len(payload),
                           "sha1": sha1, "md5": hashlib.md5(payload).hexdigest(),
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "crc32": f"{len(files) + 1:08x}"}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _resolve(self, owner: str, name: str):
        entry = {"name": name, "source_profile": owner}
        return resolve_local_file(entry, self.db, {})

    def test_the_suffixed_release_reads_its_emulator_tree(self):
        local, _status = self._resolve("cxbx-reloaded-2023", "EEPROM.bin")
        self.assertEqual(local, "bios/Other/cxbx-reloaded/EEPROM.bin")

    def test_only_whole_leading_words_name_the_tree(self):
        """dolphin-mmjr2 is not a release of dolphin-mmjr: mmjr2 is one word."""
        from common import _owner_tokens

        self.assertNotIn("dolphinmmjr", _owner_tokens({"source_profile": "dolphin-mmjr2"}))
        self.assertIn("cxbxreloaded", _owner_tokens({"source_profile": "cxbx-reloaded-2023"}))


class AnotherMachinesRomIsNotServed(unittest.TestCase):
    """np2pi reads a 16 KB PC-98 SCSI BIOS as scsi.rom. The only copy of that
    size was Clock Signal's Apple II SCSI card ROM, and the name step served
    it. Reads the repository."""

    def test_np2pi_does_not_receive_the_apple_ii_rom(self):
        import yaml

        from common import load_database

        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("database.json is absent")
        profile = yaml.safe_load((REPO_ROOT / "emulators" / "np2pi.yml").read_text())
        entry = next(f for f in profile["files"] if f.get("name") == "scsi.rom")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            db = load_database("database.json")
            local, _status = resolve_local_file(
                {**entry, "source_profile": "np2pi"}, db, {}, dest_hint=entry["path"]
            )
        finally:
            os.chdir(previous)
        self.assertFalse(local and "Clock Signal" in local, local)


if __name__ == "__main__":
    unittest.main()
