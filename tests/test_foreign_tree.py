"""A file in another emulator's tree does not answer for this one.

bios/Other/<emulator>/ holds what that emulator ships. The path step took a
shortened tail that only NetherSX2's tree answered as proof for EmuCoreX's
unlock.wav, and broke a full-tail tie between EmuCoreX's GameIndex.yaml and
the system directory's copy by index order, serving a fork's game database
to upstream PCSX2.
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
