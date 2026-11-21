"""The other copies of an entry come from the primary's own .variants/ folder.

The campaign listed every .variants/ copy the database named after the entry,
so QUASI88's PC-88 font.rom was varied with a PC-98 font filed under the
same name in another system's folder.
"""

from __future__ import annotations

import tests

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from probes.entries import held_file, held_variants
from resolve.localfile import variant_copies


def _record(root: Path, path: str, body: bytes) -> tuple[str, dict]:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    sha1 = hashlib.sha1(body).hexdigest()
    return sha1, {"path": path, "name": target.name, "size": len(body),
                  "md5": hashlib.md5(body).hexdigest(), "crc32": "", "sha256": ""}


class VariantCopies(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        files = dict([
            _record(self.root, "bios/NEC/PC-88/font.rom", b"8" * 2048),
            _record(self.root, "bios/NEC/PC-88/.variants/font.rom.11111111", b"9" * 2048),
            _record(self.root, "bios/NEC/PC-88/.variants/font.rom.22222222", b"7" * 2048),
            _record(self.root, "bios/NEC/PC-98/font.rom", b"P" * 4096),
            _record(self.root, "bios/NEC/PC-98/.variants/font.rom.425a896a", b"Q" * 6144),
        ])
        self.db = {"files": files, "indexes": {
            "by_name": {"font.rom": list(files)}, "by_md5": {}, "by_crc32": {},
            "by_sha256": {}, "by_path_suffix": {},
        }}
        self.entry = {"name": "font.rom", "path": "quasi88/font.rom", "system": "nec-pc-88"}

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_only_the_primary_folder_answers(self) -> None:
        primary = self.root / "bios/NEC/PC-88/font.rom"
        self.assertEqual(
            held_variants(self.entry, self.db, self.root, primary),
            [self.root / "bios/NEC/PC-88/.variants/font.rom.11111111",
             self.root / "bios/NEC/PC-88/.variants/font.rom.22222222"],
        )

    def test_a_variant_primary_shares_its_folder(self) -> None:
        primary = self.root / "bios/NEC/PC-88/.variants/font.rom.11111111"
        self.assertEqual(
            held_variants(self.entry, self.db, self.root, primary),
            [self.root / "bios/NEC/PC-88/.variants/font.rom.22222222"],
        )

    def test_a_declared_hash_refuses_a_copy_it_contradicts(self) -> None:
        entry = {**self.entry, "md5": hashlib.md5(b"8" * 2048).hexdigest()}
        primary = self.root / "bios/NEC/PC-88/font.rom"
        self.assertEqual(held_variants(entry, self.db, self.root, primary), [])
        accepted = {**self.entry, "md5": [hashlib.md5(b"8" * 2048).hexdigest(),
                                          hashlib.md5(b"9" * 2048).hexdigest()]}
        self.assertEqual(len(held_variants(accepted, self.db, self.root, primary)), 1)

    def test_a_size_the_code_checks_refuses_a_copy(self) -> None:
        entry = {**self.entry, "size": 4096, "validation": ["size"]}
        self.assertEqual(
            variant_copies(entry, self.db, "bios/NEC/PC-98/font.rom"), [],
        )

    def test_held_file_and_variants_agree(self) -> None:
        primary = held_file(self.entry, self.db, self.root)
        self.assertIsNotNone(primary)
        assert primary is not None
        for copy in held_variants(self.entry, self.db, self.root, primary):
            self.assertEqual(copy.parent.parent, primary.parent)


if __name__ == "__main__":
    unittest.main()
