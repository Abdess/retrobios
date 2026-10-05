"""One rule picks the held file that satisfies the emulator.

verify credited a variant found through the emulator's hashes while the
platform pack only searched by name and kept the platform's md5: the report
called ATARIOSB.ROM satisfied while the pack shipped the dump atari800
rejects, and `verify --emulator azahar` credited an otp.bin the emulator pack
never swapped in. Both sides now read find_validated_variant.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from validation import find_validated_variant  # noqa: E402


class FindValidatedVariant(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.bad = root / "rom.bin"
        self.bad.write_bytes(b"x" * 8)
        self.good = root / "other_name.bin"
        self.good.write_bytes(b"y" * 16)
        self.alias = root / "v" / "rom.bin"
        self.alias.parent.mkdir()
        self.alias.write_bytes(b"z" * 16)

        def entry(path: Path) -> tuple[str, dict]:
            data = path.read_bytes()
            sha1 = hashlib.sha1(data).hexdigest()
            return sha1, {"path": str(path), "name": path.name, "sha1": sha1,
                          "md5": hashlib.md5(data).hexdigest(), "size": len(data)}

        self.files = dict(entry(p) for p in (self.bad, self.good, self.alias))
        self.good_sha1 = hashlib.sha1(self.good.read_bytes()).hexdigest()
        self.db = {"files": self.files, "indexes": {
            "by_name": {"rom.bin": [s for s, e in self.files.items() if e["name"] == "rom.bin"]},
            "by_md5": {e["md5"]: s for s, e in self.files.items()},
        }}
        from validation import _build_validation_index

        self.by_hash = _build_validation_index({"emu": {"files": [
            {"name": "rom.bin", "validation": ["size", "sha1"], "size": 16,
             "sha1": self.good_sha1}]}})
        self.by_size = _build_validation_index({"emu": {"files": [
            {"name": "rom.bin", "validation": ["size"], "size": 16}]}})

    def test_a_dump_held_under_another_name_is_found_by_the_emulator_hash(self):
        found = find_validated_variant({"name": "rom.bin"}, self.db, str(self.bad), self.by_hash)
        self.assertEqual(found, str(self.good))

    def test_a_digest_platform_only_takes_a_value_its_entry_declares(self):
        alias_md5 = hashlib.md5(self.alias.read_bytes()).hexdigest()
        entry = {"name": "rom.bin", "md5": alias_md5}
        found = find_validated_variant(
            entry, self.db, str(self.bad), self.by_size, platform_digest="md5")
        self.assertEqual(found, str(self.alias))
        entry = {"name": "rom.bin", "md5": "0" * 32}
        self.assertIsNone(find_validated_variant(
            entry, self.db, str(self.bad), self.by_size, platform_digest="md5"))


class OneImplementation(unittest.TestCase):
    """The report and the builders call the same finder and keep no copy."""

    def test_no_module_carries_its_own_variant_search(self):
        for name in ("verify.py", "generate_pack.py", "packresolve.py"):
            source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertNotRegex(source, r"def _find_best_variant|def _find_candidate_satisfying_both")
        for name in ("verify.py", "generate_pack.py"):
            source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertGreaterEqual(len(re.findall(r"find_validated_variant\(", source)), 2
                                        if name == "generate_pack.py" else 3)


if __name__ == "__main__":
    unittest.main()
