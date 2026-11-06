"""RomM accepts a firmware file on its size and any one declared hash.

Firmware.verify_file_hashes compares file_size_bytes first, then md5, sha1
or crc. verify and the builder compared the md5 alone: a fixture entry with a
mistyped md5 beside the right sha1 was refused here and accepted by RomM, and
a wrong declared size passed here and failed there.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import json
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from nativemode import HASH_RULES, SIZE_AND_ANY_HASH  # noqa: E402
from validation import baseline_verdict, frontend_digest_matches  # noqa: E402
from verify import Status, verify_entry_md5  # noqa: E402

PAYLOAD = b"romm firmware"


class SizeAndAnyHash(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self.addCleanup(scratch.cleanup)
        self.path = str(Path(scratch.name) / "fw.bin")
        Path(self.path).write_bytes(PAYLOAD)
        self.entry = {
            "name": "fw.bin",
            "size": len(PAYLOAD),
            "md5": hashlib.md5(PAYLOAD).hexdigest(),
            "sha1": hashlib.sha1(PAYLOAD).hexdigest(),
            "crc32": f"{zlib.crc32(PAYLOAD):08x}",
        }

    def _accepts(self, **changes) -> bool:
        return frontend_digest_matches(
            {**self.entry, **changes}, self.path, "md5", SIZE_AND_ANY_HASH
        )

    def test_a_mistyped_md5_beside_the_right_sha1_is_accepted(self):
        self.assertTrue(self._accepts(md5="0" * 32))
        self.assertFalse(frontend_digest_matches({**self.entry, "md5": "0" * 32}, self.path, "md5"))

    def test_a_wrong_declared_size_is_refused_whatever_the_hashes(self):
        self.assertFalse(self._accepts(size=len(PAYLOAD) + 1))

    def test_an_entry_without_a_size_never_verifies(self):
        entry = dict(self.entry)
        del entry["size"]
        self.assertFalse(frontend_digest_matches(entry, self.path, "md5", SIZE_AND_ANY_HASH))

    def test_no_hash_matching_is_refused(self):
        self.assertFalse(self._accepts(md5="0" * 32, sha1="0" * 40, crc32="00000000"))

    def test_the_builder_refuses_a_hash_exact_file_at_the_wrong_size(self):
        entry = {**self.entry, "size": 1}
        _status, refusal = baseline_verdict(entry, self.path, "md5_exact", "md5", SIZE_AND_ANY_HASH)
        self.assertIsNotNone(refusal)
        _status, refusal = baseline_verdict(entry, self.path, "md5_exact", "md5")
        self.assertIsNone(refusal)

    def test_verify_reads_the_same_rule(self):
        accepted = verify_entry_md5({**self.entry, "md5": "0" * 32}, self.path, "hash_mismatch",
                                    SIZE_AND_ANY_HASH)
        self.assertEqual(accepted["status"], Status.OK)
        refused = verify_entry_md5({**self.entry, "size": 1}, self.path, "md5_exact",
                                   SIZE_AND_ANY_HASH)
        self.assertEqual(refused["status"], Status.UNTESTED)


class TheRuleIsDeclared(unittest.TestCase):
    def test_romm_declares_it_and_the_schema_knows_it(self):
        import yaml

        romm = yaml.safe_load((REPO_ROOT / "platforms" / "romm.yml").read_text(encoding="utf-8"))
        self.assertEqual(romm.get("hash_rule"), SIZE_AND_ANY_HASH)
        schema = json.loads((REPO_ROOT / "schemas" / "platform.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(tuple(schema["properties"]["hash_rule"]["enum"]), HASH_RULES)


if __name__ == "__main__":
    unittest.main()
