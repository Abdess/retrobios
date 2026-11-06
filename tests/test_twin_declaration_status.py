"""A path declared twice, once unpinned and once with a pin the copy misses.

The unpinned declaration ships the file and the pinned one refuses it. The
builder wrote "excluded" over the shipped path, so its summary said "1 unsafe
excluded" for a file inside the archive, while verify counted it untested
and listed no exclusion. Both orders of the two systems are checked: the
refusal read first left "excluded" behind the file the second one ships.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import hashlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
from verify import Status, verify_platform  # noqa: E402

PAYLOAD = b"a console firmware"
SHA1 = hashlib.sha1(PAYLOAD).hexdigest()


class TwinDeclarationStatus(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        for d in ("emulators", "platforms", "bios/Twin"):
            Path(d).mkdir(parents=True)
        Path("bios/Twin/fw.bin").write_bytes(PAYLOAD)
        files = {SHA1: {
            "path": "bios/Twin/fw.bin", "name": "fw.bin", "size": len(PAYLOAD),
            "sha1": SHA1, "md5": hashlib.md5(PAYLOAD).hexdigest(),
            "sha256": hashlib.sha256(PAYLOAD).hexdigest(), "crc32": "00000001",
        }}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        Path("platforms/_registry.yml").write_text(
            yaml.dump({"platforms": {"twin": {"config": "twin.yml"}}})
        )
        self.addCleanup(common._platform_config_cache.clear)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _config(self, unpinned: str, pinned: str) -> dict:
        config = {
            "platform": "Twin", "verification_mode": "md5",
            "systems": {
                unpinned: {"files": [{"name": "fw.bin", "destination": "fw.bin"}]},
                pinned: {"files": [{
                    "name": "fw.bin", "destination": "fw.bin", "md5": "0" * 32,
                }]},
            },
        }
        Path("platforms/twin.yml").write_text(yaml.dump(config))
        common._platform_config_cache.clear()
        return config

    def _check(self, config: dict) -> None:
        record = builder.PackRecord()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            builder.generate_pack(
                "twin", "platforms", self.db, "bios", "out",
                emulators_dir="emulators", emu_profiles={}, record=record,
                offline=True,
            )
        self.assertIn("fw.bin", record.members)
        summary = out.getvalue()
        self.assertNotIn("excluded", summary.lower())
        self.assertIn("0/1 files OK, 1 untested", summary)
        self.assertIn("UNTESTED: fw.bin", summary)
        report = verify_platform(config, self.db, "emulators", {})
        self.assertEqual(report["status_counts"], {Status.UNTESTED: 1})
        self.assertEqual(report["excluded_files"], [])

    def test_unpinned_declaration_read_first(self):
        self._check(self._config("aaa", "bbb"))

    def test_pinned_declaration_read_first(self):
        self._check(self._config("zzz", "bbb"))


if __name__ == "__main__":
    unittest.main()
