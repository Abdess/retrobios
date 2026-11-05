"""verify counts a release asset the cache lacks as an online build does.

verify never downloads. A declaration served by a release asset of the
large-files release, absent from bios/ and from .cache/large/, read as
missing there while an online build fetched it and packed it, so the two
disagreed on every checkout without the cache (CI among them). The
database record of the registered path says whether the asset answers the
declaration. Under --offline the builder fetches nothing, and verify then
counts the file missing as before.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
import packresolve  # noqa: E402
from verify import Status, verify_platform  # noqa: E402

PAYLOAD = b"a firmware image the repository does not commit"
SHA1 = hashlib.sha1(PAYLOAD).hexdigest()
REGISTERED = ["bios/Big/big.bin"]


class ReleaseAssetNotCached(unittest.TestCase):
    mode = "existence"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp")
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        for d in ("emulators", "platforms", "bios/Big"):
            Path(d).mkdir(parents=True)
        # Indexed by the database, gitignored, so absent from a checkout.
        files = {SHA1: {
            "path": REGISTERED[0], "name": "big.bin", "size": len(PAYLOAD),
            "sha1": SHA1, "md5": hashlib.md5(PAYLOAD).hexdigest(),
            "sha256": hashlib.sha256(PAYLOAD).hexdigest(), "crc32": "00000001",
        }}
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        self.config = {
            "platform": "Big", "verification_mode": self.mode,
            "systems": {"sys": {"files": [{
                "name": "big.bin", "destination": "big.bin", "required": True,
                "sha1": SHA1, "md5": hashlib.md5(PAYLOAD).hexdigest(),
            }]}},
        }
        Path("platforms/big.yml").write_text(yaml.dump(self.config))
        Path("platforms/_registry.yml").write_text(
            yaml.dump({"platforms": {"big": {"status": "active"}}})
        )
        common._platform_config_cache.clear()
        common._emulator_profiles_cache.clear()
        patches = (
            mock.patch("largefiles.load_registered_paths", return_value=REGISTERED),
            mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(packresolve.set_offline, False)
        packresolve.set_offline(False)

    def tearDown(self):
        common._platform_config_cache.clear()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _entry(self) -> dict:
        report = verify_platform(self.config, self.db, "emulators", {})
        return next(d for d in report["details"] if d["name"] == "big.bin")

    def test_counted_as_fetched_when_the_pack_is_built(self):
        entry = self._entry()
        self.assertEqual(entry["status"], Status.OK)
        self.assertEqual(entry["release_asset"], REGISTERED[0])

    def test_its_path_is_a_pack_destination(self):
        """The pack holds the fetched file at its path: absent from
        pack_destinations, step 5 reported it 'pack only'."""
        report = verify_platform(self.config, self.db, "emulators", {})
        self.assertIn("big.bin", report["pack_destinations"])

    def test_offline_counts_it_missing(self):
        packresolve.set_offline(True)
        self.assertEqual(self._entry()["status"], Status.MISSING)

    def test_an_asset_with_other_content_is_not_counted(self):
        self.config["systems"]["sys"]["files"][0]["sha1"] = "0" * 40
        self.assertEqual(self._entry()["status"], Status.MISSING)

    def test_the_online_build_packs_it(self):
        cache = Path("cache/big.bin")
        cache.parent.mkdir()
        cache.write_bytes(PAYLOAD)
        with mock.patch.object(
            packresolve, "fetch_large_file", return_value=str(cache)
        ):
            zip_path = builder.generate_pack(
                "big", "platforms", self.db, "bios", "out",
                emulators_dir="emulators", emu_profiles={}, offline=False,
            )
        with zipfile.ZipFile(zip_path) as zf:
            self.assertEqual(zf.read("big.bin"), PAYLOAD)
        self.assertEqual(self._entry()["status"], Status.OK)


class ReleaseAssetNotCachedMd5(ReleaseAssetNotCached):
    mode = "md5"


class OfflinePipelineVerifiesOffline(unittest.TestCase):
    """The offline pipeline builds packs without release assets: its verify
    step has to count them the same way, or step 5 compares two answers."""

    def test_verify_step_gets_offline(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text()
        block = source[source.index("verify_cmd = ["):source.index("ok, verify_output = run(")]
        self.assertIn('verify_cmd.append("--offline")', block)


if __name__ == "__main__":
    unittest.main()
