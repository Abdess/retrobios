"""A bundled file is identified by its bytes, not its name.

ZEsarUX ships ace.rom and a patched alternate_roms/ace.rom, Azahar a default
keys.txt, ARMSX2 an OpenGL and a Vulkan cas.glsl. Declared without a hash,
each resolved by its bare name to whatever shared it: the patched ROM at the
original's slot, the Wii U disc keys at the 3DS key slot, the OpenGL shader
at the Vulkan one. An entry with a hash resolves by content first.

135 bundled entries still carry neither a hash nor `unsourceable:`. The
count per profile may only fall, and the table records each fall: a new
entry is written with the hash of the file the emulator ships.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_database, resolve_local_file  # noqa: E402

UNIDENTIFIED = {
    "abuse": 3,
    "armsx2": 31,
    "ax360e": 1,
    "cdogs": 16,
    "citra-mmj": 3,
    "drastic": 5,
    # No pk3 shipped at the pin is the standalone entry's: the 1.3.x
    # releases carry 13fe8057, cc10cb70, d312ebbe and 8f4f0387, the buildbot
    # 653f7b37, the core embeds 1a3fd445. The .info md5 c011b428 was none.
    "ecwolf": 1,
    "emucorex": 5,
    "hcl": 3,
    "hurrican": 1,
    "idtech4a++": 1,
    "ikemen": 32,
    "jl-mod": 9,
    # librashader comes from SourMesen/librashader's nightly release, which
    # the build workflow downloads on every build.
    "mesence": 1,
    "msx-emu": 9,
    "nethersx2": 2,
    "nethersx2-turnip": 2,
    "nethersx2-turnip-classic": 2,
    "pcsx2": 1,
    "project64": 3,
    "ssf": 1,
    "supermodel-dojo": 3,
    "x1-box": 1,
    "xendroid": 1,
}


def _unidentified() -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in document.get("files") or []:
            if not isinstance(entry, dict) or not entry.get("bundled"):
                continue
            if entry.get("unsourceable") or entry.get("type") == "directory":
                continue
            if any(entry.get(key) for key in ("sha1", "md5", "sha256", "crc32")):
                continue
            counts[path.stem] = counts.get(path.stem, 0) + 1
    return counts


class BundledFilesCarryTheirIdentity(unittest.TestCase):
    def test_no_profile_adds_an_unidentified_bundled_file(self):
        grown = {
            name: (count, UNIDENTIFIED.get(name, 0))
            for name, count in _unidentified().items()
            if count > UNIDENTIFIED.get(name, 0)
        }
        self.assertEqual(grown, {}, "bundled entries need the shipped file's hash")

    def test_the_table_records_every_fall(self):
        # A baseline above the real count lets that profile grow back unseen:
        # j2me-loader kept 14 after its 18 bundled files were all identified.
        self.assertEqual(_unidentified(), UNIDENTIFIED)


class TheFixedEntriesGetTheirOwnBytes(unittest.TestCase):
    CASES = (
        ("azahar", "Azahar/sysdata/keys.txt"),
        ("azaharplus", "sysdata/keys.txt"),
        ("zesarux", "ace.rom"),
        ("zesarux", "alternate_roms/ace.rom"),
        ("zesarux", "coleco.rom"),
        ("zesarux", "trdos.rom"),
        ("armsx2", "pcsx2/resources/shaders/vulkan/cas.glsl"),
    )

    def test_each_resolves_to_the_declared_hash(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        db = load_database(str(db_path))
        for profile, destination in self.CASES:
            with self.subTest(profile=profile, destination=destination):
                document = yaml.safe_load(
                    (REPO_ROOT / "emulators" / f"{profile}.yml").read_text(encoding="utf-8")
                )
                entry = next(
                    e for e in document["files"]
                    if (e.get("path") or e["name"]) == destination
                )
                local, status = resolve_local_file(
                    {**entry, "source_profile": profile}, db, dest_hint=destination
                )
                if entry.get("bundled") and entry["sha1"] not in db["files"]:
                    # A bundled copy nothing else needs left the collection:
                    # no other bytes may then claim to be it.
                    self.assertIn(status, ("not_found", "hash_mismatch"))
                    continue
                self.assertIsNotNone(local)
                self.assertEqual(
                    hashlib.sha1((REPO_ROOT / local).read_bytes()).hexdigest(),
                    entry["sha1"],
                )


if __name__ == "__main__":
    unittest.main()
