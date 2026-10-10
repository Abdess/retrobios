"""A bundled file is identified by its bytes, not its name.

ZEsarUX ships ace.rom and a patched alternate_roms/ace.rom, Azahar a default
keys.txt, ARMSX2 an OpenGL and a Vulkan cas.glsl. Declared without a hash,
each resolved by its bare name to whatever shared it: the patched ROM at the
original's slot, the Wii U disc keys at the 3DS key slot, the OpenGL shader
at the Vulkan one. An entry with a hash resolves by content first.

529 bundled entries still carry neither a hash nor `unsourceable:`. The
count per profile may only fall: a new entry is written with the hash of
the file the emulator ships.
"""

from __future__ import annotations

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
    "aethersx2": 1,
    "altirra": 2,
    "arcadeflashweb": 8,
    "armsx2": 58,
    "ax360e": 2,
    "bluemsx": 14,
    "c64-emu": 8,
    "cdogs": 16,
    "citra-mmj": 9,
    "drastic": 10,
    "eka2l1": 89,
    "emucorev": 1,
    "emucorex": 23,
    "epsxe": 2,
    "fpse": 7,
    "fpse-ng": 7,
    "future-pinball": 18,
    "future-pinball-fploader": 54,
    "gba-emu": 1,
    "hakux": 1,
    "hcl": 3,
    "hurrican": 1,
    "idtech4a++": 1,
    "ikemen": 32,
    "ines": 2,
    "j2me-loader": 14,
    "jl-mod": 22,
    "kemulator": 4,
    "mastergear": 2,
    "mfme": 58,
    "msx-emu": 10,
    "my-boy": 1,
    "neo-emu": 3,
    "nethersx2": 2,
    "nethersx2-turnip": 2,
    "nethersx2-turnip-classic": 2,
    "nuance": 1,
    "pcee2": 1,
    "pcsx2": 1,
    "project64": 9,
    "sixtyforce": 5,
    "skyline": 9,
    "ssf": 1,
    "supermodel-dojo": 4,
    "x1-box": 1,
    "xendroid": 1,
    "xm6pro68k": 2,
    "yaps2": 1,
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


class TheFixedEntriesGetTheirOwnBytes(unittest.TestCase):
    CASES = (
        ("azahar", "sysdata/keys.txt"),
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
                local, _status = resolve_local_file(
                    {**entry, "source_profile": profile}, db, dest_hint=destination
                )
                self.assertIsNotNone(local)
                self.assertEqual(
                    hashlib.sha1((REPO_ROOT / local).read_bytes()).hexdigest(),
                    entry["sha1"],
                )


if __name__ == "__main__":
    unittest.main()
