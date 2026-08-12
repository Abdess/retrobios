#!/usr/bin/env python3
"""The filename-agnostic scan and the tree it is allowed to walk.

Some emulators accept any filename for their BIOS, so the builder scans the
directory holding the candidates and packs what matches. The directory came
from a first-hit lookup by name, which is the one piece of evidence that can
land in another emulator's tree: five files in the collection answer to
GameIndex.yaml and one of them belongs to an Android package. The scan then
turned that single wrong match into every file beside it, flattened into the
BIOS root of platforms that do not run that emulator.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_pack as builder  # noqa: E402

SIZE = 1024


def _blob(root: Path, relative: str, filler: bytes) -> tuple[str, dict]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (filler * SIZE)[:SIZE]
    path.write_bytes(payload)
    sha1 = hashlib.sha1(payload).hexdigest()
    return sha1, {
        "path": str(path),
        "name": path.name,
        "size": SIZE,
        "sha1": sha1,
        "md5": hashlib.md5(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "crc32": "00000000",
    }


class AgnosticScanStaysInItsTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "emulators").mkdir()
        files: dict[str, dict] = {}
        by_name: dict[str, list[str]] = {}

        def add(relative: str, filler: bytes):
            sha1, record = _blob(self.root, relative, filler)
            files[sha1] = record
            by_name.setdefault(record["name"], []).append(sha1)

        # The system's own BIOS directory: three interchangeable dumps.
        add("bios/SystemA/boot.bin", b"A")
        add("bios/SystemA/boot-alt.bin", b"B")
        add("bios/SystemA/boot-jp.bin", b"C")
        # Another emulator's asset tree, holding a file of the same name and
        # a crowd of same-sized neighbours the scan must not claim.
        add("bios/Other/someapp/shared.bin", b"D")
        for n in range(20):
            add(f"bios/Other/someapp/icons/flag{n:02d}.bin", bytes([n or 1]))
        # The same filename on both sides, which is the whole difficulty:
        # rom1.bin is a PlayStation 2 ROM and a Roland SC-55 ROM.  The foreign
        # copy is indexed first, so a lookup by name reaches it first.
        add("bios/SystemA/shared.bin", b"E")

        self.db = {
            "files": files,
            "indexes": {
                "by_name": by_name,
                "by_md5": {r["md5"]: s for s, r in files.items()},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        self.config = {
            "platform": "Demo",
            "verification_mode": "existence",
            "cores": ["demo"],
            "base_destination": "",
            "systems": {},
        }
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def _write_profile(self, body: str):
        (self.root / "emulators" / "demo.yml").write_text(body)
        return common.load_emulator_profiles(str(self.root / "emulators"))

    def _scan(self, profiles):
        extras = builder._collect_emulator_extras(
            self.config, str(self.root / "emulators"), self.db, set(), "",
            profiles,
        )
        return [e for e in extras if e.get("agnostic_scan")]

    def test_it_collects_the_interchangeable_dumps(self):
        profiles = self._write_profile(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "bios_mode: agnostic\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: boot.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
            "  - name: boot-alt.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
        )
        found = {e["name"] for e in self._scan(profiles)}
        self.assertEqual(
            found, {"boot.bin", "boot-alt.bin", "boot-jp.bin", "shared.bin"}
        )

    def test_one_colliding_filename_does_not_import_a_foreign_tree(self):
        """shared.bin resolves into another emulator's directory by name."""
        profiles = self._write_profile(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "bios_mode: agnostic\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: boot.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
            "  - name: boot-alt.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
            "  - name: shared.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
        )
        found = {e["name"] for e in self._scan(profiles)}
        self.assertNotIn(
            "flag00.bin", found,
            "a single name match must not drag its neighbours into the pack",
        )
        self.assertEqual(
            found, {"boot.bin", "boot-alt.bin", "boot-jp.bin", "shared.bin"}
        )

    def test_an_entry_without_a_size_is_not_a_scan_seed(self):
        """No shape declared means the scan would take the whole directory."""
        profiles = self._write_profile(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "bios_mode: agnostic\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: shared.bin\n"
            "    system: demo-system\n"
            "  - name: boot.bin\n"
            "    system: demo-system\n"
        )
        self.assertEqual(self._scan(profiles), [])

    def test_what_the_scan_emits_is_named_by_content(self):
        """A filename alone sends the packing step back to a by-name lookup."""
        profiles = self._write_profile(
            "emulator: demo\n"
            "type: libretro\n"
            "display_name: Demo\n"
            "bios_mode: agnostic\n"
            "systems: [demo-system]\n"
            "cores: [demo]\n"
            "files:\n"
            "  - name: boot.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
            "  - name: boot-alt.bin\n"
            "    system: demo-system\n"
            "    size: 1024\n"
        )
        self.assertTrue(self._scan(profiles))
        for extra in self._scan(profiles):
            self.assertIn("sha1", extra, f"{extra['name']} carries no identity")
            path, status = common.resolve_local_file(extra, self.db)
            self.assertEqual(status, "sha1_exact")
            self.assertTrue(path.endswith(extra["name"]))


class PathTailBeatsABareName(unittest.TestCase):
    """A destination is written from the emulator's point of view.

    "pcsx2/resources/GameIndex.yaml" and the repo's
    "bios/Sony/PlayStation 2/resources/GameIndex.yaml" meet on a tail, not on
    the whole string, so the lookup fell through to the name and returned
    whichever namesake sorted first.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        files, by_name, by_suffix = {}, {}, {}
        for relative, filler in (
            ("bios/Sony/Console/resources/index.yaml", b"R"),
            ("bios/Other/app/assets/index.yaml", b"W"),
        ):
            sha1, record = _blob(self.root, relative, filler)
            files[sha1] = record
            by_name.setdefault("index.yaml", []).append(sha1)
            parts = relative.split("/")
            for start in range(len(parts)):
                by_suffix.setdefault("/".join(parts[start:]), []).append(sha1)
        self.db = {
            "files": files,
            "indexes": {
                "by_name": by_name,
                "by_md5": {},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": by_suffix,
            },
        }

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_tail_of_the_declared_path_decides(self):
        entry = {"name": "index.yaml", "path": "app/resources/index.yaml"}
        path, status = common.resolve_local_file(
            entry, self.db, dest_hint=entry["path"]
        )
        self.assertEqual(status, "path_exact")
        self.assertIn("Sony/Console/resources", path)

    def test_a_bare_name_is_never_reached_through_the_tail(self):
        """The tail stops above the filename: that is the weaker step."""
        entry = {"name": "index.yaml", "path": "nowhere/index.yaml"}
        _path, status = common.resolve_local_file(
            entry, self.db, dest_hint=entry["path"]
        )
        self.assertEqual(status, "name_exact")


if __name__ == "__main__":
    unittest.main()
