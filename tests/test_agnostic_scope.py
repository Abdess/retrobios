"""What a filename-agnostic core's scan may emit, and where.

yaps2 declares its BIOS under pcsx2/bios/ with a free name and its shaders,
sounds and fonts under pcsx2/resources/ with fixed names. Every sized entry
seeded the scan and every find went to the pack root: 189 resources landed
flat in RetroArch's system/, and the BIOS the core reads from pcsx2/bios/
was not where it looks.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class AgnosticScan(unittest.TestCase):
    def test_only_the_bios_directory_seeds_and_finds_keep_its_folder(self):
        from packextras import _agnostic_scan_extras

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            files, by_name = {}, {}
            for path, data in (
                ("bios/PS2/scph1.bin", b"a" * 64),
                ("bios/PS2/scph2.bin", b"b" * 64),
                ("bios/PS2/res/message.wav", b"c" * 8),
                ("bios/PS2/res/other.wav", b"d" * 8),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(data)
                sha1 = hashlib.sha1(data).hexdigest()
                name = path.rsplit("/", 1)[1]
                files[sha1] = {"path": path, "name": name, "size": len(data), "sha1": sha1}
                by_name.setdefault(name, []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {}, "by_crc32": {},
                                              "by_path_suffix": {}}}
            profile = {"emulator": "Y", "type": "libretro", "bios_mode": "agnostic",
                       "bios_directory": "pcsx2/bios/", "systems": ["ps2"], "files": [
                           {"name": "scph1.bin", "path": "pcsx2/bios/scph1.bin", "size": 64},
                           {"name": "message.wav", "path": "pcsx2/resources/message.wav", "size": 8},
                       ]}
            extras = _agnostic_scan_extras({"y": profile}, {"y"}, db, by_name, set(), "")
            self.assertEqual(sorted(e["destination"] for e in extras),
                             ["pcsx2/bios/scph1.bin", "pcsx2/bios/scph2.bin"])


    def test_a_placeholder_scans_the_folder_another_profile_proves(self):
        """LRPS2 and PCEE2 name their BIOS <bios>.bin, which resolves nowhere.

        On RetroArch yaps2 anchored pcsx2/bios/ for them. On Batocera no
        other libretro PS2 core runs, and the pack held nothing there. The
        folder where another profile of the system resolves a hashed dump of
        that shape is the evidence, that folder only.
        """
        from packextras import _agnostic_scan_extras

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            files, by_name = {}, {}
            for path, data in (
                ("bios/PS2/scph1.bin", b"a" * 64),
                ("bios/PS2/scph2.bin", b"b" * 64),
                ("bios/PS2/scph2.bin.rom1", b"r" * 8),
                ("bios/PS2/scph1.nvm", b"n" * 8),
                ("bios/PS2/.variants/scph3.bin", b"e" * 64),
                ("bios/PS2/DVD/dvd.bin", b"f" * 64),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(data)
                sha1 = hashlib.sha1(data).hexdigest()
                name = path.rsplit("/", 1)[1]
                files[sha1] = {"path": path, "name": name, "size": len(data), "sha1": sha1}
                by_name.setdefault(name, []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {}, "by_crc32": {},
                                              "by_path_suffix": {}}}
            placeholders = {"emulator": "L", "type": "libretro", "bios_mode": "agnostic",
                            "bios_directory": "pcsx2/bios/", "systems": ["ps2"], "files": [
                                {"name": "<bios>.bin", "found_by": "content",
                                 "path": "pcsx2/bios/<bios>.bin", "min_size": 32, "max_size": 64},
                                {"name": "<bios>.rom1", "path": "pcsx2/bios/<bios>.rom1"},
                                {"name": "<bios>.nvm", "path": "pcsx2/bios/<bios>.nvm", "size": 8},
                            ]}
            pinned = {"emulator": "S", "type": "standalone", "systems": ["ps2"], "files": [
                {"name": "scph1.bin", "size": 64,
                 "sha1": hashlib.sha1(b"a" * 64).hexdigest()},
            ]}
            extras = _agnostic_scan_extras(
                {"l": placeholders, "s": pinned}, {"l"}, db, by_name, set(), "")
            self.assertEqual(sorted(e["destination"] for e in extras), [
                "pcsx2/bios/scph1.bin", "pcsx2/bios/scph1.nvm", "pcsx2/bios/scph2.bin",
                "pcsx2/bios/scph2.bin.rom1",
            ])
            self.assertTrue(all(e["source_profile"] == "l" for e in extras))
            # An image the platform already ships there still gets its
            # companion: RetroBat lists pcsx2/bios/scph39001.bin itself.
            shipped = {"pcsx2/bios/scph1.bin"}
            extras = _agnostic_scan_extras(
                {"l": placeholders, "s": pinned}, {"l"}, db, by_name, shipped, "")
            self.assertIn("pcsx2/bios/scph1.nvm", {e["destination"] for e in extras})
            # Nothing proves the folder: nothing is scanned.
            self.assertEqual(
                _agnostic_scan_extras({"l": placeholders}, {"l"}, db, by_name, set(), ""), [])


class OneContentTwoPaths(unittest.TestCase):
    """A standalone copy reads one file the manifest carries at two paths.

    The libretro PS2 cores put DuckStation's ps2_scph50006.bin under
    pcsx2/bios/ beside the BIOS root copy, and the copy into DuckStation's
    folder was dropped as ambiguous on Batocera, Recalbox and RetroBat.
    """

    DUCK = {"data_root": {"linux": {"path": "~/.local/share/duckstation", "source_ref": "x"}},
            "files": [{"name": "ps2_scph50006.bin", "standalone_path": "bios/ps2_scph50006.bin"}]}

    def _copies(self, entries):
        from generate_pack import _profile_copies

        return _profile_copies({"duckstation": self.DUCK}, list(entries), [], entries)

    def test_same_bytes_take_the_copy_that_serves_the_emulator(self):
        (copy,) = self._copies({
            "pcsx2/bios/ps2_scph50006.bin": {"sha1": "a", "cores": ["lrps2"]},
            "ps2_scph50006.bin": {"sha1": "a", "cores": ["duckstation", "pcsx2"]},
        })
        self.assertEqual(copy["file"], "ps2_scph50006.bin")

    def test_other_bytes_under_one_name_designate_nothing(self):
        self.assertEqual(self._copies({
            "pcsx2/bios/ps2_scph50006.bin": {"sha1": "a", "cores": ["lrps2"]},
            "ps2_scph50006.bin": {"sha1": "b", "cores": ["duckstation"]},
        }), [])


class BundledHashIsProof(unittest.TestCase):
    """A bundled file with a declared hash is served by those bytes or flagged.

    Four NetherSX2-Turnip entries named their own sha1, but the collection held
    NetherSX2's copies, which the builder shipped in their place.
    """

    def test_no_bundled_entry_resolves_to_other_bytes(self):
        if not (REPO_ROOT / "database.json").is_file():
            self.skipTest("no database.json")
        from common import (
            build_zip_contents_index,
            load_data_dir_registry,
            load_database,
            load_emulator_profiles,
            resolve_local_file,
        )

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = load_database("database.json")
        zips = build_zip_contents_index(db)
        registry = load_data_dir_registry("platforms")
        wrong = []
        for name, profile in sorted(load_emulator_profiles("emulators", skip_aliases=False).items()):
            for entry in profile.get("files") or []:
                # A bundled entry is packed only where a platform's package
                # leaves it out: there the copy has to be the declared bytes.
                if not entry.get("not_bundled_on") or entry.get("unsourceable"):
                    continue
                if not any(entry.get(k) for k in ("sha1", "md5", "sha256", "crc32")):
                    continue
                dest = entry.get("path") or entry.get("name") or ""
                local, status = resolve_local_file(
                    {**entry, "source_profile": name}, db, zips, dest_hint=dest,
                    data_dir_registry=registry)
                if local and status == "hash_mismatch":
                    wrong.append((name, dest, local))
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
