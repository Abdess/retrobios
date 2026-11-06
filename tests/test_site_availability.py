"""An emulator page never shows an unsourceable entry as held.

The page resolved each entry by name without the `unsourceable:` check
cross_reference runs first: ioquake3's pak0.pk3 wore a green "in repo"
badge, served by the pak0.pk3 of another game, and 52 such entries read as
held across the site while the gaps page listed them as known absences.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import load_database  # noqa: E402
from generate_site import _availability_check, _file_badges  # noqa: E402

SHA1 = "a" * 40
DB = {
    "files": {SHA1: {"name": "pak0.pk3", "sha1": SHA1, "path": "bios/x/pak0.pk3"}},
    "indexes": {"by_name": {"pak0.pk3": [SHA1]}},
}


class UnsourceableIsNotHeld(unittest.TestCase):
    def test_a_homonym_does_not_stand_in(self):
        available = _availability_check(DB, set())
        self.assertTrue(available({"name": "pak0.pk3"}))
        self.assertFalse(available({"name": "pak0.pk3", "unsourceable": "retail data"}))

    def test_a_release_asset_is_held_only_when_collected(self):
        """storage: large_file said "in repo" for kenji-nx's user-picked
        firmware package, which the collection does not hold."""
        available = _availability_check(DB, set())
        self.assertFalse(available({"name": "<firmware>.zip", "storage": "large_file"}))
        self.assertTrue(available({"name": "pak0.pk3", "storage": "release"}))

    def test_the_badge_says_why(self):
        entry = {"name": "pak0.pk3", "unsourceable": "retail data"}
        badges = " ".join(_file_badges(entry, False))
        self.assertIn("unsourceable", badges)
        self.assertNotIn(">missing<", badges)
        self.assertNotIn("in repo", badges)

    def test_no_profile_entry_is_shown_held(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        available = _availability_check(load_database(str(db_path)), set())
        shown_held = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            shown_held.extend(
                f"{path.stem}: {entry['name']}"
                for entry in document.get("files") or []
                if isinstance(entry, dict) and entry.get("unsourceable")
                and available(entry)
            )
        self.assertEqual(shown_held, [])


class AHeldEntrySaysWhere(unittest.TestCase):
    """164 entries wore the "in repo" badge with no copy named: they are held
    as a ZIP member (zesarux's specmate.rom in spectrum_opus.zip) or in a
    data directory (Dolphin's fonts), which the database does not index."""

    def test_member_file_and_tree(self):
        import hashlib
        import tempfile
        import zipfile

        import generate_site
        from cross_reference import FileConsumers, held_copy

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            data, bios = Path(tmp) / "data", Path(tmp) / "bios"
            (data / "dolphin-sys" / "GC").mkdir(parents=True)
            (data / "dolphin-sys" / "GC" / "font_western.bin").write_bytes(b"font")
            (bios / "Arcade" / "MAME").mkdir(parents=True)
            archive = bios / "Arcade" / "MAME" / "spectrum_opus.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("specmate.rom", b"rom")
            roots = {"data_root": str(data), "bios_root": str(bios)}
            member = held_copy({"name": "specmate.rom",
                                "sha1": hashlib.sha1(b"rom").hexdigest()}, **roots)
            self.assertEqual(member, (str(archive), "specmate.rom"))
            # A declared hash the copy does not carry names no copy.
            self.assertIsNone(held_copy({"name": "specmate.rom", "sha1": "0" * 40}, **roots))
            self.assertEqual(held_copy({"name": "font_western.bin"}, **roots),
                             (str(data / "dolphin-sys/GC/font_western.bin"), ""))
            self.assertEqual(held_copy({"name": "GC/", "type": "directory"}, **roots),
                             (f"{(data / 'dolphin-sys/GC').as_posix()}/", ""))

        consumers = FileConsumers({"files": {"z" * 40: {
            "path": "bios/Arcade/MAME/spectrum_opus.zip"}}}, data_dir_registry={})
        line = generate_site._held_copy_line(
            ("bios/Arcade/MAME/spectrum_opus.zip", "specmate.rom"), consumers)
        self.assertEqual(line, "Collection copy: member `specmate.rom` of "
                         "[`bios/Arcade/MAME/spectrum_opus.zip`]"
                         "(../systems/arcade.md#sha1-zzzzzzzzzzzz)")
        line = generate_site._held_copy_line(("data/dolphin-sys/GC/font_western.bin", ""),
                                             consumers)
        self.assertEqual(line, "Collection copy: `GC/font_western.bin` in the "
                         "`dolphin-sys` data directory")


if __name__ == "__main__":
    unittest.main()
