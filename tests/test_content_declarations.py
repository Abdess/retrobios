"""A platform declaration that a content-found core entry accepts by hash.

atari800 identifies its ROMs by CRC32 in the folder it scans. RetroDECK
lists Atari BASIC Rev A as ROM_BASIC_A, a name atari800 never opens, and
the profile answered it with a false alias. Settled by content instead, the
declared file meets the entry and the label is not shipped a second time.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from common import platform_declared_contents  # noqa: E402
from validation import declaration_settles  # noqa: E402

SHA1 = "70cdf57469a208528f78a14275837352e90e20f1"
DB = {
    "files": {SHA1: {"path": "bios/Atari/ROM_BASIC_A", "name": "ROM_BASIC_A", "sha1": SHA1,
                     "md5": "a4dc52536d526ecc51ea857b9fa2b90f", "crc32": "4bec4de2",
                     "size": 8192}},
    "indexes": {"by_md5": {"a4dc52536d526ecc51ea857b9fa2b90f": SHA1}},
}
CONFIG = {
    "base_destination": "",
    "systems": {"atari800": {"files": [
        {"name": "ROM_BASIC_A", "destination": "bios/ROM_BASIC_A",
         "md5": "a4dc52536d526ecc51ea857b9fa2b90f"},
    ]}},
}
ENTRY = {"name": "atari-basic-rev-a.rom", "found_by": "content", "crc32": "4bec4de2"}


class ContentDeclarationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contents = platform_declared_contents(CONFIG, DB)

    def test_the_declared_file_is_indexed_by_each_hash(self) -> None:
        self.assertEqual(self.contents["crc32:4bec4de2"], {""})
        self.assertEqual(self.contents[f"sha1:{SHA1}"], {""})

    def test_a_content_found_entry_is_met_by_its_hash(self) -> None:
        self.assertTrue(declaration_settles(
            ENTRY, ENTRY["name"], {}, ENTRY["name"], declared_contents=self.contents,
        ))

    def test_an_entry_opened_by_name_is_not(self) -> None:
        entry = {key: value for key, value in ENTRY.items() if key != "found_by"}
        self.assertFalse(declaration_settles(
            entry, entry["name"], {}, entry["name"], declared_contents=self.contents,
        ))

    def test_another_folder_is_not_the_one_scanned(self) -> None:
        self.assertFalse(declaration_settles(
            ENTRY, ENTRY["name"], {}, "atari800/" + ENTRY["name"],
            declared_contents=self.contents,
        ))


if __name__ == "__main__":
    unittest.main()
