"""A variant is another revision of its primary, and its catalog name says so.

The LaserActive PAC-S1 v1.05 variant was the WonderMega v1.00W boot ROM:
No-Intro and TOSEC both named it, and the name shared no word with the
path it was filed under. A revision of the same machine always shares one
(machine, maker or file stem). Reads the repository: skips without the
database.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_GENERIC = {
    "bios", "japan", "europe", "world", "boot", "firmware", "version",
    "system", "rom", "bin", "usa", "the",
}


def _words(text: str) -> set[str]:
    return {
        w for w in re.split(r"[^a-z0-9]+", text.lower())
        if len(w) >= 3 and not w.isdigit() and w not in _GENERIC
    }


def catalog_words(provenance: dict) -> set[str]:
    words: set[str] = set()
    for record in provenance.values():
        for key in ("name", "description", "dat"):
            words |= _words(record.get(key, ""))
    return words


class VariantsMatchTheirCatalogName(unittest.TestCase):
    def test_the_rule_catches_the_wondermega_case(self):
        provenance = {
            "no-intro": {"dat": "Sega - Mega Drive - Genesis",
                         "name": "[BIOS] WonderMega (Japan) (En).md"},
            "tosec": {"dat": "Sega Mega-CD & Sega CD - Firmware",
                      "name": "Wondermega v1.00W (1992-02-06)(Sega)(JP)(en).bin"},
        }
        old = "bios/Pioneer/LaserActive/.variants/[BIOS] LaserActive PAC-S1 (Japan) (v1.05).bin.d21fe71d"
        self.assertFalse(_words(old) & catalog_words(provenance))
        self.assertTrue(
            _words("bios/Sega/Mega CD/[BIOS] WonderMega (Japan) (En).bin")
            & catalog_words(provenance)
        )

    def test_every_catalogued_variant(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        files = json.loads(db_path.read_text(encoding="utf-8"))["files"]
        foreign = [
            entry["path"]
            for entry in files.values()
            if "/.variants/" in entry["path"] and entry.get("provenance")
            and not _words(entry["path"]) & catalog_words(entry["provenance"])
        ]
        self.assertEqual(foreign, [])


if __name__ == "__main__":
    unittest.main()
