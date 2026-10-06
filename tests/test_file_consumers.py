"""A file's readers are the entries that resolve to it, not those sharing its name.

The site joined database files to emulators and platforms by bare name. The
collection holds the pak0.pk3 of Quake III and of Enemy Territory; each page
named every engine that reads a pak0.pk3 as a reader of both, which is the
homonym tests/test_game_data_homonyms.py forbids the resolver to serve.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cross_reference import FileConsumers
from generate_site import generate_system_page

_TMP = tempfile.TemporaryDirectory()
_ROOT = Path(_TMP.name)


def _collected(rel: str, payload: bytes) -> tuple[str, dict]:
    path = _ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    sha1 = hashlib.sha1(payload).hexdigest()
    return sha1, {"name": path.name, "sha1": sha1, "path": str(path),
                  "md5": hashlib.md5(payload).hexdigest(), "size": len(payload)}


Q3, _q3 = _collected("bios/id/Quake III/baseq3/pak0.pk3", b"quake iii demo")
ET, _et = _collected("bios/id/ET/etmain/pak0.pk3", b"enemy territory")
DB = {
    "files": {Q3: _q3, ET: _et},
    "indexes": {
        "by_name": {"pak0.pk3": [Q3, ET]},
        "by_md5": {_q3["md5"]: Q3, _et["md5"]: ET},
        "by_path_suffix": {
            "baseq3/pak0.pk3": [Q3], "Quake III/baseq3/pak0.pk3": [Q3],
            "etmain/pak0.pk3": [ET], "ET/etmain/pak0.pk3": [ET],
        },
    },
}
PROFILES = {
    "ioquake3": {"type": "standalone", "files": [
        {"name": "pak0.pk3", "path": "baseq3/pak0.pk3", "sha1": Q3}]},
    "etlegacy": {"type": "standalone", "files": [
        {"name": "pak0.pk3", "path": "etmain/pak0.pk3", "sha1": ET}]},
    "named_only": {"type": "standalone", "files": [
        {"name": "pak0.pk3", "path": "baseq3/pak0.pk3", "sha1": "3" * 40}]},
}


class ReadersResolve(unittest.TestCase):
    def setUp(self):
        self.consumers = FileConsumers(DB)
        self.consumers.add_emulators(PROFILES)
        self.consumers.add_platforms({
            "plat": {"systems": {"s": {"files": [
                {"name": "pak0.pk3", "destination": "etmain/pak0.pk3", "sha1": ET},
            ]}}},
        })

    def test_each_file_has_its_own_readers(self):
        self.assertEqual(self.consumers.emulators[Q3], {"ioquake3"})
        self.assertEqual(self.consumers.emulators[ET], {"etlegacy"})
        self.assertNotIn(Q3, self.consumers.platforms)
        self.assertEqual(self.consumers.platforms[ET], {"plat"})

    def test_the_system_page_names_them(self):
        consoles = {"Quake III": [DB["files"][Q3]], "ET": [DB["files"][ET]]}
        page = generate_system_page("id", consoles, self.consumers)
        q3 = page[page.index("## Quake III"):]
        et = page[page.index("## ET"):page.index("## Quake III")]
        self.assertIn("ioquake3", q3)
        self.assertNotIn("etlegacy", q3)
        self.assertIn("etlegacy", et)
        self.assertNotIn("ioquake3", et)


def tearDownModule():
    _TMP.cleanup()


if __name__ == "__main__":
    unittest.main()
