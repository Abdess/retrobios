"""A file's readers are the entries that resolve to it, not those sharing its name.

The site joined database files to emulators and platforms by bare name. The
collection holds the pak0.pk3 of Quake III and of Enemy Territory, and each page
named every engine that reads a pak0.pk3 as a reader of both, which is the
homonym tests/test_game_data_homonyms.py forbids the resolver to serve.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from cross_reference import FileConsumers, entry_target  # noqa: E402
from generate_site import generate_system_page  # noqa: E402

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


class PlatformReadersResolveAsThePack(unittest.TestCase):
    """A hashless declaration resolves without its destination in the
    builder, the manifest and verify. The site passed the destination and
    credited RetroBat with another revision of its 63 mame/hash lists than
    the one its manifest installs."""

    def test_the_declared_file_is_the_one_the_pack_ships(self):
        from packresolve import resolve_declaration

        first, first_entry = _collected("bios/Arcade/MAME/hash/apfm1000.xml", b"one")
        other, other_entry = _collected("bios/Other/mame/hash/apfm1000.xml", b"two")
        db = {
            "files": {first: first_entry, other: other_entry},
            "indexes": {
                "by_name": {"apfm1000.xml": [first, other]},
                "by_path_suffix": {"mame/hash/apfm1000.xml": [other],
                                   "Other/mame/hash/apfm1000.xml": [other],
                                   "MAME/hash/apfm1000.xml": [first],
                                   "Arcade/MAME/hash/apfm1000.xml": [first]},
            },
        }
        entry = {"name": "apfm1000.xml", "destination": "mame/hash/apfm1000.xml"}
        shipped, _status = resolve_declaration(entry, db, "bios", None, None, None,
                                               offline=True)
        consumers = FileConsumers(db, data_dir_registry={})
        consumers.add_platforms({"plat": {"systems": {"s": {"files": [entry]}}}})
        self.assertEqual(shipped, first_entry["path"])
        self.assertEqual(consumers.platforms, {first: {"plat"}})


class ReadersFollowTheDataTrees(unittest.TestCase):
    """Dolphin names codehandler.bin without a hash. The pack takes it from
    data/dolphin-sys, and the site credited Dolphin and Triforce with the
    Dolphin-MMJR copy, another revision, because the consumers resolved
    without the data trees."""

    def setUp(self):
        import os

        self._previous = os.getcwd()
        self._tree = tempfile.TemporaryDirectory()
        root = Path(self._tree.name)
        fork = root / "bios" / "Other" / "dolphin-mmjr" / "codehandler.bin"
        fork.parent.mkdir(parents=True)
        fork.write_bytes(b"dolphin-mmjr codehandler")
        own = root / "data" / "dolphin-sys" / "codehandler.bin"
        own.parent.mkdir(parents=True)
        own.write_bytes(b"dolphin codehandler")
        self.fork_sha1 = hashlib.sha1(fork.read_bytes()).hexdigest()
        self.db = {
            "files": {self.fork_sha1: {
                "name": "codehandler.bin", "sha1": self.fork_sha1,
                "path": "bios/Other/dolphin-mmjr/codehandler.bin",
                "md5": hashlib.md5(fork.read_bytes()).hexdigest(),
                "size": fork.stat().st_size,
            }},
            "indexes": {
                "by_name": {"codehandler.bin": [self.fork_sha1]},
                "by_md5": {}, "by_path_suffix": {},
            },
        }
        self.registry = {"dolphin-sys": {"local_cache": str(own.parent)}}
        self.profiles = {"dolphin": {"type": "standalone + libretro", "files": [
            {"name": "codehandler.bin", "path": None, "mode": "libretro"},
        ]}}
        os.chdir(root)

    def tearDown(self):
        import os

        from common import forget_data_dir_index

        os.chdir(self._previous)
        forget_data_dir_index()
        self._tree.cleanup()

    def _readers(self, registry: dict) -> set[str]:
        consumers = FileConsumers(self.db, data_dir_registry=registry)
        consumers.add_emulators(self.profiles)
        return consumers.emulators.get(self.fork_sha1, set())

    def test_dolphin_does_not_read_the_mmjr_copy(self):
        self.assertNotIn("dolphin", self._readers(self.registry))

    def test_without_the_data_trees_the_name_step_takes_the_fork_copy(self):
        """The case above has to reach the data trees to pass: resolved
        without them, the name alone hands Dolphin the fork's copy."""
        self.assertIn("dolphin", self._readers({}))


class TheDestinationBasenameComesLast(unittest.TestCase):
    """melonDS Nightly reads dsi_nand.bin at dsi/nand.bin. With the DSi image
    absent from the checkout and only its variant left, the destination's
    basename let the Wii nand.bin outrank the entry's own name, and the site
    named melonDS Nightly a reader of the Wii NAND."""

    def setUp(self):
        self._tree = tempfile.TemporaryDirectory()
        root = Path(self._tree.name)
        files = {}
        by_name: dict[str, list[str]] = {}
        for rel, payload in (
            ("bios/Nintendo/Wii/nand.bin", b"wii nand"),
            ("bios/Nintendo/Nintendo DSi/.variants/dsi_nand.bin.8b79a73c", b"dsi nand"),
        ):
            path = root / rel
            path.parent.mkdir(parents=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            name = "dsi_nand.bin" if "dsi_nand" in rel else path.name
            files[sha1] = {"name": name, "sha1": sha1, "path": str(path),
                           "md5": hashlib.md5(payload).hexdigest(), "size": len(payload)}
            by_name.setdefault(name, []).append(sha1)
        self.wii = hashlib.sha1(b"wii nand").hexdigest()
        self.dsi = hashlib.sha1(b"dsi nand").hexdigest()
        self.db = {"files": files, "indexes": {
            "by_name": by_name, "by_md5": {}, "by_path_suffix": {}}}
        self.entry = {"name": "dsi_nand.bin", "path": "dsi/nand.bin", "agnostic": True}

    def tearDown(self):
        self._tree.cleanup()

    def test_the_resolver_keeps_the_entry_name(self):
        from common import resolve_local_file

        path, status = resolve_local_file(
            {**self.entry, "source_profile": "melonds-nightly"}, self.db,
            dest_hint=self.entry["path"],
        )
        self.assertEqual((path, status), (self.db["files"][self.dsi]["path"], "name_exact"))

    def test_the_wii_nand_has_no_ds_reader(self):
        consumers = FileConsumers(self.db, data_dir_registry={})
        consumers.add_emulators({"melonds-nightly": {"type": "standalone", "files": [self.entry]}})
        self.assertEqual(consumers.emulators.get(self.wii), None)
        self.assertEqual(consumers.emulators.get(self.dsi), {"melonds-nightly"})

    def test_a_descriptive_name_still_reaches_the_basename(self):
        """name: "MDA font ROM", path: "mda.rom" is the case the basename step serves."""
        from common import resolve_local_file

        path, _ = resolve_local_file(
            {"name": "Wii NAND image", "path": "nand.bin"}, self.db, dest_hint="nand.bin",
        )
        self.assertEqual(path, self.db["files"][self.wii]["path"])


class EveryReaderIsTheEmulatorPackFile(unittest.TestCase):
    """Each emulator FileConsumers credits with a file is one whose entry the
    emulator pack resolves to that file: the same entry fields (archive
    members, owner), destination hint, ZIP index and data trees. The pairing
    omitted the archive members, and gngeopi and neo-emu were credited with
    the MAME neogeo.zip while their pack carries the one holding the ROMs
    they open."""

    def test_pairings_agree_with_the_resolver(self):
        import json
        import os

        from common import (
            build_zip_contents_index, load_data_dir_registry,
            load_emulator_profiles, resolve_local_file,
        )

        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json absent")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = json.loads(db_path.read_text(encoding="utf-8"))
        zips = build_zip_contents_index(db)
        registry = load_data_dir_registry(str(REPO_ROOT / "platforms"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        consumers = FileConsumers(db, zips, registry)
        consumers.add_emulators(profiles)
        sha1_by_path = {e["path"]: s for s, e in db["files"].items()}

        expected: set[tuple[str, str]] = set()
        from_trees: set[tuple[str, str]] = set()
        for name, profile in profiles.items():
            if profile.get("type") == "alias":
                continue
            files = profile.get("files") or []
            for entry in files:
                if not isinstance(entry, dict) or not entry.get("name"):
                    continue
                members = consumers.directory_members(entry)
                if members:
                    from_trees |= {(sha1, name) for sha1 in members.values()}
                    continue
                # A ROM read inside an archive is the archive, as the
                # emulator pack resolves it (archive_entry).
                target, dest = entry_target(entry, files)
                path, status = resolve_local_file(
                    {**target, "source_profile": name},
                    db, zips, dest_hint=dest,
                    data_dir_registry=registry,
                )
                if path and status not in ("not_found", "hash_mismatch"):
                    sha1 = sha1_by_path.get(path)
                    if sha1:
                        expected.add((sha1, name))
        credited = {
            (sha1, name) for sha1, names in consumers.emulators.items() for name in names
        }
        self.assertEqual(sorted(expected - credited), [])
        self.assertEqual(sorted(credited - expected - from_trees), [])


def tearDownModule():
    _TMP.cleanup()


if __name__ == "__main__":
    unittest.main()
