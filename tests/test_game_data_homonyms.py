"""Game data laid out in a directory is not served by another game's file.

Engines read generic names from their own tree: `pak0.pak` is Quake II's
under `baseq2/` and Half-Life's under `valve/`. The name step of the resolver
ignores directories, so once one of them is collected every other entry of
that name resolves to it and a pack ships the wrong game's bytes under the
right path. The collection stores such a file under the tail the engine
reads (`.../baseq2/pak0.pak`), which lets its own entry resolve by path; an
entry that only reaches the same file by its bare name is a homonym, and
carries `unsourceable:` until its own bytes are held.
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    build_zip_contents_index,
    load_data_dir_registry,
    load_database,
    load_emulator_profiles,
    resolve_local_file,
)


def homonyms(claims: list[tuple[str, str, str, str]]) -> list[tuple[str, str, str]]:
    """(profile, destination, file) for name-only claims on a file that
    another entry reaches by its path.

    claims: (profile, destination, status, local file).
    """
    by_path = {local for _, _, status, local in claims if status == "path_exact"}
    found = []
    for profile, dest, status, local in claims:
        if status != "name_exact" or local not in by_path:
            continue
        if local.casefold().endswith("/" + dest.casefold()):
            continue
        if local.rsplit("/", 1)[-1].casefold() != dest.rsplit("/", 1)[-1].casefold():
            # Reached through an alias: the profile says the two are one file.
            continue
        found.append((profile, dest, local))
    return sorted(found)


class HomonymRule(unittest.TestCase):
    def test_a_name_claim_on_a_file_another_entry_reaches_by_path_is_named(self):
        claims = [
            ("quake2", "baseq2/pak0.pak", "path_exact", "bios/Q2/baseq2/pak0.pak"),
            ("halflife", "valve/pak0.pak", "name_exact", "bios/Q2/baseq2/pak0.pak"),
        ]
        self.assertEqual(
            homonyms(claims), [("halflife", "valve/pak0.pak", "bios/Q2/baseq2/pak0.pak")]
        )

    def test_a_file_only_ever_found_by_name_is_not_judged(self):
        claims = [
            ("mame2003", "mame2003/cheat.dat", "name_exact", "bios/Arcade/cheat.dat"),
            ("mame2010", "mame2010/cheat.dat", "name_exact", "bios/Arcade/cheat.dat"),
        ]
        self.assertEqual(homonyms(claims), [])

    def test_a_declared_alias_is_the_profile_speaking(self):
        claims = [
            ("m", "crosshair/cross7.png", "path_exact", "bios/m/crosshair/cross7.png"),
            ("m", "crosshair/cross8.png", "name_exact", "bios/m/crosshair/cross7.png"),
        ]
        self.assertEqual(homonyms(claims), [])

    def test_two_entries_sharing_a_path_agree(self):
        claims = [
            ("a", "etmain/pak1.pk3", "path_exact", "bios/ET/etmain/pak1.pk3"),
            ("b", "etmain/pak1.pk3", "path_exact", "bios/ET/etmain/pak1.pk3"),
        ]
        self.assertEqual(homonyms(claims), [])


class AbsentFileIsNotReplacedByAHomonym(unittest.TestCase):
    """The database names the file a destination designates. When that file
    is a release asset the checkout does not hold, the name step answered
    with whatever else carried the name: Enemy Territory's `etmain/pak0.pk3`
    resolved to the Quake III demo pak on a clone without the large files."""

    def setUp(self):
        import hashlib
        import tempfile

        import generate_db

        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        files = {}
        for relative, payload in (
            ("bios/ET/etmain/pak0.pk3", b"enemy territory"),
            ("bios/Q3/demoq3/pak0.pk3", b"quake iii demo"),
        ):
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {
                "path": str(target), "name": "pak0.pk3", "size": len(payload),
                "sha1": sha1, "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "0",
            }
        indexes = generate_db.build_indexes(
            {s: {**r, "path": r["path"][len(str(root)) + 1:]} for s, r in files.items()},
            {},
        )
        self.db = {"files": files, "indexes": indexes}
        self.own = root / "bios/ET/etmain/pak0.pk3"
        self.entry = {"name": "pak0.pk3", "path": "etmain/pak0.pk3"}

    def tearDown(self):
        self._tmp.cleanup()

    def _resolve(self):
        return resolve_local_file(self.entry, self.db, {}, dest_hint="etmain/pak0.pk3")

    def test_present_it_resolves_by_its_path(self):
        self.assertEqual(self._resolve(), (str(self.own), "path_exact"))

    def test_absent_it_is_not_found_rather_than_another_game(self):
        self.own.unlink()
        self.assertEqual(self._resolve(), (None, "not_found"))


class SecondPassKeepsIdentity(unittest.TestCase):
    """A copy of a covered file at another core's path keeps the entry's proof.

    The second extras pass copied a name the baseline already covers to the
    profile's own path, without its hashes or its `unsourceable:` flag, so
    the copy resolved on the name: RetroBat's pack carried Quake III's
    baseq3/pak1.pk3 as MOHAA's mainta/pak1.pk3.
    """

    def test_flag_and_hashes_reach_the_alternative_destination(self):
        from packextras import _collect_emulator_extras

        sha = "a" * 40
        md5 = "b" * 32
        db = {
            "files": {sha: {"path": "bios/Q3/baseq3/pak1.pk3", "name": "pak1.pk3",
                            "sha1": sha, "md5": md5, "size": 10}},
            "indexes": {"by_name": {"pak1.pk3": [sha]}, "by_md5": {md5: sha},
                        "by_path_suffix": {"baseq3/pak1.pk3": [sha]}, "by_crc32": {}},
        }
        config = {
            "platform": "P", "cores": ["mohaa"], "standalone_cores": ["mohaa"],
            "systems": {"q3": {"files": [
                {"name": "pak1.pk3", "destination": "baseq3/pak1.pk3", "md5": md5}]}},
        }
        profiles = {"mohaa": {
            "emulator": "MOHAA", "type": "standalone", "cores": ["mohaa"],
            "systems": ["mohaa"],
            "files": [
                {"name": "pak1.pk3", "path": "mainta/pak1.pk3", "unsourceable": "retail"},
                {"name": "pak1.pk3", "path": "maintt/pak1.pk3", "sha1": "c" * 40},
            ],
        }}
        extras = {e["destination"]: e for e in _collect_emulator_extras(
            config, "emulators", db, set(), "", profiles)}
        self.assertEqual(extras["mainta/pak1.pk3"].get("unsourceable"), "retail")
        self.assertEqual(extras["maintt/pak1.pk3"].get("sha1"), "c" * 40)


class ReleaseAssetIsNotANameMatch(unittest.TestCase):
    """The release fallback keeps the flag the local resolver honours.

    ioquake3's baseq3/pak0.pk3 is flagged unsourceable; the local resolver
    returned not_found, then the release fallback looked the asset up by its
    bare name and handed Return to Castle Wolfenstein's demo pak to three
    platform manifests.
    """

    def test_an_unsourceable_entry_without_hash_never_reaches_the_asset_store(self):
        from unittest import mock

        import packresolve

        entry = {"name": "pak0.pk3", "unsourceable": "retail"}
        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_path_suffix": {}}}
        with mock.patch.object(packresolve, "fetch_large_file", return_value="/x/pak0.pk3") as fetch:
            self.assertEqual(
                packresolve.resolve_file(entry, db, "bios", {}, offline=True),
                (None, "not_found"),
            )
            fetch.assert_not_called()


class NameStepPrefersTheOwnersCopy(unittest.TestCase):
    """Same-named files are ordered by where the asking profile keeps its own.

    The name step took the first path in index order: Syobon Action's
    coin.ogg came from TheXTech's sound folder while its own copy sat in
    bios/Other/syobonaction/.
    """

    def test_the_copy_stored_with_the_profile_wins(self):
        import tempfile

        from common import resolve_local_file

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            other = Path("bios/Game Engines/TheXTech/sound/coin.ogg")
            own = Path("bios/Other/syobonaction/coin.ogg")
            for path, data in ((other, b"a" * 10), (own, b"b" * 12)):
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
            files = {
                "1" * 40: {"path": str(other), "name": "coin.ogg", "size": 10},
                "2" * 40: {"path": str(own), "name": "coin.ogg", "size": 12},
            }
            db = {"files": files, "indexes": {
                "by_name": {"coin.ogg": ["1" * 40, "2" * 40]},
                "by_md5": {}, "by_crc32": {}, "by_path_suffix": {}}}
            entry = {"name": "coin.ogg", "path": "SyobonAction/SE/coin.ogg"}
            path, status = resolve_local_file(entry, db, dest_hint=entry["path"])
            self.assertEqual((path, status), (str(own), "name_exact"))
            entry = {"name": "coin.ogg", "path": "SE/coin.ogg", "source_profile": "syobonaction"}
            path, _status = resolve_local_file(entry, db, dest_hint=entry["path"])
            self.assertEqual(path, str(own))


class CollectionCarriesNoGameDataHomonym(unittest.TestCase):
    def test_the_profiles_resolve_no_game_data_to_another_game(self):
        database = REPO_ROOT / "database.json"
        if not database.is_file():
            self.skipTest("no database.json")
        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            db = load_database(str(database))
            profiles = load_emulator_profiles("emulators", skip_aliases=False)
            zip_index = build_zip_contents_index(db)
            registry = load_data_dir_registry("platforms")
            claims = []
            for name, profile in sorted(profiles.items()):
                for entry in profile.get("files") or []:
                    if entry.get("category") != "game_data" or entry.get("unsourceable"):
                        continue
                    dest = str(entry.get("path") or entry.get("name") or "")
                    if "/" not in dest.strip("/"):
                        continue
                    local, status = resolve_local_file(
                        entry, db, zip_index, dest_hint=dest, data_dir_registry=registry
                    )
                    if local:
                        claims.append((name, dest, status, local))
        finally:
            os.chdir(previous)
        self.assertEqual(homonyms(claims), [])


class ControllerDatabasesAreTheirOwn(unittest.TestCase):
    """Solarus and EKA2L1 were handed the 26 KB C-Dogs copy by name.

    Each ships its own gamecontrollerdb.txt: Solarus its assets/ copy,
    EKA2L1 the SDL_GameControllerDB submodule it pins.
    """

    def test_each_resolves_by_content(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("no database.json")
        db = load_database(str(db_path))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        for key in ("solarus", "eka2l1"):
            entry = next(
                e for e in profiles[key]["files"] if e["name"] == "gamecontrollerdb.txt"
            )
            with self.subTest(profile=key):
                path, status = resolve_local_file(entry, db)
                self.assertIn(status, ("sha1_exact", "md5_exact"))
                self.assertNotIn("C-Dogs", path or "")


class SwitchKeysAreTheNewestSet(unittest.TestCase):
    """A harvested key set under Arcade/ won the name tie: master_key_10 shipped
    where the collection held master_key_12."""

    def test_every_switch_profile_gets_the_newest_master_key(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("no database.json")
        db = load_database(str(db_path))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        held = [
            Path(entry["path"]) for entry in db["files"].values()
            if entry["name"] == "prod.keys" and (REPO_ROOT / entry["path"]).exists()
        ]

        def newest(path: Path) -> int:
            generations = re.findall(
                r"^master_key_([0-9a-f]{2})\s*=", path.read_text(errors="replace"), re.MULTILINE
            )
            return max((int(g, 16) for g in generations), default=-1)

        best = max(newest(REPO_ROOT / p) for p in held)
        for key in ("yuzu", "citron", "eden", "suyu", "ryujinx", "kenji-nx", "skyline"):
            entry = next(e for e in profiles[key]["files"] if e["name"] == "prod.keys")
            with self.subTest(profile=key):
                path, _status = resolve_local_file(entry, db, dest_hint=entry.get("path") or "")
                self.assertEqual(newest(REPO_ROOT / path), best)


class Pc98ScsiBiosIsNotTheAppleCard(unittest.TestCase):
    """np2kai declared an exact 16 KB its loader never requires; the Apple II
    SCSI card ROM of that size won the name tie over the PC-98 BIOS."""

    def test_np2kai_resolves_the_pc98_rom(self):
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("no database.json")
        db = load_database(str(db_path))
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["np2kai"]
        entry = next(e for e in profile["files"] if e["name"] == "scsi.rom")
        path, _status = resolve_local_file(entry, db, dest_hint=entry["path"])
        self.assertIn("PC-98", path or "")


if __name__ == "__main__":
    unittest.main()
