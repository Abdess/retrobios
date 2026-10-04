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


if __name__ == "__main__":
    unittest.main()
