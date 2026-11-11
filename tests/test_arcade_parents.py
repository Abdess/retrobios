"""Arcade parent index: game set to BIOS sets and device sets, per core."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
FIXTURES = ROOT / "tests" / "fixtures" / "arcade_parents"
COMMITTED = ROOT / "games" / "arcade"

from scripts.scraper import arcade_parent_importer as api  # noqa: E402

try:
    from jsonschema import Draft202012Validator
except ImportError:  # validate_schemas.py is the only tool that needs it
    Draft202012Validator = None

COMMIT = "a" * 40


def _sets(name: str, chunk: int | None = None) -> dict:
    data = (FIXTURES / name).read_bytes()
    saved = api.LISTXML_CHUNK
    if chunk:
        api.LISTXML_CHUNK = chunk
    try:
        return api.read_sets([lambda: io.BytesIO(data)])
    finally:
        api.LISTXML_CHUNK = saved


class ListxmlIndex(unittest.TestCase):
    def setUp(self) -> None:
        self.index = api.build_index(_sets("listxml.xml"), "isbios")

    def test_clone_reaches_bios_through_its_parent(self) -> None:
        self.assertEqual(self.index["bios"]["neogeo"], ["mslug", "mslugh"])

    def test_every_bios_on_the_chain_is_listed(self) -> None:
        self.assertIn("ikaruga", self.index["bios"]["naomigd"])
        self.assertIn("ikaruga", self.index["bios"]["naomi"])

    def test_device_with_roms_only(self) -> None:
        self.assertEqual(self.index["devices"], {"m68705p3": ["mslug"]})

    def test_a_clone_lists_its_parent_game(self) -> None:
        # MAME looks a clone's shared ROMs up in its parent's archive
        # (src/emu/driver.cpp:31-38): mslugh reads mslug.zip.
        self.assertEqual(self.index["parents"], {"mslug": ["mslugh"]})

    def test_chd_and_missing_parent(self) -> None:
        self.assertEqual(self.index["chd"], ["ikaruga"])
        self.assertEqual(self.index["missing_parents"], {"orphan": "gonebios"})

    def test_sets_without_a_dump_are_not_games(self) -> None:
        counts = self.index["counts"]
        # mslug, mslugh, ikaruga, orphan, pacman
        self.assertEqual(counts["games"], 5)
        self.assertEqual(counts["games_with_bios"], 3)
        self.assertEqual(counts["bios_sets"], 3)

    def test_games_without_a_bios_and_the_bios_sets_are_named(self) -> None:
        # A set on a card is then a game that needs nothing, a BIOS set,
        # or a name the DAT does not hold: only the last falls back.
        self.assertEqual(self.index["no_bios"], ["pacman"])
        self.assertEqual(len(self.index["bios_sets"]), self.index["counts"]["bios_sets"])
        self.assertIn("neogeo", self.index["bios_sets"])
        self.assertNotIn("orphan", self.index["no_bios"])

    def test_small_window_reads_the_same(self) -> None:
        small = api.build_index(_sets("listxml.xml", chunk=64), "isbios")
        self.assertEqual(api.dump(small), api.dump(self.index))


class RunnableMarker(unittest.TestCase):
    def test_runnable_no_marks_the_bios(self) -> None:
        index = api.build_index(_sets("runnable_no.dat"), "runnable")
        self.assertEqual(index["bios"], {"neogeo": ["kof98"]})
        self.assertEqual(index["missing_parents"], {"brvblade": "psarc95"})
        self.assertEqual(index["counts"]["bios_sets"], 2)

    def test_isbios_marker_ignores_runnable(self) -> None:
        index = api.build_index(_sets("runnable_no.dat"), "isbios")
        self.assertEqual(index["bios"], {})


class FlycastTable(unittest.TestCase):
    def setUp(self) -> None:
        self.index = api.flycast_index((FIXTURES / "naomi_roms.cpp").read_text())

    def test_null_bios_is_naomi_and_filename_names_the_archive(self) -> None:
        self.assertEqual(self.index["bios"]["naomi"], ["gram2000", "ikaruga", "jpgame"])
        self.assertEqual(self.index["bios"]["awbios"], ["kofnw"])
        self.assertNotIn("naomi-jp-d", self.index["bios"])

    def test_gdrom_game_needs_a_chd(self) -> None:
        self.assertEqual(self.index["chd"], ["ikaruga"])

    def test_unknown_bios_is_reported(self) -> None:
        self.assertEqual(self.index["missing_parents"], {"bad": "nosuchbios"})


class OfflineImport(unittest.TestCase):
    """import_profile reads the cache only, and two runs write the same bytes."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.cache = Path(self.temp.name)
        dat = self.cache / "repo" / "libretro" / "mame2010-libretro" / COMMIT / "metadata"
        dat.mkdir(parents=True)
        (dat / "mame2010.xml").write_bytes((FIXTURES / "listxml.xml").read_bytes())
        with zipfile.ZipFile(self.cache / "mame0000lx.zip", "w") as archive:
            archive.write(FIXTURES / "listxml.xml", "mame0000.xml")
        self.profile = {
            "source": "https://github.com/libretro/mame2010-libretro",
            "source_commit": COMMIT,
            "core_version": "0.139",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_repo_profile_is_deterministic(self) -> None:
        first = api.dump(api.import_profile("mame2010", self.profile, self.cache, offline=True))
        second = api.dump(api.import_profile("mame2010", self.profile, self.cache, offline=True))
        self.assertEqual(first, second)
        doc = json.loads(first)
        self.assertEqual(doc["bios"]["neogeo"], ["mslug", "mslugh"])
        self.assertEqual(list(doc["source"]["files"]), ["metadata/mame2010.xml"])

    def test_listxml_release_from_the_cache(self) -> None:
        doc = api.import_profile("mame", {"core_version": "0.000"}, self.cache, offline=True)
        self.assertEqual(doc["source"]["release"], "mamedev/mame mame0000")
        self.assertEqual(doc["devices"], {"m68705p3": ["mslug"]})

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_fixture_output_matches_the_schema(self) -> None:
        doc = api.import_profile("mame2010", self.profile, self.cache, offline=True)
        schema = json.loads((ROOT / "schemas" / "arcade-parents.schema.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(doc)), [])


DRIVER_C = """/* driver.c is read twice, the list comes from the second pass */
#ifndef DRIVER_RECURSIVE
#define DRIVER_RECURSIVE
#include "driver.c"
#else
#ifdef TINY_COMPILE
	DRIVER( tinyonly )
#else
	DRIVER( game1 )
	DRIVER( clone1 )
	DRIVER( game2 )
	DRIVER( hacked )
	DRIVER( built1 )
	DRIVER( diskgame )
#endif
#endif
"""

DRIVER_FILE = """#include "driver.h"
#include "board.h"

#define BOARD_BIOS \\
	ROM_REGION( 0x100, REGION_USER1, 0 ) \\
	ROM_LOAD( "b1.bin", 0, 0x100, CRC(12345678) SHA1(0000000000000000000000000000000000000000) )

ROM_START( bios1 )
	BOARD_BIOS
ROM_END

ROM_START( bios2 )
	ROM_REGION( 0x100, REGION_USER1, 0 )
	ROM_LOAD( "b2.bin", 0, 0x100, NO_DUMP )
ROM_END

ROM_START( game1 )
	ROM_LOAD( "g1.bin", 0, 0x100, CRC(11111111) SHA1(0000000000000000000000000000000000000000) )
ROM_END

ROM_START( clone1 )
	ROM_LOAD( "c1.bin", 0, 0x100, CRC(22222222) SHA1(0000000000000000000000000000000000000000) )
ROM_END

ROM_START( game2 )
	ROM_LOAD( "g2.bin", 0, 0x100, CRC(33333333) SHA1(0000000000000000000000000000000000000000) )
ROM_END

ROM_START( hacked )
	ROM_LOAD( "h.bin", 0, 0x100, CRC(44444444) SHA1(0000000000000000000000000000000000000000) )
ROM_END

ROM_START( diskgame )
	DISK_REGION( REGION_DISKS )
	DISK_IMAGE( "disk", 0, MD5(00000000000000000000000000000000) )
ROM_END

#define SET( name, program ) \\
ROM_START( name ) \\
	program \\
ROM_END

#define PROGRAM_A ROM_LOAD( "p.bin", 0, 0x100, CRC(55555555) SHA1(0000000000000000000000000000000000000000) )
SET( built1, PROGRAM_A )

GAMEX( 1995, bios1,  0,     m, i, n, ROT0, "Maker", "Board BIOS", NOT_A_DRIVER )
GAMEX( 1995, bios2,  0,     m, i, n, ROT0, "Maker", "Undumped BIOS", NOT_A_DRIVER )
GAMEX( 1995, game1,  bios1, m, i, n, ROT0, "Maker", "Game (one, two)", 0 )
GAME(  1995, clone1, game1, m, i, n, ROT0, "Maker", "Clone" )
GAME(  1995, game2,  bios2, m, i, n, ROT0, "Maker", "Game on an undumped BIOS" )
#if BOARD_HACK
GAME(  1995, hacked, bios1, m, i, n, ROT0, "Maker", "Hacked" )
#else
GAME(  1995, hacked, 0,     m, i, n, ROT0, "Maker", "Not hacked" )
#endif
GAME(  1995, built1, bios1, m, i, n, ROT0, "Maker", "Built by a macro" )
GAME(  1995, diskgame, 0,   m, i, n, ROT0, "Maker", "Disk game" )
"""

STALE_DAT = """<?xml version="1.0"?>
<mame>
	<game name="game1" sourcefile="board.c" romof="oldbios">
		<rom name="g1.bin" size="256" crc="11111111"/>
	</game>
	<game runnable="no" name="oldbios">
		<rom name="o.bin" size="256" crc="77777777"/>
	</game>
</mame>
"""


def _write_tarball(path: Path, files: dict[str, str]) -> None:
    import tarfile

    with tarfile.open(path, "w:gz") as archive:
        for name, text in files.items():
            data = text.encode("latin-1")
            info = tarfile.TarInfo(f"repo-{COMMIT}/{name}")
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))


class DriverSource(unittest.TestCase):
    """mame2000, mame2003 and mame2003-plus are read from their driver code:
    the DATs those repositories carry contradict it."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.cache = Path(self.temp.name)
        slug = "libretro/mame2003-libretro"
        tarball = self.cache / "src" / slug / f"{COMMIT}.tar.gz"
        tarball.parent.mkdir(parents=True)
        _write_tarball(tarball, {
            "src/driver.c": DRIVER_C,
            "src/driver.h": "#define NOT_A_DRIVER 0x4000\n",
            "src/includes/board.h": "#define BOARD_HACK 0\n",
            "src/drivers/board.c": DRIVER_FILE,
        })
        dat = self.cache / "repo" / slug / COMMIT / "metadata"
        dat.mkdir(parents=True)
        (dat / "mame2003.xml").write_text(STALE_DAT)
        self.profile = {
            "source": "https://github.com/libretro/mame2003-libretro",
            "source_commit": COMMIT,
            "core_version": "0.78",
        }
        self.report: dict = {}
        self.doc = api.import_profile("mame2003", self.profile, self.cache, True, self.report)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_parents_come_from_the_game_macros(self) -> None:
        self.assertEqual(self.doc["bios"], {"bios1": ["built1", "clone1", "game1"]})

    def test_a_bios_without_a_dump_needs_no_archive(self) -> None:
        self.assertNotIn("bios2", self.doc["bios"])
        self.assertEqual(self.doc["counts"]["bios_sets"], 2)

    def test_the_branch_the_build_compiles(self) -> None:
        """BOARD_HACK is 0 in the header the driver includes."""
        self.assertNotIn("hacked", self.doc["bios"]["bios1"])

    def test_the_tiny_build_list_is_left_out(self) -> None:
        self.assertEqual(self.doc["counts"]["games"], 6)

    def test_a_disk_image_is_a_chd(self) -> None:
        self.assertEqual(self.doc["chd"], ["diskgame"])

    def test_the_source_is_named_by_its_tree(self) -> None:
        tree = self.doc["source"]["files"]["src"]
        source = api.read_driver_source(self.cache / "src" / "libretro" / "mame2003-libretro" / f"{COMMIT}.tar.gz")
        self.assertEqual(tree, source.tree)
        self.assertEqual(list(self.doc["source"]["files"]), ["src"])

    def test_the_committed_dat_is_reported_where_it_disagrees(self) -> None:
        gaps = self.report["dat_gaps"]
        self.assertEqual(gaps["romof"], ["game1"])
        self.assertEqual(gaps["dat_only"], ["oldbios"])
        self.assertIn("built1", gaps["code_only"])

    def test_an_undeclared_driver_is_refused(self) -> None:
        with self.assertRaises(api.DriverSourceError):
            api.driver_source_sets("DRIVER( nosuch )", {"src/drivers/a.c": ""}, {})

    def test_the_empty_tree(self) -> None:
        self.assertEqual(api.git_tree_sha({}), "4b825dc642cb6eb9a060e54bf8d69288fbee4904")

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_output_matches_the_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "arcade-parents.schema.json").read_text())
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(self.doc)), [])


FBNEO_LIST = """\t{ "1942", "pre90s/d_1942.cpp"},
\t{ "msx_1942", "msx/d_msx.cpp"},
\t{ "msx_msx", "msx/d_msx.cpp"},
\t{ "nes_zelda", "nes/d_nes.cpp"},
\t{ "fds_zelda", "nes/d_nes.cpp"},
\t{ "nes_smb", "nes/d_nes.cpp"},
"""


def _dat(*games: str) -> bytes:
    return ("<datafile>" + "".join(games) + "</datafile>").encode()


def _game(name: str, source: str, romof: str | None = None) -> str:
    parent = f' romof="{romof}"' if romof else ""
    return (
        f'<game name="{name}" sourcefile="{source}"{parent}>'
        f'<rom name="{name}.bin" size="1" crc="12345678"/></game>'
    )


class FbneoNamespaces(unittest.TestCase):
    """Each FBNeo DAT is its own namespace, a console set is its driver."""

    def setUp(self) -> None:
        names = api.fbneo_drivers(FBNEO_LIST)
        arcade = _dat(_game("1942", "pre90s/d_1942.cpp"))
        msx = _dat(
            _game("1942", "msx/d_msx.cpp", "msx"),
            '<game name="msx" sourcefile="msx/d_msx.cpp" isbios="yes">'
            '<rom name="msx.rom" size="1" crc="87654321"/></game>',
        )
        nes = _dat(_game("zelda", "nes/d_nes.cpp"), _game("smb", "nes/d_nes.cpp"))
        sets, self.archives = api.fbneo_sets(
            [lambda d=d: io.BytesIO(d) for d in (arcade, msx, nes)], names
        )
        self.sets = sets
        self.index = api.build_index(sets, "isbios", self.archives)

    def test_the_msx_set_needs_the_msx_bios_and_the_arcade_one_does_not(self) -> None:
        self.assertEqual(self.index["bios"], {"msx": ["msx_1942"]})
        self.assertIn("1942", self.sets)

    def test_the_bios_is_named_by_its_archive(self) -> None:
        self.assertEqual(self.archives["msx_msx"], "msx")

    def test_a_shared_source_file_takes_the_prefix_of_its_dat(self) -> None:
        self.assertIn("nes_zelda", self.sets)
        self.assertNotIn("fds_zelda", self.sets)


class DeclaredArchives(unittest.TestCase):
    def test_names_aliases_and_archives(self) -> None:
        profile = {"files": [
            {"name": "neogeo.zip"},
            {"name": "sp-s2.sp1", "archive": "neogeo.zip"},
            {"name": "pgm.zip", "aliases": ["PGMBIOS.zip"]},
        ]}
        self.assertEqual(api.declared_archives(profile), {"neogeo.zip", "sp-s2.sp1", "pgm.zip", "pgmbios.zip"})


class CommittedIndex(unittest.TestCase):
    def test_every_profile_has_its_file_above_the_floor(self) -> None:
        for profile in api.PROFILES:
            with self.subTest(profile=profile):
                path = COMMITTED / f"{profile}.json"
                self.assertTrue(path.is_file(), path)
                doc = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(doc["profile"], profile)
                self.assertGreaterEqual(doc["counts"]["games_with_bios"], api.FLOORS[profile])

    def test_committed_files_are_written_canonically(self) -> None:
        for path in sorted(COMMITTED.glob("*.json")):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(api.dump(json.loads(text)), text)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_committed_files_match_the_schema(self) -> None:
        schema = json.loads((ROOT / "schemas" / "arcade-parents.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for path in sorted(COMMITTED.glob("*.json")):
            with self.subTest(path=path.name):
                errors = list(validator.iter_errors(json.loads(path.read_text(encoding="utf-8"))))
                self.assertEqual(errors, [])

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_each_file_is_read_at_its_profile_pin(self) -> None:
        """A bumped profile kept the game-to-BIOS map of the old code."""
        import sys
        from unittest import mock

        sys.path.insert(0, str(ROOT / "scripts"))
        import validate_schemas

        self.assertEqual(validate_schemas._arcade_pin_errors(), [])
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / "games" / "arcade").mkdir(parents=True)
            (root / "emulators").mkdir()
            (root / "emulators" / "core.yml").write_text(
                f"source_commit: {'b' * 40}\ncore_version: '0.2'\n")
            (root / "games" / "arcade" / "core.json").write_text(json.dumps(
                {"profile": "core", "core_version": "0.1", "source": {"commit": COMMIT}}))
            with mock.patch.object(validate_schemas, "ROOT", root):
                (error,) = validate_schemas._arcade_pin_errors()
        self.assertIn("read at aaaaaaaaaaaa", error)
        self.assertIn("core_version '0.1'", error)
        self.assertIn("arcade_parent_importer --profile core", error)


if __name__ == "__main__":
    unittest.main()
