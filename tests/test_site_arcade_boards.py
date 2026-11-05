"""Arcade boards and the ids that hold files.

The Arcade pages were cut by storage folder, so NAOMI, ZN-1, PGM and the
other boards had no section and stayed plain on 987 emulator rows.
siterender.arcade_board() names the board each set archive is the BIOS of,
read from the profiles, and system_section() leads every id of that board
to ``systems/arcade-<board_slug>/#<board_slug>``, the section the system
pages write. The 28 ids that systems.json gave files and no page either
link or carry their reason below.
"""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

import sys  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import siterender  # noqa: E402
from sitestarlight import toc_slug  # noqa: E402

# The boards the audit found with no section (N1, T-F3), by an id each.
NAMED_BOARDS = {
    "sega-naomi": "Sega NAOMI",
    "sega-naomi2": "Sega NAOMI 2",
    "sammy-atomiswave": "Sammy Atomiswave",
    "capcom-zn1": "Capcom ZN-1",
    "capcom-zn2": "Capcom ZN-2",
    "igs-pgm": "IGS PolyGame Master",
    "nintendo-playch10": "Nintendo PlayChoice-10",
    "nintendo-nss": "Nintendo Super System",
    "konami-gv": "Konami GV",
    "deco-cassette": "Data East DECO Cassette System",
    "super-kaneko-nova": "Kaneko Super Nova System",
    "hyper-neogeo64": "SNK Hyper Neo Geo 64",
    "sega-megatech": "Sega Mega-Tech",
    "sega-megaplay": "Sega Mega Play",
}

# The ids api/v1/systems.json listed with files and no url (D P2-7).
# Each one links, or stays plain for the reason given.
SYSTEMS_JSON_GAPS = (
    "atom", "bbc-master-128", "bbc-master-et", "cave-story", "dos",
    "emerson-arcadia-2001", "fpinball", "mz2000", "mz2500", "mz800", "naomi2",
    "neogeo64", "pegasus", "pv1000", "scummvm", "sega-dreamcast-arcade",
    "sinclair-zx-spectrum-next", "solarus", "spectravideo", "sunplus-spmp8000",
    "tomb-raider-1", "tyrian", "vc4000", "vgmplay", "vm-labs-nuon", "vvvvvv",
    "xrick", "zc210",
)
STAYS_PLAIN = {
    "emerson-arcadia-2001": "ar_bios.zip is the Arcadia Systems board's, filed with the Saturn",
    "fpinball": "scripten.exe, filed with Windows",
    "pv1000": "only MAME's software list pv1000.xml",
    "vc4000": "only MAME's software list vc4000.xml",
    "spectravideo": "the SVI ROMs are filed with the MSX",
    "vgmplay": "sound chip sets, no board",
    "vvvvvv": "SDL's controller database",
}


def _reset() -> None:
    """Back to the repository's sections and boards, none written."""
    siterender._arcade_source[0] = None
    siterender._boards_built[0] = False
    siterender._sections_installed[0] = False
    siterender.reset_console_pages()


def _write_every_board() -> None:
    """What the system pages do once they give each board a section."""
    for board in siterender.arcade_boards():
        siterender.record_board_section(board)


@unittest.skipUnless((REPO_ROOT / "database.json").exists(), "database.json is not built")
class Boards(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        _reset()
        with open(REPO_ROOT / "database.json", encoding="utf-8") as handle:
            cls.db = json.load(handle)
        _write_every_board()

    @classmethod
    def tearDownClass(cls) -> None:
        _reset()

    def _copies(self, name: str) -> list[str]:
        return self.db["indexes"]["by_name"][name]

    def test_named_boards_exist(self) -> None:
        boards = siterender.arcade_boards()
        names = set(boards.values())
        for sys_id, name in NAMED_BOARDS.items():
            with self.subTest(sys_id=sys_id):
                self.assertEqual(siterender.system_name(sys_id), name)
                self.assertIn(name, names)

    def test_every_copy_names_its_board(self) -> None:
        """Every copy of a board's set, wherever it is filed: naomi.zip
        under Sega > Dreamcast is still NAOMI's."""
        expect = {
            "naomi.zip": "sega-naomi",
            "awbios.zip": "sammy-atomiswave",
            "cpzn1.zip": "capcom-zn1",
            "pgm.zip": "igs-pgm",
            "playch10.zip": "nintendo-playch10",
            "hng64.zip": "hyper-neogeo64",
            "taitofx1.zip": "taito-fx1",
        }
        for name, board in expect.items():
            for sha1 in self._copies(name):
                with self.subTest(name=name, path=self.db["files"][sha1]["path"]):
                    self.assertEqual(siterender.arcade_board(sha1), board)

    def test_no_board(self) -> None:
        """neogeo.zip and cd32.zip are the BIOS of machines with a section of
        their own. mie.zip and jvs13551.zip are shared device sets."""
        for name in ("neogeo.zip", "cd32.zip", "mie.zip", "jvs13551.zip"):
            for sha1 in self._copies(name):
                with self.subTest(name=name, path=self.db["files"][sha1]["path"]):
                    self.assertIsNone(siterender.arcade_board(sha1))

    def test_slug_contract(self) -> None:
        boards = siterender.arcade_boards()
        slugs = {siterender.board_slug(board) for board in boards}
        self.assertEqual(len(slugs), len(boards), "two boards share a slug")
        for board, name in boards.items():
            with self.subTest(board=board):
                slug = siterender.board_slug(board)
                self.assertTrue(slug)
                self.assertEqual(slug, toc_slug(name))
                # The board's page is its section: no heading repeats its
                # title.
                self.assertEqual(
                    siterender.console_href(*siterender.system_section(board)),
                    f"systems/arcade-{slug}.md")

    def test_aliases_share_a_board(self) -> None:
        """Every id of one board's name leads to one section."""
        pairs = (
            ("sega-atomiswave", "sammy-atomiswave"),
            ("zn1-capcom", "capcom-zn1"),
            ("naomi2", "sega-naomi2"),
            ("neogeo64", "hyper-neogeo64"),
            ("zn1-taito", "taito-fx1"),
            ("zn1-tecmo", "tecmo-tps"),
        )
        for alias, board in pairs:
            with self.subTest(alias=alias):
                self.assertEqual(siterender.board_slug(alias), siterender.board_slug(board))
                self.assertEqual(
                    siterender.system_section(alias), siterender.system_section(board))

    def test_machines_keep_their_section(self) -> None:
        self.assertEqual(siterender.system_section("snk-neogeo-mvs"), ("snk", "Neo Geo"))
        self.assertEqual(siterender.system_section("sega-hikaru"), ("sega", "Hikaru"))
        self.assertEqual(siterender.system_section("arcade"), ("arcade", "Arcade"))

    def test_systems_json_gaps(self) -> None:
        plain = sorted(i for i in SYSTEMS_JSON_GAPS if siterender.system_section(i) is None)
        self.assertEqual(plain, sorted(STAYS_PLAIN))

    def test_parents_named_by_the_plan(self) -> None:
        expect = {
            "dos": ("dos", "DOSBox"),
            "scummvm": ("scummvm", "ScummVM"),
            "tyrian": ("other", "opentyrian"),
            "bbc-master-128": ("other", "beebem"),
        }
        for sys_id, section in expect.items():
            with self.subTest(sys_id=sys_id):
                self.assertEqual(siterender.system_section(sys_id), section)


@unittest.skipUnless((REPO_ROOT / "database.json").exists(), "database.json is not built")
class LinksWaitForTheSection(unittest.TestCase):
    """A board links once the system pages wrote its section, never to a
    page nobody wrote: the build's link check stops on those."""

    def setUp(self) -> None:
        _reset()
        self.addCleanup(_reset)

    def test_unwritten_board_stays_plain(self) -> None:
        self.assertIsNone(siterender.system_section("igs-pgm"))
        self.assertIsNone(siterender.system_section("naomi2"))
        self.assertEqual(siterender.console_href("arcade", "IGS PolyGame Master"),
                         "systems/arcade.md#igs-polygame-master")

    def test_written_board_links_and_takes_its_cards(self) -> None:
        siterender.record_board_section("igs-pgm")
        self.assertEqual(siterender.system_section("igs-pgm"),
                         ("arcade", "IGS PolyGame Master"))
        self.assertIsNone(siterender.system_section("sega-naomi"))
        sha1 = next(s for s, e in json.loads(
            (REPO_ROOT / "database.json").read_text(encoding="utf-8"))["files"].items()
            if e["path"] == "bios/Arcade/Arcade/pgm.zip")
        self.assertEqual(siterender.card_page("bios/Arcade/Arcade/pgm.zip", sha1),
                         "arcade-igs-polygame-master")
        siterender.reset_console_pages()
        self.assertIsNone(siterender.system_section("igs-pgm"))

    def test_an_alias_records_its_board(self) -> None:
        siterender.record_board_section("sega-atomiswave")
        self.assertEqual(siterender.system_section("sammy-atomiswave"),
                         ("arcade", "Sammy Atomiswave"))

    def test_no_board_refused(self) -> None:
        with self.assertRaises(KeyError):
            siterender.record_board_section("sony-playstation")


class BoardRules(unittest.TestCase):
    """The rules on a fixture: the folder decides nothing, a tie is no
    board, a machine's own set is no board, contents: rejects a homonym."""

    def setUp(self) -> None:
        tmp_root = REPO_ROOT / "tmp"
        tmp_root.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=tmp_root)
        self.root = Path(self._tmp.name)
        siterender.set_console_sections({("Arcade", "MAME"), ("SNK", "Neo Geo")})

    def tearDown(self) -> None:
        self._tmp.cleanup()
        _reset()

    def _zip(self, name: str, crc_member: bytes) -> str:
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("rom.bin", crc_member)
        return str(path)

    def _install(self, entries: dict[str, list[dict]], files: dict[str, str]) -> None:
        """``files``: sha1 -> path. Names are the paths' base names."""
        db = {
            "files": {sha1: {"path": path, "name": Path(path).name} for sha1, path in files.items()},
            "indexes": {"by_name": {}, "by_path_suffix": {}},
        }
        for sha1, path in files.items():
            db["indexes"]["by_name"].setdefault(Path(path).name, []).append(sha1)
        profiles = {key: {"systems": [], "files": rows} for key, rows in entries.items()}
        siterender.set_arcade_boards(profiles, db)

    def test_folder_decides_nothing(self) -> None:
        self._install(
            {"core": [{"name": "pgm.zip", "category": "bios_zip", "system": "igs-pgm"}]},
            {"a" * 40: "bios/Arcade/MAME/pgm.zip", "b" * 40: "bios/Other/x/pgm.zip"},
        )
        self.assertEqual(siterender.arcade_board("a" * 40), "igs-pgm")
        self.assertEqual(siterender.arcade_board("b" * 40), "igs-pgm")

    def test_tie_is_no_board(self) -> None:
        self._install(
            {
                "one": [{"name": "dev.zip", "category": "bios_zip", "system": "igs-pgm"}],
                "two": [{"name": "dev.zip", "category": "bios_zip", "system": "konami-gv"}],
            },
            {"c" * 40: "bios/Arcade/MAME/dev.zip"},
        )
        self.assertIsNone(siterender.arcade_board("c" * 40))

    def test_majority_wins(self) -> None:
        self._install(
            {
                "one": [{"name": "dev.zip", "category": "bios_zip", "system": "igs-pgm"}],
                "two": [{"name": "dev.zip", "category": "bios_zip", "system": "igs-pgm"}],
                "three": [{"name": "dev.zip", "category": "bios_zip", "system": "konami-gv"}],
            },
            {"c" * 40: "bios/Arcade/MAME/dev.zip"},
        )
        self.assertEqual(siterender.arcade_board("c" * 40), "igs-pgm")

    def test_machine_set_is_no_board(self) -> None:
        self._install(
            {
                "one": [{"name": "neogeo.zip", "category": "bios_zip", "system": "snk-neogeo-mvs"}],
                "two": [{"name": "neogeo.zip", "category": "bios_zip", "system": "igs-pgm"}],
            },
            {"d" * 40: "bios/Arcade/MAME/neogeo.zip"},
        )
        self.assertIsNone(siterender.arcade_board("d" * 40))

    def test_contents_reject_a_homonym(self) -> None:
        good = self._zip("good.zip", b"good")
        other = self.root / "other"
        other.mkdir()
        bad = str(other / "good.zip")
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("rom.bin", b"something else")
        crc = f"{zipfile.ZipFile(good).getinfo('rom.bin').CRC:08x}"
        self._install(
            {"core": [{"name": "good.zip", "category": "bios_zip", "system": "igs-pgm",
                       "contents": [{"name": "rom.bin", "crc32": crc}]}]},
            {"e" * 40: good, "f" * 40: bad},
        )
        # Both copies filed under Arcade, as by_path_suffix records it.
        db = siterender._arcade_source[0][1]
        db["indexes"]["by_path_suffix"] = {
            "Arcade/MAME/good.zip": ["e" * 40], "Arcade/FBNeo/good.zip": ["f" * 40]}
        self.assertEqual(siterender.arcade_board("e" * 40), "igs-pgm")
        self.assertIsNone(siterender.arcade_board("f" * 40))

    def test_no_copy_under_arcade_no_section(self) -> None:
        """A board with no set under Arcade has no section there to lead to."""
        self._install(
            {"core": [{"name": "pgm.zip", "category": "bios_zip", "system": "igs-pgm"}]},
            {"a" * 40: "bios/IGS/PGM/pgm.zip"},
        )
        self.assertIsNone(siterender.arcade_board("a" * 40))
        with self.assertRaises(KeyError):
            siterender.record_board_section("igs-pgm")


if __name__ == "__main__":
    unittest.main()
