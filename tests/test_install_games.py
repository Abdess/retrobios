"""install.py --for-games: what the games on a card need.

The games index (install/games/) is a fixture written per test, read from
the folder beside --manifest as a run offline reads it, so a test pins the
rules and not the state of the data. Two tests read the repository's own
index, published by scripts/generate_games_index.py.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import functools
import gzip
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import zipfile
import zlib
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import install  # noqa: E402

TMP_ROOT = REPO_ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)


def _crc(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


MD_EU = b"md europe game " * 64
MD_JP = b"md japan game " * 64
MD_ZIPPED = b"md zipped usa game " * 64
GC_HEADER = 0x458

# Every file the fixture list carries: dest -> (size, regions, cores, systems).
FILES = {
    "scph5500.bin": (512, ["japan"], None, ["sony-playstation"]),
    "scph5501.bin": (512, ["north-america"], None, ["sony-playstation"]),
    "scph5502.bin": (512, ["europe"], None, ["sony-playstation"]),
    "bios_CD_E.bin": (128, ["europe"], None, ["sega-megacd"]),
    "bios_CD_U.bin": (128, ["north-america"], None, ["sega-megacd"]),
    "bios_CD_J.bin": (128, ["japan"], None, ["sega-megacd"]),
    "cd_extra.bin": (16, None, ["picodrive"], None),
    "md_eu.bin": (64, ["europe"], None, ["sega-megadrive"]),
    "md_us.bin": (64, ["north-america"], None, ["sega-megadrive"]),
    "md_jp.bin": (64, ["japan"], None, ["sega-megadrive"]),
    "md_tmss.bin": (32, None, None, ["sega-megadrive"]),
    "dolphin/GC/USA/IPL.bin": (256, ["north-america"], ["dolphin"], None),
    "dolphin/GC/EUR/IPL.bin": (256, ["europe"], ["dolphin"], None),
    "dolphin/GC/JAP/IPL.bin": (256, ["japan"], ["dolphin"], None),
    "neogeo.zip": (300, None, None, ["snk-neogeo"]),
    "fbneo/neogeo.zip": (300, None, ["fbneo"], None),
    "fbneo/pgm.zip": (200, None, ["fbneo"], None),
    "fbneo/msx.zip": (150, None, ["fbneo"], None),
    "fbneo/samples/big.zip": (9000, None, ["fbneo"], None),
    "gba_bios.bin": (100, None, None, ["nintendo-gba"]),
}
# The fallback sets: key -> (files, optional).
SETS = {
    "sony-playstation|beetle_psx": (["scph5500.bin", "scph5501.bin", "scph5502.bin"], []),
    "sega-megacd|picodrive": (["bios_CD_E.bin", "bios_CD_U.bin", "bios_CD_J.bin",
                               "cd_extra.bin"], ["cd_extra.bin"]),
    "sega-megadrive|fixcore": (["md_eu.bin", "md_us.bin", "md_jp.bin", "md_tmss.bin"],
                               ["md_tmss.bin"]),
    "nintendo-gamecube|dolphin": (["dolphin/GC/USA/IPL.bin", "dolphin/GC/EUR/IPL.bin",
                                   "dolphin/GC/JAP/IPL.bin"], []),
    "arcade|fbneo": (["fbneo/samples/big.zip"], ["fbneo/samples/big.zip"]),
    "msx|fbneo": (["fbneo/msx.zip"], []),
    "nintendo-gba|mgba": (["gba_bios.bin"], ["gba_bios.bin"]),
    "nintendo-gba|gpsp": (["gba_bios.bin"], []),
}

REGION_READER_MCD = {
    "applies_to": {"extensions": [".cue", ".bin", ".iso"], "media": "cd"},
    "decode": {"kind": "integer", "otherwise": ["north-america"],
               "values": [{"regions": ["europe"], "value": 100},
                          {"regions": ["japan"], "value": 161}]},
    "location": {"encoding": "u8", "length": 1, "offset": 523, "sector": 0},
    "magic": {"bytes": "SEGADISCSYSTEM", "offset": 0, "sector": 0},
}

SYSTEMS = {
    "sony-playstation": {
        "identify": {"sources": [{"source": "redump", "dat": "PS"}], "regions": [["europe"]],
                     "games": [], "serials": {"SLES-00001": [0]}},
        "headers": {"readers": {"psx-serial-prefix": {
            "location": {"iso_file": "SYSTEM.CNF", "key": "BOOT", "take": "basename"},
            "decode": {"kind": "prefix-nocase", "values": [
                {"value": "sles", "regions": ["europe"]}], "otherwise": "unknown"}}},
            "cores": {"beetle_psx": {"order": ["psx-serial-prefix"],
                                     "otherwise": ["north-america"]}}},
        "region_rules": {"beetle_psx": {"keep_all_regions": [
            {"case": "psx-override-bios", "condition": "option", "keeps": "region-free-files"}]}},
    },
    "sega-megacd": {
        "identify": {"sources": [{"source": "redump", "dat": "MCD"}], "regions": [],
                     "games": [], "serials": {}},
        "headers": {"readers": {"mcd-security-code": REGION_READER_MCD},
                    "cores": {"picodrive": {"order": ["mcd-security-code"],
                                            "otherwise": ["north-america"]}}},
        "region_rules": {"picodrive": {"default_region": "north-america"}},
        "extras": [{"system": "sega-megacd", "profile": "picodrive",
                    "trigger": {"every_game": True}, "files": ["cd_extra.bin"],
                    "required": True}],
    },
    "sega-megadrive": {
        "identify": {"sources": [{"source": "no-intro", "dat": "MD"}],
                     "regions": [["europe"], ["japan"], ["north-america"]],
                     "games": sorted([[_crc(MD_EU), len(MD_EU), 0, "Game (Europe)"],
                                      [_crc(MD_JP), len(MD_JP), 1, "Game (Japan)"],
                                      [_crc(MD_ZIPPED), len(MD_ZIPPED), 2, "Zipped (USA)"]]),
                     "serials": {}},
        "headers": {"readers": {"md-country": {
            "location": {"offset": 0x1F0, "length": 3, "encoding": "ascii"},
            "decode": {"kind": "letters", "otherwise": "unknown", "values": [
                {"value": "J", "regions": ["japan"]}, {"value": "E", "regions": ["europe"]},
                {"value": "U", "regions": ["north-america"]}]}}},
            "cores": {"fixcore": {"order": ["md-country"], "otherwise": "unknown"}}},
        "region_rules": {"fixcore": {}},
    },
    "nintendo-gamecube": {
        "identify": {"sources": [{"source": "redump", "dat": "GC"}],
                     "regions": [["europe", "north-america"], ["japan"]],
                     "games": [], "serials": {"GALE01": [0], "GJPN01": [1]}},
        "headers": {"readers": {
            "gc-game-id": {"location": {"container": "gamecube-disc", "disc_offset": 0,
                                        "encoding": "ascii", "length": 6},
                           "decode": {"kind": "serial"}},
            "gc-region": {"location": {"container": "gamecube-disc", "disc_offset": GC_HEADER,
                                       "encoding": "u32be", "length": 4},
                          "decode": {"kind": "integer", "otherwise": "unknown", "values": [
                              {"value": 0, "regions": ["japan"]},
                              {"value": 1, "regions": ["north-america"]},
                              {"value": 2, "regions": ["europe"]}]}}},
            "cores": {"dolphin": {"order": ["gc-region"], "otherwise": "unknown"}}},
        "region_rules": {"dolphin": {"keep_all_regions": [
            {"case": "gamecube-unknown-region", "condition": "disc"}]}},
    },
    "nintendo-gba": {},
}

ARCADE = {
    "bios": {"neogeo": ["mslug", "mslug2"], "pgm": ["orlegend"], "nobios": ["lost"],
             "msx": ["msx_1942"]},
    "devices": {}, "chd": [], "missing_parents": {},
    "no_bios": ["1942", "nes_1942", "pacman"], "bios_sets": ["msx", "neogeo", "nobios", "pgm"],
}

SETUP = {
    "format_version": 1, "setup": "retroarch", "name": "Fixture", "platform": "retroarch",
    "sources": {}, "roms_root": {"path": "/mnt/SDCARD/Roms", "from_bios": "../Roms"},
    "case_sensitive": False,
    "media": [{"name": "Imgs"}],
    "folders": [
        {"folder": "PS", "systems": ["sony-playstation"], "basis": "id",
         "profile": "beetle_psx", "extensions": [".cue", ".bin", ".chd", ".m3u", ".iso"],
         "fallback": ["sony-playstation|beetle_psx"], "source_ref": "x"},
        {"folder": "SEGACD", "systems": ["sega-megacd"], "basis": "id",
         "profile": "picodrive", "extensions": [".cue", ".iso", ".bin", ".chd", ".m3u"],
         "fallback": ["sega-megacd|picodrive"], "source_ref": "x"},
        {"folder": "MD", "systems": ["sega-megadrive"], "basis": "id", "profile": "fixcore",
         "extensions": [".md", ".bin", ".zip", ".7z"],
         "fallback": ["sega-megadrive|fixcore"], "source_ref": "x"},
        {"folder": "GC", "systems": ["nintendo-gamecube"], "basis": "id",
         "profile": "dolphin", "extensions": [".iso", ".rvz"],
         "fallback": ["nintendo-gamecube|dolphin"], "source_ref": "x"},
        {"folder": "FBNEO", "systems": ["arcade"], "basis": "id", "profile": "fbneo",
         "arcade": "fbneo", "extensions": [".zip", ".7z"], "fallback": ["arcade|fbneo"],
         "source_ref": "x"},
        {"folder": "MSX", "systems": ["msx"], "basis": "id", "profile": "fbneo",
         "arcade": "fbneo", "extensions": [".zip"], "fallback": ["msx|fbneo"],
         "source_ref": "x"},
        {"folder": "GBA", "systems": ["nintendo-gba"], "basis": "id", "profile": "mgba",
         "extensions": [".gba"], "fallback": ["nintendo-gba|mgba"],
         "board_defaults": {"rpi": {"core": "gpsp", "profile": "gpsp",
                                    "fallback": ["nintendo-gba|gpsp"]}},
         "source_ref": "x"},
        {"folder": "PORTS", "systems": [], "basis": "unresolved", "source_ref": "x"},
    ],
}


def _dumps(doc: object) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_index(folder: Path, systems: dict | None = None, arcade: dict | None = None,
                setup: dict | None = None, extra_sets: dict | None = None,
                more_setups: dict | None = None) -> None:
    """install/games/ as the generator lays it out, every digest right."""
    rows = sorted({(dest, FILES[dest][0], "bios") for files, _o in SETS.values()
                   for dest in files})
    position = {row[0]: i for i, row in enumerate(rows)}
    sets = {**SETS, **(extra_sets or {})}
    fallback = {"format_version": 1, "platform": "retroarch", "files": [list(r) for r in rows],
                "sets": {key: {"files": [position[d] for d in files],
                               "optional": [position[d] for d in optional],
                               "bytes": 0, "required_bytes": 0}
                         for key, (files, optional) in sets.items()}}
    docs = {"setups": {"retroarch": setup or SETUP, **(more_setups or {})}, "fallback": {"retroarch": fallback},
            "systems": {key: {"format_version": 1, "system": key, **value}
                        for key, value in (systems or SYSTEMS).items()},
            "arcade": {"fbneo": {"profile": "fbneo", **(arcade or ARCADE)}}}
    index: dict = {"format_version": 1, "data_version": "0" * 16, "licences": [],
                   "folders": {"ps": ["sony-playstation"], "psx": ["sony-playstation"],
                               "md": ["sega-megadrive"], "megadrive": ["sega-megadrive"]}}
    for kind, items in docs.items():
        index[kind] = {}
        for key, doc in items.items():
            data = _dumps(doc)
            rel = f"{kind}/{key}.json"
            (folder / kind).mkdir(parents=True, exist_ok=True)
            (folder / rel).write_bytes(data)
            index[kind][key] = {"file": rel, "size": len(data),
                                "gzip_size": len(gzip.compress(data)),
                                "sha256": hashlib.sha256(data).hexdigest()}
    (folder / "index.json").write_bytes(_dumps(index))


def manifest() -> dict:
    files = []
    for dest, (size, regions, cores, systems) in FILES.items():
        payload = dest.encode().ljust(size, b".")[:size]
        entry = {"dest": dest, "size": size, "sha1": hashlib.sha1(payload).hexdigest(),
                 "sha256": hashlib.sha256(payload).hexdigest(),
                 "repo_path": f"bios/{dest.replace('/', '_')}", "cores": cores}
        if systems:
            entry["systems"] = systems
        if regions:
            entry.update(regions=regions)
        files.append(entry)
    return {"manifest_version": 2, "platform": "retroarch", "files": files,
            "omitted_files": []}


def mcd_iso(code: int, magic: bool = True) -> bytes:
    data = bytearray(2048 * 18)
    if magic:
        data[0:14] = b"SEGADISCSYSTEM"
    data[523] = code
    return bytes(data)


def gc_iso(game_id: bytes, region: int) -> bytes:
    data = bytearray(0x500)
    data[0:6] = game_id
    data[GC_HEADER:GC_HEADER + 4] = region.to_bytes(4, "big")
    return bytes(data)


def md_rom(content: bytes, country: bytes) -> bytes:
    data = bytearray(content.ljust(0x200, b"\0"))
    data[0x1F0:0x1F3] = country
    return bytes(data)


def ps_iso(boot: str) -> bytes:
    """A 2048-byte ISO 9660 image whose root holds SYSTEM.CNF."""
    sectors = [bytearray(2048) for _ in range(20)]
    volume = sectors[16]
    volume[0] = 1
    volume[1:6] = b"CD001"
    root = bytearray(34)
    root[0] = 34
    root[2:6] = (17).to_bytes(4, "little")
    root[10:14] = (2048).to_bytes(4, "little")
    volume[156:190] = root
    name = b"SYSTEM.CNF;1"
    record = bytearray(33 + len(name))
    record[0] = len(record)
    record[2:6] = (18).to_bytes(4, "little")
    text = f"BOOT = cdrom:\\{boot};1\r\n".encode()
    record[10:14] = len(text).to_bytes(4, "little")
    record[32] = len(name)
    record[33:] = name
    sectors[17][0:len(record)] = record
    sectors[18][0:len(text)] = text
    return b"".join(bytes(s) for s in sectors)


class Card:
    """A card in tmp/: BIOS/ and Roms/ at its root, the games index beside
    a saved file list."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.bios = self.root / "card" / "BIOS"
        self.roms = self.root / "card" / "Roms"
        self.bios.mkdir(parents=True)
        self.roms.mkdir()
        self.lists = self.root / "lists"
        (self.lists / "games").mkdir(parents=True)
        self.manifest_path = self.lists / "retroarch.json"
        self.manifest_path.write_text(json.dumps(manifest()))
        write_index(self.lists / "games")
        self.cache = self.root / "cache"

    def game(self, folder: str, name: str, data: bytes = b"game") -> Path:
        path = self.roms / folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def zipped(self, folder: str, name: str, member: str, data: bytes) -> Path:
        path = self.roms / folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, data)
        return path

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class GamesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.card = Card()
        self.addCleanup(self.card.close)
        patches = [mock.patch.dict(os.environ, {"RETROBIOS_CACHE": str(self.card.cache),
                                                install.OFFLINE_VARIABLE: "1"}),
                   mock.patch.object(install.LOCAL, "manifest", self.card.manifest_path),
                   mock.patch.object(install, "GAMES", install.GamesData())]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def plan(self, folder: Path | None = None) -> install.GamesPlan:
        plan = install.plan_games("retroarch", self.card.bios, manifest(), folder,
                                  os_type="linux")
        self.assertIsNotNone(plan)
        return plan

    def kept(self, plan: install.GamesPlan, prefix: str = "", required: bool = False) -> list:
        return sorted(dest for dest in plan.wanted(required) if dest.startswith(prefix))


class Identification(GamesTestCase):
    def test_a_cartridge_is_known_by_crc32_and_size(self):
        self.card.game("MD", "anything.md", MD_EU)
        plan = self.plan()
        game = plan.games[0]
        self.assertTrue(game.recognised)
        self.assertEqual(game.title, "Game (Europe)")
        self.assertEqual(game.dat_regions, frozenset({"europe"}))

    def test_a_zip_member_is_known_from_the_central_directory(self):
        self.card.zipped("MD", "z.zip", "rom.md", MD_ZIPPED)
        with mock.patch.object(install, "_crc32_file") as hashed:
            plan = self.plan()
        hashed.assert_not_called()
        self.assertTrue(plan.games[0].recognised)
        self.assertEqual(plan.games[0].dat_regions, frozenset({"north-america"}))

    def test_a_disc_serial_from_system_cnf(self):
        self.card.game("PS", "game.iso", ps_iso("SLES_000.01"))
        game = self.plan().games[0]
        self.assertTrue(game.recognised)
        self.assertEqual(game.title, "SLES_000.01")

    def test_a_chd_is_not_read(self):
        self.card.game("PS", "game.chd", b"MComprHD")
        game = self.plan().games[0]
        self.assertFalse(game.read)
        self.assertFalse(game.recognised)

    def test_files_a_cue_names_are_part_of_its_game(self):
        self.card.game("SEGACD", "g.cue", b'FILE "g.bin" BINARY\n  TRACK 01 MODE1/2048\n')
        self.card.game("SEGACD", "g.bin", mcd_iso(100))
        plan = self.plan()
        self.assertEqual([game.shown for game in plan.games], ["SEGACD/g.cue"])
        self.assertEqual(install.core_regions(plan.games[0], "sega-megacd",
                                              install.SystemData(SYSTEMS["sega-megacd"]),
                                              "picodrive"), frozenset({"europe"}))

    def test_hidden_media_and_other_files_are_not_games(self):
        self.card.game("MD", ".hidden.md", MD_EU)
        self.card.game("MD", "Imgs/cover.md", MD_EU)
        self.card.game("MD", "notes.txt", b"x")
        self.card.game("MD", "game.md", MD_EU)
        plan = self.plan()
        self.assertEqual([game.shown for game in plan.games], ["MD/game.md"])
        self.assertEqual(plan.not_games, 1)

    def test_a_folder_of_whole_names_holds_only_those_files(self):
        root = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, root, True)
        for name in ("C3.EXE", "c3.eng", "readme.txt"):
            (root / name).write_bytes(b"x")
        games, others = install.folder_games(install.GameFolder(root, {"files": ["c3.exe"]}), None, 50)
        self.assertEqual([game.name for game in games], ["C3.EXE"])
        self.assertEqual(others, 2)

    def test_a_folder_the_setup_does_not_list_holds_no_game(self):
        self.card.game("UNKNOWN", "game.md", MD_EU)
        self.card.game("PORTS", "game.sh", b"x")
        self.assertEqual(self.plan().games, [])

    def test_a_raw_cd_image_with_its_mode(self):
        user = mcd_iso(161)
        raw = bytearray()
        for index in range(len(user) // 2048):
            sector = bytearray(2352)
            sector[0:12] = b"\x00" + b"\xff" * 10 + b"\x00"
            sector[15] = 1
            sector[16:16 + 2048] = user[index * 2048:(index + 1) * 2048]
            raw += sector
        self.card.game("SEGACD", "g.bin", bytes(raw))
        plan = self.plan()
        self.assertEqual(self.kept(plan, "bios_CD"), ["bios_CD_J.bin"])


class RegionMatrix(GamesTestCase):
    """What each kind of evidence lets the run remove (research section 2)."""

    def test_a_header_read_keeps_the_region_it_proves(self):
        self.card.game("SEGACD", "sonic.iso", mcd_iso(100))
        plan = self.plan()
        self.assertEqual(self.kept(plan, "bios_CD"), ["bios_CD_E.bin"])
        self.assertEqual(plan.systems["sega-megacd"]["regions"], ["europe"])
        self.assertEqual(plan.fallback, [])

    def test_a_value_the_code_reads_as_its_default_is_a_proof(self):
        self.card.game("SEGACD", "us.iso", mcd_iso(7))
        self.assertEqual(self.kept(self.plan(), "bios_CD"), ["bios_CD_U.bin"])

    def test_two_games_keep_both_regions(self):
        self.card.game("SEGACD", "a.iso", mcd_iso(100))
        self.card.game("SEGACD", "b.iso", mcd_iso(161))
        self.assertEqual(self.kept(self.plan(), "bios_CD"), ["bios_CD_E.bin", "bios_CD_J.bin"])

    def test_a_hash_match_keeps_the_catalog_region(self):
        self.card.game("MD", "eu.md", MD_EU)
        self.assertEqual(self.kept(self.plan(), "md_"), ["md_eu.bin", "md_tmss.bin"])

    def test_a_filename_tag_alone_keeps_every_region(self):
        self.card.game("SEGACD", "Sonic CD (Europe).iso", b"no header here" * 200)
        plan = self.plan()
        self.assertEqual(self.kept(plan, "bios_CD"),
                         ["bios_CD_E.bin", "bios_CD_J.bin", "bios_CD_U.bin"])
        self.assertEqual([(g.shown, g.reason) for g in plan.fallback],
                         [("SEGACD/Sonic CD (Europe).iso", "not_recognised")])

    def test_folder_only_keeps_every_region_and_names_the_game(self):
        self.card.game("MD", "unknown.md", b"not in any catalog")
        plan = self.plan()
        self.assertEqual(self.kept(plan, "md_"),
                         ["md_eu.bin", "md_jp.bin", "md_tmss.bin", "md_us.bin"])
        self.assertEqual(plan.fallback[0].reason, "not_recognised")
        lines = install.games_lines(plan, None)
        self.assertIn("1 game gets every BIOS of its system: MD/unknown.md (not recognised)",
                      "\n".join(lines))

    def test_one_unproven_game_keeps_every_region_for_all(self):
        self.card.game("SEGACD", "a.iso", mcd_iso(100))
        self.card.game("SEGACD", "b.chd", b"MComprHD")
        plan = self.plan()
        self.assertEqual(len(self.kept(plan, "bios_CD")), 3)
        self.assertEqual([(g.shown, g.reason) for g in plan.fallback],
                         [("SEGACD/b.chd", "not_read")])
        self.assertIsNone(plan.systems["sega-megacd"]["regions"])

    def test_a_catalog_and_a_header_that_disagree_keep_every_region(self):
        self.card.game("MD", "jp.md", md_rom(MD_JP, b"E  "))
        # The catalog matches the whole file: write the header into it first.
        path = self.card.roms / "MD" / "jp.md"
        data = path.read_bytes()
        rows = [[_crc(data), len(data), 1, "Game (Japan)"]]
        systems = json.loads(json.dumps(SYSTEMS))
        systems["sega-megadrive"]["identify"]["games"] = rows
        write_index(self.card.lists / "games", systems=systems)
        plan = self.plan()
        self.assertTrue(plan.games[0].recognised)
        self.assertEqual(plan.games[0].readings["md-country"], frozenset({"europe"}))
        self.assertEqual(len(self.kept(plan, "md_")), 4)
        self.assertEqual(plan.fallback[0].reason, "region_unknown")

    def test_a_multi_region_serial_keeps_its_regions(self):
        self.card.game("GC", "game.iso", gc_iso(b"GALE01", 1))
        plan = self.plan()
        self.assertEqual(self.kept(plan, "dolphin"),
                         ["dolphin/GC/EUR/IPL.bin", "dolphin/GC/USA/IPL.bin"])

    def test_an_unknown_gamecube_region_keeps_every_ipl(self):
        self.card.game("GC", "odd.iso", gc_iso(b"XXXX01", 9))
        self.assertEqual(len(self.kept(self.plan(), "dolphin")), 3)

    def test_a_compressed_gamecube_disc_is_not_read(self):
        self.card.game("GC", "game.rvz", b"RVZ\x01")
        plan = self.plan()
        self.assertEqual(len(self.kept(plan, "dolphin")), 3)
        self.assertEqual(plan.fallback[0].reason, "not_read")

    def test_a_core_with_a_keep_all_case_never_narrows(self):
        self.card.game("PS", "game.iso", ps_iso("SLES_000.01"))
        plan = self.plan()
        self.assertTrue(plan.games[0].recognised)
        self.assertEqual(self.kept(plan, "scph"),
                         ["scph5500.bin", "scph5501.bin", "scph5502.bin"])
        # Nothing the game could have proven changes that: it is not named.
        self.assertEqual(plan.fallback, [])

    def test_a_game_region_no_file_matches_keeps_the_whole_set(self):
        dests = ["a.bin", "b.bin"]
        entries = {"a.bin": {"regions": ["japan"]}, "b.bin": {"regions": ["north-america"]}}
        self.assertEqual(install.keep_regions(dests, entries, frozenset({"europe"}), set()),
                         dests)

    def test_a_country_matches_its_region_and_region_free_files_stay(self):
        dests = ["eu.bin", "us.bin", "free.bin", "world.bin"]
        entries = {"eu.bin": {"regions": ["europe"]}, "us.bin": {"regions": ["north-america"]},
                   "free.bin": {"regions": ["japan"]}, "world.bin": {"regions": ["world"]}}
        self.assertEqual(install.keep_regions(dests, entries, frozenset({"germany"}),
                                              {"free.bin"}),
                         ["eu.bin", "free.bin", "world.bin"])

    def test_routes_send_a_region_to_another_regions_file(self):
        rule = {"routes": {"south-korea": "japan"}}
        self.assertEqual(install.needed_regions(rule, [frozenset({"south-korea"})]),
                         frozenset({"japan"}))


class KeepEveryRegionCases(unittest.TestCase):
    """Every case of games/regions.yml keeps every region where it applies."""

    @classmethod
    def setUpClass(cls) -> None:
        # The installer's own jobs (Python 3.8 with pyte alone) import this
        # module for its card builders, and install.py needs no pyyaml.
        try:
            import yaml  # noqa: PLC0415
        except ImportError as exc:
            raise unittest.SkipTest("pyyaml reads games/regions.yml") from exc
        with open(REPO_ROOT / "games" / "regions.yml", encoding="utf-8") as handle:
            cls.rules = yaml.safe_load(handle)

    def facts(self, name: str) -> install.GameFacts:
        folder = install.GameFolder(Path("x"), {})
        return install.GameFacts(Path(name), name, folder)

    def test_there_are_fourteen_cases_and_each_is_decided(self):
        cases = self.rules["cases"]
        self.assertEqual(len(cases), 14)
        disc_cases = {"first-disc-region", "multi-area-disc", "gamecube-unknown-region",
                      "saturn-kr-ipl"}
        game = [self.facts("game.iso")]
        for name in cases:
            with self.subTest(case=name):
                conditions = {case.get("condition")
                              for system in self.rules["systems"].values()
                              for rule in system.values()
                              for case in rule.get("keep_all_regions") or []
                              if case.get("case") == name}
                self.assertTrue(conditions, f"{name} is named by no rule")
                for condition in conditions:
                    rule = {"keep_all_regions": [{"case": name, "condition": condition}]}
                    keeps = install.region_rule_keeps_all(rule, game)
                    if condition in ("always", "option", "user-state"):
                        self.assertTrue(keeps, (name, condition))
                    else:
                        self.assertIn(name, disc_cases)

    def test_first_disc_region_keeps_every_region_for_a_playlist(self):
        rule = {"keep_all_regions": [{"case": "first-disc-region", "condition": "disc"}]}
        self.assertTrue(install.region_rule_keeps_all(rule, [self.facts("g.m3u")]))
        self.assertFalse(install.region_rule_keeps_all(rule, [self.facts("g.cue")]))

    def test_an_asia_ntsc_or_korean_saturn_disc_keeps_every_region(self):
        rule = {"keep_all_regions": [{"case": "saturn-kr-ipl", "condition": "disc"}]}
        self.assertIsNone(install.needed_regions(rule, [frozenset({"asia-ntsc"})]))
        self.assertIsNone(install.needed_regions(rule, [frozenset({"south-korea"})]))
        self.assertEqual(install.needed_regions(rule, [frozenset({"japan"})]),
                         frozenset({"japan"}))

    def test_a_multi_area_disc_keeps_every_area_it_lists(self):
        rule = {"keep_all_regions": [{"case": "multi-area-disc", "condition": "disc"}]}
        self.assertFalse(install.region_rule_keeps_all(rule, [self.facts("g.iso")]))
        self.assertEqual(install.needed_regions(rule, [frozenset({"japan", "europe"})]),
                         frozenset({"japan", "europe"}))

    def test_an_unknown_gamecube_region_is_no_proof(self):
        system = install.SystemData({"headers": {"cores": {"dolphin": {
            "order": ["gc-region"], "otherwise": "unknown"}}}})
        facts = self.facts("g.iso")
        facts.system = "nintendo-gamecube"
        facts.readings["gc-region"] = "unknown"
        self.assertIsNone(install.core_regions(facts, "nintendo-gamecube", system, "dolphin"))

    def test_no_rule_read_and_a_case_not_known_keep_every_region(self):
        game = [self.facts("g.iso")]
        self.assertTrue(install.region_rule_keeps_all(None, game))
        self.assertTrue(install.region_rule_keeps_all(
            {"keep_all_regions": [{"case": "new-case", "condition": "disc"}]}, game))

    def test_every_rule_of_the_repository_is_read_without_error(self):
        game = [self.facts("g.iso")]
        for system, cores in self.rules["systems"].items():
            for core, rule in cores.items():
                with self.subTest(system=system, core=core):
                    install.region_rule_keeps_all(rule, game)


class Arcade(GamesTestCase):
    def test_a_set_gets_its_bios_parent_from_the_whole_list(self):
        self.card.game("FBNEO", "mslug.zip", b"PK")
        plan = self.plan()
        self.assertEqual(self.kept(plan), ["fbneo/neogeo.zip", "neogeo.zip"])
        self.assertEqual(self.kept(plan, required=True), ["fbneo/neogeo.zip", "neogeo.zip"])

    def test_a_set_with_no_bios_needs_nothing(self):
        self.card.game("FBNEO", "pacman.zip", b"PK")
        plan = self.plan()
        self.assertEqual(self.kept(plan), [])
        self.assertTrue(plan.games[0].recognised)

    def test_a_bios_set_on_the_card_is_not_a_game(self):
        self.card.game("FBNEO", "neogeo.zip", b"PK")
        plan = self.plan()
        self.assertEqual(plan.games, [])
        self.assertEqual(plan.support, 1)

    def test_an_unknown_set_gets_every_bios_set_of_the_core(self):
        self.card.game("FBNEO", "zzzz.zip", b"PK")
        plan = self.plan()
        self.assertEqual(self.kept(plan),
                         ["fbneo/msx.zip", "fbneo/neogeo.zip", "fbneo/pgm.zip",
                          "fbneo/samples/big.zip"])
        self.assertEqual([(g.shown, g.reason) for g in plan.fallback],
                         [("FBNEO/zzzz.zip", "unknown_set")])

    def test_a_console_set_is_read_under_its_driver_name(self):
        # msx_1942 loads the MSX BIOS, the arcade 1942 needs none.
        self.card.game("MSX", "1942.zip", b"PK")
        plan = self.plan()
        self.assertEqual(self.kept(plan), ["fbneo/msx.zip"])
        self.assertEqual(plan.games[0].title, "msx_1942")

    def test_an_arcade_folder_reads_the_bare_set_name(self):
        self.card.game("FBNEO", "1942.zip", b"PK")
        plan = self.plan()
        self.assertEqual(self.kept(plan), [])
        self.assertTrue(plan.games[0].recognised)

    def test_a_console_bios_on_the_card_is_not_a_game(self):
        self.card.game("MSX", "msx.zip", b"PK")
        self.assertEqual(self.plan().support, 1)

    def test_a_parent_the_list_does_not_hold_falls_back(self):
        self.card.game("FBNEO", "lost.zip", b"PK")
        plan = self.plan()
        self.assertEqual(plan.fallback[0].reason, "no_parent")
        self.assertIn("fbneo/neogeo.zip", plan.keep)


class RequiredOnlyAndExtras(GamesTestCase):
    def test_required_only_leaves_out_what_the_set_marks_optional(self):
        self.card.game("MD", "eu.md", MD_EU)
        plan = self.plan()
        self.assertEqual(self.kept(plan, "md_"), ["md_eu.bin", "md_tmss.bin"])
        self.assertEqual(self.kept(plan, "md_", required=True), ["md_eu.bin"])

    def test_a_required_extra_the_game_triggers_stays(self):
        self.card.game("SEGACD", "sonic.iso", mcd_iso(100))
        plan = self.plan()
        self.assertIn("cd_extra.bin", plan.required)

    def test_apply_keeps_the_entries_and_the_omissions_of_the_games(self):
        self.card.game("MD", "eu.md", MD_EU)
        plan = self.plan()
        omitted = [{"dest": "md_missing.bin", "systems": ["sega-megadrive"], "required": False},
                   {"dest": "other.bin", "systems": ["nintendo-gba"], "required": True}]
        files, kept_omitted = plan.apply(manifest()["files"], omitted, False)
        self.assertEqual(sorted(e["dest"] for e in files), ["md_eu.bin", "md_tmss.bin"])
        self.assertEqual([o["dest"] for o in kept_omitted], ["md_missing.bin"])
        _files, kept_omitted = plan.apply(manifest()["files"], omitted, True)
        self.assertEqual(kept_omitted, [])

    def test_a_board_default_core_adds_its_set(self):
        self.card.game("GBA", "game.gba", b"gba game")
        plan = self.plan()
        # mgba marks the BIOS optional, gpsp (a board's default) requires it.
        self.assertEqual(self.kept(plan, "gba", required=True), ["gba_bios.bin"])


class Folders(GamesTestCase):
    def test_a_games_folder_named_on_a_computer_is_read_by_folder_names(self):
        games = self.card.root / "pc games"
        (games / "megadrive").mkdir(parents=True)
        (games / "megadrive" / "eu.md").write_bytes(MD_EU)
        setup = dict(SETUP, folders=[])
        write_index(self.card.lists / "games", setup=setup)
        plan = self.plan(games)
        self.assertFalse(plan.card)
        self.assertEqual(plan.where(), "in this folder")
        self.assertEqual(plan.unknown_core, ["sega-megadrive"])
        # The core is not known: every set of the system is read.
        self.assertIn("md_eu.bin", plan.keep)

    def test_a_folder_of_one_system_named_alone(self):
        folder = self.card.roms / "MD"
        folder.mkdir()
        (folder / "eu.md").write_bytes(MD_EU)
        plan = self.plan(folder)
        self.assertEqual(len(plan.games), 1)

    def test_no_rom_folder_beside_the_bios_folder(self):
        shutil.rmtree(self.card.roms)
        self.assertIsNone(install.plan_games("retroarch", self.card.bios, manifest(),
                                             os_type="linux"))

    def test_the_probe_counts_folders_holding_a_game(self):
        self.card.game("MD", "eu.md", MD_EU)
        self.card.game("PS", "a.chd", b"x")
        (self.card.roms / "GBA").mkdir()
        self.assertEqual(install.games_probe("retroarch", self.card.bios, network=False,
                                             os_type="linux"), 2)

    def test_the_probe_says_nothing_without_a_rom_folder(self):
        shutil.rmtree(self.card.roms)
        self.assertIsNone(install.games_probe("retroarch", self.card.bios, network=False,
                                              os_type="linux"))


class Cache(GamesTestCase):
    def test_a_second_run_hashes_nothing_that_did_not_change(self):
        game = self.card.game("MD", "eu.md", MD_EU)
        counted = []
        real = install._crc32_file

        def counting(path):
            counted.append(path)
            return real(path)

        with mock.patch.object(install, "_crc32_file", side_effect=counting):
            self.plan()
            self.assertEqual(len(counted), 1)
            install.GAMES.reset()
            plan = self.plan()
            self.assertEqual(len(counted), 1)
            self.assertTrue(plan.games[0].recognised)
            game.write_bytes(MD_JP)
            plan = self.plan()
            self.assertEqual(len(counted), 2)
            self.assertEqual(plan.games[0].dat_regions, frozenset({"japan"}))

    def test_the_index_is_cached_and_read_offline_without_the_list_beside_it(self):
        self.card.game("MD", "eu.md", MD_EU)
        index = (self.card.lists / "games" / "index.json").read_bytes()
        cached = self.card.cache / "games"
        cached.mkdir(parents=True)
        (cached / "index.json").write_bytes(index)
        for path in (self.card.lists / "games").rglob("*.json"):
            if path.name != "index.json":
                data = path.read_bytes()
                (cached / f"{hashlib.sha256(data).hexdigest()}.json").write_bytes(data)
        shutil.rmtree(self.card.lists / "games")
        install.GAMES.reset()
        self.assertTrue(self.plan().games[0].recognised)


class Unavailable(GamesTestCase):
    def test_offline_with_no_index_is_said(self):
        shutil.rmtree(self.card.lists / "games")
        with self.assertRaises(install.GamesUnavailable) as caught:
            install.plan_games("retroarch", self.card.bios, manifest(), os_type="linux")
        self.assertEqual(caught.exception.reason, "offline")

    def test_a_failed_download_says_why(self):
        """The cause was printed only under RETROBIOS_DEBUG: a proxy's 403
        or a TLS refusal read as a bare "could not be downloaded"."""
        shutil.rmtree(self.card.lists / "games")
        refusal = urllib.error.HTTPError(
            "https://example.invalid/index.json", 403, "Forbidden", {}, None)
        with mock.patch.object(install, "_fetch_json", side_effect=refusal), \
                self.assertRaises(install.GamesUnavailable) as caught:
            install.GamesData().load_index(network=True, attempts=1)
        self.assertEqual(caught.exception.reason, "network")
        self.assertIn("403", caught.exception.words)

    def test_a_document_that_is_not_the_one_listed_is_refused(self):
        (self.card.lists / "games" / "setups" / "retroarch.json").write_text("{}")
        with self.assertRaises(install.GamesUnavailable) as caught:
            install.plan_games("retroarch", self.card.bios, manifest(), os_type="linux")
        self.assertEqual(caught.exception.reason, "offline")

    def test_an_index_that_names_a_file_the_list_lacks_is_stale(self):
        self.card.game("MD", "x.md", b"unknown")
        listed = manifest()
        listed["files"] = [e for e in listed["files"] if e["dest"] != "md_us.bin"]
        with self.assertRaises(install.GamesUnavailable) as caught:
            install.plan_games("retroarch", self.card.bios, listed, os_type="linux")
        self.assertEqual(caught.exception.reason, "stale")


def run_cli(card: Card, *options: str, offline: bool = True,
            base: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "RETROBIOS_CACHE": str(card.cache)}
    env.pop(install.OFFLINE_VARIABLE, None)
    if base:
        env["RETROBIOS_BASE_URL"] = base
    command = [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retroarch",
               "--dest", str(card.bios), *options]
    if offline:
        command += ["--offline", "--manifest", str(card.manifest_path)]
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=120,
                          check=False, stdin=subprocess.DEVNULL)


class CommandLine(unittest.TestCase):
    def setUp(self) -> None:
        self.card = Card()
        self.addCleanup(self.card.close)
        self.card.game("SEGACD", "sonic.iso", mcd_iso(100))
        self.card.game("MD", "odd.md", b"not in the catalog")

    def events(self, proc: subprocess.CompletedProcess) -> list[dict]:
        return [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]

    def test_check_narrows_to_what_the_games_need(self):
        proc = run_cli(self.card, "--for-games", "--check", "--events")
        events = self.events(proc)
        games = next(e for e in events if e["event"] == "games")
        self.assertEqual(games["games"], 2)
        self.assertEqual(games["fallback"], [{"system": "sega-megadrive", "folder": "MD",
                                              "name": "MD/odd.md",
                                              "reason": "not_recognised"}])
        self.assertEqual(sorted(set(games)), sorted(["event", *install.EVENT_KEYS["games"]]))
        dests = sorted(e["dest"] for e in events if e["event"] == "file")
        self.assertEqual(dests, ["bios_CD_E.bin", "cd_extra.bin", "md_eu.bin", "md_jp.bin",
                                 "md_tmss.bin", "md_us.bin"])
        self.assertIn("1 game gets every BIOS of its system", proc.stderr)

    def test_required_only_leaves_out_the_optional_files(self):
        proc = run_cli(self.card, "--for-games", "--required-only", "--check", "--events")
        dests = sorted(e["dest"] for e in self.events(proc) if e["event"] == "file")
        self.assertEqual(dests, ["bios_CD_E.bin", "cd_extra.bin", "md_eu.bin", "md_jp.bin",
                                 "md_us.bin"])

    def test_required_only_alone_is_refused(self):
        proc = run_cli(self.card, "--required-only", "--check")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--required-only applies to --for-games", proc.stderr)

    def test_a_listing_refuses_it(self):
        proc = run_cli(self.card, "--for-games", "--list-systems")
        self.assertEqual(proc.returncode, 2)

    def test_a_games_folder_that_does_not_exist_stops_the_run(self):
        proc = run_cli(self.card, "--for-games", str(self.card.root / "nowhere"), "--check")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("does not exist", proc.stderr)

    def test_offline_without_the_index_keeps_every_file_and_says_so(self):
        shutil.rmtree(self.card.lists / "games")
        proc = run_cli(self.card, "--for-games", "--check", "--events")
        events = self.events(proc)
        unavailable = next(e for e in events if e["event"] == "games_unavailable")
        self.assertEqual(unavailable["reason"], "offline")
        self.assertEqual(len([e for e in events if e["event"] == "file"]), len(FILES))
        self.assertIn("Every file of the list is kept", proc.stderr)

    def test_a_system_choice_narrows_what_the_games_keep(self):
        proc = run_cli(self.card, "--for-games", "--system", "sega-megacd", "--check",
                       "--events")
        dests = sorted(e["dest"] for e in self.events(proc) if e["event"] == "file")
        # cd_extra.bin names no system: a system choice leaves it, as without
        # --for-games.
        self.assertEqual(dests, ["bios_CD_E.bin"])

    def test_the_install_writes_only_what_the_games_need(self):
        self.card.game("MD", "eu.md", MD_EU)
        root = self.card.root / "repo"
        (root / "install").mkdir(parents=True)
        shutil.copytree(self.card.lists / "games", root / "install" / "games")
        listed = manifest()
        (root / "bios").mkdir()
        for entry in listed["files"]:
            payload = entry["dest"].encode().ljust(entry["size"], b".")[:entry["size"]]
            (root / entry["repo_path"]).write_bytes(payload)
        (root / "install" / "retroarch.json").write_text(json.dumps(listed))
        handler = functools.partial(_Quiet, directory=str(root))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        proc = run_cli(self.card, "--for-games", "--required-only", "--yes", offline=False,
                       base=base)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        written = sorted(p.relative_to(self.card.bios).as_posix()
                         for p in self.card.bios.rglob("*") if p.is_file())
        self.assertEqual(written, ["bios_CD_E.bin", "cd_extra.bin", "md_eu.bin", "md_jp.bin",
                                   "md_us.bin"])
        self.assertIn("1 game gets every BIOS of its system", proc.stdout)
        # Cached for the next run, offline.
        self.assertTrue((self.card.cache / "games" / "index.json").is_file())
        self.assertTrue((self.card.cache / install.GAMES_SCAN_FILE).is_file())


class AMuosCardNamedByItsList(unittest.TestCase):
    """The full screen passes --platform=retroarch for a muOS card, and the
    run said no games folder was found beside MUOS/bios, where line mode,
    which had detected the card, read ROMS/."""

    def test_the_card_its_bios_folder_is_on_names_its_rom_folders(self):
        card = Card()
        self.addCleanup(card.close)
        root = card.root / "MUOSCARD"
        card.bios = root / "MUOS" / "bios"
        card.bios.mkdir(parents=True)
        game = root / "ROMS" / "MD" / "eu.md"
        game.parent.mkdir(parents=True)
        game.write_bytes(MD_EU)
        muos = dict(SETUP, setup="muos", name="muOS",
                    roms_root={"path": "/mnt/mmc/ROMS", "from_bios": "../../ROMS"})
        # RetroArch's own setup names no rom folder (configuration.c).
        retroarch = dict(SETUP, roms_root={"path": None, "from_bios": None})
        write_index(card.lists / "games", setup=retroarch, more_setups={"muos": muos})
        proc = run_cli(card, "--for-games", "--check", "--events")
        events = [json.loads(line) for line in proc.stdout.splitlines()
                  if line.startswith("{")]
        self.assertEqual([e for e in events if e["event"] == "games_unavailable"], [])
        games = next(e for e in events if e["event"] == "games")
        self.assertEqual(games["folder"], str(root / "ROMS"))
        self.assertEqual(games["games"], 1)


class ARunThatAsksNothing(unittest.TestCase):
    """`--yes` alone installed the whole list (6.4 GB on a dArkOS card that
    held two games), while the screen offers what the games need first."""

    def install(self, *options: str) -> tuple[list[str], str]:
        card = Card()
        self.addCleanup(card.close)
        card.game("SEGACD", "sonic.iso", mcd_iso(100))
        card.game("MD", "eu.md", MD_EU)
        root = card.root / "repo"
        (root / "install").mkdir(parents=True)
        shutil.copytree(card.lists / "games", root / "install" / "games")
        listed = manifest()
        (root / "bios").mkdir()
        for entry in listed["files"]:
            payload = entry["dest"].encode().ljust(entry["size"], b".")[:entry["size"]]
            (root / entry["repo_path"]).write_bytes(payload)
        (root / "install" / "retroarch.json").write_text(json.dumps(listed))
        handler = functools.partial(_Quiet, directory=str(root))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        proc = run_cli(card, *options, offline=False,
                       base=f"http://127.0.0.1:{server.server_address[1]}")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return sorted(p.relative_to(card.bios).as_posix()
                      for p in card.bios.rglob("*") if p.is_file()), proc.stdout

    def test_it_installs_what_the_games_need(self):
        unasked, said = self.install("--yes")
        self.assertEqual(unasked, self.install("--for-games", "--yes")[0])
        self.assertIn("--all-files installs the whole list", said)

    def test_all_files_installs_the_whole_list(self):
        everything, said = self.install("--all-files", "--yes")
        self.assertEqual(everything, sorted(entry["dest"] for entry in manifest()["files"]))
        self.assertNotIn("For the games", said)

    def test_all_files_and_for_games_are_refused_together(self):
        card = Card()
        self.addCleanup(card.close)
        proc = run_cli(card, "--all-files", "--for-games", "--check")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--all-files and --for-games ask for two different lists", proc.stderr)


class DataTreesFollowTheGamesCores(unittest.TestCase):
    """One GBA and one SNES game took FBNeo's cheats and samples: a tree
    only cores read is kept when the plan runs one of them."""

    def test_a_tree_of_a_core_the_plan_does_not_run_is_left_out(self):
        plan = install.GamesPlan(Path("card"), True)
        plan.profiles = {"snes9x"}
        fbneo = {"ref": "fbneo-cheats", "systems": ["nintendo-snes"], "cores": ["fbneo"]}
        dolphin = {"ref": "dolphin-sys", "systems": ["nintendo-snes"]}
        trees = {"data_directories": [fbneo, dolphin]}
        files = [{"dest": "a.bin", "systems": ["nintendo-snes"]}]
        self.assertEqual(install.select_data_directories(trees, files, True, games=plan), [dolphin])
        plan.profiles.add("fbneo")
        self.assertEqual(install.select_data_directories(trees, files, True, games=plan),
                         [fbneo, dolphin])

    def test_a_system_with_no_named_core_keeps_every_cores_tree(self):
        plan = install.GamesPlan(Path("card"), True)
        plan.any_core = {"nintendo-gba"}
        fbneo = {"ref": "fbneo-cheats", "systems": ["nintendo-gba"], "cores": ["fbneo"]}
        self.assertEqual(install.select_data_directories(
            {"data_directories": [fbneo]}, [{"systems": ["nintendo-gba"]}], True, games=plan),
            [fbneo])


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        return


class LineMenu(GamesTestCase):
    def menu(self, answers: list[str], given: object = None) -> tuple[object, str]:
        self.card.game("SEGACD", "sonic.iso", mcd_iso(100))
        plan = self.plan()
        listed = manifest()
        replies = iter(answers)
        out = io.StringIO()
        with mock.patch.object(install, "_ask", side_effect=lambda _p: next(replies)), \
                contextlib.redirect_stdout(out):
            choice = install._prompt_custom_selection(
                "retroarch", listed["files"], [], manifest=listed, played=plan, given=given,
                command=lambda choice: install._INVOCATION.command("retroarch", "<dest>"))
        return choice, out.getvalue()

    def test_the_games_are_the_first_choice(self):
        choice, text = self.menu([""])
        self.assertIsInstance(choice, install.GamesChoice)
        self.assertFalse(choice.required)
        self.assertIn("for the 1 game on this card", text)
        self.assertIn("e) everything, whatever the games", text)
        self.assertIn(f"r) {install.GAMES_REQUIRED_WORDS}", text)

    def test_e_installs_everything_and_h_goes_back(self):
        choice, text = self.menu(["e", ""])
        self.assertIsNone(choice)
        self.assertIn("h) only for the games on this card", text)
        choice, _text = self.menu(["e", "h", ""])
        self.assertIsInstance(choice, install.GamesChoice)

    def test_r_keeps_only_what_starts(self):
        choice, text = self.menu(["r", ""])
        self.assertTrue(choice.required)
        self.assertIn("r) every file the games read", text)
        self.assertEqual(choice.flags(), [("--for-games", None), ("--required-only", None)])

    def test_the_choice_is_given_back_as_a_command(self):
        self.card.game("SEGACD", "sonic.iso", mcd_iso(100))
        plan = self.plan()
        self.assertEqual(install.chosen_flags(install.GamesChoice(plan)),
                         [("--for-games", None)])
        named = install.plan_games("retroarch", self.card.bios, manifest(), self.card.roms,
                                   os_type="linux")
        self.assertEqual(install.GamesChoice(named).flags(),
                         [("--for-games", str(self.card.roms))])


class Published(unittest.TestCase):
    """The repository's own index, as a run reads it."""

    def test_a_card_reads_with_the_published_index(self):
        if not (REPO_ROOT / "install" / "games" / "index.json").exists():
            self.skipTest("install/games/ not generated")
        root = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(shutil.rmtree, root, True)
        bios = root / "userdata" / "bios"
        bios.mkdir(parents=True)
        (root / "userdata" / "roms" / "fbneo").mkdir(parents=True)
        (root / "userdata" / "roms" / "fbneo" / "mslug.zip").write_bytes(b"PK")
        (root / "userdata" / "roms" / "fbneo" / "pacman.zip").write_bytes(b"PK")
        with mock.patch.object(install.LOCAL, "manifest", REPO_ROOT / "install" / "batocera.json"), \
                mock.patch.object(install, "GAMES", install.GamesData()), \
                mock.patch.dict(os.environ, {"RETROBIOS_CACHE": str(root / "cache"),
                                             install.OFFLINE_VARIABLE: "1"}):
            listed = json.loads((REPO_ROOT / "install" / "batocera.json").read_text())
            plan = install.plan_games("batocera", bios, listed, os_type="linux")
        self.assertEqual(len(plan.games), 2)
        self.assertEqual(plan.fallback, [])
        self.assertIn("neogeo.zip", plan.required)
        self.assertTrue(all(dest.lower().endswith("neogeo.zip") for dest in plan.required))

    def test_every_published_setup_resolves_a_root_layout(self):
        index = json.loads((REPO_ROOT / "install" / "games" / "index.json").read_text())
        for key in index["setups"]:
            doc = json.loads((REPO_ROOT / "install" / "games" / "setups"
                              / f"{key}.json").read_text())
            with self.subTest(setup=key):
                self.assertIn("from_bios", doc["roms_root"])


if __name__ == "__main__":
    unittest.main()
