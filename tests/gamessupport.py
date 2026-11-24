"""The games on a card the installer tests read: the games index, the BIOS list, disc and cartridge images, a card."""

from __future__ import annotations

import tests

import gzip
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from tests import loopback


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
                     "games": sorted([[loopback.crc(MD_EU), len(MD_EU), 0, "Game (Europe)"],
                                      [loopback.crc(MD_JP), len(MD_JP), 1, "Game (Japan)"],
                                      [loopback.crc(MD_ZIPPED), len(MD_ZIPPED), 2, "Zipped (USA)"]]),
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
        self.root = Path(tempfile.mkdtemp())
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
