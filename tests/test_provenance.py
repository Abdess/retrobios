"""Tests for dump-catalog provenance: parsers, importers, join, report."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.common import (
    annotate_provenance,
    build_provenance_index,
    load_provenance_snapshots,
    write_provenance_snapshot,
)
from scripts.provenance_report import build_report
from scripts.scraper.dat_pack_importer import _bios_entries, import_pack
from scripts.scraper.logiqx_parser import parse_logiqx, validate_logiqx_format
from scripts.scraper.redump_dat_scraper import discover_bios_datfiles, parse_redump_dat

LOGIQX_GAME_FIXTURE = """<?xml version="1.0"?>
<datafile>
  <header>
    <name>Nintendo - Game Boy Advance</name>
    <version>20260801-123456</version>
  </header>
  <game name="[BIOS] Game Boy Advance (World)">
    <description>[BIOS] Game Boy Advance (World)</description>
    <rom name="[BIOS] Game Boy Advance (World).gba" size="16384" crc="81977335"
         md5="A860E8C0B6D573D191E4EC7DB1B1E4F6" sha1="300C20DF6731A33952DED8C436F7F186D25D3492"/>
  </game>
  <game name="Some Game (USA)">
    <description>Some Game (USA)</description>
    <rom name="Some Game (USA).gba" size="8388608" crc="caf2e99f"
         md5="55354d9e3bc9c1fa682b5110e5ed1544" sha1="6e4e9be9a07580ef267be9c2ea1bd0730b3be44a"/>
  </game>
</datafile>
"""

LOGIQX_MACHINE_FIXTURE = """<?xml version="1.0"?>
<datafile>
  <header>
    <name>Sony - PlayStation - BIOS Images</name>
    <version>2026-06-16</version>
  </header>
  <machine name="ps-10j">
    <description>SCPH-1000/DTL-H1000 (Version 1.0 J)</description>
    <rom name="ps-10j.bin" size="524288" crc="3b601fc8"
         md5="239665b1a3dade1b5a52c06338011044" sha1="343883a7b555646da8cee54aadd2795b6e7dd070"/>
  </machine>
  <machine name="multi-rom">
    <description>Two chips</description>
    <rom name="chip1.bin" size="10" crc="11111111" md5="aa" sha1="bb"/>
    <rom name="chip2.bin" size="20" crc="22222222" md5="cc" sha1="dd"/>
  </machine>
</datafile>
"""

TOSEC_FIRMWARE_FIXTURE = """<?xml version="1.0"?>
<datafile>
  <header>
    <name>Sega Dreamcast - Firmware</name>
    <version>TOSEC-v2025-03-13</version>
  </header>
  <game name="Dreamcast BIOS v1.01d (1998)(Sega)(JP)">
    <description>Dreamcast BIOS v1.01d (1998)(Sega)(JP)</description>
    <rom name="dc_boot.bin" size="2097152" crc="89f2b1a1"
         md5="e10c53c2f8b90bab96ead2d368858623" sha1="4e9db27eb9bcd8d19d346b7c8a1ea307debbf9c9"/>
  </game>
</datafile>
"""


class TestLogiqxParser(unittest.TestCase):
    def test_parse_header_and_games(self):
        dat = parse_logiqx(LOGIQX_GAME_FIXTURE)
        self.assertEqual(dat.name, "Nintendo - Game Boy Advance")
        self.assertEqual(dat.version, "20260801-123456")
        self.assertEqual(len(dat.roms), 2)
        bios = dat.roms[0]
        self.assertEqual(bios.game, "[BIOS] Game Boy Advance (World)")
        self.assertEqual(bios.name, "[BIOS] Game Boy Advance (World).gba")
        self.assertEqual(bios.size, 16384)

    def test_hashes_lowercased(self):
        dat = parse_logiqx(LOGIQX_GAME_FIXTURE)
        bios = dat.roms[0]
        self.assertEqual(bios.md5, "a860e8c0b6d573d191e4ec7db1b1e4f6")
        self.assertEqual(bios.sha1, "300c20df6731a33952ded8c436f7f186d25d3492")

    def test_parse_machine_entries(self):
        dat = parse_logiqx(LOGIQX_MACHINE_FIXTURE)
        self.assertEqual(len(dat.roms), 3)
        self.assertEqual(dat.roms[0].description, "SCPH-1000/DTL-H1000 (Version 1.0 J)")

    def test_multiple_roms_per_machine(self):
        dat = parse_logiqx(LOGIQX_MACHINE_FIXTURE)
        names = [r.name for r in dat.roms if r.game == "multi-rom"]
        self.assertEqual(names, ["chip1.bin", "chip2.bin"])

    def test_invalid_size_defaults_to_zero(self):
        content = LOGIQX_GAME_FIXTURE.replace('size="16384"', 'size="bogus"')
        dat = parse_logiqx(content)
        self.assertEqual(dat.roms[0].size, 0)

    def test_entity_declarations_rejected(self):
        content = (
            '<?xml version="1.0"?><!DOCTYPE datafile [<!ENTITY x "y">]>'
            "<datafile><game name=\"&x;\"><rom name=\"a\"/></game></datafile>"
        )
        with self.assertRaises(ValueError):
            parse_logiqx(content)

    def test_validate_format(self):
        self.assertTrue(validate_logiqx_format(LOGIQX_GAME_FIXTURE))
        self.assertFalse(validate_logiqx_format("clrmamepro ( name x )"))
        self.assertFalse(
            validate_logiqx_format("<datafile><header/><game name='x'/></datafile>")
        )


class TestRedumpScraper(unittest.TestCase):
    def test_discover_bios_datfiles(self):
        html = (
            '<a href="/static/bios/Sony%20PSX.dat">x</a>'
            '<a href="/static/bios/Nintendo%20GC.dat">y</a>'
            '<a href="/datfile/3DO">z</a>'
            '<a href="/static/bios/Sony%20PSX.dat">dup</a>'
        )
        self.assertEqual(
            discover_bios_datfiles(html),
            ["/static/bios/Nintendo%20GC.dat", "/static/bios/Sony%20PSX.dat"],
        )

    def test_parse_redump_dat(self):
        name, version, entries = parse_redump_dat(LOGIQX_MACHINE_FIXTURE)
        self.assertEqual(name, "Sony - PlayStation - BIOS Images")
        self.assertEqual(version, "2026-06-16")
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["dat"], "Sony - PlayStation - BIOS Images")
        self.assertEqual(entries[0]["name"], "ps-10j.bin")
        self.assertEqual(entries[0]["description"], "SCPH-1000/DTL-H1000 (Version 1.0 J)")


class TestPackImporter(unittest.TestCase):
    def test_no_intro_filter_keeps_bios_only(self):
        dat = parse_logiqx(LOGIQX_GAME_FIXTURE)
        entries = _bios_entries("no-intro", dat)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "[BIOS] Game Boy Advance (World).gba")

    def test_tosec_filter_by_dat_name(self):
        firmware = parse_logiqx(TOSEC_FIRMWARE_FIXTURE)
        self.assertEqual(len(_bios_entries("tosec", firmware)), 1)
        games = parse_logiqx(LOGIQX_GAME_FIXTURE)
        self.assertEqual(_bios_entries("tosec", games), [])

    def test_import_pack_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("Nintendo - Game Boy Advance.dat", LOGIQX_GAME_FIXTURE)
                zf.writestr("garbage.dat", "not xml at all")
                zf.writestr("readme.txt", "ignored")
            dats, entries, skipped = import_pack("no-intro", pack)
            self.assertEqual(list(dats), ["Nintendo - Game Boy Advance"])
            self.assertEqual(len(entries), 1)
            self.assertEqual(skipped, 1)

    def test_import_pack_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Sega Dreamcast - Firmware.dat").write_text(
                TOSEC_FIRMWARE_FIXTURE
            )
            dats, entries, skipped = import_pack("tosec", Path(tmp))
            self.assertEqual(list(dats), ["Sega Dreamcast - Firmware"])
            self.assertEqual(len(entries), 1)
            self.assertEqual(skipped, 0)


def _snapshot_entries():
    return [
        {
            "dat": "Sony - PlayStation - BIOS Images",
            "name": "ps-30j.bin",
            "description": "SCPH-5500 (Version 3.0 J)",
            "size": 524288,
            "crc32": "ff3eeb8c",
            "md5": "8dd7d5296a650fac7319bce665a6a53c",
            "sha1": "b05def971d8ec59f346f2d9ac21fb742e3eb6917",
        },
        {
            "dat": "Sony - PlayStation - BIOS Images",
            "name": "ps-41a.bin",
            "description": "SCPH-7001 (Version 4.1 A)",
            "size": 524288,
            "crc32": "502224b6",
            "md5": "1e68c231d0896b7eadcad1d7d8e76129",
            "sha1": "14df4f6c1e367ce097c11deae21566b4fe5647a9",
        },
        {
            "dat": "Sony - PlayStation - BIOS Images",
            "name": "no-sha1.bin",
            "description": "Entry without sha1",
            "size": 1024,
            "crc32": "deadbeef",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "",
        },
    ]


class TestProvenanceJoin(unittest.TestCase):
    def _snapshots(self):
        return {"redump": {"source": "redump", "entries": _snapshot_entries()}}

    def test_index_by_sha1_and_md5_size(self):
        index = build_provenance_index(self._snapshots())
        redump = index["redump"]
        self.assertIn("b05def971d8ec59f346f2d9ac21fb742e3eb6917", redump["by_sha1"])
        self.assertNotIn("", redump["by_sha1"])
        self.assertIn(
            ("d41d8cd98f00b204e9800998ecf8427e", 1024), redump["by_md5_size"]
        )

    def test_annotate_matches_by_sha1(self):
        files = {
            "b05def971d8ec59f346f2d9ac21fb742e3eb6917": {
                "name": "scph5500.bin",
                "size": 524288,
                "md5": "8dd7d5296a650fac7319bce665a6a53c",
            },
            "0000000000000000000000000000000000000000": {
                "name": "unrelated.bin",
                "size": 42,
                "md5": "ffffffffffffffffffffffffffffffff",
            },
        }
        counts = annotate_provenance(files, self._snapshots())
        self.assertEqual(counts, {"redump": 1})
        match = files["b05def971d8ec59f346f2d9ac21fb742e3eb6917"]["provenance"]
        self.assertEqual(match["redump"]["name"], "ps-30j.bin")
        self.assertEqual(match["redump"]["description"], "SCPH-5500 (Version 3.0 J)")
        self.assertNotIn(
            "provenance", files["0000000000000000000000000000000000000000"]
        )

    def test_annotate_falls_back_to_md5_size(self):
        files = {
            "1111111111111111111111111111111111111111": {
                "name": "other-name.bin",
                "size": 1024,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
            }
        }
        counts = annotate_provenance(files, self._snapshots())
        self.assertEqual(counts, {"redump": 1})
        self.assertEqual(
            files["1111111111111111111111111111111111111111"]["provenance"]["redump"][
                "name"
            ],
            "no-sha1.bin",
        )

    def test_annotate_pops_stale_provenance(self):
        files = {
            "2222222222222222222222222222222222222222": {
                "name": "was-matched.bin",
                "size": 5,
                "md5": "00000000000000000000000000000000",
                "provenance": {"redump": {"dat": "old", "name": "old.bin"}},
            }
        }
        annotate_provenance(files, self._snapshots())
        self.assertNotIn(
            "provenance", files["2222222222222222222222222222222222222222"]
        )

    def test_annotate_without_snapshots(self):
        files = {"aa": {"name": "x.bin", "size": 1, "md5": "bb"}}
        self.assertEqual(annotate_provenance(files, {}), {})
        self.assertNotIn("provenance", files["aa"])


class TestSnapshotIO(unittest.TestCase):
    def test_write_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "redump.json"
            written = write_provenance_snapshot(
                str(path),
                "redump",
                "2026-08-07",
                {"Sony - PlayStation - BIOS Images": "2026-06-16"},
                _snapshot_entries(),
            )
            self.assertTrue(written)
            snapshots = load_provenance_snapshots(tmp)
            self.assertEqual(list(snapshots), ["redump"])
            self.assertEqual(len(snapshots["redump"]["entries"]), 3)
            names = [e["name"] for e in snapshots["redump"]["entries"]]
            self.assertEqual(names, sorted(names))

    def test_rewrite_with_new_date_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "redump.json")
            write_provenance_snapshot(
                path, "redump", "2026-08-07", {}, _snapshot_entries()
            )
            rewritten = write_provenance_snapshot(
                path, "redump", "2027-01-01", {}, _snapshot_entries()
            )
            self.assertFalse(rewritten)

    def test_load_missing_dir(self):
        self.assertEqual(load_provenance_snapshots("does/not/exist"), {})

    def test_load_ignores_empty_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "empty.json").write_text(
                json.dumps({"source": "tosec", "entries": []})
            )
            self.assertEqual(load_provenance_snapshots(tmp), {})


class TestProvenanceReport(unittest.TestCase):
    def test_build_report_matched_and_missing(self):
        db = {
            "files": {
                "b05def971d8ec59f346f2d9ac21fb742e3eb6917": {
                    "name": "scph5500.bin",
                    "size": 524288,
                    "md5": "8dd7d5296a650fac7319bce665a6a53c",
                }
            }
        }
        snapshots = {
            "redump": {
                "source": "redump",
                "imported_at": "2026-08-07",
                "dats": {"Sony - PlayStation - BIOS Images": "2026-06-16"},
                "entries": _snapshot_entries(),
            }
        }
        report = build_report(db, snapshots)
        self.assertEqual(report["redump"]["total"], 3)
        self.assertEqual(report["redump"]["matched"], 1)
        missing = [e["name"] for e in report["redump"]["missing"]]
        self.assertEqual(missing, ["ps-41a.bin", "no-sha1.bin"])
        self.assertEqual(report["redump"]["out_of_scope"], 0)
        self.assertEqual(
            report["redump"]["covered_dats"], ["Sony - PlayStation - BIOS Images"]
        )

    def test_uncovered_dat_entries_are_out_of_scope(self):
        """Entries from a DAT the collection never matches are not targets.

        No-Intro tags digital title distribution "[BIOS]" too, so an
        uncovered DAT must not swamp the acquisition list.
        """
        entries = _snapshot_entries() + [
            {
                "dat": "Nintendo - Wii U (Digital) (CDN)",
                "name": "00000001.app",
                "description": "[BIOS] Account Settings (Japan)",
                "size": 999,
                "crc32": "aaaaaaaa",
                "md5": "99999999999999999999999999999999",
                "sha1": "9999999999999999999999999999999999999999",
            }
        ]
        db = {
            "files": {
                "b05def971d8ec59f346f2d9ac21fb742e3eb6917": {
                    "name": "scph5500.bin",
                    "size": 524288,
                    "md5": "8dd7d5296a650fac7319bce665a6a53c",
                }
            }
        }
        report = build_report(db, {"no-intro": {"entries": entries}})
        data = report["no-intro"]
        self.assertEqual(data["out_of_scope"], 1)
        self.assertNotIn(
            "Nintendo - Wii U (Digital) (CDN)",
            [e["dat"] for e in data["missing"]],
        )


if __name__ == "__main__":
    unittest.main()
