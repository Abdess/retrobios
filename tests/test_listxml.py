"""The streaming reader shared by the MAME listxml and DAT importers."""

from __future__ import annotations

import tests

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.scraper import listxml
from scripts.scraper.listxml import attrs, iter_elements, open_listxml, rom_members

DOCUMENT = b"""<?xml version="1.0"?>
<mame build="0.289 (mame0289)">
\t<machine name="comx_eb" sourcefile="comx35/eb.cpp">
\t\t<rom name="f&amp;m.basic.bin" size="4096" crc="52CB44E2" sha1="AB"/>
\t\t<rom name="dup.bin" size="16" crc="00000001"/>
\t\t<rom name="dup.bin" size="16" crc="00000002" status="baddump"/>
\t\t<rom name="undumped.bin" size="16" status="nodump"/>
\t</machine>
\t<game runnable="no" name="neogeo"><rom name="sp-s2.sp1" size="x" crc="9036d879"/></game>
</mame>
"""


class ElementsAreStreamed(unittest.TestCase):
    def _read(self, tags: tuple[str, ...]) -> list[listxml.Element]:
        return list(iter_elements(io.BytesIO(DOCUMENT), tags))

    def test_every_named_element_in_order(self):
        found = self._read(("machine", "game"))
        self.assertEqual([(e.tag, e.attrs["name"]) for e in found],
                         [("machine", "comx_eb"), ("game", "neogeo")])
        self.assertEqual(found[1].attrs["runnable"], "no")

    def test_other_elements_are_skipped(self):
        self.assertEqual([e.attrs["name"] for e in self._read(("machine",))], ["comx_eb"])

    def test_any_window_reads_the_same_elements(self):
        expected = self._read(("machine", "game"))
        saved = listxml.LISTXML_CHUNK
        try:
            for window in (1, 5, 33):
                listxml.LISTXML_CHUNK = window
                self.assertEqual(self._read(("machine", "game")), expected, window)
        finally:
            listxml.LISTXML_CHUNK = saved

    def test_head_is_read_before_the_stream(self):
        stream = io.BytesIO(DOCUMENT)
        head = stream.read(60)
        names = [e.attrs["name"] for e in iter_elements(stream, ("machine", "game"), head)]
        self.assertEqual(names, ["comx_eb", "neogeo"])


class AttributesAndMembers(unittest.TestCase):
    def test_entities_are_decoded(self):
        self.assertEqual(attrs(b' name="f&amp;m" x:y="&quot;q&quot;"'),
                         {"name": "f&m", "x:y": '"q"'})

    def test_undumped_roms_are_left_out(self):
        body = next(iter_elements(io.BytesIO(DOCUMENT))).body
        self.assertEqual([m["name"] for m in rom_members(body)],
                         ["f&m.basic.bin", "dup.bin", "dup.bin"])

    def test_dedupe_keeps_the_first_of_a_name(self):
        body = next(iter_elements(io.BytesIO(DOCUMENT))).body
        members = rom_members(body, dedupe=True, extra=("status",))
        self.assertEqual(members[0], {"name": "f&m.basic.bin", "size": 4096,
                                      "crc32": "52cb44e2", "sha1": "ab"})
        self.assertEqual(members[1], {"name": "dup.bin", "size": 16,
                                      "crc32": "00000001", "sha1": ""})
        self.assertEqual(len(members), 2)

    def test_an_unreadable_size_is_zero(self):
        body = list(iter_elements(io.BytesIO(DOCUMENT), ("game",)))[0].body
        self.assertEqual(rom_members(body)[0]["size"], 0)


class ReleaseArchive(unittest.TestCase):
    def test_one_xml_member_is_opened(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = Path(folder) / "mame0289lx.zip"
            with zipfile.ZipFile(pack, "w") as archive:
                archive.writestr("mame0289.xml", DOCUMENT)
            with open_listxml(pack) as stream:
                self.assertEqual(stream.read(), DOCUMENT)

    def test_an_archive_without_exactly_one_xml_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            pack = Path(folder) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as archive:
                archive.writestr("a.xml", DOCUMENT)
                archive.writestr("b.xml", DOCUMENT)
            with (self.assertRaisesRegex(ValueError, "expected one .xml member, found 2"),
                  open_listxml(pack)):
                pass


if __name__ == "__main__":
    unittest.main()
