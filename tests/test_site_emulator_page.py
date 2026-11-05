"""What an emulator page says about a profile and its files.

No network and no database: pages are rendered from small profiles.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site as gs  # noqa: E402

EMPTY_DB = {"files": {}, "indexes": {"by_name": {}}}


def _page(name: str, profile: dict) -> str:
    return gs.generate_emulator_page(name, profile, EMPTY_DB, None, set())


class WhereAndHowAFileIsRead(unittest.TestCase):
    """load_from, found_by and on_mismatch were in 99, 4 and 25 entries and
    on no page: Dolphin's gba_bios.bin showed a Path a RetroArch user put
    under system/, while the libretro core reads it from its save directory."""

    def test_load_from(self):
        page = _page("dolphin", {"type": "standalone + libretro", "files": [
            {"name": "gba_bios.bin", "path": "GBA/gba_bios.bin",
             "load_from": {"libretro": "save_dir"}},
            {"name": "hdd.rom", "load_from": "hdd_image"},
            {"name": "bios.bin", "load_from": "system_dir"},
        ]})
        self.assertIn("- Read from: the save directory, not the BIOS directory "
                      "(libretro build)", page)
        self.assertIn("- Read from: inside the emulated hard disk image", page)
        self.assertEqual(page.count("Read from:"), 2)

    def test_found_by_and_on_mismatch(self):
        page = _page("x", {"type": "standalone", "found_by": "content", "files": [
            {"name": "scph5501.bin", "found_by": "content", "on_mismatch": "warn"},
            {"name": "boot.bin", "on_mismatch": {"signature": "warn"}},
        ]})
        self.assertIn("| Files found by | content (the code scans the folder", page)
        self.assertIn("- Found by: content (", page)
        self.assertIn("- On a failed check: warns and runs with the file", page)
        self.assertIn("- On a failed signature check: warns and runs with the file", page)


class WhoShipsTheBuildAndWhy(unittest.TestCase):
    """built_by, pin_frozen and version_source were in 9, 13 and 40 profiles
    and on no page: mame0278 did not say only Recalbox ships it."""

    def test_meta_rows(self):
        page = _page("mame0278", {
            "type": "libretro", "built_by": ["recalbox"],
            "pin_frozen": "ROCKNIX 20261001 builds this revision.",
            "version_source": {"url": "https://example.org/news", "pattern": "v(\\S+)",
                               "no_genuine_copy": "13.0"},
            "files": [],
        })
        self.assertIn("| Built by | [recalbox](../platforms/recalbox.md), under its "
                      "core name.", page)
        self.assertIn("| Revision held | ROCKNIX 20261001 builds this revision. |", page)
        self.assertIn("| Releases announced at | [https://example.org/news]"
                      "(https://example.org/news) (version 13.0 announced there, "
                      "found only as rebuilt copies) |", page)

    def test_the_version_links_its_proof(self):
        """`0.97, stated in libretro/handy.h` was bare text beside a pinned
        Revision link: the #define it reads was one search away."""
        import generate_site as gs
        import sitesources
        import yaml

        handy = yaml.safe_load((REPO_ROOT / "emulators" / "handy.yml").read_text(encoding="utf-8"))
        path = handy["version_basis"]["path"]
        self.assertIn(path, sitesources.cited_paths(handy))
        self.assertIn(f"stated in [`{path}`](https://github.com/libretro/libretro-handy/blob/"
                      f"{handy['source_commit']}/{path})", gs.version_markdown(handy))
        tagged = {"source": "https://github.com/owner/emu", "source_commit": "a" * 40,
                  "core_version": "1.2-3-gaaaaaaa",
                  "version_basis": {"kind": "tag", "tag": "1.2", "distance": 3}}
        self.assertEqual(gs.version_markdown(tagged), "1.2-3-gaaaaaaa, 3 commits after tag "
                         "[`1.2`](https://github.com/owner/emu/tree/1.2)")
        # A file no recorded tree confirms stays plain: no link beats a 404.
        unread = {**tagged, "version_basis": {"kind": "file", "path": "src/none.h"}}
        self.assertEqual(gs.version_markdown(unread), "1.2-3-gaaaaaaa, stated in `src/none.h`")

    def test_the_upstream_pin_says_why_it_is_held(self):
        """mupen64plus showed its core revision and not that AmberELEC
        builds that one: read as a profile behind HEAD."""
        page = _page("mupen64plus", {
            "type": "libretro",
            "upstream_frozen": "AmberELEC builds the core at this revision.",
            "files": [],
        })
        self.assertIn("| Upstream revision held | AmberELEC builds the core at this "
                      "revision. |", page)


class ACardKeepsItsAddress(unittest.TestCase):
    """emulators/raze/#file-duke3d-grp stopped pointing at its card once a
    second version of the path was declared: the anchor of the first one
    became file-duke3d-grp-<hash>."""

    def test_a_second_version_moves_nothing(self):
        one = {"name": "DUKE3D.GRP", "md5": "aaaa1111bbbb"}
        two = {"name": "DUKE3D.GRP", "md5": "cccc2222dddd"}
        before = gs.emulator_file_anchors([one])
        after = gs.emulator_file_anchors([two, one])
        self.assertEqual(before, ["file-duke3d-grp-aaaa1111"])
        self.assertEqual(after[1], before[0])

    def test_the_plain_address_still_lands(self):
        files = [{"name": "DUKE3D.GRP", "md5": "aaaa1111bbbb"}]
        page = _page("raze", {"type": "standalone", "files": files})
        self.assertIn('<span id="file-duke3d-grp"></span>', page)
        self.assertIn('<h3 id="file-duke3d-grp-aaaa1111" class="rb-file-title"', page)
        # A card already holding the plain id gives it to no one else.
        files = [{"name": "x.bin"}, {"name": "x.bin", "sha1": "ab" * 20}]
        anchors = gs.emulator_file_anchors(files)
        self.assertEqual(anchors, ["file-x-bin", "file-x-bin-abababab"])
        self.assertEqual(gs.emulator_file_aliases(files, anchors), ["", ""])


class WhatASearchSnippetSays(unittest.TestCase):
    def test_a_core_loading_no_file_promises_no_hash(self):
        """152 pages of cores that load no file announced paths and hashes."""
        rel = Path("emulators/lutro.md")
        saved = dict(gs.PAGE_DATA)
        self.addCleanup(lambda: (gs.PAGE_DATA.clear(), gs.PAGE_DATA.update(saved)))
        gs.PAGE_DATA[rel.as_posix()] = {}
        text = gs._page_description("# Lutro\n", rel, "Lutro")
        self.assertNotIn("hashes", text)
        self.assertIn("It needs no BIOS or firmware file.", text)
        gs.PAGE_DATA[rel.as_posix()] = {"hasPart": [{"name": "a.bin"}]}
        self.assertNotIn("needs no BIOS", gs._page_description("# Lutro\n", rel, "Lutro"))

    def test_a_long_paragraph_is_cut_at_a_word(self):
        plain = ("files/?sha1= is the address that does not move: it opens the card "
                 "wherever the file is now, " * 4)
        text = gs._shorten(plain)
        self.assertTrue(text.endswith("..."))
        self.assertLessEqual(len(text), 160)
        self.assertTrue(plain.startswith(text[:-3]))
        self.assertIn(plain[len(text) - 3], " ,:")

    def test_code_keeps_its_underscores(self):
        self.assertEqual(gs._plain_markdown("only `validate_schemas.py` and _this_"),
                         "only validate_schemas.py and this")

    def test_structured_url_is_encoded_like_the_canonical(self):
        """The canonical link and the sitemap encode idtech4a++ as
        idtech4a%2B%2B, and the JSON-LD named the unencoded URL."""
        import json
        import tempfile

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            page = Path(tmp) / "emulators" / "idtech4a++.md"
            page.parent.mkdir()
            page.write_text("# idTech4A++\n\nSome text long enough to be a description.\n")
            gs.decorate_markdown_pages(Path(tmp))
            text = page.read_text()
        import yaml

        front = yaml.safe_load(text.split("---\n")[1])
        script = next(entry for entry in front["head"] if entry["tag"] == "script")
        data = json.loads(script["content"].replace("<\\/", "</"))
        self.assertEqual(data["url"],
                         "https://abdess.github.io/retrobios/emulators/idtech4a%2B%2B/")


if __name__ == "__main__":
    unittest.main()
