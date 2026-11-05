"""Entry pages and guides (round 4, package 4).

Six handheld setups have no ZIP, and three of them offered SSH as root as
the only route while their page already named a network folder. Six rows
of the Linux handhelds table said "The command finds it on the device" for
devices with no terminal, while the installer held each folder with its
source. The offline line sat on six setup pages, the home page carried a
stray "Reference:" label, the Your setup index left out the handheld tiles,
and an iPhone owner found one FAQ line.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import generate_site  # noqa: E402
import release_record  # noqa: E402
import siteguides  # noqa: E402
import sitemarkup  # noqa: E402
from common import load_platform_registry  # noqa: E402
from tests import sitepages  # noqa: E402

REGISTRY = load_platform_registry(str(REPO_ROOT / "platforms"))
HANDHELDS = siteguides.HANDHELD_GUIDE
OFFLINE_ANCHOR = "#without-a-network-offline-install"


def _page(name: str) -> str:
    sitepages.require()
    return re.sub(r"</?abbr[^>]*>", "", sitepages.page(name).read_text(encoding="utf-8"))


def _guide_part(text: str) -> str:
    match = re.search(r"^## Reference\b", text, re.M)
    return text[: match.start()] if match else text


def _with_zip(name: str) -> bool:
    pack = release_record.pack_for(name, release_record.load_advertised())
    return bool(pack and pack.get("assets"))


SETUPS = [name for name in siteguides.GUIDES if name in REGISTRY]


class NoZipNoUnzipText(unittest.TestCase):
    def test_a_setup_without_a_zip_never_says_unzip_or_download_pack(self):
        for name in SETUPS:
            if _with_zip(name):
                continue
            text = _guide_part(_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertNotIn("Unzip the pack into", text)
                self.assertNotIn("pack holds its own", text)
                self.assertNotRegex(text, r"Download \S+ Pack")
                self.assertNotIn("/releases/download/", text)

    def test_the_minui_family_makes_each_folder(self):
        for name in ("minui", "myminui", "nextui"):
            with self.subTest(setup=name):
                self.assertIn("The command makes each console's folder for you.",
                              _page(f"platforms/{name}.md"))

    def test_knulli_is_filled_over_the_network_with_the_samba_switch_cited(self):
        text = _guide_part(_page("platforms/knulli.md"))
        self.assertIn("## From your computer { #from-your-computer }", text)
        self.assertIn("--platform knulli --dest \\\\KNULLI\\share\\bios\n", text)
        self.assertRegex(text, r"turn on \*\*SAMBA\*\* in \*\*System Settings > Services\*\*\s*"
                               r"\(\[KNULLI docs\]\(https://github\.com/knulli-cfw/knulli\.org/blob/"
                               r"[0-9a-f]{40}/docs/play/add-games/network-transfer\.md")
        # The computer route comes before the SSH one.
        self.assertLess(text.index("## From your computer"), text.index("## On the device"))

    def test_the_elec_systems_say_they_need_the_network(self):
        for name, share in (("amberelec", "\\\\AmberELEC\\roms"), ("emuelec", "\\\\EMUELEC\\roms")):
            text = _guide_part(_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertIn("Needs the device on your network.", text)
                self.assertIn(f"--platform {name} --dest {share}\n", text)

    def test_a_mac_and_a_linux_desktop_reach_the_share_too(self):
        """The share route was a PowerShell tab alone: a Mac user with Recalbox
        on Wi-Fi fell back to SSH or to taking the card out."""
        args, how = generate_site._share_tabs("recalbox", "\\\\RECALBOX\\share\\bios")
        self.assertEqual(args["macos"], "--platform recalbox --dest /Volumes/share/bios")
        self.assertIn("`smb://recalbox/share`", how["macos"])
        self.assertIn("`/Volumes/share`", how["macos"])
        self.assertEqual(args["linux"], "--platform recalbox --dest /path/to/share/bios")
        self.assertIn("`smb://recalbox/share`", how["linux"])
        lines = generate_site._setup_routes("recalbox", "Recalbox")
        routes = "\n".join(lines[:lines.index("## On the device { #install }")])
        for label in ("Windows", "macOS", "Linux"):
            self.assertIn(f'label="{label}"', routes)

    def test_the_network_route_needs_a_share_and_no_zip(self):
        for name in SETUPS:
            share = generate_site._network_share(name, siteguides.GUIDES[name])
            with self.subTest(setup=name):
                if _with_zip(name) or siteguides.GUIDES[name].run != ("device",):
                    self.assertEqual(share, "")
                if share:
                    self.assertTrue(share.startswith("\\\\"))
                    self.assertFalse(share.endswith("\\"))


class EveryHandheldRowSaysWhere(unittest.TestCase):
    def test_no_row_sends_the_reader_to_a_command(self):
        text = _page(HANDHELDS.path)
        self.assertNotIn("The command finds it on the device", text)
        rows = [line for line in text.splitlines() if line.startswith("| ")][1:]
        self.assertEqual(len(rows), len(HANDHELDS.systems))
        for row in rows:
            folder = row.rstrip(" |").rsplit(" | ", 1)[-1]
            with self.subTest(row=row[:40]):
                self.assertTrue("([source](https://" in folder
                                or folder == generate_site.RETROARCH_FOLDER_SETTING, folder)

    def test_the_installer_folders_are_written_with_their_source(self):
        systems = {s.name: s for s in HANDHELDS.systems}
        for name in ("Allium", "JELOS", "KOLOS", "MiyooCFW"):
            with self.subTest(system=name):
                self.assertTrue(systems[name].folder)
                self.assertRegex(systems[name].folder_source, r"/[0-9a-f]{40}/")

    def test_a_folder_only_linux_reads_says_what_to_do(self):
        text = _page(HANDHELDS.path)
        for system in HANDHELDS.systems:
            row = next(line for line in text.splitlines() if line.startswith(f"| {system.name} |"))
            with self.subTest(system=system.name):
                self.assertEqual(generate_site.LINUX_ONLY_HINT in row, system.linux_only)
        self.assertTrue(any(s.linux_only for s in HANDHELDS.systems if s.name == "ArchR"))
        self.assertNotIn("Windows and macOS cannot open", text)

    def test_linux_only_needs_a_folder(self):
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_system({"name": "X", "linux_only": True}, "test")

    def test_download_is_one_jump_under_the_lead(self):
        text = _page(HANDHELDS.path)
        self.assertIn("[Download](#download)", text)
        self.assertLess(text.index("[Download](#download)"), text.index("## Where the files go"))


class OfflineLineWithEveryZip(unittest.TestCase):
    def test_every_setup_with_a_zip_links_the_offline_install(self):
        for name in SETUPS:
            text = _guide_part(_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertEqual(OFFLINE_ANCHOR in text, _with_zip(name))

    def test_the_handheld_guide_links_it(self):
        self.assertEqual(OFFLINE_ANCHOR in _page(HANDHELDS.path), _with_zip(HANDHELDS.uses))


class EntryCopy(unittest.TestCase):
    def test_no_reference_label_on_home_explore_and_the_setup_index(self):
        for name in ("index.md", "explore.md", "platforms/index.md"):
            if not sitepages.page(name).is_file():
                continue
            body = _page(name).split("\n---\n", 1)[-1]
            with self.subTest(page=name):
                self.assertNotIn("Reference: [", body)
        self.assertIn("- Have a file? [Check it](/retrobios/files/)", _page("index.md"))

    def test_the_explore_cards_have_bare_links(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"Reference: [How each platform checks files]', source)
        self.assertNotIn('"Reference: [Data and API]', source)

    def test_the_setup_index_lists_the_handheld_tiles(self):
        text = _page("platforms/index.md")
        for tile in siteguides.GROUP_TILES["handheld"]:
            target = tile.link.removesuffix(".md").replace(".md#", "/#")
            with self.subTest(tile=tile.name):
                self.assertIn(f"**[{tile.name}](/retrobios/{target}", text.replace("/)", ")"))
                self.assertIn(tile.text, text)


class IphoneAndIpad(unittest.TestCase):
    def test_a_tile_in_the_handheld_group(self):
        tile = next(t for t in siteguides.GROUP_TILES["handheld"] if t.name == "iPhone and iPad")
        self.assertEqual(tile.link, "which-pack.md#iphone-and-ipad")
        for name in ("index.md", "which-pack.md"):
            with self.subTest(page=name):
                self.assertIn('href="/retrobios/which-pack/#iphone-and-ipad"', _page(name))
        self.assertEqual(sitemarkup.initials("iPhone and iPad"), "iP")

    def test_each_app_step_is_cited_and_the_picker_replaces_the_zip(self):
        text = _page("which-pack.md")
        section = text.split("## iPhone and iPad { #iphone-and-ipad }", 1)[1].split("\n## ", 1)[0]
        self.assertIn('data-pagefind-meta="devices:iPhone iPad iOS Delta Provenance"', section)
        self.assertIn("/retrobios/which-pack/?platform=retroarch#only-some-consoles", section)
        items = [line for line in section.splitlines() if line.startswith("- ")]
        self.assertEqual([re.match(r"- \*\*(\w+)\*\*", i)[1] for i in items],
                         ["RetroArch", "Delta", "Provenance"])
        for item in items:
            with self.subTest(item=item[:20]):
                self.assertRegex(item, r"\(\[(docs|code)\]\(https://")
        self.assertNotIn("/get/retroarch/", section)


class WhatItAsks(unittest.TestCase):
    def test_the_page_says_the_screen_not_a_line_menu(self):
        # The one-liner opens the full screen: a "What it asks" block of the
        # line menu showed keys a beginner never sees (owner's note).
        text = _page("which-pack.md")
        self.assertNotIn('title="What it asks"', text)
        for line in generate_site.first_screen_words():
            self.assertIn(line, text)


if __name__ == "__main__":
    unittest.main()
