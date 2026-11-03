"""Entry pages and guides (round 3, package 4).

A handheld owner found no tile for Android, ArkOS, muOS, Onion or spruceOS:
the systems sat in a closed note with a path seen from inside the device.
The setup version a pack fits was named only under Reference, the setup page
offered the full pack only, Get your files listed every setup twice, the Your
setup index ended on a table in project words, and the home page said a
Dreamcast needs its BIOS while Flycast boots without one.
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
from common import load_platform_config, load_platform_registry  # noqa: E402
from tests import sitepages  # noqa: E402

REGISTRY = load_platform_registry(str(REPO_ROOT / "platforms"))
GUIDE = siteguides.HANDHELD_GUIDE


def _page(name: str) -> str:
    sitepages.require()
    return sitepages.page(name).read_text(encoding="utf-8")


def _guide_part(text: str) -> str:
    """The guide part of a setup page, glossary marks taken off."""
    match = re.search(r"^## Reference\b", text, re.M)
    text = text[: match.start()] if match else text
    return re.sub(r"</?abbr[^>]*>", "", text)


def _display(key: str) -> str:
    return load_platform_config(key, str(REPO_ROOT / "platforms")).get("platform", key)


class HandheldWayIn(unittest.TestCase):
    def test_android_and_linux_tiles_on_home_and_get_your_files(self):
        tiles = siteguides.GROUP_TILES.get("handheld", ())
        self.assertEqual([tile.name for tile in tiles],
                         ["Android", "Linux handhelds", "iPhone and iPad"])
        for name in ("index.md", "which-pack.md"):
            text = _page(name)
            with self.subTest(page=name):
                self.assertIn('href="/retrobios/platforms/retroarch/#where-the-files-go"', text)
                self.assertIn('href="/retrobios/platforms/linux-handhelds/"', text)
                self.assertIn(">Retroid, AYN Odin and other Android handhelds</span>", text)

    def test_the_closed_note_is_gone(self):
        self.assertNotIn("Other handhelds that run RetroArch", _page("which-pack.md"))

    def test_one_row_per_detected_system(self):
        detected = [name for name, _folder in siteguides.detected_systems(REGISTRY, GUIDE.uses)]
        self.assertEqual(sorted((s.name for s in GUIDE.systems), key=str.casefold), detected)
        text = _page(GUIDE.path)
        for system in GUIDE.systems:
            with self.subTest(system=system.name):
                self.assertIn(f"| {system.name} |", text)

    def test_every_folder_and_device_list_is_cited(self):
        for system in GUIDE.systems:
            with self.subTest(system=system.name):
                if system.folder:
                    self.assertTrue(system.folder_source.startswith("https://"))
                if system.devices:
                    self.assertTrue(system.devices_source.startswith("https://"))
        for name in ("ArkOS", "muOS", "Onion", "spruceOS"):
            system = next(s for s in GUIDE.systems if s.name == name)
            with self.subTest(system=name):
                self.assertTrue(system.folder and system.devices)

    def test_a_value_without_its_page_is_refused(self):
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_system({"name": "Onion", "folder": "`BIOS`"}, "x")
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_system(
                {"name": "Onion", "devices": ["Miyoo Mini"], "devices_source": "a blog"}, "x")

    def test_the_guide_rejects_a_missing_or_unknown_system(self):
        data = {"page": "x", "title": "X", "summary": "S", "uses": "retroarch",
                "systems": [{"name": "Onion"}]}
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_guide(data, REGISTRY, siteguides.GUIDES, "x")

    def test_devices_are_a_search_field_with_no_text(self):
        text = _page(GUIDE.path)
        match = re.search(r'<span data-pagefind-meta="devices:([^"]*)"></span>', text)
        self.assertIsNotNone(match)
        self.assertIn("R36S", match[1])
        self.assertIn("Miyoo Mini", match[1])
        self.assertNotIn(",", match[1])
        # The names typed most often are also on the page itself.
        self.assertIn("R36S", text.split(match[0], 1)[1])

    def test_the_guide_is_in_the_handheld_group_of_the_navigation(self):
        coverages = {key: {"platform": _display(key)} for key in REGISTRY}
        nav = generate_site.generate_nav(coverages, {}, {}, REGISTRY)
        setup = next(tab["Your setup"] for tab in nav if "Your setup" in tab)
        groups = {next(iter(item)): next(iter(item.values()))
                  for item in setup if isinstance(item, dict)}
        label = siteguides.DEVICE_GROUPS["handheld"][0]
        self.assertIn({GUIDE.title: GUIDE.path}, groups[label])

    def test_the_guide_fills_the_card_and_never_its_root(self):
        text = _page(GUIDE.path)
        self.assertIn("--platform retroarch --dest E:\\BIOS", text)
        self.assertNotRegex(text, r"--dest E:\\\s")


class PackNamesItsVersion(unittest.TestCase):
    def test_the_line_under_the_release(self):
        record = release_record.load_record()
        if not release_record.pack_for("batocera", record):
            self.skipTest("release.json has no Batocera pack")
        block = generate_site._pack_buttons("batocera")
        version = generate_site._pack_version(release_record.pack_name_for("batocera", record))
        self.assertIn(f"Made for Batocera {version}. "
                      + generate_site.OTHER_VERSION, block)

    def test_a_version_gap_is_said_once(self):
        record = {"tag": "v2026.10.10", "packs": {"RetroBat_1.0_BIOS_Pack.zip": {
            "assets": ["RetroBat_1.0_BIOS_Pack.zip"], "platforms": ["retrobat"]}}}
        released = generate_site.release_line("retrobat", record)
        line = generate_site.version_line("retrobat", record, named=len(released) > 1)
        self.assertEqual(line, generate_site.OTHER_VERSION)

    def test_the_v_prefix_is_dropped(self):
        self.assertEqual(generate_site.setup_version("retroarch", {}),
                         f"RetroArch {load_platform_config('retroarch', 'platforms')['version'].lstrip('v')}")

    def test_every_setup_page_names_a_version(self):
        """A setup with a release ZIP names the version it was made for. One
        without says there is no ZIP: the command installs current files."""
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _guide_part(_page(f"platforms/{key}.md"))
                if generate_site.has_release_pack(key):
                    self.assertRegex(text, r"(?:[Mm]ade for|This pack was built for) \S")
                else:
                    self.assertIn(generate_site.no_zip_line(_display(key)), text)


class SetupPagesOfferPartOfThePack(unittest.TestCase):
    def test_pick_them_and_press_c(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _guide_part(_page(f"platforms/{key}.md"))
                self.assertIn(f"/retrobios/which-pack/?platform={key}#only-some-consoles", text)
                # The screen's own row: the line menu's c is not what the
                # one-liner opens.
                self.assertIn("or run the command: **Choose systems** is on its second "
                              "screen.", text)
                # Never "choose **Choose systems**" (tui_audit_17 P3-9).
                self.assertNotIn("choose **Choose systems**", text)

    def test_the_anchor_exists(self):
        self.assertIn("## Only some consoles?", _page("which-pack.md"))

    def test_a_file_in_place_but_missing_is_answered(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                self.assertIn("Reported missing anyway?",
                              _guide_part(_page(f"platforms/{key}.md")))


class SafetyListIsLinked(unittest.TestCase):
    def test_setup_pages_link_the_home_list(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _guide_part(_page(f"platforms/{key}.md"))
                self.assertIn("[Is it safe?](/retrobios/#is-it-safe)", text)
                self.assertNotIn("<summary>Is it safe?</summary>", text)
        self.assertIn("## Is it safe? { #is-it-safe }", _page("index.md"))


class OfflineLine(unittest.TestCase):
    def test_under_from_your_computer(self):
        text = _page("platforms/batocera.md")
        start = text.index("## From your computer")
        line = text.index("No internet on the device?")
        self.assertLess(start, line)
        self.assertLess(line, text.index("## On the device"))
        self.assertIn("/retrobios/wiki/installer/#without-a-network-offline-install", text)
        self.assertIn("{ #without-a-network-offline-install }",
                      (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8"))


class GetYourFilesListsEachSetupOnce(unittest.TestCase):
    def setUp(self):
        self.text = _page("which-pack.md")

    def test_the_tables_are_in_one_closed_block(self):
        block = re.search(r'<details class="rb-details[^"]*">\s*<summary>Every folder and ZIP '
                          r'in one table</summary>(.*?)</details>', self.text, re.S)
        self.assertIsNotNone(block)
        outside = self.text.replace(block[0], "")
        self.assertNotIn("| Setup | Runs on | BIOS folder | ZIP |", outside)
        for key in REGISTRY:
            with self.subTest(platform=key):
                self.assertEqual(block[1].count(f"| [{_display(key)}](/retrobios/platforms/{key}/) |"), 1)

    def test_single_setup_groups_share_one_table(self):
        self.assertIn("**Other setups**", self.text)
        self.assertNotIn("**MiSTer FPGA**", self.text)
        self.assertNotIn("**Self-hosted game library**", self.text)

    def test_no_unzip_into_without_a_zip(self):
        record = release_record.load_record()
        for line in self.text.splitlines():
            if "Unzip into" in line:
                key = re.search(r"/retrobios/platforms/([a-z0-9]+)/", line)[1]
                with self.subTest(platform=key):
                    self.assertTrue(release_record.pack_for(key, record))

    def test_parts_are_buttons_with_the_size_after(self):
        """A row links the setup's get/ page, which lists every part, with the
        download size after the button."""
        rows = [line for line in self.text.splitlines() if ">ZIP</a>" in line]
        self.assertTrue(rows)
        for row in rows:
            self.assertRegex(row, r'<a class="rb-button" href="/retrobios/get/[a-z0-9]+/">ZIP</a>')
            self.assertRegex(row, r"</a> \(\d[\d.]* [KMG]B\) \|$")

    def test_the_zip_note(self):
        text = re.sub(r"</?abbr[^>]*>", "", self.text)
        for line in ("A big ZIP comes in parts, like `Pack.part1of2.zip`. Download every part.",
                     "Leave the ZIPs inside, like `neogeo.zip`, as they are.",
                     "Their setup's page says where to unzip them."):
            self.assertIn(line, text)
        self.assertNotIn("**Unzip into** means", self.text)


class YourSetupIndexInPlainWords(unittest.TestCase):
    def test_the_index_links_the_table(self):
        text = _page("platforms/index.md")
        self.assertNotIn("| Platform |", text)
        self.assertNotIn("at a glance", text.split("---", 2)[-1].lower().replace(
            "every setup at a glance", ""))
        self.assertIn("/retrobios/wiki/verification-modes/#every-setup-at-a-glance", text)

    def test_the_table_on_verification_modes(self):
        text = _page("wiki/verification-modes.md")
        self.assertIn("| Setup | Files on its own list | Files in the ZIP | How it checks |", text)
        table = text.split("## Every setup at a glance", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("existence", table)
        self.assertIn("| name only |", table)
        self.assertIn("No list of its own", table)
        self.assertLess(text.index("## Every setup at a glance"), text.index("## Next steps"))

    def test_insertion_keeps_next_steps_last(self):
        page = "# T\n\nBody.\n\n## Next steps\n\n- [A](a.md)\n"
        out = generate_site.with_setup_table(page, {}, {})
        self.assertTrue(out.rstrip().endswith("- [A](a.md)"))
        self.assertIn("## Every setup at a glance", out)


class HomeCopy(unittest.TestCase):
    def test_dreamcast_and_the_check_link(self):
        home = re.sub(r"</?abbr[^>]*>", "", _page("index.md"))
        self.assertIn("- **Yes** for PlayStation 1 and 2, Saturn and Neo Geo.", home)
        self.assertIn("- **Better with it** for Dreamcast: some games need it.", home)
        # A question and the link that answers it: no level label, which
        # read as a broken crumb beside the Reference tab (round 4).
        self.assertNotIn("Reference:", home.split("\n---\n", 1)[-1])
        self.assertIn("- Have a file? [Check it]", home)
        self.assertIn("BIOS missing, even with the file there?", home)

    def test_flycast_boots_without_the_dreamcast_bios(self):
        import yaml

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "flycast.yml").read_text(encoding="utf-8"))
        boot = next(f for f in profile["files"] if f.get("name") == "dc_boot.bin")
        self.assertFalse(boot.get("required"))
        self.assertTrue(boot.get("hle_fallback"))


class TileLogosLoadWhenSeen(unittest.TestCase):
    def test_the_helper(self):
        tiles = [(f"S{i}", "x.md", f"{i}.png", "here") for i in range(4)]
        html = "".join(sitemarkup.platform_tiles(tiles, eager=2))
        logos = re.findall(r"<img [^>]*>", html)
        self.assertEqual(['loading="lazy"' in logo for logo in logos], [False, False, True, True])
        self.assertNotIn("loading=", "".join(sitemarkup.platform_tiles(tiles[:1], eager=1)))

    def test_only_the_first_row_is_eager_on_entry_pages(self):
        for name in ("index.md", "which-pack.md"):
            logos = re.findall(r'<img class="rb-card-logo"[^>]*>', _page(name))
            with self.subTest(page=name):
                self.assertGreater(len(logos), sitemarkup.FIRST_ROW_TILES)
                eager = [logo for logo in logos if 'loading="lazy"' not in logo]
                self.assertEqual(eager, logos[: sitemarkup.FIRST_ROW_TILES])


class DownloadLine(unittest.TestCase):
    def test_checksums_and_signature_read_as_two(self):
        record = release_record.load_record()
        if not release_record.pack_for("batocera", record):
            self.skipTest("release.json has no Batocera pack")
        line = generate_site.release_line("batocera", record)[0]
        self.assertRegex(line, r"\[SHA256SUMS\.txt\]\([^)]+\) and its \[signature\]\([^)]+\)\.$")


if __name__ == "__main__":
    unittest.main()
