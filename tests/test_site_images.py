"""Images on the site: diagrams written from data, and local copies only.

The site loaded its platform logos from GitHub avatars and branch tips, and
its system icons from retroarch-assets ``master``: a rename upstream broke an
image in silence. Diagrams were drawn at runtime by a mermaid script from a
CDN. These tests hold the replacements in place.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sitediagrams  # noqa: E402

SVG = "{http://www.w3.org/2000/svg}"


class EveryDiagramIsAccessibleSvg(unittest.TestCase):
    def test_each_layout_parses_and_is_named(self):
        for image_id in sitediagrams.IMAGE_IDS:
            figure = sitediagrams.figures()[image_id]
            for layout in ("wide", "narrow"):
                with self.subTest(image=image_id, layout=layout):
                    root = ET.fromstring(sitediagrams.svg(figure, layout, ""))
                    self.assertEqual(root.tag, f"{SVG}svg")
                    self.assertEqual(root.get("role"), "img")
                    title, desc = root.find(f"{SVG}title"), root.find(f"{SVG}desc")
                    self.assertTrue(title is not None and title.text)
                    self.assertTrue(desc is not None and desc.text)
                    self.assertEqual(
                        root.get("aria-labelledby").split(), [title.get("id"), desc.get("id")]
                    )
                    self.assertTrue(root.findall(f".//{SVG}text"))

    def test_the_output_does_not_change_between_runs(self):
        first = [sitediagrams.figure_html(i) for i in sitediagrams.IMAGE_IDS]
        sitediagrams.figures.cache_clear()
        self.assertEqual(first, [sitediagrams.figure_html(i) for i in sitediagrams.IMAGE_IDS])

    def test_text_carries_no_typographic_tics(self):
        for image_id in sitediagrams.IMAGE_IDS:
            html = sitediagrams.figure_html(image_id)
            with self.subTest(image=image_id):
                self.assertIsNone(re.search("[\u2013\u2014\u2190-\u21ff\u2500-\u257f\u2026]", html))
                self.assertNotIn("; ", re.sub(r"<[^>]+>", " ", html))

    def test_a_second_copy_on_one_page_gets_its_own_ids(self):
        page = sitediagrams.resolve_images(
            "<!-- image: install-flow -->\n\ntext\n\n<!-- image: install-flow -->\n"
        )
        ids = re.findall(r'\bid="([^"]+)"', page)
        self.assertEqual(len(ids), len(set(ids)))


class PlaceholdersResolve(unittest.TestCase):
    """A page asks for a diagram by id. A name no function answers stays a
    comment, which validate_site reports in the built page."""

    def test_every_placeholder_in_the_sources_names_a_diagram(self):
        sources = [*sorted((ROOT / "wiki").glob("*.md")), *sorted((ROOT / "scripts").glob("*.py"))]
        found = 0
        for path in sources:
            text = path.read_text(encoding="utf-8")
            for image_id in sitediagrams.PLACEHOLDER_ANYWHERE.findall(text):
                found += 1
                with self.subTest(page=path.name, image=image_id):
                    self.assertIn(image_id, sitediagrams.IMAGE_IDS)
        self.assertGreater(found, 0)

    def test_a_block_placeholder_becomes_a_figure(self):
        page = sitediagrams.resolve_images("Intro\n\n<!-- image: bios-chain -->\n\nMore\n")
        self.assertIn('<figure class="rb-figure"', page)
        self.assertNotIn("<!-- image:", page)

    def test_an_indented_placeholder_keeps_its_indent_and_escapes_markdown(self):
        page = sitediagrams.resolve_images("1. Step\n\n    <!-- image: data-layers -->\n")
        line = page.splitlines()[2]
        self.assertTrue(line.startswith("    <span class=\"rb-figure"))
        self.assertNotIn("_shared", line)
        self.assertIn("&#95;shared", line)

    def test_an_unknown_name_is_left_for_the_validator(self):
        page = "<!-- image: no-such-diagram -->\n"
        self.assertEqual(sitediagrams.resolve_images(page), page)
        self.assertEqual(sitediagrams.unresolved_images(page), ["no-such-diagram"])


class DiagramsMatchTheData(unittest.TestCase):
    def test_every_platform_appears_under_its_mode(self):
        text = sitediagrams.figures()["verification-modes"].caption
        for display, mode, _ in sitediagrams.platform_modes().values():
            with self.subTest(platform=display):
                self.assertIn(mode, sitediagrams.MODE_TEXT)
                self.assertIn(display, text)

    def test_each_example_platform_runs_its_emulator(self):
        from common import load_emulator_profiles, load_platform_config, resolve_platform_cores

        profiles = load_emulator_profiles(str(ROOT / "emulators"), skip_aliases=False)
        for platform, emulator in sitediagrams.CHAIN_EXAMPLES:
            with self.subTest(platform=platform, emulator=emulator):
                config = load_platform_config(platform, str(ROOT / "platforms"))
                self.assertIn(emulator, resolve_platform_cores(config, profiles))

    def test_minui_tags_are_folders_minui_hands_its_cores(self):
        import yaml

        config = yaml.safe_load((ROOT / "platforms" / "minui.yml").read_text(encoding="utf-8"))
        folders = set(config["core_system_dirs"])
        for _, tag in sitediagrams.MINUI_EXAMPLES:
            with self.subTest(tag=tag):
                self.assertIn(f"Bios/{tag}", folders)
                self.assertTrue(sitediagrams.minui_files().get(tag))

    def test_the_pipeline_drawing_is_the_step_list(self):
        from pipeline import STEP_LABELS

        numbers = [box.number for box in sitediagrams._pipeline_boxes()]
        self.assertEqual(numbers, [label.split(" ", 1)[0] for label in STEP_LABELS.values()])


class NoMermaidAtRuntime(unittest.TestCase):
    """A mermaid fence made Material load mermaid@11 (3.5 MB) from unpkg."""

    def test_no_page_source_uses_a_mermaid_fence(self):
        for path in sorted((ROOT / "wiki").glob("*.md")):
            with self.subTest(page=path.name):
                self.assertNotIn("```mermaid", path.read_text(encoding="utf-8"))


class ImagesAreServedFromTheSite(unittest.TestCase):
    def _manifest(self, folder: str) -> list[dict]:
        path = ROOT / "docs_assets" / folder / "sources.json"
        return json.loads(path.read_text(encoding="utf-8"))["images"]

    def test_every_registry_logo_has_a_local_copy(self):
        import yaml

        registry = yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text())["platforms"]
        copies = {entry["platform"]: entry for entry in self._manifest("logos")}
        for name, entry in registry.items():
            if not entry.get("logo"):
                continue
            with self.subTest(platform=name):
                self.assertIn(name, copies, "run scripts/fetch_site_images.py --only logos")
                self.assertEqual(copies[name]["source"], entry["logo"])
                self.assertTrue((ROOT / "docs_assets" / "logos" / copies[name]["file"]).is_file())
                self.assertTrue(copies[name]["owner"] and copies[name]["licence"])

    def test_every_recorded_icon_exists(self):
        for entry in self._manifest("system-icons"):
            with self.subTest(icon=entry["file"]):
                self.assertTrue((ROOT / "docs_assets" / "system-icons" / entry["file"]).is_file())

    def test_remote_links_with_a_copy_are_rewritten(self):
        logo = self._manifest("logos")[0]
        page = f"| ![X]({logo['source']}){{ width=20 }} | <img src=\"{logo['source']}\"> |"
        local = sitediagrams.localize_images(page, Path("platforms/x.md"))
        self.assertNotIn(logo["source"], local)
        self.assertEqual(local.count(f"../assets/logos/{logo['file']}"), 2)

    def test_icon_paths_are_link_safe(self):
        icon = self._manifest("system-icons")[0]
        local = sitediagrams.localize_images(f"![a]({icon['source']})", Path("systems/x.md"))
        self.assertNotIn(" ", local)

    def test_the_validator_refuses_a_remote_image(self):
        from validate_site import _parse_page

        with tempfile.TemporaryDirectory(dir=ROOT / "tests") as tmp:
            path = Path(tmp) / "index.html"
            path.write_text(
                '<html lang="en"><body><img alt="x" src="https://example.org/a.png">'
                '<img alt="y" src="../assets/logos/a.png"><!-- image: nope --></body></html>'
            )
            page = _parse_page(path)
        self.assertEqual(page.remote_images, ["https://example.org/a.png"])
        self.assertEqual(page.placeholders, ["nope"])


class SharingCards(unittest.TestCase):
    def test_one_card_per_section_at_the_open_graph_size(self):
        import struct

        for section in sitediagrams.OG_SECTIONS:
            with self.subTest(section=section):
                data = (ROOT / "docs_assets" / "og" / f"{section}.png").read_bytes()
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", data[16:24]), (1200, 630))
                mark = (ROOT / "docs_assets" / "brand" / "logo.svg").read_text(encoding="utf-8")
                ET.fromstring(sitediagrams.og_card_svg(section, mark))

    def test_the_template_names_every_section(self):
        import sitestarlight  # noqa: PLC0415

        named = {sitestarlight.og_section("index.md", "")} | {
            sitestarlight.og_section("wiki/page.md", level)
            for level in ("start", "setup", "explore", "reference", "contribute")}
        self.assertEqual(named, set(sitediagrams.OG_SECTIONS))
        for section in named:
            with self.subTest(section=section):
                self.assertTrue((ROOT / "docs_assets" / "og" / f"{section}.png").is_file())


class ImagesStillNeeded(unittest.TestCase):
    """Screens that need a real device are listed, never drawn as a mock-up."""

    def test_the_list_gives_each_capture_its_alt_text(self):
        text = (ROOT / "docs_assets" / "images-needed.md").read_text(encoding="utf-8")
        entries = re.findall(r"(?m)^## ", text)
        self.assertGreater(len(entries), 3)
        self.assertEqual(len(entries), len(re.findall(r"(?m)^\*\*Alt text\*\*", text)))


if __name__ == "__main__":
    unittest.main()
