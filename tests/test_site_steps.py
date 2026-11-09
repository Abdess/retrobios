"""The drawn steps of the install box (scripts/sitesteps.py).

Each drawing says in words what it shows, to a screen reader and to a
reader whose images do not load: a title and a desc the SVG names. It tells
the same steps as the text above it, the keys included, so the picture and
the words never disagree. And it draws in the theme's colours.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import re
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sitesteps  # noqa: E402
from siteguides import TERMINALS  # noqa: E402

SVG = "{http://www.w3.org/2000/svg}"
DIST = ROOT / "website" / "dist"


class EachDrawingNamesItsSteps(unittest.TestCase):
    def test_title_and_desc_are_what_aria_points_at(self):
        for tab in sitesteps.STEPS:
            for layout in ("wide", "narrow"):
                root = ET.fromstring(sitesteps._svg(tab, layout))
                with self.subTest(tab=tab, layout=layout):
                    self.assertEqual(root.get("role"), "img")
                    title, desc = root.find(f"{SVG}title"), root.find(f"{SVG}desc")
                    self.assertIsNotNone(title)
                    self.assertIsNotNone(desc)
                    self.assertEqual(root.get("aria-labelledby").split(),
                                     [title.get("id"), desc.get("id")])
                    self.assertEqual(desc.text, sitesteps.description(tab))

    def test_every_caption_drawn_is_in_the_desc(self):
        for tab, (_title, steps) in sitesteps.STEPS.items():
            desc = sitesteps.description(tab)
            for step in steps:
                with self.subTest(tab=tab, step=step.caption):
                    self.assertIn(step.caption, desc)

    def test_the_drawing_and_the_text_name_the_same_keys(self):
        for tab, (_title, steps) in sitesteps.STEPS.items():
            text = TERMINALS[tab][1].replace("**", "")
            keys = {step.word for step in steps if step.icon == "keys"}
            with self.subTest(tab=tab):
                for word in keys:
                    self.assertIn(word, text)
                drawn = set(re.findall(r"\b(?:Ctrl|Cmd|Shift|Alt)\+\w+(?:\+\w+)?", text))
                self.assertLessEqual(drawn, keys)
                self.assertIn("Click Copy", text)

    def test_one_drawing_per_computer_tab_none_elsewhere(self):
        self.assertEqual(set(sitesteps.STEPS), {"windows", "macos", "linux", "steamdeck"})
        self.assertEqual(sitesteps.steps_figure("device"), [])

    def test_colours_come_from_the_theme(self):
        for tab in sitesteps.STEPS:
            root = ET.fromstring(sitesteps._svg(tab, "wide"))
            for node in root.iter():
                tag = node.tag.removeprefix(SVG)
                if tag in ("rect", "path", "circle"):
                    with self.subTest(tab=tab, node=ET.tostring(node)[:60]):
                        self.assertTrue(node.get("class", "").startswith("rb-d-"))

    def test_ids_are_unique_on_the_page(self):
        ids = re.findall(r'id="([^"]+)"', "".join(
            sitesteps._svg(tab, layout) for tab in sitesteps.STEPS for layout in ("wide", "narrow")))
        self.assertEqual(len(ids), len(set(ids)))


class TheBuiltPageHoldsThem(unittest.TestCase):
    def test_under_each_tab_of_get_your_files(self):
        page = DIST / "which-pack" / "index.html"
        if not page.is_file():
            self.skipTest("no built site")
        html = page.read_text(encoding="utf-8")
        for tab in sitesteps.STEPS:
            with self.subTest(tab=tab):
                self.assertIn(f'aria-labelledby="rb-steps-{tab}-wide-t rb-steps-{tab}-wide-d"',
                              html)
                self.assertIn(f'<desc id="rb-steps-{tab}-narrow-d">', html)


if __name__ == "__main__":
    unittest.main()
