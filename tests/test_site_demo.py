"""The installer demo of the README and the site (scripts/make_demo.py).

The home page and Get your files score 98 to 100 on a phone: the video must
cost nothing before it is on screen, keep still under reduced motion, and say
in words what it shows. The files are committed, so their sizes are held
here, and the words come from what the recording measured.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_readme  # noqa: E402
import make_demo  # noqa: E402
import sitestarlight  # noqa: E402

DEMO = ROOT / "docs_assets" / "demo"
COMPONENT = ROOT / "website" / "src" / "components" / "InstallDemo.astro"
DIST = ROOT / "website" / "dist"


def _facts() -> dict:
    return json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))


class TheFilesAreThereAndSmall(unittest.TestCase):
    def test_each_output_is_under_its_target(self):
        for name, limit in make_demo.LIMITS.items():
            with self.subTest(name=name):
                self.assertLessEqual((DEMO / name).stat().st_size, limit)

    def test_the_gif_and_the_poster_have_the_recorded_size(self):
        facts = _facts()
        head = (DEMO / "install.gif").read_bytes()[:10]
        self.assertEqual(head[:6], b"GIF89a")
        self.assertEqual(struct.unpack("<HH", head[6:10]), (facts["width"], facts["height"]))
        png = (DEMO / "install.png").read_bytes()[:24]
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", png[16:24]), (facts["width"], facts["height"]))

    def test_the_videos_are_webm_and_mp4(self):
        self.assertEqual((DEMO / "install.webm").read_bytes()[:4], b"\x1a\x45\xdf\xa3")
        self.assertEqual((DEMO / "install.mp4").read_bytes()[4:8], b"ftyp")


class TheTapeAndTheDriverAgree(unittest.TestCase):
    def setUp(self):
        self.tape = make_demo.TAPE.read_text(encoding="utf-8")

    def test_the_tape_writes_what_the_driver_encodes(self):
        self.assertIn(f"Output {make_demo.RECORDED.relative_to(ROOT).as_posix()}\n", self.tape)
        self.assertIn(f"Screenshot {make_demo.POSTER_SHOT.relative_to(ROOT).as_posix()}\n",
                      self.tape)

    def test_the_size_in_demo_json_is_the_tapes(self):
        facts = _facts()
        self.assertIn(f"Set Width {facts['width']}\n", self.tape)
        self.assertIn(f"Set Height {facts['height']}\n", self.tape)

    def test_the_command_typed_is_the_one_the_pages_give(self):
        from siteguides import install_command  # noqa: PLC0415

        self.assertIn(f'Type "{install_command("sh", "--for-games")}"\n', self.tape)

    def test_the_shell_answers_only_the_site_address(self):
        typed = re.search(r'Type "curl -fsSL (\S+) \|', self.tape)
        self.assertIsNotNone(typed)
        driver = Path(make_demo.__file__).read_text(encoding="utf-8")
        self.assertIn(f'"$*" = "-fsSL {typed.group(1)}"', driver)


class TheReadmeShowsTheGif(unittest.TestCase):
    def test_the_gif_sits_under_the_commands_with_its_description(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        line = f"![{generate_readme.demo_description()}]({generate_readme.DEMO_GIF})"
        self.assertIn(line, readme)
        self.assertLess(readme.index("## Install in one line"), readme.index(line))
        self.assertLess(readme.index(line), readme.index("## Or download a ZIP"))

    def test_the_description_names_what_the_recording_measured(self):
        facts = _facts()
        words = generate_readme.demo_description(facts)
        for value in (facts["setup"], f"{facts['games']} games", f"{facts['files']} BIOS files",
                      facts["size"]):
            self.assertIn(str(value), words)


class TheVideoLoadsOnlyOnScreen(unittest.TestCase):
    def setUp(self):
        self.source = COMPONENT.read_text(encoding="utf-8")
        self.markup = self.source.split("<script>", 1)[0]

    def test_nothing_is_fetched_from_the_html(self):
        self.assertIn('preload="none"', self.markup)
        self.assertNotRegex(self.markup, r"\s(src|poster)=")
        self.assertEqual(len(re.findall(r"<source data-src=", self.markup)), 2)
        self.assertIn("data-poster=", self.markup)
        self.assertIn("IntersectionObserver", self.source)

    def test_it_is_muted_looped_and_inline(self):
        for attribute in ("muted", "loop", "playsinline"):
            self.assertRegex(self.markup, rf"\n\t\t{attribute}\n")

    def test_webm_comes_before_mp4(self):
        self.assertLess(self.markup.index("install.webm"), self.markup.index("install.mp4"))

    def test_reduced_motion_keeps_the_poster_with_a_button(self):
        self.assertIn("matchMedia('(prefers-reduced-motion: reduce)')", self.source)
        self.assertIn("let wanted = !still();", self.source)
        self.assertIn('<button type="button" class="rb-demo-toggle" hidden>Play</button>',
                      self.markup)

    def test_screen_readers_get_the_description(self):
        self.assertIn('aria-describedby="rb-demo-text"', self.markup)
        self.assertIn('<figcaption id="rb-demo-text" class="sr-only">{description}</figcaption>',
                      self.markup)

    def test_the_component_is_registered(self):
        self.assertEqual(sitestarlight.COMPONENTS["InstallDemo"], "components/InstallDemo.astro")


class TheTwoPagesShowIt(unittest.TestCase):
    def test_home_and_get_your_files(self):
        import generate_site  # noqa: PLC0415

        tag = generate_site.install_demo()[0]
        self.assertIn(f'description="{generate_readme.demo_description()}"', tag)
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        for function in ("def generate_home(", "def generate_which_pack("):
            body = source[source.index(function):]
            body = body[:body.index("\ndef ", 1)]
            with self.subTest(function=function):
                self.assertIn("*install_demo(),", body)

    def test_the_site_serves_the_video_not_the_gif(self):
        import generate_site  # noqa: PLC0415

        self.assertEqual(generate_site.DEMO_ASSETS, ("install.webm", "install.mp4", "install.png"))

    def test_the_built_pages_fetch_nothing_of_it(self):
        if not (DIST / "index.html").is_file():
            self.skipTest("no built site")
        for page in ("index.html", "which-pack/index.html"):
            html = (DIST / page).read_text(encoding="utf-8")
            figure = re.search(r'<figure class="rb-demo[^"]*".*?</figure>', html, re.S)
            with self.subTest(page=page):
                self.assertIsNotNone(figure)
                self.assertIn('preload="none"', figure.group(0))
                self.assertNotRegex(figure.group(0), r"\s(src|poster)=")
                for name in ("install.webm", "install.mp4", "install.png"):
                    self.assertTrue((DIST / "assets" / "demo" / name).is_file())


if __name__ == "__main__":
    unittest.main()
