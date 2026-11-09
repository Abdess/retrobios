"""The installer demos of the README and the site (scripts/make_demo.py).

The home page and Get your files score 98 to 100 on a phone: a video must
cost nothing before it is on screen, keep still under reduced motion, and say
in words what it shows. The files are committed, so their sizes are held
here, and the words come from what each recording measured. Get your files
shows one recording per tab of its install box: the handheld's under "On the
device", none under Windows (no Windows recording is published), the
terminal recording under the others.
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


def _all_facts() -> dict:
    return json.loads((DEMO / "demo.json").read_text(encoding="utf-8"))


def _facts(variant: str = "default") -> dict:
    return _all_facts()[variant]


class TheFilesAreThereAndSmall(unittest.TestCase):
    def test_each_output_is_under_its_target(self):
        for variant in make_demo.VARIANTS.values():
            for name, limit in make_demo.limits(variant).items():
                with self.subTest(name=name):
                    self.assertLessEqual((DEMO / name).stat().st_size, limit)

    def test_only_the_readme_variant_has_a_gif(self):
        gifs = sorted(p.name for p in DEMO.glob("*.gif"))
        self.assertEqual(gifs, [Path(generate_readme.DEMO_GIF).name])
        self.assertEqual([v.name for v in make_demo.VARIANTS.values() if v.gif], ["default"])

    def test_the_gif_and_the_posters_have_the_recorded_size(self):
        facts = _facts()
        head = (DEMO / "install.gif").read_bytes()[:10]
        self.assertEqual(head[:6], b"GIF89a")
        self.assertEqual(struct.unpack("<HH", head[6:10]), (facts["width"], facts["height"]))
        for variant in make_demo.VARIANTS.values():
            facts = _facts(variant.name)
            png = (DEMO / f"{variant.stem}.png").read_bytes()[:24]
            with self.subTest(variant=variant.name):
                self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", png[16:24]),
                                 (facts["width"], facts["height"]))

    def test_the_videos_are_webm_and_mp4(self):
        for variant in make_demo.VARIANTS.values():
            with self.subTest(variant=variant.name):
                self.assertEqual((DEMO / f"{variant.stem}.webm").read_bytes()[:4],
                                 b"\x1a\x45\xdf\xa3")
                self.assertEqual((DEMO / f"{variant.stem}.mp4").read_bytes()[4:8], b"ftyp")

    def test_demo_json_holds_each_variant_and_its_alt_text(self):
        facts = _all_facts()
        self.assertEqual(list(facts), list(make_demo.VARIANTS))
        for name, entry in facts.items():
            with self.subTest(variant=name):
                self.assertEqual(entry["alt"], make_demo.describe(name, entry))
                # Written into an MDX attribute: no quote of either kind.
                self.assertNotRegex(entry["alt"], "[\"']")


class TheTapeAndTheDriverAgree(unittest.TestCase):
    def setUp(self):
        self.tape = make_demo.TAPE.read_text(encoding="utf-8")

    def test_each_tape_writes_what_the_driver_encodes(self):
        for variant in make_demo.VARIANTS.values():
            tape = variant.tape.read_text(encoding="utf-8")
            with self.subTest(variant=variant.name):
                self.assertIn(f"Output {variant.recorded.relative_to(ROOT).as_posix()}\n", tape)
                self.assertIn(
                    f"Screenshot {variant.poster_shot.relative_to(ROOT).as_posix()}\n", tape)

    def test_the_size_in_demo_json_is_each_tapes(self):
        for variant in make_demo.VARIANTS.values():
            facts, tape = _facts(variant.name), variant.tape.read_text(encoding="utf-8")
            with self.subTest(variant=variant.name):
                self.assertIn(f"Set Width {facts['width']}\n", tape)
                self.assertIn(f"Set Height {facts['height']}\n", tape)

    def test_the_handheld_is_an_r36s_screen_driven_by_its_buttons(self):
        variant = make_demo.VARIANTS["handheld"]
        tape = variant.tape.read_text(encoding="utf-8")
        self.assertIn("Set Width 640\n", tape)
        self.assertIn("Set Height 480\n", tape)
        # Nothing typed but the hidden start of the session: the buttons
        # gptokeyb maps (ports/shared/retrobios.gptk: a = enter) do the rest.
        self.assertEqual(re.findall(r"^Type (.*)$", tape, re.M),
                         ["'exec \"$RETROBIOS_DEMO_SESSION\"'"])
        gptk = (ROOT / "ports" / "shared" / "retrobios.gptk").read_text(encoding="utf-8")
        self.assertRegex(gptk, r"(?m)^a = enter$")
        env = make_demo.session_env("http://127.0.0.1:1", ROOT / "tmp", ROOT / "tmp", variant)
        self.assertEqual(env["RETROBIOS_PAD"], "gptokeyb")
        self.assertEqual(env["RETROBIOS_OS"], "linux")
        self.assertEqual(variant.mount, "/roms")

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
        self.assertLess(self.markup.index("asset('webm')"), self.markup.index("asset('mp4')"))

    def test_each_variant_has_its_files_and_its_own_ids(self):
        self.assertIn("const stem = variant === 'default' ? 'install' : `install-${variant}`;",
                      self.source)
        self.assertIn("const textId = name ? `rb-demo-text-${name}` : 'rb-demo-text';",
                      self.source)

    def test_reduced_motion_keeps_the_poster_with_a_button(self):
        self.assertIn("matchMedia('(prefers-reduced-motion: reduce)')", self.source)
        self.assertIn("let wanted = !still();", self.source)
        self.assertIn('<button type="button" class="rb-demo-toggle" hidden>Play</button>',
                      self.markup)

    def test_screen_readers_get_the_description(self):
        self.assertIn("aria-describedby={textId}", self.markup)
        self.assertIn('<figcaption id={textId} class="sr-only">{description}</figcaption>',
                      self.markup)

    def test_the_component_is_registered(self):
        self.assertEqual(sitestarlight.COMPONENTS["InstallDemo"], "components/InstallDemo.astro")


def _tab_bodies(markdown: str) -> dict[str, str]:
    """Each tab of the quick install box of Get your files, by label."""
    box = markdown[markdown.index("{ #quick-install }"):]
    box = box[:box.index("</Tabs>")]
    return dict(re.findall(r'<TabItem label="([^"]+)">(.*?)</TabItem>', box, re.S))


class TheTwoPagesShowIt(unittest.TestCase):
    def test_home_shows_the_terminal_recording(self):
        import generate_site  # noqa: PLC0415

        tag = generate_site.install_demo()[0]
        self.assertIn(f'description="{generate_readme.demo_description()}"', tag)
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        body = source[source.index("def generate_home("):]
        body = body[:body.index("\ndef ", 1)]
        self.assertIn("*install_demo(),", body)

    def test_each_tab_of_get_your_files_shows_its_variant(self):
        import generate_site  # noqa: PLC0415

        tabs = _tab_bodies(generate_site.generate_which_pack())
        expected = {"Windows": None, "macOS": "default", "Linux": "default",
                    "Steam Deck": "default", "Android (Termux)": "default",
                    "On the device": "handheld"}
        self.assertEqual(set(tabs), set(expected))
        for label, variant in expected.items():
            demos = re.findall(r"<InstallDemo [^>]*/>", tabs[label])
            with self.subTest(tab=label):
                if variant is None:
                    self.assertEqual(demos, [])
                    continue
                self.assertEqual(len(demos), 1)
                self.assertIn(f'description="{_facts(variant)["alt"]}"', demos[0])
                self.assertIn(f'width="{_facts(variant)["width"]}"', demos[0])
                self.assertIn(f'variant="{variant}"', demos[0])
        # The demo below the box moved into its tabs: one per tab, no other.
        page = generate_site.generate_which_pack()
        self.assertEqual(page.count("<InstallDemo "), len(expected) - 1)

    def test_the_site_serves_the_videos_not_the_gif(self):
        import generate_site  # noqa: PLC0415

        expected = tuple(name for variant in make_demo.VARIANTS.values()
                         for name in variant.outputs if not name.endswith(".gif"))
        self.assertEqual(sorted(generate_site.DEMO_ASSETS), sorted(expected))

    def test_the_built_pages_fetch_nothing_of_it(self):
        if not (DIST / "index.html").is_file():
            self.skipTest("no built site")
        for page in ("index.html", "which-pack/index.html"):
            html = (DIST / page).read_text(encoding="utf-8")
            figures = re.findall(r'<figure class="rb-demo[^"]*".*?</figure>', html, re.S)
            with self.subTest(page=page):
                self.assertTrue(figures)
                for figure in figures:
                    self.assertIn('preload="none"', figure)
                    self.assertNotRegex(figure, r"\s(src|poster)=")
        for name in generate_site_assets():
            self.assertTrue((DIST / "assets" / "demo" / name).is_file())

    def test_the_built_tabs_hold_their_variant(self):
        page = DIST / "which-pack" / "index.html"
        if not page.is_file():
            self.skipTest("no built site")
        html = page.read_text(encoding="utf-8")
        panel = r'<div[^>]*role="tabpanel"'
        panels = re.findall(rf"{panel}[^>]*>(.*?)(?={panel}|</starlight-tabs>)", html, re.S)
        variants = [re.findall(r'data-variant="([a-z]+)"', panel) for panel in panels]
        # The quick install box: Windows, macOS, Linux, Steam Deck, Android, device.
        self.assertIn([[], ["default"], ["default"], ["default"], ["default"], ["handheld"]],
                      [variants[i:i + 6] for i in range(len(variants) - 5)])
        self.assertIn("assets/demo/install-handheld.png", html)


def generate_site_assets() -> tuple[str, ...]:
    import generate_site  # noqa: PLC0415

    return generate_site.DEMO_ASSETS


if __name__ == "__main__":
    unittest.main()
