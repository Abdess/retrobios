"""Entry pages, get/ and guides (round 5, package 4).

The get/ page of a setup with no ZIP printed one command for three
systems, with no --dest, so it failed on the computer most readers open
it on. "All good when you see 0 wrong hash" was also what an empty folder
prints. Setups with no ZIP lost every route that works without a network.
The get/ pages were titled "Download KNULLI", /get/ answered 404, and two
Linux handheld rows sent the reader to a menu.
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
from common import load_platform_config, load_platform_registry  # noqa: E402
from tests import sitepages  # noqa: E402

REGISTRY = load_platform_registry(str(REPO_ROOT / "platforms"))
SETUPS = [name for name in siteguides.GUIDES if name in REGISTRY]
COMMAND = re.compile(r"^(?:curl -fsSL |&\(\[scriptblock\]|irm ).*$", re.M)
OFFLINE_ANCHOR = "#without-a-network-offline-install"
CARD_FAQ = "/retrobios/wiki/faq/#fill-an-sd-card-from-a-computer"


def _page(name: str) -> str:
    sitepages.require()
    return re.sub(r"</?abbr[^>]*>", "", sitepages.page(name).read_text(encoding="utf-8"))


def _guide_part(text: str) -> str:
    match = re.search(r"^## Reference\b", text, re.M)
    return text[: match.start()] if match else text


def _with_zip(name: str) -> bool:
    pack = release_record.pack_for(name, release_record.load_advertised())
    return bool(pack and pack.get("assets"))


def _display(name: str) -> str:
    return load_platform_config(name, str(REPO_ROOT / "platforms")).get("platform", name)


def _tab_labels(text: str) -> set[str]:
    return set(re.findall(r'<TabItem label="([^"]+)"', text))


class GetPagesGiveTheSetupsOwnRoutes(unittest.TestCase):
    def test_every_command_on_a_get_page_is_on_its_setup_page(self):
        for name in SETUPS:
            get = set(COMMAND.findall(_page(f"get/{name}.md")))
            page = _page(f"platforms/{name}.md")
            setup = set(COMMAND.findall(page))
            with self.subTest(setup=name):
                # The Mac and Linux lines of the network folder live on the
                # get/ page alone, which the setup page links for them.
                if f"(/retrobios/get/{name}/#from-your-computer)" in page:
                    get = {c for c in get if "--dest /Volumes/" not in c
                           and "--dest /path/to/" not in c}
                self.assertTrue(get <= setup, sorted(get - setup))
                if not _with_zip(name):
                    self.assertTrue(get, "a setup with no ZIP gets its command")

    def test_a_card_setup_names_the_card(self):
        for name in SETUPS:
            if not siteguides.GUIDES[name].on_card:
                continue
            with self.subTest(setup=name):
                for command in COMMAND.findall(_page(f"get/{name}.md")):
                    self.assertIn("--dest ", command)

    def test_no_tab_for_a_system_the_setup_does_not_run_from(self):
        labels = {key: entry[0] for key, entry in siteguides.TERMINALS.items()}
        for name in SETUPS:
            if _with_zip(name):
                continue
            guide = siteguides.GUIDES[name]
            allowed = {labels[key] for key in guide.run}
            allowed |= {labels[key] for key in guide.card_run or ("windows", "macos", "linux")}
            if generate_site._network_share(name, guide):
                # The network folder is reached from any computer.
                allowed |= {labels[key] for key in ("windows", "macos", "linux")}
            with self.subTest(setup=name):
                self.assertLessEqual(_tab_labels(_page(f"get/{name}.md")), allowed)
                self.assertNotIn("Android (Termux", _page(f"get/{name}.md"))

    def test_retrodeck_runs_from_linux_and_the_deck(self):
        text = _page("get/retrodeck.md")
        install = text.split("## Install", 1)[1].split("No network", 1)[0]
        self.assertEqual(_tab_labels(install), {"Steam Deck", "Linux"})

    def test_one_helper_writes_both_pages(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        get_page = source.split("def generate_get_page", 1)[1].split("\ndef ", 1)[0]
        guide = source.split("def _platform_guide", 1)[1].split("\ndef ", 1)[0]
        self.assertNotIn("install_commands(", get_page)
        self.assertIn("_setup_routes(", get_page)
        self.assertIn("_setup_routes(", guide)


class CheckNeedsTheFiles(unittest.TestCase):
    def test_the_pass_line_is_what_the_installer_prints_only_when_complete(self):
        installer = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        printed = re.search(r"`([^`]+)`", generate_site.check_pass_line())[1]
        self.assertEqual(printed, generate_site._installer().EVERYTHING_IN_PLACE)
        self.assertIn('print(f"\\n  {EVERYTHING_IN_PLACE}")', installer)
        self.assertNotIn("wrong hash", generate_site.check_pass_line())

    def test_no_setup_page_passes_an_empty_folder(self):
        for name in SETUPS:
            text = _page(f"platforms/{name}.md")
            with self.subTest(setup=name):
                self.assertNotIn("All good when you see `0 wrong hash`", text)
                self.assertIn(generate_site.check_pass_line(), text)


class ARouteWithoutANetwork(unittest.TestCase):
    def test_every_setup_page_has_the_offline_line_or_the_card_route(self):
        for name in SETUPS:
            guide = siteguides.GUIDES[name]
            text = _guide_part(_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                if _with_zip(name):
                    self.assertIn(OFFLINE_ANCHOR, text)
                elif guide.on_card:
                    self.assertIn("Put the SD card in a computer.", text)
                else:
                    self.assertIn("No network", text)
                    self.assertNotIn(OFFLINE_ANCHOR, text)

    def test_every_device_setup_with_no_zip_links_the_card_answer(self):
        for name in SETUPS:
            guide = siteguides.GUIDES[name]
            if _with_zip(name) or guide.run != ("device",):
                continue
            extract_to = REGISTRY[name]["extract_to"]
            for page in (f"platforms/{name}.md", f"get/{name}.md"):
                text = _page(page)
                with self.subTest(page=page):
                    self.assertIn("## From your computer { #from-your-computer }", text)
                    self.assertIn(CARD_FAQ, text)
                    self.assertIn(f"the folder the device calls `{extract_to}`", text)
                    self.assertIn(f"--platform {name} --dest /path/to/", text)

    def test_rocknix_has_a_computer_route(self):
        text = _guide_part(_page("platforms/rocknix.md"))
        self.assertLess(text.index("## From your computer"), text.index("## On the device"))

    def test_retropie_card_is_read_from_linux_only(self):
        self.assertEqual(siteguides.GUIDES["retropie"].card_run, ("linux",))
        text = _page("platforms/retropie.md")
        card = text.split("No network?", 1)[1].split("## On the device", 1)[0]
        self.assertEqual(_tab_labels(card), {"Linux"})

    def test_no_zip_is_promised_for_an_unmarked_setup(self):
        for name in SETUPS:
            if REGISTRY[name].get("release_pack") is True:
                continue
            with self.subTest(setup=name):
                for page in (f"platforms/{name}.md", f"get/{name}.md"):
                    text = _guide_part(_page(page))
                    self.assertNotIn("/releases/download/", text)
                    self.assertNotIn(OFFLINE_ANCHOR, text)


class GetPagesSayWhatTheyHold(unittest.TestCase):
    def test_title_description_and_parent(self):
        for name in SETUPS:
            display = _display(name)
            text = sitepages.page(f"get/{name}.md").read_text(encoding="utf-8")
            kind = "pack" if REGISTRY[name].get("release_pack") is True else "files"
            title = (f"BIOS {kind} for {display}"
                     if (REPO_ROOT / "emulators" / f"{name}.yml").is_file()
                     else f"{display} BIOS {kind}")
            with self.subTest(setup=name):
                self.assertEqual(generate_site.get_page_title(name, display), title)
                self.assertIn(f"title: {title}\n", text)
                self.assertNotIn("Download ", text.split("\n---\n", 1)[0].split("title:", 1)[1]
                                 .split("\n", 1)[0])
                self.assertIn(f"link: /platforms/{name}/", text)
                if kind == "files":
                    self.assertIn(f"The BIOS files for {display}: one command installs and "
                                  "checks them.", text)

    def test_a_setup_with_no_zip_links_its_get_page(self):
        for name in SETUPS:
            if REGISTRY[name].get("release_pack") is True:
                continue
            with self.subTest(setup=name):
                title = generate_site.get_page_title(name, _display(name))
                self.assertIn(f"Link to share: [{title}](/retrobios/get/{name}/)",
                              _page(f"platforms/{name}.md"))

    def test_a_relative_folder_is_named_as_the_setups(self):
        text = _page("get/retroarch.md")
        self.assertIn("Unzip them all into RetroArch's `system` folder. "
                      "[Where is it?](/retrobios/platforms/retroarch/#where-the-files-go)", text)
        self.assertIn("In RetroArch, open **Settings > Directory > System/BIOS**", text)
        self.assertIn("into RetroBat's `bios` folder", _page("get/retrobat.md"))
        self.assertNotIn("into `system/`", text)


class HandheldRowsSayWhere(unittest.TestCase):
    def test_retrooz_names_its_folder_with_a_pinned_source(self):
        system = next(s for s in siteguides.HANDHELD_GUIDE.systems if s.name == "RetroOZ")
        self.assertIn("`/roms/bios`", system.folder)
        self.assertRegex(system.folder_source, r"/wiki/Home/[0-9a-f]{40}$")
        row = next(line for line in _page("platforms/linux-handhelds.md").splitlines()
                   if line.startswith("| RetroOZ |"))
        self.assertNotIn(generate_site.RETROARCH_FOLDER_SETTING, row)


class GetIndex(unittest.TestCase):
    def test_every_setup_is_linked_under_its_group(self):
        text = _page("get/index.md")
        for name in SETUPS:
            with self.subTest(setup=name):
                self.assertIn(f"(/retrobios/get/{name}/)", text)
        for label, _description in siteguides.DEVICE_GROUPS.values():
            self.assertIn(f"## {label}", text)


class HomeAndWhichPack(unittest.TestCase):
    def test_the_home_step_does_not_promise_a_zip(self):
        text = _page("index.md")
        self.assertIn("**Run one command.** Some setups have a ZIP.", text)
        self.assertNotIn("or download a ZIP file", text)

    def test_which_pack_answers_ios(self):
        text = _page("which-pack.md")
        meta = re.search(r'data-pagefind-meta="terms:([^"]+)"', text)
        self.assertIsNotNone(meta)
        for word in ("ios", "iphone", "ipad", "delta", "provenance"):
            self.assertIn(word, meta[1].split())


class TheSiteSaysWhatTheInstallerShows(unittest.TestCase):
    """which-pack showed a line menu (Enter, i, c, q) the one-liner never
    opens, typed by hand, its keys out of date. The site, the README and
    the wiki now take the screen's words and the line menu from install.py."""

    MENU_LINES = ("Enter) install everything", "i) only what the installed cores read",
                  "c) choose systems, cores and regions")

    def test_which_pack_describes_the_screen_in_the_installers_words(self):
        installer = generate_site._installer()
        text = _page("which-pack.md")
        for line in generate_site.first_screen_words():
            self.assertIn(line, text)
        self.assertIn(f"**{installer.TUI_INSTALL_ROW}**", text)
        self.assertIn(f"**{installer.TUI_SYSTEMS_ROW}**", text)
        for line in self.MENU_LINES:
            self.assertNotIn(line, text)
        self.assertNotIn("press **c**", text)

    def test_the_plan_rows_are_the_words_the_pages_use(self):
        installer = generate_site._installer()
        state = installer.TuiState(os_type="linux", home=Path("/home/me"))
        state.stack = ["plan"]
        state.check = {"files": 2, "present": 0, "missing": 2, "wrong_hash": 0, "need": 2,
                       "bytes_needed": 10}
        state.systems = [{"system": name, "missing": 1, "wrong_hash": 0, "present": 0,
                          "files": 1, "bytes_needed": 5} for name in ("a", "b")]
        state.manifest = {"files": [{"dest": "a.bin", "systems": ["a"]},
                                    {"dest": "b.bin", "systems": ["b"]}]}
        state.ticked = {"a", "b"}
        state.checked_flags = installer.tui_flags(state)
        labels = [row.label for row in installer.tui_rows(state)]
        self.assertEqual(labels[0], installer.TUI_INSTALL_ROW)
        self.assertIn(installer.TUI_SYSTEMS_ROW, labels)

    def test_the_readme_and_the_wiki_take_the_same_words(self):
        installer = generate_site._installer()
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"fewer under **{installer.TUI_SYSTEMS_ROW}**", readme)
        self.assertNotIn("offers to install everything or to choose systems", readme)
        source = (REPO_ROOT / "scripts" / "generate_readme.py").read_text(encoding="utf-8")
        self.assertIn("_installer_words().TUI_SYSTEMS_ROW", source)
        import generate_installer_doc  # noqa: PLC0415

        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn(generate_installer_doc.line_menu(), page)
        menu = page.split("<!-- generated: line-menu -->", 1)[1]
        outside = page.replace(menu.split("<!-- /generated: line-menu -->", 1)[0], "")
        for line in self.MENU_LINES:
            self.assertNotIn(line, outside)


if __name__ == "__main__":
    unittest.main()
