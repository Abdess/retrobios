"""Entry pages and guides.

The home page said the command "writes only in your BIOS folder" while
install.py writes the entries a manifest files under `root: save` into the
frontend's save folder. It ended on a tinted "Next" box, a raw ISO stamp and
a setup count the diagrams gave one lower. Get your files offered the same
choice three times, a Batocera page sent a beginner to "a terminal on the
device" with no way to open one, and command blocks had no Windows form or
no title.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))

import generate_readme  # noqa: E402
import generate_site  # noqa: E402
import release_record  # noqa: E402
import siteguides  # noqa: E402
import sitemarkup  # noqa: E402
from common import load_platform_config, load_platform_registry  # noqa: E402
from tests import sitepages  # noqa: E402

REGISTRY = load_platform_registry(str(REPO_ROOT / "platforms"))
GUIDES_YAML = (REPO_ROOT / "platforms" / "_guides.yml").read_text(encoding="utf-8")
UNTITLED_FENCE = re.compile(r"^\s*```(?:sh|powershell)\s*$", re.M)
# A path a reader types: a network share, a home or root path, a drive letter.
ABSOLUTE_PATH = re.compile(
    r"(?<![\w/@:}>])(?:\\\\[^\s,)]+|smb://[^\s,)]+|~/[^\s,)]*|/[A-Za-z][^\s,)]*|[A-Z]:\\[^\s,)]*)"
)


def _page(name: str) -> str:
    sitepages.require()
    return sitepages.page(name).read_text(encoding="utf-8")


def _body(text: str) -> str:
    """A page without its front matter."""
    return text.split("\n---\n", 1)[1] if text.startswith("---\n") else text


def _guide_part(text: str) -> str:
    match = re.search(r"^## Reference\b", text, re.M)
    return text[: match.start()] if match else text


class TrustItemsSayWhereItWrites(unittest.TestCase):
    def test_no_only_in_the_bios_folder_while_a_manifest_writes_saves(self):
        saves = [
            path.name for path in sorted((REPO_ROOT / "install").glob("*.json"))
            if any(entry.get("root") == "save"
                   for entry in json.loads(path.read_text(encoding="utf-8")).get("files", []))
        ]
        self.assertTrue(saves, "no manifest files an entry under root: save")
        text = " ".join(siteguides.TRUST_ITEMS).lower()
        self.assertNotIn("only in your bios folder", text)
        self.assertIn("save folder", text)
        self.assertIn("--restore", text)

    def test_home_shows_the_same_items(self):
        home = _page("index.md")
        for item in siteguides.TRUST_ITEMS:
            self.assertIn(f"- {item}", home)
        self.assertNotIn("only in your BIOS folder", home)


class NextStepsIsAPlainList(unittest.TestCase):
    def test_the_helpers(self):
        block = "\n".join(generate_site._next_block(["[A](a.md)", "[B](b.md)"]))
        self.assertEqual(block, "## Next steps\n\n- [A](a.md)\n- [B](b.md)\n")
        self.assertIn("## Next steps", generate_site.reference_next())
        self.assertNotIn(":::", generate_site.reference_next())

    def test_entry_pages(self):
        for name in ("which-pack.md", "contributing.md", "platforms/batocera.md",
                     "platforms/retroarch.md"):
            with self.subTest(page=name):
                text = _page(name)
                self.assertNotIn(":::tip[Next]", text)
                self.assertIn("## Next steps", text)

    def test_home_has_no_next_box_and_no_stamp(self):
        home = _page("index.md")
        self.assertNotIn("Next steps", home)
        self.assertNotIn(":::tip", home)
        self.assertNotIn("Generated on", home)
        self.assertNotRegex(home, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class DatesInWords(unittest.TestCase):
    def test_data_as_of(self):
        moment = datetime(2026, 10, 22, 22, 43, 8, tzinfo=timezone.utc)
        self.assertEqual(
            generate_site.data_as_of(moment),
            '<time datetime="2026-10-22T22:43:08Z">Data as of 22 October 2026</time>',
        )

    def test_get_your_files_carries_no_date(self):
        self.assertNotIn("Generated on", _page("which-pack.md"))


class OneSetupCount(unittest.TestCase):
    def test_every_entry_page_states_the_registry_count(self):
        count = len(REGISTRY)
        self.assertEqual(siteguides.setup_count(), count)
        self.assertIn(f"and {count - 3} more.", _page("index.md"))
        self.assertIn(f'<span class="rb-stat-value">{count}</span>', _page("explore.md"))


class SetupTiles(unittest.TestCase):
    def test_one_tile_per_setup_on_home_and_get_your_files(self):
        for name in ("index.md", "which-pack.md"):
            text = _page(name)
            with self.subTest(page=name):
                extra = sum(len(tiles) for tiles in siteguides.GROUP_TILES.values())
                self.assertEqual(text.count('class="rb-card rb-tile"'), len(REGISTRY) + extra)
                for key in REGISTRY:
                    self.assertIn(f'href="/retrobios/platforms/{key}/"', text)

    def test_get_your_files_offers_the_choice_once(self):
        text = _page("which-pack.md")
        self.assertEqual(text.count('class="rb-card"'), 0)
        self.assertEqual(text.count("<FilePicker"), 1)

    def test_a_setup_without_a_logo_shows_its_initials(self):
        self.assertEqual(sitemarkup.initials("MyMinUI"), "MM")
        tile = "".join(sitemarkup.platform_tiles([("MyMinUI", "x.md", "", "Handhelds")]))
        self.assertIn(">MM</text>", tile)
        tile = "".join(sitemarkup.platform_tiles([("RomM", "x.md", "logo.png", "A server")]))
        self.assertIn('<img class="rb-card-logo" src="logo.png"', tile)

    def test_a_one_setup_group_is_not_titled_with_its_own_name(self):
        home = _page("index.md")
        display = {k: load_platform_config(k, str(REPO_ROOT / "platforms")).get("platform", k)
                   for k in REGISTRY}
        for group, (label, _description) in siteguides.DEVICE_GROUPS.items():
            members = [k for k in REGISTRY if REGISTRY[k].get("device_group") == group]
            if len(members) == 1:
                with self.subTest(group=group):
                    self.assertNotIn(f"**{label}**", home)
                    self.assertIn(f">{display[members[0]]}</strong>", home)

    def test_hardware_is_named_and_cited(self):
        self.assertIn("Raspberry Pi", siteguides.GUIDES["batocera"].summary)
        self.assertIn("Raspberry Pi", siteguides.DEVICE_GROUPS["gaming-os"][0])
        self.assertIn("Anbernic", siteguides.DEVICE_GROUPS["handheld"][0])
        lines = GUIDES_YAML.splitlines()
        for number, line in enumerate(lines):
            if re.match(r"    (runs_on|terminal):", line):
                with self.subTest(line=line.strip()):
                    self.assertTrue(lines[number - 1].lstrip().startswith("#"),
                                    "no source cited on the line above")


class GetYourFilesOrder(unittest.TestCase):
    def test_choice_then_tables_then_picker_then_command(self):
        text = _page("which-pack.md")
        order = [text.index(mark) for mark in (
            "## Pick your setup", "| Setup | Runs on | BIOS folder | ZIP |", "<FilePicker",
            "## Not in the list? One command finds it", "It asks **",
            "<summary>Is it safe?</summary>",
        )]
        self.assertEqual(order, sorted(order))

    def test_a_setup_after_the_release_says_no_zip_yet(self):
        text = _page("which-pack.md")
        self.assertNotIn("Not in v", text)
        record = release_record.load_advertised()
        pending = [k for k in REGISTRY if REGISTRY[k].get("release_pack")
                   and not release_record.pack_for(k, record)]
        if record.get("tag") and pending:
            self.assertIn("No ZIP yet. [Use the command]", text)
            self.assertIn("Setups added after the last release have no ZIP until the next one.",
                          text)
        else:
            self.assertNotIn("No ZIP yet.", text)
        if any(not entry.get("release_pack") for entry in REGISTRY.values()):
            self.assertIn("No ZIP. [Use the command]", text)

    def test_zip_advice_answers_the_usual_mistakes(self):
        text = _page("which-pack.md")
        self.assertIn("Download every part", text)
        self.assertIn("not in a new folder", text)
        self.assertIn("`neogeo.zip`", text)


class GuideRoutes(unittest.TestCase):
    def test_a_device_system_opens_on_the_computer_route(self):
        text = _page("platforms/batocera.md")
        self.assertLess(text.index("## From your computer"), text.index("## On the device"))
        self.assertIn("{ #install }", "\n".join(generate_site._guide_install(
            "batocera", siteguides.GUIDES["batocera"], "## On the device { #install }")))
        self.assertIn("Unzip them all into the network folder above", text)

    def test_a_computer_app_keeps_the_command_first(self):
        text = _page("platforms/retroarch.md")
        self.assertLess(text.index("## Install"), text.index("## Download"))

    def test_each_device_tab_says_how_to_open_its_terminal(self):
        shared = siteguides.TERMINALS["device"][1]
        for name, guide in siteguides.GUIDES.items():
            if "device" not in guide.run:
                continue
            with self.subTest(platform=name):
                self.assertTrue(guide.terminal, "no terminal text of its own")
                text = _guide_part(_page(f"platforms/{name}.md"))
                self.assertIn(guide.terminal.split(".")[0], text)
                self.assertNotIn(shared, text)

    def test_retroarch_names_the_menu_before_the_folders(self):
        text = _page("platforms/retroarch.md")
        self.assertLess(text.index("Settings > Directory > System/BIOS"),
                        text.index("| Where | BIOS folder |"))

    def test_emudeck_names_the_card_and_ends_the_job(self):
        text = _guide_part(_page("platforms/emudeck.md"))
        self.assertIn("installed on the SD card", text)
        self.assertIn("Return to Gaming Mode", text)
        self.assertNotIn("it is on the card", text)


class PackManualReadsThePageFolders(unittest.TestCase):
    def test_every_path_in_a_pack_manual_is_a_folder_of_its_page(self):
        for name, guide in siteguides.GUIDES.items():
            if not guide.pack_manual:
                continue
            known = " ".join(path.replace("`", "") for _w, path in siteguides.folder_list(name))
            known += " " + str(REGISTRY[name].get("extract_to") or "")
            for path in ABSOLUTE_PATH.findall(siteguides.pack_manual(name)):
                with self.subTest(platform=name, path=path):
                    self.assertIn(path.rstrip(".:"), known)

    def test_the_retroarch_manual_lists_the_detected_systems(self):
        manual = siteguides.pack_manual("retroarch")
        self.assertNotIn("{folders}", manual)
        self.assertIn("/run/muos/storage/bios", manual)
        self.assertIn("~/.var/app/org.libretro.RetroArch/config/retroarch/system/", manual)


class DownloadNamesTheRelease(unittest.TestCase):
    def test_tag_date_checksums_and_signature(self):
        record = release_record.load_record()
        if not release_record.pack_for("batocera", record):
            self.skipTest("release.json has no Batocera pack")
        tag = record["tag"]
        lines = generate_site.release_line("batocera", record)
        self.assertTrue(lines[0].startswith(f"Pack {tag}, built "))
        self.assertIn(f"/releases/download/{tag}/SHA256SUMS.txt)", lines[0])
        self.assertIn(f"/releases/download/{tag}/SHA256SUMS.txt.sig)", lines[0])
        self.assertEqual(generate_site._release_date("v2026.10.10"), "10 October 2026")

    def test_a_newer_platform_than_the_pack_is_named(self):
        record = {"tag": "v2026.10.10", "packs": {"RetroBat_1.0_BIOS_Pack.zip": {
            "assets": ["RetroBat_1.0_BIOS_Pack.zip"], "platforms": ["retrobat"]}}}
        version = load_platform_config("retrobat", str(REPO_ROOT / "platforms"))["version"]
        lines = generate_site.release_line("retrobat", record)
        self.assertIn(f"built for RetroBat 1.0. The command installs the files for "
                      f"RetroBat {version}.", lines[-1])


class CommandBlocks(unittest.TestCase):
    def test_every_command_on_an_entry_page_has_a_title(self):
        names = ["index.md", "which-pack.md", "contributing.md"] + [
            f"platforms/{key}.md" for key in REGISTRY]
        for name in names:
            with self.subTest(page=name):
                self.assertIsNone(UNTITLED_FENCE.search(_guide_part(_page(name))))

    def test_shell_lines_have_a_powershell_form(self):
        text = _page("which-pack.md")
        groups = re.findall(r"<Tabs.*?</Tabs>|<details.*?</details>", text, re.S)
        commands = [group for group in groups if "/i | sh" in group]
        self.assertGreaterEqual(len(commands), 3)
        for group in commands:
            self.assertIn("/i.ps1", group)
        block = "\n".join(generate_site._console_install_block(
            "PlayStation", [("batocera", "psx"), ("recalbox", "psx")]))
        # Every setup's options in both forms: the list of every command,
        # and the one command under the OS tabs.
        sh_args = re.findall(r"/i \| sh -s -- ([^<\n]+)", block)
        ps_args = re.findall(r"/i\.ps1\)\)\) ([^<\n]+)", block)
        self.assertEqual(sorted(set(sh_args)), sorted(set(ps_args)))
        self.assertEqual(len(set(sh_args)), 2)
        self.assertIn('```powershell title="PowerShell"', block)
        for key, guide in siteguides.GUIDES.items():
            if "windows" in guide.run:
                with self.subTest(platform=key):
                    self.assertIn("/i.ps1", _guide_part(_page(f"platforms/{key}.md")))


class ContributingOpensOnTheAction(unittest.TestCase):
    def test_both_generators_open_on_the_upload(self):
        for text in (generate_readme.generate_contributing(), generate_site.generate_contributing()):
            body = text.split("## Add a BIOS file", 1)[1]
            self.assertTrue(body.lstrip().startswith("Have a file the collection lacks?"))
            self.assertLess(body.index(generate_readme.UPLOAD_URL), body.index("## What happens next"))
            self.assertLess(body.index("gaps"), body.index("## What happens next"))
            self.assertLess(body.index("## What happens next"), body.index("CI hashes"))

    def test_description_is_a_sentence(self):
        text = generate_site._page_description("", Path("contributing.md"), "Contributing")
        self.assertTrue(text.endswith("."))
        fallback = generate_site._page_description(
            "One file needs no clone and no local setup at all here:\n\n"
            "A plain sentence that describes the page well enough.",
            Path("other.md"), "Other")
        self.assertEqual(fallback, "A plain sentence that describes the page well enough.")


class HomeLinksTheOtherTasks(unittest.TestCase):
    def test_troubleshooting_file_check_and_legal(self):
        home = _body(_page("index.md"))
        for target in ("/retrobios/wiki/troubleshooting/", "/retrobios/files/",
                       "/retrobios/wiki/legal/"):
            self.assertIn(f"]({target})", home)
        self.assertLess(home.index("/retrobios/wiki/troubleshooting/"), home.index("## Do I need it?"))


if __name__ == "__main__":
    unittest.main()
