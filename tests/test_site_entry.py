"""Entry pages, get/ pages and guides.

The home page said the command "writes only in your BIOS folder" while
install.py writes the entries a manifest files under `root: save` into the
frontend's save folder. It ended on a tinted "Next" box, a raw ISO stamp and
a setup count the diagrams gave one lower. Get your files offered the same
choice three times, a Batocera page sent a beginner to "a terminal on the
device" with no way to open one, and command blocks had no Windows form or
no title.

A handheld owner found no tile for Android, ArkOS, muOS, Onion or spruceOS:
the systems sat in a closed note with a path seen from inside the device.
The setup version a pack fits was named only under Reference, the setup page
offered the full pack only, Get your files listed every setup twice, the Your
setup index ended on a table in project words, and the home page said a
Dreamcast needs its BIOS while Flycast boots without one.

Six handheld setups have no ZIP, and three of them offered SSH as root as
the only route while their page already named a network folder. Six rows
of the Linux handhelds table said "The command finds it on the device" for
devices with no terminal, while the installer held each folder with its
source. The offline line sat on six setup pages, the home page carried a
stray "Reference:" label, the Your setup index left out the handheld tiles,
and an iPhone owner found one FAQ line.

The get/ page of a setup with no ZIP printed one command for three
systems, with no --dest, so it failed on the computer most readers open
it on. "All good when you see 0 wrong hash" was also what an empty folder
prints. Setups with no ZIP lost every route that works without a network.
The get/ pages were titled "Download KNULLI", /get/ answered 404, and two
Linux handheld rows sent the reader to a menu.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

import yaml

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
        # A term's first use on the page carries its gloss.
        home = re.sub(r"</?abbr[^>]*>", "", _page("index.md"))
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
        self.assertIn('data-initials="MM"', tile)
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
            "## Pick the setup { #pick-your-setup }", "| Setup | Runs on | BIOS folder | ZIP |", "<FilePicker",
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
        self.assertLess(text.index("## From a computer"), text.index("## On the device"))
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
        self.assertLess(home.index("/retrobios/wiki/troubleshooting/"), home.index("## Is it needed? { #do-i-need-it }"))


GUIDE = siteguides.HANDHELD_GUIDE


def _plain_guide_part(text: str) -> str:
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
                self.assertIn(f"| {generate_site.handheld_name(system)} |", text)

    def test_a_system_that_stopped_says_so_with_its_source(self):
        """ArkOS was archived on 30 December 2025 and points to dArkOS: the
        guide listed it first, as a system to install."""
        systems = {s.name: s for s in GUIDE.systems}
        self.assertEqual(GUIDE.systems[0].name, "dArkOS")
        self.assertIn("replaced by dArkOS", systems["ArkOS"].ended)
        self.assertTrue(systems["ArkOS"].ended_source.startswith("https://github.com/"))
        self.assertTrue(systems["JELOS"].ended)
        self.assertNotIn("ArkOS,", GUIDE.summary.replace("dArkOS,", ""))
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_system({"name": "X", "ended": "no longer updated"}, "test")

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
        setup = next(tab["Setups"] for tab in nav if "Setups" in tab)
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
        name = release_record.pack_name_for("batocera", record)
        version = generate_site._pack_version(name, ["batocera"])
        self.assertIn(f"Made for Batocera {version}. "
                      + generate_site.other_version("batocera"), block)

    def test_a_version_gap_is_said_once(self):
        record = {"tag": "v2026.10.10", "packs": {"RetroBat_1.0_BIOS_Pack.zip": {
            "assets": ["RetroBat_1.0_BIOS_Pack.zip"], "platforms": ["retrobat"]}}}
        released = generate_site.release_line("retrobat", record)
        line = generate_site.version_line("retrobat", record, named=len(released) > 1)
        self.assertEqual(line, generate_site.other_version("retrobat"))

    def test_a_version_with_an_underscore_is_read_whole(self):
        """AmberELEC's prerelease-20261019_1835 read as 1835, and the page
        said the pack was built for another version."""
        from generate_pack import _platform_pack_stem

        version = load_platform_config("amberelec", "platforms")["version"]
        name = _platform_pack_stem(["amberelec"], "amberelec", "platforms") + "_BIOS_Pack.zip"
        self.assertEqual(generate_site._pack_version(name, ["amberelec"]), version)
        record = {"tag": "v2026.10.10", "packs": {name: {
            "assets": [name], "platforms": ["amberelec"]}}}
        self.assertEqual(len(generate_site.release_line("amberelec", record)), 1)

    def test_another_version_is_sent_to_the_check_commands(self):
        """A ZIP reader read "Run `--check` after copying." with no command."""
        line = generate_site.other_version("emudeck")
        self.assertNotIn("Run `--check`", line)
        self.assertIn("](../platforms/emudeck.md#how-to-check)", line)
        page = _page("platforms/emudeck.md")
        self.assertIn("{ #how-to-check }", page)

    def test_the_v_prefix_is_dropped(self):
        self.assertEqual(generate_site.setup_version("retroarch", {}),
                         f"RetroArch {load_platform_config('retroarch', 'platforms')['version'].lstrip('v')}")

    def test_every_setup_page_names_a_version(self):
        """A setup with a release ZIP names the version it was made for. One
        without says there is no ZIP: the command installs current files."""
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _plain_guide_part(_page(f"platforms/{key}.md"))
                if generate_site.has_release_pack(key):
                    self.assertRegex(text, r"(?:[Mm]ade for|This pack was built for) \S")
                else:
                    self.assertIn(generate_site.no_zip_line(_display(key)), text)


class SetupPagesOfferPartOfThePack(unittest.TestCase):
    def test_pick_them_and_press_c(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _plain_guide_part(_page(f"platforms/{key}.md"))
                self.assertIn(f"/retrobios/which-pack/?platform={key}#only-some-consoles", text)
                # The screen's own row: the line menu's c is not what the
                # one-liner opens.
                self.assertIn("or the command's **Choose systems**.", text)
                # Never "choose **Choose systems**".
                self.assertNotIn("choose **Choose systems**", text)

    def test_the_anchor_exists(self):
        self.assertIn("## Only some consoles?", _page("which-pack.md"))

    def test_a_file_in_place_but_missing_is_answered(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                self.assertIn("Reported missing anyway?",
                              _plain_guide_part(_page(f"platforms/{key}.md")))


class SafetyListIsLinked(unittest.TestCase):
    def test_setup_pages_link_the_home_list(self):
        for key in REGISTRY:
            with self.subTest(platform=key):
                text = _plain_guide_part(_page(f"platforms/{key}.md"))
                self.assertIn("[Is it safe?](/retrobios/#is-it-safe)", text)
                self.assertNotIn("<summary>Is it safe?</summary>", text)
        self.assertIn("## Is it safe? { #is-it-safe }", _page("index.md"))


class OfflineLine(unittest.TestCase):
    def test_under_from_your_computer(self):
        text = _page("platforms/batocera.md")
        start = text.index("## From a computer")
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
        out = generate_site.with_setup_table(page, {})
        self.assertTrue(out.rstrip().endswith("- [A](a.md)"))
        self.assertIn("## Every setup at a glance", out)


class HomeCopy(unittest.TestCase):
    def test_dreamcast_and_the_check_link(self):
        home = re.sub(r"</?abbr[^>]*>", "", _page("index.md"))
        self.assertIn("- **Yes** for PlayStation 2 and Neo Geo.", home)
        self.assertIn("- **Better with it** for Dreamcast: some games need it.", home)
        # A question and the link that answers it: no level label, which
        # read as a broken crumb beside the Reference tab.
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


HANDHELDS = siteguides.HANDHELD_GUIDE
OFFLINE_ANCHOR = "#without-a-network-offline-install"


def _plain_page(name: str) -> str:
    sitepages.require()
    return re.sub(r"</?abbr[^>]*>", "", sitepages.page(name).read_text(encoding="utf-8"))


def _with_zip(name: str) -> bool:
    pack = release_record.pack_for(name, release_record.load_advertised())
    return bool(pack and pack.get("assets"))


SETUPS = [name for name in siteguides.GUIDES if name in REGISTRY]


class NoZipNoUnzipText(unittest.TestCase):
    def test_a_setup_without_a_zip_never_says_unzip_or_download_pack(self):
        for name in SETUPS:
            if _with_zip(name):
                continue
            text = _guide_part(_plain_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertNotIn("Unzip the pack into", text)
                self.assertNotIn("pack holds its own", text)
                self.assertNotRegex(text, r"Download \S+ Pack")
                self.assertNotIn("/releases/download/", text)

    def test_the_minui_family_makes_each_folder(self):
        for name in ("minui", "myminui", "nextui"):
            with self.subTest(setup=name):
                self.assertIn("The command makes each console's folder.",
                              _plain_page(f"platforms/{name}.md"))

    def test_knulli_is_filled_over_the_network_with_the_samba_switch_cited(self):
        text = _guide_part(_plain_page("platforms/knulli.md"))
        self.assertIn("## From a computer { #from-your-computer }", text)
        self.assertIn("--platform knulli --dest \\\\KNULLI\\share\\bios\n", text)
        self.assertRegex(text, r"turn on \*\*SAMBA\*\* in \*\*System Settings > Services\*\*\s*"
                               r"\(\[KNULLI docs\]\(https://github\.com/knulli-cfw/knulli\.org/blob/"
                               r"[0-9a-f]{40}/docs/play/add-games/network-transfer\.md")
        # The computer route comes before the SSH one.
        self.assertLess(text.index("## From a computer"), text.index("## On the device"))

    def test_the_elec_systems_say_they_need_the_network(self):
        for name, share in (("amberelec", "\\\\AmberELEC\\roms"), ("emuelec", "\\\\EMUELEC\\roms")):
            text = _guide_part(_plain_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertIn("Needs the device on the same network.", text)
                self.assertIn(f"--platform {name} --dest {share}\n", text)

    def test_a_mac_and_a_linux_desktop_reach_the_share_too(self):
        """The share route was a PowerShell tab alone: a Mac user with Recalbox
        on Wi-Fi fell back to SSH or to taking the card out."""
        args, how = generate_site._share_tabs("recalbox", "\\\\RECALBOX\\share\\bios")
        self.assertEqual(args["macos"], "--platform recalbox --dest /Volumes/share/bios")
        self.assertIn("`smb://recalbox/share`", how["macos"])
        self.assertEqual(args["linux"], "--platform recalbox --dest /path/to/share/bios")
        self.assertIn("`smb://recalbox/share`", how["linux"])
        lines = generate_site._setup_routes("recalbox", "Recalbox")
        routes = "\n".join(lines[:lines.index("## On the device { #install }")])
        for label in ("Windows", "macOS", "Linux"):
            self.assertIn(f'label="{label}"', routes)
        # The setup page sends a Mac or Linux reader to those tabs.
        lines = generate_site._setup_routes("recalbox", "Recalbox", page_link=True)
        self.assertIn("[Mac or Linux](../get/recalbox.md#from-your-computer)", lines)

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
        text = _plain_page(HANDHELDS.path)
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
        text = _plain_page(HANDHELDS.path)
        for system in HANDHELDS.systems:
            row = next(line for line in text.splitlines()
                       if line.startswith(f"| {system.name} |")
                       or line.startswith(f"| {system.name}, "))
            with self.subTest(system=system.name):
                self.assertEqual(generate_site.LINUX_ONLY_HINT in row, system.linux_only)
        self.assertTrue(any(s.linux_only for s in HANDHELDS.systems if s.name == "ArchR"))
        self.assertNotIn("Windows and macOS cannot open", text)

    def test_linux_only_needs_a_folder(self):
        with self.assertRaises(siteguides.GuideError):
            siteguides._handheld_system({"name": "X", "linux_only": True}, "test")

    def test_download_is_one_jump_under_the_lead(self):
        text = _plain_page(HANDHELDS.path)
        self.assertIn("[Download](#download)", text)
        self.assertLess(text.index("[Download](#download)"), text.index("## Where the files go"))


class OfflineLineWithEveryZip(unittest.TestCase):
    def test_every_setup_with_a_zip_links_the_offline_install(self):
        for name in SETUPS:
            text = _guide_part(_plain_page(f"platforms/{name}.md"))
            with self.subTest(setup=name):
                self.assertEqual(OFFLINE_ANCHOR in text, _with_zip(name))

    def test_the_handheld_guide_links_it(self):
        self.assertEqual(OFFLINE_ANCHOR in _plain_page(HANDHELDS.path), _with_zip(HANDHELDS.uses))


class EntryCopy(unittest.TestCase):
    def test_no_reference_label_on_home_explore_and_the_setup_index(self):
        for name in ("index.md", "explore.md", "platforms/index.md"):
            if not sitepages.page(name).is_file():
                continue
            body = _plain_page(name).split("\n---\n", 1)[-1]
            with self.subTest(page=name):
                self.assertNotIn("Reference: [", body)
        self.assertIn("- Have a file? [Check it](/retrobios/files/)", _plain_page("index.md"))

    def test_the_explore_cards_have_bare_links(self):
        source = Path(generate_site.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"Reference: [How each platform checks files]', source)
        self.assertNotIn('"Reference: [Data and API]', source)

    def test_the_setup_index_lists_the_handheld_tiles(self):
        text = _plain_page("platforms/index.md")
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
                self.assertIn('href="/retrobios/which-pack/#iphone-and-ipad"', _plain_page(name))
        self.assertEqual(sitemarkup.initials("iPhone and iPad"), "iP")

    def test_each_app_step_is_cited_and_the_picker_replaces_the_zip(self):
        text = _plain_page("which-pack.md")
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
        text = _plain_page("which-pack.md")
        self.assertNotIn('title="What it asks"', text)
        for line in generate_site.first_screen_words():
            self.assertIn(line, text)


COMMAND = re.compile(r"^(?:curl -fsSL |&\(\[scriptblock\]|irm ).*$", re.M)
CARD_FAQ = "/retrobios/wiki/faq/#fill-an-sd-card-from-a-computer"


def _tab_labels(text: str) -> set[str]:
    return set(re.findall(r'<TabItem label="([^"]+)"', text))


class GetPagesGiveTheSetupsOwnRoutes(unittest.TestCase):
    def test_every_command_on_a_get_page_is_on_its_setup_page(self):
        for name in SETUPS:
            get = set(COMMAND.findall(_plain_page(f"get/{name}.md")))
            page = _plain_page(f"platforms/{name}.md")
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
                for command in COMMAND.findall(_plain_page(f"get/{name}.md")):
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
                self.assertLessEqual(_tab_labels(_plain_page(f"get/{name}.md")), allowed)
                self.assertNotIn("Android (Termux", _plain_page(f"get/{name}.md"))

    def test_retrodeck_runs_from_linux_and_the_deck(self):
        text = _plain_page("get/retrodeck.md")
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
            text = _plain_page(f"platforms/{name}.md")
            with self.subTest(setup=name):
                self.assertNotIn("All good when you see `0 wrong hash`", text)
                self.assertIn(generate_site.check_pass_line(), text)


class ARouteWithoutANetwork(unittest.TestCase):
    def test_every_setup_page_has_the_offline_line_or_the_card_route(self):
        for name in SETUPS:
            guide = siteguides.GUIDES[name]
            text = _guide_part(_plain_page(f"platforms/{name}.md"))
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
                text = _plain_page(page)
                with self.subTest(page=page):
                    self.assertIn("## From a computer { #from-your-computer }", text)
                    self.assertIn(CARD_FAQ, text)
                    self.assertIn(f"the folder the device calls `{extract_to}`", text)
                    self.assertIn(f"--platform {name} --dest /path/to/", text)

    def test_rocknix_has_a_computer_route(self):
        text = _guide_part(_plain_page("platforms/rocknix.md"))
        self.assertLess(text.index("## From a computer"), text.index("## On the device"))

    def test_retropie_card_is_read_from_linux_only(self):
        self.assertEqual(siteguides.GUIDES["retropie"].card_run, ("linux",))
        text = _plain_page("platforms/retropie.md")
        card = text.split("No network?", 1)[1].split("## On the device", 1)[0]
        # One system, so no tab bar: its label leads the command.
        self.assertEqual(_tab_labels(card), set())
        self.assertIn("**Linux**", card)

    def test_a_linux_partition_card_says_why_and_offers_linux_alone(self):
        """Lakka's /storage is the card's ext4 partition (Lakka-LibreELEC
        scripts/mkimage): its page offered Windows and macOS tabs for a
        folder neither can open."""
        for name in ("lakka", "retropie"):
            with self.subTest(setup=name):
                self.assertEqual(siteguides.GUIDES[name].card_run, ("linux",))
                card = _plain_page(f"platforms/{name}.md").split("No network?", 1)[1]
                card = card.split("## On the device", 1)[0]
                self.assertEqual(_tab_labels(card), set())
                self.assertNotIn("E:\\", card)
                self.assertIn("Only a Linux computer opens the card.", card)

    def test_no_zip_is_promised_for_an_unmarked_setup(self):
        for name in SETUPS:
            if REGISTRY[name].get("release_pack") is True:
                continue
            with self.subTest(setup=name):
                for page in (f"platforms/{name}.md", f"get/{name}.md"):
                    text = _guide_part(_plain_page(page))
                    self.assertNotIn("/releases/download/", text)
                    self.assertNotIn(OFFLINE_ANCHOR, text)


class GetPagesSayWhatTheyHold(unittest.TestCase):
    def test_title_description_and_parent(self):
        for name in SETUPS:
            display = _display(name)
            text = sitepages.page(f"get/{name}.md").read_text(encoding="utf-8")
            kind = "pack" if REGISTRY[name].get("release_pack") is True else "files"
            # A profile that lists files titles its page "<name> BIOS files".
            profile = REPO_ROOT / "emulators" / f"{name}.yml"
            lists = profile.is_file() and (yaml.safe_load(profile.read_text(encoding="utf-8")) or {}).get("files")
            title = f"BIOS {kind} for {display}" if lists else f"{display} BIOS {kind}"
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
                              _plain_page(f"platforms/{name}.md"))

    def test_a_relative_folder_is_named_as_the_setups(self):
        text = _plain_page("get/retroarch.md")
        self.assertIn("Unzip them all into RetroArch's `system` folder. "
                      "[Where is it?](/retrobios/platforms/retroarch/#where-the-files-go)", text)
        self.assertIn("In RetroArch, open **Settings > Directory > System/BIOS**", text)
        self.assertIn("into RetroBat's `bios` folder", _plain_page("get/retrobat.md"))
        self.assertNotIn("into `system/`", text)


class HandheldRowsSayWhere(unittest.TestCase):
    def test_retrooz_names_its_folder_with_a_pinned_source(self):
        system = next(s for s in siteguides.HANDHELD_GUIDE.systems if s.name == "RetroOZ")
        self.assertIn("`/roms/bios`", system.folder)
        self.assertRegex(system.folder_source, r"/wiki/Home/[0-9a-f]{40}$")
        row = next(line for line in _plain_page("platforms/linux-handhelds.md").splitlines()
                   if line.startswith("| RetroOZ |"))
        self.assertNotIn(generate_site.RETROARCH_FOLDER_SETTING, row)


class GetIndex(unittest.TestCase):
    def test_every_setup_is_linked_under_its_group(self):
        text = _plain_page("get/index.md")
        for name in SETUPS:
            with self.subTest(setup=name):
                self.assertIn(f"(/retrobios/get/{name}/)", text)
        for label, _description in siteguides.DEVICE_GROUPS.values():
            self.assertIn(f"## {label}", text)


class HomeAndWhichPack(unittest.TestCase):
    def test_the_home_step_does_not_promise_a_zip(self):
        text = _plain_page("index.md")
        self.assertIn("**Paste it, press Enter.** Some setups have a ZIP.", text)
        self.assertNotIn("or download a ZIP file", text)

    def test_which_pack_answers_ios(self):
        text = _plain_page("which-pack.md")
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
        text = _plain_page("which-pack.md")
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
