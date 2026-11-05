"""Wiki and release docs.

Each class names the finding it holds: an error message a reader types
into search and no page that says it, an arcade answer written for
maintainers, a subfolder setting that hides every file, FAQ labels that
read as broken crumbs, no legal route to a BIOS, a packager who cannot pin
the installer, a backslash in a PowerShell command, an events table with no
sample, the installer options printed twice, and a glossary "Pack" that
ignored parts. Every claim the copy makes is held against the repository.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sitediagrams  # noqa: E402
from check_release import (  # noqa: E402
    INSTALLER,
    SUMS,
    Asset,
    compare_release,
    installer_files,
)

WIKI = REPO_ROOT / "wiki"
FENCED = re.compile(r"^```.*?^```", re.S | re.M)
ARCADE_ANCHOR = "technical-faq.md#which-mame-version-do-the-arcade-bios-sets-match"


def _wiki(name: str) -> str:
    return (WIKI / name).read_text(encoding="utf-8")


def _front(text: str) -> dict:
    return yaml.safe_load(text.split("---", 2)[1])


def _section(text: str, heading: str) -> str:
    start = re.search(rf"(?m)^#+ {re.escape(heading)}(?:\s*\{{[^}}]*\}})?\n", text)
    if start is None:
        raise AssertionError(f"no section {heading!r}")
    rest = text[start.end():]
    blank = FENCED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), rest)
    end = re.search(r"(?m)^#{1,2} ", blank)
    return rest[: end.start()] if end else rest


def _flat(text: str) -> str:
    return " ".join(text.split())


def _profile(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))


class TroubleshootingSaysTheWordsOnScreen(unittest.TestCase):
    """C6, N3: "bios not found" ranked the page 4th, and the most quoted
    on-screen message found nothing."""

    def setUp(self):
        self.text = _wiki("troubleshooting.md")

    def test_step_one_opens_on_the_messages(self):
        step = _flat(_section(self.text, "1. Check my BIOS folder"))
        self.assertIn("**BIOS not found**, **BIOS missing** or **firmware missing**?", step)
        self.assertLess(step.index("BIOS not found"), step.index("```"))

    def test_each_message_is_cited(self):
        for source in ("bsx.cpp:1232", "fds.c:312", "libretro.cpp:866", "msg_hash_us.h:32805"):
            with self.subTest(source=source):
                self.assertIn(source, self.text)

    def test_the_disc_message(self):
        section = _flat(_section(self.text, "The BIOS is fine, the game still fails"))
        self.assertIn('"Please insert PlayStation CD-ROM"?** The BIOS works.', section)
        self.assertIn("open its `.cue` or `.m3u` file, not a `.bin`", section)

    def test_terms_for_search(self):
        terms = _front(self.text)["terms"]
        for word in ("bios not found", "bios missing", "firmware missing", "bios error"):
            with self.subTest(word=word):
                self.assertIn(word, terms)


class SubfolderTrap(unittest.TestCase):
    """C8: a BIOS setting pointed at system/dc, while Flycast adds dc/ itself."""

    def test_step_three_names_it(self):
        step = _flat(_section(_wiki("troubleshooting.md"), "3. Check the folder and the names"))
        self.assertIn("subfolder, like `system/dc`?", step)
        self.assertIn("like `dc/` for Flycast", step)

    def test_flycast_reads_dc(self):
        flycast = _profile("flycast")
        boot = next(e for e in flycast["files"] if e["name"] == "dc_boot.bin")
        self.assertEqual(boot["path"], "dc/dc_boot.bin")
        self.assertIn('appends "dc/" to the system directory', flycast["notes"])


def _arcade_profiles() -> dict[str, dict]:
    """The MAME and FinalBurn libretro cores whose name does not give the version."""
    found = {}
    for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
        if not re.match(r"(mame|fbneo|fbalpha)", path.stem):
            continue
        profile = yaml.safe_load(path.read_text(encoding="utf-8"))
        if "libretro" not in str(profile.get("type", "")):
            continue
        # Recalbox's MAME 0.258 and 0.278 carry the answer in their name.
        if _version(profile) in _retroarch_name(profile):
            continue
        found[path.stem] = profile
    return found


def _retroarch_name(profile: dict) -> str:
    """"Arcade (MAME 2003)" gives "MAME 2003", "Arcade (FinalBurn Neo) (Neo-Geo)"
    gives "FinalBurn Neo (Neo-Geo)"."""
    inner = profile["display_name"].split("(", 1)[1]
    return inner.replace(")", "", 1).strip()


def _version(profile: dict) -> str:
    return str(profile.get("mame_version") or profile["core_version"]).split()[0].lstrip("v")


class ArcadeVersionTable(unittest.TestCase):
    """C4, N3: the answer named profile ids and left out FinalBurn Neo."""

    def setUp(self):
        self.text = _wiki("technical-faq.md")
        section = _section(self.text, "Which MAME version do the arcade BIOS sets match?")
        self.section = section
        self.rows = {}
        for line in section.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if (line.startswith("|") and len(cells) == 2 and not set(cells[0]) <= {"-"}
                    and cells[1] != "Sets from"):
                for name in cells[0].split(", "):
                    self.rows[name] = cells[1]

    def test_the_section_opens_on_the_answer(self):
        self.assertTrue(self.section.lstrip().startswith(
            "Your game sets and BIOS sets must come from the same version as your arcade\nemulator."))
        self.assertIn("| Emulator, as RetroArch names it | Sets from |", self.section)
        self.assertLess(self.section.index("| Emulator"), self.section.index("### How this is known"))

    def test_every_core_has_its_row_and_version(self):
        profiles = _arcade_profiles()
        self.assertGreaterEqual(len(profiles), 20)
        for key, profile in profiles.items():
            name = _retroarch_name(profile)
            with self.subTest(profile=key, name=name):
                self.assertIn(name, self.rows)
                self.assertIn(_version(profile), self.rows[name])

    def test_no_row_without_a_core(self):
        names = {_retroarch_name(p) for p in _arcade_profiles().values()}
        self.assertEqual(set(self.rows) - names, set())

    def test_terms_and_links(self):
        terms = _front(self.text)["terms"]
        for word in ("mame version", "romset version", "which mame"):
            with self.subTest(word=word):
                self.assertIn(word, terms)
        arcade = _section(_wiki("troubleshooting.md"), "An arcade game does not start")
        self.assertIn(ARCADE_ANCHOR, arcade)
        self.assertNotIn("emulators/index.md", arcade)
        faq = _wiki("faq.md")
        self.assertIn("## My arcade game fails (which MAME version?) "
                      "{ #my-arcade-game-does-not-start }", faq)


class FaqLabels(unittest.TestCase):
    """C9, N10: "Reference:" read as a broken crumb, "E::" as a typo, iOS unfound."""

    def setUp(self):
        self.text = _wiki("faq.md")

    def test_no_reference_label(self):
        self.assertNotRegex(self.text, r"(?m)^Reference:")
        arcade = _section(self.text, "My arcade game fails (which MAME version?)")
        self.assertIn(f"Game sets must match the emulator's version:\n[the list]({ARCADE_ANCHOR}).",
                      arcade)

    def test_the_card_sentence(self):
        self.assertIn("For RetroArch on a Switch,\nwith the card in drive `E:`, run:", self.text)

    def test_ios(self):
        self.assertIn("iPhone, iPad (iOS)", self.text)


class CopyYourOwnBios(unittest.TestCase):
    """C-other, need 12: no page answered the legal route."""

    def test_each_console_has_a_guide(self):
        section = _section(_wiki("faq.md"), "Can I copy my own console's BIOS?")
        links = re.findall(r"\[([^\]]+)\]\((https://[^)]+)\)", section)
        self.assertEqual(dict(links), {
            "PCSX2": "https://pcsx2.net/docs/setup/bios/",
            "melonDS": "https://melonds.kuribo64.net/faq.php",
        })


def _sums_with(names: list[str]) -> dict[str, str]:
    return {name: f"{i:064x}" for i, name in enumerate(names, 1)}


class PinnedInstaller(unittest.TestCase):
    """J9, D5: release tags are deleted and the release carried no installer."""

    def test_the_list_holds_the_installer_and_every_file_list(self):
        names = installer_files(REPO_ROOT / "install")
        self.assertEqual(names[:3], list(INSTALLER))
        self.assertIn("retroarch.json", names)
        self.assertEqual(len(names), 3 + len(list((REPO_ROOT / "install").glob("*.json"))))

    def test_a_release_without_the_installer_is_refused(self):
        record = {"tag": "v1", "packs": {"P.zip": {"download_size": 5, "assets": ["P.zip"]}}}
        files = ["install.py", "install.sh", "install.ps1", "retroarch.json"]
        sums = _sums_with(["P.zip", *files])
        assets = {name: Asset(5, digest) for name, digest in sums.items()}
        assets[SUMS] = Asset(1, None)
        self.assertEqual(compare_release(record, sums, assets, "v1", installer=files), [])

        del sums["install.py"]
        del assets["install.py"]
        kinds = {(f.kind, f.name) for f in compare_release(record, sums, assets, "v1",
                                                            installer=files)}
        self.assertEqual(kinds, {("no-installer", "install.py")})

    def test_listed_but_not_uploaded_is_missing(self):
        record = {"tag": "v1", "packs": {}}
        sums = _sums_with(list(INSTALLER))
        assets = {name: Asset(5, digest) for name, digest in sums.items() if name != "install.sh"}
        assets[SUMS] = Asset(1, None)
        kinds = {(f.kind, f.name) for f in compare_release(record, sums, assets, "v1",
                                                            installer=list(INSTALLER))}
        self.assertEqual(kinds, {("missing", "install.sh")})

    def test_the_release_steps_ship_them(self):
        text = _wiki("release-process.md")
        self.assertIn("cp install.py install.sh install.ps1 install/*.json dist/", text)
        sums = re.search(r"sha256sum [^>]+> SHA256SUMS.txt", text, re.S).group(0)
        upload = re.search(r"for f in dist/SHA256SUMS.txt.*?; do", text, re.S).group(0)
        for name in (*INSTALLER, "*.json"):
            with self.subTest(name=name):
                self.assertIn(name, sums)
        for name in INSTALLER:
            with self.subTest(upload=name):
                self.assertIn(f"dist/{name}", upload)
        self.assertIn("install/*.json", upload)

    def test_the_installer_page_pins_one_commit(self):
        # v2026.10.10 carries no install.py: until a release does, the
        # section pins a commit, never a release address.
        text = _wiki("installer.md")
        section = _flat(_section(text, "For packagers"))
        for words in ("raw.githubusercontent.com/Abdess/retrobios/$commit",
                      '"$base/install/retroarch.json"', "--manifest retroarch.json",
                      "sha256sum --check", "RETROBIOS_REF=$commit"):
            with self.subTest(words=words):
                self.assertIn(words, section)
        self.assertNotIn("releases/download/", section)
        self.assertNotIn("releases/latest/download/", section)
        terms = _front(text)["terms"]
        for word in ("manifest", "events", "exit code", "schema"):
            with self.subTest(term=word):
                self.assertIn(word, terms)


class NoBackslashInProseCode(unittest.TestCase):
    """D9: `irm \\| iex` showed its backslash outside a table."""

    def test_wiki(self):
        for path in sorted(WIKI.glob("*.md")):
            text = FENCED.sub("", path.read_text(encoding="utf-8"))
            for number, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("|"):
                    continue
                with self.subTest(page=path.name, line=number):
                    self.assertNotRegex(line, r"`[^`]*\\\|[^`]*`")


def _install_module():
    spec = importlib.util.spec_from_file_location("install_r4wiki", REPO_ROOT / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EventsTranscript(unittest.TestCase):
    """D10: the events table had no sample of what a run writes."""

    def test_five_lines_that_follow_the_schema(self):
        section = _section(_wiki("installer.md"), "Machine-readable events")
        block = re.search(r"```json\n(.*?)\n```", section, re.S)
        self.assertIsNotNone(block)
        lines = block.group(1).splitlines()
        self.assertEqual(len(lines), 5)
        keys = _install_module().EVENT_KEYS
        events = [json.loads(line) for line in lines]
        for event in events:
            with self.subTest(event=event["event"]):
                self.assertEqual(list(event), ["event", *keys[event["event"]]])
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[0]["mode"], "check")
        self.assertEqual(events[-1], {"event": "end", "code": 1})


class OneOptionsTable(unittest.TestCase):
    """T-F9: the options printed twice, the offline install 57,750 px down."""

    def setUp(self):
        self.text = _wiki("installer.md")

    def test_each_option_links_to_its_row(self):
        # The glance is written from the parser when the page is built.
        glance = _section(sitediagrams.expand_glance(self.text), "Options at a glance")
        table = _section(self.text, "Options")
        self.assertNotIn("installer-options", glance)
        self.assertNotIn("|", glance)
        for usage, _ in sitediagrams.installer_options():
            flag = usage.split()[0].rstrip(",")
            anchor = f"option-{flag.lstrip('-')}"
            with self.subTest(option=flag):
                self.assertIn(f"[`{flag}`](#{anchor})", glance)
                self.assertRegex(table, rf'(?m)^\| <span id="{anchor}"></span>`{flag}[ `]')

    def test_the_offline_install_comes_early(self):
        headings = re.findall(r"(?m)^## (.+?)(?:\s*\{[^}]*\})?$", FENCED.sub("", self.text))
        self.assertLess(headings.index("Without a network (offline install)"),
                        headings.index("The full-screen interface"))


class GlossaryPack(unittest.TestCase):
    """C-other: packs come in parts and leave out files the emulator ships."""

    def test_definition(self):
        text = _flat(_wiki("glossary.md"))
        self.assertIn("**Pack** : The ZIP, sometimes in parts, with one setup's BIOS files.", text)


if __name__ == "__main__":
    unittest.main()
