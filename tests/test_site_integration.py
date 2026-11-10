"""What separate fixes left between them once merged.

A data directory page printed its readers as a Python list, every board
page's breadcrumb read "Arcade / Arcade", the fba2012 section was headed
with its folder name, BizHawk's tile showed a GitHub avatar and MinUI's a
logo that is not its own, and the nodes the search gate starts wrote
Node's compile cache into /tmp.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import glob
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_freshness  # noqa: E402
import generate_site as gs  # noqa: E402
import sitediagrams  # noqa: E402
import siterender  # noqa: E402

DIST = REPO_ROOT / "website" / "dist"


def _profile(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "emulators" / f"{name}.yml").read_text(encoding="utf-8"))


class DataTreeReaders(unittest.TestCase):
    def test_read_by_names_the_emulators(self):
        ref = "y-sys"
        gs._DATA_MEMBERS[ref] = {"a.bin": {"size": 1, "sha1": "0" * 40}}
        gs._DATA_READERS[ref] = [("dolphin", "Dolphin"), ("ishiiruka", "Ishiiruka")]
        try:
            page = gs._data_tree_page(ref, {}, [("y-sys", ["a.bin"])], 0)
        finally:
            del gs._DATA_MEMBERS[ref], gs._DATA_READERS[ref]
        self.assertIn("Read by [Dolphin](dolphin.md#data-directories) and "
                      "[Ishiiruka](ishiiruka.md#data-directories).", page)
        self.assertNotIn("('dolphin'", page)


class EngineIntros(unittest.TestCase):
    def test_every_intro_names_what_it_emulates(self):
        for path in sorted(glob.glob(str(REPO_ROOT / "emulators" / "*.yml"))):
            profile = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            if not isinstance(profile, dict) or profile.get("type") == "alias" or profile.get("role") == "test":
                continue
            name = Path(path).stem
            with self.subTest(profile=name):
                intro = gs._emulator_intro(str(profile.get("emulator") or name), profile)
                self.assertNotRegex(intro, r"emulates\s*(?:\.|game\b|and\b|,)")
                self.assertNotIn("  ", intro)


class SectionNames(unittest.TestCase):
    def test_fba2012_is_headed_by_its_program(self):
        self.assertEqual(gs._section_label("Arcade", "fba2012"), "FB Alpha 2012")
        self.assertEqual(gs._section_label("Arcade", "Arcade"), gs.OTHER_ARCADE_LABEL)
        self.assertEqual(gs._section_label("Sony", "PlayStation"), "PlayStation")
        self.assertEqual(siterender.SECTION_LABELS[("Arcade", "fba2012")],
                         _profile("fbalpha2012")["emulator"])


class PlatformLogos(unittest.TestCase):
    def setUp(self):
        self.registry = yaml.safe_load(
            (REPO_ROOT / "platforms" / "_registry.yml").read_text(encoding="utf-8"))["platforms"]

    def test_bizhawk_shows_its_app_icon(self):
        self.assertTrue(self.registry["bizhawk"]["logo"].endswith(
            "/src/BizHawk.Client.EmuHawk/images/logo.ico"))

    def test_minui_shows_its_boot_logo_not_its_author(self):
        # The author's GitHub avatar is a face, not the project's mark.
        self.assertIn("/Bootlogo.pak/", self.registry["minui"]["logo"])
        self.assertTrue(self.registry["minui"]["logo_flip"])

    def test_every_logo_copy_has_a_registry_or_tile_logo(self):
        from siteguides import GROUP_TILES  # noqa: PLC0415

        tiles = {re.sub(r"[^a-z0-9]+", "-", tile.name.lower()).strip("-"): tile.logo
                 for group in GROUP_TILES.values() for tile in group}
        sources = json.loads((REPO_ROOT / "docs_assets" / "logos" / "sources.json").read_text())
        for entry in sources["images"]:
            with self.subTest(platform=entry["platform"]):
                logo = (self.registry[entry["platform"]].get("logo")
                        if entry["platform"] in self.registry else tiles.get(entry["platform"]))
                self.assertEqual(logo, entry["source"])


class NodeCompileCache(unittest.TestCase):
    def test_the_search_gate_starts_node_without_it(self):
        source = (REPO_ROOT / "website" / "tools" / "search_gate.py").read_text(encoding="utf-8")
        self.assertIn('NODE_ENV = {**os.environ, "NODE_DISABLE_COMPILE_CACHE": "1"}', source)
        starts = [m.start() for m in re.finditer(r'subprocess\.(?:run|Popen)\(\s*\["node"', source)]
        self.assertEqual(len(starts), 3)
        for start in starts:
            call = source[start:source.index("\n\n", start)]
            self.assertIn("env=NODE_ENV", call)

    def test_lighthouse_and_the_deploy(self):
        self.assertIn('"NODE_DISABLE_COMPILE_CACHE": "1"',
                      (REPO_ROOT / "website" / "tools" / "lighthouse.py").read_text(encoding="utf-8"))
        workflow = (REPO_ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")
        build = workflow[workflow.index("  build:"):workflow.index("    steps:")]
        self.assertIn('NODE_DISABLE_COMPILE_CACHE: "1"', build)


class SourcePathsFreshness(unittest.TestCase):
    def test_the_committed_record_is_current(self):
        from common import load_emulator_profiles  # noqa: PLC0415

        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"), skip_aliases=False)
        finding = check_freshness.check_source_paths(profiles)
        self.assertEqual(finding.status, check_freshness.OK, finding.detail)

    def test_a_recorded_build_file_tree_is_pinned(self):
        """The record holds the platform trees pin_build reads at a commit,
        and the check called them orphaned."""
        import sitesources  # noqa: PLC0415

        pin = "a" * 40
        profile = {"pin_build": [{"repo": "https://github.com/o/r", "revision": pin,
                                  "path": "p.mk"}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source-paths.json"
            path.write_text(json.dumps({f"github.com/o/r@{pin}": ["p.mk"]}), encoding="utf-8")
            with mock.patch.object(sitesources, "SOURCE_PATHS", path):
                finding = check_freshness.check_source_paths({"p": profile})
        self.assertEqual(finding.status, check_freshness.OK, finding.detail)

    def test_a_moved_pin_is_stale(self):
        profile = _profile("geolith")
        moved = dict(profile, source_commit="f" * 40, upstream_commit="e" * 40)
        finding = check_freshness.check_source_paths({"geolith": moved})
        self.assertEqual(finding.status, check_freshness.STALE)
        self.assertIn("sitesources.py --fetch", finding.detail)

    def test_a_pinned_tree_never_read_is_stale(self):
        """fbneo moved to two new pins while fbneo_cps12 kept the old ones:
        no recorded tree was orphaned, so the check said OK and 174 citations
        stayed unlinked."""
        import sitesources  # noqa: PLC0415

        profile = _profile("geolith")
        trees = [sitesources.tree_key(r, p) for r, p in sitesources.profile_trees(profile)]
        record = json.loads(sitesources.SOURCE_PATHS.read_text(encoding="utf-8"))
        for key in trees:
            record.pop(key, None)
        # Kept pinned by another profile, as fbneo_cps12 kept the old FBNeo trees.
        record.update({key: [] for key in trees[1:]})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source-paths.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            with mock.patch.object(sitesources, "SOURCE_PATHS", path):
                finding = check_freshness.check_source_paths({"geolith": profile})
        self.assertEqual(finding.status, check_freshness.STALE)
        self.assertIn("1 pinned trees not recorded", finding.detail)

    def test_a_tree_read_with_no_cited_path_is_recorded(self):
        import sitesources  # noqa: PLC0415

        profile = {"source": "https://github.com/o/r", "source_commit": "e" * 40,
                   "files": [{"source_ref": "src/a.c:5"}]}
        with mock.patch.object(sitesources, "_cached_tree", return_value=frozenset({"x.c"})):
            held, unread = sitesources.build_source_paths({"p": profile}, [Path("tmp")])
        self.assertEqual(held, {"github.com/o/r@" + "e" * 40: []})
        self.assertEqual(unread, [])


class OptionsGlanceFromTheParser(unittest.TestCase):
    """--declared-only and --offline reached install.py and its Options
    table, and not the hand-written glance above it."""

    def test_every_parser_option_has_a_group(self):
        named = {flag for _label, flags in sitediagrams.GLANCE_GROUPS for flag in flags}
        self.assertEqual(set(sitediagrams.installer_flags()) - named, set())
        self.assertEqual(named - set(sitediagrams.installer_flags()), set())

    def test_an_option_no_group_names_still_lands(self):
        with mock.patch.object(sitediagrams, "installer_flags",
                               return_value=["--platform", "--brand-new"]):
            lines = sitediagrams.options_glance()
        self.assertEqual(lines, [
            "- **Where and for what**: [`--platform`](#option-platform)",
            "- **Other**: [`--brand-new`](#option-brand-new)",
        ])

    def test_the_source_holds_no_list(self):
        text = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        section = text[text.index(sitediagrams.GLANCE_HEADING):text.index("\n## One line")]
        self.assertNotIn("\n- ", section)
        with self.assertRaises(ValueError):
            sitediagrams.expand_glance(f"# x\n\n{sitediagrams.GLANCE_HEADING}\n\n- a\n\n## y\n")


class FaqInstallsFromWhatYouHold(unittest.TestCase):
    """--from-pack reads the ZIP itself, and a wiped card had no answer."""

    def setUp(self):
        self.faq = (REPO_ROOT / "wiki" / "faq.md").read_text(encoding="utf-8")

    def _section(self, heading: str) -> str:
        return self.faq.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]

    def test_no_unzip_before_from_pack(self):
        section = " ".join(self._section("No internet on the device?").split())
        self.assertIn("point `--from-pack` at the ZIP:", section)
        self.assertNotIn("unzip", section)
        install = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        self.assertIn("Install from a pack already downloaded: its ZIP, one of its parts",
                      (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8"))
        self.assertIn('"--from-pack"', install)

    def test_the_cards_the_interface_finds(self):
        """Each system the SD card answer names is one install.py tells by
        its card: a release file (_CARD_RULES) or a card rule."""
        import install  # noqa: PLC0415

        section = " ".join(self._section("Fill an SD card from a computer?").split())
        self.assertIn("The interface finds a muOS, Onion, spruceOS, MinUI, KNULLI, ROCKNIX, Lakka "
                      "or MiSTer card.", section)
        known = {rule.name for rule in install._card_rules()}
        known |= {install.display_name(name) for name, _marker, _prefix in install._CARD_RULES}
        for name in ("muOS", "Onion", "spruceOS", "MinUI", "KNULLI", "ROCKNIX", "MiSTer FPGA"):
            with self.subTest(card=name):
                self.assertIn(name, known)
        # A card told by a rule of its share (MiSTer since 73b82375d) is named
        # here and in the README, or its user passes --dest the card's root.
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        for rule in install._SHARE_RULES:
            word = rule.name.split()[0]
            with self.subTest(share=rule.name):
                self.assertIn(word, section)
                self.assertRegex(readme, rf"\b{word}\b[^.]*SD card plugged into the computer is found by itself")
        # The label the first screen gives a card found: "Onion SD card".
        self.assertEqual(install._card_word(("retroarch", Path("/x/BIOS"), "Onion")), "SD card")
        self.assertEqual(install._card_word(("batocera", Path("/x/bios"), "Batocera")),
                         "SHARE drive")

    def test_a_wiped_card_links_the_copy(self):
        section = self._section("Lost or wiped card?")
        self.assertIn("`--from`", section)
        self.assertIn("(installer.md#copy-from-an-old-card)", section)
        installer = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        self.assertIn("## Copy from an old card { #copy-from-an-old-card }", installer)
        self.assertIn('"--from"', (REPO_ROOT / "install.py").read_text(encoding="utf-8"))


@unittest.skipUnless((DIST / "systems" / "arcade-acclaim-zn-1" / "index.html").is_file(),
                     "site not built")
class BuiltCrumbs(unittest.TestCase):
    def test_no_crumb_repeats_the_one_before(self):
        repeated = []
        for path in sorted(DIST.rglob("index.html")):
            nav = re.search(r'<nav[^>]*rb-breadcrumbs[^>]*>(.*?)</nav>',
                            path.read_text(encoding="utf-8"), re.S)
            if not nav:
                continue
            labels = [re.sub(r"<[^>]+>", "", item).strip()
                      for item in re.findall(r"<li[^>]*>(.*?)</li>", nav[1], re.S)]
            if any(a == b for a, b in zip(labels, labels[1:])):
                repeated.append(str(path.relative_to(DIST)))
        self.assertEqual(repeated, [])

    def test_a_board_page_ends_on_the_arcade_page(self):
        text = (DIST / "systems" / "arcade-acclaim-zn-1" / "index.html").read_text(encoding="utf-8")
        nav = re.search(r'<nav[^>]*rb-breadcrumbs[^>]*>(.*?)</nav>', text, re.S)[1]
        self.assertIn('href="/retrobios/systems/arcade/"', nav)
        self.assertNotIn('href="/retrobios/systems/#arcade"', nav)


if __name__ == "__main__":
    unittest.main()
