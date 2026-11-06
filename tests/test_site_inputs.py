"""generate_site --db, --emulators-dir and --platforms-dir reach every page.

The run loaded the given database, but the page-finishing pass reloaded the
repository's database.json: a card held only by the given collection stopped
the whole run on a KeyError. The emulator names and engine sections came from
./emulators, and has_release_pack read `platforms` relative to the working
directory, so a get/ page said "No ZIP" for a setup the API marked as released.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_site  # noqa: E402
import sitediagrams  # noqa: E402
import siteinputs  # noqa: E402

SHA1 = "0123456789ab" + "c" * 28


class _Inputs(unittest.TestCase):
    def use(self, **paths: Path) -> None:
        siteinputs.use(siteinputs.SiteInputs(**paths))
        self.addCleanup(siteinputs.use, siteinputs.SiteInputs())


class TheGivenDatabase(_Inputs):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None))
        self.addCleanup(shutil.rmtree, tmp)
        self.db = tmp / "database.json"
        self.db.write_text(json.dumps({"files": {SHA1: {"path": "bios/X/only-here.bin"}}}))

    def test_a_card_held_elsewhere_resolves_in_the_given_collection(self) -> None:
        self.use(db=self.db)
        page = generate_site._cards_elsewhere("[x](#sha1-0123456789ab) ")
        self.assertIn(f"files/?sha1={SHA1}", page)

    def test_paths_are_read_from_the_given_collection(self) -> None:
        self.use(db=self.db)
        self.assertEqual(generate_site._collection_sha1_by_path(), {"bios/X/only-here.bin": SHA1})


class TheGivenProfilesAndPlatforms(_Inputs):
    def setUp(self) -> None:
        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None))
        self.addCleanup(shutil.rmtree, tmp)
        self.emulators = tmp / "emulators"
        self.emulators.mkdir()
        (self.emulators / "fixturecore.yml").write_text(
            "emulator: Fixture Core\ntype: libretro\nsystems: [fixture-system]\nfiles: []\n")
        self.platforms = tmp / "platforms"
        shutil.copytree(REPO_ROOT / "platforms", self.platforms)

    def test_emulator_names_come_from_the_given_profiles(self) -> None:
        self.use(emulators=self.emulators)
        self.assertEqual(set(generate_site._profiles_on_disk()), {"fixturecore"})
        self.assertEqual(generate_site._emulator_named_link("fixturecore"),
                         "[Fixture Core](emulators/fixturecore.md)")

    def test_release_pack_does_not_depend_on_the_working_directory(self) -> None:
        released = generate_site._release_pack_platforms()
        self.assertIn("retroarch", released)
        here = os.getcwd()
        os.chdir(REPO_ROOT / "scripts")
        self.addCleanup(os.chdir, here)
        self.assertTrue(generate_site.has_release_pack("retroarch"))
        self.assertEqual(generate_site.get_page_title("retroarch", "RetroArch"), "RetroArch BIOS pack")

    def test_the_registry_comes_from_the_given_platforms(self) -> None:
        registry = self.platforms / "_registry.yml"
        registry.write_text(registry.read_text().replace("release_pack: true", "release_pack: false"))
        self.use(platforms=self.platforms)
        self.assertFalse(generate_site.has_release_pack("retroarch"))
        self.assertEqual(sitediagrams.registry()["retroarch"].get("release_pack"), False)


class TheCollectionDoesNotDependOnTheWorkingDirectory(unittest.TestCase):
    """database.json names its bios folder "bios", and the collection model
    read it from the working directory: started from tmp/, it found no copy
    on disk and dropped five system sections and 2,500 collection paths."""

    def test_same_sections_and_paths_from_another_directory(self) -> None:
        import json

        import sitecollection

        db = json.loads((REPO_ROOT / "database.json").read_text(encoding="utf-8"))
        here = sitecollection.collection_paths(db)
        places = sitecollection._copy_places(db)
        elsewhere = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" if (REPO_ROOT / "tmp").is_dir() else None))
        self.addCleanup(shutil.rmtree, elsewhere)
        cwd = os.getcwd()
        os.chdir(elsewhere)
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(sitecollection.collection_paths(db), here)
        self.assertEqual(sitecollection._copy_places(db), places)
        self.assertGreater(sum(map(len, here.values())), len(here))

    def test_the_bios_folder_sits_beside_the_given_database(self) -> None:
        import siteinputs

        siteinputs.use(siteinputs.SiteInputs(db=Path("/elsewhere/database.json")))
        self.addCleanup(siteinputs.use, siteinputs.SiteInputs())
        self.assertEqual(siteinputs.bios_dir({"bios_dir": "bios"}), Path("/elsewhere/bios"))
        self.assertEqual(siteinputs.bios_dir({"bios_dir": "/abs/bios"}), Path("/abs/bios"))

    def test_the_image_tools_do_not_load_the_page_generator(self) -> None:
        for module in ("make_og_cards.py", "fetch_site_images.py", "siterender.py"):
            with self.subTest(module=module):
                source = (REPO_ROOT / "scripts" / module).read_text(encoding="utf-8")
                self.assertNotIn("from generate_site import", source)


class NoPageModuleReadsTheRepositoryInputs(unittest.TestCase):
    """A helper that opens the repository's database, profiles or platform
    files itself bypasses the flags. siteinputs.current() is the one source."""

    MODULES = ("generate_site.py", "siterender.py", "sitediagrams.py", "sitecollection.py")
    INPUTS = {"database.json", "emulators", "platforms"}

    def test_no_literal_input_path(self) -> None:
        found = []
        for module in self.MODULES:
            tree = ast.parse((REPO_ROOT / "scripts" / module).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) \
                        and getattr(node.left, "id", "") in ("_REPO_ROOT", "ROOT") \
                        and isinstance(node.right, ast.Constant) and node.right.value in self.INPUTS:
                    found.append(f"{module}:{node.lineno}")
                if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) in (
                        "load_platform_config", "load_platform_registry", "load_emulator_profiles",
                        "list_registered_platforms", "load_database", "extract_notes",
                        "load_data_dir_registry"):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and arg.value in self.INPUTS:
                            found.append(f"{module}:{node.lineno}")
        self.assertEqual(found, [])

    def test_generate_installs_the_inputs_first(self) -> None:
        source = ast.get_source_segment(
            (REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8"),
            next(n for n in ast.parse((REPO_ROOT / "scripts" / "generate_site.py").read_text(encoding="utf-8")).body
                 if isinstance(n, ast.FunctionDef) and n.name == "_generate"))
        self.assertLess(source.index("siteinputs.use("), source.index("load_database("))


if __name__ == "__main__":
    unittest.main()
