"""A data directory a core reads reaches every platform that runs the core.

The registry entries of the buildbot trees named RetroArch, Lakka and
RetroPie only, and a platform pack carried only the trees its own systems
declared. AmberELEC and EmuELEC run the blueMSX core, whose package copies
the .so alone: their packs filled the machine configs by name from the
cache, and the install lists left 192 of them out. A platform that runs a
reader now gets the tree, or the profile says its package installs it.
"""

from __future__ import annotations

import tests

import os
import unittest
from pathlib import Path

from model.database import load_database
from model.platforms import load_platform_config
from model.profiles import load_emulator_profiles, installed_data_refs
from model.registry import load_data_dir_registry, list_registered_platforms
from resolve.cores import resolve_platform_cores
from resolve.standalone import platform_layouts, standalone_set
from packs import archive
from packs import datatrees
from packs import platformpack
from resolve.validation import deliverable, read_from_system_dir

REPO_ROOT = Path(__file__).resolve().parent.parent

PROFILES = {
    "demo": {
        "emulator": "Demo",
        "type": "libretro",
        "systems": ["demo-system"],
        "cores": ["demo"],
        "pack_structure": {"libretro": "Demo"},
        "data_directories": [
            {"ref": "shared", "destination": "Sys"},
            {"ref": "restricted"},
            {"ref": "installed", "installed_on": ["plat"]},
            {"ref": "beside", "load_from": "content_dir"},
        ],
    },
    "solo": {
        "emulator": "Solo",
        "type": "standalone",
        "systems": ["demo-system"],
        "cores": ["solo"],
        "data_directories": [{"ref": "shared"}],
    },
}

REGISTRY = {
    "shared": {"local_cache": "data/shared"},
    "restricted": {"local_cache": "data/restricted", "for_platforms": ["other"]},
    "installed": {"local_cache": "data/installed"},
    "beside": {"local_cache": "data/beside"},
}

CONFIG = {
    "platform": "Plat",
    "cores": ["demo", "solo"],
    "standalone_cores": ["solo"],
    "systems": {"demo-system": {"files": []}},
}


class CoreDataTreesTest(unittest.TestCase):
    def trees(self, platform: str = "plat", registry: dict | None = None) -> list[dict]:
        return datatrees.core_data_trees(
            CONFIG, PROFILES, platform, REGISTRY if registry is None else registry
        )

    def test_tree_below_the_build_folder(self) -> None:
        shared = [t for t in self.trees() if t["ref"] == "shared"]
        self.assertEqual([(t["core"], t["destination"]) for t in shared], [("demo", "Demo/Sys")])
        self.assertEqual(shared[0]["source_systems"], ["demo-system"])

    def test_for_platforms_names_who_gets_it(self) -> None:
        self.assertNotIn("restricted", {t["ref"] for t in self.trees()})
        self.assertIn("restricted", {t["ref"] for t in self.trees("other")})

    def test_installed_tree_stays_out(self) -> None:
        self.assertNotIn("installed", {t["ref"] for t in self.trees()})
        self.assertIn("installed", {t["ref"] for t in self.trees("other")})

    def test_tree_read_beside_the_content_stays_out(self) -> None:
        self.assertNotIn("beside", {t["ref"] for t in self.trees("other")})

    def test_standalone_build_brings_no_tree(self) -> None:
        self.assertNotIn("solo", {t["core"] for t in self.trees("other")})

    def test_every_reader_of_a_shared_tree_is_recorded(self) -> None:
        """The second core reading a tree was dropped with the duplicate, and an
        install for its games would have lost the tree."""
        twin = {**PROFILES["demo"], "emulator": "Twin", "cores": ["twin"]}
        profiles = {**PROFILES, "twin": twin}
        config = {**CONFIG, "cores": ["demo", "solo", "twin"]}
        trees = datatrees.core_data_trees(config, profiles, "plat", REGISTRY)
        shared = [t for t in trees if t["ref"] == "shared"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["readers"], ["demo", "twin"])
        self.assertEqual(datatrees.tree_readers({}, trees)["shared"], ["demo", "twin"])

    def test_a_tree_a_system_declares_names_no_core(self) -> None:
        trees = self.trees()
        declared = {"demo-system": {"data_directories": [{"ref": "shared"}]}}
        self.assertNotIn("shared", datatrees.tree_readers(declared, trees))
        self.assertIn("shared", datatrees.tree_readers({}, trees))

    def test_tree_below_the_declared_bios_folder(self) -> None:
        config = {
            **CONFIG,
            "base_destination": "",
            "systems": {"demo-system": {"files": [{"name": "a.bin", "destination": "bios/a.bin"}]}},
        }
        trees = datatrees.core_data_trees(config, PROFILES, "plat", REGISTRY)
        self.assertEqual(
            [t["destination"] for t in trees if t["ref"] == "shared"], ["bios/Demo/Sys"]
        )

    def test_no_registry_no_tree(self) -> None:
        self.assertEqual(datatrees.core_data_trees(CONFIG, PROFILES, "plat", None), [])


class EveryReaderHasTheTreeOrAReason(unittest.TestCase):
    """Reads the repository: platforms/_data_dirs.yml against the profiles."""

    def test_for_platforms_leaves_no_reader_without_a_reason(self) -> None:
        platforms_dir = str(REPO_ROOT / "platforms")
        registry = load_data_dir_registry(platforms_dir)
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
        unexplained = []
        for platform in list_registered_platforms(platforms_dir):
            config = load_platform_config(platform, platforms_dir)
            handed = standalone_set(config, profiles)
            for core in sorted(resolve_platform_cores(config, profiles)):
                profile = profiles[core]
                if all(standalone for _view, standalone
                       in platform_layouts(core, profile, handed)):
                    continue
                trees = [t for t in profile.get("data_directories") or [] if isinstance(t, dict)]
                installed = installed_data_refs(platform)
                for tree in deliverable(trees, False, platform):
                    allowed = registry.get(tree.get("ref"), {}).get("for_platforms")
                    if tree.get("ref") in installed or not read_from_system_dir(tree):
                        continue
                    if allowed and platform not in allowed:
                        unexplained.append(f"{tree['ref']} on {platform} ({core})")
        self.assertEqual(
            unexplained, [],
            "these platforms run a core that reads the tree, are not in its "
            "for_platforms, and no profile says their package installs it "
            "(installed_on) or that they never open it (unread_on)",
        )


@unittest.skipUnless(
    os.path.isdir(REPO_ROOT / "data" / "bluemsx"), "data/bluemsx is not cached"
)
class AmberelecCarriesTheMachines(unittest.TestCase):
    """AmberELEC's blueMSX package installs the core alone, so the pack and
    the install list bring the Machines tree its BIOS list names."""

    def test_machine_configs_come_with_the_tree(self) -> None:
        platforms_dir = str(REPO_ROOT / "platforms")
        cwd = os.getcwd()
        os.chdir(REPO_ROOT)
        try:
            config = load_platform_config("amberelec", platforms_dir)
            registry = load_data_dir_registry(platforms_dir)
            profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))
            trees = datatrees.core_data_trees(config, profiles, "amberelec", registry)
            refs: dict = {}
            members = dict(
                (full, src) for src, full in datatrees.data_directory_members(
                    config.get("systems", {}), registry, "amberelec",
                    config.get("base_destination", ""), archive.Placed(False),
                    refs_out=refs, core_trees=trees,
                )
            )
        finally:
            os.chdir(cwd)
        # Below bios/, where the platform writes every destination.
        self.assertIn("bios/Machines/COL - ColecoVision/config.ini", members)
        self.assertEqual(
            refs["bios/Machines/COL - ColecoVision/config.ini"][0], "bluemsx"
        )


class TheCountLineKeepsTreesOutOfTheBaseline(unittest.TestCase):
    """MyMinUI declares no file, and its pack line read "6944 baseline": the
    fbneo trees its cores read were counted as the platform's list."""

    def test_a_platform_declaring_nothing_has_no_baseline(self) -> None:
        import contextlib
        import io

        previous = os.getcwd()
        os.chdir(REPO_ROOT)
        self.addCleanup(os.chdir, previous)
        db = load_database("database.json")
        record = archive.PackRecord()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            platformpack.generate_pack(
                "myminui", "platforms", db, "bios", "tmp", offline=True, record=record,
                data_registry=load_data_dir_registry("platforms"),
            )
        line = next(entry for entry in out.getvalue().splitlines() if "files packed" in entry)
        self.assertIn("(0 baseline + ", line)
        if record.trees:
            self.assertIn(f"+ {len(record.trees)} in core data trees + ", line)


if __name__ == "__main__":
    unittest.main()
