"""A standalone build's files land in the folder its platform hands it.

``standalone_path`` is relative to the directories the standalone build
resolves it against (``standalone_directories``). RetroPie links Flycast's
~/.local/share/flycast to bios/dc and writes Dreamcast.BiosPath, ROCKNIX
patches Flycast's data directory to /storage/roms/dreamcast/data and links
that to bios/dc, EmuDeck links the Flatpak's data directory to
bios/flycast/bios, Batocera sets FLYCAST_BIOS_PATH and RetroBat
Dreamcast.BiosPath to bios/dc. Laid out at the BIOS root instead, Flycast's
naomi.zip took the place of MAME's.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    load_emulator_profiles,
    load_platform_config,
    platform_layouts,
    standalone_bindings_for,
    standalone_destination,
    standalone_set,
)
from launchers import (  # noqa: E402
    bound_path,
    handed_directories,
    normalize_handle,
    standalone_bindings,
)


def link(emulator: str, search_dir: str, passes_to: str, **fields: object) -> dict:
    return {
        "emulator": emulator, "build": "standalone", "kind": "links", "names": [],
        "search_dir": search_dir, "passes_to": passes_to, "source_ref": "x.sh:1",
        **fields,
    }


def passes(emulator: str, search_dir: str, passes_to: str) -> dict:
    return {**link(emulator, search_dir, passes_to), "kind": "passes_path"}


PROFILE = {
    "emulator": "Emu",
    "type": "standalone + libretro",
    "cores": ["emu_core"],
    "standalone_directories": ["$XDG_DATA_HOME/emu", "$HOME/.local/share/emu", "find_user_data_dir"],
    "files": [
        {"name": "boot.bin", "path": "dc/boot.bin", "standalone_path": "boot.bin"},
        {"name": "set.zip", "path": "dc/set.zip", "standalone_path": "set.zip"},
        {"name": "shared.bin", "path": "dc/shared.bin"},
    ],
}


def config(*launchers: dict, base: str = "bios") -> dict:
    return {"base_destination": base, "standalone_cores": ["emu"], "launchers": list(launchers)}


def standalone_view(cfg: dict) -> dict:
    views = platform_layouts("emu", PROFILE, standalone_set(cfg))
    return next(view for view, standalone in views if standalone)


class HandleSpelling(unittest.TestCase):
    def test_home_and_flatpak_spellings_are_one_directory(self) -> None:
        self.assertEqual(normalize_handle("$home/.local/share/emu"), "~/.local/share/emu")
        self.assertEqual(normalize_handle("${HOME}/.local/share/emu/"), "~/.local/share/emu")
        self.assertEqual(
            normalize_handle("${HOME}/.var/app/org.emu.Emu/data/emu/"), "$XDG_DATA_HOME/emu"
        )
        self.assertEqual(normalize_handle("find_user_data_dir()"), "find_user_data_dir")


class HandedDirectories(unittest.TestCase):
    def test_retropie_variable_resolves_to_a_bios_folder(self) -> None:
        found = handed_directories(config(
            link("emu", "$biosdir/dc", "$home/.local/share/emu is a symlink to it"), base="BIOS",
        ))
        self.assertEqual([h.folder for h in found], ["dc"])
        self.assertIn("~/.local/share/emu", found[0].handles)

    def test_named_and_slotted_links_hand_no_directory(self) -> None:
        found = handed_directories(config(
            {**link("emu", "$biosdir", "$md_inst/<name>"), "names": ["boot.bin"]},
            {**link("emu", "$bios_path/gc/EU", "$XDG_DATA_HOME/emu/GC/EUR"), "slot": "EUR"},
        ))
        self.assertEqual(found, [])

    def test_directory_outside_the_tree_has_no_folder(self) -> None:
        found = handed_directories(config(
            passes("emu", "/storage/roms/dreamcast/data", "find_user_data_dir() returns it"),
        ))
        self.assertIsNone(found[0].folder)


class Root(unittest.TestCase):
    def root(self, *launchers: dict, base: str = "bios") -> str | None:
        return self.bindings(*launchers, base=base).get("")

    def bindings(self, *launchers: dict, base: str = "bios") -> dict[str, str]:
        return standalone_bindings(
            {"emu"}, PROFILE["standalone_directories"], handed_directories(config(*launchers, base=base))
        )

    def test_link_of_the_data_directory_gives_its_folder(self) -> None:
        self.assertEqual(
            self.root(link("emu", "$biosdir/dc", "$home/.local/share/emu is a symlink to it")),
            "dc",
        )

    def test_flatpak_data_directory(self) -> None:
        self.assertEqual(
            self.root(link(
                "emu", "${biosPath}/emu/bios",
                "symlink ${biosPath}/emu/bios -> ${HOME}/.var/app/org.emu.Emu/data/emu/",
            )),
            "emu/bios",
        )

    def test_patched_data_directory_followed_through_its_link(self) -> None:
        self.assertEqual(
            self.root(
                passes("emu", "/storage/roms/dreamcast/data", "find_user_data_dir() returns it"),
                link("emu", "/storage/roms/bios/dc",
                     "symlink /storage/roms/dreamcast/data -> /storage/roms/bios/dc"),
            ),
            "dc",
        )

    def test_link_of_a_subfolder_binds_that_subfolder_only(self) -> None:
        # A subfolder of the emulator's tree (Dolphin's Triforce) is not the
        # directory standalone_path is relative to, only the files below it move.
        found = self.bindings(
            link("emu", "$bios_path/Triforce", "$XDG_DATA_HOME/emu/Triforce is a symlink to it"),
        )
        self.assertEqual(found, {"Triforce": "Triforce"})
        self.assertEqual(bound_path("Triforce/segaboot.gcm", found), "Triforce/segaboot.gcm")
        self.assertIsNone(bound_path("boot.bin", found))

    def test_two_folders_give_nothing(self) -> None:
        self.assertIsNone(self.root(
            link("emu", "$biosdir/dc", "$home/.local/share/emu is a symlink to it"),
            link("emu", "$biosdir/other", "$XDG_DATA_HOME/emu is a symlink to it"),
        ))


class Layout(unittest.TestCase):
    LINKED = link("emu", "$biosdir/dc", "$home/.local/share/emu is a symlink to it")

    def test_standalone_view_takes_the_linked_folder(self) -> None:
        view = standalone_view(config(self.LINKED, base="BIOS"))
        self.assertEqual(
            [f.get("standalone_path") for f in view["files"]], ["dc/boot.bin", "dc/set.zip", None]
        )
        self.assertEqual(view["files"][2]["path"], "dc/shared.bin")

    def test_without_a_link_the_profile_layout_stands(self) -> None:
        view = standalone_view(config())
        self.assertEqual([f.get("standalone_path") for f in view["files"]][:2], ["boot.bin", "set.zip"])

    def test_profile_is_not_changed(self) -> None:
        standalone_view(config(self.LINKED, base="BIOS"))
        self.assertEqual(PROFILE["files"][0]["standalone_path"], "boot.bin")

    def test_libretro_view_keeps_path(self) -> None:
        cfg = {**config(self.LINKED, base="BIOS"), "dual_mode_cores": ["emu"]}
        views = platform_layouts("emu", PROFILE, standalone_set(cfg))
        libretro = next(view for view, standalone in views if not standalone)
        self.assertIs(libretro, PROFILE)

    def test_dual_mode_gets_both_layouts(self) -> None:
        # The libretro build still reads dc/, the standalone build the
        # linked folder: neither loses a file to the other.
        cfg = {**config(link("emu", "$biosdir/emu", "$home/.local/share/emu is a symlink to it"),
                        base="BIOS"), "dual_mode_cores": ["emu"]}
        views = dict((standalone, view) for view, standalone in
                     platform_layouts("emu", PROFILE, standalone_set(cfg)))
        self.assertEqual(
            [f["path"] for f in views[False]["files"]], ["dc/boot.bin", "dc/set.zip", "dc/shared.bin"]
        )
        self.assertEqual(
            [f.get("standalone_path") for f in views[True]["files"]], ["emu/boot.bin", "emu/set.zip", None]
        )

    def test_union_of_platforms_with_two_folders_keeps_the_profile_layout(self) -> None:
        union = standalone_set(config(self.LINKED, base="BIOS")) | standalone_set(config(
            link("emu", "${biosPath}/emu/bios", "symlink ${biosPath}/emu/bios -> ${HOME}/.local/share/emu"),
        ))
        self.assertEqual(standalone_bindings_for("emu", PROFILE, union), {})

    def test_destination_function(self) -> None:
        entry = PROFILE["files"][0]
        self.assertEqual(standalone_destination(entry, PROFILE, {"": "dc"}), "dc/boot.bin")
        self.assertIsNone(standalone_destination(entry, PROFILE, {}))
        # The entry both builds share keeps path in a dual-build profile.
        self.assertIsNone(standalone_destination(PROFILE["files"][2], PROFILE, {"": "dc"}))


class FlycastOnEachPlatform(unittest.TestCase):
    """The real profile against the real launcher records."""

    EXPECTED = {
        "batocera": "dc",
        "emudeck": "flycast/bios",
        "retrobat": "dc",
        "retropie": "dc",
        "rocknix": "dc",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["flycast"]

    def test_each_platform_hands_flycast_its_folder(self) -> None:
        for platform, folder in self.EXPECTED.items():
            with self.subTest(platform=platform):
                cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                self.assertEqual(
                    standalone_bindings_for("flycast", self.profile, standalone_set(cfg)),
                    {"": folder},
                )

    def test_no_standalone_file_lands_at_the_bios_root(self) -> None:
        # Flycast's naomi.zip and awbios.zip share their names with MAME's
        # root archives: at the root they replace them.
        for platform, folder in self.EXPECTED.items():
            with self.subTest(platform=platform):
                cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                for view, standalone in platform_layouts(
                    "flycast", self.profile, standalone_set(cfg)
                ):
                    if not standalone:
                        continue
                    for entry in view["files"]:
                        self.assertTrue(
                            entry["standalone_path"].startswith(folder + "/"),
                            entry["standalone_path"],
                        )


    def test_emudeck_keeps_the_libretro_layout_beside_the_linked_one(self) -> None:
        # EmuDeck's RetroArch_installCores downloads flycast_libretro, which
        # reads system/dc/, next to the standalone Flycast in flycast/bios/.
        cfg = load_platform_config("emudeck", str(REPO_ROOT / "platforms"))
        self.assertIn("flycast", cfg.get("dual_mode_cores") or [])
        views = {
            standalone: view
            for view, standalone in platform_layouts("flycast", self.profile, standalone_set(cfg))
        }
        self.assertEqual(set(views), {False, True})
        for entry in views[False]["files"]:
            self.assertTrue(entry["path"].startswith("dc/"), entry["path"])
        for entry in views[True]["files"]:
            self.assertTrue(entry["standalone_path"].startswith("flycast/bios/"))


class Scrapers(unittest.TestCase):
    def test_emudeck_installed_libretro_cores(self) -> None:
        from scraper.emudeck_scraper import installed_libretro_cores

        script = textwrap.dedent("""\
            RetroArch_installCores(){
            \tRAcores=(
            \t\t\t81_libretro \\
            \t\t\tflycast_libretro \\
            \t\t\tmesen-s_libretro \\
            \t\t\t)
            }
            """)
        self.assertEqual(installed_libretro_cores(script), ["81", "flycast", "mesen-s"])
        with self.assertRaises(RuntimeError):
            installed_libretro_cores("RetroArch_installCores(){\n}\n")

    """The records each platform's scraper writes for these directories."""

    def test_rocknix_patched_data_directory(self) -> None:
        from scraper import rocknix_launchers as rl
        from scraper.shell_launchers import LauncherPatternMissing, RepoTree

        path = f"{rl.STANDALONE}/flycast-sa/patches/000-conf-dir.patch"
        patch = textwrap.dedent("""\
            --- a/core/linux-dist/main.cpp
            +++ b/core/linux-dist/main.cpp
            @@ -69,12 +69,17 @@
             static std::string find_user_data_dir()
             {
            +#ifdef __unix__
            +\tflycast::mkdir("/storage/roms/dreamcast/data", 0755);
            +\treturn "/storage/roms/dreamcast/data/";
            +#else
            """)
        records = rl.patched_directories(RepoTree.from_files({path: patch}))
        self.assertEqual(len(records), 1)
        entry = records[0].entry()
        self.assertEqual(entry["search_dir"], "/storage/roms/dreamcast/data")
        self.assertEqual(entry["passes_to"], "find_user_data_dir() in core/linux-dist/main.cpp returns it")
        self.assertEqual(entry["source_ref"], f"{path}:4, 8")
        with self.assertRaises(LauncherPatternMissing):
            rl.patched_directories(RepoTree.from_files({path: patch.replace("return", "x =")}))

    def test_batocera_environment_directory(self) -> None:
        from scraper.batocera_launchers import (
            GENERATORS, IMPORTER, PATHS_MODULE, Configgen, environment_directories,
        )
        from scraper.configgen_launchers import LauncherShapeError

        paths = "from pathlib import Path\nBIOS = Path('/userdata/bios')\nCONFIGS = Path('/userdata/system/configs')\n"
        importer = "_GENERATOR_MAP = {}\n_LEGACY_GENERATOR_MAP = {}\n"
        flycast_paths = "from ...batoceraPaths import BIOS\nFLYCAST_BIOS = BIOS / 'dc'\n"
        generator = textwrap.dedent("""\
            def generate(self):
                return Command.Command(
                    array=[],
                    env={
                        "XDG_CONFIG_HOME": CONFIGS,
                        "FLYCAST_BIOS_PATH": FLYCAST_BIOS,
                    }
                )
            """)
        tree = {
            PATHS_MODULE: paths,
            IMPORTER: importer,
            f"{GENERATORS}/flycast/flycastPaths.py": flycast_paths,
            f"{GENERATORS}/flycast/flycastGenerator.py": generator,
        }
        records = [r.entry() for r in environment_directories(Configgen(tree.__getitem__))]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["search_dir"], "/userdata/bios/dc")
        self.assertEqual(records[0]["passes_to"], "environment FLYCAST_BIOS_PATH")
        self.assertTrue(records[0]["source_ref"].endswith("flycastGenerator.py:6"))
        tree[f"{GENERATORS}/flycast/flycastGenerator.py"] = generator.replace("FLYCAST_BIOS,", "CONFIGS,")
        with self.assertRaises(LauncherShapeError):
            environment_directories(Configgen(tree.__getitem__))

    def test_retrobat_bios_path_setting(self) -> None:
        from scraper import retrobat_launchers as rl

        path = f"{rl.GENERATORS}/Flycast.Generator.cs"
        text = textwrap.dedent("""\
                private void SetupConfiguration(string path)
                {
                    string configfile = Path.Combine(path, "emu.cfg");
                    using (var ini = IniFile.FromFile(configfile, IniOptions.UseSpaces))
                    {
                        string biosPath = Path.Combine(AppConfig.GetFullPath("bios"), "dc");
                        ini.Remove("config", "Dreamcast.BiosPath");
                        ini.WriteValue("config", "Dreamcast.BiosPath", biosPath);
                    }
                }
            """)
        records = rl._value_writes(rl.Source(path, text), "flycast", "standalone")
        self.assertEqual([r["search_dir"] for r in records], ["bios/dc"])
        self.assertIn("Dreamcast.BiosPath", records[0]["passes_to"])


if __name__ == "__main__":
    unittest.main()
