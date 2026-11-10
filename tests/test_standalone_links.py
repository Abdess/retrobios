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
    entry_launch_systems,
    load_emulator_profiles,
    load_platform_config,
    platform_layouts,
    standalone_bindings_for,
    standalone_destination,
    standalone_set,
    system_file_index,
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
        found = self.bindings(*launchers, base=base).get("")
        return found[1] if found else None

    def bindings(self, *launchers: dict, base: str = "bios") -> dict[str, tuple[str, str]]:
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
        self.assertEqual(found, {"Triforce": ("", "Triforce")})
        self.assertEqual(bound_path("Triforce/segaboot.gcm", found), ("", "Triforce/segaboot.gcm"))
        self.assertIsNone(bound_path("boot.bin", found))

    def test_two_folders_give_nothing(self) -> None:
        self.assertIsNone(self.root(
            link("emu", "$biosdir/dc", "$home/.local/share/emu is a symlink to it"),
            link("emu", "$biosdir/other", "$XDG_DATA_HOME/emu is a symlink to it"),
        ))


def bind(cfg: dict, declared: list[str], pools: dict[str, str] | None = None,
         systems: tuple[str, ...] = ()) -> dict[str, tuple[str, str]]:
    return standalone_bindings(
        {"emu"}, declared, handed_directories(cfg), pools=pools, systems=systems
    )


class SearchLists(unittest.TestCase):
    """A setting read as a list of directories, every one searched."""

    POOLS = {"filepool": "share/systemroms"}

    def filepool(self, folder: str, position: int) -> dict:
        return passes(
            "emu", f"/userdata/bios/{folder}",
            f"written: filepool add -path /userdata/bios/{folder} -types system_rom -position {position}",
        )

    def test_two_pool_entries_give_the_first_one(self) -> None:
        # Batocera adds bios/Machines and bios/openmsx to openMSX's filepool.
        cfg = config(self.filepool("Machines", 1), self.filepool("openmsx", 2))
        self.assertEqual(
            bind(cfg, ["~/.openMSX"], self.POOLS), {"share/systemroms": ("", "Machines")}
        )

    def test_the_entry_the_platform_list_fills_comes_first(self) -> None:
        cfg = config(self.filepool("Machines", 1), self.filepool("openmsx", 2))
        cfg["systems"] = {"msx": {"files": [{"name": "a.rom", "destination": "openmsx/a.rom"}]}}
        self.assertEqual(
            bind(cfg, ["~/.openMSX"], self.POOLS), {"share/systemroms": ("", "openmsx")}
        )

    def test_without_the_pool_two_folders_give_nothing(self) -> None:
        cfg = config(self.filepool("Machines", 1), self.filepool("openmsx", 2))
        self.assertEqual(bind(cfg, ["~/.openMSX", "filepool"]), {})

    def test_a_colon_list_gives_each_directory_in_order(self) -> None:
        # RetroDECK writes XRoar's rompath as four directories.
        found = handed_directories(config(passes(
            "emu", "$roms_path/coco:$roms_path/dragon32:$bios_path", "xroar.conf rompath",
        )))
        self.assertEqual(
            [h.directory for h in found], ["$roms_path/coco", "$roms_path/dragon32", "$bios_path"]
        )
        self.assertEqual(
            bind(config(passes("emu", "$roms_path/coco:$bios_path/xroar", "xroar.conf rompath")),
                 [], {"rompath": ""}),
            {"": ("", "xroar")},
        )

    def test_a_drive_letter_is_one_directory(self) -> None:
        self.assertEqual(handed_directories(config(passes("emu", "C:/bios", "rompath"))), [])


class AboveTheDeclaredDirectory(unittest.TestCase):
    def test_a_prefix_lands_the_declared_directory_where_its_link_is(self) -> None:
        # RetroPie builds XRoar with --prefix=$md_inst and links
        # $md_inst/share/xroar/roms to $biosdir.
        cfg = config(
            passes("emu", "$md_inst", "${prefix} of configure --prefix"),
            link("emu", "$biosdir", "$md_inst/share/xroar/roms is a symlink to it"),
            base="BIOS",
        )
        self.assertEqual(bind(cfg, ["${prefix}/share/xroar/roms"]), {"": ("", "")})

    def test_a_folder_of_the_tree_takes_the_rest_of_the_path(self) -> None:
        cfg = config(passes("emu", "$biosdir/emu", "EMU_HOME"), base="BIOS")
        self.assertEqual(bind(cfg, ["EMU_HOME/share/roms"]), {"": ("", "emu/share/roms")})


class PerSystem(unittest.TestCase):
    """A record written for some systems replaces, there, the others."""

    CFG = {
        **config(
            passes("emu", "bios/dragon", "command line -rompath"),
            {**passes("emu", "bios/coco", "command line -rompath"), "systems": ["coco"]},
        ),
        "systems": {"coco": {"files": [{"name": "x.zip", "native_system": "coco"}]}},
    }
    POOLS = {"-rompath": ""}

    def test_the_system_record_wins_for_its_system(self) -> None:
        self.assertEqual(bind(self.CFG, [], self.POOLS, ("coco",)), {"": ("", "coco")})

    def test_another_system_keeps_the_generic_record(self) -> None:
        self.assertEqual(bind(self.CFG, [], self.POOLS, ("dragon32",)), {"": ("", "dragon")})
        self.assertEqual(bind(self.CFG, [], self.POOLS), {"": ("", "dragon")})

    def test_native_names_are_read_as_our_ids(self) -> None:
        cfg = {
            **config({**passes("emu", "bios/trs80coco", "-rompath"), "systems": ["trs80coco"]}),
            "systems": {"coco": {"native_id": "trs80coco", "files": []}},
        }
        self.assertEqual(
            [sorted(h.systems) for h in handed_directories(cfg)], [["coco"]]
        )

    def test_a_system_placeholder_gives_one_directory_per_system(self) -> None:
        # Recalbox passes `-rompath os.path.join(BIOS, args.system)`.
        cfg = {
            **config(passes("emu", "/recalbox/share/bios/<system>", "command line -rompath")),
            "systems": {
                "coco": {"native_id": "trs80coco", "files": []},
                "dragon64": {"native_id": "dragon", "files": []},
            },
        }
        self.assertEqual(
            [(h.folder, sorted(h.systems)) for h in handed_directories(cfg)],
            [("dragon", ["dragon64"]), ("trs80coco", ["coco"])],
        )
        self.assertEqual(bind(cfg, [], self.POOLS | {"-rompath": ""}, ("coco",)),
                         {"": ("", "trs80coco")})
        self.assertEqual(bind(cfg, [], {"-rompath": ""}, ("dragon32",)), {})

    def test_an_entry_is_launched_for_the_system_that_declares_its_name(self) -> None:
        cfg = {
            **config({**passes("emu", "bios/coco", "-rompath"), "systems": ["coco"]}),
            "systems": {"coco": {"files": [{"name": "coco3.rom", "native_system": "coco"}]}},
        }
        index = system_file_index(standalone_set(cfg))
        self.assertEqual(
            entry_launch_systems({"name": "COCO3.ROM", "system": "coco3"}, index),
            frozenset({"coco3", "coco"}),
        )


class SystemFamily(unittest.TestCase):
    def test_an_entry_follows_the_launch_its_system_is_listed_under(self) -> None:
        # Recalbox lists mc10.rom under trs80coco: alice.rom, of the same
        # profile system, is read there too.
        profile = {
            "emulator": "Emu", "type": "standalone", "standalone_pools": {"-rompath": ""},
            "files": [
                {"name": "mc10.rom", "path": "mc10.rom", "system": "mc10"},
                {"name": "alice.rom", "path": "alice.rom", "system": "mc10"},
            ],
        }
        cfg = {
            **config(passes("emu", "/recalbox/share/bios/<system>", "-rompath")),
            "systems": {"coco": {"native_id": "trs80coco",
                                 "files": [{"name": "mc10.rom"}]}},
        }
        ((view, _standalone),) = platform_layouts("emu", profile, standalone_set(cfg))
        self.assertEqual(
            [f.get("standalone_path") for f in view["files"]],
            ["trs80coco/mc10.rom", "trs80coco/alice.rom"],
        )


class OfferedMachine(unittest.TestCase):
    def test_an_entry_system_offered_as_a_machine_selects_that_launch(self) -> None:
        profile = {
            "emulator": "Emu", "type": "standalone", "standalone_pools": {"-rompath": ""},
            "files": [
                {"name": "coco3.rom", "path": "coco3.rom", "system": "coco3"},
                {"name": "mc10.rom", "path": "mc10.rom", "system": "mc10"},
            ],
        }
        cfg = {
            **config(
                passes("emu", "bios/dragon", "-rompath"),
                {**passes("emu", "bios/coco", "-rompath"), "systems": ["coco"],
                 "machines": ["coco", "coco3"]},
            ),
            "systems": {"coco": {"files": [{"name": "x.zip", "native_system": "coco"}]}},
        }
        ((view, _standalone),) = platform_layouts("emu", profile, standalone_set(cfg))
        self.assertEqual(
            [f.get("standalone_path") for f in view["files"]], ["coco/coco3.rom", "dragon/mc10.rom"]
        )


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
        self.assertEqual(standalone_destination(entry, PROFILE, {"": ("", "dc")}), ("", "dc/boot.bin"))
        self.assertIsNone(standalone_destination(entry, PROFILE, {}))
        # The entry both builds share keeps path in a dual-build profile.
        self.assertIsNone(standalone_destination(PROFILE["files"][2], PROFILE, {"": ("", "dc")}))


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
                    {"": ("", folder)},
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


class OpenmsxOnEachPlatform(unittest.TestCase):
    """openMSX finds system ROMs by SHA1 in share/systemroms below its user
    directory and in every filepool entry. RetroBat sets OPENMSX_HOME to
    bios/openmsx, RetroPie links share/systemroms of its user directory to
    BIOS/openmsx, Batocera adds bios/Machines and bios/openmsx to the
    filepool and lists its own files in bios/openmsx. KNULLI's generator
    does the same, but no KNULLI board builds openmsx."""

    EXPECTED = {
        "batocera": {"share/systemroms": ("", "openmsx")},
        "retrobat": {"": ("", "openmsx")},
        "retropie": {"share/systemroms": ("", "openmsx")},
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["openmsx"]

    def test_each_platform_hands_openmsx_its_folder(self) -> None:
        for platform, expected in self.EXPECTED.items():
            with self.subTest(platform=platform):
                cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                self.assertEqual(
                    standalone_bindings_for("openmsx", self.profile, standalone_set(cfg)),
                    expected,
                )

    def test_every_system_rom_lands_in_bios_openmsx(self) -> None:
        for platform in self.EXPECTED:
            with self.subTest(platform=platform):
                cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                (view, _standalone), = platform_layouts(
                    "openmsx", self.profile, standalone_set(cfg)
                )
                for entry in view["files"]:
                    self.assertNotIn("unplaced", entry)
                    self.assertTrue(
                        entry["standalone_path"].startswith("openmsx/"), entry["standalone_path"]
                    )


class XroarOnEachPlatform(unittest.TestCase):
    """XRoar reads each ROM from a directory of rompath. Batocera writes
    rompath bios/xroar, RetroDECK lists $bios_path in it, RetroPie links
    the build's ${prefix}/share/xroar/roms to $biosdir, RetroBat passes
    -rompath bios/coco for coco and bios/dragon otherwise, Recalbox
    -rompath bios/<system>."""

    # Platform -> profile system -> folder, "" for the BIOS root.
    EXPECTED = {
        "batocera": dict.fromkeys(("dragon32", "dragon64", "coco", "coco3", "mc10"), "xroar"),
        "retrodeck": dict.fromkeys(("dragon32", "dragon64", "coco", "coco3", "mc10"), ""),
        "retropie": dict.fromkeys(("dragon32", "dragon64", "coco", "coco3", "mc10"), ""),
        # RetroBat offers XRoar's CoCo 3 machines under coco and no MC-10.
        "retrobat": {**dict.fromkeys(("dragon32", "dragon64", "mc10"), "dragon"),
                     **dict.fromkeys(("coco", "coco3"), "coco")},
        "recalbox": {**dict.fromkeys(("dragon32", "dragon64"), "dragon"),
                     **dict.fromkeys(("coco", "coco3", "mc10"), "trs80coco")},
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["xroar"]

    def test_each_rom_lands_where_its_launch_reads_it(self) -> None:
        for platform, folders in self.EXPECTED.items():
            cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
            (view, _standalone), = platform_layouts("xroar", self.profile, standalone_set(cfg))
            for entry in view["files"]:
                with self.subTest(platform=platform, name=entry["name"]):
                    self.assertNotIn("unplaced", entry)
                    folder = folders[entry["system"]]
                    expected = f"{folder}/{entry['name']}" if folder else entry["name"]
                    self.assertEqual(entry["standalone_path"], expected)


class AmiberryOnEachPlatform(unittest.TestCase):
    """The standalone Amiberry scans rom_path for its ROMs. Batocera and KNULLI
    set it to bios/amiga, Recalbox to bios/amiga/bios."""

    BOUND = {
        "batocera": ("amiberry-7.1.1-332", "amiga"),
        "knulli": ("amiberry-7.1.1", "amiga"),
        "recalbox": ("amiberry-8.2.2", "amiga/bios"),
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def test_rom_path_is_the_platform_folder(self) -> None:
        for platform, (name, folder) in self.BOUND.items():
            with self.subTest(platform=platform):
                cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
                self.assertEqual(
                    standalone_bindings_for(name, self.profiles[name], standalone_set(cfg)),
                    {"": ("", folder)},
                )

    def test_every_rom_path_entry_lands_in_that_folder(self) -> None:
        for platform, (name, folder) in self.BOUND.items():
            profile = self.profiles[name]
            cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
            views = platform_layouts(name, profile, standalone_set(cfg))
            ((view, _standalone),) = [(v, s) for v, s in views if s]
            for own, entry in zip(profile["files"], view["files"]):
                if own.get("mode") == "libretro":
                    continue
                layout = own.get("standalone_path") or own.get("path") or own["name"]
                with self.subTest(platform=platform, name=entry["name"]):
                    self.assertNotIn("unplaced", entry)
                    self.assertEqual(entry["standalone_path"], f"{folder}/{layout}")

    def test_retrobat_reads_its_folders_below_the_amiberry_emulator_folder(self) -> None:
        # RetroBat writes rom_path and whdboot_path below the amiberry
        # folder of its install and copies the kickstarts it finds in bios
        # into that ROMs folder.
        name = "amiberry-8.3.0"
        profile = self.profiles[name]
        cfg = load_platform_config("retrobat", str(REPO_ROOT / "platforms"))
        self.assertEqual(
            standalone_bindings_for(name, profile, standalone_set(cfg)),
            {"": ("emulators", "amiberry/ROMs"), "WHDBoot": ("emulators", "amiberry/WHDBoot")},
        )
        ((view, _standalone),) = platform_layouts(name, profile, standalone_set(cfg))
        for own, entry in zip(profile["files"], view["files"]):
            layout = own.get("standalone_path") or own.get("path") or own["name"]
            folder = "amiberry" if layout.startswith("WHDBoot/") else "amiberry/ROMs"
            with self.subTest(name=entry["name"]):
                self.assertNotIn("unplaced", entry)
                self.assertEqual(entry.get("root"), "emulators")
                self.assertEqual(entry["standalone_path"], f"{folder}/{layout}")


class AmiberryBuildEachPlatformShips(unittest.TestCase):
    """Each platform resolves the name amiberry to the build its own package
    compiles. RetroBat keeps the 8.5.0 libretro core beside its standalone,
    and Batocera's x86_64 boards fetch it with RetroArch's core downloader
    (installable_cores)."""

    OWN = {
        "rocknix": {"amiberry-5.6.5"},
        "amberelec": {"amiberry-7.1.1"},
        "emuelec": {"amiberry-8.0.0"},
        "batocera": {"amiberry", "amiberry-7.1.1-332"},
        "knulli": {"amiberry-7.1.1"},
        "recalbox": {"amiberry-8.2.2"},
        "retrobat": {"amiberry", "amiberry-8.3.0"},
        "retropie": {"amiberry-5.7.2", "amiberry-6.3.3"},
        "emudeck": {"amiberry"},
        "retrodeck": {"amiberry"},
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

    def resolved(self, platform: str) -> set[str]:
        from common import resolve_platform_cores

        cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
        return {p for p in resolve_platform_cores(cfg, self.profiles) if p.startswith("amiberry")}

    def test_each_platform_resolves_its_own_build(self) -> None:
        for platform, own in self.OWN.items():
            with self.subTest(platform=platform):
                self.assertEqual(self.resolved(platform), own)

    def test_no_standalone_amiberry_is_the_buildbot_revision(self) -> None:
        from common import list_registered_platforms

        for platform in list_registered_platforms(str(REPO_ROOT / "platforms")):
            cfg = load_platform_config(platform, str(REPO_ROOT / "platforms"))
            if "amiberry" not in self.resolved(platform):
                continue
            layouts = platform_layouts("amiberry", self.profiles["amiberry"], standalone_set(cfg))
            with self.subTest(platform=platform):
                self.assertEqual([standalone for _view, standalone in layouts], [False])

    def test_the_buildbot_core_runs_where_retroarch_installs_it(self) -> None:
        from common import load_target_config, resolve_platform_cores

        for platform in ("retroarch", "lakka", "batocera"):
            with self.subTest(platform=platform):
                self.assertIn("amiberry", self.resolved(platform))
        cfg = load_platform_config("batocera", str(REPO_ROOT / "platforms"))
        # x86_64 boards download from linux-x86_64, which builds the core.
        # linux-armhf does not, and aarch64 boards have no downloader.
        for target, runs in (("x86_64", True), ("zen3", True), ("h3", False), ("bcm2711", False)):
            cores = load_target_config("batocera", target, str(REPO_ROOT / "platforms"))
            with self.subTest(target=target):
                resolved = resolve_platform_cores(cfg, self.profiles, cores)
                self.assertEqual("amiberry" in resolved, runs)
                self.assertIn("amiberry-7.1.1-332", resolved)

    def test_retropie_reads_kickstarts_below_its_start_folder(self) -> None:
        # amiberry 5.7 and 6.3 read <start path>/kickstarts, which RetroPie
        # links to bios/amiga. Its whdboot and roms folders stay below it.
        cfg = load_platform_config("retropie", str(REPO_ROOT / "platforms"))
        for name in ("amiberry-5.7.2", "amiberry-6.3.3"):
            profile = self.profiles[name]
            self.assertEqual(
                standalone_bindings_for(name, profile, standalone_set(cfg)),
                {"kickstarts": ("", "amiga")},
            )
            ((view, _standalone),) = platform_layouts(name, profile, standalone_set(cfg))
            for entry in view["files"]:
                with self.subTest(name=name, file=entry["name"]):
                    if entry["path"].startswith("kickstarts/"):
                        self.assertEqual(entry["standalone_path"],
                                         "amiga/" + entry["path"][len("kickstarts/"):])
                    else:
                        self.assertEqual(entry.get("unplaced"), "outside_bios_folder")

    def test_rocknix_reads_kickstarts_through_the_copied_link(self) -> None:
        # amiberry 5.6.5 reads <cwd>/kickstarts. ROCKNIX runs it in
        # /storage/.config/amiberry, the copy of /usr/config/amiberry whose
        # kickstarts link points at the BIOS root.
        profile = self.profiles["amiberry-5.6.5"]
        cfg = load_platform_config("rocknix", str(REPO_ROOT / "platforms"))
        self.assertEqual(
            standalone_bindings_for("amiberry-5.6.5", profile, standalone_set(cfg)),
            {"kickstarts": ("", "")},
        )
        ((view, _standalone),) = platform_layouts("amiberry-5.6.5", profile, standalone_set(cfg))
        for entry in view["files"]:
            with self.subTest(name=entry["name"]):
                if entry["path"].startswith("kickstarts/"):
                    self.assertEqual(entry["standalone_path"], entry["path"][len("kickstarts/"):])
                else:
                    self.assertEqual(entry.get("unplaced"), "outside_bios_folder")


if __name__ == "__main__":
    unittest.main()
