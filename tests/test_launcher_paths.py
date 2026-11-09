"""Folders a platform's launcher hands an emulator, read from its code.

Batocera patches Citron's path code to read its keys from /userdata/bios/
switch and starts shadPS4 from /userdata/system/configs/shadps4, KNULLI sets
suyu's XDG data folder, and RetroBat creates a portable user folder beside
Citron and shadPS4. Each fixture is a cut-down copy of the lines at the
revisions the platform files pin, and a binding reads the record the
extractor writes.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from launchers import handed_directories, standalone_bindings  # noqa: E402
from scraper import retrobat_launchers as rl  # noqa: E402
from scraper.batocera_launchers import (  # noqa: E402
    GENERATORS,
    IMPORTER,
    PATHS_MODULE,
    Configgen,
    LauncherShapeError,
    patched_paths,
    working_directories,
)

PATCH = "package/batocera/emulators/citron/002-adjust-paths.patch"
PATCH_TEXT = textwrap.dedent("""\
    diff --git a/src/common/fs/path_util.cpp b/src/common/fs/path_util.cpp
    index f92cbe0f7b..9e3dcd9c18 100644
    --- a/src/common/fs/path_util.cpp
    +++ b/src/common/fs/path_util.cpp
    @@ -121,12 +121,12 @@ public:
             GenerateCitronPath(CitronPath::ConfigDir, citron_path_config);
             GenerateCitronPath(CitronPath::DumpDir, citron_path / DUMP_DIR);
    -        GenerateCitronPath(CitronPath::KeysDir, citron_path / KEYS_DIR);
    +        GenerateCitronPath(CitronPath::KeysDir, "/userdata/bios/switch");
    -        GenerateCitronPath(CitronPath::LogDir, citron_path / LOG_DIR);
    +        GenerateCitronPath(CitronPath::LogDir, "/userdata/system/logs");
    """)

PATHS = """from pathlib import Path
from typing import Final

USERDATA: Final = Path('/userdata')
BIOS: Final = USERDATA / 'bios'
SAVES: Final = USERDATA / 'saves'
CONFIGS: Final = USERDATA / 'system' / 'configs'
"""
IMPORTER_TEXT = """_LEGACY_GENERATOR_MAP = {}
_GENERATOR_MAP = {}
"""
SHADPS4 = f"{GENERATORS}/shadps4/shadps4Generator.py"
SHADPS4_TEXT = textwrap.dedent("""\
    import os
    from ...batoceraPaths import CONFIGS

    class ShadPS4Generator:
        def generate(self, system, rom):
            configPath = CONFIGS / "shadps4"
            userConfigPath = configPath / "user"
            os.chdir(configPath)
            return None
    """)


def records(entries: list) -> list[dict]:
    return [entry.entry() if hasattr(entry, "entry") else entry for entry in entries]


class APatchRewritingAFolder(unittest.TestCase):
    def test_the_bios_folder_a_patch_gives_is_a_record(self):
        (record,) = records(patched_paths({PATCH: PATCH_TEXT}.__getitem__))
        self.assertEqual(
            (record["emulator"], record["kind"], record["search_dir"], record["source_ref"]),
            ("citron", "passes_path", "/userdata/bios/switch", f"{PATCH}:8-9"),
        )
        self.assertIn("CitronPath::KeysDir", record["passes_to"])
        self.assertIn("citron_path / KEYS_DIR", record["passes_to"])

    def test_a_patch_that_no_longer_rewrites_a_bios_folder_stops_the_scrape(self):
        text = PATCH_TEXT.replace('"/userdata/bios/switch"', '"/userdata/saves/switch"')
        with self.assertRaises(LauncherShapeError):
            patched_paths({PATCH: text}.__getitem__)

    def test_the_named_handle_binds_its_folder_alone(self):
        config = {"base_destination": "bios", "standalone_cores": ["citron"], "launchers":
                  records(patched_paths({PATCH: PATCH_TEXT}.__getitem__))}
        found = standalone_bindings(
            {"citron"}, ["$XDG_DATA_HOME/citron", "CitronPath::KeysDir = keys"],
            handed_directories(config),
        )
        self.assertEqual(found, {"keys": ("", "switch")})


class AFolderTheGeneratorEnters(unittest.TestCase):
    def tree(self, text: str = SHADPS4_TEXT) -> Configgen:
        files = {PATHS_MODULE: PATHS, IMPORTER: IMPORTER_TEXT, SHADPS4: text}
        return Configgen(files.__getitem__)

    def test_the_working_directory_is_a_record(self):
        (record,) = records(working_directories(self.tree()))
        self.assertEqual(
            (record["emulator"], record["search_dir"], record["passes_to"], record["source_ref"]),
            ("shadps4", "/userdata/system/configs/shadps4",
             "working directory of shadps4Generator.py", f"{SHADPS4}:6, 8"),
        )

    def test_a_generator_that_no_longer_enters_a_folder_stops_the_scrape(self):
        with self.assertRaises(LauncherShapeError):
            working_directories(self.tree(SHADPS4_TEXT.replace("os.chdir(configPath)", "pass")))

    def test_the_user_folder_below_it_is_outside_the_bios_tree(self):
        config = {"base_destination": "bios", "standalone_cores": ["shadps4"],
                  "launchers": records(working_directories(self.tree()))}
        found = standalone_bindings(
            {"shadps4"}, ["getcwd/user", "$XDG_DATA_HOME/shadPS4"], handed_directories(config)
        )
        self.assertEqual(found, {"": ("outside", "")})


class AVariableADeclaredFolderIsSpelledFrom(unittest.TestCase):
    def test_a_data_folder_outside_the_tree_binds_outside(self):
        record = {"emulator": "emu", "build": "standalone", "kind": "passes_path",
                  "names": [], "search_dir": "/userdata/saves/switch",
                  "passes_to": "environment XDG_DATA_HOME", "source_ref": "x.py:1"}
        config = {"base_destination": "bios", "standalone_cores": ["emu"], "launchers": [record]}
        found = standalone_bindings(
            {"emu"}, ["$XDG_DATA_HOME/emu"], handed_directories(config)
        )
        self.assertEqual(found, {"": ("outside", "")})

    def test_a_data_folder_in_the_tree_binds_below_it(self):
        record = {"emulator": "emu", "build": "standalone", "kind": "passes_path",
                  "names": [], "search_dir": "/userdata/bios/data",
                  "passes_to": "environment XDG_DATA_HOME", "source_ref": "x.py:1"}
        config = {"base_destination": "bios", "standalone_cores": ["emu"], "launchers": [record]}
        found = standalone_bindings(
            {"emu"}, ["$XDG_DATA_HOME/emu"], handed_directories(config)
        )
        self.assertEqual(found, {"": ("", "data/emu")})


class APortableUserFolder(unittest.TestCase):
    CITRON = """
        public override System.Diagnostics.ProcessStartInfo Generate(string system, string emulator, string core, string rom, string playersControllers, ScreenResolution resolution)
        {
            if (!GetEmulatorPathAndExe(emulator, out string path, out string exe, "citron.exe"))
                return null;

            // Ensure user folder exists
            string userFolder = Path.Combine(path, "user");
            if (!Directory.Exists(userFolder)) try { Directory.CreateDirectory(userFolder); }
                catch { }
        }
    """
    SHADPS4 = """
        public override System.Diagnostics.ProcessStartInfo Generate(string system, string emulator, string core, string rom, string playersControllers, ScreenResolution resolution)
        {
            string path = AppConfig.GetFullPath(emulator);
        }

        private void SetupConfigurationJSON(string path, string rom)
        {
            string userFolder = Path.Combine(path, "user");
            if (!Directory.Exists(userFolder))
                try { Directory.CreateDirectory(userFolder); } catch { }
        }
    """

    RYUJINX = """
        public override System.Diagnostics.ProcessStartInfo Generate(string system, string emulator, string core, string rom, string playersControllers, ScreenResolution resolution)
        {
            string path = AppConfig.GetFullPath("ryujinx");
            string portablePath = Path.Combine(AppConfig.GetFullPath("saves"), "switch", "ryujinx", "portable");
            string setupPath = Path.Combine(path, "portable");
        }
    """

    def sources(self) -> dict[str, rl.Source]:
        def source(ref: str, text: str) -> rl.Source:
            return rl.Source(ref, textwrap.dedent(text).lstrip("\n"))

        def yuzu_like(exe: str) -> str:
            return self.CITRON.replace("citron.exe", exe)

        return {
            f"{rl.GENERATORS}/Citron.Generator.cs": source("c", self.CITRON),
            f"{rl.GENERATORS}/Eden.Generator.cs": source("e", yuzu_like("eden.exe")),
            f"{rl.GENERATORS}/Ryujinx.Generator.cs": source("r", self.RYUJINX),
            f"{rl.GENERATORS}/ShadPS4.Generator.cs": source("s", self.SHADPS4),
            f"{rl.GENERATORS}/Sudachi.Generator.cs": source("u", yuzu_like("sudachi.exe")),
            f"{rl.GENERATORS}/Yuzu.Generator.cs": source("y", yuzu_like("yuzu.exe")),
        }

    def test_each_generator_gives_its_user_folder(self):
        found = rl.portable_users(self.sources())
        self.assertEqual(
            [(r["emulator"], r["search_dir"], r["source_ref"]) for r in found],
            [("citron", '<AppConfig.GetFullPath("citron")>/user', "c:3, 7-8"),
             ("eden", '<AppConfig.GetFullPath("eden")>/user', "e:3, 7-8"),
             ("ryujinx", '<AppConfig.GetFullPath("ryujinx")>/portable', "r:3-5"),
             ("shadps4", '<AppConfig.GetFullPath("shadps4")>/user', "s:3, 8-10"),
             ("sudachi", '<AppConfig.GetFullPath("sudachi")>/user', "u:3, 7-8"),
             ("yuzu", '<AppConfig.GetFullPath("yuzu")>/user', "y:3, 7-8")],
        )
        ryujinx = found[2]
        self.assertEqual(ryujinx["passes_to"], "DefaultPortableDir, the portable folder beside Ryujinx.exe")
        self.assertEqual(
            ryujinx["depends_on_option"], "unless saves/switch/ryujinx/portable exists, passed with -r"
        )

    def test_the_user_folder_binds_below_the_emulator_folder(self):
        config = {
            "base_destination": "bios", "standalone_cores": ["citron"],
            "emulators_directory": {"launcher_spelling": '<AppConfig.GetFullPath("{key}")>'},
            "launchers": rl.portable_users(self.sources())[:1],
        }
        found = standalone_bindings(
            {"citron"}, ["$XDG_DATA_HOME/citron", "PORTABLE_DIR"], handed_directories(config)
        )
        self.assertEqual(found, {"": ("emulators", "citron/user")})



class OnlyWhatABoardBuildsIsRun(unittest.TestCase):
    """KNULLI's es_systems.yml lists citron and shadps4, which its Config.in
    selects only on x86_64 boards (it has none), and its
    configgen-defaults.yml picks suyu, which no package builds."""

    ES = textwrap.dedent("""\
        switch:
          emulators:
            citron:
              citron: { requireAnyOf: [BR2_PACKAGE_CITRON] }
        gba:
          emulators:
            libretro:
              mgba: { requireAnyOf: [BR2_PACKAGE_LIBRETRO_MGBA] }
        voxatron:
          emulators: {}
        """)
    DEFAULTS = textwrap.dedent("""\
        switch:
          emulator: suyu
          core: suyu
        voxatron:
          emulator: lexaloffle
          core: vox_official
        kodi:
          emulator: kodi
          core: kodi
        mpv:
          emulator: mpv
          core: mpv
        """)
    LAUNCHERS = [{"emulator": "lexaloffle", "kind": "fixed_name", "passes_to": "exec",
                  "search_dir": "/userdata/bios"}]

    def selection(self, symbols: set[str]):
        from scraper.targets.batocera_targets_scraper import BuildSelection

        return BuildSelection(
            targets={}, emulators=frozenset({"mgba"}),
            listed=frozenset({"citron", "mgba"}), symbols=frozenset(symbols),
            packages={"kodi": "BR2_PACKAGE_KODI"},
        )

    def test_only_what_a_board_builds_or_the_user_supplies_is_run(self):
        from scraper import batocera_scraper as bs

        # A board selects kodi's package and buildroot's mpv; citron is
        # listed by es_systems, so the symbol of a folder of that name does
        # not count for it.
        built = bs.boards_build(
            self.selection({"BR2_PACKAGE_KODI", "BR2_PACKAGE_MPV", "BR2_PACKAGE_CITRON_X"}),
            self.LAUNCHERS,
        )
        cores, standalone, _dual = bs.configgen_cores(self.DEFAULTS, self.ES, set(), built)
        self.assertEqual(sorted(cores), ["kodi", "mgba", "mpv", "vox_official"])
        self.assertEqual(sorted(standalone), ["kodi", "lexaloffle", "mpv", "vox_official"])
        # Each system keeps the list es_systems.yml writes (whose files its
        # entries ask for), less a default no package builds.
        by_system = bs.es_systems_by_system(self.ES, self.DEFAULTS, set(), built)
        self.assertEqual(by_system["switch"], ["citron"])
        self.assertEqual(by_system["voxatron"], ["lexaloffle", "vox_official"])
        self.assertEqual(by_system["gba"], ["mgba"])

    def test_a_listed_name_is_built_only_through_its_packages(self):
        from scraper import batocera_scraper as bs

        built = bs.boards_build(self.selection({"BR2_PACKAGE_CITRON"}), [])
        self.assertFalse(built("citron"))
        self.assertTrue(built("mgba"))
        self.assertFalse(built("lexaloffle"))
        # Without a selection, every name counts, as before.
        self.assertIn("suyu", bs.configgen_cores(self.DEFAULTS, self.ES, set())[0])

    def test_the_real_lists_name_only_what_a_board_builds(self):
        import yaml

        for platform, absent in (("knulli", ("suyu", "citron", "shadps4", "pcsx2")),
                                 ("batocera", ("citron", "ryujinx", "applewin"))):
            config = yaml.safe_load((REPO_ROOT / "platforms" / f"{platform}.yml").read_text())
            names = set(config["cores"]) | set(config.get("standalone_cores") or [])
            targets = yaml.safe_load(
                (REPO_ROOT / "platforms" / "targets" / f"{platform}.yml").read_text())["targets"]
            boards = {c for entry in targets.values() for c in entry["cores"]}
            with self.subTest(platform=platform):
                self.assertFalse(names & set(absent))
                # What a board builds and the list once named is still there,
                # and what no board builds is a program the user supplies.
                self.assertLessEqual(names - boards, {"kodi", "lexaloffle", "mpv", "vox_official"})


class AUserFolderInTheConfigsFolder(unittest.TestCase):
    """Batocera starts shadPS4 from /userdata/system/configs/shadps4, a folder
    of the configs root its batoceraPaths builds (../system/configs)."""

    def test_the_sys_modules_go_below_the_configs_root(self):
        from common import load_emulator_profiles, load_platform_config, platform_layouts
        from common import standalone_set

        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["shadps4"]
        # KNULLI's generator does the same, but no KNULLI board builds shadps4.
        for platform in ("batocera",):
            config = load_platform_config(platform, str(REPO_ROOT / "platforms"))
            ((view, _standalone),) = platform_layouts("shadps4", profile, standalone_set(config))
            with self.subTest(platform=platform):
                self.assertEqual(
                    {(f.get("root"), f["standalone_path"].rsplit("/", 1)[0]) for f in view["files"]},
                    {("configs", "shadps4/user/sys_modules"), ("configs", "shadps4/user/fonts/font"),
                     ("configs", "shadps4/user/fonts/font2")},
                )

    def test_the_installer_follows_from_bios_to_the_configs_folder(self):
        import install

        manifest = {"configs_directory": {"bios_folder": "bios", "from_bios": "../system/configs"}}
        install._check_relative_directories(manifest)
        files = [{"dest": "shadps4/user/sys_modules/libSceNgs2.sprx", "root": "configs"}]
        bios = Path("/userdata/bios")
        kept, left = install.place_relative_entries(files, bios, manifest, "x", say=False)
        self.assertEqual((len(kept), left), (1, []))
        self.assertEqual(
            install._entry_place(bios, kept[0])[0], Path("/userdata/system/configs")
        )
        kept, left = install.place_relative_entries(
            files, Path("/elsewhere/firmware"), manifest, "x", say=False)
        self.assertEqual((kept, [o["reason"] for o in left]), ([], ["no_configs_directory"]))
        for value in ("../C:x", "../../../x", "../system/../x"):
            with self.subTest(from_bios=value), self.assertRaises(ValueError):
                install._check_relative_directories(
                    {"configs_directory": {"bios_folder": "bios", "from_bios": value}})


if __name__ == "__main__":
    unittest.main()
