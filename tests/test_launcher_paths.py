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
from scraper import knulli_launchers as kl  # noqa: E402
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


class ADataFolderTheEnvironmentSets(unittest.TestCase):
    SUYU = f"{kl.GENERATORS}/suyu/suyuGenerator.py"
    TEXT = textwrap.dedent("""\
        from ...batoceraPaths import CACHE, CONFIGS, SAVES

        class SuyuGenerator:
            def generate(self, system, rom):
                commandArray = ["/usr/bin/suyu", "-f", "-g", rom]
                return Command.Command(array=commandArray, env={
                    "XDG_CONFIG_HOME": CONFIGS,
                    "XDG_DATA_HOME": SAVES / "switch",
                })
        """)

    def test_the_data_folder_is_a_record_and_binds_outside(self):
        files = {f"{kl.CONFIGGEN}/batoceraPaths.py": PATHS,
                 f"{kl.GENERATORS}/importer.py": IMPORTER_TEXT, self.SUYU: self.TEXT}
        (record,) = records(kl.data_homes(kl.configgen(files.__getitem__)))
        self.assertEqual(
            (record["emulator"], record["search_dir"], record["passes_to"], record["source_ref"]),
            ("suyu", "/userdata/saves/switch", "environment XDG_DATA_HOME", f"{self.SUYU}:8"),
        )
        config = {"base_destination": "bios", "standalone_cores": ["suyu"], "launchers": [record]}
        found = standalone_bindings(
            {"suyu"}, ["$XDG_DATA_HOME/suyu", "SuyuPath::KeysDir = keys"],
            handed_directories(config),
        )
        self.assertEqual(found, {"": ("outside", "")})


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

    def sources(self) -> dict[str, rl.Source]:
        return {
            f"{rl.GENERATORS}/Citron.Generator.cs": rl.Source(
                "c", textwrap.dedent(self.CITRON).lstrip("\n")),
            f"{rl.GENERATORS}/ShadPS4.Generator.cs": rl.Source(
                "s", textwrap.dedent(self.SHADPS4).lstrip("\n")),
        }

    def test_each_generator_gives_its_user_folder(self):
        found = rl.portable_users(self.sources())
        self.assertEqual(
            [(r["emulator"], r["search_dir"], r["source_ref"]) for r in found],
            [("citron", '<AppConfig.GetFullPath("citron")>/user', "c:3, 7-8"),
             ("shadps4", '<AppConfig.GetFullPath("shadps4")>/user', "s:3, 8-10")],
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


if __name__ == "__main__":
    unittest.main()
