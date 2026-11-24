"""install.py copies the files standalone emulators read into their own folders, and stays inside them."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path, PurePosixPath

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, _LoopbackRun, _install_run


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_standalone")


class TestStandaloneCopiesExtraDirs(unittest.TestCase):
    """Setups that keep emulators outside the default locations."""

    def _manifest(self) -> dict:
        return {
            "files": [{"dest": "ps2-0230a.bin"}, {"dest": "GC/USA/IPL.bin"}],
            "standalone_copies": [
                {
                    "pattern": "ps2-*.bin",
                    "emulator": "pcsx2",
                    "targets": {"windows": []},
                },
                {
                    "file": "GC/USA/IPL.bin",
                    "emulator": "dolphin",
                    "targets": {"windows": []},
                },
            ]
        }

    def test_pattern_entry_copies_into_extra_dir(self):
        bios = scratch_dir(self)
        (bios / "ps2-0230a.bin").write_text("rom")
        extra = scratch_dir(self) / "bios"
        extra.mkdir()
        copied, _, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"pcsx2": extra}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((extra / "ps2-0230a.bin").exists())

    def test_file_entry_keeps_its_subdirectory(self):
        bios = scratch_dir(self)
        (bios / "GC" / "USA").mkdir(parents=True)
        (bios / "GC" / "USA" / "IPL.bin").write_text("ipl")
        user = scratch_dir(self) / "User"
        (user / "GC" / "USA").mkdir(parents=True)
        copied, _, _ = install.do_standalone_copies(
            self._manifest(), bios, "windows", {"dolphin": user}
        )
        self.assertEqual(copied, 1)
        self.assertTrue((user / "GC" / "USA" / "IPL.bin").exists())

    def test_no_extra_dirs_is_unchanged(self):
        bios = scratch_dir(self)
        (bios / "ps2-0230a.bin").write_text("rom")
        self.assertEqual(
            install.do_standalone_copies(self._manifest(), bios, "windows"), (0, 0, 0)
        )


@unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                 "a closed folder needs POSIX permissions and a non-root user")
class StandaloneFolderClosedToThisUser(unittest.TestCase):
    """Termux on Android 11 and later cannot look into another app's
    Android/data folder: is_dir() on Dolphin's GC/USA raised PermissionError
    after the install, and the run stopped with code 1."""

    def setUp(self) -> None:
        self.bios = scratch_dir(self)
        (self.bios / "IPL.bin").write_text("ipl")
        self.app = scratch_dir(self) / "org.dolphinemu.dolphinemu"
        (self.app / "files" / "GC" / "USA").mkdir(parents=True)
        self.app.chmod(0)
        self.addCleanup(self.app.chmod, 0o755)
        self.target = self.app / "files" / "GC" / "USA"
        self.manifest = {"files": [{"dest": "IPL.bin"}], "standalone_copies": [
            {"file": "IPL.bin", "targets": {"android": [str(self.target)]}},
            {"note": "Dolphin reads GC/", "detect": {"android": [str(self.target)]}},
        ]}

    def test_listing_the_folders_here_skips_it(self):
        self.assertEqual(install.standalone_folders_here(self.manifest, "android"), [])

    def test_planning_skips_it(self):
        self.assertEqual(install.standalone_plan([self.manifest], "android"), [])

    def test_copying_names_it_and_goes_on(self):
        """Skipped, not failed: Android answers the same refusal for an app
        that is not installed, and a run without Dolphin is no failure."""
        failures: list[tuple[str, str]] = []
        with contextlib.redirect_stdout(io.StringIO()) as out:
            result = install.do_standalone_copies(
                self.manifest, self.bios, "android", failures=failures)
        self.assertEqual(result, (0, 1, 0))
        self.assertEqual(failures, [])
        self.assertIn(f"{self.target}: could not be read", out.getvalue())


class StandaloneCopiesReadWhereThePackPutTheFile(unittest.TestCase):
    """The registry names Citra/sysdata/aes_keys.txt for every platform,
    but EmuDeck's manifest installs it at the root. The installer looked under
    the registry's path, found nothing and copied nothing to Azahar."""

    def _copy(self, entry: dict) -> tuple[Path, tuple[int, int, int]]:
        bios = scratch_dir(self)
        (bios / "aes_keys.txt").write_text("keys")
        sysdata = scratch_dir(self) / "sysdata"
        sysdata.mkdir()
        manifest = {"files": [{"dest": "aes_keys.txt"}], "standalone_copies": [
            {**entry, "emulator": "azahar", "targets": {"linux": [str(sysdata)]}},
        ]}
        return sysdata, install.do_standalone_copies(manifest, bios, "linux")

    def test_the_source_the_manifest_names_is_copied(self):
        sysdata, (copied, _, _) = self._copy(
            {"file": "Citra/sysdata/aes_keys.txt", "source": "aes_keys.txt"}
        )
        self.assertEqual(copied, 1)
        self.assertEqual((sysdata / "aes_keys.txt").read_text(), "keys")

    def test_without_a_source_the_file_path_is_read(self):
        _, (copied, _, _) = self._copy({"file": "Citra/sysdata/aes_keys.txt"})
        self.assertEqual(copied, 0)

    def test_an_unsafe_source_is_refused_at_load(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[1] / "install" / "emudeck.json").read_text()
        )
        manifest["standalone_copies"] = [
            {"file": "aes_keys.txt", "source": "../../etc/passwd",
             "targets": {"linux": ["/tmp"]}},
        ]
        with self.assertRaisesRegex(ValueError, r"standalone_copies\[0\]\.source"):
            install._validate_manifest(manifest, "emudeck")


class StandaloneCopiesFollowTheList(unittest.TestCase):
    """The platform pass scanned the BIOS folder for each pattern: a user's
    own bios/old/scph9999.bin went to DuckStation, while the plan of a run
    with no platform named scph5501.bin alone."""

    def setUp(self) -> None:
        self.bios = scratch_dir(self)
        (self.bios / "scph5501.bin").write_bytes(b"rom")
        (self.bios / "old").mkdir()
        (self.bios / "old" / "scph9999.bin").write_bytes(b"other")
        self.emu = scratch_dir(self) / "duckstation"
        self.emu.mkdir()
        self.manifest = {"files": [{"dest": "scph5501.bin"}], "standalone_copies": [
            {"pattern": "scph*.bin", "emulator": "duckstation",
             "targets": {"linux": [str(self.emu)]}}]}

    def test_the_copy_and_the_plan_name_the_same_files(self):
        plan = install.standalone_plan([self.manifest], "linux")
        self.assertEqual([(folder, [entry["dest"] for entry in entries])
                          for folder, entries in plan], [(self.emu, ["scph5501.bin"])])
        self.assertEqual(install.do_standalone_copies(self.manifest, self.bios, "linux"),
                         (1, 0, 0))
        self.assertEqual(sorted(path.name for path in self.emu.iterdir()), ["scph5501.bin"])

    def test_only_a_file_the_run_verified_is_copied(self):
        self.assertEqual(install.do_standalone_copies(self.manifest, self.bios, "linux",
                                                      verified=[]), (0, 0, 0))
        self.assertEqual(list(self.emu.iterdir()), [])


class OuterRootsAreUntrusted(unittest.TestCase):
    """roms_directory and emulators_directory come from a downloaded list: each
    path in them meets the rules a BIOS destination meets, and each folder
    they resolve to stays where the platform's layout puts it."""

    ROMS = {"bios_folder": "bios", "from_bios": ".."}
    EMULATORS = {
        "bios_folder": "bios", "searched": ["frontend/{key}", "emulators/{key}"],
        "default": "emulators/{key}", "config": "frontend/launcher.cfg",
    }
    UNSAFE = ("..\\x", "C:", "C:/x", "..//x", "../", "../x\x01", "x" * 1025)

    def test_unsafe_from_bios_is_refused(self):
        for value in (*self.UNSAFE, "../../../x", "../x/..", "x", "./x", "/x", "..x", None):
            with self.subTest(from_bios=value), self.assertRaises(ValueError):
                install._check_relative_directories({"roms_directory": {**self.ROMS, "from_bios": value}})

    def test_the_relations_the_rom_folders_files_use_are_accepted(self):
        bios = Path("/card/system/bios")
        expected = {
            ".": bios, "..": Path("/card/system"), "../roms": Path("/card/system/roms"),
            "../Roms": Path("/card/system/Roms"), "../../Roms": Path("/card/Roms"),
            "../../ROMS": Path("/card/ROMS"),
        }
        for value, root in expected.items():
            with self.subTest(from_bios=value):
                install._check_relative_directories({"roms_directory": {**self.ROMS, "from_bios": value}})
                self.assertEqual(install._relative_root(bios, value), root)
        self.assertEqual(install.MAX_ROMS_UPS, 2)

    def test_a_list_without_a_roms_root_leaves_the_files_out(self):
        files = [{"dest": "pico-8/pico8_64", "root": "roms", "cores": ["x"]}]
        kept, left = install.place_relative_entries(files, Path("/card/roms/bios"), {})
        self.assertEqual((kept, [o["reason"] for o in left]), ([], ["no_roms_directory"]))

    def test_roms_left_out_are_counted_after_the_choice(self):
        # --system panasonic-3do said 1918 EmuDeck roms files were left out, 6 of them its.
        files = [{"dest": f"{system}/x{n}.bin", "root": "roms", "systems": [system]}
                 for system, count in (("panasonic-3do", 1), ("sony-psx", 3)) for n in range(count)]
        bios = Path("/card/notbios")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            kept, left = install.place_relative_entries(files, bios, {})
        self.assertEqual((kept, len(left), out.getvalue()), ([], 4, ""))
        chosen = install.narrow([], left, ["panasonic-3do"], [], [])[1]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            install.say_unplaced(chosen, "EmuDeck")
        self.assertEqual(out.getvalue(), "  1 file read from EmuDeck's roms folder left out: "
                                         f"{bios} is not its BIOS folder.\n")

    def test_unsafe_emulator_folders_are_refused(self):
        for field in ("searched", "default", "config"):
            for value in self.UNSAFE + ("../{key}", "/abs/{key}"):
                layout = dict(self.EMULATORS)
                if field == "searched":
                    layout["searched"] = [value if "{key}" in value else value + "/{key}"]
                    layout["default"] = layout["searched"][0]
                elif field == "default":
                    layout["default"] = value
                else:
                    layout["config"] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    install._check_emulators_directory({"emulators_directory": layout})

    def test_a_drive_or_colon_segment_is_refused_on_either_host(self):
        from pathlib import PureWindowsPath

        bios = PureWindowsPath("C:/RetroBat/bios")
        for host in ("posix", "nt"):
            with unittest.mock.patch.object(install.os, "name", host):
                for value in ("../C:x", "..\\x", "../x:", "../Roms:x"):
                    with self.subTest(host=host, from_bios=value), self.assertRaises(ValueError):
                        install._check_relative_directories(
                            {"roms_directory": {**self.ROMS, "from_bios": value}})
                for value in ("C:x/{key}", "x:/{key}", "emu:x/{key}"):
                    layout = {**self.EMULATORS, "searched": [value], "default": value}
                    with self.subTest(host=host, searched=value), self.assertRaises(ValueError):
                        install._check_emulators_directory({"emulators_directory": layout})
                for dest in ("bios/C:x.bin", "bios/x:", "a:b/c.bin"):
                    with self.subTest(host=host, dest=dest), self.assertRaises(ValueError):
                        install._safe_relative_path(dest, "dest")
                with self.subTest(host=host), self.assertRaises(ValueError):
                    install._safe_relative_path("pico8/x:y", "dest", colons=False)
        # Each of these leaves the folder on Windows once joined.
        self.assertEqual(PureWindowsPath(bios, "..", "D:x"), PureWindowsPath("D:x"))
        self.assertEqual(PureWindowsPath("C:x").drive, "C:")
        # RetroDECK's ares names are kept where the host is not Windows.
        with unittest.mock.patch.object(install.os, "name", "posix"):
            install._safe_relative_path("bios/snes:st018.data.rom", "dest")
        with unittest.mock.patch.object(install.os, "name", "nt"), self.assertRaises(ValueError):
            install._safe_relative_path("bios/snes:st018.data.rom", "dest")

    def test_an_emulator_folder_stays_below_the_platform_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "bios").mkdir()
            (home / "frontend").mkdir()
            (home / "frontend" / "launcher.cfg").write_text("")
            manifest = {"emulators_directory": self.EMULATORS}
            for dest in ("../x/prog", "C:/prog", "prog\\..\\..\\x/a"):
                with self.subTest(dest=dest), self.assertRaises(ValueError):
                    install.place_emulator_entries(
                        [{"dest": dest, "root": "emulators"}], home / "bios", manifest)
            kept, left = install.place_emulator_entries(
                [{"dest": "prog/prog.exe", "root": "emulators"}], home / "bios", manifest)
            self.assertEqual((len(kept), left), (1, []))
            folder, rest = install._entry_place(home / "bios", kept[0])
            self.assertEqual((folder, rest), (home / "emulators" / "prog", "prog.exe"))


class ARefusedCopyIsAnError(unittest.TestCase):
    """A PermissionError on a standalone copy was counted as "dir not found"
    and the run ended on Done with exit code 0."""

    def test_a_refused_copy_is_counted_failed_not_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            bios = Path(tmp, "bios")
            bios.mkdir()
            (bios / "prod.keys").write_bytes(b"k")
            target = Path(tmp, "keys")
            target.mkdir()
            manifest = {"files": [{"dest": "prod.keys"}], "standalone_copies": [
                {"file": "prod.keys", "targets": {"linux": [str(target)]}}
            ]}
            with unittest.mock.patch("shutil.copy2", side_effect=PermissionError(13, "denied")):
                result = install.do_standalone_copies(manifest, bios, "linux")
        self.assertEqual(result, (0, 0, 1))


class TestStandaloneCopyTargetsAreUntrusted(unittest.TestCase):
    """The manifest names these directories, so it does not get to escape them."""

    def _manifest(self, target: str) -> dict:
        return {
            "files": [{"dest": "boot.bin"}],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": [target]}}
            ]
        }

    def test_traversal_in_a_target_is_refused_by_validation(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["~/emu/../../../etc"]}}
            ],
        }
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")

    def test_nul_in_a_target_is_refused_by_validation(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["/tmp/a\x00b"]}}
            ],
        }
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")

    def test_entries_the_copy_step_cannot_read_are_refused(self):
        """Each passed validation and crashed do_standalone_copies after the
        download: a list for detect, no file nor pattern, a list for emulator."""
        for entry in (
            {"note": "hi", "detect": ["/x"]},
            {"emulator": "pcsx2", "targets": {"linux": ["/tmp"]}},
            {"file": "bios/x.bin", "emulator": ["a"], "targets": {"linux": ["/tmp"]}},
        ):
            manifest = {"manifest_version": 2, "platform": "retroarch", "files": [],
                        "standalone_copies": [entry]}
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")

    def test_plain_absolute_target_still_works(self):
        manifest = {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [],
            "standalone_copies": [
                {"file": "boot.bin", "targets": {"linux": ["~/.config/emu/bios"]}}
            ],
        }
        self.assertIsInstance(install._validate_manifest(manifest, "retroarch"), dict)

    def test_symlinked_destination_is_not_written_through(self):
        """A link at the name was skipped in silence and counted as "dir
        not found" while the folder existed: the emulator kept whatever the
        link pointed at. The link now gives way to the file."""
        bios = scratch_dir(self)
        (bios / "boot.bin").write_text("rom")
        target = scratch_dir(self)
        outside = scratch_dir(self) / "secret"
        outside.write_text("untouched")
        (target / "boot.bin").symlink_to(outside)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            copied, skipped, failed = install.do_standalone_copies(
                self._manifest(str(target)), bios, "linux"
            )
        self.assertEqual((copied, skipped, failed), (1, 0, 0))
        self.assertEqual(outside.read_text(), "untouched")
        self.assertFalse((target / "boot.bin").is_symlink())
        self.assertEqual((target / "boot.bin").read_text(), "rom")
        self.assertIn("link replaced", out.getvalue())
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["boot.bin"])


@unittest.skipUnless(shutil.which("pwsh"), "pwsh not available")
class TestDestinationFollowsUserLinks(unittest.TestCase):
    """EmuDeck links bios/shadps4/sys_modules into shadPS4's own directory.

    The manifest still cannot climb out of the BIOS root, but a link the
    user's frontend placed under it is where the emulator reads the file.
    """

    def test_symlinked_directory_under_root_is_followed(self):
        bios = scratch_dir(self)
        elsewhere = scratch_dir(self) / "sys_modules"
        elsewhere.mkdir()
        (bios / "shadps4").mkdir()
        (bios / "shadps4" / "sys_modules").symlink_to(elsewhere)

        dest = install._destination_path(bios, "shadps4/sys_modules/libSceLibcInternal.sprx")

        self.assertEqual(dest, bios.resolve() / "shadps4" / "sys_modules" / "libSceLibcInternal.sprx")
        self.assertEqual(dest.resolve().parent, elsewhere.resolve())

    def test_check_local_survives_a_linked_directory(self):
        bios = scratch_dir(self)
        elsewhere = scratch_dir(self) / "sys_modules"
        elsewhere.mkdir()
        (bios / "shadps4").mkdir()
        (bios / "shadps4" / "sys_modules").symlink_to(elsewhere)
        entry = {"dest": "shadps4/sys_modules/x.sprx", "size": 1, "sha1": "0" * 40}

        to_download, up_to_date, mismatched = install.check_local([entry], bios)

        self.assertEqual([e["dest"] for e in to_download], ["shadps4/sys_modules/x.sprx"])
        self.assertEqual((up_to_date, mismatched), ([], []))

    def test_climbing_is_still_refused(self):
        bios = scratch_dir(self)
        with self.assertRaises(ValueError):
            install._destination_path(bios, "../outside.bin")
        with self.assertRaises(ValueError):
            install._destination_path(bios, "/etc/passwd")


class StandaloneCopiesReachFlatpakInstalls(unittest.TestCase):
    """Copies went only to native and AppImage directories: Dolphin, PPSSPP
    and Azahar from Flathub received nothing. Azahar's native Linux
    directory was wrong too: XDG_DATA_HOME/azahar-emu (common_paths.h
    EMU_DATA_DIR), not azahar."""

    def test_flatpak_and_native_directories(self):
        import yaml

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        linux = {
            target
            for entry in registry["_standalone_copies"]
            for target in (entry.get("targets") or {}).get("linux", [])
        }
        for expected in (
            "$HOME/.var/app/org.DolphinEmu.dolphin-emu/data/dolphin-emu/GC/USA",
            "$HOME/.var/app/org.ppsspp.PPSSPP/config/ppsspp/PSP/SYSTEM",
            "$HOME/.var/app/org.azahar_emu.Azahar/data/azahar-emu/sysdata",
            "$HOME/.local/share/azahar-emu/sysdata",
        ):
            with self.subTest(target=expected):
                self.assertIn(expected, linux)
        self.assertNotIn("$HOME/.local/share/azahar/sysdata", linux)


class ARefusedStandaloneCopyIsNamed(unittest.TestCase):
    """A standalone copy refused by a read-only emulator folder counted as
    an error with no failures entry: the summary named no file, pointed at
    the BIOS folder and gave no advice."""

    def test_the_file_and_its_folder_reach_the_summary(self):
        import contextlib

        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("a read-only folder needs POSIX modes and a non-root user")
        bios = scratch_dir(self)
        (bios / "scph5501.bin").write_bytes(b"x")
        target = scratch_dir(self) / "pcsx2-bios"
        target.mkdir()
        target.chmod(0o500)
        self.addCleanup(target.chmod, 0o700)
        manifest = {"files": [{"dest": "scph5501.bin"}], "standalone_copies": [
            {"file": "scph5501.bin", "emulator": "pcsx2",
             "targets": {"linux": [str(target)]}},
        ]}
        failures: list = []
        with contextlib.redirect_stdout(io.StringIO()):
            _copied, _skipped, failed = install.do_standalone_copies(
                manifest, bios, "linux", None, failures)
        self.assertEqual(failed, 1)
        self.assertEqual(failures, [(str(target / "scph5501.bin"), install.NOT_WRITABLE)])

        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            install._report_outcome([bios], 0, 1, failed, 0, False,
                                    details=install.OutcomeDetails(failures=failures))
        text = out.getvalue()
        self.assertIn(str(target / "scph5501.bin"), text)
        self.assertIn(str(target), text.split("BIOS folder")[-1])
        self.assertIn("cannot write there", text)


class OneEmulatorsFilesInOneCommand(unittest.TestCase):
    """An emulator page offers one command for that emulator's files.
    --core kept the platform's whole list, and narrowing to cores kept the
    platform files of every system no core is mapped to."""

    MANIFEST = {
        "system_cores": {"ibm-pc": ["pcem"], "nintendo-nes": ["fceumm"]},
        "core_names": {"pcem": ["pcem"], "fceumm": ["fceumm"]},
        "files": [],
    }

    def test_only_its_files_and_its_systems(self):
        import contextlib

        files = [
            {"dest": "pcem/ibmpc.bin", "cores": ["pcem"], "systems": ["ibm-pc"]},
            {"dest": "disksys.rom", "cores": None, "systems": ["nintendo-nes"]},
            {"dest": "ep128emu/exos.rom", "cores": None, "systems": ["enterprise"]},
            {"dest": "ibm.rom", "cores": None, "systems": ["ibm-pc"]},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            _chosen, kept, _omitted = install._narrow_to_emulators(
                ["PCem"], self.MANIFEST, "retroarch", files, [])
        self.assertEqual(sorted(e["dest"] for e in kept), ["ibm.rom", "pcem/ibmpc.bin"])

    def test_an_unknown_name_is_refused(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            install._narrow_to_emulators(["nope"], self.MANIFEST, "retroarch", [], [])


class StandaloneCopiesUnderTheirOwnName(unittest.TestCase):
    """melonDS reads dsisd.bin and xemu eeprom.bin, names the platforms
    give dsi_sd_card.bin and xbox_eeprom.bin: a copy says the name the
    emulator reads."""

    def test_the_copy_takes_the_emulator_name(self):
        bios = scratch_dir(self)
        (bios / "xbox_eeprom.bin").write_bytes(b"eeprom")
        folder = scratch_dir(self)
        manifest = {"files": [{"dest": "xbox_eeprom.bin"}], "standalone_copies": [
            {"file": "xbox_eeprom.bin", "as": "eeprom.bin", "targets": {"linux": [str(folder)]}}]}
        install._validate_manifest(
            {**self._published(), "standalone_copies": manifest["standalone_copies"]}, "emudeck")
        self.assertEqual(install.do_standalone_copies(manifest, bios, "linux"), (1, 0, 0))
        self.assertEqual((folder / "eeprom.bin").read_bytes(), b"eeprom")
        self.assertFalse((folder / "xbox_eeprom.bin").exists())
        plan = install.standalone_plan(
            [{"files": [{"dest": "xbox_eeprom.bin", "sha1": "0" * 40, "size": 6}],
              **manifest}], "linux")
        self.assertEqual([entry["dest"] for entry in plan[0][1]], ["eeprom.bin"])

    def _published(self) -> dict:
        return json.loads((REPO_ROOT / "install" / "emudeck.json").read_text())

    def test_a_name_that_climbs_is_refused(self):
        for name in ("../eeprom.bin", "a/eeprom.bin", "", 3):
            with self.subTest(name=name), \
                    self.assertRaisesRegex(ValueError, "standalone copy name|\\.as"):
                install._validate_manifest({**self._published(), "standalone_copies": [
                    {"file": "x.bin", "as": name, "targets": {}}]}, "emudeck")

    def test_cemu_alone_is_found_from_the_published_list(self):
        home = scratch_dir(self)
        (home / ".local" / "share" / "Cemu").mkdir(parents=True)
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        with unittest.mock.patch.dict(os.environ, {"HOME": str(home)}):
            plan = dict(install.standalone_plan([manifest], "linux"))
        names = {entry["dest"] for entry in plan[home / ".local" / "share" / "Cemu"]}
        self.assertLessEqual({"keys.txt", "otp.bin", "seeprom.bin"}, names)


class EveryStandaloneCopyNamesItsMacFolder(unittest.TestCase):
    """--standalone-copies copied Azahar's keys and Flycast's boot ROM on
    Linux and Windows and silently skipped them on macOS, where both
    emulators read a fixed Application Support folder."""

    def test_each_copy_has_a_darwin_target(self):
        import yaml

        registry = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / "platforms" / "_registry.yml").read_text()
        )
        missing = [
            entry.get("file") or entry.get("pattern")
            for entry in registry["_standalone_copies"]
            if entry.get("targets") and "darwin" not in entry["targets"]
        ]
        self.assertEqual(missing, [])


class StandaloneFoldersAreNamedWhenThereAreAny(unittest.TestCase, _LoopbackRun):
    """'Standalone copies skipped' closed every install, on a machine with
    no standalone emulator as on one whose DuckStation lacked its BIOS."""

    def setUp(self):
        self.env = self.serve(self)

    def _run(self) -> str:
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "system"), "--system", "atari-lynx",
                            "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def test_nothing_is_said_without_an_emulator_folder(self):
        out = self._run()
        self.assertNotIn("skipped", out)
        self.assertNotIn("--standalone-copies", out)

    def test_a_found_folder_is_named(self):
        duckstation = self.home / ".local" / "share" / "duckstation" / "bios"
        duckstation.mkdir(parents=True)
        out = self._run()
        self.assertIn("Standalone emulator folders found here:", out)
        self.assertIn(str(duckstation), out)
        self.assertIn("--standalone-copies", out)


class StandaloneCopiesAreChecked(unittest.TestCase, _LoopbackRun):
    """--check and --dry-run with --standalone-copies said nothing of the
    emulator folders: the flag was taken and never applied."""

    def setUp(self) -> None:
        self.env = self.serve(self)
        self.duckstation = self.home / ".local" / "share" / "duckstation" / "bios"
        self.duckstation.mkdir(parents=True)

    def _run(self, *argv: str) -> subprocess.CompletedProcess:
        return _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "system"), "--system", "sony-playstation",
                            "--standalone-copies", "--no-input", *argv)

    def test_check_names_what_the_folder_lacks(self):
        proc = self._run("--check")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("Standalone emulators:", proc.stdout)
        self.assertIn(f"{self.duckstation}:", proc.stdout)
        self.assertIn("missing: scph1001.bin", proc.stdout)

    def test_dry_run_plans_the_copies(self):
        proc = self._run("--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(f"{self.duckstation}:", proc.stdout)
        self.assertEqual(list(self.duckstation.iterdir()), [])


class StandaloneEmulatorsWithoutAPlatformAreServed(unittest.TestCase, _LoopbackRun):
    """ES-DE with DuckStation and PCSX2 and no RetroArch: the run said 'No
    supported platform detected' and offered RetroArch's folder, which no
    emulator on the machine reads."""

    def setUp(self):
        self.env = self.serve(self)
        (self.home / "ES-DE").mkdir()
        self.duckstation = self.home / ".local" / "share" / "duckstation" / "bios"
        self.duckstation.mkdir(parents=True)

    def test_the_emulator_folder_is_filled(self):
        proc = _install_run(self.env, "--no-input", "--dry-run")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Found standalone emulator folders:", proc.stdout)
        self.assertIn(f"to {self.duckstation}:", proc.stdout)
        self.assertNotIn("--platform retroarch --dest", proc.stdout)
        proc = _install_run(self.env, "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        names = sorted(path.name for path in self.duckstation.iterdir())
        self.assertIn("scph5501.bin", names)
        # Every image the DuckStation profile places in its bios folder,
        # its PS2 and OpenBIOS images included, and nothing else.
        import yaml

        profile = yaml.safe_load((REPO_ROOT / "emulators" / "duckstation.yml").read_text())
        named = {PurePosixPath(entry["standalone_path"]).name
                 for entry in profile["files"] if entry.get("standalone_path")}
        self.assertEqual([name for name in names
                          if name not in named and not name.startswith("scph")], [])
        proc = _install_run(self.env, "--no-input", "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Every file on the list is in place.", proc.stdout)

    def test_the_run_ends_on_its_summary(self):
        """--check --events gave code 3 and only start, detect and end: no
        summary, so no pending, installed or failed to read."""
        proc = _install_run(self.env, "--no-input", "--check", "--events")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()
                  if line.startswith("{")]
        summary = [event for event in events if event["event"] == "summary"]
        self.assertEqual(len(summary), 1, events)
        self.assertEqual(summary[0]["mode"], "check")
        self.assertGreater(summary[0]["pending"], 0)
        self.assertEqual(events[-1], {"event": "end", "code": 3})
        proc = _install_run(self.env, "--no-input", "--events")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        events = [json.loads(line) for line in proc.stdout.splitlines()
                  if line.startswith("{")]
        summary = [event for event in events if event["event"] == "summary"]
        self.assertEqual(len(summary), 1, events)
        self.assertGreater(summary[0]["installed"], 0)
        self.assertEqual(summary[0]["pending"], 0)

    def test_no_emulator_folder_keeps_the_hint(self):
        self.duckstation.rmdir()
        proc = _install_run(self.env, "--no-input")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("--platform retroarch --dest", proc.stdout)


class TheEmulatorNamesHaveTheirOwnListing(unittest.TestCase, _LoopbackRun):
    """--emulator nope said "--list-cores lists all 441" and --list-cores
    printed 189: the buildbot names --emulator accepts were listed nowhere."""

    def setUp(self):
        self.env = self.serve(self)

    def test_the_hint_counts_what_the_listing_prints(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--no-input",
                            "--emulator", "nope")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        found = re.search(r"--list-emulators lists all (\d+)\.", proc.stderr)
        self.assertIsNotNone(found, proc.stderr)
        listing = _install_run(self.env, "--platform", "retroarch", "--no-input",
                               "--list-emulators")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        names = [re.split(r"\s{2,}", line.strip())[0]
                 for line in listing.stdout.splitlines() if line.startswith("  ")]
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        accepted = install.emulator_names(
            manifest, manifest["files"], manifest.get("omitted_files", []))
        self.assertEqual(int(found.group(1)), len(accepted))
        self.assertTrue(set(accepted) <= set(names), set(accepted) - set(names))
        self.assertIn("mednafen_psx", accepted)
        self.assertRegex(listing.stdout, r"mednafen_psx\s+same as beetle_psx")

    def test_every_listed_name_is_accepted(self):
        manifest = {"core_names": {"beetle_psx": ["mednafen_psx"]}}
        files = [{"dest": "a", "cores": ["pcsx_rearmed"]}]
        names = install.emulator_names(manifest, files, [])
        self.assertEqual(names, {"beetle_psx": "beetle_psx", "mednafen_psx": "beetle_psx",
                                 "pcsx_rearmed": "pcsx_rearmed"})
        self.assertEqual(install.resolve_choices(["MEDNAFEN_PSX"], sorted(names), "emulator"),
                         ["mednafen_psx"])


if __name__ == "__main__":
    unittest.main()
