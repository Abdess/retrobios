"""install.py on Android, handhelds and cards: the device's own files name the system, its board and its version."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
import unittest.mock
import zipfile
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, _LoopbackRun, _install_run


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_devices")


class TestEmbeddedDetection(unittest.TestCase):
    """MiSTer is identified by the main binary at the SD card root."""

    def _detect_with(self, existing: set[str], os_id: str = ""):
        real_exists = install.Path.exists
        real_parse = install._parse_os_release

        def fake_exists(self):
            return str(self) in existing

        install.Path.exists = fake_exists
        install._parse_os_release = lambda: {"ID": os_id} if os_id else {}
        try:
            return install._detect_embedded()
        finally:
            install.Path.exists = real_exists
            install._parse_os_release = real_parse

    def test_mister_detected_from_main_binary(self):
        # A path rule of the registry, read by _detect_by_path.
        real_exists = install.Path.exists
        install.Path.exists = lambda self: str(self) == "/media/fat/MiSTer"
        try:
            found: list = []
            install._detect_by_path("linux", found)
        finally:
            install.Path.exists = real_exists
        self.assertEqual(found, [("misterfpga", Path("/media/fat/games"))])

    def test_rocknix_wins_over_path_probes(self):
        self.assertEqual(
            self._detect_with({"/media/fat/MiSTer"}, os_id="rocknix"),
            [("rocknix", Path("/storage/roms/bios"))],
        )

    def test_no_embedded_os_detected(self):
        self.assertEqual(self._detect_with(set()), [])


class TestAndroidDetection(unittest.TestCase):
    """Android reports itself as Linux, and RetroArch is the frontend there."""

    def setUp(self):
        self.saved = {
            key: os.environ.get(key)
            for key in ("ANDROID_ROOT", "ANDROID_DATA", "EXTERNAL_STORAGE", "RETROBIOS_OS")
        }
        for key in self.saved:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_runtime_variables_name_android(self):
        os.environ["ANDROID_ROOT"] = "/system"
        os.environ["ANDROID_DATA"] = "/data"
        self.assertTrue(install._is_android())

    def test_plain_linux_is_not_android(self):
        self.assertFalse(
            install._is_android() and not Path("/system/build.prop").exists()
        )

    def test_forced_os_accepts_android(self):
        os.environ["RETROBIOS_OS"] = "android"
        self.assertEqual(install.detect_os(), "android")

    def test_default_directory_found_without_a_config(self):
        storage = scratch_dir(self)
        (storage / "RetroArch" / "system").mkdir(parents=True)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._detect_android(),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_config_default_resolves_against_the_retroarch_root(self):
        storage = scratch_dir(self)
        files = storage / "Android" / "data" / "com.retroarch.aarch64" / "files"
        files.mkdir(parents=True)
        (files / "retroarch.cfg").write_text(
            'system_directory = "default"\n'
            'bundle_assets_extract_version_current = "1745000000"\n')
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._detect_android(),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_custom_system_directory_wins(self):
        storage = scratch_dir(self)
        files = storage / "Android" / "data" / "com.retroarch" / "files"
        files.mkdir(parents=True)
        custom = storage / "Emulation" / "bios"
        (files / "retroarch.cfg").write_text(f'system_directory = "{custom}"\n')
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(install._detect_android(), [("retroarch", custom)])
        shutil.rmtree(storage)

    def test_nothing_found_on_a_bare_device(self):
        storage = scratch_dir(self)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(install._detect_android(), [])
        shutil.rmtree(storage)

    def test_detect_platforms_routes_android(self):
        storage = scratch_dir(self)
        (storage / "RetroArch" / "system").mkdir(parents=True)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install.detect_platforms("android"),
            [("retroarch", storage / "RetroArch" / "system")],
        )
        shutil.rmtree(storage)

    def test_manual_hint_names_the_android_path(self):
        hint = "\n".join(install._manual_usage_hint("android"))
        self.assertIn("/storage/emulated/0/RetroArch/system", hint)

    def test_named_platform_falls_back_to_shared_storage(self):
        storage = scratch_dir(self)
        os.environ["EXTERNAL_STORAGE"] = str(storage)
        self.assertEqual(
            install._default_dest("android", "retroarch"),
            storage / "RetroArch" / "system",
        )
        self.assertEqual(
            install._default_dest("linux", "batocera"), Path("/userdata/bios")
        )
        shutil.rmtree(storage)

    def test_packages_match_the_published_flavors(self):
        self.assertEqual(
            install.ANDROID_RETROARCH_PACKAGES,
            ("com.retroarch.aarch64", "com.retroarch", "com.retroarch.ra32"),
        )


class TargetFlagIsAppliedOrRefused(unittest.TestCase):
    """A filter the installer cannot apply must stop it, not be ignored.

    An unknown target used to print a warning and then install every file:
    4 GB where the user asked for a subset. And the aliases the pack builder
    accepts -- switch, ps2, psp -- were absent from the published target
    manifests, so the documented word was the one that failed.
    """

    def test_the_published_manifests_carry_the_builder_aliases(self):
        path = REPO_ROOT / "install" / "targets" / "retroarch.json"
        if not path.is_file():
            self.skipTest("no target manifest generated yet")
        targets = json.loads(path.read_text())
        self.assertIn("nintendo-switch", targets)
        for alias in ("switch", "nx"):
            with self.subTest(alias=alias):
                self.assertIn(alias, targets, f"builder accepts --target {alias}")
                self.assertEqual(targets[alias], targets["nintendo-switch"])

    def test_every_alias_resolves_to_its_canonical_core_list(self):
        from model.targets import load_target_config

        for name in ("install/targets/retroarch.json",):
            path = REPO_ROOT / name
            if not path.is_file():
                self.skipTest(f"{name} not generated yet")
            targets = json.loads(path.read_text())
            for alias in ("switch", "ps2", "psp"):
                # An alias the builder accepts and the manifest lacks is a
                # documented word that fails on the installer's side.
                self.assertIn(alias, targets, f"builder accepts --target {alias}")
                with self.subTest(alias=alias):
                    resolved = load_target_config(
                        "retroarch", alias, str(REPO_ROOT / "platforms")
                    )
                    self.assertEqual(
                        sorted(targets[alias] or []),
                        sorted(resolved),
                        f"{alias} disagrees with what the builder resolves",
                    )

    def test_every_published_target_is_the_list_the_builder_resolves(self):
        """add_cores and remove_cores reach the installer, not only the builder.

        The published lists were the scraped ones, untouched by the
        overrides: Batocera x86_64 lacked citron and xenia, which the pack
        for that target ships, and carried the Amiga machine variants and
        the launchers the builder drops.

        Both ways: a target the builder knows and the installer lacks answers
        "unknown target" on one side only, and a published null left behind
        once the builder filters a target makes the installer serve every core.
        """
        from model.targets import list_available_targets, load_target_config

        platforms = str(REPO_ROOT / "platforms")
        sources = sorted(
            path.stem for path in (REPO_ROOT / "platforms" / "targets").glob("*.yml")
            if not path.name.startswith("_")
        )
        manifests = {
            path.stem: path for path in (REPO_ROOT / "install" / "targets").glob("*.json")
        }
        if not manifests:
            self.skipTest("no target manifest generated yet")
        self.assertEqual(sorted(manifests), sources)
        for platform in sources:
            targets = json.loads(manifests[platform].read_text())
            known = {
                name
                for target in list_available_targets(platform, platforms)
                for name in (target["name"], *target["aliases"])
            }
            with self.subTest(platform=platform):
                self.assertEqual(sorted(targets), sorted(known))
            for target, cores in targets.items():
                # A target that names its card images carries them beside.
                cores = cores["cores"] if isinstance(cores, dict) else cores
                with self.subTest(platform=platform, target=target):
                    resolved = load_target_config(platform, target, platforms)
                    self.assertEqual(cores, None if resolved is None else sorted(resolved))


class AndroidCitationsNameTheRelease(unittest.TestCase):
    """The Android detection cited platform_unix.c lines of a RetroArch
    revision nobody named, which no longer held the code they described."""

    def test_the_lines_are_those_of_v1_22_2(self):
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        for text in (install._detect_android.__doc__, page):
            self.assertIn("v1.22.2", text)
            self.assertIn("platform_unix.c:1670-1697", text.replace("\n    ", ""))
            self.assertNotIn("1327-1395", text)
            self.assertNotIn("2836-2851", text)


class AndroidRetroArchFolderFollowsItsBuild(unittest.TestCase):
    """The Google Play build of RetroArch builds its defaults under
    Android/data/<package>/files/RetroArch, the retroarch.com build under
    the shared storage root (RetroArch v1.22.2, MainMenuActivity.java:
    182-183), and both publish com.retroarch and com.retroarch.aarch64.
    Detection sent every build to <shared storage>/RetroArch/system."""

    PLAY_CODE = 1597175870
    SITE_CODE = 1745000000

    def _run(self, make):
        root = scratch_dir(self)
        app_data, storage = root / "data", root / "storage"
        app_data.mkdir()
        storage.mkdir()
        make(app_data, storage)
        try:
            with unittest.mock.patch.object(install, "ANDROID_APP_DATA", app_data), \
                    unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(storage)}):
                return storage, install._detect_android(), install.android_unreachable_folders()
        finally:
            for folder in root.rglob("*"):
                if folder.is_dir():
                    folder.chmod(0o755)

    @staticmethod
    def _install(app_data, storage, package, cfg=None, visible=True):
        (app_data / package).mkdir()
        if visible:
            files = storage / "Android" / "data" / package / "files"
            files.mkdir(parents=True)
            if cfg is not None:
                (files / "retroarch.cfg").write_text(cfg)

    @staticmethod
    def _cfg(code, system="default"):
        return (f'system_directory = "{system}"\n'
                f'bundle_assets_extract_version_current = "{code}"\n')

    def test_google_play_build_reads_its_own_files(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch", self._cfg(self.PLAY_CODE)))
        folder = storage / "Android/data/com.retroarch/files/RetroArch/system"
        self.assertEqual(found, [("retroarch", folder)])
        self.assertEqual(lines, [])

    def test_retroarch_com_build_reads_shared_storage(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.aarch64", self._cfg(self.SITE_CODE)))
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])
        self.assertEqual(lines, [])

    def test_ra32_has_no_google_play_build(self):
        storage, found, _lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.ra32", 'system_directory = "default"\n'))
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])

    def test_play_plus_folder_seen_without_a_config(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch.aarch64")
            (storage / "Android/data/com.retroarch.aarch64/files/RetroArch").mkdir()
        storage, found, _lines = self._run(make)
        self.assertEqual(found, [(
            "retroarch",
            storage / "Android/data/com.retroarch.aarch64/files/RetroArch/system")])

    def test_play_folder_out_of_reach_is_named(self):
        if os.geteuid() == 0:
            self.skipTest("root writes any folder")

        def make(data, storage):
            self._install(data, storage, "com.retroarch", self._cfg(self.PLAY_CODE))
            (storage / "Android/data/com.retroarch/files").chmod(0o555)
        storage, found, lines = self._run(make)
        self.assertEqual(found, [])
        self.assertEqual(len(lines), 1)
        self.assertIn("RetroArch (Google Play build, com.retroarch) is installed", lines[0])
        self.assertIn(str(storage / "Android/data/com.retroarch/files/RetroArch/system"),
                      lines[0])

    def test_hidden_private_data_and_shared_folder_mean_retroarch_com(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch", visible=False)
            (storage / "RetroArch").mkdir()
        storage, found, lines = self._run(make)
        self.assertEqual(found, [("retroarch", storage / "RetroArch/system")])
        self.assertEqual(lines, [])

    def test_undecided_build_names_both_folders(self):
        storage, found, lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch.aarch64", visible=False))
        self.assertEqual(found, [])
        self.assertEqual(len(lines), 1)
        self.assertIn(
            str(storage / "Android/data/com.retroarch.aarch64/files/RetroArch/system"),
            lines[0])
        self.assertIn(str(storage / "RetroArch/system"), lines[0])

    def test_named_folder_needs_no_build(self):
        storage, found, _lines = self._run(lambda data, storage: self._install(
            data, storage, "com.retroarch", f'system_directory = "{storage}/bios"\n'))
        self.assertEqual(found, [("retroarch", storage / "bios")])

    def test_each_installed_build_is_found(self):
        def make(data, storage):
            self._install(data, storage, "com.retroarch", self._cfg(self.PLAY_CODE))
            self._install(data, storage, "com.retroarch.ra32", self._cfg(self.SITE_CODE))
        storage, found, _lines = self._run(make)
        self.assertEqual(found, [
            ("retroarch", storage / "Android/data/com.retroarch/files/RetroArch/system"),
            ("retroarch", storage / "RetroArch/system"),
        ])

    def test_detection_prints_the_retroarch_line(self):
        err = io.StringIO()
        root = scratch_dir(self)
        (root / "data" / "com.retroarch").mkdir(parents=True)
        with unittest.mock.patch.object(install, "ANDROID_APP_DATA", root / "data"), \
                unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(root / "s")}), \
                contextlib.redirect_stderr(err):
            install.detect_platforms("android")
        self.assertIn("RetroArch (com.retroarch) is installed", err.getvalue())


class AndroidEmulatorsOutOfReachAreSaid(unittest.TestCase):
    """DraStic keeps its BIOS in its private data and Flycast in
    Android/data, which Termux cannot write on Android 11 and later: both
    were skipped without a word."""

    def _lines(self, make) -> list[str]:
        root = scratch_dir(self)
        app_data, storage = root / "data", root / "storage"
        app_data.mkdir()
        make(app_data, storage)
        with unittest.mock.patch.object(install, "ANDROID_APP_DATA", app_data), \
                unittest.mock.patch.dict(os.environ, {"EXTERNAL_STORAGE": str(storage)}):
            return install.android_unreachable_folders()

    def test_nothing_installed_says_nothing(self):
        self.assertEqual(self._lines(lambda data, storage: None), [])

    def test_an_installed_drastic_is_named(self):
        lines = self._lines(lambda data, storage: (data / "com.dsemu.drastic").mkdir())
        self.assertEqual(len(lines), 1)
        self.assertIn("DraStic is installed", lines[0])
        self.assertIn("nds_bios_arm7.bin", lines[0])

    def test_flycast_out_of_reach_is_named(self):
        lines = self._lines(lambda data, storage: (data / "com.flycast.emulator").mkdir())
        self.assertEqual(len(lines), 1)
        self.assertIn("Flycast is installed", lines[0])
        self.assertIn("dc_boot.bin", lines[0])

    def test_a_writable_flycast_folder_is_a_copy_target(self):
        def make(data, storage):
            (data / "com.flycast.emulator").mkdir()
            (storage / "Android/data/com.flycast.emulator/files/data").mkdir(parents=True)
        self.assertEqual(self._lines(make), [])
        import yaml

        registry = yaml.safe_load((REPO_ROOT / "platforms" / "_registry.yml").read_text())
        copies = {entry.get("file"): entry for entry in registry["_standalone_copies"]}
        self.assertEqual(copies["dc/dc_boot.bin"]["targets"]["android"],
                         ["$EXTERNAL_STORAGE/Android/data/com.flycast.emulator/files/data"])

    def test_detection_prints_them(self):
        err = io.StringIO()
        with unittest.mock.patch.object(install, "_detect_android", return_value=[]), \
                unittest.mock.patch.object(install, "android_unreachable_folders",
                                           return_value=["DraStic is installed, but"]), \
                contextlib.redirect_stderr(err):
            install.detect_platforms("android")
        self.assertIn("DraStic is installed", err.getvalue())


class ACardPreparedOnAComputerGetsItsBoard(unittest.TestCase):
    """A Batocera RPi4 card prepared on a PC took every board's files (8.9 GB
    where bcm2711 reads 5.8): the board was read only on the device, and
    only without --dest, which the full-screen interface always gives."""

    def setUp(self):
        self.root = scratch_dir(self)
        self.boot = self.root / "BATOCERA"
        (self.boot / "boot").mkdir(parents=True)
        (self.boot / "boot" / "batocera.board").write_text("bcm2711\n")
        self.share = self.root / "SHARE"
        (self.share / "system").mkdir(parents=True)
        (self.share / "system" / "batocera.conf").write_text("system.hostname=BATOCERA\n")
        lists = self.root / "lists"
        (lists / "targets").mkdir(parents=True)
        one, two = b"pi core file", b"pc core file"
        self.list = lists / "batocera.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "batocera", "base_destination": "bios",
            "files": [
                {"dest": "pi.bin", "sha1": hashlib.sha1(one).hexdigest(), "size": len(one),
                 "repo_path": "bios/pi.bin", "cores": ["picore"], "systems": ["pi"]},
                {"dest": "pc.bin", "sha1": hashlib.sha1(two).hexdigest(), "size": len(two),
                 "repo_path": "bios/pc.bin", "cores": ["pccore"], "systems": ["pc"]},
            ],
            "system_cores": {"pi": ["picore"], "pc": ["pccore"]},
        }))
        (lists / "targets" / "batocera.json").write_text(
            json.dumps({"bcm2711": ["picore"], "x86_64": ["pccore"]}))

    def run_main(self, *extra: str) -> tuple[str, list[dict]]:
        # A child process: main() changes the run's globals (the file list,
        # the event stream), which leaked into the next tests.
        code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "import install; card = Path(sys.argv[2]); "
                "install._mounted_cards = lambda: [card]; "
                "sys.argv = ['install.py', *sys.argv[3:]]; install.main()")
        env = {**os.environ, "RETROBIOS_OS": "linux", "HOME": str(self.root)}
        proc = subprocess.run(
            [sys.executable, "-c", code, str(REPO_ROOT), str(self.boot),
             "--platform", "batocera", "--dest", str(self.share), "--manifest",
             str(self.list), "--offline", "--check", "--events", *extra],
            env=env, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, check=False)
        events = [json.loads(line) for line in proc.stdout.splitlines()
                  if line.startswith("{")]
        return proc.stdout + proc.stderr, events

    def test_the_boot_partition_names_the_board(self):
        with unittest.mock.patch.object(install, "_mounted_cards", return_value=[self.boot]):
            self.assertEqual(install.card_board("batocera"), "bcm2711")
            self.assertIsNone(install.card_board("retroarch"))

    def test_the_run_keeps_that_boards_files(self):
        _out, events = self.run_main()
        [board] = [event for event in events if event["event"] == "board"]
        self.assertEqual((board["board"], board["applied"]), ("bcm2711", True))
        self.assertIn("found on the card", board["message"])
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin"})

    def test_a_card_naming_its_image_gets_the_board_of_that_image(self):
        """A Batocera RG35XX Plus card names anbernic-rg35xx-plus, a zen3 one
        x86-64-v3: neither is a target name, and the card took every
        board's files (9.0 GB where h700 reads 6.1)."""
        (self.boot / "boot" / "batocera.board").write_text("anbernic-rg35xx-plus\n")
        (self.list.parent / "targets" / "batocera.json").write_text(json.dumps({
            "h700": {"cores": ["picore"], "images": ["anbernic-rg28xx",
                                                    "anbernic-rg35xx-plus"]},
            "x86_64": ["pccore"]}))
        out, events = self.run_main()
        [board] = [event for event in events if event["event"] == "board"]
        self.assertEqual((board["board"], board["applied"]), ("h700", True))
        self.assertIn("Board h700 (anbernic-rg35xx-plus) found on the card", out)
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin"})

    def test_an_image_two_boards_build_names_neither(self):
        targets = install._validate_targets({
            "zen3": {"cores": ["a"], "images": ["x86-64-v3"]},
            "rk3326": {"cores": ["b"], "images": ["r36s"]},
            "rk3566": {"cores": ["c"], "images": ["r36s"]}})
        self.assertEqual(install.board_target("x86-64-v3", targets), "zen3")
        self.assertEqual(install.board_target("zen3", targets), "zen3")
        self.assertIsNone(install.board_target("r36s", targets))

    def test_a_knulli_card_names_its_image_too(self):
        (self.boot / "boot" / "knulli.board").write_text("rg35xx-plus\n")
        with unittest.mock.patch.object(install, "_mounted_cards", return_value=[self.boot]):
            self.assertEqual(install.card_board("knulli"), "rg35xx-plus")
        published = json.loads((REPO_ROOT / "install" / "targets" / "knulli.json").read_text())
        self.assertEqual(install.board_target(
            "rg35xx-plus", install._validate_targets(published)), "h700")
        batocera = install._validate_targets(json.loads(
            (REPO_ROOT / "install" / "targets" / "batocera.json").read_text()))
        for image, board in (("anbernic-rg35xx-plus", "h700"), ("x86-64-v3", "zen3"),
                             ("odroidn2", "s922x"), ("bcm2711", "bcm2711")):
            self.assertEqual(install.board_target(image, batocera), board)

    def test_every_board_keeps_them_all(self):
        _out, events = self.run_main("--every-board")
        self.assertFalse([event for event in events if event["event"] == "board"])
        files = {event["dest"] for event in events if event["event"] == "file"}
        self.assertEqual(files, {"pi.bin", "pc.bin"})

    def test_the_plan_says_it(self):
        state = install.TuiState()
        state.run = "check"
        install._take_event(state, {"event": "board", "platform": "batocera",
                                  "board": "bcm2711", "applied": True,
                                  "message": "Board bcm2711 found on the card (x)"})
        self.assertEqual(state.board, "Board bcm2711 found on the card (x)")


class APlatformWithoutTargetsSaysSoOffline(unittest.TestCase):
    """Offline, --target on AmberELEC asked for install/targets/amberelec.json,
    which existed nowhere: online the same run said it had no targets.
    MiSTer FPGA has none still."""

    def test_the_list_matches_the_published_targets(self):
        published = {path.stem for path in (REPO_ROOT / "install" / "targets").glob("*.json")}
        self.assertEqual(install.TARGET_PLATFORMS, published)

    def test_offline_says_there_are_no_targets(self):
        dest = scratch_dir(self)
        for extra in ([], ["--manifest", str(REPO_ROOT / "install" / "misterfpga.json")]):
            with self.subTest(manifest=bool(extra)):
                proc = subprocess.run(
                    [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "misterfpga",
                     "--dest", str(dest), "--target", "de10-nano", "--offline", "--no-input",
                     "--dry-run", *extra],
                    capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, check=False)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("MiSTer FPGA has no hardware targets", proc.stderr)
                self.assertNotIn("targets/misterfpga.json", proc.stderr)


class TheBoardTheSystemNamesIsTheTarget(unittest.TestCase):
    """Batocera, Recalbox and ROCKNIX each write the board they were built
    for, but the installer read none of them, so a Batocera RPi4 installed
    every board's files (8.6 GiB where bcm2711 needs 5.5)."""

    def test_each_source_is_read(self):
        root = scratch_dir(self)
        arch = root / "batocera.arch"
        arch.write_text("bcm2711")
        with unittest.mock.patch.dict(install._BOARD_SOURCES, {"batocera": ("file", str(arch))}):
            self.assertEqual(install.detect_board("batocera"), "bcm2711")
        with unittest.mock.patch.object(install, "_parse_os_release",
                                        return_value={"HW_DEVICE": "RK3326"}):
            self.assertEqual(install.detect_board("rocknix"), "rk3326")
        self.assertIsNone(install.detect_board("retroarch"))

    def test_retropie_names_its_pi_as_get_platform_does(self):
        """A RetroPie Pi 4 installed every target's files, 8.4 GiB where
        rpi4 needs 4.0: nothing read the Pi model."""
        root = scratch_dir(self)
        (root / "proc" / "device-tree").mkdir(parents=True)
        cpuinfo = root / "proc" / "cpuinfo"
        tree = root / "proc" / "device-tree" / "compatible"
        cases = (
            ("Hardware\t: BCM2835\nRevision\t: c03114\n", None, "rpi4"),
            ("Revision\t: d04170\n", b"raspberrypi,5-model-b\0brcm,bcm2712\0", "rpi5"),
            ("Hardware\t: BCM2835\nRevision\t: a02082\n", None, "rpi3"),
            ("Hardware\t: BCM2835\nRevision\t: 000e\n", None, "rpi1"),
            ("Hardware\t: ODROIDC\n", None, None),
        )
        with unittest.mock.patch.object(install, "_SYSTEM_ROOT", root):
            # Not installed here: a computer preparing a Pi's card.
            cpuinfo.write_text(cases[0][0])
            self.assertIsNone(install.detect_board("retropie"))
            (root / "opt" / "retropie").mkdir(parents=True)
            for text, compatible, board in cases:
                with self.subTest(board=board, text=text):
                    cpuinfo.write_text(text)
                    if compatible is None:
                        tree.unlink(missing_ok=True)
                    else:
                        tree.write_bytes(compatible)
                    self.assertEqual(install.detect_board("retropie"), board)
            tree.unlink(missing_ok=True)
            cpuinfo.write_text("processor\t: 0\n")
            with unittest.mock.patch.object(install.platform, "machine",
                                            return_value="x86_64"):
                self.assertEqual(install.detect_board("retropie"), "x86_64")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "retropie.json")
                             .read_text(encoding="utf-8"))
        self.assertLessEqual({*install._RPI_MODELS.values(), "x86_64"}, set(targets))

    def test_amberelec_names_its_device(self):
        # An RG351P image carries no melonDS or bsnes, and the full list was
        # installed: AmberELEC had no target list to read the device against.
        with unittest.mock.patch.object(
            install, "_parse_os_release", return_value={"COREELEC_DEVICE": "RG351P"}
        ):
            self.assertEqual(install.detect_board("amberelec"), "rg351p")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "amberelec.json")
                             .read_text(encoding="utf-8"))
        self.assertIn("rg351p", targets)

    def test_emuelec_names_its_device(self):
        # An OdroidGoAdvance image carries no DuckStation, Dolphin or MAME
        # core, and the full list was installed: EmuELEC had no target list.
        with unittest.mock.patch.object(
            install, "_parse_os_release", return_value={"COREELEC_DEVICE": "OdroidGoAdvance"}
        ):
            self.assertEqual(install.detect_board("emuelec"), "odroidgoadvance")
        targets = json.loads((REPO_ROOT / "install" / "targets" / "emuelec.json")
                             .read_text(encoding="utf-8"))
        self.assertIn("odroidgoadvance", targets)
        self.assertNotIn("Duckstation", targets["odroidgoadvance"])

    def test_lakka_names_its_device_or_its_project(self):
        # An RPi4 Lakka installed 5.7 GB of every board's files: its board
        # was in os-release and never read.
        for release, board in (
            ({"LIBREELEC_PROJECT": "RPi", "LIBREELEC_DEVICE": "RPi4"}, "rpi4"),
            ({"LIBREELEC_PROJECT": "Generic"}, "generic"),
        ):
            with self.subTest(board=board), unittest.mock.patch.object(
                install, "_parse_os_release", return_value=release
            ):
                self.assertEqual(install.detect_board("lakka"), board)

    def test_every_board_and_target_are_refused_together(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--every-board",
             "--target", "bcm2711", "--platform", "batocera", "--dry-run"],
            capture_output=True, text=True, timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--every-board", result.stderr)

    def test_the_sources_name_our_target_lists(self):
        import yaml

        for platform in install._BOARD_SOURCES:
            with self.subTest(platform=platform):
                targets = yaml.safe_load(
                    (REPO_ROOT / "platforms" / "targets" / f"{platform}.yml").read_text()
                )["targets"]
                self.assertTrue(targets)


class TheBoardSystemsAreNamedFromTheCode(unittest.TestCase):
    """--help and the wiki named six systems whose board is read, while the
    code read eight: an AmberELEC user concluded --target was needed."""

    def test_help_and_wiki_name_every_one(self):
        names = [install.display_name(name) for name in install._BOARD_SOURCES]
        help_text = " ".join(install.build_parser().format_help().split())
        wiki = " ".join((REPO_ROOT / "wiki" / "installer.md").read_text().split())
        paragraph = wiki[:wiki.index("RetroPie reads the Pi model") + len("RetroPie")][-400:]
        for name in names:
            with self.subTest(name=name):
                self.assertIn(name, help_text[help_text.index("--target"):])
                self.assertIn(name, paragraph)


class RomMIsToldToScan(unittest.TestCase, _LoopbackRun):
    """RomM serves the firmware its library scan records, and the run ended
    on "installed" with no word of the scan the player waits on."""

    def test_the_end_of_an_install_names_the_scan(self):
        env = self.serve(self)
        dest = self.home / "library" / "bios"
        dest.mkdir(parents=True)
        proc = _install_run(env, "--platform", "romm", "--dest", str(dest),
                            "--system", "atari-lynx", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn(install.ROMM_SCAN_WORDS, " ".join(proc.stdout.split()))


def _device(test: unittest.TestCase, files: dict[str, str],
            release: str = "", home: str = "/root") -> Path:
    """A fake root holding these files, read by the embedded rules."""
    root = scratch_dir(test)
    if release:
        files = {**files, "/etc/os-release": release}
    for name, text in files.items():
        path = root / name.lstrip("/")
        if name.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for patcher in (
        unittest.mock.patch.object(install, "_SYSTEM_ROOT", root),
        unittest.mock.patch.dict(os.environ, {"HOME": home}),
        unittest.mock.patch.dict(install._RETROARCH_CONFIGS, clear=True),
        unittest.mock.patch.dict(install._DETECTED_OS, clear=True),
    ):
        patcher.start()
        test.addCleanup(patcher.stop)
    return root


class MuOsIsReadFromItsRetroArchConfig(unittest.TestCase):
    """muOS wrote to /mnt/mmc/MUOS/bios while RetroArch reads
    /run/muos/storage/bios, bound to the second card when it holds MUOS/bios,
    and --installed-cores found no core in /opt/muos/share/core."""

    USER = "/opt/muos/share/info/config/retroarch.cfg"
    DEFAULT = "/opt/muos/share/emulator/retroarch/retroarch.default.cfg"

    def _muos(self, files: dict[str, str]) -> Path:
        root = _device(self, {"/opt/muos/": "", **files})
        found = install._detect_embedded()
        self.assertEqual(len(found), 1)
        self.assertEqual(install.detected_os(*found[0]), "muOS")
        return root

    def test_the_users_config_decides(self):
        root = self._muos({
            self.USER: 'libretro_directory = "/opt/muos/share/core"\n'
                       'system_directory = "/mnt/sdcard/MUOS/bios"\n',
            self.DEFAULT: 'system_directory = "/run/muos/storage/bios"\n',
        })
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "mnt/sdcard/MUOS/bios")])
        self.assertIn(Path("/opt/muos/share/core"),
                      install.core_dirs("retroarch", root / "mnt/sdcard/MUOS/bios"))

    def test_before_the_first_launch_the_default_does(self):
        root = self._muos({self.DEFAULT: 'system_directory = "/run/muos/storage/bios"\n'})
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "run/muos/storage/bios")])

    def test_without_a_config_the_bound_folder_is_used(self):
        root = self._muos({})
        self.assertEqual(install._detect_embedded(),
                         [("retroarch", root / "run/muos/storage/bios")])


class HandheldSystemsByTheirOwnFiles(unittest.TestCase):
    """AmberELEC, EmuELEC, JELOS, ArkOS on a second card and a dozen other
    handheld systems were not detected, or got /roms/bios whatever their
    RetroArch read: each is found by what its own build writes, and its
    folder is the system_directory of its RetroArch config."""

    ELEC_CFG = "/storage/.config/retroarch/retroarch.cfg"
    ARK_CFG = "/home/ark/.config/retroarch/retroarch.cfg"
    TITLE = "/usr/share/plymouth/themes/text.plymouth"

    def _found(self, files: dict, release: str = "", home: str = "/root"):
        root = _device(self, files, release, home)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            found = install._detect_embedded()
        names = [install.detected_os(plat, path) for plat, path in found]
        return root, found, names, err.getvalue()

    def _one(self, files: dict, release: str = "", home: str = "/root"):
        root, found, names, _err = self._found(files, release, home)
        self.assertEqual(len(found), 1, found)
        return root, found[0], names[0]

    def _elec(self, release: str, name: str, extra: dict | None = None,
              plat: str = "retroarch", folder: str = "storage/roms/bios"):
        cfg = {self.ELEC_CFG: 'system_directory = "~/roms/bios"\n'}
        root, (found_plat, path), found_name = self._one({**cfg, **(extra or {})}, release)
        self.assertEqual((found_plat, path, found_name),
                         (plat, root / folder, name))

    # AmberELEC and EmuELEC publish their own lists, written against
    # /storage/roms (bios/, ports/ and neogeo/ side by side).
    def test_amberelec(self):
        self._elec('NAME="AmberELEC"\nID="coreelec"\n', "AmberELEC",
                   plat="amberelec", folder="storage/roms")

    def test_chaos_names_itself_amberelec(self):
        # tech4bot/AmberELEC writes the same os-release as AmberELEC.
        self._elec('NAME="AmberELEC"\nID="coreelec"\nCOREELEC_DEVICE="RG552"\n', "AmberELEC",
                   plat="amberelec", folder="storage/roms")

    def test_pan4elec_over_amberelec(self):
        self._elec('NAME="AmberELEC"\n', "PAN4ELEC",
                   {"/usr/bin/batocera-info": 'echo "OPERATING SYSTEM: PAN4ELEC"\n'},
                   plat="amberelec", folder="storage/roms")

    def test_emuelec(self):
        self._elec('NAME="EmuELEC"\nID="emuelec"\n', "EmuELEC",
                   plat="emuelec", folder="storage/roms")

    def test_jelos(self):
        self._elec('OS_NAME="JELOS"\nHW_DEVICE="RK3566"\n', "JELOS")

    def test_kolos_over_jelos(self):
        self._elec('OS_NAME="JELOS"\n', "KOLOS",
                   {"/usr/lib/systemd/system/jelos-ready.service":
                    "Description=KOLOS system ready script\n"})

    def test_unofficialos(self):
        self._elec('OS_NAME="UnofficialOS"\n', "UnofficialOS")

    def test_archr(self):
        self._elec('NAME="ArchR"\nID="archr"\nOS_NAME="ArchR"\n', "ArchR")

    def test_an_elec_config_moved_elsewhere_is_followed(self):
        root, (_plat, path), _name = self._one(
            {self.ELEC_CFG: 'system_directory = "/storage/roms2/bios"\n'}, 'OS_NAME="JELOS"\n')
        self.assertEqual(path, root / "storage/roms2/bios")

    def test_arkos_first_and_second_card(self):
        base = {"/home/ark/": "", "/opt/system/": "",
                self.TITLE: "[ubuntu-text]\ntitle=ArkOS 2.0 (02012025)-3\n"}
        for folder in ("/roms/bios", "/roms2/bios"):
            with self.subTest(folder=folder):
                root, found, name = self._one(
                    {**base, self.ARK_CFG: f'system_directory = "{folder}"\n'})
                self.assertEqual((found, name),
                                 (("retroarch", root / folder.lstrip("/")), "ArkOS"))

    def test_arkos_32_bit_config_when_the_64_bit_one_is_missing(self):
        root, found, _name = self._one({
            "/home/ark/": "", "/opt/system/": "",
            "/home/ark/.config/retroarch32/retroarch.cfg": 'system_directory = "/roms2/bios"\n',
        })
        self.assertEqual(found, ("retroarch", root / "roms2/bios"))

    def test_darkos_first_and_second_card(self):
        base = {"/home/ark/": "", "/opt/system/": "",
                self.TITLE: "title=dArkOS (05102026)\n"}
        for folder in ("/roms/bios", "/roms2/bios"):
            with self.subTest(folder=folder):
                root, found, name = self._one(
                    {**base, self.ARK_CFG: f'system_directory = "{folder}"\n'})
                self.assertEqual((found, name),
                                 (("retroarch", root / folder.lstrip("/")), "dArkOS"))

    def test_darkos_without_a_config(self):
        root, found, name = self._one({"/home/ark/": "", "/opt/system/": "",
                                       self.TITLE: "title=dArkOS (05102026)\n"})
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "dArkOS"))

    def test_retrooz(self):
        cfg = "/home/odroid/.config/retroarch32/retroarch.cfg"
        root, found, name = self._one({
            "/opt/.retrooz/version": "0.60\n", self.TITLE: "[ubuntu-text]\ntitle=RetroOZ\n",
            cfg: 'system_directory = "/roms/bios"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "RetroOZ"))
        root, found, name = self._one({"/etc/retrooz_version": "1\n"})
        self.assertEqual((found, name), (("retroarch", root / "roms/bios"), "RetroOZ"))

    def test_thera_is_not_detected(self):
        _root, found, _names, _err = self._found({self.TITLE: "title= *TheRA RC 1*\n"})
        self.assertEqual(found, [])

    def test_spruceos_on_a_trimui(self):
        root, found, name = self._one({
            "/usr/trimui/": "", "/mnt/SDCARD/spruce/": "",
            "/mnt/SDCARD/Saves/ra-configs/retroarch-Brick.cfg":
                'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "mnt/SDCARD/BIOS"), "spruceOS"))

    def test_crossmix_os(self):
        root, found, name = self._one({
            "/usr/trimui/": "", "/mnt/SDCARD/System/usr/trimui/crossmix-version.txt": "1.3\n",
            "/mnt/SDCARD/RetroArch/retroarch.cfg": 'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, name), (("retroarch", root / "mnt/SDCARD/BIOS"), "CrossMix-OS"))

    def _miyoo_mini(self, marker: str, name: str):
        root, found, found_name = self._one({
            marker: "x\n",
            "/mnt/SDCARD/RetroArch/.retroarch/retroarch.cfg":
                'system_directory = "/mnt/SDCARD/BIOS"\n',
        })
        self.assertEqual((found, found_name), (("retroarch", root / "mnt/SDCARD/BIOS"), name))

    def test_onion(self):
        self._miyoo_mini("/mnt/SDCARD/.tmp_update/onionVersion/version.txt", "Onion")

    def test_allium(self):
        self._miyoo_mini("/mnt/SDCARD/.allium/version.txt", "Allium")

    def test_koriki(self):
        self._miyoo_mini("/mnt/SDCARD/Koriki/version.txt", "Koriki")

    def test_miyoocfw_default_and_config(self):
        base = {"/etc/main": "export HOME=/mnt\n", "/usr/bin/miyooctl": ""}
        root, found, name = self._one(base)
        self.assertEqual((found, name),
                         (("retroarch", root / "mnt/.retroarch/system"), "MiyooCFW"))
        root, found, _name = self._one(
            {**base, "/mnt/.retroarch/retroarch.cfg": 'system_directory = "~/bios"\n'})
        self.assertEqual(found, ("retroarch", root / "mnt/bios"))

    def test_plumos(self):
        root, found, name = self._one({"/mnt/plumos-user/": ""}, 'NAME="plumOS"\nID=plumos\n')
        self.assertEqual((found, name), (("retroarch", root / "mnt/plumos-user/bios"), "plumOS"))
        _root, found, _names, err = self._found({}, 'NAME="plumOS"\nID=plumos\n')
        self.assertEqual(found, [])
        self.assertIn("plumOS found here", err)

    def test_trimui_stock_and_minui_are_named_not_installed_to(self):
        _root, found, _names, err = self._found({"/usr/trimui/": ""})
        self.assertEqual(found, [])
        self.assertIn("TrimUI found here", err)
        _root, found, _names, err = self._found(
            {"/usr/trimui/": "", "/mnt/SDCARD/.system/res/": ""})
        self.assertEqual(found, [])
        self.assertIn("MinUI found here", err)
        self.assertIn("--platform minui", err)
        self.assertIn("--dest", err)
        self.assertNotIn("TrimUI", err)

    def test_a_minui_card_on_its_device_gets_its_file_list(self):
        """--list-platforms said the MinUI layout was not written yet, while
        --from-pack and --dest wrote it: on the device the card root is the
        folder, and the card's version.txt names which of the three it is."""
        for release, plat, shown in (("MinUI-20251127-0", "minui", "MinUI"),
                                     ("NextUI-20250601-1", "nextui", "NextUI"),
                                     ("MyMinUI-20260809b-0", "myminui", "MyMinUI")):
            with self.subTest(release=release):
                root, found, name = self._one({
                    "/usr/trimui/": "", "/mnt/SDCARD/.system/res/": "",
                    "/mnt/SDCARD/.system/version.txt": release + "\n"})
                self.assertEqual((found, name), ((plat, root / "mnt/SDCARD"), shown))

    def test_the_listing_says_what_the_minui_family_gets(self):
        line = next(line for line in install._system_lines() if line.startswith("MinUI:"))
        self.assertNotIn("does not write", line)
        self.assertIn("minui, nextui or myminui", line)

    def test_two_unrelated_systems_are_refused(self):
        _root, found, names, _err = self._found(
            {"/mnt/SDCARD/Koriki/version.txt": "1\n"}, 'OS_NAME="JELOS"\n')
        self.assertEqual(names, ["JELOS", "Koriki"])
        self.assertEqual(install.os_conflict(found), ["JELOS", "Koriki"])
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--no-input"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stop:
            install.main()
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("JELOS and Koriki are both detected here", err.getvalue())
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--no-input", "--events"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=found), \
                unittest.mock.patch.object(install, "detect_frontends", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            install.main()
        errors = [event for event in map(json.loads, out.getvalue().splitlines())
                  if event["event"] == "error"]
        self.assertEqual([(e["stage"], e["reason"]) for e in errors], [("detect", "conflict")])

    def test_the_system_is_announced_by_its_own_name(self):
        root, found, _name = self._one({self.ELEC_CFG: ""}, 'OS_NAME="JELOS"\n')
        self.assertEqual(install.found_label(*found),
                         f"JELOS at {root / 'storage/roms/bios'} (RetroArch files)")

    def test_list_platforms_names_every_system(self):
        with unittest.mock.patch.object(sys, "argv", ["install.py", "--list-platforms"]), \
                unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch.object(install, "detect_platforms", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            install.main()
        for rule in install._EMBEDDED_RULES:
            self.assertIn(f"  {rule.name}: ", out.getvalue())


class BatoceraAndKnulliByWhatTheirBuildsWrite(unittest.TestCase):
    """No Batocera build writes /etc/batocera-version (batocera-system.mk
    writes /usr/share/batocera/batocera.version), and Knulli writes no
    /etc/knulli-release and removes /usr/share/batocera: neither was
    detected, and a Knulli board got every board's files without a word."""

    def _detect(self, release: dict, files: tuple[str, ...]):
        with unittest.mock.patch.object(install, "_parse_os_release", return_value=release), \
                unittest.mock.patch.object(Path, "exists", lambda p: str(p) in files):
            return install._detect_embedded()

    def test_batocera_by_its_version_file(self):
        self.assertEqual(self._detect({}, ("/usr/share/batocera/batocera.version",)),
                         [("batocera", Path("/userdata/bios"))])
        self.assertEqual(self._detect({}, ("/etc/batocera-version",)), [])

    def test_knulli_by_its_os_release_or_version_file(self):
        self.assertEqual(self._detect({"OS_NAME": "knulli"}, ()),
                         [("knulli", Path("/userdata/bios"))])
        self.assertEqual(self._detect({}, ("/usr/share/knulli/knulli.version",)),
                         [("knulli", Path("/userdata/bios"))])

    def test_amberelec_and_emuelec_by_their_os_release(self):
        """Both write os-release from DISTRONAME in scripts/image. AmberELEC
        keeps CoreELEC's ID, so its NAME tells it apart."""
        self.assertEqual(self._detect({"NAME": "AmberELEC", "ID": "coreelec"}, ()),
                         [("amberelec", Path("/storage/roms"))])
        self.assertEqual(self._detect({"NAME": "EmuELEC", "ID": "emuelec"}, ()),
                         [("emuelec", Path("/storage/roms"))])
        self.assertEqual(self._detect({"NAME": "CoreELEC", "ID": "coreelec"}, ()), [])

    def test_a_knulli_board_narrows_to_its_target(self):
        """KNULLI publishes a core list per board since 2026-11-05, and an
        H700 handheld still took every board's files (9.3 GB for 4.5)."""
        arch = scratch_dir(self) / "knulli.arch"
        targets = json.loads((REPO_ROOT / "install" / "targets" / "knulli.json")
                             .read_text(encoding="utf-8"))
        for written, board in (("h700", "h700"), ("rk3568", "rk3566"), ("unknown", None)):
            arch.write_text(written)
            with self.subTest(written=written), unittest.mock.patch.dict(
                    install._BOARD_SOURCES, {"knulli": ("file", str(arch))}):
                self.assertEqual(install.detect_board("knulli"), board)
                if board:
                    self.assertIn(board, targets)

    def test_a_batocera_zen3_board_narrows_to_its_target(self):
        """batocera.arch says x86-64-v3 on a zen3 image, which no target
        list names: the run installed the files of every board."""
        arch = scratch_dir(self) / "batocera.arch"
        arch.write_text("x86-64-v3")
        with unittest.mock.patch.dict(install._BOARD_SOURCES,
                                      {"batocera": ("file", str(arch))}):
            self.assertEqual(install.detect_board("batocera"), "zen3")

    def test_each_board_name_is_a_published_target(self):
        for plat, names in install._BOARD_NAMES.items():
            targets = json.loads((REPO_ROOT / "install" / "targets" / f"{plat}.json")
                                 .read_text(encoding="utf-8"))
            for written, board in names.items():
                with self.subTest(platform=plat, board=board):
                    self.assertIn(board, targets)
                    self.assertNotIn(written, targets)

    def test_the_run_says_why_every_board_is_installed(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        block = source[source.index("board = detect_board(plat_name)"):]
        block = block[:block.index("if target:")]
        self.assertIn("has no", block)


class RomMFirmwareFollowsItsTemplate(unittest.TestCase):
    """RomM 5.4 reads firmware where filesystem.structure.firmware says, and
    a {platform}/roms library is told to declare "{platform}/bios". The
    installer only wrote bios/<platform>/, where such a library lists none."""

    CONFIG = (
        "# RomM\n"
        "exclude:\n"
        "  platforms: []\n"
        "filesystem:\n"
        "  structure:\n"
        "    default: \"{platform}/roms/{game}\"\n"
        "    firmware: \"{platform}/bios\"  # as RomM suggests\n"
        "system:\n"
        "  firmware: elsewhere\n"
    )

    def _romm(self, config: str | None) -> Path:
        base = scratch_dir(self)
        library = base / "library"
        (library / "psx" / "roms").mkdir(parents=True)
        if config is not None:
            (base / "config").mkdir()
            (base / "config" / "config.yml").write_text(config)
        return library / "bios"

    def test_templates_parse_as_romm_parses_them(self):
        self.assertEqual(install.parse_romm_firmware("bios/{platform}"), (("bios",), ()))
        self.assertEqual(install.parse_romm_firmware("{platform}/bios"), ((), ("bios",)))
        self.assertEqual(install.parse_romm_firmware("/a/{platform}/b/c/"),
                         (("a",), ("b", "c")))
        for bad in ("", "bios", "{platform}/{game}", "{region}/{platform}",
                    "../{platform}", "{platform}/{platform}"):
            with self.subTest(template=bad), self.assertRaises(ValueError):
                install.parse_romm_firmware(bad)

    def test_the_template_is_read_from_config_yml(self):
        bios = self._romm(self.CONFIG)
        layout = install.romm_firmware_layout(bios, None)
        self.assertEqual(layout, ((), ("bios",)))
        files = [{"dest": "psx/scph5501.bin"}, {"dest": "3do/panafz1.bin"}]
        moved, root = install.romm_relayout(files, bios, *layout)
        self.assertEqual(root, bios.parent)
        self.assertEqual([f["dest"] for f in moved],
                         ["psx/bios/scph5501.bin", "3do/bios/panafz1.bin"])

    def test_the_default_keeps_the_pack_layout(self):
        bios = self._romm("filesystem:\n  structure:\n    firmware: bios/{platform}\n")
        files = [{"dest": "psx/scph5501.bin"}]
        self.assertEqual(install.romm_relayout(files, bios, *install.romm_firmware_layout(
            bios, None)), (files, bios))

    def test_a_platform_first_library_without_a_template_is_refused(self):
        bios = self._romm(None)
        with self.assertRaises(ValueError) as raised:
            install.romm_firmware_layout(bios, None)
        self.assertIn('--romm-firmware "{platform}/bios"', str(raised.exception))
        self.assertEqual(install.romm_firmware_layout(bios, "{platform}/bios"),
                         ((), ("bios",)))

    def test_the_option_is_refused_where_romm_is_not_installed(self):
        err = io.StringIO()
        with unittest.mock.patch.object(install, "detect_os", return_value="linux"), \
                unittest.mock.patch("sys.argv", [
                    "install.py", "--platform", "batocera", "--dest", str(scratch_dir(self)),
                    "--romm-firmware", "{platform}/bios", "--no-input"]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            install.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("--romm-firmware applies to RomM", err.getvalue())


class RomMFirmwareInstallsUnderItsTemplate(unittest.TestCase, _LoopbackRun):
    """The whole run, over loopback: config.yml beside the library decides."""

    def setUp(self):
        self.env = self.serve(self)

    def test_lynx_lands_in_its_platform_folder(self):
        base = self.home / "romm"
        (base / "library" / "lynx" / "roms").mkdir(parents=True)
        (base / "config").mkdir()
        (base / "config" / "config.yml").write_text(
            "filesystem:\n  structure:\n    default: \"{platform}/roms/{game}\"\n"
            "    firmware: \"{platform}/bios\"\n")
        proc = _install_run(self.env, "--platform", "romm", "--dest",
                            str(base / "library" / "bios"), "--system", "atari-lynx",
                            "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((base / "library" / "lynx" / "bios" / "lynxboot.img").is_file())
        self.assertFalse((base / "library" / "bios").exists())
        self.assertIn("{platform}/bios", proc.stdout)


class TheListVersionIsComparedWithTheSystems(unittest.TestCase):
    """The list says which version of the platform it was built for, and the
    installer reads the version the system runs from the file the system
    writes. A difference is said, never refused."""

    def note(self, plat: str, listed: str, bios: Path = Path("/userdata/bios")):
        return install.version_note(plat, bios, {"platform": plat, "version": listed})

    def test_batocera_reads_the_first_word_of_its_version_file(self):
        _device(self, {"/usr/share/batocera/batocera.version": "41 2025/01/17 10:12\n"})
        listed, installed, text = self.note("batocera", "43.1")
        self.assertEqual((listed, installed), ("43.1", "41"))
        self.assertEqual(
            text, "This list was built for Batocera 43.1, this machine runs 41. "
            "Batocera's own BIOS check reads the list of the version it runs, and "
            "may show some files as not matching it.")
        self.assertIsNone(self.note("batocera", "41"))

    def test_recalbox_reads_only_a_release(self):
        _device(self, {"/recalbox/recalbox.version": "10.0\n"})
        self.assertEqual(self.note("recalbox", "10.1.1")[:2], ("10.1.1", "10.0"))
        self.assertIsNone(self.note("recalbox", "10.0"))
        for built in ("development", "2026/10/01 main (4242)"):
            with self.subTest(built=built):
                _device(self, {"/recalbox/recalbox.version": built})
                self.assertIsNone(self.note("recalbox", "10.1.1"))

    def test_retrobat_reads_the_folder_beside_its_bios_folder(self):
        root = scratch_dir(self)
        version = root / "system" / "version.info"
        version.parent.mkdir()
        version.write_text("8.3.1.1-stable-win64")
        # The release tagged 8.3.1 ships 8.3.1.1.
        self.assertIsNone(self.note("retrobat", "8.3.1", root / "bios"))
        version.write_text("8.2.0-stable-win64")
        self.assertEqual(self.note("retrobat", "8.3.1", root / "bios")[:2],
                         ("8.3.1", "8.2.0"))

    def test_lakka_and_emuelec_read_os_release(self):
        _device(self, {}, release='NAME="Lakka"\nID="lakka"\nVERSION_ID="6.0"\n')
        listed, installed, text = self.note("lakka", "v6.1")
        self.assertEqual((listed, installed), ("v6.1", "6.0"))
        self.assertIn("Lakka checks only that a file is there", text)
        _device(self, {}, release='NAME="Lakka"\nID="lakka"\nVERSION_ID="6.1"\n')
        self.assertIsNone(self.note("lakka", "v6.1"))
        _device(self, {}, release='NAME="EmuELEC"\nVERSION_ID="4.7"\n')
        self.assertEqual(self.note("emuelec", "4.8")[:2], ("4.8", "4.7"))
        # The file of another system says nothing about this one.
        self.assertIsNone(self.note("lakka", "v6.1"))

    def test_an_unknown_version_says_nothing(self):
        _device(self, {"/usr/share/batocera/batocera.version": "41 2025/01/17 10:12"})
        self.assertIsNone(self.note("batocera", "1.0"))
        self.assertIsNone(install.version_note("batocera", Path("/userdata/bios"),
                                               {"platform": "batocera"}))
        self.assertIsNone(self.note("retroarch", "v1.22.2"))
        _device(self, {"/usr/share/knulli/knulli.version": "scarab 2026/05/11 10:00"})
        self.assertIsNone(self.note("knulli", "20260511"))
        _device(self, {})
        self.assertIsNone(self.note("batocera", "43.1"))
        _device(self, {"/usr/share/batocera/batocera.version": "\x1b[2J 2025/01/17"})
        self.assertIsNone(self.note("batocera", "43.1"))

    def test_a_pack_alone_gives_the_version_of_its_list(self):
        """A handheld without network installs from the pack: its manifest.json
        records the list's version, which generate_pack takes from the
        install list built with the same choices."""
        from packs import scope
        data = b"bios"
        install_list = {"version": "43.1", "files": [
            {"dest": "a.bin", "sha1": hashlib.sha1(data).hexdigest(), "size": 4}]}
        pack_list = {"files": [{"path": "a.bin", "sha1": hashlib.sha1(data).hexdigest(),
                                "size": 4}]}
        scope.annotate_pack_systems(pack_list, scope.pack_systems(install_list))
        self.assertEqual(pack_list["list_version"], "43.1")
        pack = scratch_dir(self) / "Batocera_43.1_BIOS_Pack.zip"
        with zipfile.ZipFile(pack, "w") as archive:
            archive.writestr("manifest.json", json.dumps(pack_list))
            archive.writestr("a.bin", data)
        source = install.PackSource([pack])
        self.addCleanup(source.close)
        self.assertEqual(source.manifest("batocera")["version"], "43.1")

    def test_the_result_repeats_it_in_every_ending(self):
        for kw in ({"downloaded": 3}, {"errors": 2}, {"downloaded": 1, "errors": 1}):
            with self.subTest(**kw):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
                    install._report_outcome([Path("/userdata/bios")], omitted=0,
                                            interrupted=False,
                                            details=install.OutcomeDetails(
                                                notes=["Built for 43.1."]),
                                            **{"downloaded": 0, "up_to_date": 0,
                                               "errors": 0, **kw})
                self.assertIn("Built for 43.1.", buf.getvalue())


class TheListVersionIsSaidBeforeAndAfter(unittest.TestCase):
    """A RetroBat folder holding 8.2.0 and a list built for 8.3.1, through
    the installer as a person and as the screen run it."""

    DATA = b"retrobat bios" * 8

    def setUp(self):
        self.root = scratch_dir(self)
        (self.root / "system").mkdir()
        (self.root / "system" / "version.info").write_text("8.2.0-stable-win64")
        self.bios = self.root / "bios"
        self.bios.mkdir()
        (self.bios / "a.bin").write_bytes(self.DATA)
        self.list = self.root / "retrobat.json"
        self.list.write_text(json.dumps({
            "manifest_version": 2, "platform": "retrobat", "version": "8.3.1",
            "files": [{"dest": "a.bin", "sha1": hashlib.sha1(self.DATA).hexdigest(),
                       "size": len(self.DATA), "repo_path": "bios/a.bin"}],
        }))

    def run_installer(self, *options: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--platform", "retrobat",
             "--dest", str(self.bios), "--manifest", str(self.list), "--offline",
             "--yes", *options],
            capture_output=True, text=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL,
        )

    SAID = ("This list was built for RetroBat 8.3.1, this machine runs 8.2.0. "
            "RetroBat's own BIOS check reads the list of the version it runs, and "
            "may show some files as not matching it.")

    def test_line_mode_says_it_before_the_install_and_with_the_result(self):
        proc = self.run_installer("--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout.count(self.SAID), 2, proc.stdout)
        self.assertLess(proc.stdout.index(self.SAID), proc.stdout.index("Checking existing"))
        self.assertGreater(proc.stdout.rindex(self.SAID), proc.stdout.index("Done."))

    def test_the_screen_reads_an_event(self):
        proc = self.run_installer("--check", "--events")
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        said = [event for event in events if event["event"] == "version"]
        self.assertEqual(said, [{"event": "version", "platform": "retrobat",
                                 "list_version": "8.3.1", "installed_version": "8.2.0",
                                 "message": self.SAID}])
        kinds = [event["event"] for event in events]
        self.assertLess(kinds.index("version"), kinds.index("check"))

    def test_the_same_version_says_nothing(self):
        (self.root / "system" / "version.info").write_text("8.3.1.1-stable-win64")
        proc = self.run_installer()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("This list was built for", proc.stdout)


if __name__ == "__main__":
    unittest.main()
