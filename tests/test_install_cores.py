"""The one-liner narrows to the cores a RetroArch already has.

RetroArch keeps its cores in libretro_directory, named the buildbot's way
(`mednafen_psx_libretro.so`), while a file in the manifest names the profile
that reads it (`beetle_psx`). The manifest maps one to the other and says
which cores keep each system, the rule a pack built for a target follows.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import io
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import install  # noqa: E402
from test_install_selection import FakeRepository  # noqa: E402


class CoreDirectories(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_the_config_detection_read_names_the_cores(self):
        cfg = self.tmp / "retroarch.cfg"
        cfg.write_text(
            f'system_directory = "{self.tmp / "sys"}"\n'
            f'libretro_directory = "{self.tmp / "my cores"}"\n'
        )
        system_dir = install._parse_retroarch_system_dir(cfg)
        self.assertEqual(
            install.core_dirs("retroarch", system_dir), [self.tmp / "my cores"]
        )

    def test_a_portable_layout_defaults_to_cores_beside_the_config(self):
        (self.tmp / "retroarch.cfg").write_text('libretro_directory = "default"\n')
        self.assertEqual(
            install.core_dirs("retroarch", self.tmp / "system"), [self.tmp / "cores"]
        )
        (self.tmp / "retroarch.cfg").write_text('video_driver = "gl"\n')
        self.assertEqual(
            install.core_dirs("retroarch", self.tmp / "system"), [self.tmp / "cores"]
        )

    def test_retropie_and_lakka_keep_their_own_folders(self):
        self.assertIn(
            Path("/opt/retropie/libretrocores"),
            install.core_dirs("retropie", self.tmp / "none"),
        )
        self.assertIn(Path("/storage/cores"), install.core_dirs("lakka", self.tmp / "none"))

    def test_core_files_of_every_system_and_retropie_folders(self):
        cores = self.tmp / "cores"
        (cores / "lr-fceumm").mkdir(parents=True)
        for name in (
            "mednafen_psx_libretro.so", "snes9x_libretro.dll",
            "mgba_libretro.dylib", "genesis_plus_gx_libretro_android.so",
            "lr-fceumm/fceumm_libretro.so", "mgba_libretro.info", "readme.txt",
        ):
            (cores / name).write_bytes(b"")
        self.assertEqual(
            install.installed_cores([cores, self.tmp / "missing"]),
            ["fceumm", "genesis_plus_gx", "mednafen_psx", "mgba", "snes9x"],
        )


MANIFEST = {
    "core_names": {"beetle_psx": ["mednafen_psx"]},
    "system_cores": {"sony-playstation": ["beetle_psx", "pcsx_rearmed"],
                     "nintendo-gba": ["mgba"]},
    "files": [
        {"dest": "scph5501.bin", "cores": None, "systems": ["sony-playstation"]},
        {"dest": "gba_bios.bin", "cores": None, "systems": ["nintendo-gba"]},
        {"dest": "unlisted.bin", "cores": None, "systems": ["arcade"]},
        {"dest": "psx/extra.bin", "cores": ["beetle_psx"], "systems": ["sony-playstation"]},
        {"dest": "mgba/extra.bin", "cores": ["mgba"], "systems": ["nintendo-gba"]},
    ],
    "omitted_files": [
        {"dest": "gone.bin", "cores": ["mgba"], "systems": ["nintendo-gba"]},
    ],
}


class NarrowToCores(unittest.TestCase):
    def test_a_buildbot_name_keeps_its_profile_and_its_systems(self):
        files, omitted = install.narrow_to_cores(MANIFEST, ["mednafen_psx"])
        self.assertEqual(
            [f["dest"] for f in files],
            ["scph5501.bin", "unlisted.bin", "psx/extra.bin"],
        )
        self.assertEqual(omitted, [])

    def test_an_older_list_keeps_the_platform_files(self):
        older = {k: v for k, v in MANIFEST.items() if k in ("files", "omitted_files")}
        files, _ = install.narrow_to_cores(older, ["mgba"])
        self.assertEqual(
            [f["dest"] for f in files],
            ["scph5501.bin", "gba_bios.bin", "unlisted.bin", "mgba/extra.bin"],
        )


class ACoreOnlyTheDownloaderBrings(unittest.TestCase):
    """Batocera builds amiberry standalone on every board, and only its
    x86_64 RetroArch downloads the amiberry core: both answer to amiberry
    in a board's core list. The builder reads the downloader's reach
    (resolve_platform_cores) and the list carries it in downloaded_cores."""

    MANIFEST = {
        "core_names": {"amiberry": [], "amiberry-7": ["amiberry"]},
        "downloaded_cores": {"amiberry": ["x86_64", "pc"]},
        "system_cores": {"commodore-amiga": ["amiberry", "amiberry-7"]},
        "files": [
            {"dest": "kick31.rom", "cores": ["amiberry-7"], "systems": ["commodore-amiga"]},
            {"dest": "roms/a4091.rom", "cores": ["amiberry"], "systems": ["commodore-amiga"]},
        ],
        "omitted_files": [],
    }

    def test_a_board_without_the_download_keeps_its_own_build(self):
        files, _ = install.narrow_to_cores(self.MANIFEST, ["amiberry"], target="bcm2711")
        self.assertEqual([f["dest"] for f in files], ["kick31.rom"])

    def test_a_board_or_its_alias_with_the_download_keeps_both(self):
        for target in ("x86_64", "pc"):
            with self.subTest(target=target):
                files, _ = install.narrow_to_cores(self.MANIFEST, ["amiberry"], target=target)
                self.assertEqual([f["dest"] for f in files], ["kick31.rom", "roms/a4091.rom"])

    def test_an_installed_core_is_no_board(self):
        files, _ = install.narrow_to_cores(self.MANIFEST, ["amiberry"])
        self.assertEqual([f["dest"] for f in files], ["kick31.rom", "roms/a4091.rom"])



class CoreOfferedOnSomeBoards(unittest.TestCase):
    """ROCKNIX writes uae4arm for roms/amiga under the devices it builds it
    for (emulators/package.mk:188), and s922x runs uae4arm for amigacd32:
    the core list alone would keep its roms/amiga files there."""

    MANIFEST = {
        "core_names": {"uae4arm": [], "puae": []},
        "offered_boards": {
            "uae4arm": [{"root": "roms", "folder": "amiga", "boards": ["h700", "rk3326"]}],
        },
        "files": [
            {"dest": "amiga/kick.rom", "cores": ["uae4arm"], "root": "roms"},
            {"dest": "amigacd32/kick.rom", "cores": ["uae4arm"], "root": "roms"},
            {"dest": "amiga/shared.rom", "cores": ["uae4arm", "puae"], "root": "roms"},
        ],
        "omitted_files": [],
    }

    def dests(self, target):
        files, _ = install.narrow_to_cores(self.MANIFEST, ["uae4arm"], target=target)
        return [f["dest"] for f in files]

    def test_a_board_it_is_offered_on_keeps_the_folder(self):
        self.assertEqual(self.dests("rk3326"),
                         ["amiga/kick.rom", "amigacd32/kick.rom", "amiga/shared.rom"])

    def test_another_board_keeps_only_the_folders_offering_it(self):
        self.assertEqual(self.dests("s922x"), ["amigacd32/kick.rom"])

    def test_a_core_offered_everywhere_keeps_a_shared_file(self):
        files, _ = install.narrow_to_cores(self.MANIFEST, ["uae4arm", "puae"], target="s922x")
        self.assertEqual([f["dest"] for f in files], ["amigacd32/kick.rom", "amiga/shared.rom"])

    def test_installed_cores_are_no_board(self):
        files, _ = install.narrow_to_cores(self.MANIFEST, ["uae4arm"])
        self.assertEqual(len(files), 3)

    def test_the_manifest_check_refuses_a_malformed_map(self):
        base = {"manifest_version": 2, "platform": "rocknix", "files": [], "omitted_files": []}
        install._validate_manifest(
            {**base, "offered_boards": self.MANIFEST["offered_boards"]}, "rocknix")
        with self.assertRaisesRegex(ValueError, "offered_boards"):
            install._validate_manifest(
                {**base, "offered_boards": {"uae4arm": [{"folder": "amiga"}]}}, "rocknix")

class ACoreTheListDoesNotKnow(unittest.TestCase):
    """A core newer than the list (parallel_dc, issue 87) loses nothing its .info declares."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_only_names_no_profile_answers_for(self):
        self.assertEqual(
            install.unknown_cores(MANIFEST, ["mednafen_psx", "pcsx_rearmed", "mgba",
                                             "parallel_dc"]),
            ["parallel_dc"],
        )

    def test_the_info_paths_retroarch_reads(self):
        (self.tmp / "parallel_dc_libretro.info").write_text(
            'firmware_count = 3\n'
            'firmware0_desc = "dc/dc_boot.bin (Dreamcast BIOS)"\n'
            'firmware0_path = "dc/dc_boot.bin"\n'
            'firmware1_path = dc\\naomi.zip\n'
            'firmware2 = "ignored.bin"\n'
        )
        self.assertEqual(
            install.info_firmware([self.tmp / "missing", self.tmp], "parallel_dc"),
            ["dc/dc_boot.bin", "dc/naomi.zip"],
        )
        self.assertIsNone(install.info_firmware([self.tmp], "odin"))

    def test_the_config_names_the_info_folder(self):
        (self.tmp / "retroarch.cfg").write_text('libretro_info_path = "default"\n')
        self.assertEqual(
            install.info_dirs("retroarch", self.tmp / "system", [self.tmp / "cores"]),
            [self.tmp / "info", self.tmp / "cores"],
        )

    def test_its_declared_files_survive_the_narrowing(self):
        files, _ = install.narrow_to_cores(
            MANIFEST, ["mednafen_psx"], declared_by_info=["GBA_BIOS.bin", "mgba/extra.bin"])
        self.assertEqual(
            [f["dest"] for f in files],
            ["scph5501.bin", "gba_bios.bin", "unlisted.bin", "psx/extra.bin",
             "mgba/extra.bin"],
        )


class TheBuildersOrder(unittest.TestCase):
    """RetroPie reads megaplay.zip as advancemame (copy A), mame (copy B),
    then mame2003 (copy A). Without advancemame the builder ships mame's
    copy, and merging mame2003 into the first copy gave it A."""

    ENTRY = {
        "dest": "megaplay.zip", "sha1": "a" * 40, "size": 1,
        "repo_path": "bios/a.zip", "cores": ["advancemame"], "systems": ["arcade"],
        "alternatives": [
            {"sha1": "b" * 40, "sha256": "", "size": 2, "repo_path": "bios/b.zip",
             "cores": ["mame"]},
            {"sha1": "a" * 40, "sha256": "", "size": 1, "repo_path": "bios/a.zip",
             "cores": ["mame2003"]},
        ],
    }

    def test_the_first_chosen_claim_wins(self):
        manifest = {"files": [self.ENTRY], "omitted_files": []}
        for names, sha in ((["mame", "mame2003"], "b"), (["mame2003"], "a"),
                           (["advancemame", "mame"], "a")):
            with self.subTest(names=names):
                files, _ = install.narrow_to_cores(manifest, names)
                self.assertEqual(files[0]["sha1"], sha * 40)
                self.assertNotIn("alternatives", files[0] if sha == "b" else {})

    def test_the_parity_covers_a_core_set(self):
        """A real build for mame and mame2003 on RetroPie, the shape
        --installed-cores produces there."""
        db_path = REPO_ROOT / "database.json"
        if not db_path.exists():
            self.skipTest("database.json is not built")
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack as gp
        from common import load_emulator_profiles

        db = json.loads(db_path.read_text(encoding="utf-8"))
        profiles = load_emulator_profiles(str(REPO_ROOT / "emulators"))

        def manifest(cores):
            return gp.generate_manifest(
                "retropie", str(REPO_ROOT / "platforms"), db, str(REPO_ROOT / "bios"),
                str(REPO_ROOT / "platforms" / "_registry.yml"),
                emulators_dir=str(REPO_ROOT / "emulators"), emu_profiles=profiles,
                target_cores=cores, offline=True,
            )

        names = ["mame", "mame2003"]
        files, _ = install.narrow_to_cores(manifest(None), names)
        built = manifest(set(names))
        self.assertEqual(
            {(f["dest"], f["sha1"]) for f in files},
            {(f["dest"], f["sha1"]) for f in built["files"]},
        )


class TheBoundaryBoundsAlternatives(unittest.TestCase):
    def _manifest(self, alternative: dict) -> dict:
        entry = {"dest": "a.bin", "sha1": "a" * 40, "size": 1,
                 "repo_path": "bios/a.bin", "cores": ["x"],
                 "alternatives": [alternative]}
        return {"manifest_version": 2, "platform": "retroarch", "files": [entry]}

    def test_an_alternative_carries_only_a_copy(self):
        good = {"sha1": "b" * 40, "size": 1, "repo_path": "bios/b.bin", "cores": ["y"]}
        install._validate_manifest(self._manifest(good), "retroarch")
        for extra in ({"dest": "../../evil"}, {"regions": 5}, {"cores": []},
                      {"repo_path": "../x"}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                install._validate_manifest(self._manifest({**good, **extra}), "retroarch")

    def test_the_cap_counts_the_largest_copy(self):
        big = {"sha1": "b" * 40, "size": install.MAX_DOWNLOAD_SIZE,
               "repo_path": "bios/b.bin", "cores": ["y"]}
        manifest = self._manifest(big)
        manifest["files"] = [
            {**manifest["files"][0], "dest": f"f{i}.bin"} for i in range(70)
        ]
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")


class OneDigestRuleAtTheBoundary(unittest.TestCase):
    """install.py defined _SHA1_RE twice: the second, lowercase only,
    replaced the first everywhere, so an uppercase sha1 was refused where
    an uppercase sha256 passed. Every comparison reads the digest as
    hashlib writes it, so both refuse uppercase, data trees included."""

    def _manifest(self, **digests: str) -> dict:
        entry = {"dest": "a.bin", "size": 1, "repo_path": "bios/a.bin", **digests}
        return {"manifest_version": 2, "platform": "retroarch", "files": [entry]}

    def test_sha1_and_sha256_follow_the_same_rule(self):
        install._validate_manifest(self._manifest(sha1="a" * 40), "retroarch")
        install._validate_manifest(self._manifest(sha256="a" * 64), "retroarch")
        for digests in ({"sha1": "A" * 40}, {"sha256": "A" * 64}):
            with self.subTest(digests=digests), self.assertRaises(ValueError):
                install._validate_manifest(self._manifest(**digests), "retroarch")

    def test_one_definition_each(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        for name in ("_SHA1_RE", "_SHA256_RE"):
            self.assertEqual(source.count(f"\n{name} = "), 1, name)


class APlatformOmissionKeepsItsClaim(unittest.TestCase):
    """A file the platform declares and a core reads, absent from the
    collection, was recorded under the core alone: RetroPie's dsi_nand.bin
    went to melonds, and a target without melonds lost the omission its
    pack reports for nintendo-ds."""

    OMISSION = {
        "dest": "dsi_nand.bin", "name": "dsi_nand.bin", "system": "nintendo-ds",
        "required": True, "reason": "not_found", "cores": None,
        "systems": ["nintendo-ds", "nintendo-dsi"], "declared_in": ["nintendo-ds"],
        "alternatives": [{"cores": ["melonds"]}],
    }
    MANIFEST = {
        "files": [], "omitted_files": [OMISSION],
        "core_names": {"melonds": ["melonds"], "desmume": ["desmume"]},
        "system_cores": {"nintendo-ds": ["desmume"], "nintendo-dsi": ["melonds"]},
    }

    def test_the_declaring_system_keeps_it(self):
        _, omitted = install.narrow_to_cores(self.MANIFEST, ["desmume"])
        self.assertEqual(omitted, [self.OMISSION])

    def test_a_dropped_system_falls_to_the_claiming_core(self):
        _, omitted = install.narrow_to_cores(self.MANIFEST, ["melonds"])
        self.assertEqual([o["cores"] for o in omitted], [["melonds"]])
        _, omitted = install.narrow_to_cores(self.MANIFEST, ["mgba"])
        self.assertEqual(omitted, [])

    def test_the_generator_files_the_core_behind_the_platform(self):
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import generate_pack as gp

        held = {"cores": None}
        self.assertTrue(gp._claim_platform_omission(held, "melonds"))
        self.assertTrue(gp._claim_platform_omission(held, "melonds"))
        self.assertEqual(held["alternatives"], [{"cores": ["melonds"]}])
        self.assertFalse(gp._claim_platform_omission({"cores": ["x"]}, "melonds"))
        self.assertFalse(gp._claim_platform_omission(None, "melonds"))

    def test_the_boundary_takes_only_core_names(self):
        manifest = {"manifest_version": 2, "platform": "retroarch", "files": [],
                    "omitted_files": [self.OMISSION]}
        install._validate_manifest(manifest, "retroarch")
        for claims in ([{"cores": []}], [{"cores": ["x"], "sha1": "a" * 40}],
                       ["melonds"], [5], {"cores": ["x"]}):
            bad = {**self.OMISSION, "alternatives": claims}
            with self.subTest(claims=claims), self.assertRaises(ValueError):
                install._validate_manifest(
                    {**manifest, "omitted_files": [bad]}, "retroarch"
                )


class APlatformFileSettledByCoresAndSystems(unittest.TestCase):
    """RetroArch's dsi_bios9.bin ships melonds' copy where melonds runs. On
    a target without it the pack serves the platform's answer, and the
    pinned nintendo-dsi declaration gives way to the bare nintendo-ds one
    once its system drops. The installer kept melonds' copy on rpi4."""

    def copy(self, letter: str) -> dict:
        return {"sha1": letter * 40, "size": 1, "repo_path": f"bios/{letter}.bin"}

    def manifest(self) -> dict:
        entry = {
            "dest": "dsi_bios9.bin", **self.copy("a"), "cores": None,
            "systems": ["nintendo-ds", "nintendo-dsi"],
            "slot_choices": [{"cores": ["desmume"]}, {**self.copy("a"), "cores": ["melonds"]}],
            "declared_choices": [
                {**self.copy("c"), "systems": ["nintendo-dsi"]},
                {**self.copy("b"), "systems": ["nintendo-ds"]},
            ],
        }
        return {
            "manifest_version": 2, "platform": "retroarch",
            "files": [entry], "omitted_files": [],
            "core_names": {},
            "system_cores": {"nintendo-ds": ["desmume", "melonds", "nds"],
                             "nintendo-dsi": ["melonds", "dsi"]},
        }

    def served(self, names: list[str]) -> str:
        files, _ = install.narrow_to_cores(self.manifest(), names)
        self.assertEqual(len(files), 1)
        self.assertNotIn("declared_choices", files[0])
        return files[0]["sha1"][0]

    def test_the_first_chosen_core_decides(self):
        self.assertEqual(self.served(["melonds"]), "a")

    def test_a_core_agreeing_with_the_platform_leaves_its_answer(self):
        self.assertEqual(self.served(["desmume", "melonds"]), "c")
        self.assertEqual(self.served(["desmume"]), "b")

    def test_the_remaining_system_answers_without_the_cores(self):
        self.assertEqual(self.served(["dsi"]), "c")
        self.assertEqual(self.served(["nds"]), "b")

    def test_declared_only_keeps_the_declaration_whose_system_remains(self):
        """--declared-only settled the slot on the first declaration before
        the cores narrowed it: on a target without melonds it checked the
        nintendo-dsi copy, the platform the nintendo-ds one."""
        manifest = self.manifest()
        for names, letter in ((["nds"], "b"), (["dsi"], "c"), (["melonds"], "c"),
                              (["desmume"], "b")):
            with self.subTest(names=names):
                files, omitted = install.keep_declared(manifest["files"], [])
                files, _ = install.narrow_to_cores(manifest, names, files, omitted)
                self.assertEqual(files[0]["sha1"][0], letter)

    def test_the_declared_event_judges_the_copy_the_platform_checks(self):
        """melonds' copy is served at the slot, the platform checks its own:
        the event and a --declared-only check give the same answer."""
        import hashlib

        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, tmp, True)
        payloads = {letter: letter.encode() * 3 for letter in "abc"}
        manifest = self.manifest()
        entry = manifest["files"][0]

        def real(copy: dict, letter: str) -> None:
            copy.update(sha1=hashlib.sha1(payloads[letter]).hexdigest(),
                        sha256=hashlib.sha256(payloads[letter]).hexdigest(), size=3)

        real(entry, "a")
        real(entry["slot_choices"][1], "a")
        real(entry["declared_choices"][0], "c")
        real(entry["declared_choices"][1], "b")
        (tmp / "dsi_bios9.bin").write_bytes(payloads["c"])

        def declared_event(files: list[dict]) -> dict:
            _todo, fine, wrong = install.check_local(files, tmp)
            with mock.patch.object(install.EVENTS, "emit") as emit:
                install._emit_check("retroarch", manifest, tmp, files, fine, wrong, 0, 0)
            return next(call.kwargs for call in emit.call_args_list
                        if call.args[0] == "declared")

        for names in (None, ["melonds"], ["desmume", "melonds"]):
            with self.subTest(names=names):
                served = manifest["files"]
                own, _ = install.keep_declared(manifest["files"], [])
                if names is not None:
                    served, _ = install.narrow_to_cores(manifest, names)
                    own, _ = install.narrow_to_cores(manifest, names, own, [])
                self.assertEqual(declared_event(served), declared_event(own))
                self.assertEqual(declared_event(own)["present"], 1)

    def test_the_boundary_checks_every_copy(self):
        install._validate_manifest(self.manifest(), "retroarch")
        bad_choices = (
            [{"cores": []}],
            [{"cores": ["x"], "repo_path": "../x", "sha1": "a" * 40, "size": 1}],
            [{"cores": ["x"], "dest": "../evil"}],
        )
        for choices in bad_choices:
            manifest = self.manifest()
            manifest["files"][0]["slot_choices"] = choices
            with self.subTest(choices=choices), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")
        for declared in ([], [self.copy("c")], [{**self.copy("c"), "systems": []}],
                         [{**self.copy("c"), "systems": ["s"], "cores": ["x"]}]):
            manifest = self.manifest()
            manifest["files"][0]["declared_choices"] = declared
            with self.subTest(declared=declared), self.assertRaises(ValueError):
                install._validate_manifest(manifest, "retroarch")
        manifest = self.manifest()
        del manifest["files"][0]["declared_choices"]
        with self.assertRaises(ValueError):
            install._validate_manifest(manifest, "retroarch")


class RefusedBeforeAnyInstall(unittest.TestCase):
    def test_a_platform_shipping_its_cores_stops_the_run_first(self):
        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, tmp, True)
        detected = [("retroarch", tmp / "system"), ("batocera", tmp / "bios")]
        (tmp / "retroarch.cfg").write_text("")
        (tmp / "cores").mkdir()
        (tmp / "cores" / "mgba_libretro.so").write_bytes(b"")
        # Two setups found stop a run without questions before either is
        # read: the refusal is checked with Batocera
        # named, and with both found nothing is fetched either.
        for argv, said in (
                (["--platform", "batocera", "--dest", str(tmp / "bios")],
                 "batocera ships its cores"),
                ([], "2 setups were found here")):
            with self.subTest(argv=argv), \
                    mock.patch.object(install, "detect_os", return_value="linux"), \
                    mock.patch.object(install, "detect_frontends", return_value=[]), \
                    mock.patch.object(install, "detect_platforms", return_value=detected), \
                    mock.patch.object(install, "_mounted_cards", return_value=[]), \
                    mock.patch.object(install, "fetch_manifest") as fetch, \
                    mock.patch.object(sys, "argv", ["install.py", "--installed-cores",
                                                    "--no-input", *argv]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as stop:
                    install.main()
                self.assertEqual(stop.exception.code, 1)
                self.assertIn(said, err.getvalue())
                fetch.assert_not_called()


class AnUnknownTargetStopsTheRunFirst(unittest.TestCase):
    """EmuDeck installed 3.2 GB, then steamos was refused for RetroArch and
    the run ended without a summary."""

    def test_nothing_is_fetched_when_one_platform_lacks_the_target(self):
        tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, tmp, True)
        detected = [("emudeck", tmp / "bios"), ("retroarch", tmp / "system")]
        lists = {"emudeck": {"steamos": {"cores": []}}, "retroarch": {"x86_64": {"cores": []}}}
        # Listed for both platforms: a listing reads every list found.
        with mock.patch.object(install, "detect_os", return_value="linux"), \
                mock.patch.object(install, "detect_frontends", return_value=[]), \
                mock.patch.object(install, "detect_platforms", return_value=detected), \
                mock.patch.object(install, "fetch_targets", side_effect=lists.get), \
                mock.patch.object(install, "fetch_manifest") as fetch, \
                mock.patch.object(sys, "argv", ["install.py", "--target", "steamos",
                                                "--list-systems", "--no-input"]), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as stop:
                install.main()
        self.assertEqual(stop.exception.code, 2)
        self.assertIn("unknown target 'steamos' for RetroArch", err.getvalue())
        self.assertIn("Nothing was installed", err.getvalue())
        fetch.assert_not_called()


class APlatformWithoutTargetsSaysSo(unittest.TestCase):
    """`--target switch` on MiSTer FPGA read "unknown target", a typo to the
    user, when no value can work there."""

    def test_the_way_forward_is_named(self):
        with contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            install._unknown_target("switch", "misterfpga", {})
        said = err.getvalue()
        self.assertIn("MiSTer FPGA has no hardware targets: run again without --target.", said)
        self.assertNotIn("unknown target", said)


class _CoreRepository(FakeRepository):
    """The fake repository with the two maps and a portable RetroArch."""

    def __enter__(self):
        super().__enter__()
        path = self.root / "install" / "retroarch.json"
        manifest = json.loads(path.read_text())
        manifest["core_names"] = {"pcsx_rearmed": ["pcsx_rearmed_neon"]}
        manifest["system_cores"] = {
            "sony-playstation": ["pcsx_rearmed"], "nintendo-gba": ["mgba"],
        }
        path.write_text(json.dumps(manifest))
        (self.root / "retroarch.cfg").write_text('libretro_directory = ":/cores"\n')
        (self.root / "cores").mkdir()
        return self

    def install_core(self, name: str) -> None:
        (self.root / "cores" / f"{name}_libretro.so").write_bytes(b"")


class TheOneLinerReadsInstalledCores(unittest.TestCase):
    def test_only_what_the_installed_cores_read(self):
        with _CoreRepository() as repo:
            repo.install_core("pcsx_rearmed_neon")
            proc = repo.run("--installed-cores", "--verbose")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("1 core installed", proc.stdout)
            self.assertEqual(
                repo.installed(), ["pcsx/extra.bin", "scph5500.bin", "scph5501.bin"]
            )

    def test_a_core_the_list_does_not_know_keeps_its_info_files(self):
        with _CoreRepository() as repo:
            repo.install_core("pcsx_rearmed_neon")
            repo.install_core("newgba")
            (repo.root / "cores" / "newgba_libretro.info").write_text(
                'firmware0_path = "gba_bios.bin"\n')
            repo.install_core("noinfo")
            proc = repo.run("--installed-cores")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("newgba: a core this list does not know, 1 file its .info "
                          "declares kept", proc.stdout)
            self.assertIn("noinfo: a core this list does not know, with no .info",
                          proc.stdout)
            self.assertEqual(
                repo.installed(),
                ["gba_bios.bin", "pcsx/extra.bin", "scph5500.bin", "scph5501.bin"],
            )

    def test_no_core_found_is_an_error_not_everything(self):
        with _CoreRepository() as repo:
            proc = repo.run("--installed-cores")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("no installed core found", proc.stderr)
            self.assertEqual(repo.installed(), [])

    def test_an_older_file_list_is_refused(self):
        with FakeRepository() as repo:
            (repo.root / "retroarch.cfg").write_text("")
            (repo.root / "cores").mkdir()
            (repo.root / "cores" / "mgba_libretro.so").write_bytes(b"")
            proc = repo.run("--installed-cores")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("older release", proc.stderr)

    def test_a_platform_that_ships_its_cores_refuses_the_flag(self):
        with _CoreRepository() as repo:
            batocera = repo.root / "install" / "batocera.json"
            manifest = json.loads((repo.root / "install" / "retroarch.json").read_text())
            manifest["platform"] = "batocera"
            batocera.write_text(json.dumps(manifest))
            command = repo.command("--installed-cores")
            command[command.index("retroarch")] = "batocera"
            proc = subprocess.run(
                command, env=repo.env(), capture_output=True, text=True,
                timeout=60, check=False, stdin=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("ships its cores with the system", proc.stderr)


    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_the_prompt_offers_the_installed_cores(self):
        with _CoreRepository() as repo:
            repo.install_core("mgba")
            command = " ".join(shlex.quote(part) for part in repo.command())
            proc = subprocess.run(
                ["script", "-qec", command, "/dev/null"],
                input="i\n\n", env=repo.env(), capture_output=True,
                text=True, timeout=60, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("i) only what the installed cores read: 2 files", proc.stdout)
            self.assertRegex(proc.stdout, r"--platform retroarch --dest \S+ --installed-cores")
            self.assertEqual(repo.installed(), ["gba_bios.bin", "mgba/extra.bin"])


class TheInterfaceFindsTheCoresLineModeFinds(unittest.TestCase):
    """The interface names the BIOS folder with --dest, so its runs never
    read retroarch.cfg: "only installed cores" found none where line mode,
    detecting the same config, found them (macOS, Flatpak, any custom
    system_directory)."""

    def test_a_config_away_from_the_bios_folder(self):
        with _CoreRepository() as repo:
            (repo.root / "retroarch.cfg").unlink()
            home = repo.root / "home"
            config = home / ".config" / "retroarch"
            config.mkdir(parents=True)
            cores = repo.root / "elsewhere" / "my cores"
            cores.mkdir(parents=True)
            (cores / "mgba_libretro.so").write_bytes(b"")
            (config / "retroarch.cfg").write_text(
                f'system_directory = "{repo.dest}"\n'
                f'libretro_directory = "{cores}"\n')
            env = {**repo.env(), "HOME": str(home), "RETROBIOS_OS": "linux",
                   "XDG_CONFIG_HOME": str(home / ".config")}
            repo.dest.mkdir()
            found = []
            for given in ((), ("--dest", str(repo.dest))):
                command = [sys.executable, str(REPO_ROOT / "install.py"), "--platform",
                           "retroarch", *given, "--installed-cores", "--check", "--verbose"]
                proc = subprocess.run(command, env=env, capture_output=True, text=True,
                                      timeout=60, check=False, stdin=subprocess.DEVNULL)
                self.assertNotIn("no installed core found", proc.stderr)
                found.append([line for line in proc.stdout.splitlines()
                              if "core installed" in line or "Narrowed" in line])
            self.assertEqual(found[0], found[1])
            self.assertIn("  1 core installed", found[1])


if __name__ == "__main__":
    unittest.main()
