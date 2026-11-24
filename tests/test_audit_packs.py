"""Audit regressions on pack building: baseline verdicts, exclusions, regions, archives and downloads."""

from __future__ import annotations

import tests
from tests.sources import script_source
import ast
import contextlib
import hashlib
import io
import json
import os
import re
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock
import yaml
from scripts.resolve import regionaudit, regions
from scripts.packs.extraregions import _emulator_region_group
from scripts.packs.platformcheck import verify_pack_against_platform
from tests import REPO_ROOT


class APackIsSwappedInWhole(unittest.TestCase):
    """Packs were opened on their final name: a rebuild truncated the good
    pack at once, and a build that raised half way left a readable ZIP of
    part of the files, which the run then verified and summed."""

    def _dir(self) -> Path:
        import shutil
        import tempfile

        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def test_a_failed_build_keeps_the_previous_pack(self):
        import zipfile

        from packs.archive import writing_pack

        directory = self._dir()
        pack = directory / "Pack.zip"
        with zipfile.ZipFile(pack, "w") as zf:
            zf.writestr("old.bin", b"complete")
        with self.assertRaises(OSError), writing_pack(str(pack)) as zf:
            zf.writestr("new.bin", b"half")
            raise OSError("disk full")
        with zipfile.ZipFile(pack) as zf:
            self.assertEqual(zf.namelist(), ["old.bin"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["Pack.zip"])

    def test_a_finished_build_replaces_it(self):
        import zipfile

        from packs.archive import writing_pack

        directory = self._dir()
        pack = directory / "Pack.zip"
        pack.write_bytes(b"stale")
        with writing_pack(str(pack)) as zf:
            zf.writestr("new.bin", b"whole")
        with zipfile.ZipFile(pack) as zf:
            self.assertEqual(zf.namelist(), ["new.bin"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["Pack.zip"])

    def test_no_pack_is_opened_on_its_final_name(self):
        source = script_source("generate_pack.py")
        self.assertNotIn('ZipFile(zip_path, "w"', source)


class EverySharedGroupServesAPlatform(unittest.TestCase):
    """Six of the eight shared groups injected nothing: fuse, mt32 and
    jiffydos were included by no platform, and kronos, keropi and ep128emu
    repeated System.dat entry for entry. load_platform_config keeps the
    platform's own entry, so a hash corrected there changed no pack, no
    verify and no manifest, and nothing said so."""

    def test_each_group_contributes_an_entry_somewhere(self):
        from model.registry import list_registered_platforms
        from model.platforms import load_platform_config

        platforms_dir = str(REPO_ROOT / "platforms")
        with (REPO_ROOT / "platforms" / "_shared.yml").open(encoding="utf-8") as handle:
            groups = set((yaml.safe_load(handle) or {}).get("shared_groups") or {})
        served = {
            entry.get("shared_group")
            for name in list_registered_platforms(platforms_dir)
            for system in load_platform_config(name, platforms_dir).get("systems", {}).values()
            for entry in system.get("files", [])
        }
        self.assertEqual(sorted(groups - served), [])


class StandaloneCopiesNameTheirSource(unittest.TestCase):
    """The registry's anchor names one path per file for every platform,
    while each manifest places the file its own way, and the installer copied
    nothing where the two differed (EmuDeck's aes_keys.txt, Batocera's
    switch/prod.keys)."""

    def _placed(self, copies, dests):
        from packs.standalone import _placed_copies

        return _placed_copies(copies, dests)

    def test_a_path_tail_finds_the_file(self):
        (copy,) = self._placed(
            [{"file": "GC/USA/IPL.bin"}],
            ["dolphin-emu/Sys/GC/USA/IPL.bin", "dolphin-emu/Sys/GC/EUR/IPL.bin"],
        )
        self.assertEqual(copy["source"], "dolphin-emu/Sys/GC/USA/IPL.bin")

    def test_the_tail_with_least_on_top_wins(self):
        (copy,) = self._placed(
            [{"file": "GC/USA/IPL.bin"}],
            ["bios/GC/USA/IPL.bin", "bios/dolphin-emu/Sys/GC/USA/IPL.bin"],
        )
        self.assertEqual(copy["source"], "bios/GC/USA/IPL.bin")

    def test_a_unique_name_finds_the_file_elsewhere(self):
        (copy,) = self._placed(
            [{"file": "Citra/sysdata/aes_keys.txt"}], ["aes_keys.txt", "bios.bin"]
        )
        self.assertEqual(copy["source"], "aes_keys.txt")

    def test_an_ambiguous_or_present_file_is_left_as_written(self):
        copies = [{"file": "prod.keys"}, {"file": "IPL.bin"}]
        placed = self._placed(copies, ["prod.keys", "a/IPL.bin", "b/IPL.bin"])
        self.assertEqual(placed, copies)


class StandaloneCopiesComeFromTheProfiles(unittest.TestCase):
    """The copies were a hand-kept list of eight emulators while 61 profiles
    give their data_root with the code that builds it: a machine with only
    standalone Cemu got none of its keys."""

    CEMU = {
        "data_root": {
            "linux": {"path": "$XDG_DATA_HOME/Cemu, else ~/.local/share/Cemu",
                      "source_ref": "x"},
            "windows": {"path": "%APPDATA%/Cemu", "source_ref": "x"},
            "macos": {"path": "~/Library/Application Support/Cemu", "source_ref": "x"},
        },
        "files": [
            {"name": "keys.txt", "path": "Cemu/keys.txt", "standalone_path": "keys.txt"},
            {"name": "CafeCn.ttf", "path": "Cemu/mlc01/CafeCn.ttf",
             "standalone_path": "mlc01/sys/CafeCn.ttf"},
            {"name": "gone.bin", "path": "Cemu/gone.bin", "standalone_path": "gone.bin"},
            {"name": "core.bin", "path": "Cemu/core.bin", "standalone_path": "core.bin",
             "mode": "libretro"},
        ],
    }

    def _copies(self, profiles, dests, declared=()):
        from packs.standalone import _profile_copies

        return _profile_copies(profiles, dests, list(declared))

    def test_each_file_goes_under_the_data_root(self):
        copies = self._copies({"cemu": self.CEMU},
                              ["Cemu/keys.txt", "Cemu/mlc01/CafeCn.ttf", "Cemu/core.bin"])
        self.assertEqual(copies, [
            {"file": "Cemu/keys.txt", "targets": {
                "linux": ["$HOME/.local/share/Cemu"], "windows": ["%APPDATA%\\Cemu"],
                "darwin": ["$HOME/Library/Application Support/Cemu"]}},
            {"file": "Cemu/mlc01/CafeCn.ttf", "targets": {
                "linux": ["$HOME/.local/share/Cemu/mlc01/sys"],
                "windows": ["%APPDATA%\\Cemu\\mlc01\\sys"],
                "darwin": ["$HOME/Library/Application Support/Cemu/mlc01/sys"]}},
        ])

    def test_a_place_no_run_can_name_is_left_out(self):
        melonds = {
            "data_root": {
                "windows": {"path": "<folder of melonDS.exe>", "source_ref": "x"},
                "linux": {"path": "$XDG_CONFIG_HOME/melonDS, else ~/.config/melonDS",
                          "source_ref": "x"},
            },
            "files": [{"name": "dsi_sd_card.bin", "standalone_path": "dsisd.bin"}],
        }
        (copy,) = self._copies({"melonds": melonds}, ["dsi_sd_card.bin"])
        self.assertEqual(copy, {"file": "dsi_sd_card.bin",
                                "targets": {"linux": ["$HOME/.config/melonDS"]},
                                "as": "dsisd.bin"})

    def test_the_registry_keeps_what_it_already_names(self):
        declared = [{"pattern": "k*.txt", "targets": {"linux": ["$HOME/.local/share/Cemu"]}}]
        (copy, _font) = self._copies({"cemu": self.CEMU},
                                     ["Cemu/keys.txt", "Cemu/mlc01/CafeCn.ttf"], declared)
        self.assertNotIn("linux", copy["targets"])
        self.assertIn("windows", copy["targets"])

    def test_a_file_found_by_content_is_left_to_the_scan(self):
        amiberry = {
            "data_root": {"linux": {"path": "~/Amiberry", "source_ref": "x"}},
            "files": [{"name": "cd32fmv.rom", "path": "roms/cd32fmv.rom",
                       "standalone_path": "cd32fmv.rom", "found_by": "content"}],
        }
        self.assertEqual(self._copies({"amiberry": amiberry}, ["roms/cd32fmv.rom"]), [])

    def test_the_published_retroarch_list_reaches_cemu(self):
        import json

        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        files = {copy["file"]: copy for copy in manifest["standalone_copies"]
                 if "file" in copy}
        for name in ("Cemu/keys.txt", "Cemu/otp.bin", "Cemu/seeprom.bin"):
            with self.subTest(name=name):
                self.assertEqual(files[name]["targets"]["linux"], ["$HOME/.local/share/Cemu"])


class ADamagedArchiveIsNotPacked(unittest.TestCase):
    """A member whose bytes fail their CRC stops the build. The builder once
    copied the damaged archive into the pack "for verify to flag", which
    nothing did."""

    def test_the_rebuild_refusal_reaches_the_run(self):
        import zipfile

        from packs.archive import DamagedArchiveError, add_zip_to_pack

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "set.zip"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr("rom.bin", b"A" * 64)
            data = bytearray(source.read_bytes())
            data[data.index(b"A" * 64)] ^= 0xFF
            source.write_bytes(bytes(data))
            pack = Path(directory) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as target:
                with self.assertRaises(DamagedArchiveError) as caught:
                    add_zip_to_pack(str(source), "set.zip", target)
                self.assertNotIn("set.zip", target.namelist())
            self.assertIsInstance(caught.exception, OSError)
            self.assertIn("set.zip", str(caught.exception))


class APackedArchiveKeepsItsBytes(unittest.TestCase):
    """Packs rebuilt about 1,500 ZIPs in a fixed byte order while the install
    list kept the collection's hash: an extracted pack failed --check on each."""

    def test_the_member_is_the_source_byte_for_byte(self):
        import hashlib
        import zipfile

        from packs.archive import add_zip_to_pack

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "set.zip"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(zipfile.ZipInfo("rom.bin", (1999, 1, 2, 3, 4, 5)), b"rom" * 40)
            pack = Path(directory) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as target:
                add_zip_to_pack(str(source), "set.zip", target)
            with zipfile.ZipFile(pack) as packed:
                inner = packed.read("set.zip")
            self.assertEqual(hashlib.sha1(inner).hexdigest(),
                             hashlib.sha1(source.read_bytes()).hexdigest())


class OneBaselineVerdict(unittest.TestCase):
    """The builder and the manifest each wrote the platform baseline.

    The builder looked inside a zipped_file archive whatever the outer
    resolution said, the manifest only after a hash_mismatch. An archive
    found by name without the member Batocera checks left the pack and
    stayed in the manifest. A slot override replaced a release asset in the
    manifest and not in the pack.
    """

    def _archive(self, directory: Path, member: str) -> str:
        path = directory / "dragon32.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, b"rom")
        return str(path)

    def test_a_missing_member_is_refused_whatever_the_outer_status(self):
        from scripts.resolve.acceptance import baseline_verdict

        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom", "md5": ""}
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(Path(directory), "other.rom")
            status, refusal = baseline_verdict(entry, path, "name_exact", "md5")
            self.assertEqual(refusal, "d32.rom not found inside ZIP")
            # An existence frontend never opens it.
            self.assertEqual(
                baseline_verdict(entry, path, "name_exact", "existence"),
                ("name_exact", None),
            )

    def test_the_pack_check_reads_the_same_verdict(self):
        """--verify-packs called the archive missing: its own rule looked
        inside only after a hash_mismatch, and an archive found by name
        without d32.rom is one the builder left out on purpose."""
        import hashlib

        from scripts.packs.platformcheck import _intentional_hash_exclusion

        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom", "md5": ""}
        with tempfile.TemporaryDirectory() as directory:
            path = self._archive(Path(directory), "other.rom")
            sha1 = hashlib.sha1(Path(path).read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": path, "name": "dragon32.zip", "sha1": sha1}},
                  "indexes": {"by_name": {"dragon32.zip": [sha1]}, "by_md5": {},
                              "by_path_suffix": {}, "by_crc32": {}}}
            self.assertTrue(_intentional_hash_exclusion([entry], db, verification_mode="md5"))
            self.assertFalse(
                _intentional_hash_exclusion([entry], db, verification_mode="existence")
            )

    def test_the_builder_accepts_what_verify_accepts(self):
        """verify took a ZIP by its composite, but the builder compared exact
        md5s and refused it when another declared hash disagreed. A value cut
        short accepts nothing: Batocera compares the whole md5 string
        (batocera-systems:1088), and verify accepted any prefix, down to one
        digit."""
        import hashlib

        from scripts.core.hashing import md5_composite
        from scripts.resolve.acceptance import baseline_verdict, digest_verdict

        with tempfile.TemporaryDirectory() as directory:
            loose = Path(directory) / "abc.bin"
            loose.write_bytes(b"abc")
            md5 = hashlib.md5(b"abc").hexdigest()
            truncated = {"name": "abc.bin", "md5": md5[:29], "crc32": "deadbeef"}
            self.assertIsNotNone(
                baseline_verdict(truncated, str(loose), "hash_mismatch", "md5")[1]
            )
            for length in (1, 29, 31):
                self.assertFalse(
                    digest_verdict({"md5": md5[:length]}, 3, lambda: {"md5": md5}, "md5")
                )
            self.assertTrue(digest_verdict({"md5": md5}, 3, lambda: {"md5": md5}, "md5"))
            archive = self._archive(Path(directory), "rom.bin")
            composite = {"name": "dragon32.zip", "md5": md5_composite(archive),
                         "crc32": "deadbeef"}
            self.assertEqual(
                baseline_verdict(composite, archive, "hash_mismatch", "md5"),
                ("frontend_digest_exact", None),
            )

    def test_a_composite_only_archive_ignores_its_raw_md5(self):
        """Recalbox hashes a .zip by its members (Bios.cpp:64-68), and the
        pack check accepted the container's own md5 before the composite:
        neocd.bin shipped as neocdz.zip passed while Recalbox marks it red."""
        import hashlib

        from scripts.core.hashing import md5_composite
        from scripts.resolve.acceptance import digest_verdict

        with tempfile.TemporaryDirectory() as directory:
            archive = self._archive(Path(directory), "rom.bin")
            raw = hashlib.md5(Path(archive).read_bytes()).hexdigest()
            members = md5_composite(archive)
            for declared, accepted in ((raw, False), (members, True)):
                entry = {"name": "dragon32.zip", "md5": declared, "zip_digest": "composite"}
                with self.subTest(declared=declared):
                    self.assertIs(
                        digest_verdict(entry, 0, lambda: {"md5": raw}, "md5", "",
                                       lambda: members),
                        accepted,
                    )
            plain = {"name": "dragon32.zip", "md5": raw}
            self.assertTrue(digest_verdict(plain, 0, lambda: {"md5": raw}, "md5"))

    def test_a_release_asset_keeps_its_answer(self):
        from scripts.resolve.packfiles import apply_override

        self.assertEqual(
            apply_override("bios/x.bin", "/cache/big.bin", "release_asset"),
            ("/cache/big.bin", "release_asset"),
        )
        self.assertEqual(
            apply_override("bios/x.bin", "bios/y.bin", "name_exact"),
            ("bios/x.bin", "slot_arbitrated"),
        )

    def test_the_builder_and_the_manifest_read_the_same_rules(self):
        source = script_source("generate_pack.py")
        tree = ast.parse(source)
        for name in ("build_platform_pack", "generate_manifest"):
            function = next(
                node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            body = ast.get_source_segment(source, function) or ""
            with self.subTest(function=name):
                self.assertIn("DeclarationJudge(", body)
                self.assertNotIn('"slot_arbitrated"', body)
        judge = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "DeclarationJudge"
        )
        body = ast.get_source_segment(source, judge) or ""
        self.assertIn("baseline_verdict(", body)
        self.assertIn("resolve_declaration(", body)
        self.assertNotIn('"slot_arbitrated"', body)

    def test_verify_and_the_region_pass_resolve_as_the_builder(self):
        """verify called common.resolve_local_file and put the slot override
        first, the region pass passed a destination hint the builder never
        gives: a gitignored file absent from bios/ read as missing in verify
        while the pack shipped its cached release asset."""
        for module, name in (("verify.py", "_resolve_for_platform"),
                             ("packs/extraregions.py", "_ships")):
            source = script_source(module)
            function = next(
                node for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            body = ast.get_source_segment(source, function) or ""
            with self.subTest(function=name):
                self.assertIn("resolve_declaration(", body)
                self.assertNotIn("resolve_local_file(", body)
                self.assertNotIn('"slot_arbitrated"', body)

    def test_verify_finds_the_cached_release_asset(self):
        # verify imports the scripts directory's modules by their bare names.
        from resolve import packfiles as packresolve
        from scripts.packs.platformtally import _resolve_for_platform

        with tempfile.TemporaryDirectory() as directory:
            cached = Path(directory) / "BIG.PUP"
            cached.write_bytes(b"large firmware")
            sha1 = hashlib.sha1(cached.read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": f"{directory}/absent/BIG.PUP",
                                   "name": "BIG.PUP", "sha1": sha1}},
                  "indexes": {"by_name": {"BIG.PUP": [sha1]}}}
            entry = {"name": "BIG.PUP", "sha1": sha1, "destination": "BIG.PUP"}
            # The record's path is a registered release asset.
            registered = [f"{directory}/absent/BIG.PUP"]
            with mock.patch.object(
                packresolve, "fetch_large_file", return_value=str(cached)
            ), mock.patch("model.largefiles.load_registered_paths", return_value=registered):
                found = _resolve_for_platform(
                    entry, "sys", db, {}, None, {"BIG.PUP": "bios/other.bin"},
                    "md5", {},
                )
        self.assertEqual(found, (str(cached), "release_asset"))


class PackExclusionRegressions(unittest.TestCase):
    def test_slug_platform_core_requirement_uses_the_generated_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            core_payload = root / "extra.bin"
            core_payload.write_bytes(b"mapped core payload")
            core_sha1 = hashlib.sha1(core_payload.read_bytes()).hexdigest()
            core_md5 = hashlib.md5(core_payload.read_bytes()).hexdigest()
            database = {
                "files": {
                    core_sha1: {
                        "name": "extra.bin",
                        "path": str(core_payload),
                        "md5": core_md5,
                        "size": core_payload.stat().st_size,
                    }
                },
                "indexes": {
                    "by_name": {"extra.bin": [core_sha1]},
                    "by_md5": {core_md5: core_sha1},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }
            config = {
                "platform": "Slug platform",
                "base_destination": "bios",
                "verification_mode": "existence",
                "cores": ["core_a"],
                "systems": {
                    "console-a": {
                        "files": [
                            {
                                "name": "base-a.bin",
                                "destination": "slug-a/base-a.bin",
                            }
                        ]
                    },
                    "console-b": {
                        "files": [
                            {
                                "name": "base-b.bin",
                                "destination": "slug-b/base-b.bin",
                            }
                        ]
                    },
                },
            }
            (platforms / "slug.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            profiles = {
                "core_a": {
                    "emulator": "Core A",
                    "type": "libretro",
                    "systems": ["console-a"],
                    "files": [
                        {
                            "name": "extra.bin",
                            "path": "extra.bin",
                            "sha1": core_sha1,
                        }
                    ],
                }
            }
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("slug-a/base-a.bin", b"baseline a")
                archive.writestr("slug-b/base-b.bin", b"baseline b")
                archive.writestr("slug-a/extra.bin", core_payload.read_bytes())

            result = verify_pack_against_platform(
                str(pack),
                "slug",
                str(platforms),
                db=database,
                emu_profiles=profiles,
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[6:8], (1, 1))

    def _mismatch_fixture(self, root: Path, mode: str) -> tuple[dict, Path]:
        """A platform declaring a hash the only local payload contradicts."""
        platforms = root / "platforms"
        platforms.mkdir()
        payload = root / "firmware.bin"
        payload.write_bytes(b"wrong local variant")
        sha1 = hashlib.sha1(payload.read_bytes()).hexdigest()
        md5 = hashlib.md5(payload.read_bytes()).hexdigest()
        database = {
            "files": {
                sha1: {
                    "name": "firmware.bin",
                    "path": str(payload),
                    "md5": md5,
                    "size": payload.stat().st_size,
                }
            },
            "indexes": {
                "by_name": {"firmware.bin": [sha1]},
                "by_md5": {md5: sha1},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        config = {
            "platform": f"Platform {mode}",
            "verification_mode": mode,
            "systems": {
                "console": {
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "sha1": "f" * 40,
                        }
                    ]
                }
            },
        }
        (platforms / "plat.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        return database, platforms

    def test_hash_platform_accounts_for_an_unsafe_exclusion(self):
        """A platform that reads the bytes would reject the local payload."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "md5")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "safe subset")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[8], 1)

    def test_existence_platform_never_withholds_over_a_declared_hash(self):
        """RetroArch and friends only look for the filename.

        An upstream hash the local dump contradicts must not remove a file the
        frontend would have loaded, so its absence stays a conformance error.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "existence")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "no firmware")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in e for e in result[3]), result[3])
            self.assertEqual(result[8], 0)

    def test_unexplained_missing_file_still_fails_conformance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            config = {
                "platform": "Missing",
                "verification_mode": "existence",
                "systems": {
                    "console": {
                        "files": [
                            {"name": "absent.bin", "destination": "absent.bin"}
                        ]
                    }
                },
            }
            (platforms / "missing.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "incomplete")
            database = {
                "files": {},
                "indexes": {
                    "by_name": {},
                    "by_md5": {},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }

            result = verify_pack_against_platform(
                str(pack),
                "missing",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in error for error in result[3]))


class RegionRegressions(unittest.TestCase):
    def test_tagged_and_untagged_same_path_is_preserved(self):
        profiles = {
            "tagged": {
                "type": "libretro",
                "files": [
                    {"name": "bios.bin", "path": "sys/bios.bin", "region": ["japan"]}
                ],
            },
            "untagged": {
                "type": "libretro",
                "files": [{"name": "bios.bin", "path": "sys/bios.bin"}],
            },
        }
        index = regions.build_region_index(profiles)
        self.assertEqual(regions.lookup_regions(index, "sys/bios.bin", "bios.bin"), set())
        drops = regions.resolve_region_drops(
            {"system": [("sys/bios.bin", "bios.bin")]},
            index,
            ["north-america"],
        )
        self.assertEqual(drops, set())

    def test_world_candidate_beats_unmatched_regional_fallback(self):
        profiles = {
            "core": {
                "type": "libretro",
                "files": [
                    {"name": "ntsc.bin", "region": ["world"]},
                    {"name": "pal.bin", "region": ["europe"]},
                ],
            }
        }
        index = regions.build_region_index(profiles)
        groups = {"system": [("ntsc.bin", "ntsc.bin"), ("pal.bin", "pal.bin")]}
        self.assertEqual(
            regions.resolve_region_drops(groups, index, ["north-america"]),
            {"pal.bin"},
        )
        self.assertEqual(regions.resolve_region_drops(groups, index, ["europe"]), set())

    def test_multi_system_emulator_uses_separate_region_groups(self):
        profile = {"systems": ["odyssey2", "videopac"]}
        north_america = _emulator_region_group(
            "o2em", profile, {"name": "o2rom.bin", "system": "odyssey2"}, "o2rom.bin"
        )
        europe = _emulator_region_group(
            "o2em", profile, {"name": "c52.bin", "system": "videopac"}, "c52.bin"
        )
        self.assertNotEqual(north_america, europe)

    def test_a_systemless_file_groups_alike_in_both_modes(self):
        """geargrafx files pac-n1.bin [japan] and pac-n10.bin [north-america]
        under none of its four systems: emulator mode grouped them and
        dropped pac-n1.bin for --region us, platform mode isolated each and
        kept it."""
        from packs.extraregions import extra_region_groups

        profile = {"systems": ["nec-pc-engine", "nec-pc-engine-cd", "nec-supergrafx",
                               "pioneer-laseractive"]}
        names = ["pac-n1.bin", "pac-n10.bin"]
        emulator = [
            _emulator_region_group("geargrafx", profile, {"name": n}, n) for n in names
        ]
        platform = [
            extra_region_groups({
                "source_emulator": "geargrafx", "destination": n,
                "source_systems": profile["systems"],
            })[0]
            for n in names
        ]
        self.assertEqual(emulator, platform)

    def test_an_entry_systems_list_groups_alike_in_both_modes(self):
        """An entry's own one-element `systems:` names its machine on the
        platform side. Emulator mode read only `system:`, so --emulator
        --region us kept the Japanese file --platform --region us dropped."""
        from model.profiles import entry_system_ids
        from packs.extraregions import emulator_region_drops, extra_region_groups

        profile = {"systems": ["sys-a", "sys-b"], "files": [
            {"name": "us.bin", "systems": ["sys-a"], "region": ["north-america"]},
            {"name": "jp.bin", "systems": ["sys-a"], "region": ["japan"]},
        ]}
        self.assertEqual(
            emulator_region_drops([("emu", profile)], False, ["north-america"]),
            {"jp.bin"},
        )
        for fe in profile["files"]:
            self.assertEqual(
                _emulator_region_group("emu", profile, fe, fe["name"]),
                "emu:system:" + extra_region_groups({
                    "source_emulator": "emu", "destination": fe["name"],
                    "source_systems": entry_system_ids(fe, profile),
                })[0],
            )

    def test_region_audit_resolves_the_way_the_pack_does(self):
        """A private resolver read sha1, md5 and a lone name: an entry
        identified by its path (Dolphin's three IPL.bin) was never checked."""
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            self.addCleanup(os.chdir, previous)
            files, shas = {}, {}
            for rel, payload in (("bios/GC/USA/IPL.bin", b"usa"), ("bios/GC/JAP/IPL.bin", b"jap")):
                Path(rel).parent.mkdir(parents=True, exist_ok=True)
                Path(rel).write_bytes(payload)
                sha1 = hashlib.sha1(payload).hexdigest()
                shas[rel] = sha1
                files[sha1] = {"path": rel, "name": "IPL.bin", "size": len(payload), "sha1": sha1,
                               "md5": hashlib.md5(payload).hexdigest(),
                               "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001"}
            from collection.indexes import build_indexes

            db = {"files": files, "indexes": build_indexes(files, {})}
            by_md5 = {e["md5"]: s for s, e in files.items()}
            self.assertEqual(
                regionaudit.resolve_sha1({"name": "IPL.bin", "md5": [files[shas["bios/GC/USA/IPL.bin"]]["md5"]]}, db),
                shas["bios/GC/USA/IPL.bin"],
            )
            self.assertEqual(
                regionaudit.resolve_sha1({"name": "IPL.bin", "path": "GC/JAP/IPL.bin"}, db),
                shas["bios/GC/JAP/IPL.bin"],
            )
            self.assertTrue(by_md5)


class APackNameFitsAFileName(unittest.TestCase):
    """--system snes joined 23 emulator names and died on ENAMETOOLONG
    before writing anything, while verify --system snes reported."""

    def test_a_long_selection_is_bounded_and_told_apart(self):
        from scripts.packs.naming import MAX_PACK_NAME_BYTES, bounded_join

        def bounded_pack_name(display: list[str], keys: list[str], suffix: str) -> str:
            return bounded_join(display, keys, joiner="_", budget=MAX_PACK_NAME_BYTES, suffix=suffix)

        names = [f"Emulator_Number_{i}" for i in range(23)]
        long_name = bounded_pack_name(names, names, "_BIOS_Pack.zip")
        self.assertLessEqual(len(long_name.encode()), MAX_PACK_NAME_BYTES)
        self.assertTrue(long_name.startswith("Emulator_Number_0_and_22_more_"))
        other = bounded_pack_name(names, names[:-1] + ["x"], "_BIOS_Pack.zip")
        self.assertNotEqual(long_name, other)
        self.assertEqual(bounded_pack_name(["A", "B"], ["a", "b"], ".zip"), "A_B.zip")

    def test_a_long_system_list_is_bounded(self):
        """Thirty systems joined made a 261-byte platform pack name."""
        from scripts.packs.naming import MAX_SYSTEM_TAG_BYTES, system_tag

        systems = [f"vendor-console-number-{i}" for i in range(30)]
        tag = system_tag(systems)
        self.assertLessEqual(len(tag.encode()), MAX_SYSTEM_TAG_BYTES + 1)
        self.assertNotEqual(tag, system_tag(systems[:-1] + ["other-console"]))
        self.assertEqual(system_tag(["sony-playstation"]), "_Playstation")

    def test_two_systems_never_name_one_system(self):
        """sega-dreamcast,arcade and sega-dreamcast-arcade both wrote
        RetroArch_..._Dreamcast_Arcade.zip, and the second replaced the first."""
        from scripts.packs.naming import system_tag

        pairs = [
            (["sega-dreamcast", "arcade"], ["sega-dreamcast-arcade"]),
            (["mega-cd", "sega-32x"], ["mega-cd-32x"]),
            (["x86", "nintendo-64"], ["x86-64"]),
        ]
        for two, one in pairs:
            with self.subTest(two=two):
                self.assertNotEqual(system_tag(two), system_tag(one))

    def test_two_hash_lists_get_two_names(self):
        """--from-md5 named its pack after the context only: a second list
        overwrote the first pack in the same directory."""
        source = script_source("generate_pack.py")
        self.assertIn('_Custom_{selection}', source)

    def test_the_system_pack_names_itself(self):
        source = script_source("generate_pack.py")
        self.assertIn("pack_name=final_name", source)


class AGroupPackIsWrittenUnderItsOwnName(unittest.TestCase):
    """The RetroArch + Lakka pack was written as RetroArch_..._BIOS_Pack.zip
    and renamed: a `--platform retroarch` pack already in the directory was
    overwritten then carried away, and os.rename refuses an existing target
    on Windows."""

    def test_no_pack_is_renamed_after_its_build(self):
        source = script_source("generate_pack.py")
        self.assertNotIn("os.rename(", source)
        self.assertIn("pack_name=group_name", source)


class ARegionDroppedExtraBlocksNothing(unittest.TestCase):
    """The builder skips a region-dropped core extra before placing it,
    but the report placed it anyway, so on a case-folding platform it hid the
    next core's FOO.ROM that the pack does carry."""

    def test_the_report_skips_what_the_region_pass_drops(self):
        from unittest import mock

        from scripts.packs import extraresolver

        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory) / "FOO.ROM"
            other.write_bytes(b"other bytes")
            first = Path(directory) / "foo.rom"
            first.write_bytes(b"first bytes")
            copies = {"foo.rom": str(first), "FOO.ROM": str(other)}
            extras = [
                {"name": "foo.rom", "destination": "foo.rom", "source_emulator": "a"},
                {"name": "FOO.ROM", "destination": "FOO.ROM", "source_emulator": "b"},
            ]
            config = {"case_insensitive_fs": True, "base_destination": ""}

            def report(region_drops):
                with mock.patch.object(extraresolver, "collect_emulator_extras",
                                       return_value=extras), \
                        mock.patch.object(extraresolver, "resolve_local_file",
                                          side_effect=lambda fe, *a, **k: (
                                              copies[fe["name"]], "name_exact")):
                    return extraresolver.hidden_extras(
                        config, "emulators", {"files": {}}, {}, {}, None, region_drops
                    )

            self.assertTrue(report(None))
            self.assertEqual(report({"foo.rom"}), {})


class APackNoteBesideItsSlotIsANote(unittest.TestCase):
    """The builder writes INSTRUCTIONS_<name>.txt beside the slot it
    explains, but verify_pack recognised notes at the ZIP root only and failed
    a pack holding games/keen6/INSTRUCTIONS_egagraph.ck6.txt."""

    def test_a_nested_note_is_not_hashed_against_the_collection(self):
        from scripts.packs.integrity import verify_pack

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Pack.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("games/keen6/INSTRUCTIONS_egagraph.ck6.txt", "File needed")
                archive.writestr("bios/RENAMED_x.bin.txt", "renamed")
            result = verify_pack(str(path), {"files": {}, "indexes": {}})
        self.assertTrue(result[0], result)

    def test_verify_reads_the_rule_where_it_is_defined(self):
        source = script_source("verify.py")
        self.assertNotIn("from generate_pack import _preferred_entries", source)


class AnArchiveShipsWholeUnderARegion(unittest.TestCase):
    """verify --emulator dropped kronos' regional stvbios.zip members before
    rebuilding the archive, so its archive held 4 of 14 members and its
    required changed, while the emulator pack ships the archive whole."""

    def test_verify_filters_loose_files_only(self):
        loose_only = (
            'if fe.get("archive")\n                or resolve_destination(fe, selection.standalone)'
            ' not in selection.region_drops'
        )
        # The pack and the report read the same selection.
        self.assertIn(loose_only, script_source("verify.py"))
        self.assertIn(loose_only, script_source("generate_pack.py"))


class APathConflictKeepsTheMainVerdict(unittest.TestCase):
    """The builder's file/directory conflict branch judged a declaration by
    the raw resolver status: a zipped_file archive whose member is right was
    counted excluded while verify counted it OK."""

    def test_the_branch_reads_baseline_verdict(self):
        source = script_source("generate_pack.py")
        branch = source[source.index("Content ships under the conflicting shape"):]
        branch = branch[: branch.index("storage = file_entry.get")]
        self.assertIn("self.declarations.verdict(", branch)
        self.assertNotIn('conflict_status == "hash_mismatch"', branch)


class AnEmptyTargetIsNotEveryCore(unittest.TestCase):
    """A board scraped with `cores: []` and `add_cores: [gpsp]`: the pack
    served gpsp's files only, the published list said null (every core)."""

    def test_the_published_list_is_the_builder_reading(self):
        from scripts.model.targets import load_target_config
        from scripts.packs.targets import generate_target_manifests

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        targets = tmp / "platforms" / "targets"
        targets.mkdir(parents=True)
        (targets / "demo.yml").write_text(
            "platform: demo\ntargets:\n"
            "  board:\n    architecture: aarch64\n    cores: []\n"
            "  full:\n    architecture: x86_64\n    cores: null\n"
        )
        (targets / "_overrides.yml").write_text(
            "demo:\n  targets:\n    board:\n      add_cores: [gpsp]\n"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            generate_target_manifests(str(targets), str(tmp / "out"))
        published = json.loads((tmp / "out" / "demo.json").read_text())
        builder = load_target_config("demo", "board", str(tmp / "platforms"))
        self.assertEqual(published["board"], sorted(builder))
        self.assertEqual(published["board"], ["gpsp"])
        self.assertIsNone(published["full"])


class ADataDirectoryIsHeldWhileRead(unittest.TestCase):
    """A pack resolved names against data/bluemsx, then a concurrent refresh
    swapped the tree: the index named files that were gone and the copy
    died on FileNotFoundError, or shipped bytes nobody had verified."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))

    def test_the_index_follows_a_swapped_tree(self):
        from scripts.resolve.datadirs import _data_dir_basenames

        cache = self.tmp / "cache"
        cache.mkdir()
        (cache / "old.rom").write_bytes(b"old")
        self.assertIn("old.rom", _data_dir_basenames(str(cache)))
        cache.rename(self.tmp / "gone")
        cache.mkdir()
        (cache / "new.rom").write_bytes(b"new")
        index = _data_dir_basenames(str(cache))
        self.assertIn("new.rom", index)
        self.assertNotIn("old.rom", index)

    def test_a_holder_makes_the_refresh_lock_wait(self):
        import fcntl

        from scripts.packs import datadirs

        cache = self.tmp / "bluemsx"
        cache.mkdir()
        lock = cache.with_name(f".{cache.name}.lock")

        def exclusive_free() -> bool:
            with open(lock, "a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return False
                fcntl.flock(handle, fcntl.LOCK_UN)
                return True

        with contextlib.ExitStack() as held:
            datadirs.hold_data_dirs(held, {"bluemsx": {"local_cache": str(cache)}})
            self.assertFalse(exclusive_free())
        self.assertTrue(exclusive_free())

    def test_a_cache_not_yet_on_disk_is_held_too(self):
        """Skipped while absent, a tree a refresh installed mid-run was
        missing for verify and present for the packs of the same run."""
        import fcntl

        from scripts.packs import datadirs

        cache = self.tmp / "absent"
        lock = cache.with_name(f".{cache.name}.lock")
        with contextlib.ExitStack() as held:
            datadirs.hold_data_dirs(held, {"absent": {"local_cache": str(cache)}})
            self.assertFalse(cache.exists())
            with open(lock, "a") as handle, self.assertRaises(BlockingIOError):
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_both_entry_points_hold_the_trees(self):
        pack = script_source("generate_pack.py")
        verify_src = script_source("verify.py")
        self.assertIn("hold_data_dirs(held,", verify_src)
        refresh = pack.index("results = refresh_all(")
        self.assertIn("hold_data_dirs(held, data_registry)", pack[refresh:])

    def test_verify_packs_alone_holds_the_trees(self):
        # --verify-packs returned before the hold and resolved core files
        # against data/ while a refresh could swap a tree.
        pack = script_source("generate_pack.py")
        branch = pack.index("if args.verify_packs and not args.all_variants:")
        run = pack.index("run_verify_packs(args)", branch)
        self.assertIn("hold_data_dirs(held,", pack[branch:run])


class ReportsHoldTheDataTrees(unittest.TestCase):
    """Run on their own, the README, site and slot reports resolved against
    data/ without the shared hold, so a concurrent refresh could swap a tree
    while they read it and the published counts came from half of it."""

    def test_each_entry_point_holds_them(self):
        import ast

        # export_native holds them in build_export, which the freshness
        # check calls too (TheExportHoldsTheDataTrees in test_export_report).
        for script in ("generate_readme.py", "generate_site.py", "slots.py",
                       "cross_reference.py"):
            tree = ast.parse((REPO_ROOT / "scripts" / script).read_text(encoding="utf-8"))
            main = next(
                node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "main"
            )
            # A thin command holds them in main or in the package run main calls.
            called = {getattr(call.func, "id", None) for call in ast.walk(main)
                      if isinstance(call, ast.Call)}
            entry_points = [main] + [
                node for node in ast.walk(ast.parse(script_source(script)))
                if isinstance(node, ast.FunctionDef) and node.name in called
            ]
            with self.subTest(script=script):
                self.assertTrue(any(
                    isinstance(call, ast.Call)
                    and getattr(call.func, "id", None) == "hold_data_dirs"
                    for entry in entry_points for call in ast.walk(entry)
                ))


class ThePackCheckAppliesTheFrontendRule(unittest.TestCase):
    """The integrity step compared a member's md5 alone. Under RomM's rule
    (size, then any of md5, sha1 and crc32) the builder ships a revision
    matched on its sha1, and the check then refused a correct pack."""

    def test_romm_accepts_on_size_and_sha1(self):
        import hashlib
        import zipfile

        from scripts.packs.packhashes import _check_member_hash

        payload = b"revision B"
        entry = {
            "md5": "0" * 32,
            "sha1": hashlib.sha1(payload).hexdigest(),
            "size": len(payload),
        }
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / "p.zip"
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("bios/x.bin", payload)
            with zipfile.ZipFile(pack) as zf:
                self.assertIsNone(
                    _check_member_hash(zf, "bios/x.bin", entry, "md5", "size_and_any_hash")
                )
                self.assertIsNotNone(_check_member_hash(zf, "bios/x.bin", entry, "md5"))


class RequiredOnlyReachesDataDirectories(unittest.TestCase):
    """--required-only filtered files and packed every data tree anyway: the
    Required RetroArch pack still carried the 90 FreeIntv overlays, which the
    core reads only with its multi-screen option and replaces by a drawn
    keypad when absent (FreeIntv src/libretro.c:294-296, 350-369)."""

    def _members(self, required_only: bool) -> list[str]:
        from scripts.packs import datatrees
        from scripts.packs.archive import Placed

        with tempfile.TemporaryDirectory() as tmp:
            for key in ("needed", "optional"):
                Path(tmp, key).mkdir()
                Path(tmp, key, f"{key}.bin").write_bytes(b"x")
            registry = {
                key: {"local_cache": str(Path(tmp, key))}
                for key in ("needed", "optional")
            }
            systems = {
                "sys": {
                    "data_directories": [
                        {"ref": "needed", "destination": "a"},
                        {"ref": "optional", "destination": "b", "required": False},
                    ]
                }
            }
            return [
                dest
                for _src, dest in datatrees.data_directory_members(
                    systems, registry, "retroarch", "", Placed(False),
                    required_only=required_only,
                )
            ]

    def test_an_optional_tree_leaves_the_required_pack(self):
        self.assertEqual(self._members(False), ["a/needed.bin", "b/optional.bin"])
        self.assertEqual(self._members(True), ["a/needed.bin"])

    def test_every_tree_walk_reads_the_flag(self):
        source = script_source("generate_pack.py")
        # The pack's walk and the manifest's, which records the flag for
        # install.py --required-only.
        self.assertEqual(source.count('if required_only and dd.get("required") is False:'), 1)
        self.assertIn('needed = dd.get("required") is not False\n        if required_only and not needed:',
                      source)
        self.assertIn("self.placed, required_only=required_only,", source)
        self.assertIn("data_refs, required_only=required_only,", source)

    def test_the_overlays_are_declared_optional(self):
        retroarch = yaml.safe_load((REPO_ROOT / "platforms" / "retroarch.yml").read_text())
        trees = retroarch["systems"]["mattel-intellivision"]["data_directories"]
        self.assertEqual(trees, [
            {"ref": "freeintv-overlays", "destination": "freeintv_overlays",
             "required": False},
        ])

    def test_an_alias_reads_the_trees_of_its_core(self):
        """An alias is the same binary under another name. FreeIntv declared
        no overlay tree while its alias freeintv_ts_overlay did, so the
        emulator pack of the core itself left the overlays out."""
        profiles = {
            path.stem: yaml.safe_load(path.read_text(encoding="utf-8"))
            for path in (REPO_ROOT / "emulators").glob("*.yml")
        }

        def trees(profile: dict) -> dict:
            return {
                dd["ref"]: dd.get("required", True)
                for dd in profile.get("data_directories") or []
            }

        for name, profile in profiles.items():
            target = profile.get("alias_of")
            if not target or target not in profiles:
                continue
            with self.subTest(alias=name, core=target):
                self.assertEqual(trees(profile), trees(profiles[target]))


class _ResponseBody(io.BytesIO):
    """A body with the headers attribute urlopen's response carries."""

    headers: dict[str, str] = {}


class ExternalDownloadsFollowTheRunPolicy(unittest.TestCase):
    """download_external lived outside packresolve and fetched under
    --offline, into the system /tmp, holding the whole body in memory."""

    ENTRY = {"name": "ext.bin", "source_url": "https://example.invalid/ext.bin",
             "sha1": hashlib.sha1(b"payload").hexdigest()}

    def setUp(self):
        # tests/__init__ sets RETROBIOS_OFFLINE for the suite: these cases
        # download from a mocked urlopen, so the switch is cleared here.
        patcher = mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _response(self, body: bytes):
        stream = _ResponseBody(body)
        response = mock.MagicMock()
        response.__enter__.return_value = stream
        response.__exit__.return_value = False
        return response

    def test_offline_never_reaches_the_network(self):
        from resolve import packfiles as packresolve

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch("urllib.request.urlopen") as urlopen, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            fetch = packresolve.download_external(self.ENTRY, f"{tmp}/x", offline=True)
        self.assertIs(fetch.outcome, packresolve.ExternalOutcome.OFFLINE)
        self.assertFalse(fetch.fetched)
        self.assertEqual(out.getvalue(), "")
        urlopen.assert_not_called()

    def test_each_failure_names_its_own_cause(self):
        """Four causes came back as one False, reported as a download failure."""
        from core import forgehttp
        from resolve import packfiles as packresolve

        outcome = packresolve.ExternalOutcome
        with tempfile.TemporaryDirectory() as tmp:
            no_hash = packresolve.download_external(
                {"name": "ext.bin", "source_url": "https://example.invalid/x"},
                f"{tmp}/x", offline=False)
            offline = packresolve.download_external(self.ENTRY, f"{tmp}/x", offline=True)
            with mock.patch("urllib.request.urlopen",
                            side_effect=urllib.error.URLError("refused")), \
                    mock.patch.object(forgehttp, "_sleep", lambda _s: None):
                failed = packresolve.download_external(self.ENTRY, f"{tmp}/x", offline=False)
        self.assertIs(no_hash.outcome, outcome.NO_HASH)
        self.assertIs(offline.outcome, outcome.OFFLINE)
        self.assertIs(failed.outcome, outcome.NETWORK_ERROR)
        self.assertIn("offline", offline.reason)
        self.assertIn("hash", no_hash.reason)
        self.assertIn("refused", failed.reason)

    def test_the_run_switch_is_inherited(self):
        from resolve import packfiles as packresolve

        saved = packresolve.OFFLINE
        packresolve.set_offline(True)
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                    mock.patch("urllib.request.urlopen") as urlopen:
                self.assertFalse(packresolve.download_external(self.ENTRY, f"{tmp}/x").fetched)
            urlopen.assert_not_called()
        finally:
            packresolve.set_offline(saved)

    def test_the_environment_switch_holds_whatever_the_caller_passes(self):
        """RETROBIOS_OFFLINE stopped release assets but not external URLs."""
        from resolve import packfiles as packresolve

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": "1"}), \
                mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(
                packresolve.download_external(self.ENTRY, f"{tmp}/x", offline=False).fetched)
        urlopen.assert_not_called()

    def test_a_verified_body_lands_and_a_wrong_one_is_removed(self):
        from resolve import packfiles as packresolve

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x"
            with mock.patch("urllib.request.urlopen",
                                   return_value=self._response(b"payload")):
                self.assertTrue(
                    packresolve.download_external(self.ENTRY, str(target), offline=False).fetched)
            self.assertEqual(target.read_bytes(), b"payload")
            target.unlink()
            with mock.patch("urllib.request.urlopen",
                                   return_value=self._response(b"other")):
                fetch = packresolve.download_external(self.ENTRY, str(target), offline=False)
            self.assertIs(fetch.outcome, packresolve.ExternalOutcome.MISMATCH)
            self.assertFalse(target.exists())

    def test_every_accepted_value_of_a_listed_field_verifies(self):
        # A list or a comma-joined field was compared as its string form
        # ("['a', 'b']"), so no body could ever match it.
        from resolve import packfiles as packresolve

        good = hashlib.sha1(b"payload").hexdigest().upper()
        for sha1 in (["0" * 40, good], f"{'0' * 40}, {good}"):
            with self.subTest(sha1=sha1), tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.object(packresolve.urllib.request, "urlopen",
                                      return_value=self._response(b"payload")):
                entry = {**self.ENTRY, "sha1": sha1}
                self.assertTrue(
                    packresolve.download_external(entry, f"{tmp}/x", offline=False).fetched)

    def test_a_transient_failure_is_retried_and_no_scratch_remains(self):
        """One 503 failed the external file for the whole build."""
        from core import forgehttp
        from resolve import packfiles as packresolve

        refusal = urllib.error.HTTPError(self.ENTRY["source_url"], 503, "busy", {}, None)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x"
            with mock.patch("urllib.request.urlopen",
                            side_effect=[refusal, self._response(b"payload")]), \
                    mock.patch.object(forgehttp, "_sleep", lambda _s: None):
                self.assertTrue(
                    packresolve.download_external(self.ENTRY, str(target), offline=False).fetched)
            self.assertEqual(target.read_bytes(), b"payload")
            self.assertEqual(os.listdir(tmp), ["x"])

    def test_scratch_files_stay_in_the_repository(self):
        source = script_source("generate_pack.py")
        self.assertNotIn("def download_external", source)
        self.assertNotIn("urlopen", source)
        for call in re.findall(r"NamedTemporaryFile\(([^)]*)\)", source):
            self.assertIn("dir=", call)


class NoArchiveRepeatsAMemberName(unittest.TestCase):
    """s8k_cpu.zip held three member names twice (MAME reuses them across
    two ROM_SYSTEM_BIOS of one device). Every pack build printed raw zipfile
    warnings and Info-ZIP stops on an interactive replace? at extraction."""

    def test_member_names_are_unique(self):
        archives = sorted((REPO_ROOT / "bios").rglob("*.zip"))
        if not archives:
            self.skipTest("no archive under bios/")
        repeated = []
        for path in archives:
            try:
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
            except (zipfile.BadZipFile, OSError):
                continue
            if len(names) != len(set(names)):
                repeated.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(repeated, [])


if __name__ == "__main__":
    unittest.main()
