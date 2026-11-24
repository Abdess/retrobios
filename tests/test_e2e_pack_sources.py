"""End-to-end hash scrapers, pack source variants, hashed archives and the MiSTer scraper."""

from __future__ import annotations

import tests
import os
import tempfile
import unittest
import zipfile
from unittest import mock
from model import largefiles
import yaml
from model.profiles import load_emulator_profiles
from model.platforms import load_platform_config
from tests.e2esupport import E2EFixture, _h


class TestE2EHashScrapers(E2EFixture):
    """MAME and FBNeo parsers and the hash merge."""

    # ---------------------------------------------------------------
    # Hash scraper: parsers + merge
    # ---------------------------------------------------------------

    def test_mame_parser_finds_bios_root_sets(self):
        from scripts.scraper.mame_parser import find_bios_root_sets, parse_rom_block

        source = """
ROM_START( neogeo )
    ROM_REGION( 0x020000, "mainbios", 0 )
    ROM_LOAD( "sp-s2.sp1", 0x00000, 0x020000, CRC(9036d879) SHA1(4f834c580f3471ce40c3210ef5e7491df38d8851) )
ROM_END
GAME( 1990, neogeo, 0, ng, neogeo, ng_state, empty_init, ROT0, "SNK", "Neo Geo", MACHINE_IS_BIOS_ROOT )
ROM_START( pacman )
    ROM_REGION( 0x10000, "maincpu", 0 )
    ROM_LOAD( "pacman.6e", 0x0000, 0x1000, CRC(c1e6ab10) SHA1(e87e059c5be45753f7e9f33dff851f16d6751181) )
ROM_END
GAME( 1980, pacman, 0, pacman, pacman, pacman_state, empty_init, ROT90, "Namco", "Pac-Man", 0 )
"""
        sets = find_bios_root_sets(source, "neogeo.cpp")
        self.assertIn("neogeo", sets)
        self.assertNotIn("pacman", sets)
        roms = parse_rom_block(source, "neogeo")
        self.assertEqual(len(roms), 1)
        self.assertEqual(roms[0]["crc32"], "9036d879")

    def test_fbneo_parser_finds_bios_sets(self):
        from scripts.scraper.fbneo_parser import find_bios_sets, parse_rom_info

        source = """
static struct BurnRomInfo neogeoRomDesc[] = {
    { "sp-s2.sp1",    0x020000, 0x9036d879, BRF_ESS | BRF_BIOS },
    { "",              0,        0,          0 }
};
STD_ROM_PICK(neogeo)
STD_ROM_FN(neogeo)
struct BurnDriver BurnDrvneogeo = {
    "neogeo", NULL, NULL, NULL, "1990",
    "Neo Geo\\0", "BIOS only", "SNK", "Neo Geo MVS",
    NULL, NULL, NULL, NULL, BDF_BOARDROM, 0, 0,
    0, 0, 0, NULL, neogeoRomInfo, neogeoRomName, NULL, NULL,
    NULL, NULL, NULL, NULL, 0
};
"""
        sets = find_bios_sets(source, "d_neogeo.cpp")
        self.assertIn("neogeo", sets)
        roms = parse_rom_info(source, "neogeo")
        self.assertEqual(len(roms), 1)
        self.assertEqual(roms[0]["crc32"], "9036d879")

    def test_mame_merge_preserves_manual_fields(self):
        from scripts.scraper._hash_merge import merge_mame_profile

        profile = {
            "emulator": "Test",
            "type": "libretro",
            "upstream": "https://github.com/mamedev/mame",
            "core_version": "0.285",
            "files": [
                {
                    "name": "neogeo.zip",
                    "required": True,
                    "category": "bios_zip",
                    "system": "snk-neogeo-mvs",
                    "note": "MVS BIOS",
                    "source_ref": "old.cpp:1",
                    "contents": [
                        {"name": "sp-s2.sp1", "size": 131072, "crc32": "oldcrc"}
                    ],
                }
            ],
        }
        hashes = {
            "source": "mamedev/mame",
            "version": "0.286",
            "commit": "abc",
            "fetched_at": "2026-03-30T00:00:00Z",
            "bios_sets": {
                "neogeo": {
                    "source_file": "neo.cpp",
                    "source_line": 42,
                    "roms": [
                        {
                            "name": "sp-s2.sp1",
                            "size": 131072,
                            "crc32": "newcrc",
                            "sha1": "abc123",
                        }
                    ],
                }
            },
        }
        result = merge_mame_profile(profile, hashes)
        neo = next(f for f in result["files"] if f["name"] == "neogeo.zip")
        self.assertEqual(neo["contents"][0]["crc32"], "newcrc")
        self.assertEqual(neo["system"], "snk-neogeo-mvs")
        self.assertEqual(neo["note"], "MVS BIOS")
        self.assertEqual(neo["source_ref"], "neo.cpp:42")
        self.assertEqual(result["core_version"], "0.286")

    def test_fbneo_merge_updates_individual_roms(self):
        from scripts.scraper._hash_merge import merge_fbneo_profile

        profile = {
            "emulator": "FBNeo",
            "type": "libretro",
            "upstream": "https://github.com/finalburnneo/FBNeo",
            "core_version": "v1.0.0.02",
            "files": [
                {
                    "name": "sp-s2.sp1",
                    "archive": "neogeo.zip",
                    "system": "snk-neogeo-mvs",
                    "required": True,
                    "size": 131072,
                    "crc32": "oldcrc",
                }
            ],
        }
        hashes = {
            "source": "finalburnneo/FBNeo",
            "version": "v1.0.0.03",
            "commit": "def",
            "fetched_at": "2026-03-30T00:00:00Z",
            "bios_sets": {
                "neogeo": {
                    "source_file": "neo.cpp",
                    "source_line": 10,
                    "roms": [{"name": "sp-s2.sp1", "size": 131072, "crc32": "newcrc"}],
                }
            },
        }
        result = merge_fbneo_profile(profile, hashes)
        rom = next(f for f in result["files"] if f["name"] == "sp-s2.sp1")
        self.assertEqual(rom["crc32"], "newcrc")
        self.assertEqual(rom["system"], "snk-neogeo-mvs")
        # The version is the pin's, read through version_basis.
        self.assertEqual(result["core_version"], "v1.0.0.02")


class TestE2EPackSource(E2EFixture):
    """Pack source variants: platform, truth and full."""

    def _load_config(self, platform_name: str) -> dict:
        return load_platform_config(platform_name, self.platforms_dir)

    def test_200_find_undeclared_include_all(self):
        """include_all=True returns ALL core files, including declared ones."""
        from packs.gaps import find_undeclared_files

        config = self._load_config("test_existence")
        profiles = load_emulator_profiles(self.emulators_dir)
        # Without include_all: only undeclared files returned
        undeclared = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles
        )
        undeclared_names = {u["name"] for u in undeclared}
        # present_req.bin is declared in platform YAML, should NOT be in undeclared
        self.assertNotIn("present_req.bin", undeclared_names)

        # With include_all: ALL core files returned, including declared ones
        all_files = find_undeclared_files(
            config, self.emulators_dir, self.db, profiles, include_all=True
        )
        all_names = {u["name"] for u in all_files}
        # present_req.bin IS declared but should be returned with include_all
        self.assertIn("present_req.bin", all_names)
        # undeclared files should still be present
        self.assertIn("undeclared_req.bin", all_names)
        # Launcher/alias files should still be excluded
        self.assertNotIn("launcher_bios.bin", all_names)

    def test_201_collect_emulator_extras_include_all(self):
        """include_all=True passes through to find_undeclared_files."""
        from packs.extras import collect_emulator_extras

        config = self._load_config("test_existence")
        profiles = load_emulator_profiles(self.emulators_dir)
        base_dest = config.get("base_destination", "")

        # Default call must succeed without TypeError
        extras = collect_emulator_extras(
            config, self.emulators_dir, self.db, set(), base_dest, profiles
        )
        self.assertIsInstance(extras, list)

        # include_all=True must be accepted and return a list
        all_extras = collect_emulator_extras(
            config, self.emulators_dir, self.db, set(), base_dest, profiles,
            include_all=True,
        )
        self.assertIsInstance(all_extras, list)

        # include_all=True is a superset: at least as many entries as default
        all_names = {e["name"] for e in all_extras}
        default_names = {e["name"] for e in extras}
        self.assertGreaterEqual(len(all_names), len(default_names))
        # All default entries are present in include_all result
        for name in default_names:
            self.assertIn(name, all_names)


    def test_202_pack_source_platform(self):
        """source='platform' skips core extras."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_platform")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        zip_path = generate_pack(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emu_profiles=profiles,
            emulators_dir=self.emulators_dir,
            source="platform",
        )
        self.assertIsNotNone(zip_path)
        self.assertIn("_Platform_", os.path.basename(zip_path))

    def test_203_pack_source_truth(self):
        """source='truth' uses emulator profile files."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_truth")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        zip_path = generate_pack(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emu_profiles=profiles,
            emulators_dir=self.emulators_dir,
            source="truth",
        )
        self.assertIsNotNone(zip_path)
        self.assertIn("_Truth_", os.path.basename(zip_path))

    def test_204_pack_source_full_unchanged(self):
        """source='full' (default) has no source tag in filename."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_full")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        zip_path = generate_pack(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emu_profiles=profiles,
            emulators_dir=self.emulators_dir,
            source="full",
        )
        self.assertIsNotNone(zip_path)
        bn = os.path.basename(zip_path)
        self.assertNotIn("_Platform_", bn)
        self.assertNotIn("_Truth_", bn)


    def test_205_pack_source_platform_required(self):
        """source='platform' + required_only=True."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_plat_req")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        zip_path = generate_pack(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emu_profiles=profiles,
            emulators_dir=self.emulators_dir,
            source="platform",
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        self.assertIn("_Platform_Required_", os.path.basename(zip_path))
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
        self.assertTrue(any("present_req.bin" in n for n in names))
        self.assertFalse(any("present_opt.bin" in n for n in names))

    def test_206_pack_source_truth_required(self):
        """source='truth' + required_only=True."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_truth_req")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        zip_path = generate_pack(
            "test_existence",
            self.platforms_dir,
            self.db,
            self.bios_dir,
            output_dir,
            emu_profiles=profiles,
            emulators_dir=self.emulators_dir,
            source="truth",
            required_only=True,
        )
        self.assertIsNotNone(zip_path)
        self.assertIn("_Truth_Required_", os.path.basename(zip_path))

    def test_207_manifest_source(self):
        """generate_manifest respects source param."""
        from packs.manifest import generate_manifest

        profiles = load_emulator_profiles(self.emulators_dir)
        registry_path = os.path.join(self.platforms_dir, "_registry.yml")
        if not os.path.exists(registry_path):
            with open(registry_path, "w") as fh:
                yaml.dump({"platforms": {}}, fh)
        manifest_full = generate_manifest(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            registry_path, emulators_dir=self.emulators_dir, emu_profiles=profiles,
            source="full", offline=True,
        )
        manifest_plat = generate_manifest(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            registry_path, emulators_dir=self.emulators_dir, emu_profiles=profiles,
            source="platform", offline=True,
        )
        self.assertLessEqual(manifest_plat["total_files"], manifest_full["total_files"])
        self.assertEqual(manifest_plat.get("source"), "platform")
        self.assertEqual(manifest_full.get("source"), "full")

    def test_208_split_source_tag_in_dirname(self):
        """generate_split_packs uses source tag in split directory name."""
        from packs.platformpack import generate_split_packs

        output_dir = os.path.join(self.root, "split_src")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        generate_split_packs(
            "test_existence", self.platforms_dir, self.db, self.bios_dir,
            output_dir, emulators_dir=self.emulators_dir, emu_profiles=profiles,
            source="platform",
        )
        entries = os.listdir(output_dir)
        platform_dirs = [e for e in entries if "_Platform_" in e and "Split" in e]
        self.assertTrue(len(platform_dirs) > 0, f"No _Platform_ split dir in {entries}")

    def test_209_all_variants_generates_6_zips(self):
        """All 6 source x required combinations produce unique ZIPs."""
        from packs.platformpack import generate_pack

        output_dir = os.path.join(self.root, "pack_allvar")
        os.makedirs(output_dir, exist_ok=True)
        profiles = load_emulator_profiles(self.emulators_dir)
        variants = [
            ("full", False), ("full", True),
            ("platform", False), ("platform", True),
            ("truth", False), ("truth", True),
        ]
        for source, required_only in variants:
            generate_pack(
                "test_existence", self.platforms_dir, self.db, self.bios_dir,
                output_dir, emu_profiles=profiles, emulators_dir=self.emulators_dir,
                source=source, required_only=required_only,
            )
        zips = [f for f in os.listdir(output_dir) if f.endswith(".zip")]
        self.assertEqual(len(zips), 6, f"Expected 6 ZIPs, got {len(zips)}: {zips}")
        self.assertEqual(len(set(zips)), 6)


class TestE2EHashResolution(E2EFixture):
    """Declared archive bytes, strong hash resolution and zip member checks."""

    def _make_hash_zip_fixture(self, tmpdir, declare_md5=True):
        """Platform fixture with one ZIP file, optionally md5-declared."""
        import hashlib as hl

        plat_dir = os.path.join(tmpdir, "platforms")
        bios_dir = os.path.join(tmpdir, "bios", "Arcade")
        out_dir = os.path.join(tmpdir, "dist")
        os.makedirs(plat_dir)
        os.makedirs(bios_dir)

        zip_src = os.path.join(bios_dir, "testbios.zip")
        with zipfile.ZipFile(zip_src, "w", zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("rom.bin", date_time=(2020, 6, 15, 12, 0, 0))
            zf.writestr(info, b"rom_content_bytes")
        from core.hashing import compute_hashes

        h = compute_hashes(zip_src)

        db = {
            "files": {
                h["sha1"]: {
                    "name": "testbios.zip",
                    "md5": h["md5"],
                    "sha1": h["sha1"],
                    "path": zip_src,
                    "paths": ["Arcade/testbios.zip"],
                },
            },
            "indexes": {
                "by_md5": {h["md5"]: h["sha1"]},
                "by_name": {"testbios.zip": [h["sha1"]]},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        entry = {"name": "testbios.zip", "destination": "dc/testbios.zip"}
        if declare_md5:
            entry["md5"] = h["md5"]
        config = {
            "platform": "HashZipTest",
            "verification_mode": "md5",
            "base_destination": "bios",
            "systems": {"arcade-sys": {"files": [entry]}},
        }
        with open(os.path.join(plat_dir, "test_hashzip.yml"), "w") as fh:
            yaml.dump(config, fh)
        return plat_dir, os.path.join(tmpdir, "bios"), out_dir, db, h, hl

    def test_210_pack_copies_md5_declared_zip_byte_identical(self):
        """md5-declared ZIPs are copied unchanged, never rebuilt."""
        import tempfile

        from packs.platformpack import generate_pack

        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir, bios_root, out_dir, db, h, hl = self._make_hash_zip_fixture(
                tmpdir, declare_md5=True
            )
            zip_path = generate_pack(
                "test_hashzip", plat_dir, db, bios_root, out_dir
            )
            self.assertIsNotNone(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                data = zf.read("dc/testbios.zip")
            self.assertEqual(hl.md5(data).hexdigest(), h["md5"])

    def test_211_pack_keeps_zip_bytes_without_declared_hash(self):
        """A ZIP with no declared hash keeps the collection's bytes, so it
        hashes to what the install list publishes."""
        import io
        import tempfile

        from packs.platformpack import generate_pack

        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir, bios_root, out_dir, db, h, hl = self._make_hash_zip_fixture(
                tmpdir, declare_md5=False
            )
            zip_path = generate_pack(
                "test_hashzip", plat_dir, db, bios_root, out_dir
            )
            self.assertIsNotNone(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                data = zf.read("dc/testbios.zip")
            self.assertEqual(hl.md5(data).hexdigest(), h["md5"])
            with zipfile.ZipFile(io.BytesIO(data)) as inner:
                self.assertEqual(inner.read("rom.bin"), b"rom_content_bytes")

    def test_212_verify_pack_flags_native_md5_mismatch(self):
        """Pack verification reproduces the native md5 check per member."""
        import tempfile

        from packs.platformcheck import verify_pack_against_platform

        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir, bios_root, out_dir, db, h, hl = self._make_hash_zip_fixture(
                tmpdir, declare_md5=True
            )
            os.makedirs(out_dir)
            bad_pack = os.path.join(out_dir, "HashZipTest_BIOS_Pack.zip")
            with zipfile.ZipFile(bad_pack, "w") as zf:
                zf.writestr("dc/testbios.zip", b"wrong bytes entirely")
            result = verify_pack_against_platform(
                bad_pack, "test_hashzip", plat_dir, db=None
            )
            errors = result[3]
            self.assertTrue(
                any("md5" in e for e in errors),
                f"expected md5 mismatch error, got: {errors}",
            )

    def test_213_verify_pack_passes_correct_member_hash(self):
        """Pack verification passes when member bytes match declared md5."""
        import tempfile

        from packs.platformcheck import verify_pack_against_platform

        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir, bios_root, out_dir, db, h, hl = self._make_hash_zip_fixture(
                tmpdir, declare_md5=True
            )
            os.makedirs(out_dir)
            good_pack = os.path.join(out_dir, "HashZipTest_BIOS_Pack.zip")
            src = os.path.join(bios_root, "Arcade", "testbios.zip")
            with zipfile.ZipFile(good_pack, "w") as zf:
                zf.write(src, "dc/testbios.zip")
            result = verify_pack_against_platform(
                good_pack, "test_hashzip", plat_dir, db=None
            )
            self.assertEqual(result[3], [], f"unexpected errors: {result[3]}")

    def test_213b_absent_game_data_is_counted_apart(self):
        """Game data the collection lacks is counted apart from the pack's
        errors, while firmware the collection lacks stays one."""
        import tempfile

        from packs.platformpack import generate_pack
        from packs.platformcheck import verify_pack_against_platform

        profiles = {"eng": {"emulator": "Eng", "type": "game", "cores": ["eng"],
                            "systems": ["arcade-sys"],
                            "files": [{"name": "data.pak", "category": "game_data"},
                                      {"name": "firmware.bin"}]}}
        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir, bios_root, out_dir, db, _h, _hl = self._make_hash_zip_fixture(
                tmpdir, declare_md5=True
            )
            config_path = os.path.join(plat_dir, "test_hashzip.yml")
            with open(config_path) as fh:
                config = yaml.safe_load(fh)
            config["cores"] = ["eng"]
            config["systems"]["arcade-sys"]["files"].append(
                {"name": "data.pak", "destination": "dc/data.pak"}
            )
            with open(config_path, "w") as fh:
                yaml.dump(config, fh)
            zip_path = generate_pack("test_hashzip", plat_dir, db, bios_root, out_dir,
                                     emu_profiles=profiles)
            result = verify_pack_against_platform(
                zip_path, "test_hashzip", plat_dir, db=db, emu_profiles=profiles)
            self.assertEqual(result[3], [])
            self.assertEqual((result[4], result[5], result[9]), (2, 1, 1))

            config["systems"]["arcade-sys"]["files"][-1]["name"] = "firmware.bin"
            config["systems"]["arcade-sys"]["files"][-1]["destination"] = "dc/firmware.bin"
            with open(os.path.join(plat_dir, "test_hashzip_fw.yml"), "w") as fh:
                yaml.dump(config, fh)
            result = verify_pack_against_platform(
                zip_path, "test_hashzip_fw", plat_dir, db=db, emu_profiles=profiles)
            self.assertEqual([e.rsplit("/", 1)[-1] for e in result[3]], ["firmware.bin"])
            self.assertTrue(result[3][0].startswith("baseline missing: "))
            self.assertEqual(result[9], 0)

    def test_216_resolve_by_sha256(self):
        """resolve_local_file matches files by declared sha256."""
        import tempfile

        from resolve.localfile import resolve_local_file

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "SNES_dsp1.rom")
            with open(path, "wb") as fh:
                fh.write(b"dsp firmware bytes")
            import hashlib as hl

            sha256 = hl.sha256(b"dsp firmware bytes").hexdigest()
            db = {
                "files": {
                    "sha1x": {
                        "name": "SNES_dsp1.rom",
                        "path": path,
                        "sha256": sha256,
                    },
                },
                "indexes": {
                    "by_md5": {},
                    "by_name": {"SNES_dsp1.rom": ["sha1x"]},
                    "by_sha256": {sha256: "sha1x"},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }
            # Name differs, only sha256 identifies the content
            entry = {"name": "dsp1.rom", "sha256": sha256}
            local, status = resolve_local_file(entry, db)
            self.assertEqual(local, path)
            self.assertEqual(status, "sha256_exact")
            # Multi-hash list also resolves
            entry = {"name": "dsp1.rom", "sha256": f"{'0' * 64},{sha256}"}
            local, status = resolve_local_file(entry, db)
            self.assertEqual(local, path)
            # Unknown sha256 falls through to not_found
            entry = {"name": "dsp1.rom", "sha256": "f" * 64}
            local, status = resolve_local_file(entry, db)
            self.assertIsNone(local)
            self.assertEqual(status, "not_found")

    def test_220_large_file_dotted_asset_fallback(self):
        """Files with spaces resolve to GitHub's dotted asset name."""
        import tempfile
        import urllib.error

        from model.largefiles import fetch_large_file

        attempts = []

        class FakeResponse:
            headers: dict = {}

            def __init__(self, payload):
                self._payload = payload

            def read(self, _size=None):
                data, self._payload = self._payload, b""
                return data

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def fake_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            attempts.append(url)
            if "MAME%200.174" in url:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return FakeResponse(b"payload")

        original = largefiles.urllib.request.urlopen
        largefiles.urllib.request.urlopen = fake_urlopen
        try:
            with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(
                os.environ, {"RETROBIOS_OFFLINE": ""}
            ):
                path = fetch_large_file(
                    "MAME 0.174 Arcade XML.dat", dest_dir=tmpdir
                )
                self.assertIsNotNone(path)
                with open(path, "rb") as fh:
                    self.assertEqual(fh.read(), b"payload")
        finally:
            largefiles.urllib.request.urlopen = original

        self.assertEqual(len(attempts), 2, attempts)
        self.assertIn("MAME%200.174", attempts[0])
        self.assertIn("MAME.0.174.Arcade.XML.dat", attempts[1])

    def test_219_batocera_stable_tag_selection(self):
        """Stable tag picker takes the highest batocera-N(.M) tag."""
        from scripts.scraper.batocera_scraper import pick_stable_tag

        tags = [
            "uboot-rockpro64", "batocera-pre-br2-external",
            "batocera-41", "batocera-42", "batocera-43", "batocera-43.1",
            "master_20180518",
        ]
        self.assertEqual(pick_stable_tag(tags), "batocera-43.1")
        self.assertEqual(pick_stable_tag(["batocera-9", "batocera-10"]), "batocera-10")
        self.assertIsNone(pick_stable_tag(["uboot-x", "random"]))

    def test_218_resolve_by_crc32_and_size(self):
        """crc-only profile entries resolve by crc32 confirmed by size."""
        import tempfile
        import zlib

        from resolve.localfile import resolve_local_file

        with tempfile.TemporaryDirectory() as tmpdir:
            data = b"exos rom bytes" * 100
            path = os.path.join(tmpdir, "exos21.rom")
            with open(path, "wb") as fh:
                fh.write(data)
            crc = f"{zlib.crc32(data) & 0xffffffff:08x}"
            db = {
                "files": {
                    "sha1e": {
                        "name": "exos21.rom",
                        "path": path,
                        "size": len(data),
                        "crc32": crc,
                    },
                },
                "indexes": {
                    "by_md5": {},
                    "by_name": {"exos21.rom": ["sha1e"]},
                    "by_crc32": {crc: "sha1e"},
                    "by_path_suffix": {},
                },
            }
            # Different extension in the profile, crc32+size identify it
            local, status = resolve_local_file(
                {"name": "exos21.bin", "crc32": crc, "size": len(data)}, db
            )
            self.assertEqual(local, path)
            self.assertEqual(status, "crc32_exact")
            # Wrong size rejects the crc match
            local, status = resolve_local_file(
                {"name": "exos21.bin", "crc32": crc, "size": 1}, db
            )
            self.assertIsNone(local)

    def test_217_resolve_name_casefold_fallback(self):
        """Name resolution falls back to a case-insensitive match."""
        import tempfile

        from resolve.localfile import resolve_local_file

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "VEC_Minestorm.vec")
            with open(path, "wb") as fh:
                fh.write(b"minestorm rom")
            db = {
                "files": {"sha1v": {"name": "VEC_Minestorm.vec", "path": path}},
                "indexes": {
                    "by_md5": {},
                    "by_name": {"VEC_Minestorm.vec": ["sha1v"]},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }
            # Upstream declares a different casing, no hash
            local, status = resolve_local_file(
                {"name": "VEC_MineStorm.vec"}, db
            )
            self.assertEqual(local, path)
            self.assertEqual(status, "name_exact")

    def test_217b_zipped_file_composite_needs_the_member(self):
        """One member of another name has the zipped_file md5 as composite.

        Batocera looks the member up by name, so the archive is not proof of
        the entry: a MAME rename leaves exactly that archive behind.
        """
        import hashlib as hl
        import tempfile

        from resolve.localfile import resolve_local_file

        rom = b"inner rom bytes"
        rom_md5 = hl.md5(rom).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "foo.zip")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("renamed.bin", rom)
            db = {
                "files": {"sha1z": {"name": "foo.zip", "path": path, "md5": "f" * 32}},
                "indexes": {
                    "by_md5": {}, "by_name": {"foo.zip": ["sha1z"]},
                    "by_crc32": {}, "by_path_suffix": {},
                },
            }
            entry = {"name": "foo.zip", "zipped_file": "expected.bin", "md5": rom_md5}
            self.assertNotEqual(
                resolve_local_file(entry, db)[1], "md5_composite_exact"
            )
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("expected.bin", rom)
            self.assertEqual(
                resolve_local_file(entry, db), (path, "md5_composite_exact")
            )

    def test_215_check_member_hash_inside_zip(self):
        """zipped_file entries verify the ROM inside the ZIP, not the ZIP."""
        import hashlib as hl
        import tempfile

        from packs.packhashes import _check_member_hash

        rom = b"inner rom bytes"
        rom_md5 = hl.md5(rom).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            pack = os.path.join(tmpdir, "pack.zip")
            import io

            inner_buf = io.BytesIO()
            with zipfile.ZipFile(inner_buf, "w") as inner:
                inner.writestr("EPR-123.IC27", rom)
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("dc/game.zip", inner_buf.getvalue())
            with zipfile.ZipFile(pack) as zf:
                # Case-insensitive inner match (Batocera casefold)
                ok = _check_member_hash(
                    zf,
                    "dc/game.zip",
                    {"zipped_file": "epr-123.ic27", "md5": rom_md5},
                    "md5",
                )
                self.assertIsNone(ok)
                bad = _check_member_hash(
                    zf,
                    "dc/game.zip",
                    {"zipped_file": "epr-123.ic27", "md5": "0" * 32},
                    "md5",
                )
                self.assertIsNotNone(bad)


class TestE2EMister(E2EFixture):
    """The MiSTer BiosDB scraper, cross-reference filtering and compressed manifests."""

    # -- MiSTer FPGA scraper (BiosDB) -------------------------------------

    MISTER_DB = {
        "db_id": "bios_db",
        "timestamp": 1785183064,
        "files": {
            "games/3DO/boot.rom": {
                "hash": "f47264dd47fe30f73ab3c010015c155b",
                "size": 1048576,
                "url": "https://archive.org/download/x/3DO.zip/boot.rom",
            },
            "games/GameCom/boot.rom": {
                "hash": "3f2178d717dd309ed7424d49ef92987f",
                "size": 262144,
                "url": "https://archive.org/download/x/GameCom.zip/boot.rom",
            },
        },
        "archives": {
            "neogeo_unibios": {
                "archive_file": {"hash": "a" * 32, "size": 101498, "url": "http://x/u.zip"},
                "summary_inline": {
                    "files": {
                        "games/NEOGEO/uni-bios.rom": {
                            "hash": "4f0aeda8d2d145f596826b62d563c4ef",
                            "size": 131072,
                        }
                    }
                },
            }
        },
    }

    def _mister_scraper(self):
        import json

        from scraper.misterfpga_scraper import Scraper

        scraper = Scraper(url="https://example.test/bios_db.json.zip")
        scraper._raw_data = json.dumps(self.MISTER_DB)
        return scraper

    def test_221_mister_parse_db_inlines_archive_entries(self):
        """Archive-provided files carry the extracted member hash."""
        import json

        from scraper.misterfpga_scraper import parse_db

        entries = parse_db(json.dumps(self.MISTER_DB))
        self.assertIn("games/NEOGEO/uni-bios.rom", entries)
        self.assertEqual(
            entries["games/NEOGEO/uni-bios.rom"]["hash"],
            "4f0aeda8d2d145f596826b62d563c4ef",
        )
        self.assertEqual(len(entries), 3)

    def test_222_mister_validate_format_rejects_foreign_db(self):
        """Only the bios_db database is accepted."""
        import json

        scraper = self._mister_scraper()
        self.assertTrue(scraper.validate_format(json.dumps(self.MISTER_DB)))
        self.assertFalse(scraper.validate_format("not json"))
        self.assertFalse(
            scraper.validate_format(json.dumps({"db_id": "distribution_mister", "files": {}}))
        )
        broken = json.loads(json.dumps(self.MISTER_DB))
        broken["files"]["games/3DO/boot.rom"].pop("size")
        self.assertFalse(scraper.validate_format(json.dumps(broken)))

    def test_223_mister_requirements_strip_games_prefix(self):
        """Destinations are relative to base_destination games."""
        reqs = {r.destination: r for r in self._mister_scraper().fetch_requirements()}
        self.assertIn("3DO/boot.rom", reqs)
        self.assertEqual(reqs["3DO/boot.rom"].name, "boot.rom")
        self.assertEqual(reqs["3DO/boot.rom"].system, "3do")
        self.assertEqual(reqs["3DO/boot.rom"].native_id, "3DO")
        self.assertEqual(reqs["3DO/boot.rom"].size, 1048576)

    def test_224_mister_platform_yaml_shape(self):
        """The generated config declares md5 verification and no cores."""
        config = self._mister_scraper().generate_platform_yaml()
        self.assertEqual(config["verification_mode"], "md5")
        self.assertEqual(config["base_destination"], "games")
        self.assertEqual(config["cores"], [])
        self.assertEqual(config["version"], "2026-07-27")
        systems = config["systems"]
        self.assertEqual(
            systems["3do"]["docs"], "https://github.com/MiSTer-devel/3DO_MiSTer"
        )
        # No MiSTer-devel repository exists for the Game.com core
        self.assertNotIn("docs", systems["tiger-game-com"])
        entry = systems["3do"]["files"][0]
        self.assertTrue(entry["required"])
        self.assertEqual(entry["md5"], "f47264dd47fe30f73ab3c010015c155b")

    def test_225_mister_docs_targets_are_unique_per_system(self):
        """Every mapped system resolves to a distinct retrobios system ID."""
        from scraper.misterfpga_scraper import SYSTEM_MAP

        folders = list(SYSTEM_MAP)
        systems = [SYSTEM_MAP[f][0] for f in folders]
        self.assertEqual(len(systems), len(set(systems)))


    def test_226_cross_reference_platform_filter(self):
        """--platform restricts declarations to that platform alone."""
        from packs.crossref import global_report_scope, platform_configs

        with tempfile.TemporaryDirectory() as tmpdir:
            plat_dir = os.path.join(tmpdir, "platforms")
            os.makedirs(plat_dir)
            registry = {
                "platforms": {
                    "alpha": {"config": "alpha.yml"},
                    "beta": {"config": "beta.yml"},
                }
            }
            with open(os.path.join(plat_dir, "_registry.yml"), "w") as f:
                yaml.dump(registry, f)
            for name, fname in (("alpha", "a.bin"), ("beta", "b.bin")):
                cfg = {
                    "platform": name,
                    "verification_mode": "md5",
                    "systems": {"shared-system": {"files": [{"name": fname}]}},
                }
                with open(os.path.join(plat_dir, f"{name}.yml"), "w") as f:
                    yaml.dump(cfg, f)

            # Keyed by the normalized system ID, as profiles spell systems
            # differently from platforms.
            db = {"files": {}, "indexes": {}}
            everything, _ = global_report_scope(platform_configs(plat_dir), db, {})
            self.assertEqual(everything["sharedsystem"], {"a.bin", "b.bin"})

            only_alpha, _ = global_report_scope(platform_configs(plat_dir, ["alpha"]), db, {})
            self.assertEqual(only_alpha["sharedsystem"], {"a.bin"})


    def test_227_manifest_injected_compressed(self):
        """The manifest is deflated whichever injection path runs."""
        import json as _json

        from packs.finalize import inject_manifest

        manifest = {"files": [{"path": f"f{i}.bin"} for i in range(200)]}
        raw = _json.dumps(manifest, indent=2, ensure_ascii=False)
        sizes = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for preexisting in (False, True):
                path = os.path.join(tmpdir, f"pack{int(preexisting)}.zip")
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("bios.bin", b"x" * 4096)
                    if preexisting:
                        zf.writestr("manifest.json", "{}")
                inject_manifest(path, manifest)
                with zipfile.ZipFile(path) as zf:
                    info = zf.getinfo("manifest.json")
                    self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)
                    self.assertEqual(_json.loads(zf.read("manifest.json")), manifest)
                    sizes.append(info.compress_size)
        self.assertLess(sizes[0], len(raw))
        self.assertEqual(sizes[0], sizes[1])


if __name__ == "__main__":
    unittest.main()
