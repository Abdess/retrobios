"""How many files a pack holds, said where the pack is downloaded.

The release notes opened on the size of the whole collection, 10 330 files,
right after "one pack per platform", and nothing anywhere gave the count of
one pack. A reader who extracted the RetroArch pack and found 4 525 files
concluded that more than half was missing, when the pack was complete. The
install manifest counted 1 872 for the same pack, because it lists what the
installer fetches and leaves out the data directories a pack also carries.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

try:
    import jsonschema  # noqa: F401
except ImportError:
    HAS_JSONSCHEMA = False
else:
    HAS_JSONSCHEMA = True

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
import generate_readme  # noqa: E402
import generate_site  # noqa: E402
import release_notes  # noqa: E402
import release_record  # noqa: E402
import split_pack  # noqa: E402

PROFILE = """\
emulator: Demo
type: libretro
display_name: Demo
systems: [demo-system]
cores: [demo]
files:
  - name: "extra.bin"
    required: false
"""

PLATFORM = {
    "platform": "Demo",
    "version": "2.1",
    "verification_mode": "existence",
    "base_destination": "",
    "cores": ["demo"],
    "systems": {
        "demo-system": {
            "files": [{"name": "boot.bin", "destination": "boot.bin"}],
            "data_directories": [{"ref": "demo-data", "destination": "demo"}],
        },
    },
}


class PackCountFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bios = self.root / "bios"
        self.emulators = self.root / "emulators"
        self.platforms = self.root / "platforms"
        self.data = self.root / "data" / "demo-data"
        for directory in (self.bios, self.emulators, self.platforms, self.data):
            directory.mkdir(parents=True)
        files: dict[str, dict] = {}
        for relative, payload in (
            ("SystemA/boot.bin", b"boot"),
            ("SystemA/extra.bin", b"extra file"),
        ):
            path = self.bios / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            files[sha1] = {
                "path": str(path),
                "name": path.name,
                "size": len(payload),
                "sha1": sha1,
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "crc32": f"{len(payload):08x}",
            }
        self.db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
        for name, payload in (("a.txt", b"one"), ("sub/b.txt", b"three"), ("c.txt", b"")):
            (self.data / name).parent.mkdir(parents=True, exist_ok=True)
            (self.data / name).write_bytes(payload)
        self.registry = {"demo-data": {"local_cache": str(self.data)}}
        (self.platforms / "demo.yml").write_text(yaml.dump(PLATFORM))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"demo": {"config": "demo.yml"}}})
        )
        (self.emulators / "demo.yml").write_text(PROFILE)
        common._emulator_profiles_cache.clear()
        self.profiles = common.load_emulator_profiles(str(self.emulators))

    def tearDown(self):
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def _manifest(self) -> dict:
        return builder.generate_manifest(
            "demo", str(self.platforms), self.db, str(self.bios),
            str(self.platforms / "_registry.yml"),
            emulators_dir=str(self.emulators), emu_profiles=self.profiles,
            offline=True, data_registry=self.registry,
        )


class ManifestStatesWhatThePackHolds(PackCountFixture):
    def test_the_count_is_the_one_an_extraction_shows(self):
        out = self.root / "dist"
        out.mkdir()
        zip_path = builder.generate_pack(
            "demo", str(self.platforms), self.db, str(self.bios), str(out),
            emulators_dir=str(self.emulators),
            emu_profiles=self.profiles, data_registry=self.registry,
            offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            members = archive.infolist()
        # manifest.json joins the archive when the pack is finalized.
        names = {member.filename for member in members} | {"manifest.json"}
        manifest = self._manifest()
        self.assertEqual(manifest["pack_files"], len(names))
        self.assertEqual(
            manifest["pack_size"],
            sum(
                member.file_size
                for member in members
                if member.filename not in builder.PACK_DOCUMENTS
            ),
        )

    def test_a_file_the_user_provides_counts_its_instructions(self):
        """The pack writes INSTRUCTIONS_<name>.txt in a user_provided slot;
        the manifest counted none, so the archive held one member more than
        pack_files said and release_record refused it."""
        platform = {**PLATFORM, "systems": {"demo-system": {
            **PLATFORM["systems"]["demo-system"],
            "files": PLATFORM["systems"]["demo-system"]["files"] + [
                {"name": "keys.bin", "destination": "keys.bin",
                 "storage": "user_provided", "instructions": "Dump your own."},
            ],
        }}}
        (self.platforms / "demo.yml").write_text(yaml.dump(platform))
        common._platform_config_cache.clear()
        self.addCleanup(common._platform_config_cache.clear)
        out = self.root / "dist"
        out.mkdir()
        zip_path = builder.generate_pack(
            "demo", str(self.platforms), self.db, str(self.bios), str(out),
            emulators_dir=str(self.emulators),
            emu_profiles=self.profiles, data_registry=self.registry,
            offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            members = archive.infolist()
        self.assertIn("INSTRUCTIONS_keys.bin.txt", {m.filename for m in members})
        manifest = self._manifest()
        self.assertEqual(
            manifest["pack_files"], len({m.filename for m in members} | {"manifest.json"})
        )
        self.assertEqual(
            manifest["pack_size"],
            sum(m.file_size for m in members if m.filename not in builder.PACK_DOCUMENTS),
        )

    def test_the_installer_count_is_left_alone(self):
        """install.py refuses a manifest whose total is not its list."""
        manifest = self._manifest()
        self.assertEqual(manifest["total_files"], len(manifest["files"]))
        self.assertEqual(manifest["total_files"], 2)
        self.assertEqual(manifest["pack_files"], 2 + 3 + len(builder.PACK_DOCUMENTS))

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_the_manifest_schema_accepts_the_two_figures(self):
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (REPO_ROOT / "schemas" / "install-manifest.schema.json").read_text()
        )
        # The fixture stores its files under a temporary directory, which
        # no entry of a real manifest does: only the document itself is judged.
        errors = [
            error.message
            for error in Draft202012Validator(schema).iter_errors(self._manifest())
            if not error.absolute_path
        ]
        self.assertEqual(errors, [])


class ManifestFollowsTheBuilder(PackCountFixture):
    """Two places where the pack carried a file the manifest left out.

    The release record compares each archive with the count its manifest
    expects, and the first comparison named both: four `pc6001*.zip` in the
    Batocera pack, two MSX2+ ROMs in the Recalbox pack.
    """

    def _platform(self, files: list[dict], mode: str = "md5") -> None:
        config = dict(PLATFORM, verification_mode=mode, cores=[])
        config["systems"] = {"demo-system": {"files": files}}
        (self.platforms / "demo.yml").write_text(yaml.dump(config))

    def _pack_names(self) -> set[str]:
        out = self.root / "dist"
        out.mkdir(exist_ok=True)
        zip_path = builder.generate_pack(
            "demo", str(self.platforms), self.db, str(self.bios), str(out),
            emulators_dir=str(self.emulators),
            emu_profiles=self.profiles, data_registry=self.registry,
            offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            return set(archive.namelist()) | {"manifest.json"}

    def test_an_archive_checked_by_the_rom_inside_it_is_listed(self):
        """Batocera pins the MD5 of a ROM inside the ZIP, not of the ZIP. The
        builder looked inside, the manifest did not, and an installation by
        script lost four required archives the pack shipped."""
        rom = b"rom inside the set"
        archive = self.bios / "SystemA" / "set.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("basic.rom", rom)
            # A second ROM, so the archive is not identified by the first.
            handle.writestr("chargen.rom", b"another rom of the set")
        raw = archive.read_bytes()
        sha1 = hashlib.sha1(raw).hexdigest()
        self.db["files"][sha1] = {
            "path": str(archive), "name": "set.zip", "size": len(raw),
            "sha1": sha1, "md5": hashlib.md5(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(), "crc32": "00000000",
        }
        self.db["indexes"] = generate_db.build_indexes(self.db["files"], {})
        self._platform([{
            "name": "set.zip", "destination": "set.zip",
            "md5": hashlib.md5(rom).hexdigest(), "zipped_file": "basic.rom",
        }])
        names = self._pack_names()
        self.assertIn("set.zip", names)
        manifest = self._manifest()
        self.assertIn("set.zip", {entry["dest"] for entry in manifest["files"]})
        self.assertEqual(manifest["pack_files"], len(names))

    def test_a_file_only_a_data_directory_holds_still_counts(self):
        """The installer cannot fetch it, so it stays out of the list. The
        pack carries it, so it is part of what an extraction shows."""
        (self.data / "Machines").mkdir()
        (self.data / "Machines" / "Msx2pe.rom").write_bytes(b"machine rom")
        self._platform([{
            "name": "Msx2pe.rom", "destination": "Machines/Msx2pe.rom",
            "md5": hashlib.md5(b"machine rom").hexdigest(),
        }])
        names = self._pack_names()
        self.assertIn("Machines/Msx2pe.rom", names)
        manifest = self._manifest()
        self.assertNotIn(
            "Machines/Msx2pe.rom", {entry["dest"] for entry in manifest["files"]}
        )
        self.assertEqual(manifest["pack_files"], len(names))


RECORD = {
    "tag": "v2026.09.04",
    "packs": {
        "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip": {
            "files": 4525,
            "extracted_size": 5882727352,
            "download_size": 3349430771,
            "assets": [
                "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip.001",
                "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip.002",
            ],
            "platforms": ["lakka", "retroarch"],
        },
        "MiSTer_FPGA_2026-08-29_BIOS_Pack.zip": {
            "files": 74,
            "extracted_size": 17000000,
            "download_size": 16769418,
            "assets": ["MiSTer_FPGA_2026-08-29_BIOS_Pack.zip"],
            "platforms": ["misterfpga"],
        },
    },
}


class APackForAndroidHidesItsMedia(PackCountFixture):
    """RetroArch Android writes no .nomedia, and its system folder held the
    samples, overlays and videos the gallery and music apps then showed."""

    def _pack(self, target: str | None) -> dict[str, int]:
        targets = self.platforms / "targets"
        targets.mkdir(exist_ok=True)
        (targets / "demo.yml").write_text(yaml.dump({"platform": "demo", "targets": {
            "android-arm64-v8a": {"architecture": "aarch64", "cores": ["demo"]},
            "linux-x86_64": {"architecture": "x86_64", "cores": ["demo"]},
        }}))
        out = self.root / f"dist-{target}"
        out.mkdir()
        zip_path = builder.generate_pack(
            "demo", str(self.platforms), self.db, str(self.bios), str(out),
            emulators_dir=str(self.emulators), emu_profiles=self.profiles,
            data_registry=self.registry, offline=True, target_name=target,
        )
        with zipfile.ZipFile(zip_path) as archive:
            return {m.filename: m.file_size for m in archive.infolist()}

    def test_the_whole_pack_and_an_android_one_carry_it(self):
        for target in (None, "android-arm64-v8a"):
            with self.subTest(target=target):
                self.assertEqual(self._pack(target).get(".nomedia"), 0)

    def test_a_pack_for_another_target_does_not(self):
        self.assertNotIn(".nomedia", self._pack("linux-x86_64"))

    def test_the_manifest_counts_it(self):
        members = self._pack(None)
        manifest = builder.generate_manifest(
            "demo", str(self.platforms), self.db, str(self.bios),
            str(self.platforms / "_registry.yml"),
            emulators_dir=str(self.emulators), emu_profiles=self.profiles,
            offline=True, data_registry=self.registry,
        )
        self.assertEqual(manifest["pack_files"], len(set(members) | {"manifest.json"}))

    def test_the_integrity_check_takes_it_for_a_marker(self):
        import packverify

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(".nomedia", b"")
            archive.writestr("empty.bin", b"")
        with zipfile.ZipFile(buffer) as archive:
            errors = packverify._structural_errors(archive, set(archive.namelist()))
        self.assertEqual(errors, ["zero-byte: empty.bin"])

    def test_a_platform_without_android_gets_none(self):
        self.assertEqual(builder.pack_markers("demo", None, str(self.platforms)), ())


class TheTableDescribesTheRelease(unittest.TestCase):
    """The Download link gives the last release, not what main would build.

    The install manifest of main already counted 8 225 files for RetroArch
    while the published pack held 4 525: printed beside the link, the newer
    figure would have sent the next reader looking for 3 700 missing files.
    """

    def test_a_platform_reads_the_pack_that_serves_it(self):
        for platform in ("retroarch", "lakka"):
            self.assertEqual(
                generate_readme.release_totals(platform, RECORD),
                (4525, 5882727352),
            )
        self.assertEqual(
            generate_readme.release_totals("misterfpga", RECORD), (74, 17000000)
        )

    def test_a_platform_the_release_does_not_carry_has_no_figure(self):
        self.assertEqual(
            generate_readme.release_totals("vita3k", RECORD), (None, None)
        )
        self.assertEqual(generate_readme.release_totals("retroarch", {}), (None, None))

    def test_the_download_table_gives_the_file_count_of_each_pack(self):
        rows = generate_readme.download_table(
            {"retroarch": {"platform": "RetroArch"}, "vita3k": {"platform": "Vita3K"}},
            {"RetroArch": "`system/`"},
            RECORD,
        )
        self.assertIn("| Platform | Files | Extracted size |", rows[0])
        self.assertIn("| RetroArch | 4,525 | 5.5 GB | `system/` |", rows[2])
        self.assertIn("| Vita3K | - | - |", rows[3])

    def test_the_committed_record_is_the_one_the_readme_prints(self):
        record_path = REPO_ROOT / "release.json"
        if not record_path.is_file():
            self.skipTest("no release.json")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        files, _size = generate_readme.release_totals("retroarch", record)
        self.assertTrue(f"| RetroArch | {files:,} |" in readme)


def _incompressible(seed: int) -> bytes:
    """960 bytes deflate cannot shrink, so a member outweighs a part marker."""
    return b"".join(hashlib.sha256(bytes([seed, n])).digest() for n in range(30))


class ReleaseRecord(unittest.TestCase):
    OWNERS = {
        "Whole_1.0_BIOS_Pack.zip": ["whole"],
        "Demo_2.0_BIOS_Pack.zip": ["demo"],
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self._tmp.name) / "dist"
        self.dist.mkdir()
        self.install = Path(self._tmp.name) / "install"
        self.install.mkdir()
        self._pack("Whole_1.0_BIOS_Pack.zip", {"a.bin": b"a" * 10, "README.txt": b"r"})
        big = self._pack(
            "Demo_2.0_BIOS_Pack.zip",
            {f"dir/file{n}.bin": _incompressible(n) for n in range(6)},
        )
        self.parts = split_pack.split_pack(big, limit=big.stat().st_size - 1)

    def tearDown(self):
        self._tmp.cleanup()

    def _pack(self, name: str, members: dict[str, bytes]) -> Path:
        path = self.dist / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for member, data in members.items():
                archive.writestr(member, data)
        return path

    def test_a_pack_in_parts_is_counted_once_across_them(self):
        record = release_record.build_record(self.dist, "v1", owners=self.OWNERS)
        self.assertEqual(record["tag"], "v1")
        demo = record["packs"]["Demo_2.0_BIOS_Pack.zip"]
        self.assertEqual(demo["files"], 6)
        self.assertEqual(demo["extracted_size"], 6 * 960)
        self.assertEqual(demo["assets"], [part.name for part in self.parts])
        self.assertEqual(
            demo["download_size"], sum(part.stat().st_size for part in self.parts)
        )
        self.assertEqual(record["packs"]["Whole_1.0_BIOS_Pack.zip"]["files"], 2)

    def test_a_pack_that_disagrees_with_its_manifest_is_named(self):
        """The count main predicts and the count the archive holds are two
        computations of one thing. Apart, one of them is wrong."""
        record = release_record.build_record(self.dist, "v1", owners=self.OWNERS)
        (self.install / "demo.json").write_text(json.dumps({"pack_files": 6}))
        (self.install / "whole.json").write_text(json.dumps({"pack_files": 5}))
        self.assertEqual(
            release_record.manifest_mismatches(record, self.install),
            ["Whole_1.0_BIOS_Pack.zip holds 2 files, install/whole.json expects 5"],
        )


    def test_a_pack_beside_its_parts_is_refused(self):
        """A split reading its parts back, or one killed before removing the
        pack, leaves both: summed, the download size doubled."""
        self._pack(
            "Demo_2.0_BIOS_Pack.zip",
            {f"dir/file{n}.bin": _incompressible(n) for n in range(6)},
        )
        with self.assertRaises(release_record.UnfinishedSplitError):
            release_record.build_record(self.dist, "v1", owners=self.OWNERS)

    def test_a_narrowed_pack_is_refused_not_recorded(self):
        """A pack that sorts before the full one (Android targets, Asia) was
        taken for the platform's pack by a substring match."""
        self._pack("Whole_1.0_Asia_BIOS_Pack.zip", {"a.bin": b"a"})
        with self.assertRaises(release_record.NotAReleasePackError) as raised:
            release_record.build_record(self.dist, "v1", owners=self.OWNERS)
        self.assertIn("Whole_1.0_Asia_BIOS_Pack.zip", str(raised.exception))

    def test_a_platform_finds_the_pack_that_serves_it_by_name(self):
        record = release_record.build_record(self.dist, "v1", owners=self.OWNERS)
        record["packs"]["Whole_1.0_AAA_BIOS_Pack.zip"] = dict(
            record["packs"]["Whole_1.0_BIOS_Pack.zip"], files=99, platforms=["other"]
        )
        self.assertEqual(
            release_record.pack_name_for("whole", record), "Whole_1.0_BIOS_Pack.zip"
        )
        self.assertEqual(release_record.pack_for("whole", record)["files"], 2)

    def test_the_owners_are_the_full_pack_names_the_builder_writes(self):
        owners = release_record.release_owners(str(REPO_ROOT / "platforms"))
        retroarch = [name for name, serves in owners.items() if "retroarch" in serves]
        self.assertEqual(len(retroarch), 1, retroarch)
        for tags in ("_AndroidArm64V8A", "_Asia", "_Required"):
            narrowed = retroarch[0].replace("_BIOS_Pack.zip", f"{tags}_BIOS_Pack.zip")
            self.assertNotIn(narrowed, owners)

    def test_a_directory_being_written_is_not_read(self):
        with common.artifact_lock(str(self.dist)), \
                self.assertRaises(common.ArtifactLockBusy):
            release_record.build_record(self.dist, "v1", owners=self.OWNERS)


class TheCollectionTotalNamesTheCollection(unittest.TestCase):
    COMPOSITION = {
        "systems": {"files": 5030},
        "arcade": {"files": 2806},
        "game_data": {"files": 2539},
    }

    def test_in_the_readme(self):
        line = generate_readme.collection_line(10375, self.COMPOSITION)
        self.assertIn("**10,375 files in the collection**", line)
        self.assertIn("no pack holds them all", line)

    def test_on_the_site(self):
        db = {
            "total_files": 10375,
            "files": {},
            "indexes": {},
        }
        sentence = generate_site.composition_sentence(db)
        self.assertTrue(sentence.startswith("The collection"), sentence)
        self.assertEqual(generate_site.COLLECTION_FILES_LABEL, "Files collected")


class RefusedFilesAreNotPresent(unittest.TestCase):
    """RetroDECK's dsifirmware.bin is held, but its declared hash contradicts
    the local copy, so the md5 builder leaves it out. The README still
    printed 2,008/2,008 for a pack that carries 2,007."""

    def test_the_coverage_subtracts_a_refused_file(self):
        import os

        import common
        import generate_db
        import generate_readme

        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, previous)
            for d in ("bios/X", "platforms", "emulators"):
                Path(d).mkdir(parents=True)
            files = {}
            for name in ("good.bin", "wrong.bin"):
                payload = name.encode()
                Path(f"bios/X/{name}").write_bytes(payload)
                sha1 = hashlib.sha1(payload).hexdigest()
                files[sha1] = {
                    "path": f"bios/X/{name}", "name": name, "size": len(payload),
                    "sha1": sha1, "md5": hashlib.md5(payload).hexdigest(),
                    "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001",
                }
            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            config = {
                "platform": "Hashy", "version": "2.1", "verification_mode": "md5", "base_destination": "bios",
                "systems": {"sys": {"files": [
                    {"name": "good.bin", "destination": "good.bin",
                     "md5": hashlib.md5(b"good.bin").hexdigest()},
                    {"name": "wrong.bin", "destination": "wrong.bin", "md5": "f" * 32},
                ]}},
            }
            Path("platforms/hashy.yml").write_text(yaml.dump(config))
            Path("platforms/_registry.yml").write_text(
                yaml.dump({"platforms": {"hashy": {"config": "hashy.yml"}}})
            )
            common._platform_config_cache.clear()
            self.addCleanup(common._platform_config_cache.clear)
            coverage = generate_readme.compute_coverage(
                "hashy", "platforms", db, emulators_dir="emulators"
            )
        self.assertEqual((coverage["present"], coverage["total"]), (1, 2))


class TheReleaseNotesReadTheRecord(unittest.TestCase):
    """The notes' pack table was typed by hand from release.json: a copied
    cell or an old collection total at the top reproduced issue 81."""

    RECORD = {"tag": "v2026.10.10", "packs": {
        "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip": {
            "files": 8504, "extracted_size": 6_400_000_000, "download_size": 4_000_000_000,
            "assets": ["RetroArch_Lakka_v1.22.2_BIOS_Pack.part1of2.zip",
                       "RetroArch_Lakka_v1.22.2_BIOS_Pack.part2of2.zip"],
            "platforms": ["lakka", "retroarch"]},
        "EmuDeck_2.7EA_BIOS_Pack.zip": {
            "files": 620, "extracted_size": 3_500_000_000, "download_size": 3_000_000_000,
            "assets": ["EmuDeck_2.7EA_BIOS_Pack.zip"], "platforms": ["emudeck"]},
    }}

    def render(self, record=None):
        return release_notes.render(record or self.RECORD, str(REPO_ROOT / "platforms"),
                                    "### What changed\n\n- x\n")

    def test_each_pack_row_carries_the_record(self):
        text = self.render()
        row = next(line for line in text.splitlines() if line.startswith("| RetroArch"))
        self.assertIn("8,504", row)
        self.assertIn("[Download, 2 parts](https://abdess.github.io/retrobios/get/retroarch/)", row)
        self.assertNotIn("/releases/download/", row)
        self.assertIn("`system/`", row)
        self.assertIn("| Platform | Download | Extracted size | Files |", text)

    def test_the_parts_sentence_sits_above_the_table_only_when_needed(self):
        text = self.render()
        self.assertLess(text.index("ordinary ZIP"), text.index("| Platform"))
        whole = {"tag": "v1", "packs": {"EmuDeck_2.7EA_BIOS_Pack.zip":
                                        self.RECORD["packs"]["EmuDeck_2.7EA_BIOS_Pack.zip"]}}
        self.assertNotIn("ordinary ZIP", self.render(whole))

    def test_the_notes_never_open_on_the_collection(self):
        self.assertNotIn("collection", self.render().split("### What changed")[0])

    def test_the_notes_claim_only_what_the_gaps_allow(self):
        """v2026.10.10 said a pack holds every file its emulators open, "so a
        game never stops on a missing file", and that hashes never come
        "from a forum list". The gap analysis lists what no pack carries."""
        text = self.render().split("### What changed")[0]
        self.assertNotIn("every file its emulators", text)
        self.assertIn("https://abdess.github.io/retrobios/gaps/", text)
        self.assertEqual(release_notes.refused_words(text), [])

    def test_a_judging_whats_new_is_refused(self):
        self.assertEqual(
            release_notes.refused_words(
                "- Every hash comes from the emulator's source, never from a forum list.\n"
                "- So a game never stops on a missing file."),
            ["forum", "never stops"])
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            whats_new = Path(tmp) / "whats-new.md"
            whats_new.write_text("- Hashes never from a forum list\n", encoding="utf-8")
            record = Path(tmp) / "release.json"
            record.write_text(json.dumps(self.RECORD), encoding="utf-8")
            argv = ["release_notes.py", "--record", str(record), "--whats-new", str(whats_new),
                    "--platforms-dir", str(REPO_ROOT / "platforms"),
                    "--output", str(Path(tmp) / "notes.md")]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                self.assertEqual(release_notes.main(), 1)
            self.assertIn("'forum'", err.getvalue())
            self.assertFalse((Path(tmp) / "notes.md").exists())

    def test_the_release_process_runs_it(self):
        page = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn("scripts/release_notes.py", page)


class CoreCopiesKeepTheirCategory(unittest.TestCase):
    """The second pass copies a file the platform declares to the path a core
    reads it from. Its extra named no gap report entry, so verify looked its
    category up by an empty key and counted RetroArch's six hiscore.dat
    copies, game data, under core files."""

    def test_a_copy_counts_as_its_entry_says(self):
        from packextras import _collect_emulator_extras, hidden_extras

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            held = Path(tmp) / "x.dat"
            held.write_bytes(b"data")
            sha1 = hashlib.sha1(b"data").hexdigest()
            config = {"platform": "P", "_key": "p", "cores": ["demo"], "systems": {
                "s": {"files": [{"name": "x.dat", "destination": "x.dat"}]}}}
            profiles = {"demo": {
                "emulator": "Demo", "type": "libretro", "cores": ["demo"],
                "systems": ["s"],
                "files": [{"name": "x.dat", "path": "core/x.dat",
                           "category": "game_data"}],
            }}
            db = {"files": {sha1: {"path": str(held), "name": "x.dat", "sha1": sha1}},
                  "indexes": {"by_name": {"x.dat": [sha1]}, "by_path_suffix": {}}}
            (extra,) = _collect_emulator_extras(
                config, "emulators", db, {"x.dat"}, "", profiles
            )
            self.assertEqual(
                (extra["source_name"], extra["source_path"], extra["category"]),
                ("x.dat", "core/x.dat", "game_data"),
            )
            kinds: dict[str, str] = {}
            hidden_extras(config, "emulators", db, profiles, {"x.dat": str(held)},
                          report=[], placed_kind=kinds)
        self.assertEqual(kinds, {"core/x.dat": "game_data"})


if __name__ == "__main__":
    unittest.main()
