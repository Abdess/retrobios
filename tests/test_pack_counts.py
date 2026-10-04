"""How many files a pack holds, said where the pack is downloaded.

The release notes opened on the size of the whole collection, 10 330 files,
right after "one pack per platform", and nothing anywhere gave the count of
one pack. A reader who extracted the RetroArch pack and found 4 525 files
concluded that more than half was missing, when the pack was complete. The
install manifest counted 1 872 for the same pack, because it lists what the
installer fetches and leaves out the data directories a pack also carries.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import common  # noqa: E402
import generate_db  # noqa: E402
import generate_pack as builder  # noqa: E402
import generate_readme  # noqa: E402
import generate_site  # noqa: E402
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
            yaml.dump({"platforms": {"demo": {"status": "active"}}})
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
            include_extras=True, emulators_dir=str(self.emulators),
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

    def test_the_installer_count_is_left_alone(self):
        """install.py refuses a manifest whose total is not its list."""
        manifest = self._manifest()
        self.assertEqual(manifest["total_files"], len(manifest["files"]))
        self.assertEqual(manifest["total_files"], 2)
        self.assertEqual(manifest["pack_files"], 2 + 3 + len(builder.PACK_DOCUMENTS))

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
        },
        "MiSTer_FPGA_2026-08-29_BIOS_Pack.zip": {
            "files": 74,
            "extracted_size": 17000000,
            "download_size": 16769418,
            "assets": ["MiSTer_FPGA_2026-08-29_BIOS_Pack.zip"],
        },
    },
}


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
            set(),
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


class ReleaseRecord(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dist = Path(self._tmp.name) / "dist"
        self.dist.mkdir()
        self.install = Path(self._tmp.name) / "install"
        self.install.mkdir()
        self._pack("Whole_1.0_BIOS_Pack.zip", {"a.bin": b"a" * 10, "README.txt": b"r"})
        big = self._pack(
            "Demo_2.0_BIOS_Pack.zip",
            {f"dir/file{n}.bin": bytes([n]) * 700 + bytes(range(256)) for n in range(6)},
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
        record = release_record.build_record(self.dist, "v1")
        self.assertEqual(record["tag"], "v1")
        demo = record["packs"]["Demo_2.0_BIOS_Pack.zip"]
        self.assertEqual(demo["files"], 6)
        self.assertEqual(demo["extracted_size"], 6 * (700 + 256))
        self.assertEqual(demo["assets"], [part.name for part in self.parts])
        self.assertEqual(
            demo["download_size"], sum(part.stat().st_size for part in self.parts)
        )
        self.assertEqual(record["packs"]["Whole_1.0_BIOS_Pack.zip"]["files"], 2)

    def test_a_pack_that_disagrees_with_its_manifest_is_named(self):
        """The count main predicts and the count the archive holds are two
        computations of one thing. Apart, one of them is wrong."""
        record = release_record.build_record(self.dist, "v1")
        (self.install / "demo.json").write_text(json.dumps({"pack_files": 6}))
        (self.install / "whole.json").write_text(json.dumps({"pack_files": 5}))
        self.assertEqual(
            release_record.manifest_mismatches(record, self.install),
            ["Whole_1.0_BIOS_Pack.zip holds 2 files, install/whole.json expects 5"],
        )


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


if __name__ == "__main__":
    unittest.main()
