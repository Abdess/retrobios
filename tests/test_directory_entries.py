"""A profile entry that names a directory stands for the files under it.

Some cores read a whole tree: EasyRPG looks for an RTP under `rtp/2000/`,
O2EM for speech samples under `voice/`. The profile declares the directory,
the collection holds the files, and for a long time nothing joined the two:
the entry was resolved as one file called `rtp/2000/`, found nowhere, and
reported missing while 3 584 collected files stayed out of every pack.
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
import verify  # noqa: E402

PROFILE = """\
emulator: Demo
type: libretro
display_name: Demo
systems: [demo-system]
cores: [demo]
files:
  - name: "RTP 2000"
    path: "rtp/2000/"
    type: directory
    category: game_data
    required: false
  - name: "Fonts"
    path: "demo/Fonts/"
    type: directory
    category: game_data
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
        },
    },
}


class DirectoryFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bios = self.root / "bios"
        self.emulators = self.root / "emulators"
        self.platforms = self.root / "platforms"
        for directory in (self.bios, self.emulators, self.platforms):
            directory.mkdir()
        self.files: dict[str, dict] = {}
        self.sha1: dict[str, str] = {}

        self._add("SystemA/boot.bin", b"boot")
        self._add("Engine/demo/rtp/2000/Backdrop/a.png", b"backdrop")
        self._add("Engine/demo/rtp/2000/Music/b.mid", b"music")
        self._add("Engine/demo/rtp/2000/.variants/a.png.1234", b"older backdrop")

        (self.platforms / "demo.yml").write_text(yaml.dump(PLATFORM))
        (self.platforms / "_registry.yml").write_text(
            yaml.dump({"platforms": {"demo": {"status": "active"}}})
        )
        common._emulator_profiles_cache.clear()

    def tearDown(self):
        common._emulator_profiles_cache.clear()
        self._tmp.cleanup()

    def _add(self, relative: str, payload: bytes) -> None:
        path = self.bios / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        sha1 = hashlib.sha1(payload).hexdigest()
        self.sha1[relative] = sha1
        self.files[sha1] = {
            "path": f"bios/{relative}",
            "name": path.name,
            "size": len(payload),
            "sha1": sha1,
            "md5": hashlib.md5(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "crc32": f"{len(payload):08x}",
        }

    def _db(self) -> dict:
        """The index generate_db builds, over files stored where the test put them."""
        indexes = generate_db.build_indexes(self.files, {})
        stored = {
            sha1: {**record, "path": str(self.root / record["path"])}
            for sha1, record in self.files.items()
        }
        return {"files": stored, "indexes": indexes}

    def _profiles(self, body: str = PROFILE) -> dict:
        (self.emulators / "demo.yml").write_text(body)
        common._emulator_profiles_cache.clear()
        return common.load_emulator_profiles(str(self.emulators))


class DirectoryMembers(DirectoryFixture):
    def test_every_file_under_the_tail_is_a_member(self):
        self.assertEqual(
            common.directory_members(self._db(), "rtp/2000/"),
            {
                "rtp/2000/Backdrop/a.png": self.sha1[
                    "Engine/demo/rtp/2000/Backdrop/a.png"
                ],
                "rtp/2000/Music/b.mid": self.sha1["Engine/demo/rtp/2000/Music/b.mid"],
            },
        )

    def test_a_directory_nobody_collected_has_no_member(self):
        self.assertEqual(common.directory_members(self._db(), "demo/Fonts/"), {})

    def test_two_trees_answering_one_tail_prove_nothing(self):
        """`voice/` under two unrelated parents is two directories, and merging
        them would hand one emulator the other's files."""
        self._add("Console/voice/E480.WAV", b"speech")
        self._add("Other/app/voice/hello.wav", b"another program")
        self.assertEqual(common.directory_members(self._db(), "voice/"), {})

    def test_one_tree_under_a_generic_name_is_enough(self):
        self._add("Console/voice/E480.WAV", b"speech")
        self.assertEqual(
            common.directory_members(self._db(), "voice/"),
            {"voice/E480.WAV": self.sha1["Console/voice/E480.WAV"]},
        )


class CrossReferenceReadsADirectory(DirectoryFixture):
    def _report(self, body: str = PROFILE) -> list[dict]:
        profiles = self._profiles(body)
        return verify.find_undeclared_files(
            PLATFORM, str(self.emulators), self._db(), profiles
        )

    def test_each_held_file_is_reported_as_held(self):
        held = {
            entry["path"]: entry["sha1"]
            for entry in self._report()
            if entry["in_repo"]
        }
        self.assertEqual(
            held,
            {
                "rtp/2000/Backdrop/a.png": self.sha1[
                    "Engine/demo/rtp/2000/Backdrop/a.png"
                ],
                "rtp/2000/Music/b.mid": self.sha1["Engine/demo/rtp/2000/Music/b.mid"],
            },
        )

    def test_a_directory_with_nothing_collected_stays_one_gap(self):
        gaps = [entry for entry in self._report() if not entry["in_repo"]]
        self.assertEqual([(g["name"], g["path"]) for g in gaps], [("Fonts", "demo/Fonts/")])

    def test_a_file_the_profile_also_names_is_reported_once(self):
        body = PROFILE + (
            '  - name: "b.mid"\n'
            '    path: "rtp/2000/Music/b.mid"\n'
            "    category: game_data\n"
            "    required: true\n"
        )
        paths = [entry["path"] for entry in self._report(body)]
        self.assertEqual(paths.count("rtp/2000/Music/b.mid"), 1)


class PackCarriesADirectory(DirectoryFixture):
    EXPECTED = {"rtp/2000/Backdrop/a.png", "rtp/2000/Music/b.mid"}

    def test_a_platform_pack_ships_the_tree(self):
        profiles = self._profiles()
        out = self.root / "dist"
        out.mkdir()
        zip_path = builder.generate_pack(
            "demo", str(self.platforms), self._db(), str(self.bios), str(out),
            include_extras=True, emulators_dir=str(self.emulators),
            emu_profiles=profiles, offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            names = set(archive.namelist())
            self.assertEqual(
                archive.read("rtp/2000/Backdrop/a.png"), b"backdrop"
            )
        self.assertTrue(self.EXPECTED <= names, sorted(names))
        self.assertFalse([n for n in names if ".variants" in n])

    def test_the_install_manifest_lists_the_tree(self):
        profiles = self._profiles()
        manifest = builder.generate_manifest(
            "demo", str(self.platforms), self._db(), str(self.bios),
            str(self.platforms / "_registry.yml"),
            emulators_dir=str(self.emulators), emu_profiles=profiles,
            offline=True,
        )
        dests = {entry["dest"] for entry in manifest["files"]}
        self.assertTrue(self.EXPECTED <= dests, sorted(dests))
        json.dumps(manifest)

    def test_an_emulator_pack_ships_the_tree(self):
        self._profiles()
        out = self.root / "emu"
        out.mkdir()
        zip_path = builder.generate_emulator_pack(
            ["demo"], str(self.emulators), self._db(), str(self.bios), str(out),
            offline=True,
        )
        with zipfile.ZipFile(zip_path) as archive:
            names = set(archive.namelist())
        self.assertTrue(self.EXPECTED <= names, sorted(names))

    def test_verify_counts_what_the_emulator_pack_ships(self):
        self._profiles()
        result = verify.verify_emulator(["demo"], str(self.emulators), self._db())
        held = {
            detail["name"]
            for detail in result["details"]
            if detail["status"] == verify.Status.OK
        }
        self.assertEqual(held, self.EXPECTED)
        missing = [
            detail["name"]
            for detail in result["details"]
            if detail["status"] == verify.Status.MISSING
        ]
        self.assertEqual(missing, ["Fonts"])


class ProfileContract(unittest.TestCase):
    """One way to say an entry is a directory, so one place reads it."""

    def _errors(self, entry: dict) -> list[str]:
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (REPO_ROOT / "schemas" / "emulator.schema.json").read_text()
        )
        validator = Draft202012Validator(schema["properties"]["files"]["items"])
        return [error.message for error in validator.iter_errors(entry)]

    def test_a_name_that_is_a_directory_must_say_so(self):
        self.assertTrue(self._errors({"name": "voice/"}))
        self.assertEqual(self._errors({"name": "voice/", "type": "directory"}), [])

    def test_the_marker_takes_no_other_value(self):
        self.assertTrue(self._errors({"name": "RTP", "path": "rtp/", "type": "folder"}))

    def test_a_directory_is_written_with_its_trailing_slash(self):
        self.assertTrue(
            self._errors({"name": "RTP", "path": "rtp/2000", "type": "directory"})
        )
        self.assertEqual(
            self._errors({"name": "RTP", "path": "rtp/2000/", "type": "directory"}),
            [],
        )

    def test_every_profile_follows_it(self):
        offenders = []
        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in document.get("files") or []:
                if self._errors_for_directory_rules(entry):
                    offenders.append(f"{path.name}: {entry.get('name')}")
        self.assertEqual(offenders, [])

    @staticmethod
    def _errors_for_directory_rules(entry: dict) -> bool:
        name = str(entry.get("name", ""))
        path = entry.get("path")
        if entry.get("type") == "directory":
            return isinstance(path, str) and not path.endswith("/")
        return name.endswith("/") or "type" in entry


if __name__ == "__main__":
    unittest.main()
