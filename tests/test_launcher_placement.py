"""A platform's launcher moves where an emulator's file lands.

A profile's ``path`` is where the emulator's code reads a file. UAE4All2
reads kickstarts/<name> below its working directory, and RetroPie starts it
in its install directory, whose kickstarts/ it links to BIOS/amiga. The
pack, the manifest and verify all put the file in amiga/ on that platform,
and a platform with no such record keeps the profile's layout.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import io
import shutil
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    _emulator_profiles_cache,
    load_emulator_profiles,
    load_platform_config,
    platform_layouts,
    standalone_set,
)
from generate_pack import generate_manifest, generate_pack  # noqa: E402
from verify import verify_platform  # noqa: E402

WORKING_DIRECTORY = {
    "emulator": "kick", "build": "standalone", "kind": "passes_path", "names": [],
    "search_dir": "$md_inst", "passes_to": "working directory of $romdir/amiga/+Start.sh",
    "source_ref": "kick.sh:90",
}
LINK = {
    "emulator": "kick", "build": "standalone", "kind": "links", "names": [],
    "search_dir": "$biosdir/amiga", "passes_to": "$md_inst/kickstarts is a symlink to it",
    "source_ref": "kick.sh:79",
}


class ALinkMovesTheDestination(unittest.TestCase):
    def setUp(self) -> None:
        _emulator_profiles_cache.clear()
        (REPO_ROOT / "tmp").mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, self.root, True)
        bios = self.root / "bios" / "Commodore" / "Amiga"
        bios.mkdir(parents=True)
        data = b"KICKSTART 1.3"
        (bios / "kick13.rom").write_bytes(data)
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        self.db = {
            "files": {sha1: {
                "path": str(bios / "kick13.rom"), "name": "kick13.rom", "sha1": sha1,
                "md5": md5, "crc32": "", "size": len(data),
            }},
            "indexes": {
                "by_md5": {md5: sha1}, "by_name": {"kick13.rom": [sha1]},
                "by_crc32": {}, "by_path_suffix": {},
            },
        }
        self.platforms = self.root / "platforms"
        self.emulators = self.root / "emulators"
        self.platforms.mkdir()
        self.emulators.mkdir()
        for name, launchers in (("linkplat", [WORKING_DIRECTORY, LINK]), ("plainplat", [])):
            (self.platforms / f"{name}.yml").write_text(yaml.safe_dump({
                "platform": name, "version": "1", "verification_mode": "existence",
                "base_destination": "BIOS", "cores": ["kick"], "standalone_cores": ["kick"],
                "launchers": launchers,
                "systems": {"commodore-amiga": {"files": []}},
            }))
        (self.platforms / "_registry.yml").write_text(yaml.safe_dump({"platforms": {
            "linkplat": {"config": "linkplat.yml"}, "plainplat": {"config": "plainplat.yml"},
        }}))
        (self.emulators / "kick.yml").write_text(yaml.safe_dump({
            "emulator": "Kick", "type": "standalone", "cores": ["kick"],
            "systems": ["commodore-amiga"],
            "standalone_directories": ["getcwd"],
            "files": [{"name": "kick13.rom", "path": "kickstarts/kick13.rom",
                       "sha1": sha1, "required": False}],
        }))

    def pack_names(self, platform: str) -> list[str]:
        with redirect_stdout(io.StringIO()):
            zip_path = generate_pack(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.root / "out" / platform), emulators_dir=str(self.emulators),
                offline=True,
            )
        with zipfile.ZipFile(zip_path) as zf:
            return [n for n in zf.namelist() if n.endswith("kick13.rom")]

    def manifest_dests(self, platform: str) -> list[str]:
        with redirect_stdout(io.StringIO()):
            manifest = generate_manifest(
                platform, str(self.platforms), self.db, str(self.root / "bios"),
                str(self.platforms / "_registry.yml"),
                emulators_dir=str(self.emulators), offline=True,
            )
        return [f["dest"] for f in manifest["files"] if f["dest"].endswith("kick13.rom")]

    def verify_paths(self, platform: str) -> list[str]:
        config = load_platform_config(platform, str(self.platforms))
        result = verify_platform(config, self.db, str(self.emulators))
        return [u["path"] for u in result["undeclared_files"] if u["name"] == "kick13.rom"]

    def test_the_link_moves_it_in_pack_manifest_and_verify(self) -> None:
        self.assertEqual(self.pack_names("linkplat"), ["amiga/kick13.rom"])
        self.assertEqual(self.manifest_dests("linkplat"), ["amiga/kick13.rom"])
        self.assertEqual(self.verify_paths("linkplat"), ["amiga/kick13.rom"])

    def test_a_platform_without_the_record_is_unchanged(self) -> None:
        self.assertEqual(self.pack_names("plainplat"), ["kickstarts/kick13.rom"])
        self.assertEqual(self.manifest_dests("plainplat"), ["kickstarts/kick13.rom"])
        self.assertEqual(self.verify_paths("plainplat"), ["kickstarts/kick13.rom"])

    def test_the_link_alone_binds_nothing(self) -> None:
        # Without the working directory the link's $md_inst is not the
        # directory the profile's paths are relative to.
        config = {"standalone_cores": ["kick"], "launchers": [LINK]}
        profile = load_emulator_profiles(str(self.emulators))["kick"]
        (view, standalone), = platform_layouts("kick", profile, standalone_set(config))
        self.assertTrue(standalone)
        self.assertNotIn("standalone_path", view["files"][0])


class UAE4AllOnRetroPie(unittest.TestCase):
    """The real profile against the real launcher records."""

    def test_kickstarts_land_in_amiga(self) -> None:
        profile = load_emulator_profiles(str(REPO_ROOT / "emulators"))["uae4all"]
        config = load_platform_config("retropie", str(REPO_ROOT / "platforms"))
        (view, standalone), = platform_layouts("uae4all", profile, standalone_set(config))
        self.assertTrue(standalone)
        for entry in view["files"]:
            self.assertEqual(
                entry["standalone_path"], "amiga/" + entry["path"].removeprefix("kickstarts/")
            )


if __name__ == "__main__":
    unittest.main()
