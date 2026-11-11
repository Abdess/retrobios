"""Held pins name the build file that holds them.

pin_frozen was free prose and no tool read the build file it cites: a
platform moving mame0278 to another commit would have left the profile
holding a revision no platform builds, in silence. `pin_build` records the
file, and check_freshness reads it again where the platform now stands.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_freshness as cf  # noqa: E402

RECALBOX = "https://gitlab.com/recalbox/recalbox"


class HeldPinsReadTheirBuildFileAgain(unittest.TestCase):
    REF = {"platform": "recalbox", "repo": RECALBOX,
           "revision": "10.1.1", "path": "package/libretro-mame0278/libretro-mame0278.mk",
           "variable": "LIBRETRO_MAME0278_VERSION", "value": "a" * 40}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.platforms = Path(self._tmp.name)

    def _platform(self, revision: str) -> None:
        (self.platforms / "recalbox.yml").write_text(
            f'source: "{RECALBOX}/-/raw/{revision}/board/es_bios.xml"\n'
        )

    def _check(self, lines=None, offline=False):
        profiles = {"mame0278": {"pin_frozen": "Recalbox builds it.", "pin_build": [self.REF]},
                    "raine": {"pin_frozen": "RetroBat installs this release."}}
        with mock.patch.object(cf.upstream, "fetch_file", return_value=lines) as fetched:
            findings = cf.check_pin_builds(profiles, self.platforms, "cache", offline)
        return {f.subject: f for f in findings}, fetched

    def test_the_variable_forms_the_platforms_write(self):
        cases = [
            (["LIBRETRO_MAME0278_VERSION = fba5074"], "LIBRETRO_MAME0278_VERSION", "fba5074"),
            (['PKG_VERSION="37cddf2" #v0.6.3'], "PKG_VERSION", "37cddf2"),
            (['rp_module_repo="file $__archive_url/advancemame-1.4.tar.gz"'], "rp_module_repo",
             "file $__archive_url/advancemame-1.4.tar.gz"),
            (["function f() {", '    local version="20250829"', '    version="20250302"'],
             "version", "20250829"),
            (["OTHER_VERSION = 1"], "PKG_VERSION", None),
        ]
        for lines, variable, expected in cases:
            with self.subTest(variable=variable):
                self.assertEqual(cf.build_variable(lines, variable), expected)

    def test_the_platform_read_at_the_same_revision_needs_no_network(self):
        self._platform("10.1.1")
        found, fetched = self._check()
        fetched.assert_not_called()
        self.assertEqual(found["mame0278 (recalbox)"].status, cf.OK)

    def test_a_new_revision_building_another_commit_is_stale(self):
        self._platform("10.2")
        found, fetched = self._check([f"LIBRETRO_MAME0278_VERSION = {'b' * 40}"])
        self.assertEqual(fetched.call_args.args[1:3],
                         ("10.2", "package/libretro-mame0278/libretro-mame0278.mk"))
        row = found["mame0278 (recalbox)"]
        self.assertEqual(row.status, cf.STALE)
        self.assertIn("now builds " + "b" * 40, row.detail)

    def test_a_new_revision_building_the_same_commit_is_ok(self):
        self._platform("10.2")
        found, _ = self._check([f"LIBRETRO_MAME0278_VERSION = {'a' * 40}"])
        self.assertEqual(found["mame0278 (recalbox)"].status, cf.OK)

    def test_a_build_file_gone_is_stale(self):
        self._platform("10.2")
        found, _ = self._check(None)
        self.assertEqual(found["mame0278 (recalbox)"].status, cf.STALE)
        self.assertIn("is gone", found["mame0278 (recalbox)"].detail)

    def test_a_file_of_a_submodule_is_read_at_its_gitlink(self):
        """KNULLI builds Batocera's amiberry package through its batocera
        submodule: the file is not in knulli-linux's own tree."""
        self._platform("10.2")
        ref = {**self.REF, "path": "batocera/package/amiberry/amiberry.mk",
               "variable": "AMIBERRY_VERSION", "value": "v7.1.0"}
        modules = ['[submodule "batocera"]', "\tpath = batocera",
                   "\turl = https://github.com/batocera-linux/batocera.linux.git"]

        def fetch(repo, sha, path, *_args):
            if path == ".gitmodules":
                return modules
            if repo.slug == "batocera-linux/batocera.linux" and sha == "c" * 40:
                return ["AMIBERRY_VERSION = v7.1.0"]
            return None

        profiles = {"amiberry": {"pin_frozen": "x", "pin_build": [ref]}}
        with mock.patch.object(cf.upstream, "fetch_file", side_effect=fetch), \
                mock.patch.object(cf.upstream, "list_gitlinks", return_value={"batocera": "c" * 40}):
            (row,) = cf.check_pin_builds(profiles, self.platforms, "cache", False)
        self.assertEqual(row.status, cf.OK, row.detail)

    def test_offline_and_uncached_is_skipped(self):
        self._platform("10.2")
        profiles = {"mame0278": {"pin_frozen": "x", "pin_build": [self.REF]}}
        cold = cf.upstream.NotCachedError("not cached")
        with mock.patch.object(cf.upstream, "fetch_file", side_effect=cold):
            (row,) = cf.check_pin_builds(profiles, self.platforms, "cache", True)
        self.assertEqual(row.status, cf.SKIPPED)

    def test_a_hold_with_no_build_file_is_counted(self):
        self._platform("10.1.1")
        found, _ = self._check()
        row = found["pin_frozen without pin_build"]
        self.assertEqual(row.status, cf.SKIPPED)
        self.assertEqual(row.items, ["raine"])


class EveryBuildReferenceNamesThePin(unittest.TestCase):
    """Reads the repository: a pin_build value is what the platform builds,
    so it is the profile's source_commit or names its core_version, and the
    platform's own YAML was scraped from that repository."""

    def test_the_values_agree(self):
        from common import load_emulator_profiles

        disagree = []
        for name, profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).items():
            references = profile.get("pin_build") or []
            if not references:
                continue
            pins = profile.get("source_commit")
            pins = set(pins.values()) if isinstance(pins, dict) else {pins}
            versions = profile.get("core_version")
            versions = (
                {str(v) for v in versions.values()} if isinstance(versions, dict)
                else {str(versions)} if versions else set()
            )

            source = str(profile.get("source") or "").rstrip("/").removesuffix(".git")

            def names_it(value: str) -> bool:
                if profile.get("pin_follows"):
                    # A build of the branch tip names the repository it
                    # clones, at no revision: RetroPie's advmame.
                    return value.split()[-1].rstrip("/").removesuffix(".git") == source
                token = value.split()[-1].rsplit("/", 1)[-1].removesuffix(".tar.gz")
                return value in pins or any(token in v or v in value for v in versions)

            if not any(names_it(str(r["value"])) for r in references):
                disagree.append(name)
            for reference in references:
                if not cf.pin_build_revision(reference, REPO_ROOT / "platforms"):
                    disagree.append(f"{name}: {reference['platform']} is not read from "
                                    f"{reference['repo']}")
        self.assertEqual(disagree, [])


if __name__ == "__main__":
    unittest.main()
