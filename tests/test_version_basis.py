"""core_version is read from the code at the pin, where version_basis says.

Four bulk pin advances moved 295 pins and no version, and 54 profiles said
"Git" or "SVN" where the code states a release. These tests read the
recorded sources offline from a fixture of forge answers, hold every profile
to a basis, and hold a pin advance to reading the version again.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import contextlib
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import profile_sync  # noqa: E402
import upstream  # noqa: E402
import version_basis  # noqa: E402
from common import load_emulator_profiles  # noqa: E402
from profile_sync import ProfileReport, bump_commit  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "version_basis.json"


def _fixture_cache(directory: Path) -> dict:
    """The fixture's forge answers, laid out as upstream caches them."""
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for url, payload in data["api"].items():
        target = directory / "_api" / f"{hashlib.sha256(url.encode()).hexdigest()}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(upstream.ABSENT if payload is None else json.dumps(payload),
                          encoding="utf-8")
    for key, text in data["files"].items():
        host, owner, name, sha, path = key.split("/", 4)
        repo = upstream.make_repo(host, owner, name)
        target = upstream.cache_path(str(directory), repo, sha, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(upstream.ABSENT if text is None else text, encoding="utf-8")
    return data["profiles"]


class ReadsTheRecordedSourceOffline(unittest.TestCase):
    """The check needs nothing the cache does not hold."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cache"
        self.profiles = _fixture_cache(self.cache)

    def tearDown(self):
        self.tmp.cleanup()

    def _check(self, name: str, profiles: dict | None = None) -> list:
        profiles = profiles or self.profiles
        return version_basis.check(profiles[name], str(self.cache), True, profiles)

    def test_every_kind_reads_its_version(self):
        for name in self.profiles:
            with self.subTest(profile=name):
                readings = self._check(name)
                self.assertEqual([r.status for r in readings], [version_basis.MATCH],
                                 readings)

    def test_a_file_basis_names_the_line_it_read(self):
        (reading,) = self._check("snes9x")
        self.assertEqual(reading.read, "1.63")
        self.assertTrue(reading.where.endswith("snes9x.h:11"), reading.where)

    def test_groups_are_laid_out_by_the_format(self):
        (reading,) = self._check("fbneo")
        self.assertEqual(reading.read, "v1.0.0.03")

    def test_a_version_the_code_does_not_state_is_drift(self):
        for name, stale in (("snes9x", "1.61"), ("fbneo", "v1.0.0.2"),
                            ("dolphin", "2609"), ("mednafen_psx", "v0.9.44"),
                            ("anarch", "Git")):
            with self.subTest(profile=name):
                profiles = copy.deepcopy(self.profiles)
                profiles[name]["core_version"] = stale
                (reading,) = self._check(name, profiles)
                self.assertEqual(reading.status, version_basis.DRIFT)

    def test_a_tag_distance_the_forge_contradicts_is_drift(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["dolphin"]["version_basis"]["distance"] = 400
        (reading,) = self._check("dolphin", profiles)
        self.assertEqual(reading.status, version_basis.DRIFT)
        self.assertEqual(dict(reading.updates)["distance"], 437)

    def test_a_pattern_that_no_longer_matches_is_unreadable(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["snes9x"]["version_basis"]["pattern"] = "#define\\s+NOPE\\s+(\\S+)"
        (reading,) = self._check("snes9x", profiles)
        self.assertEqual(reading.status, version_basis.UNREADABLE)

    def test_a_profile_without_basis_is_reported(self):
        profiles = copy.deepcopy(self.profiles)
        del profiles["snes9x"]["version_basis"]
        (reading,) = self._check("snes9x", profiles)
        self.assertEqual(reading.status, version_basis.NO_BASIS)

    def test_the_command_fails_on_drift_and_passes_clean(self):
        emulators = Path(self.tmp.name) / "emulators"
        emulators.mkdir()
        for name, profile in self.profiles.items():
            body = dict(profile, files=[] if profile["type"] != "alias" else None)
            body = {k: v for k, v in body.items() if v is not None or k == "core_version"}
            (emulators / f"{name}.yml").write_text(yaml.safe_dump(body), encoding="utf-8")
        argv = ["profile_sync.py", "--all", "--verify-version", "--offline",
                "--emulators-dir", str(emulators), "--cache-dir", str(self.cache)]

        def run() -> int:
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                try:
                    profile_sync.main()
                except SystemExit as exc:
                    return int(exc.code or 0)
            return 0

        import common  # noqa: PLC0415

        common._emulator_profiles_cache.clear()
        self.assertEqual(run(), 0)
        stale = emulators / "snes9x.yml"
        stale.write_text(stale.read_text(encoding="utf-8").replace("1.63", "1.61"),
                         encoding="utf-8")
        common._emulator_profiles_cache.clear()
        self.assertEqual(run(), 1)


class EveryProfileSaysWhereItsVersionIsRead(unittest.TestCase):
    """What can be held without a forge is held here, for every profile."""

    @classmethod
    def setUpClass(cls):
        cls.profiles = load_emulator_profiles(str(ROOT / "emulators"), skip_aliases=False)

    def test_every_profile_has_a_basis(self):
        missing = sorted(name for name, p in self.profiles.items()
                         if not version_basis.bases(p))
        self.assertEqual(missing, [], "profiles without version_basis")

    def test_no_placeholder_is_a_version(self):
        named = sorted(
            name for name, p in self.profiles.items()
            for mode in (version_basis.bases(p) or {"": {}})
            if version_basis.is_placeholder(version_basis.declared(p, mode))
        )
        self.assertEqual(named, [])

    def test_keyed_bases_follow_the_keyed_version(self):
        for name, profile in self.profiles.items():
            found = version_basis.bases(profile)
            if not found or "" in found:
                continue
            with self.subTest(profile=name):
                self.assertIsInstance(profile.get("core_version"), dict)
                self.assertEqual(set(found), set(profile["core_version"]))

    def test_none_states_no_version(self):
        for name, profile in self.profiles.items():
            for mode, basis in version_basis.bases(profile).items():
                if basis.get("kind") == "none":
                    with self.subTest(profile=name, mode=mode):
                        self.assertIsNone(version_basis.declared(profile, mode))

    def test_a_tag_version_is_the_describe_form_of_its_pin(self):
        for name, profile in self.profiles.items():
            for mode, basis in version_basis.bases(profile).items():
                if basis.get("kind") != "tag" or basis.get("url"):
                    continue
                field = version_basis.PIN_FIELDS[str(basis.get("repo") or "source")]
                pin = version_basis._by_mode(profile, field, mode)
                if not pin:
                    continue
                with self.subTest(profile=name, mode=mode):
                    self.assertEqual(
                        version_basis.declared(profile, mode),
                        version_basis.describe_form(basis["tag"], basis["distance"], pin),
                    )

    def test_an_alias_carries_the_version_of_its_profile(self):
        for name, profile in self.profiles.items():
            for mode, basis in version_basis.bases(profile).items():
                if basis.get("kind") != "alias":
                    continue
                with self.subTest(profile=name):
                    (reading,) = [r for r in version_basis.check(
                        profile, "", True, self.profiles) if r.mode == mode]
                    self.assertEqual(reading.status, version_basis.MATCH, reading)

    def test_a_package_named_after_its_version_states_it(self):
        for name, profile in self.profiles.items():
            for mode, basis in version_basis.bases(profile).items():
                if basis.get("kind") != "package" or not basis.get("pattern"):
                    continue
                with self.subTest(profile=name):
                    (reading,) = [r for r in version_basis.check(profile, "", True)
                                  if r.mode == mode]
                    self.assertEqual(reading.status, version_basis.MATCH, reading)


SAMPLE = """emulator: Sample
type: libretro
source: "https://github.com/o/n"
profiled_date: "2026-01-01"
source_commit: "aaaaaaa"
core_version: "1.0"
version_basis:
  kind: file
  path: "version.h"
  pattern: '#define\\s+VERSION\\s+"([^"]+)"'
files: []
"""


class AnAdvanceReadsTheVersionAgain(unittest.TestCase):
    """A pin never moves without its version: read again, or refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")
        self.report = ProfileReport(
            name="p", repo="o/n", pin="aaaaaaa", head="bbbbbbb", entries=[], counts={},
            skipped=profile_sync.NO_SOURCE_REF,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _reading(self, status: str, value: str | None):
        return version_basis.Reading("", "file", "1.0", value, "o/n@bbbbbbb:version.h:3", status)

    def test_the_version_moves_with_the_pin(self):
        seen = []

        def check(profile, cache_dir, offline, profiles=None, recompute=False):
            seen.append((profile["source_commit"], recompute))
            return [self._reading(version_basis.DRIFT, "2.0")]

        with mock.patch.object(version_basis, "check", check):
            self.assertTrue(bump_commit(self.path, self.report))
        written = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.assertEqual(written["source_commit"], "bbbbbbb")
        self.assertEqual(written["core_version"], "2.0")
        # Read at the new pin, the nearest tag asked again.
        self.assertEqual(seen, [("bbbbbbb", True)])

    def test_an_unreadable_version_holds_the_pin(self):
        with mock.patch.object(version_basis, "check",
                               return_value=[self._reading(version_basis.UNREADABLE, None)]):
            self.assertFalse(bump_commit(self.path, self.report))
        self.assertEqual(self.path.read_text(encoding="utf-8"), SAMPLE)

    def test_a_profile_without_basis_is_not_advanced(self):
        self.path.write_text(SAMPLE.split("version_basis:")[0] + "files: []\n", encoding="utf-8")
        before = self.path.read_text(encoding="utf-8")
        self.assertFalse(bump_commit(self.path, self.report))
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_a_package_version_is_advanced_by_hand(self):
        reading = version_basis.Reading("", "package", "1.0", None, "read from x.apk",
                                        version_basis.UNCHECKED)
        with mock.patch.object(version_basis, "check", return_value=[reading]):
            self.assertFalse(bump_commit(self.path, self.report))


class TheWriterKeepsTheDocument(unittest.TestCase):
    def test_keyed_versions_and_bases_round_trip(self):
        text = ('emulator: X\nsource_commit: "abc"\ncore_version:\n  standalone: "1"\n'
                '  libretro: "2"\ndisplay_name: X\n')
        basis = {"standalone": {"kind": "tag", "tag": "2407", "distance": 0},
                 "libretro": {"kind": "none"}}
        written = profile_sync.set_version_fields(
            text, {"standalone": "2407", "libretro": None}, basis)
        document = yaml.safe_load(written)
        self.assertEqual(document["core_version"], {"standalone": "2407", "libretro": None})
        self.assertEqual(document["version_basis"], basis)
        self.assertEqual(document["display_name"], "X")
        self.assertIn('tag: "2407"', written)

    def test_a_missing_version_is_written_after_the_pins(self):
        text = 'emulator: X\nsource_commit: "abc"\nfiles: []\n'
        written = profile_sync.set_version_fields(text, None, {"kind": "none"})
        self.assertEqual(written.splitlines()[2:4], ["core_version: null", "version_basis:"])


class TheSchemaRefusesPlaceholders(unittest.TestCase):
    def setUp(self):
        try:
            import jsonschema  # noqa: PLC0415
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads((ROOT / "schemas" / "emulator.schema.json").read_text())
        self.validator = jsonschema.Draft202012Validator(schema)

    def _valid(self, **fields) -> bool:
        profile = {"emulator": "X", "type": "libretro", "files": [], **fields}
        return self.validator.is_valid(profile)

    def test_placeholders(self):
        for value in ("Git", "GIT", "svn", "SVN (2015 snapshot)", "unknown", "master",
                      "latest", "dev", "main", "HEAD", ""):
            with self.subTest(value=value):
                self.assertFalse(self._valid(core_version=value))

    def test_versions(self):
        for value in ("1.63", "v1.0.0.03", "2609-437-g3aac3f0", "0.37b5", "r22",
                      "2026.4.1git", "developer-1", "Dev-4.0.0"):
            with self.subTest(value=value):
                self.assertTrue(self._valid(core_version=value))

    def test_none_means_null(self):
        self.assertTrue(self._valid(core_version=None, version_basis={"kind": "none"}))
        self.assertFalse(self._valid(core_version="1.0", version_basis={"kind": "none"}))

    def test_each_kind_names_what_it_reads(self):
        self.assertFalse(self._valid(version_basis={"kind": "file", "path": "v.h"}))
        self.assertFalse(self._valid(version_basis={"kind": "tag", "tag": "v1"}))
        self.assertFalse(self._valid(version_basis={"kind": "package"}))
        self.assertTrue(self._valid(core_version="1", version_basis={"kind": "tag", "tag": "1",
                                                                      "distance": 0}))


class VersionModesRefuseOtherFlags(unittest.TestCase):
    def test_refused(self):
        for extra in (["--bump-commit"], ["--check-version"], ["--strict"]):
            argv = ["profile_sync.py", "--all", "--verify-version", *extra]
            with self.subTest(flags=extra), mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    profile_sync.main()
                self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
