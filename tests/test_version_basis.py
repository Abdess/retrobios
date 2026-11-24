"""core_version is read from the code at the pin, where version_basis says.

Four bulk pin advances moved 295 pins and no version, and 54 profiles said
"Git" or "SVN" where the code states a release. These tests read the
recorded sources offline from a fixture of forge answers, hold every profile
to a basis, and hold a pin advance to reading the version again.
"""

from __future__ import annotations

import tests

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

import profile_sync
from profiling import resolver
from profiling import yamledit
from core import upstream
from core import upstreamtree
from profiling import versionbasis
from model.profilerepos import pin_field
from model.profiles import load_emulator_profiles
from profiling.reports import ProfileReport, SkipKind
from profiling.bump import bump_commit

ROOT = Path(__file__).resolve().parent.parent

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
        return versionbasis.check(profiles[name], str(self.cache), True, profiles)

    def test_every_kind_reads_its_version(self):
        for name in self.profiles:
            with self.subTest(profile=name):
                readings = self._check(name)
                self.assertEqual([r.status for r in readings], [versionbasis.MATCH],
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
                self.assertEqual(reading.status, versionbasis.DRIFT)

    def test_a_tag_distance_the_forge_contradicts_is_drift(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["dolphin"]["version_basis"]["distance"] = 400
        (reading,) = self._check("dolphin", profiles)
        self.assertEqual(reading.status, versionbasis.DRIFT)
        self.assertEqual(dict(reading.updates)["distance"], 437)

    def test_a_pattern_that_no_longer_matches_is_unreadable(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["snes9x"]["version_basis"]["pattern"] = "#define\\s+NOPE\\s+(\\S+)"
        (reading,) = self._check("snes9x", profiles)
        self.assertEqual(reading.status, versionbasis.UNREADABLE)

    def test_a_profile_without_basis_is_reported(self):
        profiles = copy.deepcopy(self.profiles)
        del profiles["snes9x"]["version_basis"]
        (reading,) = self._check("snes9x", profiles)
        self.assertEqual(reading.status, versionbasis.NO_BASIS)

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

        from model.profiles import emulator_profiles_cache

        emulator_profiles_cache.clear()
        self.assertEqual(run(), 0)
        stale = emulators / "snes9x.yml"
        stale.write_text(stale.read_text(encoding="utf-8").replace("1.63", "1.61"),
                         encoding="utf-8")
        emulator_profiles_cache.clear()
        self.assertEqual(run(), 1)


class EveryProfileSaysWhereItsVersionIsRead(unittest.TestCase):
    """What can be held without a forge is held here, for every profile."""

    @classmethod
    def setUpClass(cls):
        cls.profiles = load_emulator_profiles(str(ROOT / "emulators"), skip_aliases=False)

    def test_every_profile_has_a_basis(self):
        missing = sorted(name for name, p in self.profiles.items()
                         if not versionbasis.bases(p))
        self.assertEqual(missing, [], "profiles without version_basis")

    def test_no_placeholder_is_a_version(self):
        named = sorted(
            name for name, p in self.profiles.items()
            for mode in (versionbasis.bases(p) or {"": {}})
            if versionbasis.is_placeholder(versionbasis.declared(p, mode))
        )
        self.assertEqual(named, [])

    def test_keyed_bases_follow_the_keyed_version(self):
        for name, profile in self.profiles.items():
            found = versionbasis.bases(profile)
            if not found or "" in found:
                continue
            with self.subTest(profile=name):
                self.assertIsInstance(profile.get("core_version"), dict)
                self.assertEqual(set(found), set(profile["core_version"]))

    def test_none_states_no_version(self):
        for name, profile in self.profiles.items():
            for mode, basis in versionbasis.bases(profile).items():
                if basis.get("kind") == "none":
                    with self.subTest(profile=name, mode=mode):
                        self.assertIsNone(versionbasis.declared(profile, mode))

    def test_a_tag_version_is_the_describe_form_of_its_pin(self):
        for name, profile in self.profiles.items():
            for mode, basis in versionbasis.bases(profile).items():
                if basis.get("kind") != "tag" or basis.get("url"):
                    continue
                field = pin_field(str(basis.get("repo") or "source")) + "_commit"
                pin = versionbasis._by_mode(profile, field, mode)
                if not pin:
                    continue
                with self.subTest(profile=name, mode=mode):
                    self.assertEqual(
                        versionbasis.declared(profile, mode),
                        versionbasis.describe_form(basis["tag"], basis["distance"], pin),
                    )

    def test_an_alias_carries_the_version_of_its_profile(self):
        for name, profile in self.profiles.items():
            for mode, basis in versionbasis.bases(profile).items():
                if basis.get("kind") != "alias":
                    continue
                with self.subTest(profile=name):
                    (reading,) = [r for r in versionbasis.check(
                        profile, "", True, self.profiles) if r.mode == mode]
                    self.assertEqual(reading.status, versionbasis.MATCH, reading)

    def test_a_package_named_after_its_version_states_it(self):
        for name, profile in self.profiles.items():
            for mode, basis in versionbasis.bases(profile).items():
                if basis.get("kind") != "package" or not basis.get("pattern"):
                    continue
                with self.subTest(profile=name):
                    (reading,) = [r for r in versionbasis.check(profile, "", True)
                                  if r.mode == mode]
                    self.assertEqual(reading.status, versionbasis.MATCH, reading)


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


class TheBasisPinIsTheComparisonPin(unittest.TestCase):
    def test_a_source_without_commit_reads_at_the_profiled_date(self):
        """version_basis fell back on profiled_date for upstream only, while
        profile_sync compares every repository at that date's commit."""
        profile = {"source": "https://github.com/o/r", "source_branch": "port",
                   "profiled_date": "2026-01-01"}
        basis = {"kind": "file", "repo": "source"}
        with mock.patch.object(upstream, "resolve_commit_at", return_value="a" * 40) as at:
            repo, pin = versionbasis._repo_and_pin(profile, basis, "", "cache", True)
        self.assertEqual((repo.slug, pin), ("o/r", "a" * 40))
        self.assertEqual(at.call_args.args[1:], ("2026-01-01", "cache", True, "port"))

    def test_a_mirror_is_pinned_by_the_source_commit(self):
        profile = {"source_mirror": "https://github.com/o/m", "source_commit": "b" * 40}
        repo, pin = versionbasis._repo_and_pin(
            profile, {"kind": "file", "repo": "source_mirror"}, "", "cache", True)
        self.assertEqual((repo.slug, pin), ("o/m", "b" * 40))


class TheVersionRepositoryIsTheBasisRepository(unittest.TestCase):
    """--check-version read pcee2's core_version against the port's tags,
    while version_basis reads it in PCSX2."""

    PROFILE = {
        "source": "https://github.com/o/port",
        "upstream": "https://github.com/o/up",
        "version_basis": {"kind": "tag", "repo": "upstream"},
    }

    def test_a_basis_naming_the_upstream_is_read_there(self):
        repo, field = versionbasis.version_repo(self.PROFILE)
        self.assertEqual((repo.slug, field), ("o/up", "upstream"))

    def test_a_profile_without_basis_is_read_where_it_was_profiled(self):
        profile = {k: v for k, v in self.PROFILE.items() if k != "version_basis"}
        repo, field = versionbasis.version_repo(profile)
        self.assertEqual((repo.slug, field), ("o/port", "source"))

    def test_a_basis_url_is_its_own_repository(self):
        profile = dict(self.PROFILE, version_basis={
            "kind": "package", "url": "https://github.com/o/pkg/releases"})
        repo, field = versionbasis.version_repo(profile)
        self.assertEqual((repo.slug, field), ("o/pkg", "url"))

    def test_the_check_reads_the_tags_and_the_pin_of_that_repository(self):
        from profiling import run as profiling_run

        report = ProfileReport(
            name="p", repo="o/port", host="github.com", pin="portpin", head="porthead",
            upstream_pin="uppin", upstream_head="uphead",
        )
        asked = []

        def tag_commit(repo, tag, *_a, **_k):
            asked.append(repo.slug)
            return "uptag" if repo.slug == "o/up" else None

        args = mock.Mock(cache_dir="cache", offline=True)
        with mock.patch.object(upstream, "latest_release", return_value=None), \
                mock.patch.object(upstream, "newest_tag", return_value=None), \
                mock.patch.object(upstream, "tag_commit", side_effect=tag_commit), \
                mock.patch.object(upstreamtree, "ancestry", return_value=(3, 0)) as ancestry:
            profiling_run._attach_version(args, dict(self.PROFILE, core_version="v1"), report)
        self.assertEqual(set(asked), {"o/up"})
        self.assertEqual(report.version.tag_commit, "uptag")
        self.assertEqual(ancestry.call_args.args[1:3], ("uptag", "uppin"))
        self.assertIn("the pin resolved to uppin", report.version_warning)


class TheTagCoreVersionNames(unittest.TestCase):
    """armsx2 declared 2.9.2-77-gfc4ab0b over tag 2.9.2: --check-version
    asked for a tag named after the whole string, found none, and never said
    that 2.10.0 was out. jgenesis asked for the tag "{'standalone': ...}"."""

    DESCRIBED = {
        "source": "https://github.com/o/n",
        "core_version": "2.9.2-77-gfc4ab0b",
        "version_basis": {"kind": "tag", "tag": "2.9.2", "distance": 77},
    }

    def _attach(self, profile, tags):
        from profiling import run as profiling_run

        report = ProfileReport(name="p", repo="o/n", host="github.com",
                               pin="fc4ab0b" + "0" * 33, head="head")
        args = mock.Mock(cache_dir="cache", offline=True)
        asked = []

        def tag_commit(repo, tag, *_a, **_k):
            asked.append(tag)
            return tags.get(tag)

        def ancestry(repo, base, head, *_a, **_k):
            # The tag 2.9.2 sits 77 commits before the pin, the release
            # 2.10.0 after both.
            return {("tag292", report.pin): (77, 0), ("tag292", "rel210"): (5, 0),
                    (report.pin, "rel210"): (3, 0)}.get((base, head))

        with mock.patch.object(upstream, "latest_release",
                               return_value=upstream.Release("2.10.0", "2026-11-01", False)), \
                mock.patch.object(upstream, "newest_tag", return_value="2.10.0"), \
                mock.patch.object(upstream, "tag_commit", side_effect=tag_commit), \
                mock.patch.object(upstreamtree, "ancestry", side_effect=ancestry):
            profiling_run._attach_version(args, profile, report)
        return report, asked

    def test_a_tag_basis_names_its_tag(self):
        [named] = versionbasis.version_tags(self.DESCRIBED)
        self.assertEqual((named.declared, named.tag, named.distance),
                         ("2.9.2-77-gfc4ab0b", "2.9.2", 77))

    def test_a_mode_keyed_version_names_one_tag_per_build(self):
        profile = {"source": "https://github.com/o/n",
                   "core_version": {"standalone": "v1.1", "libretro": "v0.9"}}
        self.assertEqual([(n.mode, n.tag) for n in versionbasis.version_tags(profile)],
                         [("standalone", "v1.1"), ("libretro", "v0.9")])
        same = dict(profile, core_version={"standalone": "0.14.1", "libretro": "0.14.1"})
        self.assertEqual([n.tag for n in versionbasis.version_tags(same)], ["0.14.1"])

    def test_a_release_after_the_described_pin_is_named(self):
        report, asked = self._attach(self.DESCRIBED, {"2.9.2": "tag292", "2.10.0": "rel210"})
        self.assertEqual(asked[0], "2.9.2")
        self.assertEqual(report.version.tag_commit, "tag292")
        self.assertIn("release 2.10.0 is newer than core_version 2.9.2-77-gfc4ab0b",
                      report.version_warning)

    def test_the_stated_distance_is_no_warning(self):
        report, _ = self._attach(self.DESCRIBED, {"2.9.2": "tag292"})
        self.assertIsNone(report.version_warning)

    def test_the_page_is_held_against_the_build_it_announces(self):
        from profiling import versions

        profile = {"core_version": {"standalone": "20260807-10669", "libretro": "1.0.0"}}
        self.assertEqual(versions.page_declared(profile, "20260807-10669"), "20260807-10669")
        self.assertEqual(versions.page_declared(profile, "20261101-10700"), "20260807-10669")
        self.assertEqual(versions.page_declared({"core_version": "4.40"}, "4.50"), "4.40")
        self.assertIsNone(versions.page_declared({}, "4.50"))


class AnAdvanceReadsTheVersionAgain(unittest.TestCase):
    """A pin never moves without its version: read again, or refused."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.yml"
        self.path.write_text(SAMPLE, encoding="utf-8")
        self.report = ProfileReport(
            name="p", repo="o/n", pin="aaaaaaa", head="bbbbbbb", entries=[], counts={},
            skipped=resolver.NO_SOURCE_REF, skip_kind=SkipKind.NO_SOURCE_REF,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _reading(self, status: str, value: str | None):
        return versionbasis.Reading("", "file", "1.0", value, "o/n@bbbbbbb:version.h:3", status)

    def test_the_version_moves_with_the_pin(self):
        seen = []

        def check(profile, cache_dir, offline, profiles=None, recompute=False):
            seen.append((profile["source_commit"], recompute))
            return [self._reading(versionbasis.DRIFT, "2.0")]

        with mock.patch.object(versionbasis, "check", check):
            self.assertTrue(bump_commit(self.path, self.report).moved)
        written = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.assertEqual(written["source_commit"], "bbbbbbb")
        self.assertEqual(written["core_version"], "2.0")
        # Read at the new pin, the nearest tag asked again.
        self.assertEqual(seen, [("bbbbbbb", True)])

    def test_an_unreadable_version_holds_the_pin(self):
        with mock.patch.object(versionbasis, "check",
                               return_value=[self._reading(versionbasis.UNREADABLE, None)]):
            self.assertFalse(bump_commit(self.path, self.report).moved)
        self.assertEqual(self.path.read_text(encoding="utf-8"), SAMPLE)

    def test_a_profile_without_basis_is_not_advanced(self):
        self.path.write_text(SAMPLE.split("version_basis:")[0] + "files: []\n", encoding="utf-8")
        before = self.path.read_text(encoding="utf-8")
        self.assertFalse(bump_commit(self.path, self.report).moved)
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)

    def test_a_package_version_is_advanced_by_hand(self):
        reading = versionbasis.Reading("", "package", "1.0", None, "read from x.apk",
                                        versionbasis.UNCHECKED)
        with mock.patch.object(versionbasis, "check", return_value=[reading]):
            self.assertFalse(bump_commit(self.path, self.report).moved)


class TheWriterKeepsTheDocument(unittest.TestCase):
    def test_keyed_versions_and_bases_round_trip(self):
        text = ('emulator: X\nsource_commit: "abc"\ncore_version:\n  standalone: "1"\n'
                '  libretro: "2"\ndisplay_name: X\n')
        basis = {"standalone": {"kind": "tag", "tag": "2407", "distance": 0},
                 "libretro": {"kind": "none"}}
        written = yamledit.set_version_fields(
            text, {"standalone": "2407", "libretro": None}, basis)
        document = yaml.safe_load(written)
        self.assertEqual(document["core_version"], {"standalone": "2407", "libretro": None})
        self.assertEqual(document["version_basis"], basis)
        self.assertEqual(document["display_name"], "X")
        self.assertIn('tag: "2407"', written)

    def test_a_missing_version_is_written_after_the_pins(self):
        text = 'emulator: X\nsource_commit: "abc"\nfiles: []\n'
        written = yamledit.set_version_fields(text, None, {"kind": "none"})
        self.assertEqual(written.splitlines()[2:4], ["core_version: null", "version_basis:"])


class TheSchemaRefusesPlaceholders(unittest.TestCase):
    def setUp(self):
        try:
            import jsonschema
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
