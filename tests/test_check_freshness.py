"""check_freshness: the pure parts, no network.

The script answers "is the local copy the one upstream serves" for every
transcribed layer. What can be locked without a network is how a diff is
read, how a core name is resolved, how a pin is parsed, and how a profile
report is folded, since each of those decides whether a row says STALE.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_freshness as cf  # noqa: E402
from common import yaml_load  # noqa: E402


class NativeCacheTests(unittest.TestCase):
    """A cached original is patched only if it is the file we transcribed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.cache = Path(self._tmp.name)
        self.index = self.cache / cf.export_native.SOURCES_INDEX
        self.root = self.cache / "plat"
        self.root.mkdir()
        self.wanted = {"list.txt": "https://example.invalid/tag-2/list.txt"}

    def _cached(self, mtime: float) -> None:
        path = self.root / "list.txt"
        path.write_text("x", encoding="utf-8")
        os.utime(path, (mtime, mtime))

    def _state(self, recorded: dict, transcribed_at: float) -> str:
        return cf.native_cache_state(
            self.wanted, self.root, recorded, self.index, transcribed_at
        )

    def test_a_file_fetched_after_the_scrape_from_the_named_url_is_fresh(self):
        self._cached(200.0)
        recorded = {"plat/list.txt": self.wanted["list.txt"]}
        self.assertEqual(self._state(recorded, 100.0), "")

    def test_an_absent_file_is_named(self):
        self.assertEqual(self._state({}, 0.0), "list.txt not cached")

    def test_a_file_with_no_recorded_url_proves_nothing(self):
        self._cached(200.0)
        self.assertEqual(self._state({}, 100.0), "list.txt cached from an unrecorded URL")

    def test_a_file_from_the_previous_pin_is_stale(self):
        self._cached(200.0)
        recorded = {"plat/list.txt": "https://example.invalid/tag-1/list.txt"}
        self.assertEqual(self._state(recorded, 100.0), "list.txt cached from another revision")

    def test_a_file_older_than_the_rescrape_is_stale(self):
        """A branch URL does not change when its content does."""
        self._cached(100.0)
        recorded = {"plat/list.txt": self.wanted["list.txt"]}
        self.assertEqual(
            self._state(recorded, 200.0),
            "list.txt cached before the platform file was rewritten",
        )

    def test_the_transcription_date_follows_inheritance(self):
        platforms = self.cache / "platforms"
        platforms.mkdir()
        (platforms / "parent.yml").write_text("platform: P\n", encoding="utf-8")
        (platforms / "child.yml").write_text("inherits: parent\n", encoding="utf-8")
        os.utime(platforms / "parent.yml", (300.0, 300.0))
        os.utime(platforms / "child.yml", (100.0, 100.0))
        self.assertEqual(cf._transcribed_at(platforms, "child"), 300.0)
        self.assertEqual(cf._transcribed_at(platforms, "parent"), 300.0)

    def test_every_registered_platform_with_an_exporter_gets_a_row(self):
        rows = cf.check_native(REPO_ROOT / "platforms", self.cache, self.cache / "truth")
        self.assertTrue(rows)
        self.assertEqual({r.area for r in rows}, {"native"})
        self.assertEqual({r.status for r in rows}, {cf.STALE})
        self.assertIn("batocera", {r.subject for r in rows})

    def test_the_model_build_notes_stay_out_of_the_report(self):
        """generate_truth reports how two cores' hashes were settled. Under
        `--only native` they opened the report and named no step to take."""
        import contextlib
        import io

        def noisy(truth, scraped):
            print("WARNING: hash conflict for GameIndex.yaml (sha1: a vs b, core yaps2)",
                  file=sys.stderr)
            print("other diagnostic", file=sys.stderr)
            return {}, None

        err = io.StringIO()
        with mock.patch.object(cf, "build_native_model", side_effect=noisy), \
                contextlib.redirect_stderr(err):
            cf.check_native(REPO_ROOT / "platforms", self.cache, self.cache / "truth")
        self.assertNotIn("hash conflict", err.getvalue())
        self.assertIn("other diagnostic", err.getvalue())


class PublishedExportTests(unittest.TestCase):
    """exports/ is committed and published, and CI cannot rebuild it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.published = Path(self._tmp.name)
        (self.published / "plat").mkdir()
        (self.published / "plat" / "list.txt").write_text("a", encoding="utf-8")
        (self.published / "plat.json").write_text("{}", encoding="utf-8")

    def _state(self, written: str, ok: bool = True) -> str:
        def fake(platform, _cls, _truth, output, *_rest):
            (output / platform).mkdir(parents=True)
            (output / platform / "list.txt").write_text(written, encoding="utf-8")
            (output / f"{platform}.json").write_text("{}", encoding="utf-8")
            return ok, [] if ok else ["the platform's own file is required"]

        with mock.patch.object(cf.export_native, "export_platform", fake):
            return cf.published_export_state(
                "plat", object, Path("t"), Path("p"), Path("c"), self.published
            )

    def test_the_same_bytes_are_fresh(self):
        self.assertEqual(self._state("a"), "")

    def test_a_moved_hash_is_named(self):
        self.assertIn("is not what the export writes now", self._state("b"))

    def test_an_export_that_fails_is_named(self):
        self.assertIn("the export fails", self._state("a", ok=False))


class PlatformDiffTests(unittest.TestCase):
    def _platform(self, version="1", files=None, cores=None):
        return {
            "version": version,
            "cores": cores or ["a", "b"],
            "systems": {
                "sys": {"files": files if files is not None else [
                    {"name": "x.bin", "destination": "x.bin", "md5": "1"},
                ]},
            },
        }

    def test_identical_files_are_not_a_change(self):
        diff = cf.diff_platform(self._platform(), self._platform())
        self.assertFalse(diff.changed)
        self.assertEqual(diff.summary(), "identical")

    def test_version_alone_is_a_change_but_not_content(self):
        diff = cf.diff_platform(self._platform("1"), self._platform("2"))
        self.assertTrue(diff.changed)
        self.assertFalse(diff.content_changed)
        self.assertEqual(diff.version, ("1", "2"))

    def test_hash_change_on_a_destination_is_a_change_not_a_swap(self):
        old = self._platform(files=[{"name": "x.bin", "destination": "x.bin", "md5": "1"}])
        new = self._platform(files=[{"name": "x.bin", "destination": "x.bin", "md5": "2"}])
        diff = cf.diff_platform(old, new)
        self.assertEqual(diff.files_changed, ["sys/x.bin"])
        self.assertEqual(diff.files_added, [])
        self.assertEqual(diff.files_removed, [])

    def test_systems_files_and_cores_are_reported_separately(self):
        old = self._platform()
        new = self._platform(cores=["a", "c"])
        new["systems"]["other"] = {"files": []}
        new["systems"]["sys"]["files"].append({"name": "y.bin", "destination": "y.bin"})
        new["standalone_cores"] = ["dolphin"]
        diff = cf.diff_platform(old, new)
        self.assertEqual(diff.systems_added, ["other"])
        self.assertEqual(diff.files_added, ["sys/y.bin"])
        self.assertEqual(diff.cores_added, ["c", "standalone:dolphin"])
        self.assertEqual(diff.cores_removed, ["b"])
        self.assertIn("+cores 2", diff.summary())

    def test_every_other_scraped_field_is_a_change(self):
        """launchers feed verify, dual_mode_cores the grouping, a system's
        data_directories the pack: a rescrape that moves only them is stale."""
        old = self._platform()
        old["launchers"] = [{"emulator": "e"}]
        old["dual_mode_cores"] = ["flycast"]
        old["systems"]["sys"].update(core="c1", native_id="psx",
                                     data_directories=[{"ref": "x"}])
        new = self._platform()
        new["launchers"] = []
        new["systems"]["sys"].update(core="c2", native_id="psx")
        diff = cf.diff_platform(old, new)
        self.assertTrue(diff.content_changed)
        self.assertEqual(
            diff.fields_changed,
            ["dual_mode_cores", "launchers", "sys/core", "sys/data_directories"],
        )
        self.assertIn("~fields 4", diff.summary())

    def test_the_revision_read_alone_is_not_a_change(self):
        old, new = self._platform(), self._platform()
        old["source"], new["source"] = "https://x/tar.gz/aaa", "https://x/tar.gz/bbb"
        old["launchers"] = [{"emulator": "e", "source_ref": "es_features.cfg:11638-11646"}]
        new["launchers"] = [{"emulator": "e", "source_ref": "es_features.cfg:11649-11657"}]
        self.assertFalse(cf.diff_platform(old, new).changed)

    def test_target_stamp_is_not_a_change(self):
        old = {"scraped_at": "2026-01-01", "targets": {"t": {"cores": ["a"]}}}
        new = {"scraped_at": "2026-02-01", "targets": {"t": {"cores": ["a"]}}}
        self.assertFalse(cf.diff_targets(old, new).content_changed)
        new["targets"]["t"]["cores"].append("b")
        diff = cf.diff_targets(old, new)
        self.assertEqual(diff.cores_added, ["t/b"])


class CoreResolutionTests(unittest.TestCase):
    PROFILES = {
        "beetle_psx": {"cores": ["mednafen_psx"], "type": "libretro"},
        "eka2l1": {"cores": ["eka2l1"], "type": "standalone"},
        "FreeIntv": {"cores": ["freeintvtsoverlay"], "type": "alias"},
    }

    def test_index_maps_key_and_every_core_alias(self):
        index = cf.profile_name_index(self.PROFILES)
        self.assertEqual(index["mednafen_psx"], {"beetle_psx"})
        self.assertEqual(index["beetle_psx"], {"beetle_psx"})

    def test_unresolved_honours_remove_cores_per_target(self):
        index = cf.profile_name_index(self.PROFILES)
        targets = {
            "targets": {
                "android": {"cores": ["mednafen_psx", "na", "ghost"]},
                "linux": {"cores": ["ghost"]},
            }
        }
        overrides = {"android": {"remove_cores": ["na"]}}
        self.assertEqual(
            cf.unresolved_target_cores(targets, index, overrides),
            {"ghost": ["android", "linux"]},
        )

    def test_a_default_override_drops_a_name_on_every_target(self):
        index = cf.profile_name_index(self.PROFILES)
        targets = {
            "targets": {
                "x86_64": {"cores": ["A500", "ghost"]},
                "rpi": {"cores": ["A500", "na"]},
            }
        }
        overrides = {
            "plat": {
                "targets": {
                    "_default": {"remove_cores": ["A500"]},
                    "rpi": {"remove_cores": ["na"]},
                }
            }
        }
        self.assertEqual(
            cf.unresolved_target_cores(targets, index, cf._platform_overrides(overrides, "plat")),
            {"ghost": ["x86_64"]},
        )

    def test_an_added_core_is_read_as_the_builder_reads_it(self):
        """add_cores without a profile is the false skip this check exists
        for, and a target may add back what _default removes."""
        index = cf.profile_name_index(self.PROFILES)
        targets = {"targets": {"board": {"cores": ["mednafen_psx"]}}}
        overrides = {
            "_default": {"remove_cores": ["mednafen_psx"]},
            "board": {"add_cores": ["mednafen_psx", "citron"]},
        }
        self.assertEqual(
            cf.unresolved_target_cores(targets, index, overrides), {"citron": ["board"]}
        )

    def test_coreinfo_gaps_fold_case_and_flag_standalone_profiles(self):
        names = ["FreeIntvTSOverlay", "eka2l1", "wqxemu", "mednafen_psx"]
        unprofiled, standalone = cf.coreinfo_gaps(names, self.PROFILES)
        self.assertEqual(unprofiled, ["wqxemu"])
        self.assertEqual(standalone, [("eka2l1", "eka2l1")])

    def test_a_changed_info_of_a_profiled_core_is_stale(self):
        """A firmwareN_path added to a profiled core's .info changes its blob:
        the names alone said OK."""
        blobs = {"mednafen_psx": "new", "eka2l1": "same", "wqxemu": "other"}
        recorded = {"mednafen_psx": "old", "eka2l1": "same"}
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "_core_info.json"
            record.write_text(cf.json.dumps({"blobs": recorded}))
            with mock.patch.object(cf, "core_info_blobs", return_value=blobs):
                rows = cf.check_coreinfo(self.PROFILES, "", True, record)
        stale = {r.subject: r for r in rows if r.status == cf.STALE}
        self.assertIn("mednafen_psx", stale)
        self.assertIn("--record-coreinfo mednafen_psx", stale["mednafen_psx"].detail)
        self.assertNotIn(".info changed", stale["eka2l1"].detail)
        self.assertEqual(cf.coreinfo_drift(blobs, recorded, self.PROFILES), ["mednafen_psx"])

    def test_recording_a_core_leaves_the_others_unread(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "_core_info.json"
            record.write_text(cf.json.dumps({"blobs": {"a": "1", "b": "1"}}))
            cf.record_core_info({"a": "2", "b": "2"}, ["a"], record)
            self.assertEqual(cf.load_core_info_record(record), {"a": "2", "b": "1"})
            with self.assertRaises(ValueError):
                cf.record_core_info({"a": "2"}, ["ghost"], record)

    def test_offline_without_a_cached_listing_is_skipped(self):
        """Offline, the row read UNKNOWN and failed the run as an upstream
        that could not be read, though nothing was asked of it."""
        with mock.patch.object(cf, "core_info_blobs", return_value=None):
            (row,) = cf.check_coreinfo(self.PROFILES, "", True)
            self.assertEqual((row.status, row.detail), (cf.SKIPPED, "offline"))
            (row,) = cf.check_coreinfo(self.PROFILES, "", False)
            self.assertEqual(row.status, cf.UNKNOWN)

    def test_the_committed_record_holds_git_blobs(self):
        recorded = cf.load_core_info_record()
        self.assertIsNotNone(recorded)
        self.assertTrue(all(len(sha) == 40 for sha in recorded.values()))


class PinParsingTests(unittest.TestCase):
    WORKFLOW = """
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7
      - run: pip install pyyaml jsonschema==4.23.0 "mkdocs-material>=9.7.5,<10" "pymdown-extensions>=10.14"
      - uses: actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128
    """

    def test_pip_pins_keep_the_specifier(self):
        pins = cf.parse_pip_pins(self.WORKFLOW)
        self.assertEqual(pins["pyyaml"], "")
        self.assertEqual(pins["jsonschema"], "==4.23.0")
        self.assertEqual(pins["mkdocs-material"], ">=9.7.5,<10")
        self.assertEqual(pins["pymdown-extensions"], ">=10.14")

    def test_action_pins_carry_sha_and_optional_tag(self):
        pins = cf.parse_action_pins(self.WORKFLOW)
        self.assertEqual(pins["actions/checkout"], ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7"))
        self.assertEqual(pins["actions/deploy-pages"][1], "")

    def test_specifier_admits_or_refuses_the_latest(self):
        self.assertTrue(cf.specifier_allows("", "9.9"))
        self.assertTrue(cf.specifier_allows(">=9.7.5,<10", "9.7.7"))
        self.assertFalse(cf.specifier_allows(">=9.7.5,<10", "10.0.0"))
        self.assertFalse(cf.specifier_allows("==4.23.0", "4.26.0"))
        self.assertTrue(cf.specifier_allows("==4.23.0", "4.23.0"))
        self.assertTrue(cf.specifier_allows(">=10.14", "12.0.1"))


class SiteNpmPins(unittest.TestCase):
    """The site's npm dependencies are pinned to exact versions in
    website/package.json, and the ci area compared only the PyPI and action
    pins: astro 7.4.2 stayed behind 7.4.7 with no STALE row."""

    def test_both_dependency_kinds_are_read(self):
        pins = cf.parse_npm_pins(
            '{"dependencies": {"astro": "7.4.2"}, "devDependencies": {"x": "^1.0.0"}}'
        )
        self.assertEqual(pins, {"astro": "7.4.2", "x": "^1.0.0"})

    def test_a_newer_release_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "package.json"
            package.write_text(json.dumps({"dependencies": {
                "astro": "7.4.2", "@astrojs/starlight": "0.42.9", "y": "^2.0.0",
            }}))
            latest = {"astro": "7.4.7", "@astrojs/starlight": "0.42.9"}
            def answer(url):
                name = url.split("registry.npmjs.org/", 1)[1].rsplit("/latest", 1)[0]
                return {"version": latest[name]}
            with mock.patch.object(cf, "SITE_PACKAGE", package), \
                    mock.patch.object(cf.upstream, "_http_json", side_effect=answer):
                rows = {f.subject: f for f in cf._npm_findings()}
        self.assertEqual(rows["npm:astro"].status, cf.STALE)
        self.assertEqual(rows["npm:astro"].remote, "7.4.7")
        self.assertEqual(rows["npm:@astrojs/starlight"].status, cf.OK)
        self.assertEqual(rows["npm:y"].status, cf.UNKNOWN)

    def test_the_ci_area_reads_the_site_pins(self):
        with mock.patch.object(cf, "_npm_findings", return_value=[]) as npm, \
                mock.patch.object(cf, "parse_pip_pins", return_value={}), \
                mock.patch.object(cf, "parse_action_pins", return_value={}):
            cf.check_ci("unused", offline=False)
        npm.assert_called_once()


class RomFolderPins(unittest.TestCase):
    """The rom folders of a setup were pinned by hand and nothing compared
    the pins with the platform file or the project's releases."""

    def _tree(self, tmp: str, platform_source: str, os_source: str) -> Path:
        root = Path(tmp)
        (root / "romfolders" / "_sources").mkdir(parents=True)
        (root / "_registry.yml").write_text("platforms:\n  plat: {}\n")
        (root / "plat.yml").write_text(f"source: {platform_source}\n")
        (root / "romfolders" / "_sources" / "plat.yml").write_text(
            f"sources:\n  os:\n    repo: https://github.com/o/r\n{os_source}")
        (root / "romfolders" / "_sources" / "other.yml").write_text(
            "sources:\n  os:\n    repo: https://github.com/x/y\n    commit: " + "c" * 40 + "\n")
        return root

    def test_a_platform_setup_follows_its_platform_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "https://raw.githubusercontent.com/o/r/v2/list.txt",
                              "    tag: v1\n    commit: " + "a" * 40 + "\n")
            rows = {f.subject: f for f in cf.check_romfolders(root, "", True)}
        self.assertEqual(rows["plat"].status, cf.STALE)
        self.assertIn("scraped at v2, the rom folders at v1", rows["plat"].detail)
        self.assertEqual(rows["other"].status, cf.SKIPPED)

    def test_the_same_revision_is_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "https://github.com/o/r/tree/" + "a" * 40,
                              "    commit: " + "a" * 40 + "\n")
            rows = {f.subject: f for f in cf.check_romfolders(root, "", True)}
        self.assertEqual(rows["plat"].status, cf.OK)

    def test_a_newer_release_makes_another_setup_stale(self):
        release = cf.upstream.Release("v9", "2026-11-01", False)
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "https://github.com/o/r/tree/" + "a" * 40,
                              "    commit: " + "a" * 40 + "\n")
            with mock.patch.object(cf.upstream, "commit_date", return_value="2026-10-01T00:00:00"), \
                    mock.patch.object(cf.upstream, "latest_release", return_value=release):
                rows = {f.subject: f for f in cf.check_romfolders(root, "", False)}
        self.assertEqual((rows["other"].status, rows["other"].remote), (cf.STALE, "v9 (2026-11-01)"))

    def test_the_committed_setups_agree_with_their_platform_files(self):
        platforms = REPO_ROOT / "platforms"
        drift = [d for setup, doc in cf.romfolder_sources(platforms).items()
                 if (d := cf.romfolder_pin_drift(setup, doc, platforms))]
        self.assertEqual(drift, [])


class CatalogParsingTests(unittest.TestCase):
    def test_game_catalogs_are_watched(self):
        """The 38 game catalogs the games-on-card mode identifies discs by
        had no row: only the BIOS snapshots of provenance/ were compared."""
        versions = {code: "2026-01-01 00-00-00" for code in cf.game_dat_importer.REDUMP_DATS}
        versions["PSX"] = "2099-01-01 00-00-00"
        local = [{"system": system, "version": "2026-01-01 00-00-00"}
                 for _n, system, _f in cf.game_dat_importer.REDUMP_DATS.values()]
        with mock.patch.object(cf, "_game_catalogs", return_value=local), \
                mock.patch.object(cf, "redump_datfile_version", side_effect=versions.get):
            row = cf._check_redump_games(False)
            self.assertEqual((row.status, row.items), (cf.STALE, ["sony-playstation"]))
            self.assertEqual(cf._check_redump_games(True).status, cf.SKIPPED)
        with mock.patch.object(cf, "_game_catalogs", return_value=[{"fetched": "2026-11-03"}]):
            for rebuilt, status in (("2026-07-08", cf.OK), ("2026-11-04", cf.STALE)):
                with mock.patch.object(cf, "_no_intro_asset_date", return_value=rebuilt):
                    self.assertEqual(cf._check_nointro_games("", False).status, status)
        self.assertIn("no-intro games",
                      [f.subject for f in cf.check_catalogs("", True)])

    def test_tosec_newest_release_from_category_links(self):
        html = (
            '<a href="/downloads/category/58-2024-05-17">x</a>'
            '<a href="/downloads/category/59-2025-03-13">y</a>'
            '<a href="/downloads/category/22-datfiles">z</a>'
        )
        self.assertEqual(cf.tosec_latest_pack(html), "2025-03-13")
        self.assertIsNone(cf.tosec_latest_pack("<html></html>"))

    def test_fbneo_drift_compares_blob_shas_and_reports_untracked(self):
        listing = [
            {"type": "file", "name": "A.dat", "sha": "1"},
            {"type": "file", "name": "B.dat", "sha": "2"},
            {"type": "dir", "name": "old"},
        ]
        snapshot = {"upstream": {"blobs": {"A.dat": "1", "B.dat": "9"}}}
        self.assertEqual(cf.fbneo_blob_drift(snapshot, listing), (["B.dat"], True))
        self.assertEqual(cf.fbneo_blob_drift({"upstream": {}}, listing), ([], False))
        snapshot = {"upstream": {"blobs": {"A.dat": "1", "B.dat": "2", "C.dat": "3"}}}
        self.assertEqual(cf.fbneo_blob_drift(snapshot, listing), (["C.dat"], True))

    def test_mame_versions_read_from_dat_labels(self):
        recipes = {"dats": {"MAME mame0250": "0.250", "MAME mame0289": "0.289", "FinalBurn Neo": "x"}}
        self.assertEqual(cf.mame_versions(recipes), ["mame0250", "mame0289"])


class ProfileSummaryTests(unittest.TestCase):
    def test_summary_separates_review_moved_and_unreachable(self):
        report = [
            {"name": "a", "pin": "1" * 40, "head": "1" * 40, "needs_review": 0},
            {"name": "b", "pin": "1" * 40, "head": "2" * 40, "needs_review": 0},
            {"name": "c", "pin": "1" * 40, "head": "2" * 40, "needs_review": 3},
            {"name": "d", "skipped": "no declared repository answers"},
            {"name": "e", "skipped": "upstream gone (declared): archived 2019"},
        ]
        findings = cf.summarize_profile_sync(report)
        by_subject = {f.subject: f for f in findings}
        self.assertEqual(by_subject["profile_sync"].status, cf.STALE)
        self.assertEqual(by_subject["profile_sync"].local, "1 at tip, 1 anchored past the tip")
        self.assertEqual(by_subject["c"].status, cf.STALE)
        self.assertEqual(by_subject["d"].status, cf.UNKNOWN)
        # Never checkable by nature: it does not hold the exit code.
        self.assertEqual(by_subject["e"].status, cf.SKIPPED)
        self.assertNotIn("a", by_subject)
        self.assertNotIn("b", by_subject)

    def test_new_upstream_names_and_hashes_are_stale(self):
        """A file name the cited code gained since the pin, or a hash nobody
        declares, was printed only by the text pass that --profiles never ran."""
        report = [
            {"name": "a", "pin": "1" * 40, "head": "2" * 40, "needs_review": 0,
             "new_files": [
                 {"path": "x.c", "line": 4, "name": "old.rom", "since_pin": False},
                 {"path": "x.c", "line": 9, "name": "new.rom", "since_pin": True},
             ], "new_hashes": []},
            {"name": "b", "pin": "1" * 40, "head": "2" * 40, "needs_review": 0,
             "new_files": [], "new_hashes": [{"path": "x.c", "kind": "md5", "value": "0" * 32}]},
            {"name": "c", "pin": "1" * 40, "head": "2" * 40, "needs_review": 0,
             "new_files": [
                 {"path": "x.c", "line": 4, "name": "old.rom", "since_pin": False},
             ], "new_hashes": []},
        ]
        by_subject = {f.subject: f for f in cf.summarize_profile_sync(report)}
        self.assertEqual(by_subject["a"].status, cf.STALE)
        self.assertIn("new.rom", by_subject["a"].detail)
        self.assertNotIn("old.rom", by_subject["a"].detail)
        self.assertEqual(by_subject["b"].status, cf.STALE)
        self.assertNotIn("c", by_subject)

    def test_profile_sync_accepts_the_command_it_is_given(self):
        """--json with the detection flags was refused, so --profiles read an
        empty stdout and reported "unreadable report" on every run."""
        import profile_sync  # noqa: PLC0415

        captured = []

        def run(cmd, **kwargs):
            captured.append(cmd)
            return mock.Mock(returncode=0, stdout="[]", stderr="")

        with mock.patch.object(cf.subprocess, "run", side_effect=run):
            cf.check_profiles(True, offline=True)
        (cmd,) = captured
        args = profile_sync.build_parser().parse_args(cmd[2:])
        profile_sync._refuse_flag_combinations(args)
        self.assertTrue(args.as_json)

    def test_a_non_list_report_is_an_error_not_a_crash(self):
        findings = cf.summarize_profile_sync({"oops": 1})
        self.assertEqual(findings[0].status, cf.ERROR)


class RepositoryWiringTests(unittest.TestCase):
    """The script derives its work from the registry: a platform whose scraper
    module does not exist would be skipped in silence."""

    def test_every_registered_scraper_module_exists(self):
        rows = cf._scrapable_platforms(REPO_ROOT / "platforms")
        self.assertGreaterEqual(len(rows), 10)
        for _name, module, _path in rows:
            self.assertTrue(
                (REPO_ROOT / (module.replace(".", "/") + ".py")).is_file(), module
            )

    def test_inheriting_platforms_without_a_source_are_not_scraped(self):
        names = {name for name, _m, _p in cf._scrapable_platforms(REPO_ROOT / "platforms")}
        with (REPO_ROOT / "platforms" / "lakka.yml").open(encoding="utf-8") as fh:
            lakka = yaml_load(fh)
        self.assertTrue(lakka.get("inherits"))
        self.assertNotIn("lakka", names)
        self.assertIn("retropie", names)

    def test_render_counts_every_status_once(self):
        findings = [
            cf.Finding("ci", "a", cf.OK),
            cf.Finding("ci", "b", cf.STALE, detail="x"),
            cf.Finding("data", "c", cf.UNKNOWN),
        ]
        text = cf.render(findings)
        self.assertIn("FRESHNESS: 1 stale, 1 unknown, 1 ok", text)
        self.assertIn("[ci]", text)
        self.assertIn("[data]", text)

    def test_an_unanswered_upstream_is_not_fresh(self):
        """With no network every data row was unknown and the run exited 0,
        the answer of a collection with nothing to refresh."""
        self.assertEqual(cf.exit_code([cf.Finding("data", "a", cf.UNKNOWN)]), 1)
        self.assertEqual(cf.exit_code([cf.Finding("data", "a", cf.SKIPPED),
                                       cf.Finding("data", "b", cf.OK)]), 0)

    def test_stale_rows_name_the_command_that_refreshes_them(self):
        text = cf.render([cf.Finding("native", "batocera", cf.STALE)])
        self.assertIn("refresh_stale.py", text)
        self.assertNotIn("refresh_stale.py", cf.render([cf.Finding("ci", "a", cf.OK)]))

    def test_a_stale_original_names_its_platform(self):
        """The hint refetched the originals of all twelve platforms to fix
        one, and wrote no export."""
        source = Path(cf.__file__).read_text(encoding="utf-8")
        hint = source.index('" fetches it, then the export is written again"')
        self.assertIn("--platform {name} --refresh-cache", source[hint - 120:hint])

    def test_an_unknown_area_names_the_valid_ones(self):
        message = cf.unknown_areas_message(["platform"])
        self.assertIn("did you mean platforms?", message)
        for area in cf.AREAS:
            self.assertIn(area, message)

    def test_a_target_of_every_declared_core_does_not_age(self):
        """RetroBat, RetroDECK and RomM name one target that runs every core
        they declare. With nothing hand-kept, there is no date to watch."""
        import tempfile  # noqa: PLC0415
        from pathlib import Path as _Path  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = _Path(tmp) / "targets"
            targets.mkdir()
            (targets / "solo.yml").write_text(
                "platform: solo\nsource: static\ntargets:\n  only:\n    cores: null\n")
            findings = cf.check_targets(_Path(tmp), _Path(tmp), {}, 1, True)
        solo = [f for f in findings if f.subject == "solo"]
        self.assertEqual([(f.status, f.detail) for f in solo], [(cf.OK, "every declared core")])

    def test_a_scraped_target_offline_is_skipped_not_ok(self):
        """Offline, scraped target lists were labelled static and counted OK
        without any comparison, so a list 400 days old read as current."""
        import tempfile  # noqa: PLC0415
        from pathlib import Path as _Path  # noqa: PLC0415

        scraped = sorted(cf._target_scrapers())
        self.assertTrue(scraped)
        platform = scraped[0]
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp") as tmp:
            targets = _Path(tmp) / "targets"
            targets.mkdir()
            (targets / f"{platform}.yml").write_text(
                f"platform: {platform}\nscraped_at: '2025-01-01'\n"
                "targets:\n  one:\n    cores: []\n")
            findings = cf.check_targets(_Path(tmp), _Path(tmp), {}, 1, True)
        row = [f for f in findings if f.subject == platform]
        self.assertEqual([(f.status, f.detail) for f in row], [(cf.SKIPPED, "offline")])

    def test_romm_emulatorjs_pin_is_read_from_its_dockerfile(self):
        """emulatorjs.yml is no registered platform: a RomM image moving to
        another EmulatorJS changed the cores its users run, unnoticed."""
        text = "FROM x\nARG EMULATORJS_VERSION=4.2.3\nARG EMULATORJS_SHA256=ab\n"
        self.assertEqual(cf.emulatorjs_pin(text), "4.2.3")
        self.assertIsNone(cf.emulatorjs_pin("FROM x\n"))

    def test_render_keeps_long_values_whole(self):
        """The profile_sync row lost the end of its sentence at 32 characters."""
        local = "12 profiles behind upstream, 103 refs to re-read"
        text = cf.render([cf.Finding("profiles", "profile_sync", cf.STALE, local=local,
                                     remote="run profile_sync --all --triage")])
        self.assertIn(local, text)
        self.assertIn("run profile_sync --all --triage", text)


class RepeatedDestinations(unittest.TestCase):
    def test_a_change_to_an_earlier_declaration_is_seen(self):
        from check_freshness import diff_platform  # noqa: PLC0415

        def platform(first_md5: str) -> dict:
            return {"systems": {"pce": {"files": [
                {"name": "syscard3.pce", "destination": "syscard3.pce", "md5": first_md5},
                {"name": "syscard3.pce", "destination": "syscard3.pce", "md5": "b" * 32},
            ]}}}

        diff = diff_platform(platform("a" * 32), platform("c" * 32))
        self.assertEqual(diff.files_changed, ["pce/syscard3.pce"])


class PinsWithExtras(unittest.TestCase):
    def test_an_extras_bracket_keeps_its_pin(self):
        from check_freshness import parse_pip_pins  # noqa: PLC0415

        pins = parse_pip_pins('  run: pip install pyyaml "jsonschema[format-nongpl]==4.26.0"')
        self.assertEqual(pins["jsonschema"], "==4.26.0")



class AStaticTargetStillNamesItsCores(unittest.TestCase):
    """RetroBat's single target is `cores: null`, and the check returned OK
    before reading the names, and its 50 unprofiled emulators never showed."""

    def test_declared_names_are_checked(self):
        names = cf._declared_cores("retrobat")
        self.assertIn("winuae", names)
        source = Path(cf.__file__).read_text()
        static = source.index('detail="every declared core"')
        self.assertLess(static, source.index("_declared_cores(platform)"))



class TheBuildbotIndexIsRead(unittest.TestCase):
    """A new asset in buildbot's assets/system was seen only by
    check_buildbot_system, which exited 0, as a non-blocking step."""

    def test_new_and_dropped_assets_are_stale(self):
        from unittest import mock

        import check_buildbot_system as cbs

        report = {"entries": [
            {"zip": "New.zip", "status": "NEW", "key": None},
            {"zip": "Old.zip", "status": "OK", "key": "old"},
        ]}
        with mock.patch.object(cbs, "check", lambda registry: report):
            finding = cf._check_buildbot_system()
        self.assertEqual(finding.status, cf.STALE)
        self.assertIn("new New.zip", finding.detail)
        with mock.patch.object(cbs, "check", lambda registry: {"error": "x", "entries": []}):
            self.assertEqual(cf._check_buildbot_system().status, cf.UNKNOWN)
        self.assertEqual([e["zip"] for e in cbs.pending(report)], ["New.zip"])



class RowsSayAllTheyStandFor(unittest.TestCase):
    """A row with no remote value ended on an arrow to nothing, and the 50
    RetroPie cores without a profile were cut to 12, in --json too."""

    def test_no_arrow_without_a_remote_value(self):
        text = cf.render([
            cf.Finding("native", "emudeck", "OK", local="1 file(s)"),
        ])
        self.assertNotIn("->", text)

    def test_a_detail_starts_in_one_column(self):
        text = cf.render([
            cf.Finding("native", "amberelec", cf.STALE, detail="no longer matches"),
            cf.Finding("native", "bizhawk", cf.STALE, local="1 file(s)", detail="is not what"),
        ])
        rows = [line for line in text.splitlines() if line.startswith("  STALE")]
        self.assertEqual(rows[0].index("no longer"), rows[1].index("is not what"))

    def test_json_carries_every_unresolved_name(self):
        missing = {f"core{i:02d}": [] for i in range(50)}
        (row,) = cf._unresolved_findings("retropie", missing)
        self.assertEqual(len(row.items), 50)
        self.assertIn("--json lists all 50", row.detail)


class AReleasePageMakesAProfileStale(unittest.TestCase):
    def test_a_newer_announced_version_is_stale(self):
        import check_freshness

        rows = [
            {"name": "altirra", "skipped": "unsupported host: x",
             "declared_version": "4.40", "page_version": "4.50"},
            {"name": "mednafen", "skipped": "unsupported host: y",
             "declared_version": "1.32.1", "page_version": "1.32.1"},
        ]
        found = {f.subject: f.status for f in check_freshness.summarize_profile_sync(rows)}
        self.assertEqual(found["altirra"], check_freshness.STALE)
        self.assertEqual(found["mednafen"], check_freshness.OK)

    def test_a_release_with_no_genuine_copy_waits_for_the_next(self):
        """FPse 13.0 exists only as rebuilt copies: the profile stays on 12.1
        and flagging it on every run said nothing new. 13.1 would."""
        import check_freshness

        rows = [
            {"name": "fpse", "skipped": "unsupported host: x", "declared_version": "12.1",
             "page_version": "13.0", "no_genuine_copy": "13.0"},
            {"name": "later", "skipped": "unsupported host: x", "declared_version": "12.1",
             "page_version": "13.1", "no_genuine_copy": "13.0"},
        ]
        found = {f.subject: f for f in check_freshness.summarize_profile_sync(rows)}
        self.assertEqual(found["fpse"].status, check_freshness.OK)
        self.assertIn("no genuine copy", found["fpse"].detail)
        self.assertEqual(found["later"].status, check_freshness.STALE)

    def test_no_genuine_copy_is_never_the_profiled_version(self):
        """The field names a release the profile could not read."""
        import yaml

        for path in sorted((REPO_ROOT / "emulators").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if "no_genuine_copy" not in text:
                continue
            profile = yaml.safe_load(text)
            source = profile["version_source"]
            with self.subTest(profile=path.stem):
                self.assertNotEqual(source["no_genuine_copy"], str(profile["core_version"]))


if __name__ == "__main__":
    unittest.main()
