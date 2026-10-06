"""check_freshness: the pure parts, no network.

The script answers "is the local copy the one upstream serves" for every
transcribed layer. What can be locked without a network is how a diff is
read, how a core name is resolved, how a pin is parsed, and how a profile
report is folded, since each of those decides whether a row says STALE.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
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
        removed = {"android": {"na"}}
        self.assertEqual(
            cf.unresolved_target_cores(targets, index, removed),
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
        removed = cf._removed_cores(overrides, "plat")
        self.assertEqual(
            cf.unresolved_target_cores(targets, index, removed),
            {"ghost": ["x86_64"]},
        )

    def test_coreinfo_gaps_fold_case_and_flag_standalone_profiles(self):
        names = ["FreeIntvTSOverlay", "eka2l1", "wqxemu", "mednafen_psx"]
        unprofiled, standalone = cf.coreinfo_gaps(names, self.PROFILES)
        self.assertEqual(unprofiled, ["wqxemu"])
        self.assertEqual(standalone, [("eka2l1", "eka2l1")])


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


class CatalogParsingTests(unittest.TestCase):
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
            {"name": "d", "skipped": "host does not resolve"},
        ]
        findings = cf.summarize_profile_sync(report)
        by_subject = {f.subject: f for f in findings}
        self.assertEqual(by_subject["profile_sync"].status, cf.STALE)
        self.assertEqual(by_subject["profile_sync"].local, "1 at tip, 1 anchored past the tip")
        self.assertEqual(by_subject["c"].status, cf.STALE)
        self.assertEqual(by_subject["d"].status, cf.UNKNOWN)
        self.assertNotIn("a", by_subject)
        self.assertNotIn("b", by_subject)

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


if __name__ == "__main__":
    unittest.main()
