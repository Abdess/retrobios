"""The site and the README share one coverage computation.

generate_site.py and generate_readme.py each verified every platform, a
minute of the site build spent twice on the same answer. The first to run
stores the coverage, keyed by its inputs, and the second reads it. A cache
that outlived a change to its inputs would publish stale counts, so these
tests change an input and expect a fresh computation.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_readme  # noqa: E402


class CoverageCache(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        self.platforms = self.work / "platforms"
        self.platforms.mkdir()
        (self.platforms / "alpha.yml").write_text("platform: Alpha\n")
        self.emulators = self.work / "emulators"
        self.emulators.mkdir()
        self.db = self.work / "database.json"
        self.db.write_text("{}")
        self.calls: list[str] = []
        patches = [
            mock.patch.object(generate_readme, "COVERAGE_CACHE_DIR", self.work / "cache"),
            mock.patch.object(generate_readme, "compute_coverage", self._compute),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.work, ignore_errors=True)

    def _compute(self, name, platforms_dir, db, data_registry=None, emulators_dir=""):
        self.calls.append(name)
        if name == "ghost":
            raise FileNotFoundError(name)
        return {"platform": name.title(), "missing_names": {"a.bin"}}

    def _run(self, names=("beta", "alpha")) -> dict:
        return generate_readme.platform_coverages(
            list(names), str(self.platforms), {}, {},
            emulators_dir=str(self.emulators), db_path=str(self.db),
        )

    def test_second_run_reads_the_first(self):
        first = self._run()
        self.assertEqual(self.calls, ["alpha", "beta"])
        second = self._run()
        self.assertEqual(self.calls, ["alpha", "beta"])
        self.assertEqual(first, second)
        # The caller's order, not the computation's.
        self.assertEqual(list(second), ["beta", "alpha"])
        self.assertEqual(second["alpha"]["missing_names"], {"a.bin"})

    def test_a_changed_input_computes_again(self):
        self._run()
        for change in (
            lambda: (self.platforms / "alpha.yml").write_text("platform: Alpha 2\n"),
            lambda: self.db.write_text('{"files": {}}'),
            lambda: (self.emulators / "core.yml").write_text("emulator: core\n"),
        ):
            self.calls.clear()
            change()
            self._run()
            self.assertEqual(self.calls, ["alpha", "beta"])

    def test_another_platform_list_computes_again(self):
        self._run()
        self.calls.clear()
        self._run(("alpha",))
        self.assertEqual(self.calls, ["alpha"])

    def test_a_platform_without_a_file_is_left_out(self):
        self.assertEqual(list(self._run(("ghost", "alpha"))), ["alpha"])
        self.assertEqual(list(self._run(("ghost", "alpha"))), ["alpha"])

    def test_one_cache_file_is_kept(self):
        self._run()
        (self.platforms / "alpha.yml").write_text("platform: Alpha 3\n")
        self._run()
        self.assertEqual(len(list((self.work / "cache").glob("*.pickle"))), 1)

    def test_a_purge_racing_another_generator_does_not_fail(self):
        """generate_site and generate_readme purge the same directory: one
        unlinking a pickle the other had listed ended on FileNotFoundError."""
        cache_dir = self.work / "cache"
        cache_dir.mkdir()
        ghost = cache_dir / "gone.pickle"
        real_glob = Path.glob

        def listing_a_vanished_file(path, pattern):
            found = list(real_glob(path, pattern))
            return [*found, ghost] if path == cache_dir else found

        with mock.patch.object(Path, "glob", listing_a_vanished_file):
            coverages = self._run()
        self.assertEqual(sorted(coverages), ["alpha", "beta"])
        self.assertEqual(len(list(cache_dir.glob("*.pickle"))), 1)

    def test_a_missing_input_directory_stops_the_run(self):
        """A missing --emulators-dir skipped every platform as if it had no
        YAML, then replaced the cache with the empty result."""
        self._run()
        kept = sorted((self.work / "cache").glob("*.pickle"))

        def missing(*_args, **_kwargs):
            raise generate_readme.InputMissing("no emulator profile directory at nosuch")

        with mock.patch.object(generate_readme, "compute_coverage", missing), \
                mock.patch.object(generate_readme, "_coverage_inputs", return_value="other"), \
                self.assertRaises(generate_readme.InputMissing):
            self._run()
        self.assertEqual(sorted((self.work / "cache").glob("*.pickle")), kept)


if __name__ == "__main__":
    unittest.main()
