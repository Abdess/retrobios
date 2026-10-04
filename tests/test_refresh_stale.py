"""refresh_stale: which command answers which stale row, and in what order.

The network side is check_freshness and the scrapers themselves. What is
locked here is the planning: a stale row maps to one command, rows a human
must read are surfaced instead of run, and a platform rescrape is followed
by the refresh of the original its export patches.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import refresh_stale as rs  # noqa: E402

REGISTRY = {
    "retrobat": {"scraper": "retrobat", "target_scraper": None},
    "batocera": {"scraper": "batocera", "target_scraper": "batocera_targets"},
    "lakka": {},
}


def finding(area: str, subject: str, status: str = "STALE") -> dict:
    return {"area": area, "subject": subject, "status": status, "detail": ""}


class Planning(unittest.TestCase):
    def _plan(self, *findings: dict):
        return rs.plan_jobs(list(findings), REGISTRY)

    def test_a_stale_platform_is_rescraped_then_its_original_is_refreshed(self):
        jobs, surfaced, _ = self._plan(finding("platforms", "retrobat"))
        self.assertEqual(surfaced, [])
        self.assertEqual(len(jobs), 1)
        self.assertEqual(
            jobs[0].command[1:],
            ["-m", "scripts.scraper.retrobat_scraper", "-o", "platforms/retrobat.yml"],
        )
        self.assertEqual(
            [list(c[1:]) for c in jobs[0].then],
            [["scripts/export_native.py", "--platform", "retrobat", "--refresh-cache"]],
        )

    def test_a_native_row_of_a_rescraped_platform_is_not_a_second_job(self):
        """Two jobs would race: the refresh must follow the scrape."""
        jobs, _, ignored = self._plan(
            finding("native", "retrobat"), finding("platforms", "retrobat")
        )
        self.assertEqual([j.area for j in jobs], ["platforms"])
        self.assertEqual([f["area"] for f in ignored], ["native"])

    def test_a_stale_original_alone_is_refreshed(self):
        jobs, _, _ = self._plan(finding("native", "lakka"))
        self.assertEqual(
            jobs[0].command[1:],
            ["scripts/export_native.py", "--platform", "lakka", "--refresh-cache"],
        )
        self.assertEqual(jobs[0].then, ())

    def test_a_platform_without_a_scraper_is_surfaced(self):
        jobs, surfaced, _ = self._plan(finding("platforms", "lakka"))
        self.assertEqual(jobs, [])
        self.assertEqual([f["subject"] for f in surfaced], ["lakka"])

    def test_unprofiled_cores_need_a_human(self):
        jobs, surfaced, _ = self._plan(finding("targets", "batocera cores"))
        self.assertEqual(jobs, [])
        self.assertEqual(len(surfaced), 1)

    def test_targets_data_and_recipes_map_to_their_refreshers(self):
        jobs, surfaced, _ = self._plan(
            finding("targets", "batocera"),
            finding("data", "dolphin-sys"),
            finding("catalogs", "fbneo recipes"),
            finding("catalogs", "redump"),
        )
        commands = {j.subject: " ".join(j.command[1:]) for j in jobs}
        self.assertEqual(
            commands,
            {
                "batocera": "-m scripts.scraper.targets.batocera_targets_scraper"
                " -o platforms/targets/batocera.yml",
                "dolphin-sys": "scripts/refresh_data_dirs.py --key dolphin-sys --force",
                "fbneo recipes": "-m scripts.scraper.romset_dat_importer"
                " --source fbneo --fetch",
            },
        )
        self.assertEqual([f["subject"] for f in surfaced], ["redump"])

    def test_only_stale_rows_run_and_errors_are_shown(self):
        jobs, surfaced, ignored = self._plan(
            finding("data", "a", "OK"),
            finding("data", "b", "SKIPPED"),
            finding("platforms", "retrobat", "ERROR"),
        )
        self.assertEqual(jobs, [])
        self.assertEqual([f["status"] for f in surfaced], ["ERROR"])
        self.assertEqual(len(ignored), 2)

    def test_pins_and_profiles_are_never_run(self):
        jobs, surfaced, _ = self._plan(
            finding("ci", "pypi:jsonschema"),
            finding("coreinfo", "libretro-core-info"),
            finding("profiles", "profile_sync"),
        )
        self.assertEqual(jobs, [])
        self.assertEqual(len(surfaced), 3)


class Running(unittest.TestCase):
    def _job(self, directory: str, command: list[str], then=()) -> rs.Job:
        return rs.Job("platforms", "x", command, Path(directory) / "x.log", then)

    def test_a_follow_up_runs_after_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            job = self._job(
                directory,
                [sys.executable, "-c", "pass"],
                ((sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"),),
            )
            result = rs.run_job(job, {})
            self.assertEqual(result.returncode, 0)
            self.assertTrue(marker.exists())

    def test_a_failed_scrape_leaves_the_original_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            job = self._job(
                directory,
                [sys.executable, "-c", "raise SystemExit(3)"],
                ((sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"),),
            )
            result = rs.run_job(job, {})
            self.assertEqual(result.returncode, 3)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
