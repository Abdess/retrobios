"""refresh_stale: which command answers which stale row, and in what order.

The network side is check_freshness and the scrapers themselves. What is
locked here is the planning: a stale row maps to one command, rows a human
must read are surfaced instead of run, and a platform rescrape is followed
by the refresh of the original its export patches.
"""

from __future__ import annotations

import tests

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from freshness import stalefindings
from freshness.stalecommands import AUTO_AREAS, MANUAL_AREAS, verify_command
from freshness.stalefindings import load_findings
from freshness.stalejob import LOG_DIR, Job, JobResult
from freshness.staleplan import plan_jobs
from freshness.stalereport import render
from freshness.stalerun import run_job, run_jobs

REPO_ROOT = Path(__file__).resolve().parents[1]

REGISTRY = {
    "retrobat": {"scraper": "retrobat", "target_scraper": None},
    "batocera": {"scraper": "batocera", "target_scraper": "batocera_targets"},
    "lakka": {},
}


def finding(area: str, subject: str, status: str = "STALE") -> dict:
    return {"area": area, "subject": subject, "status": status, "detail": ""}


class Planning(unittest.TestCase):
    def _plan(self, *findings: dict, parents: dict | None = None):
        return plan_jobs(list(findings), REGISTRY, parents or {})

    def test_a_stale_platform_is_rescraped_then_its_original_is_refreshed(self):
        jobs, surfaced, _ = self._plan(finding("platforms", "retrobat"))
        self.assertEqual(surfaced, [])
        self.assertEqual(len(jobs), 1)
        self.assertEqual(
            jobs[0].command[1:],
            ["-m", "scripts.scraper.retrobat_scraper", "-o", "platforms/retrobat.yml"],
        )
        # The truth reads the platform file and export_native refuses one
        # older than the profiles: regenerated between the two.
        self.assertEqual(
            [list(c[1:]) for c in jobs[0].then],
            [["scripts/generate_truth.py", "--platform", "retrobat"],
             ["scripts/export_native.py", "--platform", "retrobat", "--refresh-cache"],
             ["scripts/export_native.py", "--platform", "retrobat"],
             ["scripts/verify.py", "--platform", "retrobat"]],
        )

    def test_a_scraper_reading_its_pin_is_moved_by_rescrape_args(self):
        registry = dict(REGISTRY, retrobat={"scraper": "retrobat",
                                            "rescrape_args": ["--revision", "master"]})
        jobs, _, _ = plan_jobs([finding("platforms", "retrobat")], registry, {})
        self.assertEqual(jobs[0].command[-2:], ["--revision", "master"])
        with (REPO_ROOT / "platforms" / "_registry.yml").open(encoding="utf-8") as fh:
            real = yaml.safe_load(fh)["platforms"]["retrobat"]
        self.assertEqual(real["rescrape_args"], ["--revision", "master"])

    def test_a_child_waits_for_its_rescraped_parent(self):
        """retropie inherits retroarch: run beside the parent's rescrape, its
        truth read the old parent and its export was refused as stale."""
        registry = dict(REGISTRY, retroarch={"scraper": "libretro"},
                        retropie={"scraper": "retropie"})
        parents = {"retropie": "retroarch", "lakka": "retroarch"}
        jobs, _, _ = plan_jobs(
            [finding("platforms", "retroarch"), finding("platforms", "retropie"),
             finding("platforms", "retrobat")],
            registry, parents,
        )
        after = {(j.area, j.subject): j.after for j in jobs}
        self.assertEqual(after[("platforms", "retroarch")], frozenset())
        self.assertEqual(after[("platforms", "retrobat")], frozenset())
        self.assertEqual(after[("platforms", "retropie")], frozenset({"retroarch"}))
        # lakka has no row and no scraper: its export follows the parent's.
        self.assertEqual(after[("native", "lakka")], frozenset({"retroarch"}))

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
            jobs[0].command[1:], ["scripts/generate_truth.py", "--platform", "lakka"]
        )
        self.assertEqual(
            [list(c[1:]) for c in jobs[0].then],
            # exports/ is published: the corrected file is written again
            # from the refreshed original.
            [["scripts/export_native.py", "--platform", "lakka", "--refresh-cache"],
             ["scripts/export_native.py", "--platform", "lakka"]],
        )

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
                "fbneo recipes": "-m scripts.scraper.arcade.romset_dat_importer"
                " --source fbneo --fetch",
            },
        )
        self.assertEqual([f["subject"] for f in surfaced], ["redump"])

    def test_game_catalogs_are_imported_again(self):
        jobs, _surfaced, _ = self._plan(
            finding("catalogs", "no-intro games"), finding("catalogs", "redump games"))
        self.assertEqual(
            {j.subject: " ".join(j.command[1:]) for j in jobs},
            {
                "no-intro games": "-m scripts.scraper.dats.game_dat_importer --source no-intro"
                " --fetch --refresh --floor",
                "redump games": "-m scripts.scraper.dats.game_dat_importer --source redump"
                " --fetch --refresh --floor",
            },
        )

    def test_a_data_row_outside_the_registry_needs_a_human(self):
        """refresh_data_dirs.py --key 'buildbot system' exits 1 on an unknown
        key: the row asks for a registry entry, not a refresh."""
        jobs, surfaced, _ = self._plan(
            finding("data", "buildbot system"), finding("data", "_data_dirs.yml")
        )
        self.assertEqual(jobs, [])
        self.assertEqual([f["subject"] for f in surfaced],
                         ["buildbot system", "_data_dirs.yml"])

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

    def test_the_installer_pin_is_written_by_its_script(self):
        jobs, surfaced, _ = self._plan(finding("ci", "install.py pin"))
        self.assertEqual([job.command[1:] for job in jobs], [["scripts/pin_installer.py"]])
        self.assertEqual(surfaced, [])

    def test_the_help_lists_an_area_with_a_refresher_as_refreshed(self):
        """--help listed ci for a human while its install.py pin row ran
        scripts/pin_installer.py: both now read the planner's table."""
        self.assertIn("ci", AUTO_AREAS)
        self.assertNotIn("ci", MANUAL_AREAS)
        for area in MANUAL_AREAS:
            with self.subTest(area=area):
                jobs, _, _ = self._plan(finding(area, "anything"))
                self.assertEqual(jobs, [])


class ProducedRows(unittest.TestCase):
    """The rows the checks write are the ones the planner knows: a renamed
    row would otherwise leave its refresher unplanned with the suite green."""

    def _stale(self, row) -> dict:
        from dataclasses import asdict, replace

        return asdict(replace(row, status="STALE"))

    def test_catalog_rows_reach_their_importers(self):
        from freshness import catalogs

        with tempfile.TemporaryDirectory() as cache:
            rows = [
                catalogs._check_mame(cache, True),
                catalogs._check_fbneo(cache, True),
                catalogs._check_nointro_games(cache, True),
                catalogs._check_redump_games(True),
            ]
        jobs, surfaced, _ = plan_jobs([self._stale(r) for r in rows], REGISTRY, {})
        sources = {job.subject: job.command[job.command.index("--source") + 1] for job in jobs}
        self.assertEqual(sources, {
            "mame recipes": "mame", "fbneo recipes": "fbneo",
            "no-intro games": "no-intro", "redump games": "redump",
        })
        self.assertEqual(surfaced, [])

    def test_the_installer_pin_row_reaches_its_script(self):
        from freshness import ci

        jobs, surfaced, _ = plan_jobs([self._stale(ci._check_installer_pins())], REGISTRY, {})
        self.assertEqual([job.command[1:] for job in jobs], [["scripts/pin_installer.py"]])
        self.assertEqual(surfaced, [])

    def test_the_unprofiled_cores_row_is_surfaced(self):
        from freshness import targets

        rows = targets._unresolved_findings("batocera", {"newcore": []})
        jobs, surfaced, _ = plan_jobs([self._stale(r) for r in rows], REGISTRY, {})
        self.assertEqual(jobs, [])
        self.assertEqual([f["subject"] for f in surfaced], ["batocera cores"])


class Running(unittest.TestCase):
    def test_a_child_starts_after_its_parent_ends(self):
        with tempfile.TemporaryDirectory() as directory:
            order = Path(directory) / "order"
            def job(area, subject, after=()):
                code = f"open({str(order)!r}, 'a').write({subject!r} + chr(10))"
                if subject == "parent":
                    code = "import time; time.sleep(0.5); " + code
                return Job(area, subject, [sys.executable, "-c", code],
                              Path(directory) / f"{subject}.log", (), frozenset(after))
            run_jobs([job("native", "child", ["parent"]),
                         job("platforms", "parent")], {}, 4)
            self.assertEqual(order.read_text().split(), ["parent", "child"])

    def test_the_report_prints_verify_after_a_rescrape(self):
        job = Job("platforms", "x", ["true"], LOG_DIR / "x.log")
        outputs = (
            (("true",), "scraped\n"),
            (tuple(verify_command("x")), "\nX: 10/12 OK, 2 missing [md5]\n"),
        )
        text = render([JobResult(job, 0, 1.0, "", outputs)], [], [])
        self.assertIn("X: 10/12 OK, 2 missing [md5]", text)
        self.assertIn("python scripts/verify.py --platform x", text)

    def test_the_verify_output_is_read_whatever_its_command_line(self):
        """The report found verify by a copy of its command line in the log:
        a verify run as `-m scripts.verify` read as `(no verify output)`."""
        with tempfile.TemporaryDirectory() as directory:
            verify = (sys.executable, "-c", "print('X: 10/12 OK')")
            job = Job("platforms", "x", [sys.executable, "-c", "print('scraped')"],
                      Path(directory) / "x.log", (verify,))
            with mock.patch("freshness.stalereport.verify_command", return_value=list(verify)):
                result = run_job(job, {})
                text = render([result], [], [])
        self.assertEqual(result.output_of(job.command), "scraped\n")
        self.assertIn("X: 10/12 OK", text)

    def _job(self, directory: str, command: list[str], then=()) -> Job:
        return Job("platforms", "x", command, Path(directory) / "x.log", then)

    def test_a_follow_up_runs_after_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            job = self._job(
                directory,
                [sys.executable, "-c", "pass"],
                ((sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"),),
            )
            result = run_job(job, {})
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
            result = run_job(job, {})
            self.assertEqual(result.returncode, 3)
            self.assertFalse(marker.exists())


class SavedFindings(unittest.TestCase):
    """--findings reads the report a full check_freshness run saved, so the
    nightly job checks every area once and refreshes only some."""

    def test_rows_outside_the_asked_areas_are_left_out(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "freshness.json"
            path.write_text(
                '[{"area": "data", "subject": "dolphin-sys", "status": "STALE"},'
                ' {"area": "platforms", "subject": "batocera", "status": "STALE"}]',
                encoding="utf-8",
            )
            findings = load_findings(path, ("data", "catalogs"))
            self.assertEqual([f["subject"] for f in findings], ["dolphin-sys"])

    def test_dry_run_json_prints_the_plan_as_json(self):
        """--dry-run --json printed the text plan, and a caller parsing it
        as JSON failed on the first line."""
        import json
        import subprocess

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "freshness.json"
            path.write_text(json.dumps([
                finding("catalogs", "mame recipes"), finding("coreinfo", "anybor"),
            ]), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "scripts/refresh_stale.py", "--findings", str(path),
                 "--dry-run", "--json"],
                cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=120,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        plan = json.loads(proc.stdout)
        self.assertEqual([(j["area"], j["subject"]) for j in plan["planned"]],
                         [("catalogs", "mame recipes")])
        self.assertEqual([f["subject"] for f in plan["surfaced"]], ["anybor"])

    def test_every_area_check_freshness_reports_is_known(self):
        """romfolders was added to check_freshness and not here: its rows
        were dropped from a saved report without a word, and --only
        romfolders was refused."""
        from freshness.findings import AREAS

        self.assertEqual(set(AREAS), set(AUTO_AREAS + MANUAL_AREAS))
        jobs, surfaced, _ = plan_jobs([finding("romfolders", "muos")], REGISTRY, {})
        self.assertEqual((jobs, [f["subject"] for f in surfaced]), ([], ["muos"]))

    def test_a_report_that_is_not_a_list_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "freshness.json"
            path.write_text('{"area": "data"}', encoding="utf-8")
            with self.assertRaises(RuntimeError):
                load_findings(path, ("data",))


class AFailedCheckIsNamed(unittest.TestCase):
    """A crash of check_freshness exits 1 like a STALE row: its traceback,
    on stderr, was dropped for "unreadable JSON", and a timeout ended on
    a traceback of refresh_stale itself."""

    def _run(self, raises: Exception | None = None, **result):
        proc = subprocess.CompletedProcess([], **result) if result else None
        with mock.patch.object(stalefindings.subprocess, "run", side_effect=raises, return_value=proc):
            return stalefindings.run_check_freshness(("coreinfo",), [])

    def test_a_crash_shows_its_stderr(self):
        with self.assertRaises(RuntimeError) as raised:
            self._run(returncode=1, stdout="", stderr="Traceback\nRuntimeError: no listing\n")
        self.assertIn("RuntimeError: no listing", str(raised.exception))
        self.assertNotIn("JSON", str(raised.exception))

    def test_stale_rows_are_read(self):
        self.assertEqual(self._run(returncode=1, stdout='[{"area": "coreinfo"}]', stderr=""),
                         [{"area": "coreinfo"}])

    def test_a_timeout_says_what_to_run(self):
        with self.assertRaises(RuntimeError) as raised:
            self._run(raises=subprocess.TimeoutExpired(["x"], 1800))
        self.assertIn("--findings", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
