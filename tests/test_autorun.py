"""autorun: the runner every unattended job goes through, and its first jobs.

Everything here is offline. Jobs are fake commands, git repositories are
built in tmp/tests with a bare repository standing in for origin, and gh is
a function returning canned CI runs.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path
from types import MappingProxyType

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import autorun as ar  # noqa: E402
import bios_integrity as bib  # noqa: E402
import cleanup_disk as cd  # noqa: E402
import sync_release_assets as sra  # noqa: E402

PY = "python"
_ENV_KEYS = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")
_saved_env: dict[str, str | None] = {}
_config_dir: Path | None = None


def setUpModule() -> None:
    global _config_dir
    _config_dir = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
    config = _config_dir / "gitconfig"
    config.write_text(
        "[user]\n\tname = Test\n\temail = test@example.invalid\n"
        "[init]\n\tdefaultBranch = main\n"
        "[commit]\n\tgpgsign = false\n",
        encoding="utf-8",
    )
    for key in _ENV_KEYS:
        _saved_env[key] = os.environ.get(key)
    os.environ["GIT_CONFIG_GLOBAL"] = str(config)
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"


def tearDownModule() -> None:
    for key, value in _saved_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    if _config_dir is not None:
        shutil.rmtree(_config_dir, ignore_errors=True)


def run_git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True,
    ).stdout


class FakeHost(ar.Host):
    def __init__(self, loads: list[float] | None = None, cpus: int = 4) -> None:
        self.loads = list(loads or [0.0])
        self.now = 0.0
        self.slept: list[float] = []
        super().__init__(
            loadavg=self._load, sleep=self._sleep, clock=lambda: self.now,
            cpu_count=cpus, poll=10.0,
        )

    def _load(self) -> tuple[float, float, float]:
        value = self.loads.pop(0) if len(self.loads) > 1 else self.loads[0]
        return (value, value, value)

    def _sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp" / "tests"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def context(self, jobs: dict, **kwargs) -> ar.Context:
        repo = self.tmp / "repo"
        repo.mkdir(exist_ok=True)
        parsed = ar.parse_jobs({"jobs": jobs})
        kwargs.setdefault("host", FakeHost())
        return ar.Context(repo=repo, jobs=parsed, lock_path=self.tmp / "auto.lock", **kwargs)

    def state(self, ctx: ar.Context) -> dict:
        return json.loads(ctx.state_path.read_text(encoding="utf-8"))


class Registry(Scratch):
    def test_the_committed_registry_loads(self):
        jobs = ar.load_jobs()
        self.assertIn("nightly", jobs)
        self.assertTrue(jobs["nightly"].commits)
        self.assertFalse(jobs["disk-check"].lock)

    def test_an_unknown_key_is_refused(self):
        with self.assertRaises(ValueError):
            ar.parse_jobs({"jobs": {"x": {"steps": [], "schedul": "daily"}}})

    def test_a_subject_the_hook_refuses_is_refused_at_load(self):
        for subject in ("chore: fix the broken manifests",
                        "update things",
                        "chore: " + "a" * 60):
            with self.subTest(subject=subject), self.assertRaises(ValueError):
                ar.parse_jobs({"jobs": {"x": {"commits": [
                    {"subject": subject, "paths": ["a"]}]}}})

    def test_a_job_outside_the_worktree_cannot_commit(self):
        with self.assertRaises(ValueError):
            ar.parse_jobs({"jobs": {"x": {"worktree": False, "commits": [
                {"subject": "chore: add a", "paths": ["a"]}]}}})

    def test_a_twice_entry_names_its_output(self):
        with self.assertRaises(ValueError):
            ar.parse_jobs({"jobs": {"x": {"twice": [
                {"artifact": "a.json", "run": [PY, "gen.py"]}]}}})


class Lock(Scratch):
    def test_a_second_holder_is_refused(self):
        path = self.tmp / "auto.lock"
        with ar.global_lock(path):
            self.assertTrue(ar.lock_busy(path))
            with self.assertRaises(ar.LockBusy), ar.global_lock(path):
                pass
        self.assertFalse(ar.lock_busy(path))

    def test_a_job_waiting_on_the_lock_is_deferred_and_recorded(self):
        ctx = self.context({"x": {"worktree": False, "min_free_gb": 0,
                                  "steps": [[PY, "-c", "open('ran', 'w')"]]}})
        with ar.global_lock(ctx.lock_path):
            result, detail = ar.run_job(ctx, "x")
        self.assertEqual(result, ar.DEFERRED)
        self.assertIn("held", detail)
        self.assertFalse((ctx.repo / "ran").exists())
        self.assertEqual(self.state(ctx)["jobs"]["x"]["result"], ar.DEFERRED)

    def test_a_job_that_takes_no_lock_runs_beside_a_holder(self):
        ctx = self.context({"x": {"worktree": False, "lock": False, "min_free_gb": 0,
                                  "steps": [[PY, "-c", "open('ran', 'w')"]]}})
        with ar.global_lock(ctx.lock_path):
            self.assertEqual(ar.run_job(ctx, "x")[0], ar.OK)
        self.assertTrue((ctx.repo / "ran").exists())


class Guards(Scratch):
    def test_the_load_guard_waits_then_lets_go(self):
        host = FakeHost(loads=[3.0, 3.0, 0.5], cpus=4)
        self.assertTrue(ar.wait_for_load(host, max_wait=600))
        self.assertEqual(host.slept, [10.0, 10.0])

    def test_the_load_guard_gives_up_at_its_deadline(self):
        host = FakeHost(loads=[8.0], cpus=4)
        self.assertFalse(ar.wait_for_load(host, max_wait=25))
        self.assertEqual(sum(host.slept), 25)

    def test_a_busy_host_defers_the_job(self):
        ctx = self.context({"x": {"worktree": False, "min_free_gb": 0, "max_load_wait": 0,
                                  "steps": [[PY, "-c", "open('ran', 'w')"]]}},
                           host=FakeHost(loads=[64.0]))
        self.assertEqual(ar.run_job(ctx, "x")[0], ar.DEFERRED)
        self.assertFalse((ctx.repo / "ran").exists())

    def test_a_full_disk_refuses_the_job(self):
        ctx = self.context({"x": {"worktree": False, "min_free_gb": 10 ** 9,
                                  "steps": [[PY, "-c", "open('ran', 'w')"]]}})
        result, detail = ar.run_job(ctx, "x")
        self.assertEqual(result, ar.REFUSED)
        self.assertIn("GB free", detail)
        self.assertFalse((ctx.repo / "ran").exists())

    def test_a_failure_counts_and_a_success_resets(self):
        ctx = self.context({
            "bad": {"worktree": False, "min_free_gb": 0, "steps": [[PY, "-c", "raise SystemExit(3)"]]},
        })
        ar.run_job(ctx, "bad")
        ar.run_job(ctx, "bad")
        record = self.state(ctx)["jobs"]["bad"]
        self.assertEqual(record["result"], ar.FAILED)
        self.assertEqual(record["consecutive_failures"], 2)
        self.assertIsNone(record["last_success"])


class StepEnvironment(Scratch):
    """A step can run third-party code: it never inherits a token or a password."""

    HOST = MappingProxyType({
        "PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C.UTF-8", "LC_ALL": "C", "TZ": "UTC",
        "TMPDIR": "/t", "GITHUB_TOKEN": "t1", "GH_TOKEN": "t2", "ROMSTATION_USER": "u",
        "ROMSTATION_PASS": "p", "NPM_TOKEN": "t3", "AWS_SECRET_ACCESS_KEY": "s",
        "DB_PASSWORD": "p2", "ROMFETCH_CONTENT_DIR": "/c", "EDITOR": "vi"})

    def test_the_allowlist(self):
        env = ar.safe_env(["ROMFETCH_CONTENT_DIR", "GITHUB_TOKEN"], {"RETROBIOS_AUTO": "1"},
                          source=dict(self.HOST))
        self.assertEqual(env, {"PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C.UTF-8",
                               "LC_ALL": "C", "TZ": "UTC", "TMPDIR": "/t",
                               "ROMFETCH_CONTENT_DIR": "/c", "RETROBIOS_AUTO": "1"})

    def test_a_step_naming_a_secret_is_refused_at_load(self):
        for name in ("GITHUB_TOKEN", "ROMSTATION_PASS", "MY_SECRET"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ar.parse_jobs({"jobs": {"x": {"steps": [{"run": [PY, "-V"], "env": [name]}]}}})

    def test_a_network_job_step_sees_no_token(self):
        dump = "import json, os; print(json.dumps(dict(os.environ)))"
        ctx = self.context({"x": {"worktree": False, "min_free_gb": 0, "network": True,
                                  "steps": [{"run": [PY, "-c", dump], "stdout": "env.json",
                                             "env": ["ROMFETCH_CONTENT_DIR"]}]}})
        with unittest.mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t1", "GH_TOKEN": "t2",
                                                   "ROMSTATION_PASS": "p",
                                                   "ROMFETCH_CONTENT_DIR": "/c", "EDITOR": "vi"}):
            self.assertEqual(ar.run_job(ctx, "x")[0], ar.OK)
            given = ar.token_env()
        seen = json.loads((ctx.repo / "env.json").read_text())
        self.assertFalse({"GITHUB_TOKEN", "GH_TOKEN", "ROMSTATION_PASS", "EDITOR"} & set(seen))
        self.assertEqual((seen["ROMFETCH_CONTENT_DIR"], seen["RETROBIOS_AUTO"]), ("/c", "1"))
        self.assertEqual(seen[ar.LOCK_HELD_ENV], "1")
        # The push and gh are the phases that get it.
        self.assertEqual(given["GITHUB_TOKEN"], "t1")


class GithubTokenPerStep(Scratch):
    """GITHUB_TOKEN goes to first-party scripts that call the API, declared
    per step, and never to third-party code or the campaign."""

    def job(self, run: list[str], name: str = "x") -> dict:
        return ar.parse_jobs({"jobs": {name: {"steps": [{"run": run, "github_token": True}]}}})

    def test_allowed_on_the_scrapers_and_freshness_scripts(self):
        for run in ([PY, "-m", "scripts.scraper.mame_hash_scraper"],
                    [PY, "scripts/check_freshness.py", "--json"],
                    [PY, "scripts/refresh_stale.py", "--only", "data"]):
            with self.subTest(run=run):
                step = self.job(run)["x"].steps[0]
                self.assertTrue(step.github_token)
                with unittest.mock.patch.object(ar, "token_env", return_value={"GITHUB_TOKEN": "t1"}):
                    self.assertEqual(ar.job_env(self.job(run)["x"], step)["GITHUB_TOKEN"], "t1")

    def test_refused_on_any_other_step(self):
        for run in ([PY, "-c", "print(1)"], [PY, "scripts/campaign.py", "run"],
                    [PY, "scripts/core_probe.py", "run"], ["sh", "-c", "env"],
                    [PY, "scripts/not_tracked_here.py"], [PY, "-m", "scripts.scraper.not_tracked"],
                    [PY, "-m", "os"], ["/usr/bin/python3", "scripts/check_freshness.py"]):
            with self.subTest(run=run), self.assertRaises(ValueError):
                self.job(run)

    def test_refused_in_the_campaign_job_even_on_a_scraper(self):
        with self.assertRaisesRegex(ValueError, "campaign never receives"):
            self.job([PY, "-m", "scripts.scraper.mame_hash_scraper"], name="campaign")

    def test_an_undeclared_step_gets_no_token(self):
        job = ar.parse_jobs({"jobs": {"x": {"network": True, "steps": [
            [PY, "-m", "scripts.scraper.mame_hash_scraper"]]}}})["x"]
        with unittest.mock.patch.object(ar, "token_env", return_value={"GITHUB_TOKEN": "t1"}), \
                unittest.mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t1"}):
            self.assertNotIn("GITHUB_TOKEN", ar.job_env(job, job.steps[0]))

    def test_the_committed_registry(self):
        jobs = ar.load_jobs()
        self.assertTrue(all(step.github_token for step in jobs["nightly"].steps))


class ReportAlert(Scratch):
    def test_a_report_alert_is_raised_then_cleared(self):
        write = "import json, sys; json.dump({'alert': sys.argv[1]} if sys.argv[1] else {}, open('r.json', 'w'))"
        for message, expected in (("no sandbox", True), ("", False)):
            ctx = self.context({"x": {"worktree": False, "min_free_gb": 0, "report": "r.json",
                                      "steps": [[PY, "-c", write, message]]}})
            ar.run_job(ctx, "x")
            alerts = self.state(ctx).get("alerts", {})
            self.assertEqual("job:x" in alerts, expected)
            if expected:
                self.assertEqual(alerts["job:x"]["detail"], "no sandbox")


class Retry(Scratch):
    def _runs(self, *outcomes: ar.Outcome):
        queue = list(outcomes)
        calls = []

        def run() -> ar.Outcome:
            calls.append(1)
            return queue.pop(0)
        return run, calls

    def test_a_segfault_is_retried_once_on_an_idle_host(self):
        run, calls = self._runs(ar.Outcome(139), ar.Outcome(0))
        waited = []
        outcome = ar.run_with_retry(run, (0,), lambda: waited.append(1))
        self.assertEqual((outcome.returncode, outcome.retried, len(calls), waited),
                         (0, True, 2, [1]))

    def test_a_second_segfault_is_a_failure(self):
        run, calls = self._runs(ar.Outcome(-11), ar.Outcome(-11), ar.Outcome(0))
        outcome = ar.run_with_retry(run, (0,), lambda: None)
        self.assertEqual((outcome.returncode, len(calls)), (-11, 2))

    def test_a_host_misread_message_is_retried(self):
        run, calls = self._runs(ar.Outcome(1, "SystemError: unknown opcode"), ar.Outcome(0))
        self.assertEqual(ar.run_with_retry(run, (0,), lambda: None).returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_an_ordinary_failure_is_not_retried(self):
        run, calls = self._runs(ar.Outcome(1, "KeyError: 'x'"), ar.Outcome(0))
        self.assertEqual(ar.run_with_retry(run, (0,), lambda: None).returncode, 1)
        self.assertEqual(len(calls), 1)

    def test_a_real_segfault_runs_again_and_the_job_passes(self):
        crash = ("import os, signal, pathlib\n"
                 "p = pathlib.Path('crashed')\n"
                 "if not p.exists():\n"
                 "    p.touch()\n"
                 "    os.kill(os.getpid(), signal.SIGSEGV)\n")
        ctx = self.context({"x": {"worktree": False, "min_free_gb": 0,
                                  "steps": [[PY, "-c", crash]]}})
        self.assertEqual(ar.run_job(ctx, "x")[0], ar.OK)
        self.assertEqual(len(self.state(ctx)["jobs"]["x"]["retried"]), 1)


class DoubleComputation(Scratch):
    GEN = ("import json, random, sys\n"
           "json.dump({'generated_at': str(random.random()), 'value': %s},"
           " open(sys.argv[1], 'w'))\n")

    def _run(self, cwd: Path):
        def run(argv):
            return ar.Outcome(subprocess.run(argv, cwd=cwd, check=False).returncode)
        return run

    def test_timestamps_aside_two_equal_runs_agree(self):
        script = self.tmp / "gen.py"
        script.write_text(self.GEN % "1", encoding="utf-8")
        diff = ar.twice([PY, str(script), "{out}"], self.tmp / "a.json",
                        self.tmp / "b.json", self._run(self.tmp))
        self.assertEqual(diff, [])

    def test_two_runs_that_disagree_are_named(self):
        script = self.tmp / "gen.py"
        script.write_text(self.GEN % "random.random()", encoding="utf-8")
        diff = ar.twice([PY, str(script), "{out}"], self.tmp / "a.json",
                        self.tmp / "b.json", self._run(self.tmp))
        self.assertEqual(diff, ["a.json"])

    def test_directories_compare_file_by_file_within_the_glob(self):
        a, b = self.tmp / "a", self.tmp / "b"
        (a / "targets").mkdir(parents=True)
        b.mkdir()
        (a / "x.json").write_text('{"generated": "1", "n": 1}')
        (b / "x.json").write_text('{"generated": "2", "n": 1}')
        (a / "targets" / "t.json").write_text("{}")
        self.assertEqual(ar.differences(a, b, "*.json"), [])
        (b / "y.json").write_text("{}")
        self.assertEqual(ar.differences(a, b, "*.json"), ["y.json"])

    def test_a_job_whose_artifact_disagrees_fails_with_an_alert(self):
        script = self.tmp / "repo" / "gen.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(self.GEN % "random.random()", encoding="utf-8")
        ctx = self.context({"x": {
            "worktree": False, "min_free_gb": 0, "max_load_wait": 0,
            "gate": [[PY, "gen.py", "db.json"]],
            "twice": [{"artifact": "db.json", "run": [PY, "gen.py", "{out}"]}],
        }})
        result, detail = ar.run_job(ctx, "x")
        self.assertEqual(result, ar.FAILED)
        self.assertIn("two computations disagree", detail)
        self.assertIn("host-integrity", self.state(ctx)["alerts"])

    def test_a_job_whose_artifact_agrees_passes_and_clears_the_alert(self):
        script = self.tmp / "repo" / "gen.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(self.GEN % "1", encoding="utf-8")
        ctx = self.context({"x": {
            "worktree": False, "min_free_gb": 0,
            "gate": [[PY, "gen.py", "db.json"]],
            "twice": [{"artifact": "db.json", "run": [PY, "gen.py", "{out}"]}],
        }})
        ar.save_state(ctx.state_path, {"alerts": {"host-integrity": {"since": "x"}}})
        self.assertEqual(ar.run_job(ctx, "x")[0], ar.OK)
        self.assertNotIn("host-integrity", self.state(ctx).get("alerts", {}))


def ci_run(sha: str, conclusion: str | None, created: str, name: str = "Deploy Site") -> dict:
    return {"workflowName": name, "headSha": sha, "createdAt": created,
            "status": "completed" if conclusion else "in_progress",
            "conclusion": conclusion or ""}


class CircuitBreaker(Scratch):
    def _gh(self, by_commit: dict, on_main: list):
        calls = []

        def gh(args):
            calls.append(args)
            if "--commit" in args:
                return by_commit.get(args[args.index("--commit") + 1], [])
            return on_main
        return gh, calls

    def test_a_red_run_on_the_pushed_commit_opens_it(self):
        state = {"push": {"sha": "a" * 40, "ci": "pending"}}
        gh, _ = self._gh({"a" * 40: [ci_run("a" * 40, "success", "2026-10-27T02:10:00Z"),
                                     ci_run("a" * 40, "failure", "2026-10-27T02:10:00Z",
                                            "Validate")]}, [])
        ar.refresh_breaker(state, gh, "now")
        self.assertTrue(state["breaker"]["open"])
        self.assertEqual(state["breaker"]["reason"], "Validate")
        self.assertIn("ci", state["alerts"])
        self.assertEqual(ar.may_push(state), "circuit breaker open")

    def test_runs_still_going_keep_the_push_pending(self):
        state = {"push": {"sha": "a" * 40, "ci": "pending"}}
        gh, _ = self._gh({"a" * 40: [ci_run("a" * 40, None, "2026-10-27T02:10:00Z")]}, [])
        ar.refresh_breaker(state, gh, "now")
        self.assertFalse(state["breaker"]["open"])
        self.assertIn("has not ended green", ar.may_push(state))

    def test_a_later_green_run_on_main_closes_it(self):
        state = {"push": {"sha": "a" * 40, "ci": "failure"},
                 "breaker": {"open": True, "sha": "a" * 40,
                             "failed_run_at": "2026-10-27T02:10:00Z"},
                 "alerts": {"ci": {"since": "x"}}}
        pending = [ci_run("b" * 40, None, "2026-10-27T09:00:00Z")]
        gh, _ = self._gh({}, pending + [ci_run("a" * 40, "failure", "2026-10-27T02:10:00Z")])
        ar.refresh_breaker(state, gh, "now")
        self.assertTrue(state["breaker"]["open"])
        green = [ci_run("c" * 40, "success", "2026-10-27T10:00:00Z"),
                 ci_run("c" * 40, "skipped", "2026-10-27T10:00:01Z", "Validate")]
        gh, _ = self._gh({}, green + pending)
        ar.refresh_breaker(state, gh, "later")
        self.assertFalse(state["breaker"]["open"])
        self.assertNotIn("ci", state["alerts"])

    def test_an_open_breaker_blocks_a_committing_job_before_any_git(self):
        gh, _ = self._gh({"a" * 40: [ci_run("a" * 40, "failure", "t")]}, [])
        ctx = self.context({"x": {"min_free_gb": 0, "commits": [
            {"subject": "chore: add a", "paths": ["a"]}]}}, gh=gh)
        ar.save_state(ctx.state_path, {"push": {"sha": "a" * 40, "ci": "pending"}})
        result, _ = ar.run_job(ctx, "x")
        self.assertEqual(result, ar.BLOCKED)
        self.assertFalse(ctx.worktree.exists())


class Origin(Scratch):
    """A bare origin, a main checkout cloned from it, and a second clone
    standing for another contributor."""

    def setUp(self) -> None:
        super().setUp()
        self.origin = self.tmp / "origin.git"
        run_git(self.tmp, "init", "--quiet", "--bare", "-b", "main", str(self.origin))
        self.repo = self.tmp / "repo"
        run_git(self.tmp, "clone", "--quiet", str(self.origin), str(self.repo))
        (self.repo / ".gitignore").write_text(".cache/\ntmp/\n", encoding="utf-8")
        (self.repo / "database.json").write_text("{}\n", encoding="utf-8")
        (self.repo / "install").mkdir()
        (self.repo / "install" / "a.json").write_text("{}\n", encoding="utf-8")
        run_git(self.repo, "add", ".gitignore", "database.json", "install/a.json")
        run_git(self.repo, "commit", "--quiet", "-m", "chore: start")
        run_git(self.repo, "push", "--quiet", "origin", "main")

    def other_commit(self, name: str) -> None:
        other = self.tmp / "other"
        if not other.exists():
            run_git(self.tmp, "clone", "--quiet", str(self.origin), str(other))
        run_git(other, "pull", "--quiet", "origin", "main")
        (other / name).write_text(name, encoding="utf-8")
        run_git(other, "add", name)
        run_git(other, "commit", "--quiet", "-m", f"chore: add {name}")
        run_git(other, "push", "--quiet", "origin", "main")

    def worktree(self) -> Path:
        wt = self.repo / ".cache" / "autorun" / "worktree"
        ar.ensure_worktree(self.repo, wt)
        return wt


class Commits(Origin):
    def test_globs_stay_inside_one_segment(self):
        self.assertTrue(ar.path_matches("install/*.json", "install/a.json"))
        self.assertFalse(ar.path_matches("install/*.json", "install/targets/a.json"))
        self.assertFalse(ar.path_matches("install/*.json", "x/install/a.json"))

    def test_the_dry_run_names_only_matching_files_and_stages_nothing(self):
        wt = self.worktree()
        (wt / "database.json").write_text('{"n": 1}\n', encoding="utf-8")
        (wt / "install" / "b.json").write_text("{}\n", encoding="utf-8")
        (wt / "notes.txt").write_text("x", encoding="utf-8")
        ctx = ar.Context(repo=self.repo, lock_path=self.tmp / "l", dry_run=True,
                         jobs=ar.parse_jobs({"jobs": {"n": {"commits": [{
                             "subject": "chore: regenerate collection records",
                             "paths": ["database.json", "install/*.json"]}]}}}))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ar.run_job(ctx, "n"), (ar.OK, "dry run"))
        lines = ar.describe(ctx.jobs["n"], ctx)
        would = sorted(l.split("would commit ")[1] for l in lines if "would commit" in l)
        self.assertEqual(would, ["database.json", "install/b.json"])
        self.assertEqual(run_git(wt, "diff", "--cached", "--name-only"), "")
        self.assertFalse(ctx.state_path.exists())

    def test_a_commit_takes_its_paths_and_nothing_staged_beside(self):
        wt = self.worktree()
        (wt / "database.json").write_text('{"n": 1}\n', encoding="utf-8")
        (wt / "other.txt").write_text("x", encoding="utf-8")
        run_git(wt, "add", "other.txt")
        rule = ar.CommitRule("chore: regenerate collection records", ("database.json",))
        files = ar.plan_commit(ar.changed_files(wt), rule.paths)
        ar.commit_paths(wt, files, rule)
        shown = run_git(wt, "show", "--name-only", "--format=%s", "HEAD").split()
        self.assertEqual(shown[-1], "database.json")
        self.assertNotIn("other.txt", shown)
        self.assertEqual(run_git(wt, "diff", "--cached", "--name-only").split(), ["other.txt"])


class Worktree(Origin):
    def test_it_is_created_on_its_own_branch_and_reused(self):
        wt = self.worktree()
        self.assertEqual(run_git(wt, "branch", "--show-current").strip(), ar.BRANCH)
        self.assertEqual(run_git(self.repo, "branch", "--show-current").strip(), "main")
        ar.ensure_worktree(self.repo, wt)
        self.assertEqual(len(run_git(self.repo, "worktree", "list").splitlines()), 2)

    def test_it_follows_origin_and_stops_on_leftovers(self):
        wt = self.worktree()
        self.other_commit("x.txt")
        base = ar.sync_worktree(wt)
        self.assertTrue((wt / "x.txt").exists())
        self.assertEqual(base, run_git(wt, "rev-parse", "HEAD").strip())
        (wt / "database.json").write_text("changed", encoding="utf-8")
        with self.assertRaises(ar.AutorunError) as caught:
            ar.sync_worktree(wt)
        self.assertEqual(caught.exception.result, ar.BLOCKED)
        self.assertEqual((wt / "database.json").read_text(), "changed")

    def test_the_hard_links_share_bytes_with_the_main_checkout(self):
        (self.repo / ".gitignore").write_text(".cache/\ntmp/\nbios/big.bin\n")
        (self.repo / "bios").mkdir()
        (self.repo / "bios" / "big.bin").write_bytes(b"x" * 10)
        (self.repo / ".cache" / "large").mkdir(parents=True)
        (self.repo / ".cache" / "large" / "a.zip").write_bytes(b"z")
        wt = self.worktree()
        seeded = ar.seed_worktree(self.repo, wt)
        self.assertEqual(sorted(seeded), [".cache/large", "bios/big.bin"])
        self.assertTrue(os.path.samefile(wt / "bios" / "big.bin", self.repo / "bios" / "big.bin"))
        self.assertEqual(ar.seed_worktree(self.repo, wt), [])


class Push(Origin):
    def _commit(self, wt: Path) -> None:
        (wt / "database.json").write_text('{"n": 2}\n', encoding="utf-8")
        ar.commit_paths(wt, ["database.json"],
                        ar.CommitRule("chore: regenerate collection records", ("database.json",)))

    def test_a_batch_on_an_unmoved_origin_pushes_without_a_second_gate(self):
        wt = self.worktree()
        base = ar.sync_worktree(wt)
        self._commit(wt)
        gates = []
        pushed = ar.push_batch(wt, base, lambda: gates.append(1) or True)
        self.assertEqual(gates, [])
        self.assertEqual(run_git(self.origin, "rev-parse", "main").strip(), pushed)

    def test_a_moved_origin_rebases_and_gates_again(self):
        wt = self.worktree()
        base = ar.sync_worktree(wt)
        self._commit(wt)
        self.other_commit("y.txt")
        gates = []
        pushed = ar.push_batch(wt, base, lambda: gates.append(1) or True)
        self.assertEqual(gates, [1])
        log = run_git(self.origin, "log", "--format=%s", "main").splitlines()
        self.assertEqual(log[:2], ["chore: regenerate collection records", "chore: add y.txt"])
        self.assertEqual(run_git(self.origin, "rev-parse", "main").strip(), pushed)

    def test_a_failed_second_gate_pushes_nothing(self):
        wt = self.worktree()
        base = ar.sync_worktree(wt)
        self._commit(wt)
        self.other_commit("y.txt")
        before = run_git(self.origin, "rev-parse", "main")
        with self.assertRaises(ar.AutorunError):
            ar.push_batch(wt, base, lambda: False)
        self.assertEqual(run_git(self.origin, "rev-parse", "main"), before)

    def test_a_conflicting_batch_is_kept_and_nothing_pushed(self):
        wt = self.worktree()
        base = ar.sync_worktree(wt)
        self._commit(wt)
        other = self.tmp / "other"
        run_git(self.tmp, "clone", "--quiet", str(self.origin), str(other))
        (other / "database.json").write_text('{"n": 3}\n', encoding="utf-8")
        run_git(other, "commit", "--quiet", "-am", "chore: other database")
        run_git(other, "push", "--quiet", "origin", "main")
        mine = run_git(wt, "rev-parse", "HEAD")
        with self.assertRaises(ar.AutorunError) as caught:
            ar.push_batch(wt, base, lambda: True)
        self.assertEqual(caught.exception.result, ar.BLOCKED)
        self.assertEqual(run_git(wt, "rev-parse", "HEAD"), mine)
        self.assertEqual(ar.changed_files(wt), [])


class RunnerPush(Origin):
    def _ctx(self, value: int, push: bool) -> ar.Context:
        write = "open('database.json', 'w').write('{\"n\": %d}')" % value
        jobs = {"n": {"min_free_gb": 0, "steps": [[PY, "-c", write]], "commits": [
            {"subject": "chore: regenerate collection records", "paths": ["database.json"]}]}}
        return ar.Context(repo=self.repo, jobs=ar.parse_jobs({"jobs": jobs}),
                          lock_path=self.tmp / "auto.lock", host=FakeHost(),
                          gh=lambda _args: [], push=push)

    def test_without_push_the_commit_stays_local(self):
        before = run_git(self.origin, "rev-parse", "main")
        result, detail = ar.run_job(self._ctx(5, push=False), "n")
        self.assertEqual((result, detail), (ar.OK, "1 commits"))
        self.assertEqual(run_git(self.origin, "rev-parse", "main"), before)
        self.assertEqual(ar.unpushed(self.repo / ".cache" / "autorun" / "worktree"), 1)

    def test_a_push_waits_for_the_previous_push_to_end_green(self):
        ctx = self._ctx(5, push=True)
        result, detail = ar.run_job(ctx, "n")
        self.assertEqual(result, ar.OK)
        self.assertIn("pushed", detail)
        pushed = run_git(self.origin, "rev-parse", "main").strip()
        self.assertEqual(self.state(ctx)["push"]["sha"], pushed)
        result, detail = ar.run_job(self._ctx(6, push=True), "n")
        self.assertEqual(result, ar.OK)
        self.assertIn("push held", detail)
        self.assertEqual(run_git(self.origin, "rev-parse", "main").strip(), pushed)


class Units(Scratch):
    def test_one_service_template_and_a_timer_per_scheduled_job(self):
        jobs = ar.parse_jobs({"jobs": {
            "nightly": {"schedule": "*-*-* 02:00"}, "manual": {}}})
        units = ar.render_units(jobs, Path("/srv/retrobios"), "/usr/bin/python3")
        self.assertEqual(sorted(units), ["retrobios-nightly.timer", "retrobios@.service"])
        service = units["retrobios@.service"]
        self.assertIn("ExecStart=/usr/bin/python3 /srv/retrobios/scripts/autorun.py run %i\n",
                      service)
        self.assertIn("WorkingDirectory=/srv/retrobios\n", service)
        self.assertIn("SuccessExitStatus=75\n", service)
        timer = units["retrobios-nightly.timer"]
        self.assertIn("OnCalendar=*-*-* 02:00\n", timer)
        self.assertIn("Persistent=true\n", timer)
        self.assertIn("Unit=retrobios@nightly.service\n", timer)
        pushed = ar.render_units(jobs, Path("/r"), "py", push=True)["retrobios@.service"]
        self.assertIn("run %i --push\n", pushed)

    def test_units_are_written_and_enabled_only_when_asked(self):
        units = ar.render_units(ar.load_jobs(), Path("/r"), "py")
        calls = []
        timers = ar.install_timers(self.tmp, units, False, lambda a: calls.append(a) or 0)
        self.assertEqual(calls, [])
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), sorted(units))
        ar.install_timers(self.tmp, units, True, lambda a: calls.append(a) or 0)
        self.assertEqual(calls, [["daemon-reload"], ["enable", "--now", *timers]])


class Cleanup(Origin):
    HOURS = 72

    def _worktree(self, name: str, age_hours: float) -> Path:
        path = self.repo / "sessions" / name
        run_git(self.repo, "worktree", "add", "--quiet", "-b", f"wt-{name}", str(path))
        stamp = time.time() - age_hours * 3600
        os.utime(path, (stamp, stamp))
        return path

    def _decisions(self, busy=()) -> dict[str, cd.Decision]:
        return {d.path.name: d for d in cd.plan(self.repo, busy, self.HOURS, time.time())}

    def test_generated_files_are_the_ones_a_run_rewrites(self):
        """mkdocs.yml stayed in the list after the site moved to Starlight,
        while CONTRIBUTING.md and website/src/data/*.json were left out."""
        for path in ("README.md", "CONTRIBUTING.md", "database.json", "install/retroarch.json",
                     "exports/batocera.json", "website/src/data/source-paths.json"):
            self.assertTrue(cd.GENERATED.match(path), path)
        for path in ("mkdocs.yml", "website/src/data/x/y.json", "scripts/verify.py"):
            self.assertFalse(cd.GENERATED.match(path), path)

    def test_worktree_and_tmp_rules(self):
        old_clean = self._worktree("old-clean", 100)
        old_code = self._worktree("old-code", 100)
        (old_code / "install" / "a.json").write_text("generated", encoding="utf-8")
        (old_code / ".gitignore").write_text("edited", encoding="utf-8")
        old_generated = self._worktree("old-generated", 100)
        (old_generated / "database.json").write_text("generated", encoding="utf-8")
        self._worktree("recent", 10)
        busy = self._worktree("busy", 100)
        tmp = self.repo / "tmp"
        for name in ("acquire", "old", "fresh", "used"):
            (tmp / name).mkdir(parents=True)
        (tmp / "main.bundle").write_bytes(b"")
        stamp = time.time() - 100 * 3600
        for name in ("acquire", "old", "used", "main.bundle"):
            os.utime(tmp / name, (stamp, stamp))
        # The worktree mtimes moved when files were written into them.
        for path in (old_clean, old_code, old_generated, busy):
            os.utime(path, (stamp, stamp))

        decisions = self._decisions(busy=[str(busy / "scripts"), str(tmp / "used" / "f")])
        actions = {name: d.action for name, d in decisions.items()}
        self.assertEqual(actions, {
            "old-clean": "remove", "old-code": "keep", "old-generated": "remove",
            "recent": "keep", "busy": "keep",
            "acquire": "keep", "main.bundle": "keep", "old": "remove",
            "fresh": "keep", "used": "keep",
        })
        self.assertIn("uncommitted code: 1 files", decisions["old-code"].reason)

        failures = cd.apply(self.repo, decisions.values())
        self.assertEqual(failures, [])
        self.assertFalse(old_clean.exists())
        self.assertFalse(old_generated.exists())
        self.assertTrue(old_code.exists())
        self.assertFalse((tmp / "old").exists())
        self.assertTrue((tmp / "acquire").exists())
        branches = run_git(self.repo, "branch", "--format=%(refname:short)").split()
        self.assertIn("wt-old-clean", branches)
        self.assertIn("wt-old-generated", branches)

    def test_a_name_prefix_of_a_busy_path_is_not_in_use(self):
        self.assertTrue(cd.in_use(Path("/r/tmp/a"), ["/r/tmp/a/x"]))
        self.assertFalse(cd.in_use(Path("/r/tmp/a"), ["/r/tmp/a2/x"]))

    def test_the_automation_worktree_is_never_a_candidate(self):
        self.worktree()
        self.assertEqual(cd.session_worktrees(self.repo), [])

    def test_a_worktree_outside_the_checkout_is_never_a_candidate(self):
        outside = self.tmp / "elsewhere"
        run_git(self.repo, "worktree", "add", "--quiet", "-b", "away", str(outside))
        self.assertEqual(cd.session_worktrees(self.repo), [])

    def test_a_tmp_entry_holding_a_worktree_with_code_survives(self):
        holder = self.repo / "tmp" / "holder"
        holder.mkdir(parents=True)
        work = holder / "wt"
        run_git(self.repo, "worktree", "add", "--quiet", "-b", "held", str(work))
        (work / ".gitignore").write_text("edited", encoding="utf-8")
        stamp = time.time() - 100 * 3600
        for path in (holder, work):
            os.utime(path, (stamp, stamp))
        decisions = self._decisions()
        self.assertEqual((decisions["wt"].action, decisions["holder"].action), ("keep", "keep"))
        self.assertEqual(decisions["holder"].reason, "holds a worktree")
        cd.apply(self.repo, decisions.values())
        self.assertEqual((work / ".gitignore").read_text(), "edited")

    def test_low_space_raises_the_alert_line(self):
        line, low = cd.disk_line(self.tmp, alert_gb=10 ** 9)
        self.assertTrue(low)
        self.assertIn("ALERT: free space under", line)
        self.assertFalse(cd.disk_line(self.tmp, alert_gb=0)[1])


class AssetSync(Scratch):
    GITIGNORE = "bios/A/big.bin\nbios/B/big.bin\nbios/C/solo.iso\n"

    def setUp(self) -> None:
        super().setUp()
        self.root = self.tmp
        for rel, data in (("bios/A/big.bin", b"a"), ("bios/C/solo.iso", b"c")):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_bytes(data)
        self.db = {"files": {
            sra.sha1_of(self.root / "bios/A/big.bin"): {"path": "bios/A/big.bin", "size": 1},
            "0" * 40: {"path": "bios/C/solo.iso", "size": 1},
        }}

    def test_only_a_file_whose_sha1_matches_twice_is_cleared(self):
        findings = [("missing", "bios/A/big.bin", 1, None), ("size", "bios/C/solo.iso", 1, 5),
                    ("notes", "release description", 0, None)]
        plans = sra.plan_uploads(self.root, self.db, self.GITIGNORE, findings)
        self.assertEqual([(p.path, p.asset, p.verdict) for p in plans], [
            ("bios/A/big.bin", "A--big.bin", "upload"),
            ("bios/C/solo.iso", "solo.iso", "refused"),
        ])
        self.assertIn("not the database's", plans[1].reason)

    def test_two_reads_that_disagree_refuse_the_upload(self):
        reads = iter(["1" * 40, "2" * 40])
        plans = sra.plan_uploads(self.root, self.db, self.GITIGNORE,
                                 [("content", "bios/A/big.bin", 1, 1)],
                                 hasher=lambda _p: next(reads))
        self.assertEqual(plans[0].verdict, "refused")
        self.assertIn("two reads disagree", plans[0].reason)

    def test_an_upload_goes_under_its_asset_name_and_is_tried_twice(self):
        plans = [sra.Upload("bios/A/big.bin", "A--big.bin", "missing", "upload"),
                 sra.Upload("bios/C/solo.iso", "solo.iso", "size", "refused", "x")]
        seen = []

        def upload(path: Path) -> int:
            seen.append(path.name)
            return 1
        self.assertEqual(sra.upload_all(self.root, plans, upload), ["bios/A/big.bin"])
        self.assertEqual(seen, ["A--big.bin", "A--big.bin"])
        self.assertFalse((self.root / sra.STAGING / "A--big.bin").exists())


class BiosIntegrity(Scratch):
    """A flipped bit keeps the size and the mtime, so git status shows a
    clean tree. Only the rehash against database.json finds it."""

    OLD = time.time() - 10 * 86400

    def setUp(self) -> None:
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "--quiet", "-b", "main")
        # A flip on disk leaves the ctime alone, the rewrite that stands for
        # it here does not: git sees it whenever it lands a second after
        # the commit, so slow runs read the flip as a working change.
        run_git(self.repo, "config", "core.trustctime", "false")
        files = {
            "bios/Aristocrat/aristmk6.zip": bytes(range(256)) * 4,
            "bios/Sony/scph5501.bin": b"\x55" * 512,
            "bios/Sony/edited.bin": b"\x01" * 64,
            "bios/Big/large.iso": b"\x99" * 2048,
        }
        (self.repo / ".gitignore").write_text("bios/Big/large.iso\n", encoding="utf-8")
        self.db = {"files": {}}
        for rel, data in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            # An old mtime keeps git from re-reading the file as racily clean.
            os.utime(path, (self.OLD, self.OLD))
            sha1 = bib.sha1_of(path)
            self.db["files"][sha1] = {"path": rel, "sha1": sha1}
        run_git(self.repo, "add", ".gitignore", *[r for r in files if "Big" not in r])
        run_git(self.repo, "commit", "--quiet", "-m", "chore: start")

    def flip(self, rel: str, offset: int = 100) -> bytes:
        """Flip one bit in place, size and mtime unchanged."""
        path = self.repo / rel
        data = bytearray(path.read_bytes())
        original = bytes(data)
        data[offset] ^= 0x10
        path.write_bytes(bytes(data))
        os.utime(path, (self.OLD, self.OLD))
        return original

    def test_the_flip_is_invisible_to_git_and_restored(self):
        rel = "bios/Aristocrat/aristmk6.zip"
        original = self.flip(rel)
        self.assertEqual(run_git(self.repo, "status", "--porcelain"), "")
        report = bib.check(self.repo, self.db, apply=False)
        self.assertEqual([(f.path, f.verdict) for f in report.findings], [(rel, bib.FLAGGED)])
        self.assertNotEqual((self.repo / rel).read_bytes(), original)

        report = bib.check(self.repo, self.db, apply=True)
        self.assertEqual([(f.path, f.verdict) for f in report.findings], [(rel, bib.RESTORED)])
        self.assertEqual((self.repo / rel).read_bytes(), original)
        self.assertTrue(report.clean)
        self.assertEqual(bib.check(self.repo, self.db, apply=True).findings, [])

    def test_a_flip_in_a_gitignored_file_is_flagged_never_fixed(self):
        rel = "bios/Big/large.iso"
        self.flip(rel)
        flipped = (self.repo / rel).read_bytes()
        report = bib.check(self.repo, self.db, apply=True)
        self.assertEqual([(f.path, f.verdict) for f in report.findings], [(rel, bib.FLAGGED)])
        self.assertIn("gitignored", report.findings[0].reason)
        self.assertEqual((self.repo / rel).read_bytes(), flipped)
        self.assertFalse(report.clean)

    def test_a_working_change_git_sees_is_left_to_its_session(self):
        rel = "bios/Sony/edited.bin"
        (self.repo / rel).write_bytes(b"\x02" * 80)
        report = bib.check(self.repo, self.db, apply=True)
        self.assertEqual([(f.path, f.verdict) for f in report.findings], [(rel, bib.SKIPPED)])
        self.assertEqual((self.repo / rel).read_bytes(), b"\x02" * 80)

    def test_an_unreadable_index_stops_before_any_restore(self):
        """git status failed on a corrupt index, its empty stdout read as
        "unmodified", and --apply wrote HEAD's bytes over the session's."""
        rel = "bios/Sony/edited.bin"
        (self.repo / rel).write_bytes(b"\x02" * 80)
        (self.repo / ".git" / "index").write_bytes(b"garbage\n")
        with self.assertRaises(bib.GitFailed):
            bib.check(self.repo, self.db, apply=True)
        self.assertEqual((self.repo / rel).read_bytes(), b"\x02" * 80)

    def test_a_mismatch_the_second_read_does_not_confirm_is_a_misread(self):
        reads = {}
        expected = {e["path"]: e["sha1"] for e in self.db["files"].values()}

        def hasher(path: Path) -> str:
            rel = path.relative_to(self.repo).as_posix()
            reads[rel] = reads.get(rel, 0) + 1
            if rel == "bios/Sony/scph5501.bin" and reads[rel] == 1:
                return "f" * 40
            return expected[rel]
        report = bib.check(self.repo, self.db, apply=True, hasher=hasher)
        self.assertEqual([(f.path, f.verdict) for f in report.findings],
                         [("bios/Sony/scph5501.bin", bib.MISREAD)])
        self.assertTrue(report.clean)

    def test_a_blob_that_is_not_the_database_content_is_not_written(self):
        rel = "bios/Sony/scph5501.bin"
        self.flip(rel)
        db = json.loads(json.dumps(self.db))
        for entry in db["files"].values():
            if entry["path"] == rel:
                entry["sha1"] = "0" * 40
        flipped = (self.repo / rel).read_bytes()
        report = bib.check(self.repo, db, apply=True)
        self.assertEqual(report.findings[0].verdict, bib.FLAGGED)
        self.assertIn("other bytes", report.findings[0].reason)
        self.assertEqual((self.repo / rel).read_bytes(), flipped)

    def test_the_runner_keeps_the_report_in_the_job_status(self):
        rel = "bios/Aristocrat/aristmk6.zip"
        self.flip(rel)
        Path(self.db_path).write_text(json.dumps(self.db), encoding="utf-8")
        script = str(REPO_ROOT / "scripts" / "bios_integrity.py")
        ctx = ar.Context(
            repo=self.repo, lock_path=self.tmp / "auto.lock", host=FakeHost(),
            jobs=ar.parse_jobs({"jobs": {"bios-integrity": {
                "worktree": False, "min_free_gb": 0,
                "steps": [{"run": [PY, script, "--apply", "--json", "--db", self.db_path],
                           "stdout": "tmp/autorun/bios-integrity.json"}],
                "report": "tmp/autorun/bios-integrity.json"}}}))
        self.assertEqual(ar.run_job(ctx, "bios-integrity")[0], ar.OK)
        report = self.state(ctx)["jobs"]["bios-integrity"]["report"]
        self.assertEqual(report["counts"], {"restored": 1})
        self.assertEqual(report["findings"][0]["path"], rel)
        self.assertIn("1 restored", ar.render_status(ar.status(ctx)))

    @property
    def db_path(self) -> str:
        return str(self.tmp / "database.json")


class SubjectsFollowTheRepositoryRules(unittest.TestCase):
    """The commit rules live in scripts/commit_rules.py, which the local hook
    calls: a copy in the hook alone let CI check only the shape."""

    def test_the_runner_reads_the_tracked_rules(self):
        import commit_rules  # noqa: PLC0415

        for subject in ("chore: fix the broken manifests", "update things", "chore: " + "a" * 60):
            with self.subTest(subject=subject):
                self.assertEqual(ar.check_subject(subject), commit_rules.problems(subject))
                self.assertTrue(ar.check_subject(subject))
        self.assertEqual(ar.check_subject("chore: tidy the cache"), [])

    def test_review_numbers_are_refused(self):
        """47 pushed subjects pointed at a numbered private review, which no
        clone can follow. The subject says what the change does."""
        import commit_rules  # noqa: PLC0415

        for subject in ("chore: audit 24 and 17 cases, host kept out",
                        "fix: polish the screens audit 11 named",
                        "chore: merge audit batch, resolver and profiles",
                        "fix: settle the review 3 notes"):
            with self.subTest(subject=subject):
                self.assertTrue(commit_rules.problems(subject))
        for subject in ("fix: scroll long messages in the installer",
                        "feat: read regions in region_audit.py",
                        "chore: merge resolver and profile fixes"):
            with self.subTest(subject=subject):
                self.assertEqual(commit_rules.problems(subject), [])

    def test_the_rules_run_as_a_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            message = Path(tmp) / "MSG"
            script = REPO_ROOT / "scripts" / "commit_rules.py"
            for text, code in (("fix: keep the cache\n", 0), ("fix: a broken cache\n", 1),
                               ("fix: keep it\n\nCo-Authored-By: x\n", 1)):
                message.write_text(text)
                done = subprocess.run([sys.executable, str(script), str(message)],
                                      capture_output=True, text=True, check=False)
                with self.subTest(text=text):
                    self.assertEqual(done.returncode, code, done.stderr)


if __name__ == "__main__":
    unittest.main()
