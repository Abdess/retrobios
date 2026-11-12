#!/usr/bin/env python3
"""Concurrency guard on the pack output directory.

Two runs building the same dist/ leave readers looking at half-written
ZIPs, which surfaces as BadZipFile far from its cause.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import os
import subprocess
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from common import (  # noqa: E402
    ArtifactLockBusy,
    artifact_lock,
    hold_artifact_lock,
    hold_repository_outputs,
    publish_hold,
)
from tests.scratchtree import scratch_checkout  # noqa: E402
import artifacts  # noqa: E402
from unittest import mock  # noqa: E402


def _tempdir(test: unittest.TestCase) -> str:
    """A scratch directory under the repository's tmp/, removed after the test.

    The system temp directory is a RAM disk here, and directories left by
    every run piled up on it.
    """
    scratch = REPO_ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    path = tempfile.mkdtemp(dir=str(scratch))
    test.addCleanup(shutil.rmtree, path, True)
    return path


class ArtifactLockTest(unittest.TestCase):
    def setUp(self):
        self.dir = _tempdir(self)

    def test_writer_excludes_writer(self):
        with artifact_lock(self.dir):
            with self.assertRaises(ArtifactLockBusy):
                with artifact_lock(self.dir):
                    pass

    def test_writer_excludes_reader(self):
        with artifact_lock(self.dir):
            with self.assertRaises(ArtifactLockBusy):
                with artifact_lock(self.dir, exclusive=False):
                    pass

    def test_readers_share(self):
        with artifact_lock(self.dir, exclusive=False):
            with artifact_lock(self.dir, exclusive=False):
                pass

    def test_a_reader_never_creates_the_directory(self):
        """A mistyped --output-dir given to --verify-packs or release_record
        was created holding a .lock, and the next run with the same typo no
        longer said the path did not exist."""
        from common import ArtifactDirectoryMissing  # noqa: PLC0415

        missing = os.path.join(self.dir, "sub", "dsit")
        with self.assertRaises(ArtifactDirectoryMissing):
            with artifact_lock(missing, exclusive=False):
                pass
        self.assertFalse(os.path.exists(os.path.join(self.dir, "sub")))

    def test_split_refuses_a_missing_target_before_locking(self):
        missing = Path(self.dir) / "sub" / "dsit"
        proc = subprocess.run(
            [sys.executable, "scripts/split_pack.py", str(missing)],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=60,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no such pack or directory", proc.stderr)
        self.assertFalse(missing.parent.exists())

    def test_lock_is_released_on_exit(self):
        with artifact_lock(self.dir):
            pass
        with artifact_lock(self.dir):
            pass

    def test_lock_is_released_on_error(self):
        with self.assertRaises(ValueError):
            with artifact_lock(self.dir):
                raise ValueError("boom")
        with artifact_lock(self.dir):
            pass

    def test_separate_directories_do_not_contend(self):
        other = _tempdir(self)
        with artifact_lock(self.dir):
            with artifact_lock(other):
                pass

    def test_lock_survives_a_missing_directory(self):
        missing = os.path.join(self.dir, "not-created-yet")
        with artifact_lock(missing):
            self.assertTrue(os.path.isdir(missing))


class PackLockCliTest(unittest.TestCase):
    """generate_pack and pipeline must refuse a directory held elsewhere."""

    def setUp(self):
        self.dir = _tempdir(self)

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        # In a copy: a pipeline that missed the lock regenerated
        # database.json and install/ wherever it ran.
        return subprocess.run(
            [sys.executable, *argv],
            capture_output=True,
            text=True,
            cwd=str(scratch_checkout()),
            timeout=300,
        )

    def test_generate_pack_refuses_locked_output(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/generate_pack.py",
                    "--platform",
                    "misterfpga",
                    "--output-dir",
                    self.dir,
                    "--offline",
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stderr)

    def test_a_held_output_is_refused_before_the_data_refresh(self):
        """The refresh waits for every run holding a data tree, and a
        pipeline holds them all for its whole run: probed after the refresh,
        a second build sat silent for hours instead of being refused."""
        from refresh_data_dirs import cache_lock  # noqa: PLC0415

        platforms = Path(self.dir) / "platforms"
        platforms.mkdir()
        for name in ("_registry.yml", "_shared.yml", "misterfpga.yml"):
            shutil.copyfile(REPO_ROOT / "platforms" / name, platforms / name)
        cache = Path(self.dir) / "cache" / "probe"
        cache.mkdir(parents=True)
        (platforms / "_data_dirs.yml").write_text(
            "data_directories:\n  probe:\n    source_type: zip\n"
            f"    source_url: https://example.invalid/probe.zip\n"
            f"    local_cache: {cache}\n"
        )
        output = Path(self.dir) / "out"
        with artifact_lock(str(output)), cache_lock(cache):
            try:
                proc = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", "--platform", "misterfpga",
                     "--platforms-dir", str(platforms), "--output-dir", str(output)],
                    capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
                )
            except subprocess.TimeoutExpired:
                self.fail("generate_pack waited on the data tree instead of refusing")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stderr)

    def test_every_writing_mode_refuses_a_locked_output(self):
        """Two of seven modes took the lock, and five wrote straight into it.

        A mode that writes packs or manifests into a directory another run
        holds produces the half-written artifact the lock exists to prevent.
        """
        modes = [
            (["--emulator", "handy", "--offline"], "emulator"),
            (["--system", "atari-lynx", "--offline"], "system"),
            (["--manifest-targets"], "manifest-targets"),
            (["--platform", "misterfpga", "--manifest", "--offline"], "manifest"),
            (
                ["--platform", "misterfpga", "--from-md5",
                 "d8f1206299c48946e6ec5ef96d014eaa", "--offline"],
                "from-md5",
            ),
        ]
        with artifact_lock(self.dir):
            for argv, label in modes:
                with self.subTest(mode=label):
                    proc = self._run(
                        ["scripts/generate_pack.py", *argv,
                         "--output-dir", self.dir]
                    )
                    self.assertNotEqual(
                        proc.returncode, 0,
                        f"{label} wrote into a directory held by another run",
                    )
                    self.assertIn("in use", (proc.stdout + proc.stderr).lower())

    def test_verify_packs_refuses_a_writer(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/generate_pack.py",
                    "--platform",
                    "misterfpga",
                    "--verify-packs",
                    "--output-dir",
                    self.dir,
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stderr)

    def test_pipeline_refuses_locked_output(self):
        with artifact_lock(self.dir):
            proc = self._run(
                [
                    "scripts/pipeline.py",
                    "--offline",
                    "--skip-docs",
                    "--output-dir",
                    self.dir,
                ]
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("is in use by another run", proc.stderr)


class PipelineHoldsItsFixedOutputs(unittest.TestCase):
    """A pipeline on a scratch --output-dir still rewrites database.json,
    install/, README.md and docs/: only the output directory was locked."""

    def test_a_second_pipeline_is_refused_whatever_its_output_dir(self):
        scratch = _tempdir(self)
        checkout = scratch_checkout()
        with hold_repository_outputs(str(checkout)):
            proc = subprocess.run(
                [sys.executable, "scripts/pipeline.py", "--offline", "--skip-docs",
                 "--output-dir", scratch],
                capture_output=True, text=True, cwd=str(checkout), timeout=120,
            )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("another run is writing database.json", proc.stderr)
        self.assertNotIn("generate database", proc.stdout.lower())

    def test_two_holds_of_the_repository_exclude_each_other(self):
        with hold_repository_outputs(str(REPO_ROOT)), \
                self.assertRaises(ArtifactLockBusy):
            with hold_repository_outputs(str(REPO_ROOT)):
                pass


class TheSuiteTakesTheRepositoryHoldInItsScratch(unittest.TestCase):
    """scripts/run_tests.py runs modules side by side: a pipeline one module
    ran held the repository root, and every module that ran another one, or
    a generator writing database.json, failed on the busy lock."""

    def test_the_hold_is_taken_where_the_variable_says(self):
        scratch = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, scratch, True)
        moved = scratch / "repository-lock"
        with mock.patch.dict(os.environ, {artifacts.REPOSITORY_LOCK_ENV: str(moved)}):
            with artifacts.hold_repository_outputs(str(REPO_ROOT)):
                key = str(REPO_ROOT.resolve()).strip(os.sep).replace(os.sep, "__")
                self.assertTrue((moved / key / ".lock").is_file())
                # Held there: a second hold in the same tree is refused.
                with self.assertRaises(artifacts.ArtifactLockBusy):
                    with artifacts.hold_repository_outputs(str(REPO_ROOT)):
                        pass

    def test_another_directory_keeps_its_own_lock(self):
        out = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, out, True)
        with mock.patch.dict(os.environ, {artifacts.REPOSITORY_LOCK_ENV: str(out / "x")}):
            with artifacts.artifact_lock(str(out)):
                self.assertTrue((out / ".lock").is_file())
        self.assertFalse((out / "x").exists())

    def test_the_suite_sets_it(self):
        self.assertTrue(os.environ.get(artifacts.REPOSITORY_LOCK_ENV))


class StandaloneWritersHonourTheRepositoryHold(unittest.TestCase):
    """Only pipeline runs took the repository's lock: generate_db.py beside
    a pipeline replaced database.json between its verify and its packs, and
    a manifest run on install/ failed the pipeline's own manifest step."""

    def _beside_a_pipeline(self, argv: list[str]) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != "RETROBIOS_HELD_ARTIFACT_DIR"}
        return subprocess.run(
            [sys.executable, *argv], capture_output=True, text=True,
            cwd=str(scratch_checkout()), timeout=300, env=env, check=False,
        )

    def test_a_writer_of_a_fixed_output_is_refused(self):
        # The writers run in a copy, where a missed lock writes nothing of ours.
        with hold_repository_outputs(str(scratch_checkout())):
            for argv in (
                ["scripts/generate_db.py", "--bios-dir", "bios", "--output", "database.json"],
                ["scripts/generate_pack.py", "--all", "--manifest", "--offline",
                 "--output-dir", "install"],
                ["scripts/generate_games_index.py", "--quiet"],
            ):
                with self.subTest(script=argv[0]):
                    proc = self._beside_a_pipeline(argv)
                    self.assertEqual(proc.returncode, 1, proc.stdout[-500:] + proc.stderr[-500:])
                    self.assertIn("another run is writing database.json", proc.stderr)
                    self.assertNotIn("Traceback", proc.stderr)

    def _child(self, target: str, env: dict) -> subprocess.CompletedProcess:
        code = (
            "import sys; sys.path.insert(0, 'scripts')\n"
            "from common import artifact_lock, repository_output_lock\n"
            f"with repository_output_lock({target!r}), artifact_lock({self.scratch!r}):\n"
            "    pass\n"
        )
        return subprocess.run([sys.executable, "-c", code], cwd=str(REPO_ROOT), env=env,
                              capture_output=True, text=True, timeout=60, check=False)

    def test_a_step_the_pipeline_spawns_passes(self):
        """A pipeline holds the root and its --output-dir, and its steps
        write both: the environment names the two, os.pathsep apart."""
        self.scratch = _tempdir(self)
        with hold_repository_outputs(str(REPO_ROOT)), publish_hold(str(REPO_ROOT)), \
                hold_artifact_lock(self.scratch):
            proc = self._child(str(REPO_ROOT / "install" / "games"), dict(os.environ))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_scratch_output_takes_nothing(self):
        self.scratch = _tempdir(self)
        env = {k: v for k, v in os.environ.items() if k != "RETROBIOS_HELD_ARTIFACT_DIR"}
        with hold_repository_outputs(str(REPO_ROOT)):
            proc = self._child(os.path.join(self.scratch, "database.json"), env)
        self.assertEqual(proc.returncode, 0, proc.stderr)


class HeldLockTest(unittest.TestCase):
    """pipeline.py took the lock step by step: between the pack build and the
    integrity check dist/ was free, another run's purge emptied it, and the
    check reported every platform SKIP and passed."""

    def setUp(self):
        self.dir = _tempdir(self)

    def _child_locks(self, env: dict) -> subprocess.CompletedProcess:
        code = (
            "import sys; sys.path.insert(0, 'scripts')\n"
            "from common import artifact_lock\n"
            f"with artifact_lock({self.dir!r}):\n    pass\n"
        )
        return subprocess.run(
            [sys.executable, "-c", code], cwd=str(REPO_ROOT), env=env,
            capture_output=True, text=True, timeout=60, check=False,
        )

    def test_a_spawned_step_inherits_the_hold(self):
        with hold_artifact_lock(self.dir):
            self.assertEqual(self._child_locks(dict(os.environ)).returncode, 0)

    def test_any_other_run_is_refused_for_the_whole_hold(self):
        with hold_artifact_lock(self.dir):
            env = {k: v for k, v in os.environ.items() if not k.startswith("RETROBIOS_")}
            proc = self._child_locks(env)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("ArtifactLockBusy", proc.stderr)
        self.assertNotIn("RETROBIOS_HELD_ARTIFACT_DIR", os.environ)
        self.assertEqual(self._child_locks(dict(os.environ)).returncode, 0)

    def test_the_pipeline_holds_its_output_for_the_run(self):
        source = (REPO_ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn("hold_artifact_lock(args.output_dir)", source)


class PipelineHoldsTheDataTrees(unittest.TestCase):
    """The pipeline held dist/ for the whole run but not the data directory
    trees: a refresh from another session could swap one between the packs
    and the manifests, which then described two revisions of it."""

    def test_the_trees_are_held_after_the_refresh_and_before_verify(self):
        source = (Path(__file__).resolve().parents[1] / "scripts" / "pipeline.py").read_text()
        refresh = source.index('"scripts/refresh_data_dirs.py"')
        hold = source.index("hold_data_dirs(held,")
        verify = source.index('"scripts/verify.py", "--all"')
        self.assertLess(refresh, hold)
        self.assertLess(hold, verify)



class SiteGenerationHoldsDocs(unittest.TestCase):
    """generate_site swept from docs/ every file its own run had not
    written, including the scratch file and new pages of a second run on
    the same tree. That run then died on os.replace or lost pages."""

    def test_a_second_run_is_refused_before_it_writes(self):
        docs = _tempdir(self)
        marker = Path(docs) / "platforms" / ".retroarch.md.k2j3.tmp"
        marker.parent.mkdir()
        marker.write_text("scratch of another run")
        with artifact_lock(docs):
            result = subprocess.run(
                [sys.executable, "scripts/generate_site.py", "--docs-dir", docs],
                cwd=scratch_checkout(), capture_output=True, text=True, timeout=600,
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("in use by another run", result.stderr)
        self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
