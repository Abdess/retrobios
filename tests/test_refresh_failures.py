"""A step that could not do its job says so with its exit code.

validate_pr --changed answered "No changed BIOS files detected" and exited
0 when git itself had failed (no origin, or no repository), and
check_buildbot_system --update exited 0 after a refresh it launched had
failed, the cache left at the old version.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_buildbot_system  # noqa: E402


class GitThatCannotAnswer(unittest.TestCase):
    def test_outside_a_repository_is_an_error_not_an_empty_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            # TMPDIR may lie inside this repository (the audit gate puts it in
            # tmp/): git must not find the enclosing work tree from there.
            env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(Path(tmp).parent))
            # The script moves to its own checkout first: kept here, it stands
            # for a copy of scripts/ that no repository holds.
            proc = subprocess.run(
                [sys.executable, "-c", (
                    f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r}); "
                    "import verify; verify.work_from_repo_root = lambda *a: None; "
                    "import validate_pr; sys.argv = ['validate_pr.py', '--changed']; "
                    "validate_pr.main()"
                )],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertNotIn("No changed BIOS files detected", proc.stdout)

    def test_a_clone_without_origin_reads_the_index_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            Path(tmp, "bios").mkdir()
            Path(tmp, "bios", "x.bin").write_bytes(b"x")
            subprocess.run(["git", "-C", tmp, "add", "bios/x.bin"], check=True)
            proc = subprocess.run(
                [sys.executable, "-c", (
                    f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r}); "
                    "import validate_pr; print(validate_pr.get_changed_files())"
                )],
                cwd=tmp, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("bios/x.bin", proc.stdout)
        self.assertIn("untracked files only", proc.stderr)


class ChangesNotYetCommittedAreRead(unittest.TestCase):
    """--changed read only `git diff origin/main...HEAD`: a file copied into
    bios/ before any commit, as CONTRIBUTING has it, or committed on a
    fork's own main, answered "No changed BIOS files detected", rc 0."""

    def test_an_untracked_file_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            Path(tmp, "README").write_text("x")
            subprocess.run(["git", "-C", tmp, "add", "README"], check=True)
            subprocess.run(["git", "-C", tmp, "-c", "user.email=a@b", "-c", "user.name=a",
                            "commit", "-qm", "init"], check=True)
            Path(tmp, "bios").mkdir()
            Path(tmp, "bios", "new.bin").write_bytes(b"x")
            proc = subprocess.run(
                [sys.executable, "-c", (
                    f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r}); "
                    "import validate_pr; print(validate_pr.get_changed_files())"
                )],
                cwd=tmp, capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("bios/new.bin", proc.stdout)


class AForkPushedToItsOwnMain(unittest.TestCase):
    """A fork's clone has origin alone. Once the commit was pushed to the
    fork's main, origin/main was HEAD, the diff was empty, and --changed
    said "No changed BIOS files detected" with rc 0."""

    GIT = ["git", "-c", "user.email=a@b", "-c", "user.name=a",
           "-c", "init.defaultBranch=main"]

    def _git(self, *args: str, cwd: str | None = None) -> None:
        subprocess.run([*self.GIT, *args], cwd=cwd, check=True, capture_output=True)

    def _changed(self, clone: str, project: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", (
                f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'scripts')!r}); "
                "import validate_pr; "
                f"validate_pr.PROJECT_URLS = ({project!r},); "
                "print(validate_pr.get_changed_files())"
            )],
            cwd=clone, capture_output=True, text=True, timeout=60, check=False,
        )

    def test_the_project_main_is_fetched_and_compared(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, fork, clone = (str(Path(tmp, n)) for n in ("project", "fork", "clone"))
            self._git("init", "-q", project)
            Path(project, "README").write_text("x")
            self._git("add", "README", cwd=project)
            self._git("commit", "-qm", "init", cwd=project)
            self._git("clone", "-q", "--bare", project, fork)
            self._git("clone", "-q", fork, clone)
            Path(clone, "bios").mkdir()
            Path(clone, "bios", "new.bin").write_bytes(b"x")
            self._git("add", "bios/new.bin", cwd=clone)
            self._git("commit", "-qm", "add", cwd=clone)
            self._git("push", "-q", "origin", "main", cwd=clone)
            proc = self._changed(clone, project)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("bios/new.bin", proc.stdout)
            # A project that cannot be reached is an error, never "nothing".
            missing = self._changed(clone, str(Path(tmp, "absent")))
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("fetching its main from", missing.stderr)


class RefreshFailuresAreFailures(unittest.TestCase):
    def test_a_failed_refresh_is_returned_and_exits_nonzero(self):
        report = {"entries": [{"status": "UPDATED", "key": "dolphin-sys"},
                              {"status": "OK", "key": "ppsspp-assets"}]}
        with mock.patch.object(
            check_buildbot_system.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            self.assertEqual(check_buildbot_system.update_changed(report), ["dolphin-sys"])
        source = (REPO_ROOT / "scripts" / "check_buildbot_system.py").read_text(encoding="utf-8")
        self.assertIn("failed = update_changed(report)", source)
        self.assertIn("sys.exit(1)", source[source.index("failed = update_changed(report)"):])


class AnEmptyExtractionKeepsTheCache(unittest.TestCase):
    """An archive without the cited subtree replaced the cache with an empty
    directory, recorded the version and reported success."""

    def setUp(self):
        import refresh_data_dirs

        self.module = refresh_data_dirs
        scratch = Path(__file__).resolve().parent.parent / "tmp"
        scratch.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(dir=scratch))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        (self.cache / "keep.dat").write_bytes(b"cached")

    def test_a_tarball_without_the_subtree(self):
        import tarfile

        archive = self.root / "archive.tar.gz"
        payload = self.root / "a.txt"
        payload.write_bytes(b"x")
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(payload, arcname="repo-main/OtherDir/a.txt")
        with self.assertRaises(self.module.NothingExtractedError):
            self.module._download_and_extract(
                archive.as_uri(), "repo-main/Data/Sys", str(self.cache), []
            )
        self.assertEqual((self.cache / "keep.dat").read_bytes(), b"cached")

    def test_a_zip_with_no_file(self):
        import zipfile

        archive = self.root / "archive.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("only/", b"")
        with self.assertRaises(self.module.NothingExtractedError):
            self.module._download_and_extract_zip(archive.as_uri(), str(self.cache))
        self.assertEqual((self.cache / "keep.dat").read_bytes(), b"cached")


class TheVersionIsReadBeforeTheDownload(unittest.TestCase):
    """The buildbot republishes nightly. Read after the download, the tag
    named the new build while the cache held the old one, and every later
    run called it up to date."""

    def test_a_build_published_during_the_download(self):
        import refresh_data_dirs as rdd

        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        state = {"downloaded": False}

        def etag(_url):
            return "build-2" if state["downloaded"] else "build-1"

        def download(*_args, **_kwargs):
            state["downloaded"] = True
            return 3

        versions = root / "versions.json"
        entry = {"source_type": "zip", "source_url": "https://example.invalid/Sys.zip",
                 "local_cache": str(root / "cache")}
        with mock.patch.object(rdd, "_get_remote_etag", etag), \
                mock.patch.object(rdd, "_download_and_extract_zip", download):
            self.assertTrue(rdd._refresh_entry("sys", entry, True, False, str(versions)))
        self.assertEqual(json.loads(versions.read_text())["sys"]["sha"], "build-1")


class ABadResponseIsTriedAgain(unittest.TestCase):
    """The buildbot once served something that was not ScummVM.zip. CI
    failed the whole data step on it, and the next download was fine."""

    def setUp(self) -> None:
        import refresh_data_dirs as rdd

        self.rdd = rdd
        root = Path(tempfile.mkdtemp(dir=REPO_ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, root, True)
        self.versions = str(root / "versions.json")
        self.entry = {"source_type": "zip", "source_url": "https://example.invalid/S.zip",
                      "local_cache": str(root / "cache")}
        self.waits: list[int] = []

    def run_with(self, outcomes: list) -> bool | None:
        calls = iter(outcomes)

        def download(*_args, **_kwargs):
            outcome = next(calls)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with mock.patch.object(self.rdd, "_get_remote_etag", lambda _url: "tag"), \
                mock.patch.object(self.rdd, "_download_and_extract_zip", download), \
                mock.patch.object(self.rdd.time, "sleep", self.waits.append):
            return self.rdd._refresh_entry("s", self.entry, True, False, self.versions)

    def test_a_bad_archive_then_a_good_one_refreshes(self):
        self.assertTrue(self.run_with([zipfile.BadZipFile("File is not a zip file"), 12]))
        self.assertEqual(self.waits, [self.rdd.DOWNLOAD_RETRY_WAITS[0]])

    def test_a_source_bad_on_every_try_fails_after_them(self):
        bad = zipfile.BadZipFile("File is not a zip file")
        tries = len(self.rdd.DOWNLOAD_RETRY_WAITS) + 1
        self.assertIsNone(self.run_with([bad] * tries))
        self.assertEqual(self.waits, list(self.rdd.DOWNLOAD_RETRY_WAITS))

    def test_an_empty_archive_is_not_tried_again(self):
        self.assertIsNone(self.run_with([self.rdd.NothingExtractedError("nothing")]))
        self.assertEqual(self.waits, [])


class AKeyMustServeThePlatform(unittest.TestCase):
    """--platform narrowed only a full refresh: under --key it was ignored and
    dolphin-sys was refreshed for RomM, which never reads it."""

    def test_a_key_outside_the_platform_is_refused(self):
        import subprocess  # noqa: PLC0415

        root = Path(__file__).resolve().parents[1]
        refused = subprocess.run(
            [sys.executable, "scripts/refresh_data_dirs.py", "--key", "dolphin-sys",
             "--platform", "romm", "--dry-run"],
            cwd=root, capture_output=True, text=True, timeout=120, check=False,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("does not serve romm", refused.stdout + refused.stderr)


if __name__ == "__main__":
    unittest.main()
