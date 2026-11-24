"""Audit regressions on the project itself: workflows, test isolation, dependencies and code rules."""

from __future__ import annotations

import tests
from tests.sources import script_source
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import yaml
from tests import HAS_JSONSCHEMA, REPO_ROOT


class AModuleRunAloneHasItsScratchDirectory(unittest.TestCase):
    """About forty modules write under tmp/, which git does not track. Only
    three created it, as an import side effect, so a module run alone on a
    fresh clone raised FileNotFoundError. The test package creates it."""

    def test_importing_the_package_creates_tmp(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory)
            (clone / "tests").mkdir()
            (clone / "tests" / "__init__.py").write_bytes(
                (REPO_ROOT / "tests" / "__init__.py").read_bytes()
            )
            # The folder a module gets alone, not the one scripts/run_tests.py
            # names for each module it runs beside others.
            env = {k: v for k, v in os.environ.items() if k != "RETROBIOS_TEST_SCRATCH"}
            proc = subprocess.run(
                [sys.executable, "-I", "-c",
                 "import sys; sys.path.insert(0, '.'); import tests, tempfile, os;"
                 " print(tempfile.gettempdir()); print(os.environ['TMPDIR'])"],
                cwd=clone, env=env, capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((clone / "tmp" / "tests").is_dir())
            # 264 TemporaryDirectory() calls without dir= wrote to the /tmp
            # tmpfs, and a full tmpfs failed modules no change touched.
            scratch = str((clone / "tmp" / "tests").resolve())
            self.assertEqual(proc.stdout.split(), [scratch, scratch])


class EveryTestModuleImportsTheIsolation(unittest.TestCase):
    """tests/__init__.py keeps a run offline, its scratch under tmp/ and its
    installer cache its own, but only `discover -s tests -t .` imported it:
    `discover tests` ran with RETROBIOS_OFFLINE unset, scratch in /tmp and
    the user's real cache. Each module now imports the package first."""

    def test_the_package_import_comes_before_any_other(self):
        missing = []
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            body = ast.parse(path.read_text(encoding="utf-8")).body
            imports = [
                node for node in body
                if isinstance(node, (ast.Import, ast.ImportFrom))
                and getattr(node, "module", None) != "__future__"
            ]
            first = imports[0] if imports else None
            if not (isinstance(first, ast.Import)
                    and [alias.name for alias in first.names] == ["tests"]):
                missing.append(path.name)
        self.assertEqual(missing, [])

    def test_discover_without_a_top_level_runs_isolated(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("RETROBIOS_OFFLINE", "TMPDIR", "RETROBIOS_CACHE",
                            "RETROBIOS_TEST_SCRATCH")}
        proc = subprocess.run(
            [sys.executable, "-c",
             "import os, sys, tempfile, unittest\n"
             "unittest.TestLoader().discover('tests', pattern='test_artifact_lock.py')\n"
             "print(os.environ.get('RETROBIOS_OFFLINE'), tempfile.gettempdir(),"
             " os.environ.get('RETROBIOS_CACHE'))\n"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        offline, scratch, cache = proc.stdout.split()
        self.assertEqual(offline, "1")
        self.assertEqual(scratch, str(REPO_ROOT / "tmp" / "tests"))
        self.assertEqual(cache, str(REPO_ROOT / "tmp" / "tests" / "cache"))


class ReleaseSigningRegressions(unittest.TestCase):
    """A checksum list published beside its own artifacts proves nothing.

    SHA256SUMS.txt answers corruption, but whoever can rewrite a release rewrites
    the list with it. The signature is what a third party checks, and it is
    only checkable while allowed_signers, the signing step and the upload
    list stay in agreement.
    """

    PRINCIPAL = "releases@retrobios"

    def test_allowed_signers_names_one_usable_key(self):
        path = REPO_ROOT / "allowed_signers"
        self.assertTrue(path.exists(), "allowed_signers is the published trust root")
        lines = [
            line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertTrue(lines, "allowed_signers carries no key")
        for line in lines:
            principal, keytype, blob = line.split()[:3]
            self.assertEqual(principal, self.PRINCIPAL)
            self.assertTrue(keytype.startswith(("ssh-", "sk-", "ecdsa-")), keytype)
            self.assertTrue(len(blob) > 40, "key material looks truncated")

    def test_the_release_signs_the_list_and_ships_the_signature(self):
        process = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn(
            "ssh-keygen -Y sign", process, "the release no longer signs the list"
        )
        upload = next(
            line for line in process.splitlines()
            if line.startswith("for f in dist/SHA256SUMS.txt")
        )
        self.assertIn(
            "dist/SHA256SUMS.txt.sig", upload,
            "the signature is produced but never uploaded",
        )

    def test_the_documented_verification_matches_the_published_principal(self):
        process = (REPO_ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn("ssh-keygen -Y verify", process)
        self.assertIn(f"-I {self.PRINCIPAL}", process)
        self.assertIn("allowed_signers", process)


class WorkflowRegressions(unittest.TestCase):
    """The test suite must sit on every road into main.

    run-tests lived in a pull_request-only workflow while the work landed by
    direct push, so 1,318 cases guarded a road almost nothing took. What is
    asserted here is reachability, not the workflow's shape.
    """

    @staticmethod
    def _workflow(name: str) -> dict:
        with (REPO_ROOT / ".github" / "workflows" / name).open(encoding="utf-8") as f:
            document = yaml.safe_load(f)
        # PyYAML resolves the bare `on:` key to the boolean True.
        document["on"] = document.pop(True, document.get("on"))
        return document

    def test_no_validation_step_discards_its_exit_code(self):
        """A check whose result is thrown away is not a check.

        The BIOS validation step ended in `|| true`, so validate_pr.py could
        exit 1 on a file that failed its hash and the job stayed green. The
        report still has to reach the pull request, so the code is recorded
        and acted on afterwards rather than swallowed. A best-effort side
        action such as adding a label is not a check and keeps its `|| true`.
        """
        checks = ("python scripts/", "unittest", "npm run build")
        for name in ("validate.yml", "deploy-site.yml"):
            workflow = self._workflow(name)
            for job_name, job in workflow["jobs"].items():
                for step in job.get("steps", []):
                    # A shell continuation puts the command and its `|| true`
                    # on different lines, so they are rejoined before scanning.
                    body = str(step.get("run", "")).replace("\\\n", " ")
                    for line in body.splitlines():
                        if not any(marker in line for marker in checks):
                            continue
                        self.assertNotIn(
                            "|| true",
                            line,
                            f"{name}:{job_name}:{step.get('name', '?')} runs a "
                            f"check and discards its exit code: {line.strip()}",
                        )

        workflow = self._workflow("validate.yml")
        steps = workflow["jobs"]["validate-bios"]["steps"]
        gate = [s for s in steps if "rc != " in str(s.get("if", ""))]
        self.assertTrue(
            gate,
            "nothing in validate-bios acts on the validation exit code",
        )

    def test_the_suite_runs_on_a_direct_push_to_main(self):
        workflow = self._workflow("validate.yml")
        triggers = workflow["on"]
        self.assertIn("push", triggers, "validate.yml no longer runs on push")
        self.assertIn("main", triggers["push"]["branches"])
        job = next(
            (
                name
                for name, body in workflow["jobs"].items()
                if any(
                    "scripts/run_tests.py" in str(step.get("run", ""))
                    for step in body.get("steps", [])
                )
            ),
            None,
        )
        self.assertIsNotNone(job, "no job runs the test suite")
        self.assertIsNone(
            workflow["jobs"][job].get("if"),
            f"{job} carries a condition, but the suite must run on push and on PR",
        )

    def test_added_profiles_meet_their_upstream_on_both_roads(self):
        """A new profile's refs were confronted only if its author remembered."""
        workflow = self._workflow("validate.yml")
        runs = [
            (name, str(step.get("run", "")))
            for name, body in workflow["jobs"].items()
            for step in body.get("steps", [])
            if "profile_sync.py" in str(step.get("run", ""))
        ]
        self.assertTrue(runs, "no job confronts profiles with their upstream")
        for name, body in runs:
            self.assertIn("--strict", body)
            self.assertIn("--added", body)
            self.assertIsNone(workflow["jobs"][name].get("if"), f"{name} must run on push too")

    def test_both_events_watch_the_same_paths(self):
        triggers = self._workflow("validate.yml")["on"]
        self.assertEqual(
            triggers["pull_request"]["paths"],
            triggers["push"]["paths"],
            "the two path lists have drifted, so a push would skip what a PR checks",
        )

    def test_pull_request_only_jobs_are_guarded(self):
        workflow = self._workflow("validate.yml")
        for name, body in workflow["jobs"].items():
            uses_pr_context = "github.event.pull_request" in yaml.dump(body)
            if uses_pr_context:
                self.assertEqual(
                    body.get("if"),
                    "github.event_name == 'pull_request'",
                    f"{name} reads pull request context and would run on a push",
                )

    def test_no_workflow_relies_on_a_yaml_anchor(self):
        """The workflow parser reads no anchor, and PyYAML would hide the break."""
        for path in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                self.assertIsNone(
                    re.search(r"(?:^|\s)[&*][A-Za-z_]", line),
                    f"{path.name}:{number} uses a YAML anchor: {line.strip()}",
                )


class PatchesTargetWhatRuns(unittest.TestCase):
    """mock.patch.object with create set to True builds an attribute on a
    module when the name is missing: packextras imported resolve_platform_cores
    inside the function, the patch created a global nobody read, and the
    real function walked the repository while the test claimed to isolate
    it."""

    def test_no_test_creates_the_attribute_it_patches(self):
        needle = "create" + "=True"
        offenders = []
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if needle in code:
                    offenders.append(f"{path.name}:{number}")
        self.assertEqual(offenders, [])


class NoParserAcceptsAnAbbreviation(unittest.TestCase):
    """argparse completes a prefix: `slots.py --emulator dolphin` became
    --emulators-dir dolphin and reported 0 contested destinations, exit 0, and
    `pipeline.py --all` became --all-variants and built six packs per
    platform. The flags read like other scripts' and were never refused."""

    def test_every_parser_refuses_prefixes(self):
        import ast

        lax = []
        for path in sorted([*(REPO_ROOT / "scripts").rglob("*.py"), REPO_ROOT / "install.py"]):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name != "ArgumentParser":
                    continue
                if not any(
                    kw.arg == "allow_abbrev"
                    and isinstance(kw.value, ast.Constant) and kw.value.value is False
                    for kw in node.keywords
                ):
                    lax.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(lax, [])


class SchemaFormatsAreChecked(unittest.TestCase):
    """date-time and uri need jsonschema's format extras. Without them the
    published format constraints were accepted unread."""

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_a_missing_checker_is_named(self):
        from schemas import validators

        empty = mock.Mock(checkers={})
        with mock.patch.object(validators, "FormatChecker", return_value=empty):
            self.assertEqual(validators.unchecked_formats(), ["date-time", "uri"])

    def test_every_install_asks_for_the_extras(self):
        for path in (".github/workflows/validate.yml", ".github/workflows/deploy-site.yml",
                     "pyproject.toml"):
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotRegex(text, r"jsonschema(?!\[format)[=>]")


class CheckoutCompletenessRegressions(unittest.TestCase):
    """Coverage is resolved against the disk, so the checkout must be whole.

    Files over 50 MB and the data directory caches are gitignored. A job that
    regenerates the README or the site without restoring them counts those
    files as missing and publishes a coverage the collection does not have.
    """

    def _steps(self, workflow: str, job: str) -> list[dict]:
        data = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / workflow).read_text())
        return data["jobs"][job]["steps"]

    def _index(self, steps: list[dict], needle: str) -> int:
        for position, step in enumerate(steps):
            if needle in step.get("name", "") or needle in str(step.get("run", "")):
                return position
        raise self.failureException(f"no step matching {needle!r}")

    def test_site_deploy_completes_the_checkout_before_generating(self):
        steps = self._steps("deploy-site.yml", "build")
        generate = self._index(steps, "Generate site")
        self.assertLess(self._index(steps, "restore_large_files.py"), generate)
        self.assertLess(self._index(steps, "refresh_data_dirs.py"), generate)

    def test_restore_matches_assets_by_content_not_by_name(self):
        from scripts.release.restore import restore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"firmware bytes"
            (cache / "renamed-asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text("bios/Sony/big.pup\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {sha1: {"path": "bios/Sony/big.pup"}}}),
                encoding="utf-8",
            )
            result = restore(
                str(cache), str(root / "database.json"), str(root / ".gitignore"),
                root=root,
            )
            self.assertEqual(
                (result.restored, result.unsatisfied), (["bios/Sony/big.pup"], [])
            )
            self.assertEqual((root / "bios/Sony/big.pup").read_bytes(), payload)
            # A path already in the checkout is never overwritten.
            result = restore(
                str(cache), str(root / "database.json"), str(root / ".gitignore"),
                root=root,
            )
            self.assertEqual((result.restored, result.unsatisfied), ([], []))

    def test_restore_without_its_registry_fails(self):
        """A mistyped --gitignore read as an empty registry: nothing to
        restore, nothing unsatisfied, exit 0 with every asset absent."""
        import subprocess

        from scripts.release.restore import gitignored_paths

        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "absent")
            with self.assertRaises(FileNotFoundError):
                gitignored_paths(missing)
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "restore_large_files.py"),
                 "--gitignore", missing, "--cache", directory],
                capture_output=True, text=True, timeout=120,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("lists the release assets", proc.stderr)

    def test_restore_refuses_a_copy_replaced_after_the_index(self):
        """The cache is hashed first and copied later: another run that
        replaced the cached name in between put its bytes at a path the
        database pins to the old ones."""
        from scripts.release import restore as release_restore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"firmware bytes"
            (cache / "asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text("bios/Sony/big.pup\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {sha1: {"path": "bios/Sony/big.pup"}}}),
                encoding="utf-8",
            )
            real_index = release_restore.index_cache

            def index_then_replace(cache_dir: str) -> dict[str, str]:
                index = real_index(cache_dir)
                (cache / "asset.bin").write_bytes(b"re-uploaded bytes")
                return index

            with mock.patch.object(release_restore, "index_cache", index_then_replace):
                result = release_restore.restore(
                    str(cache), str(root / "database.json"),
                    str(root / ".gitignore"), root=root,
                )
            self.assertEqual(
                (result.restored, result.unsatisfied), ([], ["bios/Sony/big.pup"])
            )
            self.assertFalse((root / "bios/Sony/big.pup").exists())
            self.assertEqual(os.listdir(root / "bios/Sony"), [])

    def test_restore_leaves_tracked_paths_alone(self):
        from scripts.release.restore import restore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"tracked bytes"
            (cache / "asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text("bios/other.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {sha1: {"path": "bios/tracked.bin"}}}),
                encoding="utf-8",
            )
            result = restore(
                str(cache), str(root / "database.json"), str(root / ".gitignore"),
                root=root,
            )
            self.assertEqual((result.restored, result.unsatisfied), ([], []))
            self.assertFalse((root / "bios/tracked.bin").exists())

    def test_restore_without_a_cache_names_what_is_missing(self):
        """A job that skipped `mkdir .cache/large` exited 0 with every
        gitignored file absent: the early return ran before the check."""
        from scripts.release.restore import restore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text("bios/big.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {"a" * 40: {"path": "bios/big.bin"}}}),
                encoding="utf-8",
            )
            result = restore(
                str(root / "no-cache"), str(root / "database.json"),
                str(root / ".gitignore"), root=root,
            )
            self.assertEqual(
                (result.restored, result.unsatisfied, result.cache_found),
                ([], ["bios/big.bin"], False),
            )

    def test_restore_command_prints_the_report(self):
        """The command, not the library, says what was restored and what the
        cache could not supply, relative to the directory it runs in."""
        import subprocess

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            payload = b"firmware bytes"
            (cache / "asset.bin").write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            (root / ".gitignore").write_text(
                "bios/big.bin\nbios/absent.bin\n", encoding="utf-8"
            )
            (root / "database.json").write_text(
                json.dumps({"files": {
                    sha1: {"path": "bios/big.bin"},
                    "a" * 40: {"path": "bios/absent.bin"},
                }}),
                encoding="utf-8",
            )
            command = [sys.executable, str(REPO_ROOT / "scripts" / "restore_large_files.py")]
            proc = subprocess.run(
                [*command, "--cache", "cache"],
                capture_output=True, text=True, cwd=str(root), timeout=120,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertEqual(
                proc.stdout, "Restored: bios/big.bin\nTotal: 1 files restored\n"
            )
            self.assertEqual(
                proc.stderr,
                "Unsatisfied: 1 declared paths the cache cannot supply\n"
                "  bios/absent.bin\n",
            )
            self.assertEqual((root / "bios/big.bin").read_bytes(), payload)
            without_cache = subprocess.run(
                [*command, "--cache", "no-cache"],
                capture_output=True, text=True, cwd=str(root), timeout=120,
                check=False,
            )
            self.assertTrue(without_cache.stdout.startswith("No cache at no-cache\n"))


class PreservedBytesAreNeverNormalised(unittest.TestCase):
    """git must not rewrite a preserved file's line endings.

    SHA1 is the primary key of this collection. Git for Windows sets
    core.autocrlf=true by default, so without an attribute saying otherwise a
    clone there rewrites every file git guesses is text -- shaders, .ini,
    .txt and .dat assets under bios/ -- and each one arrives with a different
    hash from the one published here.
    """

    def _attr(self, path: str) -> str:
        import subprocess

        out = subprocess.run(
            ["git", "check-attr", "text", "--", path],
            capture_output=True, text=True, cwd=REPO_ROOT,
            check=False,
        ).stdout
        return out.rsplit(":", 1)[-1].strip()

    def test_gitattributes_exists(self):
        self.assertTrue(
            (REPO_ROOT / ".gitattributes").is_file(),
            "without it git guesses, and guesses wrong on Windows",
        )

    def test_collection_paths_are_exempt_from_normalisation(self):
        for path in (
            "bios/Sony/PlayStation/scph5501.bin",
            "bios/Other/j2me-loader/color.fsh",
            "data/anything.txt",
            "data/dolphin-sys/config.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._attr(path), "unset", f"{path} may be rewritten")

    def test_generated_artefacts_stay_lf(self):
        for path in (
            "database.json",
            "scripts/dedup.py",
            "README.md",
            "provenance/redump.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(self._attr(path), "set")


class FreshnessGuardMechanics(unittest.TestCase):
    """write_if_changed is what makes `git diff --exit-code` a real check.

    deploy-site.yml regenerates README.md and CONTRIBUTING.md and then fails
    if git sees a change. That is only a staleness check because a run which
    moves nothing but the clock leaves the file untouched. If the comparison
    missed a timestamp form, the guard would fail on every run and stop
    meaning anything.
    """

    def setUp(self):
        from core.artifacts import write_if_changed

        self.write_if_changed = write_if_changed
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "page.md")

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_new_file_is_written(self):
        self.assertTrue(self.write_if_changed(self.path, "body\n"))
        with open(self.path) as handle:
            self.assertEqual(handle.read(), "body\n")

    def test_identical_content_is_not_rewritten(self):
        self.write_if_changed(self.path, "body\n")
        self.assertFalse(self.write_if_changed(self.path, "body\n"))

    def test_real_change_is_written(self):
        self.write_if_changed(self.path, "body\n")
        self.assertTrue(self.write_if_changed(self.path, "other\n"))

    def test_every_timestamp_form_is_ignored_on_its_own(self):
        forms = [
            '{{"generated_at": "{}"}}',
            '{{"imported_at": "{}"}}',
            '{{"generated": "{}"}}',
            '{{"fetched": "{}"}}',
            "*Auto-generated on {}*",
            "*Generated on {}*",
            '<div class="rb-timestamp">Generated on {}.</div>',
        ]
        for form in forms:
            with self.subTest(form=form):
                first = form.format("2026-01-01T00:00:00Z")
                second = form.format("2026-09-09T09:09:09Z")
                self.write_if_changed(self.path, first)
                self.assertFalse(
                    self.write_if_changed(self.path, second),
                    f"a clock-only change rewrote the file for {form!r}",
                )

    def test_a_change_beside_a_moving_timestamp_is_still_written(self):
        self.write_if_changed(self.path, "count: 1\n*Generated on A*\n")
        self.assertTrue(
            self.write_if_changed(self.path, "count: 2\n*Generated on B*\n")
        )

    def test_the_written_file_keeps_the_new_timestamp_when_content_changed(self):
        self.write_if_changed(self.path, "count: 1\n*Generated on A*\n")
        self.write_if_changed(self.path, "count: 2\n*Generated on B*\n")
        with open(self.path) as handle:
            self.assertIn("Generated on B", handle.read())


class AMissingDependencyStopsTheBuild(unittest.TestCase):
    """generate_db read every alias inside `try: import yaml ... except
    ImportError: pass`: on an interpreter without pyyaml the database lost
    3186 alias lines and the run exited 0."""

    def test_generate_db_without_pyyaml_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "database.json"
            proc = subprocess.run(
                [sys.executable, "-S", "scripts/generate_db.py", "--force",
                 "--bios-dir", "bios", "--output", str(output)],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("PyYAML required", proc.stderr)
            self.assertFalse(output.exists())

    def test_every_yaml_command_stops_on_one_line(self):
        """refresh_data_dirs and check_buildbot_system ended on a traceback."""
        for command in (["scripts/refresh_data_dirs.py", "--dry-run"],
                        ["scripts/check_buildbot_system.py"]):
            with self.subTest(command=command[0]):
                proc = subprocess.run(
                    [sys.executable, "-S", *command],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.assertEqual(
                    proc.stderr.strip(), "Error: PyYAML required (pip install pyyaml)"
                )

    def test_no_script_swallows_an_import_error(self):
        offenders = []
        for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            offenders.extend(
                f"{path.relative_to(REPO_ROOT)}:{node.lineno}"
                for node in ast.walk(tree)
                if (
                    isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Name)
                    and node.type.id in ("ImportError", "ModuleNotFoundError")
                    and all(isinstance(stmt, ast.Pass) for stmt in node.body)
                )
            )
        self.assertEqual(offenders, [])


class TestsCleanUpTheirScratch(unittest.TestCase):
    """Sixteen classes called mkdtemp() and kept the directory: each suite
    run left about 400 of them on the RAM-backed /tmp."""

    def test_every_class_that_makes_a_directory_removes_it(self):
        offenders = []
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            source = path.read_text(encoding="utf-8")
            for node in ast.parse(source).body:
                if not isinstance(node, ast.ClassDef):
                    continue
                body = ast.get_source_segment(source, node) or ""
                if "mkdtemp(" in body and not any(
                    word in body for word in ("rmtree", "addCleanup", "tearDown")
                ):
                    offenders.append(f"{path.name}:{node.name}")
        self.assertEqual(offenders, [])


class DeclaredDependenciesMatchTheDocumentedWorkflows(unittest.TestCase):
    """What the workflows install has to be what the project declares.

    mkdocs-material and pymdown-extensions were hard requirements of the site
    build in CI and in the release guide while pyproject declared neither, so
    a contributor following either had to read the workflow to find out.
    """

    @staticmethod
    def _pyproject() -> dict:
        import tomllib

        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle)

    def test_every_package_ci_installs_is_declared(self):
        extras = self._pyproject()["project"]["optional-dependencies"]
        declared = {
            name.split(">")[0].split("=")[0].split("<")[0].strip('"')
            for group in extras.values()
            for name in group
        }
        declared |= set(self._pyproject()["project"]["dependencies"])
        installed: set[str] = set()
        for workflow in ("validate.yml", "deploy-site.yml"):
            body = (REPO_ROOT / ".github" / "workflows" / workflow).read_text(
                encoding="utf-8"
            )
            for line in body.splitlines():
                if "pip install" not in line:
                    continue
                for token in line.split("pip install", 1)[1].split():
                    name = token.strip('"').split(">")[0].split("=")[0]
                    name = name.split("<")[0].strip()
                    if name:
                        installed.add(name)
        self.assertEqual(
            installed - declared,
            set(),
            "CI installs packages pyproject does not declare",
        )


class TheAnnotationsAreChecked(unittest.TestCase):
    """Every signature carried type hints and nothing read them: six pack
    helpers declared `zipfile.ZipFile` while every caller also passed a
    PackRecord, and 990 such contradictions went through CI green. They sat
    in a baseline until the last one was fixed: the code now carries no
    type error, and CI runs mypy bare, so any new one fails."""

    def test_ci_runs_mypy_without_a_baseline(self):
        body = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(body, r"(?m)^\s+mypy$")
        self.assertNotIn("mypy-baseline", body)
        self.assertFalse((REPO_ROOT / "mypy-baseline.txt").exists())

    def test_the_code_reports_no_type_error(self):
        try:
            __import__("mypy")
        except ImportError:
            self.skipTest("mypy is not installed (pip install -e '.[dev]')")
        report = subprocess.run(
            [sys.executable, "-m", "mypy"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(report.returncode, 0, report.stdout[-4000:])


class TheProjectInstallsWithPip(unittest.TestCase):
    """pyproject declared a dev extra that pip could not install: without a
    [build-system] and an explicit module list, setuptools' flat-layout
    discovery found scripts/ and tests/ and refused to build."""

    def test_setuptools_discovers_nothing_to_package(self):
        import importlib.util

        if importlib.util.find_spec("setuptools") is None:
            # The dev extra and CI install it: skipped there, the guard held
            # nothing on any run.
            if os.environ.get("CI"):
                self.fail("CI must install setuptools")
            self.skipTest("setuptools is not installed")
        program = (
            "from setuptools.dist import Distribution\n"
            "from setuptools.config.pyprojecttoml import apply_configuration\n"
            "dist = apply_configuration(Distribution(), 'pyproject.toml')\n"
            "dist.set_defaults()\n"
            "print(sorted(dist.packages or []), sorted(dist.py_modules or []))\n"
        )
        done = subprocess.run([sys.executable, "-c", program], cwd=REPO_ROOT,
                              capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        self.assertEqual(done.stdout.strip(), "[] []")
        import tomllib

        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            build = tomllib.load(handle)["build-system"]
        self.assertEqual(build["build-backend"], "setuptools.build_meta")


class TestEntryPointsRunEveryClass(unittest.TestCase):
    """`unittest.main()` has to sit after the last test class.

    In this file it sat in the middle, so running it directly discovered only
    the classes defined above it: eight cases never ran that way, while
    `python -m unittest discover` ran all of them. The two roads have to agree.
    """

    def test_no_module_calls_main_before_its_last_class(self):
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            lines = path.read_text(encoding="utf-8").splitlines()
            # Column zero only: the same text appears inside this very test as
            # a string literal, and a substring search matched that instead.
            entry = next(
                (n for n, line in enumerate(lines)
                 if line.startswith("if __name__ ==")),
                None,
            )
            if entry is None:
                continue
            last_class = max(
                (n for n, line in enumerate(lines) if line.startswith("class ")),
                default=-1,
            )
            self.assertGreater(
                entry,
                last_class,
                f"{path.name} calls unittest.main() before its last class, so "
                "running the file directly skips what follows",
            )


class ScriptsImportThreeWays(unittest.TestCase):
    """A script is run directly, run as a module, and imported as a package.

    The three do not agree on what is on the path: only the first form adds
    the scripts directory. Adding the package marker without the bootstrap
    made `import scripts.common` (now scripts.core.cli) fail on the first sibling import it reached.
    """

    def _run(self, *args: str):
        import subprocess

        return subprocess.run(
            [sys.executable, *args],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=300,
            check=False,
        )

    def test_imported_as_a_package(self):
        result = self._run(
            "-c", "import scripts.core.cli, scripts.model.platforms, scripts.resolve.localfile, "
            "scripts.verify, scripts.generate_pack"
        )
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_module(self):
        result = self._run("-m", "scripts.scraper.libretro_scraper", "--help")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_script(self):
        result = self._run("scripts/list_platforms.py")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])


class NoHandlerSwallowsEverything(unittest.TestCase):
    """The project forbids `except Exception: pass`, but the edit hook missed
    the two-line form and nothing in CI checked it."""

    def test_no_catch_all_handler_only_passes(self):
        import ast

        offenders = []
        for path in [*sorted((REPO_ROOT / "scripts").rglob("*.py")), REPO_ROOT / "install.py"]:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                broad = node.type is None or (
                    isinstance(node.type, ast.Name)
                    and node.type.id in ("Exception", "BaseException")
                )
                if broad and all(isinstance(stmt, ast.Pass) for stmt in node.body):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [])


class ModuleConstantsDeclaredOnce(unittest.TestCase):
    """Splitting common.py into modules emitted some constants twice.

    The values matched, so nothing broke, but the second assignment orphans
    the comment written above the first and leaves two lines to keep in step
    the day a value changes.
    """

    @staticmethod
    def _redeclared(path: Path) -> list[str]:
        seen: dict[str, str] = {}
        again = []
        for node in ast.parse(path.read_text()).body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = ast.unparse(node.value)
            if seen.get(target.id) == value:
                again.append(target.id)
            seen[target.id] = value
        return again

    def test_no_module_assigns_the_same_constant_twice(self):
        offenders = {}
        for path in sorted(REPO_ROOT.glob("scripts/**/*.py")) + [REPO_ROOT / "install.py"]:
            again = self._redeclared(path)
            if again:
                offenders[path.name] = again
        self.assertEqual(offenders, {})


class OnlyTheSchemaValidatorNeedsJsonschema(unittest.TestCase):
    """Build scripts and install.py run on stdlib plus pyyaml, and jsonschema is
    tooling for the schemas package behind validate_schemas and CI. An import
    anywhere else turns a contributor's pipeline run into an ImportError."""

    @staticmethod
    def _imports_jsonschema(source: str) -> bool:
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(name.split(".")[0] == "jsonschema" for name in names):
                return True
        return False

    def test_no_other_module_imports_it(self):
        offenders = [
            str(path.relative_to(REPO_ROOT))
            for path in sorted(REPO_ROOT.glob("scripts/**/*.py")) + [REPO_ROOT / "install.py"]
            if path.parent != REPO_ROOT / "scripts" / "schemas"
            and self._imports_jsonschema(path.read_text())
        ]
        self.assertEqual(offenders, [])

    def test_a_nested_import_is_seen(self):
        self.assertTrue(
            self._imports_jsonschema("def f():\n    from jsonschema import validate\n")
        )


class ADuplicateYamlKeyIsRefused(unittest.TestCase):
    """PyYAML kept the last of two equal keys: the registry carried two
    target_source keys for Recalbox and nothing noticed."""

    def test_the_loader_names_the_repeated_key(self):
        from model.safeparse import yaml_load

        with self.assertRaises(yaml.constructor.ConstructorError) as caught:
            yaml_load("platform: x\ntarget_source: a\ntarget_source: b\n")
        self.assertIn("duplicate key 'target_source'", str(caught.exception))
        self.assertEqual(yaml_load("a: &x {b: 1}\nc: *x\n"), {"a": {"b": 1}, "c": {"b": 1}})


class NoSourceWarnsWhenCompiled(unittest.TestCase):
    """A docstring naming C:\\RetroArch-Win64 with one backslash compiled to
    an invalid escape: a SyntaxWarning on every run of the installer."""

    def test_every_script_compiles_clean(self):
        import warnings

        sources = [REPO_ROOT / "install.py", *sorted((REPO_ROOT / "scripts").rglob("*.py"))]
        for path in sources:
            with self.subTest(path=path.name), warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                warnings.simplefilter("error", DeprecationWarning)
                compile(path.read_text(encoding="utf-8"), str(path), "exec")


class TestsRunOffline(unittest.TestCase):
    def test_the_package_forbids_downloads(self):
        self.assertTrue(os.environ.get("RETROBIOS_OFFLINE"))

    def test_every_documented_run_imports_the_package(self):
        """`discover tests` makes tests/ the top level, so tests/__init__.py,
        which sets RETROBIOS_OFFLINE, never ran: a local run of the documented
        command queried the release and wrote into the shared cache. Only CI,
        which sets the variable itself, was offline."""
        import subprocess

        listed = subprocess.run(
            ["git", "grep", "-n", "unittest discover", "--", ":!tests"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=False,
        ).stdout.splitlines()
        self.assertTrue(listed)
        self.assertEqual([line for line in listed if "-t ." not in line], [])


class MessagesSeparateWithAColon(unittest.TestCase):
    """Em-dashes were replaced by " -" in messages: "bios/BLOOD.RFF -raze
    says size mismatch" reads as a flag glued to a file name."""

    PATTERN = re.compile(r"\} -[{a-z]")

    def test_no_message_uses_a_dash_separator(self):
        found = []
        for path in [REPO_ROOT / "install.py", *sorted((REPO_ROOT / "scripts").rglob("*.py"))]:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if self.PATTERN.search(line):
                    found.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(found, [])


class TheIssueFormListsEveryPlatform(unittest.TestCase):
    """The missing-BIOS form offered 7 of the 12 registered platforms."""

    def test_every_registered_platform_is_an_option(self):
        from scripts.model.registry import list_registered_platforms
        from scripts.model.platforms import load_platform_config

        form = yaml.safe_load(
            (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "missing-bios.yml").read_text()
        )
        options = next(
            item["attributes"]["options"] for item in form["body"]
            if item.get("id") == "platform"
        )
        for name in list_registered_platforms(str(REPO_ROOT / "platforms")):
            display = load_platform_config(name, str(REPO_ROOT / "platforms"))["platform"]
            self.assertIn(display, options)


class TheTestJobHasTheDataTrees(unittest.TestCase):
    """Packs built without data directories exit non-zero, but the CI test job
    had none, and two pack parity tests failed there only."""

    def test_the_trees_are_fetched_before_the_suite(self):
        steps = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text()
        )["jobs"]["run-tests"]["steps"]
        runs = [step.get("run", "") for step in steps]
        fetch = next(i for i, run in enumerate(runs) if "refresh_data_dirs.py" in run)
        suite = next(i for i, run in enumerate(runs) if "scripts/run_tests.py" in run)
        self.assertLess(fetch, suite)


class GeneratedArtifactsMeetTheirSchemas(unittest.TestCase):
    """A manifest field added without its schema passed every local test
    and failed the site deploy, which is the first run of the full check."""

    @unittest.skipUnless(HAS_JSONSCHEMA, "needs jsonschema")
    def test_the_full_schema_check_passes(self):
        proc = subprocess.run(
            [sys.executable, "scripts/validate_schemas.py"], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=600,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class SignaturesCarryTheirTypes(unittest.TestCase):
    """Type hints on every signature is a written rule; 177 had none, the
    shared API among them (artifact locks, the data-dir resolver, the region
    priority list of _select_variants)."""

    # Lowered as modules are annotated, never raised.
    CEILING = 0
    COMPLETE = ("core/artifacts.py", "model/platforms.py", "model/profiles.py", "resolve/localfile.py",
                "resolve/lookup.py", "resolve/namestages.py", "resolve/validation.py",
                "resolve/entryscope.py", "resolve/acceptance.py", "generate_pack.py")

    @staticmethod
    def _missing(path: Path) -> list[str]:
        found = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            params = [a for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
                      if a.arg not in ("self", "cls")]
            params += [a for a in (args.vararg, args.kwarg) if a]
            if node.returns is None or any(a.annotation is None for a in params):
                found.append(f"{path.name}:{node.lineno} {node.name}")
        return found

    def test_the_count_only_goes_down(self):
        paths = [REPO_ROOT / "install.py", *sorted((REPO_ROOT / "scripts").rglob("*.py"))]
        missing = [m for path in paths for m in self._missing(path)]
        self.assertLessEqual(len(missing), self.CEILING, missing[:20])
        for name in self.COMPLETE:
            with self.subTest(module=name):
                self.assertEqual(self._missing(REPO_ROOT / "scripts" / name), [])


class TheApiSchemaHoldsTheFieldsItPromises(unittest.TestCase):
    """The data page promises fields are only added within v1, and the
    published schema left items unconstrained: renaming url in
    file-locations.json passed validation and broke consumers silently."""

    def test_a_renamed_field_is_refused(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is tooling only")
        schema = json.loads((REPO_ROOT / "schemas" / "site-api-envelope.schema.json").read_text())
        envelope = {"schema_version": 1, "generated_at": "2026-10-20T00:00:00Z",
                    "kind": "file-locations", "count": 1,
                    "items": [{"sha1": "a" * 40, "url": "https://x/y"}]}
        jsonschema.validate(envelope, schema)
        envelope["items"] = [{"sha1": "a" * 40, "href": "https://x/y"}]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(envelope, schema)


class CommentsSayWhy(unittest.TestCase):
    """A one-line comment that names the next statement ("# Load registry",
    "# Build cross-reference indexes") repeats the code. A comment that
    stays says why (for, only, so, because)."""

    LABEL = re.compile(
        r"^\s*# (Load|Build|Collect|Determine|Resolve|Group|Copy|Count|Append|"
        r"Filter|Separate|Compute|Create|Get|Check|Generate|Write|Read|Parse|Sort)"
        r"\b[^.:;,()]{0,60}$"
    )
    REASON = re.compile(r"\b(for|only|so|because|if|when|unless|before|after)\b")

    def test_no_label_comment_restates_the_next_line(self):
        """Three scripts were read, and 22 labels stood in 13 others."""
        tracked = subprocess.run(
            ["git", "ls-files", "--", "scripts/*.py", "scripts/**/*.py", "install.py"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.split()
        self.assertIn("install.py", tracked)
        self.assertIn("scripts/scraper/mame_parser.py", tracked)
        found = []
        for name in sorted(set(tracked)):
            lines = (REPO_ROOT / name).read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not self.LABEL.match(line) or self.REASON.search(line):
                    continue
                around = (lines[index - 1].strip(), lines[index + 1].strip())
                if any(neighbour.startswith("#") for neighbour in around):
                    continue
                if not line.startswith(" "):
                    continue
                found.append(f"{name}:{index + 1}: {line.strip()}")
        self.assertEqual(found, [])


class PipelineChildrenSkipNodeCompileCache(unittest.TestCase):
    """The site build's compile cache filled the 4 GB /tmp tmpfs to 3.4 GB:
    every child the pipeline starts carries NODE_DISABLE_COMPILE_CACHE."""

    def test_the_run_helper_sets_it(self):
        source = script_source("pipeline.py")
        self.assertIn('"NODE_DISABLE_COMPILE_CACHE": "1"', source)


class TupleAnnotationsMatchTheirReturns(unittest.TestCase):
    """`_by_affinity.score` gained a fifth sort key while its annotation kept
    four, so the signature misread the order that sends C-Dogs'
    gamecontrollerdb.txt behind a neutral copy."""

    @staticmethod
    def _own_returns(fn: ast.AST):
        stack = list(ast.iter_child_nodes(fn))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Return):
                yield node
            stack.extend(ast.iter_child_nodes(node))

    def test_a_fixed_tuple_annotation_counts_its_returned_values(self):
        sources = sorted((REPO_ROOT / "scripts").rglob("*.py")) + [REPO_ROOT / "install.py"]
        mismatched = []
        for path in sources:
            for fn in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                hint = fn.returns
                if not (isinstance(hint, ast.Subscript) and isinstance(hint.value, ast.Name)
                        and hint.value.id == "tuple"):
                    continue
                declared = hint.slice.elts if isinstance(hint.slice, ast.Tuple) else [hint.slice]
                if any(isinstance(e, ast.Constant) and e.value is Ellipsis for e in declared):
                    continue
                for ret in self._own_returns(fn):
                    value = ret.value
                    if (isinstance(value, ast.Tuple)
                            and not any(isinstance(e, ast.Starred) for e in value.elts)
                            and len(value.elts) != len(declared)):
                        mismatched.append(
                            f"{path.relative_to(REPO_ROOT)}:{ret.lineno} "
                            f"{len(value.elts)} returned, {len(declared)} declared"
                        )
        self.assertEqual(mismatched, [])


if __name__ == "__main__":
    unittest.main()
