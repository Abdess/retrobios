"""Regression tests for the holistic reliability and security audit."""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import ast
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

import yaml

try:
    import jsonschema  # noqa: F401
except ImportError:
    HAS_JSONSCHEMA = False
else:
    HAS_JSONSCHEMA = True

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / "tmp" / "tests"
TMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import install
from scripts import pipeline, region, region_audit
from scripts.common import resolve_local_file, safe_extract_zip
from scripts.generate_pack import (
    _emulator_region_group,
    generate_target_manifests,
    verify_pack_against_platform,
)


class ReadmeRegressions(unittest.TestCase):
    """The README advertises commands, and these must stay executable.

    Wording is the maintainer's, so nothing here asserts prose. What is
    asserted is that every flag and URL the README hands a reader is one the
    shipped scripts actually accept.
    """

    def _quick_install(self) -> str:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        return readme.split("## Install in one line", 1)[1].split(
            "## Or download a ZIP", 1
        )[0]

    def test_advertised_bootstrap_urls_are_the_shipped_ones(self):
        import sitebootstrap
        from siteguides import INSTALL_BASE

        quick_install = self._quick_install()
        for name in sitebootstrap.SOURCES:
            url = f"{INSTALL_BASE}/{name}"
            self.assertIn(f"{url} |", quick_install, f"{name} bootstrap URL missing")
        # The site serves each bootstrap with install.py read from the
        # commit it was built from, the raw form from main.
        commit = "0" * 40
        for name in sitebootstrap.SOURCES:
            self.assertIn(sitebootstrap.installer_url(commit),
                          sitebootstrap.served_text(name, ROOT, commit))
        self.assertIn(
            "https://raw.githubusercontent.com/Abdess/retrobios/main/install.py",
            (ROOT / "install.sh").read_text(encoding="utf-8"),
        )

    def test_advertised_installer_flags_exist(self):
        quick_install = self._quick_install()
        advertised = set(re.findall(r"(?<![\w-])--[a-z][a-z-]+", quick_install))
        parser_source = (ROOT / "install.py").read_text(encoding="utf-8")
        supported = set(re.findall(r'add_argument\(\s*"(--[a-z][a-z-]+)"', parser_source))
        unknown = advertised - supported
        self.assertEqual(unknown, set(), f"README advertises unknown flags: {unknown}")

    def test_the_build_version_is_the_one_the_pipeline_requires(self):
        """"Python 3 + pyyaml" sent a 3.8 user to a SyntaxError in
        generate_pack, and a 3.10 one through six steps to fail at step 7."""
        floor = re.search(
            r"sys\.version_info < \((\d+), (\d+)\)",
            (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8"),
        )
        self.assertIsNotNone(floor, "pipeline.py checks no interpreter version")
        version = f"Python {floor.group(1)}.{floor.group(2)}"
        for page in ("README.md", "wiki/tools.md", "wiki/testing-guide.md"):
            with self.subTest(page=page):
                self.assertIn(version, (ROOT / page).read_text(encoding="utf-8"))
        self.assertIn(
            version, (ROOT / "scripts" / "generate_readme.py").read_text(encoding="utf-8")
        )

    def test_an_older_interpreter_is_refused_before_the_first_step(self):
        import shutil  # noqa: PLC0415

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        # --help: without the guard the run must stop at argparse, not
        # rebuild database.json under an interpreter missing pyyaml.
        proc = subprocess.run(
            [python38, "-I", "scripts/pipeline.py", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("needs Python 3.9", proc.stderr)

    def test_the_readme_build_command_names_the_floor(self):
        """The README's first command is generate_pack.py. Under 3.8 it
        stopped on a raw SyntaxError at a parenthesized `with`."""
        import shutil  # noqa: PLC0415

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        proc = subprocess.run(
            [python38, "-I", "scripts/generate_pack.py", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("SyntaxError", proc.stderr)
        self.assertIn("generate_pack.py needs Python 3.9", proc.stderr)

    def test_every_script_names_the_floor_under_an_older_interpreter(self):
        """Only generate_pack.py and pipeline.py checked the version. verify.py,
        slots.py, validate_pr.py and cross_reference.py started under 3.8 and
        stopped halfway on a str.removeprefix AttributeError."""
        import shutil  # noqa: PLC0415

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8")
            self.skipTest("no python3.8 on PATH")
        commands = (
            ["verify.py", "--emulator", "handy"],
            ["verify.py", "--platform", "batocera"],
            ["validate_pr.py", "--json", "README.md"],
            ["cross_reference.py", "--emulator", "handy"],
            ["slots.py"],
            ["identity.py"],
            ["generate_site.py", "--help"],
            ["campaign.py", "--help"],
            ["region_check.py", "--help"],
        )
        for command in commands:
            with self.subTest(command=" ".join(command)):
                # -E -s rather than -I: -I drops the script's folder from
                # sys.path, so the imports would fail before any check.
                proc = subprocess.run(
                    [python38, "-E", "-s", f"scripts/{command[0]}", *command[1:]],
                    cwd=ROOT, capture_output=True, text=True, timeout=60,
                    check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn(f"{command[0]} needs Python 3.9", proc.stderr)

    def test_the_floor_interpreter_imports_every_script(self):
        """Every module under scripts/ is loaded by a real interpreter of the
        floor version, as the installer's 3.8 floor is proven by running it.
        Compiling only checks the grammar: a module-level alias such as
        `tuple[int, int | None]` compiles under 3.9 and raises TypeError
        when the module loads."""
        import shutil  # noqa: PLC0415

        floor = re.search(
            r"sys\.version_info < \((\d+), (\d+)\)",
            (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8"),
        )
        name = f"python{floor.group(1)}.{floor.group(2)}"
        interpreter = shutil.which(name)
        if interpreter is None:
            if os.environ.get("CI"):
                self.fail(f"CI must provide {name}")
            self.skipTest(f"no {name} on PATH")
        check = (
            "import importlib, json, pathlib, sys\n"
            "sys.path.insert(0, '.')\n"
            "failed = {}\n"
            "for p in sorted(pathlib.Path('scripts').rglob('*.py')):\n"
            "    if '__pycache__' in p.parts:\n"
            "        continue\n"
            "    parts = p.with_suffix('').parts\n"
            "    if parts[-1] == '__init__':\n"
            "        parts = parts[:-1]\n"
            "    try:\n"
            "        importlib.import_module('.'.join(parts))\n"
            "    except BaseException as e:\n"
            "        failed[str(p)] = [type(e).__name__, getattr(e, 'name', None), str(e)]\n"
            "print(json.dumps(failed))\n"
        )
        proc = subprocess.run(
            [interpreter, "-I", "-c", check], cwd=ROOT, capture_output=True,
            text=True, timeout=600, check=False,
            env={**os.environ, "RETROBIOS_OFFLINE": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        failed = json.loads(proc.stdout.strip().splitlines()[-1])
        # pyyaml for every build script, jsonschema for validate_schemas:
        # without them the floor interpreter cannot load the modules, which
        # proves nothing either way.
        absent = sorted({
            err[1] for err in failed.values()
            if err[0] == "ModuleNotFoundError" and err[1] in ("yaml", "jsonschema")
        })
        if absent:
            message = f"{name} lacks {', '.join(absent)}"
            if os.environ.get("CI"):
                self.fail(message)
            self.skipTest(message)
        self.assertEqual(failed, {})


class AModuleRunAloneHasItsScratchDirectory(unittest.TestCase):
    """About forty modules write under tmp/, which git does not track. Only
    three created it, as an import side effect, so a module run alone on a
    fresh clone raised FileNotFoundError. The test package creates it."""

    def test_importing_the_package_creates_tmp(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            clone = Path(directory)
            (clone / "tests").mkdir()
            (clone / "tests" / "__init__.py").write_bytes(
                (ROOT / "tests" / "__init__.py").read_bytes()
            )
            proc = subprocess.run(
                [sys.executable, "-I", "-c",
                 "import sys; sys.path.insert(0, '.'); import tests, tempfile, os;"
                 " print(tempfile.gettempdir()); print(os.environ['TMPDIR'])"],
                cwd=clone, capture_output=True, text=True, timeout=60, check=False,
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
        for path in sorted((ROOT / "tests").glob("test_*.py")):
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
               if k not in ("RETROBIOS_OFFLINE", "TMPDIR", "RETROBIOS_CACHE")}
        proc = subprocess.run(
            [sys.executable, "-c",
             "import os, sys, tempfile, unittest\n"
             "unittest.TestLoader().discover('tests', pattern='test_artifact_lock.py')\n"
             "print(os.environ.get('RETROBIOS_OFFLINE'), tempfile.gettempdir(),"
             " os.environ.get('RETROBIOS_CACHE'))\n"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        offline, scratch, cache = proc.stdout.split()
        self.assertEqual(offline, "1")
        self.assertEqual(scratch, str(ROOT / "tmp" / "tests"))
        self.assertEqual(cache, str(ROOT / "tmp" / "tests" / "cache"))


class ReleaseSigningRegressions(unittest.TestCase):
    """A checksum list published beside its own artifacts proves nothing.

    SHA256SUMS.txt answers corruption, but whoever can rewrite a release rewrites
    the list with it. The signature is what a third party checks, and it is
    only checkable while allowed_signers, the signing step and the upload
    list stay in agreement.
    """

    PRINCIPAL = "releases@retrobios"

    def test_allowed_signers_names_one_usable_key(self):
        path = ROOT / "allowed_signers"
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
        process = (ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
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
        process = (ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
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
        with (ROOT / ".github" / "workflows" / name).open(encoding="utf-8") as f:
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
                    "unittest discover" in str(step.get("run", ""))
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
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                self.assertIsNone(
                    re.search(r"(?:^|\s)[&*][A-Za-z_]", line),
                    f"{path.name}:{number} uses a YAML anchor: {line.strip()}",
                )


class UnreachableCitationRegressions(unittest.TestCase):
    """A citation must name a place a declared repository can hold.

    kenji-nx carried tmp/es-de/ANDROID.md:470-474, a path from the machine
    of whoever profiled it. No revision of any declared repository holds it,
    so profile_sync could only report it missing, every pass, forever. The
    check is offline and runs on every push.
    """

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def _hits(self, text: str) -> bool:
        import validate_schemas

        return bool(validate_schemas._UNREACHABLE_REF.search(" " + text))

    def test_a_scratch_directory_is_rejected(self):
        self.assertTrue(self._hits("tmp/es-de/ANDROID.md:470-474"))

    def test_an_absolute_path_is_rejected(self):
        self.assertTrue(self._hits("/home/someone/src/a.c:12"))
        self.assertTrue(self._hits(r"C:\work\src\a.c:12"))

    def test_a_path_climbing_out_of_the_tree_is_rejected(self):
        self.assertTrue(self._hits("../outside/src/a.c:12"))

    def test_ordinary_citations_pass(self):
        for good in (
            "src/core/main.cpp:210",
            "libretro.c:5293-5337",
            "PCE.emu/src/main/Main.cc:80-91",
            "es-de ANDROID.md:470-474",
            "see tmp files for details",
        ):
            with self.subTest(citation=good):
                self.assertFalse(self._hits(good))

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_the_corpus_carries_none(self):
        import validate_schemas

        errors = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            with path.open(encoding="utf-8") as handle:
                errors.extend(
                    validate_schemas._unreachable_citations(path, yaml.safe_load(handle))
                )
        self.assertEqual(errors, [])


@unittest.skipUnless(HAS_JSONSCHEMA, "validate_schemas needs jsonschema")
class DoubledCitationPaths(unittest.TestCase):
    """primehack cited Source/Core/Core/IOS/USB/Bluetooth/ twice in a row in a
    comment: no revision holds that path, and the parsed document never
    showed it to the citation checks."""

    def _hits(self, text: str) -> bool:
        import validate_schemas

        return bool(validate_schemas._DOUBLED_PATH.search(text))

    def test_a_repeated_directory_is_rejected(self):
        self.assertTrue(self._hits(
            "# ref: Source/Core/Core/IOS/USB/Bluetooth/Source/Core/Core/IOS/USB/"
            "Bluetooth/RealtekFirmwareLoader.cpp:373-416"
        ))

    def test_a_directory_named_once_passes(self):
        for good in (
            "Source/Core/Core/IOS/USB/Bluetooth/RealtekFirmwareLoader.cpp:383",
            "src/src/main.c:10",
            "a/b/c/a/b.c:1",
        ):
            with self.subTest(citation=good):
                self.assertFalse(self._hits(good))

    def test_the_corpus_carries_none(self):
        import validate_schemas

        errors = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            errors.extend(validate_schemas._doubled_paths(path))
        self.assertEqual(errors, [])


class VerboseAppliesToJson(unittest.TestCase):
    """verify accepted --verbose beside --json in every mode and dropped it:
    the output was byte for byte the same, and the passing entries a script
    asked for never came."""

    def _run(self, *args: str) -> dict:
        import json
        import subprocess

        completed = subprocess.run(
            [sys.executable, "scripts/verify.py", *args, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=900, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        return json.loads(completed.stdout)

    def test_emulator_and_system_modes_list_the_passing_entries(self):
        for mode in (("--emulator", "handy"), ("--system", "atari-lynx")):
            with self.subTest(mode=mode[0]):
                plain = self._run(*mode)
                verbose = self._run(*mode, "--verbose")
                self.assertGreater(len(verbose["details"]), len(plain["details"]))
                self.assertIn("ok", {d["status"] for d in verbose["details"]})

    def test_every_json_branch_reads_the_flag(self):
        source = (ROOT / "scripts" / "verify.py").read_text()
        self.assertEqual(source.count("_json_details("), 4)
        self.assertNotIn('if d["status"] != Status.OK\n            ]', source)


class OnePlatformPerFlag(unittest.TestCase):
    """generate_pack validated --platform as a comma list, then used the whole
    string as one name: `--platform bizhawk,misterfpga` passed and ended in a
    FileNotFoundError traceback. Every script now says it takes one name."""

    def test_a_list_is_refused_with_a_message(self):
        import subprocess

        runs = {
            "generate_pack.py": ["--list-systems"],
            "verify.py": [],
            "cross_reference.py": [],
        }
        for script, extra in runs.items():
            with self.subTest(script=script):
                completed = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform",
                     "bizhawk,misterfpga", *extra],
                    capture_output=True, text=True, cwd=ROOT, timeout=600, check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("takes one platform", completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)

    def test_unknown_names_still_get_a_suggestion(self):
        from common import require_platform

        with self.assertRaises(SystemExit) as caught:
            require_platform("batocra", str(ROOT / "platforms"))
        self.assertIn("batocera", str(caught.exception))


class APackIsSwappedInWhole(unittest.TestCase):
    """Packs were opened on their final name: a rebuild truncated the good
    pack at once, and a build that raised half way left a readable ZIP of
    part of the files, which the run then verified and summed."""

    def _dir(self) -> Path:
        import shutil
        import tempfile

        (ROOT / "tmp").mkdir(exist_ok=True)
        directory = Path(tempfile.mkdtemp(dir=ROOT / "tmp"))
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def test_a_failed_build_keeps_the_previous_pack(self):
        import zipfile

        from generate_pack import _writing_pack

        directory = self._dir()
        pack = directory / "Pack.zip"
        with zipfile.ZipFile(pack, "w") as zf:
            zf.writestr("old.bin", b"complete")
        with self.assertRaises(OSError):
            with _writing_pack(str(pack)) as zf:
                zf.writestr("new.bin", b"half")
                raise OSError("disk full")
        with zipfile.ZipFile(pack) as zf:
            self.assertEqual(zf.namelist(), ["old.bin"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["Pack.zip"])

    def test_a_finished_build_replaces_it(self):
        import zipfile

        from generate_pack import _writing_pack

        directory = self._dir()
        pack = directory / "Pack.zip"
        pack.write_bytes(b"stale")
        with _writing_pack(str(pack)) as zf:
            zf.writestr("new.bin", b"whole")
        with zipfile.ZipFile(pack) as zf:
            self.assertEqual(zf.namelist(), ["new.bin"])
        self.assertEqual(sorted(p.name for p in directory.iterdir()), ["Pack.zip"])

    def test_no_pack_is_opened_on_its_final_name(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text()
        self.assertNotIn('ZipFile(zip_path, "w"', source)


class EverySharedGroupServesAPlatform(unittest.TestCase):
    """Six of the eight shared groups injected nothing: fuse, mt32 and
    jiffydos were included by no platform, and kronos, keropi and ep128emu
    repeated System.dat entry for entry. load_platform_config keeps the
    platform's own entry, so a hash corrected there changed no pack, no
    verify and no manifest, and nothing said so."""

    def test_each_group_contributes_an_entry_somewhere(self):
        from common import list_registered_platforms, load_platform_config

        platforms_dir = str(ROOT / "platforms")
        with (ROOT / "platforms" / "_shared.yml").open(encoding="utf-8") as handle:
            groups = set((yaml.safe_load(handle) or {}).get("shared_groups") or {})
        served = {
            entry.get("shared_group")
            for name in list_registered_platforms(platforms_dir)
            for system in load_platform_config(name, platforms_dir).get("systems", {}).values()
            for entry in system.get("files", [])
        }
        self.assertEqual(sorted(groups - served), [])


class PatchesTargetWhatRuns(unittest.TestCase):
    """mock.patch.object with create set to True builds an attribute on a
    module when the name is missing: packextras imported resolve_platform_cores
    inside the function, the patch created a global nobody read, and the
    real function walked the repository while the test claimed to isolate
    it."""

    def test_no_test_creates_the_attribute_it_patches(self):
        needle = "create" + "=True"
        offenders = []
        for path in sorted((ROOT / "tests").glob("test_*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if needle in code:
                    offenders.append(f"{path.name}:{number}")
        self.assertEqual(offenders, [])


class StandaloneCopiesNameTheirSource(unittest.TestCase):
    """The registry's anchor names one path per file for every platform,
    while each manifest places the file its own way, and the installer copied
    nothing where the two differed (EmuDeck's aes_keys.txt, Batocera's
    switch/prod.keys)."""

    def _placed(self, copies, dests):
        from generate_pack import _placed_copies

        return _placed_copies(copies, dests)

    def test_a_path_tail_finds_the_file(self):
        (copy,) = self._placed(
            [{"file": "GC/USA/IPL.bin"}],
            ["dolphin-emu/Sys/GC/USA/IPL.bin", "dolphin-emu/Sys/GC/EUR/IPL.bin"],
        )
        self.assertEqual(copy["source"], "dolphin-emu/Sys/GC/USA/IPL.bin")

    def test_the_tail_with_least_on_top_wins(self):
        (copy,) = self._placed(
            [{"file": "GC/USA/IPL.bin"}],
            ["bios/GC/USA/IPL.bin", "bios/dolphin-emu/Sys/GC/USA/IPL.bin"],
        )
        self.assertEqual(copy["source"], "bios/GC/USA/IPL.bin")

    def test_a_unique_name_finds_the_file_elsewhere(self):
        (copy,) = self._placed(
            [{"file": "Citra/sysdata/aes_keys.txt"}], ["aes_keys.txt", "bios.bin"]
        )
        self.assertEqual(copy["source"], "aes_keys.txt")

    def test_an_ambiguous_or_present_file_is_left_as_written(self):
        copies = [{"file": "prod.keys"}, {"file": "IPL.bin"}]
        placed = self._placed(copies, ["prod.keys", "a/IPL.bin", "b/IPL.bin"])
        self.assertEqual(placed, copies)


class StandaloneCopiesComeFromTheProfiles(unittest.TestCase):
    """The copies were a hand-kept list of eight emulators while 61 profiles
    give their data_root with the code that builds it: a machine with only
    standalone Cemu got none of its keys."""

    CEMU = {
        "data_root": {
            "linux": {"path": "$XDG_DATA_HOME/Cemu, else ~/.local/share/Cemu",
                      "source_ref": "x"},
            "windows": {"path": "%APPDATA%/Cemu", "source_ref": "x"},
            "macos": {"path": "~/Library/Application Support/Cemu", "source_ref": "x"},
        },
        "files": [
            {"name": "keys.txt", "path": "Cemu/keys.txt", "standalone_path": "keys.txt"},
            {"name": "CafeCn.ttf", "path": "Cemu/mlc01/CafeCn.ttf",
             "standalone_path": "mlc01/sys/CafeCn.ttf"},
            {"name": "gone.bin", "path": "Cemu/gone.bin", "standalone_path": "gone.bin"},
            {"name": "core.bin", "path": "Cemu/core.bin", "standalone_path": "core.bin",
             "mode": "libretro"},
        ],
    }

    def _copies(self, profiles, dests, declared=()):
        from generate_pack import _profile_copies

        return _profile_copies(profiles, dests, list(declared))

    def test_each_file_goes_under_the_data_root(self):
        copies = self._copies({"cemu": self.CEMU},
                              ["Cemu/keys.txt", "Cemu/mlc01/CafeCn.ttf", "Cemu/core.bin"])
        self.assertEqual(copies, [
            {"file": "Cemu/keys.txt", "targets": {
                "linux": ["$HOME/.local/share/Cemu"], "windows": ["%APPDATA%\\Cemu"],
                "darwin": ["$HOME/Library/Application Support/Cemu"]}},
            {"file": "Cemu/mlc01/CafeCn.ttf", "targets": {
                "linux": ["$HOME/.local/share/Cemu/mlc01/sys"],
                "windows": ["%APPDATA%\\Cemu\\mlc01\\sys"],
                "darwin": ["$HOME/Library/Application Support/Cemu/mlc01/sys"]}},
        ])

    def test_a_place_no_run_can_name_is_left_out(self):
        melonds = {
            "data_root": {
                "windows": {"path": "<folder of melonDS.exe>", "source_ref": "x"},
                "linux": {"path": "$XDG_CONFIG_HOME/melonDS, else ~/.config/melonDS",
                          "source_ref": "x"},
            },
            "files": [{"name": "dsi_sd_card.bin", "standalone_path": "dsisd.bin"}],
        }
        (copy,) = self._copies({"melonds": melonds}, ["dsi_sd_card.bin"])
        self.assertEqual(copy, {"file": "dsi_sd_card.bin",
                                "targets": {"linux": ["$HOME/.config/melonDS"]},
                                "as": "dsisd.bin"})

    def test_the_registry_keeps_what_it_already_names(self):
        declared = [{"pattern": "k*.txt", "targets": {"linux": ["$HOME/.local/share/Cemu"]}}]
        (copy, _font) = self._copies({"cemu": self.CEMU},
                                     ["Cemu/keys.txt", "Cemu/mlc01/CafeCn.ttf"], declared)
        self.assertNotIn("linux", copy["targets"])
        self.assertIn("windows", copy["targets"])

    def test_a_file_found_by_content_is_left_to_the_scan(self):
        amiberry = {
            "data_root": {"linux": {"path": "~/Amiberry", "source_ref": "x"}},
            "files": [{"name": "cd32fmv.rom", "path": "roms/cd32fmv.rom",
                       "standalone_path": "cd32fmv.rom", "found_by": "content"}],
        }
        self.assertEqual(self._copies({"amiberry": amiberry}, ["roms/cd32fmv.rom"]), [])

    def test_the_published_retroarch_list_reaches_cemu(self):
        import json

        manifest = json.loads((ROOT / "install" / "retroarch.json").read_text())
        files = {copy["file"]: copy for copy in manifest["standalone_copies"]
                 if "file" in copy}
        for name in ("Cemu/keys.txt", "Cemu/otp.bin", "Cemu/seeprom.bin"):
            with self.subTest(name=name):
                self.assertEqual(files[name]["targets"]["linux"], ["$HOME/.local/share/Cemu"])


class ADamagedArchiveIsNotPacked(unittest.TestCase):
    """A member whose bytes fail their CRC stops the build. The builder once
    copied the damaged archive into the pack "for verify to flag", which
    nothing did."""

    def test_the_rebuild_refusal_reaches_the_run(self):
        import zipfile

        from generate_pack import DamagedArchiveError, _add_zip_to_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            source = Path(directory) / "set.zip"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr("rom.bin", b"A" * 64)
            data = bytearray(source.read_bytes())
            data[data.index(b"A" * 64)] ^= 0xFF
            source.write_bytes(bytes(data))
            pack = Path(directory) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as target:
                with self.assertRaises(DamagedArchiveError) as caught:
                    _add_zip_to_pack(str(source), "set.zip", target)
                self.assertNotIn("set.zip", target.namelist())
            self.assertIsInstance(caught.exception, OSError)
            self.assertIn("set.zip", str(caught.exception))


class APackedArchiveKeepsItsBytes(unittest.TestCase):
    """Packs rebuilt about 1,500 ZIPs in a fixed byte order while the install
    list kept the collection's hash: an extracted pack failed --check on each."""

    def test_the_member_is_the_source_byte_for_byte(self):
        import hashlib
        import zipfile

        from generate_pack import _add_zip_to_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            source = Path(directory) / "set.zip"
            with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(zipfile.ZipInfo("rom.bin", (1999, 1, 2, 3, 4, 5)), b"rom" * 40)
            pack = Path(directory) / "pack.zip"
            with zipfile.ZipFile(pack, "w") as target:
                _add_zip_to_pack(str(source), "set.zip", target)
            with zipfile.ZipFile(pack) as packed:
                inner = packed.read("set.zip")
            self.assertEqual(hashlib.sha1(inner).hexdigest(),
                             hashlib.sha1(source.read_bytes()).hexdigest())


class PackReadmesSayWhatTheInstallerDoes(unittest.TestCase):
    """The EmuDeck README promised keys set up automatically (they need
    --standalone-copies) and gave a Citra path the installer never uses, and the
    RetroArch README offered only `| sh`, which Windows cannot run."""

    def _guide(self, platform: str) -> str:
        from packreadme import _build_readme

        registry = yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text())
        install = registry["platforms"][platform].get("install") or {}
        text = _build_readme(platform, platform, "", 1, 1,
                             detect=install.get("detect", []),
                             standalone_copies=install.get("standalone_copies", []))
        return text[text.index("INSTALLATION"):text.index("TROUBLESHOOTING")]

    def test_retroarch_offers_the_windows_installer(self):
        from siteguides import INSTALL_PS1, INSTALL_SH

        guide = self._guide("retroarch")
        self.assertIn(f"{INSTALL_SH} | sh", guide)
        self.assertIn(f"{INSTALL_PS1} | iex", guide)

    def test_emudeck_keys_match_the_registry_and_the_flag(self):
        import re

        guide = self._guide("emudeck")
        self.assertIn("--standalone-copies", guide)
        self.assertNotIn("emulator keys automatically", guide)
        self.assertNotIn("handles this for you", guide)
        with (ROOT / "platforms" / "_registry.yml").open(encoding="utf-8") as handle:
            registry = yaml.safe_load(handle)
        targets = {
            target.rstrip("/").replace("$HOME", "~")
            for copy in registry["_standalone_copies"]
            for target in copy.get("targets", {}).get("linux", [])
        }
        named = {
            path.rstrip("/") for path in re.findall(r"-> (~/\S+)", guide)
        }
        self.assertEqual(sorted(named - targets), [])

    def test_retropie_never_sends_a_pc_to_the_linux_partition(self):
        guide = self._guide("retropie")
        from siteguides import INSTALL_SH

        self.assertNotIn("Put the SD card in your PC", guide)
        self.assertIn(f"{INSTALL_SH} | sh", guide)


class AutoFetchReadsListsAndPlacesWithoutClobbering(unittest.TestCase):
    """A profile hash list (daedalusx64's n64.psh) stopped auto_fetch with
    an unhashable-type error, and a fetched file went to the first folder
    sharing one word of the system slug (nintendo-64 into Nintendo/SNES),
    overwriting a same-named file there."""

    def test_a_hash_list_is_every_accepted_revision(self):
        import hashlib

        from scripts import auto_fetch

        data = b"second revision"
        entry = {"sha1": ["0" * 40, hashlib.sha1(data).hexdigest()]}
        self.assertTrue(auto_fetch.verify_content(data, entry))
        db = {"files": {hashlib.sha1(data).hexdigest(): {"path": "bios/x/n64.psh"}},
              "indexes": {"by_md5": {}}}
        self.assertEqual(auto_fetch.step1_crossref_db(entry, db), "bios/x/n64.psh")

    def test_the_whole_slug_picks_the_folder_and_nothing_is_overwritten(self):
        from scripts import auto_fetch

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            bios = Path(directory)
            for folder in ("Nintendo/SNES", "Nintendo/N64", "Nintendo/Nintendo 64DD"):
                (bios / folder).mkdir(parents=True)
            held = bios / "Nintendo" / "N64" / "n64.psh"
            held.write_bytes(b"other revision")
            placed = Path(auto_fetch.place_file(
                b"fetched", {"name": "n64.psh", "system": "nintendo-64"}, str(bios), {}
            ))
            self.assertEqual(placed.parent.parent, bios / "Nintendo" / "N64")
            self.assertEqual(placed.parent.name, ".variants")
            self.assertEqual(held.read_bytes(), b"other revision")


class NoParserAcceptsAnAbbreviation(unittest.TestCase):
    """argparse completes a prefix: `slots.py --emulator dolphin` became
    --emulators-dir dolphin and reported 0 contested destinations, exit 0, and
    `pipeline.py --all` became --all-variants and built six packs per
    platform. The flags read like other scripts' and were never refused."""

    def test_every_parser_refuses_prefixes(self):
        import ast

        lax = []
        for path in sorted([*(ROOT / "scripts").rglob("*.py"), ROOT / "install.py"]):
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
                    lax.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(lax, [])


class FaqRegressions(unittest.TestCase):
    """The FAQ states facts the code owns, and these tie it back to the source.

    Three of its claims had drifted: a pinned MAME version, Adler-32
    attributed to Dolphin's IPL instead of its DSP ROMs, and a verbose
    per-emulator report described as the only way to catch a bad file on an
    existence platform. Readers act on all three.
    """

    @staticmethod
    def _faq() -> str:
        # The questions about hashes and checks moved to the technical FAQ.
        return "\n\n".join(
            (ROOT / "wiki" / name).read_text(encoding="utf-8")
            for name in ("faq.md", "technical-faq.md")
        )

    @staticmethod
    def _profile(key: str) -> dict:
        with (ROOT / "emulators" / f"{key}.yml").open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_the_romset_table_is_written_from_the_profiles(self):
        # Typed by hand, the table and the prose under it kept MAME 0.160
        # and FinalBurn Neo 1.0.0.2, versions no source at the pins states,
        # and the test holding them to the profiles kept the errors in step.
        sys.path.insert(0, str(ROOT / "scripts"))
        import generate_site  # noqa: PLC0415
        from common import load_emulator_profiles  # noqa: PLC0415

        profiles = load_emulator_profiles(str(ROOT / "emulators"), skip_aliases=False)
        page = (ROOT / "wiki" / "technical-faq.md").read_text(encoding="utf-8")
        self.assertEqual(
            page, generate_site.with_romset_table(page, profiles),
            "wiki/technical-faq.md romset table is stale: run scripts/generate_site.py",
        )
        prose = page.split("### How this is known", 1)[1].split("\n## ", 1)[0]
        self.assertIsNone(re.search(r"\(0\.\d", prose),
                          "the prose under the table types a version again")

    def test_adler32_is_attributed_to_the_files_that_carry_it(self):
        dolphin = self._profile("dolphin")
        carriers = {
            f["name"] for f in dolphin["files"] if f.get("known_hash_adler32")
        }
        self.assertTrue(carriers, "dolphin.yml declares no Adler-32 hash")
        sentence = self._faq().split("Adler-32", 1)[1].split("\n\n", 1)[0]
        for name in carriers:
            self.assertIn(name, sentence, f"FAQ omits the Adler-32 file {name}")
        self.assertNotIn(
            "IPL.bin", carriers,
            "IPL.bin gained an Adler-32 hash, but the docs say it has none",
        )
        for page in ("faq.md", "profiling.md"):
            text = (ROOT / "wiki" / page).read_text(encoding="utf-8")
            for line in text.splitlines():
                if "Adler-32" in line or "adler32" in line:
                    self.assertNotIn(
                        "IPL", line,
                        f"wiki/{page} ties Adler-32 back to IPL: {line.strip()}",
                    )

    def test_existence_platforms_are_not_told_the_verbose_report_is_the_only_check(self):
        self.assertIn(
            "DISCREPANCY",
            self._faq(),
            "the FAQ must name the check the platform report performs itself",
        )
        self.assertIn(
            'result["discrepancy"]',
            (ROOT / "scripts" / "verify.py").read_text(encoding="utf-8"),
            "verify.py no longer raises the discrepancy the FAQ advertises",
        )


class CatalogRatioRegressions(unittest.TestCase):
    """The catalog-matched count must read the same on every surface.

    The home page, the provenance page, the README and the stats export each
    used to count matches on their own. Two of them dropped the systems
    scope, so the site published 566 and 553 for the same quantity, one click
    apart, and the export paired the wider number with composition.systems as
    its denominator.
    """

    _SURFACES = ("scripts/generate_site.py", "scripts/generate_readme.py")

    def test_no_surface_counts_matches_on_its_own(self):
        for relative in self._SURFACES:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            inline = [
                node.lineno
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "sum"
                and "provenance" in ast.dump(node)
            ]
            self.assertEqual(
                inline,
                [],
                f"{relative} counts provenance matches inline at {inline}; "
                "call common.count_catalog_matched instead",
            )

    def test_arcade_and_engine_data_stay_out_of_the_ratio(self):
        from scripts.common import compute_composition, count_catalog_matched

        db = {
            "files": {
                "a": {"path": "bios/Sony/PlayStation/scph5501.bin", "size": 1,
                      "provenance": {"redump": {}}},
                "b": {"path": "bios/Arcade/Arcade/neogeo.zip", "size": 1,
                      "provenance": {"no-intro": {}}},
                "c": {"path": "bios/ScummVM/soundfonts/Roland.sf2", "size": 1,
                      "provenance": {"tosec": {}}},
                "d": {"path": "bios/Sega/Saturn/sega_101.bin", "size": 1},
            }
        }
        self.assertEqual(count_catalog_matched(db), 1)
        self.assertEqual(compute_composition(db)["systems"]["files"], 2)

    def test_engine_and_publisher_trees_are_game_data(self):
        """Engine data collected under `Game Engines/` and under a game
        publisher counted as console and computer system files: 7 697 of
        them made the README announce 13 564 system files."""
        from scripts.common import composition_tier

        for path in (
            "bios/Game Engines/C-Dogs SDL/cdogs/data/guns.json",
            "bios/Id Software/Quake III Arena/baseq3/pak1.pk3",
            "bios/Epic MegaGames/Jazz Jackrabbit 2/jazz2/Source/share.j2e",
            "bios/RPG Maker/easyrpg/rtp/2000/Backdrop/Bridge.png",
        ):
            self.assertEqual(composition_tier(path), "game_data", path)
        self.assertEqual(composition_tier("bios/Sony/PlayStation/scph5501.bin"), "systems")
        self.assertEqual(composition_tier("bios/Microsoft/MSX/MSX2.ROM"), "systems")

    def test_readme_ratio_matches_the_database(self):
        from scripts.common import compute_composition, count_catalog_matched, load_database

        database = ROOT / "database.json"
        if not database.exists():
            self.skipTest("database.json not generated")
        db = load_database(str(database))
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(
            r"\*\*([\d,]+) of ([\d,]+) system files\*\* matched to", readme
        )
        if match is None:
            # The README states no ratio since it leads to the site: a ratio
            # it states must still be the database's.
            return
        matched, total = (int(g.replace(",", "")) for g in match.groups())
        self.assertEqual(matched, count_catalog_matched(db))
        self.assertEqual(total, compute_composition(db)["systems"]["files"])


class PipelineRegressions(unittest.TestCase):
    def test_integrity_checks_the_variants_step_4_built(self):
        """Step 6 ran --verify-packs without --all-variants: the five
        narrowed packs were never opened and an empty _Platform passed."""
        import argparse  # noqa: PLC0415

        def command(**flags) -> list[str]:
            base = {"output_dir": "dist", "target": None, "all_variants": False}
            return pipeline.integrity_command(argparse.Namespace(**{**base, **flags}))

        self.assertIn("--all-variants", command(all_variants=True))
        self.assertNotIn("--all-variants", command())
        self.assertEqual(command(target="switch")[-2:], ["--target", "switch"])

    def test_pack_parser_removes_source_metadata(self):
        output = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  3 files packed (2 baseline + 1 from cores), 2/2 files OK",
            ]
        )
        self.assertEqual(pipeline.parse_pack_counts(output), {"RetroArch": (2, 2)})

    def test_missing_pack_is_a_consistency_failure(self):
        verify = "RetroArch: 2/2 OK"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, ""))

    def test_display_name_matches_compact_registry_id(self):
        verify = "MiSTer FPGA: 65/65 OK [md5]"
        pack = "\n".join(
            [
                "Generating pack for misterfpga [source=full]...",
                "  pack.zip: 65 files packed (65 baseline + 0 from cores), "
                "65/65 files OK [md5]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(pipeline.check_consistency(verify, pack))

    def test_the_cores_share_is_compared_too(self):
        """RomM passed this step while verify counted 412 core files and game
        data in the pack and the builder placed 60."""
        verify = "\n".join([
            "RomM: 383/383 OK [md5]",
            "  Core files: 61 in pack, 0 required missing, 1 optional missing",
            "  Game data: 351 in pack, 0 missing",
        ])
        pack = "\n".join([
            "Generating pack for RomM [source=full]...",
            "  pack.zip: 443 files packed (383 baseline + 60 from cores), "
            "383/383 files OK [md5]",
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))
            agreed = verify.replace("61 in pack", "60 in pack").replace("351 in pack", "0 in pack")
            self.assertTrue(pipeline.check_consistency(agreed, pack))

    def test_an_exclusion_never_covers_a_file_verify_counts_ok(self):
        """An existence platform packs a file whose hash disagrees and a hash
        platform's verify reports it untested: exclusions that make up the
        difference hid the very divergence this step exists to catch."""
        verify = "RetroArch: 3/3 present [existence]"
        pack = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  pack.zip: 2 files packed (2 baseline + 0 from cores), "
                "2/3 files OK, 1 unsafe excluded [existence]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))
        self.assertEqual(pipeline.parse_pack_exclusions(pack), {"RetroArch": 1})

    def test_unaccounted_pack_omission_is_a_consistency_failure(self):
        verify = "RetroArch: 3/3 present [existence]"
        pack = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  pack.zip: 1 files packed (1 baseline + 0 from cores), "
                "1/3 files OK, 1 unsafe excluded, 1 missing [existence]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))

    def test_a_pack_more_optimistic_than_verify_is_a_failure(self):
        """The invariant held one way only: a pack counting more OK files
        than the report passed as 'pack resolves more'."""
        verify = "DupTest: 0/1 OK, 1 untested [md5]"
        pack = "\n".join(
            [
                "Generating pack for DupTest [source=full]...",
                "  x/DupTest_1_BIOS_Pack.zip: 1 files packed (1 baseline + 0 from cores), "
                "1/1 files OK [md5]",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))

    def test_nothing_parsed_is_not_consistent(self):
        """A changed output format must not pass with no platform compared."""
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency("RetroArch = 2/2 OK", ""))
            self.assertFalse(pipeline.check_consistency("", ""))

    def test_pack_without_verify_result_is_a_failure(self):
        verify = "RetroArch: 2/2 OK"
        pack = "\n".join(
            [
                "Generating pack for RetroArch [source=full]...",
                "  a.zip: 2 files packed (2 baseline + 0 from cores), 2/2 files OK",
                "Generating pack for Batocera [source=full]...",
                "  b.zip: 2 files packed (2 baseline + 0 from cores), 2/2 files OK",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(pipeline.check_consistency(verify, pack))

    def test_only_the_full_variant_feeds_the_comparison(self):
        """--all-variants printed six packs under one label, and the last won."""
        output = "\n".join([
            "Generating pack for RetroArch [source=full]...",
            "  a.zip: 5 files packed (5 baseline + 0 from cores), 535/535 files OK",
            "Generating pack for RetroArch [source=platform, required]...",
            "  b.zip: 5 files packed (5 baseline + 0 from cores), 530/530 files OK",
        ])
        self.assertEqual(pipeline.parse_pack_counts(output), {"RetroArch": (535, 535)})

    def test_exclusions_read_only_the_full_variant(self):
        """--all-variants printed six packs under one label, and the last won."""
        output = "\n".join([
            "Generating pack for Batocera [source=full]...",
            "  a.zip: 5 files packed (5 baseline + 0 from cores), 5/5 files OK, 3 unsafe excluded",
            "Generating pack for Batocera [source=truth, required]...",
            "  b.zip: 2 files packed (0 baseline + 2 from cores), 2/2 files OK",
        ])
        self.assertEqual(pipeline.parse_pack_exclusions(output), {"Batocera": 3})

    def test_slot_step_reaches_the_summary(self):
        source = Path(pipeline.__file__).read_text(encoding="utf-8")
        self.assertIn('results["slots"] = ok', source)

    def test_every_refresh_failure_reaches_pipeline_exit_status(self):
        for failed_label in (
            "2 refresh data directories",
            "2a refresh MAME hashes",
            "2a2 refresh FBNeo hashes",
        ):
            with self.subTest(failed_label=failed_label):
                def fake_run(_command, label):
                    return label != failed_label, "RetroArch: 1/1 OK\n"

                argv = ["pipeline.py", "--skip-packs", "--skip-docs"]
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(pipeline, "run", side_effect=fake_run),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    pipeline.main()
                self.assertEqual(raised.exception.code, 1)


    def test_a_targeted_export_reads_a_full_model(self):
        """--target wrote truth/<target>/ only, but the export read truth/."""
        commands: list[list[str]] = []

        def fake_run(command, _label):
            commands.append([str(part) for part in command])
            return True, "RetroArch: 1/1 OK\n"

        argv = ["pipeline.py", "--offline", "--skip-packs", "--skip-docs",
                "--with-export", "--target", "switch"]
        # The originals the offline export patches are not cached in a
        # checkout: the run would be refused before any step.
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            pipeline, "run", side_effect=fake_run
        ), mock.patch.object(pipeline, "_refuse_offline_export_without_originals"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(SystemExit):
            pipeline.main()
        truth_runs = [c for c in commands if "scripts/generate_truth.py" in c]
        export = next(c for c in commands if "scripts/export_native.py" in c)
        read_dir = export[export.index("--truth-dir") + 1]
        full_models = [
            c for c in truth_runs
            if "--target" not in c and c[c.index("--output-dir") + 1] == read_dir
        ]
        self.assertTrue(full_models, truth_runs)


class SchemaFormatsAreChecked(unittest.TestCase):
    """date-time and uri need jsonschema's format extras. Without them the
    published format constraints were accepted unread."""

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_a_missing_checker_is_named(self):
        import validate_schemas  # noqa: PLC0415

        empty = mock.Mock(checkers={})
        with mock.patch.object(validate_schemas, "FormatChecker", return_value=empty):
            self.assertEqual(validate_schemas.unchecked_formats(), ["date-time", "uri"])

    def test_every_install_asks_for_the_extras(self):
        for path in (".github/workflows/validate.yml", ".github/workflows/deploy-site.yml",
                     "pyproject.toml"):
            text = (ROOT / path).read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotRegex(text, r"jsonschema(?!\[format)[=>]")


class ResolverRegressions(unittest.TestCase):
    def _database(self, entries: dict[str, Path], suffix: str | None = None) -> dict:
        files = {}
        by_name: dict[str, list[str]] = {}
        by_suffix: dict[str, list[str]] = {}
        for name, path in entries.items():
            payload = path.read_bytes()
            sha1 = hashlib.sha1(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            files[sha1] = {
                "path": str(path),
                "name": name,
                "size": len(payload),
                "md5": md5,
                "sha256": sha256,
                "crc32": "00000000",
            }
            by_name.setdefault(name, []).append(sha1)
            if suffix and name == "firmware.bin":
                by_suffix.setdefault(suffix, []).append(sha1)
        return {
            "files": files,
            "indexes": {
                "by_name": by_name,
                "by_md5": {entry["md5"]: sha1 for sha1, entry in files.items()},
                "by_sha256": {
                    entry["sha256"]: sha1 for sha1, entry in files.items()
                },
                "by_crc32": {},
                "by_path_suffix": by_suffix,
            },
        }

    def test_hash_identity_wins_over_wrong_destination_hint(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            wrong = root / "wrong" / "firmware.bin"
            correct = root / "correct" / "firmware.bin"
            wrong.parent.mkdir()
            correct.parent.mkdir()
            wrong.write_bytes(b"wrong")
            correct.write_bytes(b"correct")
            db = self._database(
                {"firmware.bin": wrong, "correct-name.bin": correct},
                suffix="Console/USA/firmware.bin",
            )
            expected = hashlib.sha1(b"correct").hexdigest()
            path, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": expected},
                db,
                dest_hint="Console/USA/firmware.bin",
            )
            self.assertEqual(path, str(correct))
            self.assertEqual(status, "sha1_exact")

    def test_name_cannot_mask_a_declared_hash_mismatch(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(b"wrong")
            db = self._database({"firmware.bin": path})
            resolved, status = resolve_local_file(
                {"name": "firmware.bin", "sha1": "f" * 40}, db
            )
            self.assertEqual(resolved, str(path))
            self.assertEqual(status, "hash_mismatch")


class OneBaselineVerdict(unittest.TestCase):
    """The builder and the manifest each wrote the platform baseline.

    The builder looked inside a zipped_file archive whatever the outer
    resolution said, the manifest only after a hash_mismatch. An archive
    found by name without the member Batocera checks left the pack and
    stayed in the manifest. A slot override replaced a release asset in the
    manifest and not in the pack.
    """

    def _archive(self, directory: Path, member: str) -> str:
        path = directory / "dragon32.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, b"rom")
        return str(path)

    def test_a_missing_member_is_refused_whatever_the_outer_status(self):
        from scripts.validation import baseline_verdict

        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom", "md5": ""}
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = self._archive(Path(directory), "other.rom")
            status, refusal = baseline_verdict(entry, path, "name_exact", "md5")
            self.assertEqual(refusal, "d32.rom not found inside ZIP")
            # An existence frontend never opens it.
            self.assertEqual(
                baseline_verdict(entry, path, "name_exact", "existence"),
                ("name_exact", None),
            )

    def test_the_pack_check_reads_the_same_verdict(self):
        """--verify-packs called the archive missing: its own rule looked
        inside only after a hash_mismatch, and an archive found by name
        without d32.rom is one the builder left out on purpose."""
        import hashlib

        from scripts.packverify import _intentional_hash_exclusion

        entry = {"name": "dragon32.zip", "zipped_file": "d32.rom", "md5": ""}
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = self._archive(Path(directory), "other.rom")
            sha1 = hashlib.sha1(Path(path).read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": path, "name": "dragon32.zip", "sha1": sha1}},
                  "indexes": {"by_name": {"dragon32.zip": [sha1]}, "by_md5": {},
                              "by_path_suffix": {}, "by_crc32": {}}}
            self.assertTrue(_intentional_hash_exclusion([entry], db, verification_mode="md5"))
            self.assertFalse(
                _intentional_hash_exclusion([entry], db, verification_mode="existence")
            )

    def test_the_builder_accepts_what_verify_accepts(self):
        """verify took a ZIP by its composite, but the builder compared exact
        md5s and refused it when another declared hash disagreed. A value cut
        short accepts nothing: Batocera compares the whole md5 string
        (batocera-systems:1088), and verify accepted any prefix, down to one
        digit."""
        import hashlib

        from scripts.common import md5_composite
        from scripts.validation import baseline_verdict, digest_verdict

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            loose = Path(directory) / "abc.bin"
            loose.write_bytes(b"abc")
            md5 = hashlib.md5(b"abc").hexdigest()
            truncated = {"name": "abc.bin", "md5": md5[:29], "crc32": "deadbeef"}
            self.assertIsNotNone(
                baseline_verdict(truncated, str(loose), "hash_mismatch", "md5")[1]
            )
            for length in (1, 29, 31):
                self.assertFalse(
                    digest_verdict({"md5": md5[:length]}, 3, lambda: {"md5": md5}, "md5")
                )
            self.assertTrue(digest_verdict({"md5": md5}, 3, lambda: {"md5": md5}, "md5"))
            archive = self._archive(Path(directory), "rom.bin")
            composite = {"name": "dragon32.zip", "md5": md5_composite(archive),
                         "crc32": "deadbeef"}
            self.assertEqual(
                baseline_verdict(composite, archive, "hash_mismatch", "md5"),
                ("frontend_digest_exact", None),
            )

    def test_a_composite_only_archive_ignores_its_raw_md5(self):
        """Recalbox hashes a .zip by its members (Bios.cpp:64-68), and the
        pack check accepted the container's own md5 before the composite:
        neocd.bin shipped as neocdz.zip passed while Recalbox marks it red."""
        import hashlib

        from scripts.common import md5_composite
        from scripts.validation import digest_verdict

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            archive = self._archive(Path(directory), "rom.bin")
            raw = hashlib.md5(Path(archive).read_bytes()).hexdigest()
            members = md5_composite(archive)
            for declared, accepted in ((raw, False), (members, True)):
                entry = {"name": "dragon32.zip", "md5": declared, "zip_digest": "composite"}
                with self.subTest(declared=declared):
                    self.assertIs(
                        digest_verdict(entry, 0, lambda: {"md5": raw}, "md5", "",
                                       lambda: members),
                        accepted,
                    )
            plain = {"name": "dragon32.zip", "md5": raw}
            self.assertTrue(digest_verdict(plain, 0, lambda: {"md5": raw}, "md5"))

    def test_a_release_asset_keeps_its_answer(self):
        from scripts.packresolve import apply_override

        self.assertEqual(
            apply_override("bios/x.bin", "/cache/big.bin", "release_asset"),
            ("/cache/big.bin", "release_asset"),
        )
        self.assertEqual(
            apply_override("bios/x.bin", "bios/y.bin", "name_exact"),
            ("bios/x.bin", "slot_arbitrated"),
        )

    def test_the_builder_and_the_manifest_read_the_same_rules(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for name in ("generate_pack", "generate_manifest"):
            function = next(
                node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            body = ast.get_source_segment(source, function) or ""
            with self.subTest(function=name):
                self.assertIn("baseline_verdict(", body)
                self.assertIn("resolve_declaration(", body)
                self.assertNotIn('"slot_arbitrated"', body)

    def test_verify_and_the_region_pass_resolve_as_the_builder(self):
        """verify called common.resolve_local_file and put the slot override
        first, the region pass passed a destination hint the builder never
        gives: a gitignored file absent from bios/ read as missing in verify
        while the pack shipped its cached release asset."""
        for module, name in (("verify.py", "_resolve_for_platform"),
                             ("packextras.py", "_ships")):
            source = (ROOT / "scripts" / module).read_text(encoding="utf-8")
            function = next(
                node for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name == name
            )
            body = ast.get_source_segment(source, function) or ""
            with self.subTest(function=name):
                self.assertIn("resolve_declaration(", body)
                self.assertNotIn("resolve_local_file(", body)
                self.assertNotIn('"slot_arbitrated"', body)

    def test_verify_finds_the_cached_release_asset(self):
        # verify imports the scripts directory's modules by their bare names.
        import packresolve
        from scripts.verify import _resolve_for_platform

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            cached = Path(directory) / "BIG.PUP"
            cached.write_bytes(b"large firmware")
            sha1 = hashlib.sha1(cached.read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": f"{directory}/absent/BIG.PUP",
                                   "name": "BIG.PUP", "sha1": sha1}},
                  "indexes": {"by_name": {"BIG.PUP": [sha1]}}}
            entry = {"name": "BIG.PUP", "sha1": sha1, "destination": "BIG.PUP"}
            with mock.patch.object(
                packresolve, "fetch_large_file", return_value=str(cached)
            ):
                found = _resolve_for_platform(
                    entry, "sys", db, {}, None, {"BIG.PUP": "bios/other.bin"},
                    "md5", {},
                )
        self.assertEqual(found, (str(cached), "release_asset"))


class PackExclusionRegressions(unittest.TestCase):
    def test_slug_platform_core_requirement_uses_the_generated_destination(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            core_payload = root / "extra.bin"
            core_payload.write_bytes(b"mapped core payload")
            core_sha1 = hashlib.sha1(core_payload.read_bytes()).hexdigest()
            core_md5 = hashlib.md5(core_payload.read_bytes()).hexdigest()
            database = {
                "files": {
                    core_sha1: {
                        "name": "extra.bin",
                        "path": str(core_payload),
                        "md5": core_md5,
                        "size": core_payload.stat().st_size,
                    }
                },
                "indexes": {
                    "by_name": {"extra.bin": [core_sha1]},
                    "by_md5": {core_md5: core_sha1},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }
            config = {
                "platform": "Slug platform",
                "base_destination": "bios",
                "verification_mode": "existence",
                "cores": ["core_a"],
                "systems": {
                    "console-a": {
                        "files": [
                            {
                                "name": "base-a.bin",
                                "destination": "slug-a/base-a.bin",
                            }
                        ]
                    },
                    "console-b": {
                        "files": [
                            {
                                "name": "base-b.bin",
                                "destination": "slug-b/base-b.bin",
                            }
                        ]
                    },
                },
            }
            (platforms / "slug.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            profiles = {
                "core_a": {
                    "emulator": "Core A",
                    "type": "libretro",
                    "systems": ["console-a"],
                    "files": [
                        {
                            "name": "extra.bin",
                            "path": "extra.bin",
                            "sha1": core_sha1,
                        }
                    ],
                }
            }
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("slug-a/base-a.bin", b"baseline a")
                archive.writestr("slug-b/base-b.bin", b"baseline b")
                archive.writestr("slug-a/extra.bin", core_payload.read_bytes())

            result = verify_pack_against_platform(
                str(pack),
                "slug",
                str(platforms),
                db=database,
                emu_profiles=profiles,
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[6:8], (1, 1))

    def _mismatch_fixture(self, root: Path, mode: str) -> tuple[dict, Path]:
        """A platform declaring a hash the only local payload contradicts."""
        platforms = root / "platforms"
        platforms.mkdir()
        payload = root / "firmware.bin"
        payload.write_bytes(b"wrong local variant")
        sha1 = hashlib.sha1(payload.read_bytes()).hexdigest()
        md5 = hashlib.md5(payload.read_bytes()).hexdigest()
        database = {
            "files": {
                sha1: {
                    "name": "firmware.bin",
                    "path": str(payload),
                    "md5": md5,
                    "size": payload.stat().st_size,
                }
            },
            "indexes": {
                "by_name": {"firmware.bin": [sha1]},
                "by_md5": {md5: sha1},
                "by_sha256": {},
                "by_crc32": {},
                "by_path_suffix": {},
            },
        }
        config = {
            "platform": f"Platform {mode}",
            "verification_mode": mode,
            "systems": {
                "console": {
                    "files": [
                        {
                            "name": "firmware.bin",
                            "destination": "firmware.bin",
                            "sha1": "f" * 40,
                        }
                    ]
                }
            },
        }
        (platforms / "plat.yml").write_text(yaml.safe_dump(config), encoding="utf-8")
        return database, platforms

    def test_hash_platform_accounts_for_an_unsafe_exclusion(self):
        """A platform that reads the bytes would reject the local payload."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "md5")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "safe subset")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertTrue(result[0], result[3])
            self.assertEqual(result[3], [])
            self.assertEqual(result[8], 1)

    def test_existence_platform_never_withholds_over_a_declared_hash(self):
        """RetroArch and friends only look for the filename.

        An upstream hash the local dump contradicts must not remove a file the
        frontend would have loaded, so its absence stays a conformance error.
        """
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            database, platforms = self._mismatch_fixture(root, "existence")
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "no firmware")

            result = verify_pack_against_platform(
                str(pack),
                "plat",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in e for e in result[3]), result[3])
            self.assertEqual(result[8], 0)

    def test_unexplained_missing_file_still_fails_conformance(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            platforms = root / "platforms"
            platforms.mkdir()
            config = {
                "platform": "Missing",
                "verification_mode": "existence",
                "systems": {
                    "console": {
                        "files": [
                            {"name": "absent.bin", "destination": "absent.bin"}
                        ]
                    }
                },
            }
            (platforms / "missing.yml").write_text(
                yaml.safe_dump(config), encoding="utf-8"
            )
            pack = root / "pack.zip"
            with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("README.txt", "incomplete")
            database = {
                "files": {},
                "indexes": {
                    "by_name": {},
                    "by_md5": {},
                    "by_sha256": {},
                    "by_crc32": {},
                    "by_path_suffix": {},
                },
            }

            result = verify_pack_against_platform(
                str(pack),
                "missing",
                str(platforms),
                db=database,
                emu_profiles={},
            )
            self.assertFalse(result[0])
            self.assertTrue(any("baseline missing" in error for error in result[3]))


class RegionRegressions(unittest.TestCase):
    def test_tagged_and_untagged_same_path_is_preserved(self):
        profiles = {
            "tagged": {
                "type": "libretro",
                "files": [
                    {"name": "bios.bin", "path": "sys/bios.bin", "region": ["japan"]}
                ],
            },
            "untagged": {
                "type": "libretro",
                "files": [{"name": "bios.bin", "path": "sys/bios.bin"}],
            },
        }
        index = region.build_region_index(profiles)
        self.assertEqual(region.lookup_regions(index, "sys/bios.bin", "bios.bin"), set())
        drops = region.resolve_region_drops(
            {"system": [("sys/bios.bin", "bios.bin")]},
            index,
            ["north-america"],
        )
        self.assertEqual(drops, set())

    def test_world_candidate_beats_unmatched_regional_fallback(self):
        profiles = {
            "core": {
                "type": "libretro",
                "files": [
                    {"name": "ntsc.bin", "region": ["world"]},
                    {"name": "pal.bin", "region": ["europe"]},
                ],
            }
        }
        index = region.build_region_index(profiles)
        groups = {"system": [("ntsc.bin", "ntsc.bin"), ("pal.bin", "pal.bin")]}
        self.assertEqual(
            region.resolve_region_drops(groups, index, ["north-america"]),
            {"pal.bin"},
        )
        self.assertEqual(region.resolve_region_drops(groups, index, ["europe"]), set())

    def test_multi_system_emulator_uses_separate_region_groups(self):
        profile = {"systems": ["odyssey2", "videopac"]}
        north_america = _emulator_region_group(
            "o2em", profile, {"name": "o2rom.bin", "system": "odyssey2"}, "o2rom.bin"
        )
        europe = _emulator_region_group(
            "o2em", profile, {"name": "c52.bin", "system": "videopac"}, "c52.bin"
        )
        self.assertNotEqual(north_america, europe)

    def test_a_systemless_file_groups_alike_in_both_modes(self):
        """geargrafx files pac-n1.bin [japan] and pac-n10.bin [north-america]
        under none of its four systems: emulator mode grouped them and
        dropped pac-n1.bin for --region us, platform mode isolated each and
        kept it."""
        from packextras import extra_region_groups

        profile = {"systems": ["nec-pc-engine", "nec-pc-engine-cd", "nec-supergrafx",
                               "pioneer-laseractive"]}
        names = ["pac-n1.bin", "pac-n10.bin"]
        emulator = [
            _emulator_region_group("geargrafx", profile, {"name": n}, n) for n in names
        ]
        platform = [
            extra_region_groups({
                "source_emulator": "geargrafx", "destination": n,
                "source_systems": profile["systems"],
            })[0]
            for n in names
        ]
        self.assertEqual(emulator, platform)

    def test_region_audit_resolves_the_way_the_pack_does(self):
        """A private resolver read sha1, md5 and a lone name: an entry
        identified by its path (Dolphin's three IPL.bin) was never checked."""
        import hashlib  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            previous = os.getcwd()
            os.chdir(directory)
            self.addCleanup(os.chdir, previous)
            files, shas = {}, {}
            for rel, payload in (("bios/GC/USA/IPL.bin", b"usa"), ("bios/GC/JAP/IPL.bin", b"jap")):
                Path(rel).parent.mkdir(parents=True, exist_ok=True)
                Path(rel).write_bytes(payload)
                sha1 = hashlib.sha1(payload).hexdigest()
                shas[rel] = sha1
                files[sha1] = {"path": rel, "name": "IPL.bin", "size": len(payload), "sha1": sha1,
                               "md5": hashlib.md5(payload).hexdigest(),
                               "sha256": hashlib.sha256(payload).hexdigest(), "crc32": "00000001"}
            from scripts import generate_db  # noqa: PLC0415

            db = {"files": files, "indexes": generate_db.build_indexes(files, {})}
            by_md5 = {e["md5"]: s for s, e in files.items()}
            self.assertEqual(
                region_audit.resolve_sha1({"name": "IPL.bin", "md5": [files[shas["bios/GC/USA/IPL.bin"]]["md5"]]}, db),
                shas["bios/GC/USA/IPL.bin"],
            )
            self.assertEqual(
                region_audit.resolve_sha1({"name": "IPL.bin", "path": "GC/JAP/IPL.bin"}, db),
                shas["bios/GC/JAP/IPL.bin"],
            )
            self.assertTrue(by_md5)


class ArchiveSecurityRegressions(unittest.TestCase):
    def _zip_path(self, directory: Path, name: str = "archive.zip") -> Path:
        return directory / name

    def test_member_count_limit_is_enforced(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("one.bin", b"1")
                handle.writestr("two.bin", b"2")
            with self.assertRaisesRegex(ValueError, "members"):
                safe_extract_zip(str(archive), str(root / "out"), max_members=1)

    def test_member_modes_follow_the_archive_and_the_umask(self):
        """Every member came out 0600, the mode of its temporary file: the
        pico8 and vox launchers the RetroDECK pack keeps 0755 lost their
        execute bit once download.py extracted them."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            program = zipfile.ZipInfo("pico8")
            program.create_system = 3
            program.external_attr = (stat.S_IFREG | 0o755) << 16
            plain = zipfile.ZipInfo("bios.bin")
            plain.create_system = 0
            plain.external_attr = 0x20  # MS-DOS archive bit, no Unix mode
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(program, b"\x7fELF")
                handle.writestr(plain, b"data")
            umask = os.umask(0o022)
            try:
                safe_extract_zip(str(archive), str(root / "out"))
            finally:
                os.umask(umask)
            self.assertEqual((root / "out" / "pico8").stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "out" / "bios.bin").stat().st_mode & 0o777, 0o644)

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            link = zipfile.ZipInfo("link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(link, "target")
            with self.assertRaisesRegex(ValueError, "link or special"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_windows_separator_is_a_path_not_a_rejection(self):
        """Archives written on Windows store a backslash separator.

        download.py feeds third-party archives to this function, so a legal
        Windows path must extract into a subdirectory instead of failing.
        """
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("sub\\rom.bin", b"payload")
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "sub" / "rom.bin").read_bytes(), b"payload")

    def test_windows_separator_cannot_smuggle_traversal(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("..\\escaped.bin", b"payload")
            with self.assertRaisesRegex(ValueError, "traversal"):
                safe_extract_zip(str(archive), str(root / "out"))

    def test_high_ratio_method_is_bounded_by_size_not_ratio(self):
        """bzip2 legitimately exceeds the DEFLATE ceiling."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_BZIP2) as handle:
                handle.writestr("zeros.bin", bytes(4_000_000))
            out = root / "out"
            safe_extract_zip(str(archive), str(out))
            self.assertEqual((out / "zeros.bin").stat().st_size, 4_000_000)

    def test_compression_ratio_limit_is_enforced(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            archive = self._zip_path(root)
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("zeros.bin", bytes(16_384))
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                safe_extract_zip(
                    str(archive), str(root / "out"), max_compression_ratio=2
                )


class NoMd5IsNotNothingChecked(unittest.TestCase):
    """A declared hash that is not an md5 still contradicts.

    verify_entry_md5 returned OK the moment the entry declared no md5, so an
    entry whose sha256 the local file contradicts read as covered while the
    builder was already excluding it. RetroDECK's dsifirmware.bin declares a
    sha256 and no md5.
    """

    def setUp(self):
        import verify

        self.verify = verify

    def _entry(self):
        return {"name": "dsifirmware.bin", "sha256": "b" * 64}

    def test_a_contradicted_sha256_is_not_reported_ok(self):
        result = self.verify.verify_entry_md5(
            self._entry(), "bios/whatever.bin", "hash_mismatch"
        )
        self.assertNotEqual(result["status"], self.verify.Status.OK)
        self.assertIn("contradicted", result.get("reason", ""))

    def test_a_clean_resolution_is_still_ok(self):
        result = self.verify.verify_entry_md5(
            self._entry(), "bios/whatever.bin", "sha256_exact"
        )
        self.assertEqual(result["status"], self.verify.Status.OK)


class InstallerBoundaryRegressions(unittest.TestCase):
    def _manifest(self, dest: str) -> dict:
        return {
            "manifest_version": 2,
            "platform": "retroarch",
            "files": [
                {
                    "dest": dest,
                    "size": 1,
                    "sha1": "a" * 40,
                    "sha256": "b" * 64,
                    "repo_path": "bios/test.bin",
                    "cores": None,
                }
            ],
            "standalone_copies": [],
        }

    def test_manifest_destination_traversal_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(self._manifest("../escape"), "retroarch")

    def test_manifest_repo_source_is_confined_to_bios(self):
        manifest = self._manifest("safe.bin")
        manifest["files"][0]["repo_path"] = "scripts/pipeline.py"
        with self.assertRaisesRegex(ValueError, "outside bios"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_cannot_overlap_a_download(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "safe.bin",
                "name": "safe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "conflicting omitted"):
            install._validate_manifest(manifest, "retroarch")

    def test_omitted_destination_traversal_is_rejected(self):
        manifest = self._manifest("safe.bin")
        manifest["omitted_files"] = [
            {
                "dest": "../unsafe.bin",
                "name": "unsafe.bin",
                "system": "console",
                "required": True,
                "reason": "hash_mismatch",
                "cores": None,
            }
        ]
        manifest["total_omitted"] = 1
        with self.assertRaisesRegex(ValueError, "unsafe"):
            install._validate_manifest(manifest, "retroarch")

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_target_schema_accepts_the_null_the_generator_emits(self):
        """The schema and generate_target_manifests must agree on null.

        A target with no core list is written as null, and a schema that rejects
        it turns a valid manifest into a CI failure.
        """
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (ROOT / "schemas" / "target-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        document = {"windows": None, "switch": ["a5200"]}
        self.assertEqual(list(validator.iter_errors(document)), [])

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_pack_manifests_are_read_from_inside_the_archive(self):
        """generate_pack writes manifest.json into the ZIP, not beside it.

        A filesystem glob over dist/ matches nothing and reports success
        without validating a single document.
        """
        import validate_schemas

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            dist = Path(directory)
            broken = {
                "schema_version": 1,
                "version": 1,
                "generator": "retrobios generate_pack.py",
                "generated": "2026-08-10T00:00:00Z",
                "files": [{"path": "a.bin", "sha1": "nope", "md5": "nope",
                           "size": 1, "status": "verified", "name": "a.bin"}],
                "summary": {"total_files": 1, "verified": 1, "untracked": 0,
                            "errors": 0},
                "errors": [],
            }
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(broken))

            errors = validate_schemas._validate_pack_manifests(dist)
            self.assertTrue(errors, "an invalid in-archive manifest must be reported")
            self.assertTrue(any("sha1" in message for message in errors), errors)

    @unittest.skipUnless(HAS_JSONSCHEMA, "validating a schema needs jsonschema")
    def test_a_pack_carries_its_install_list_and_board_lists(self):
        """pack_systems puts the install list and the per-board core lists
        in the pack's manifest.json, which install.py reads with the pack
        alone. The pack schema refused both keys, and each is checked under
        its own contract."""
        import generate_pack
        import validate_schemas

        install_list = json.loads((ROOT / "install" / "romm.json").read_text(encoding="utf-8"))
        targets = {"browser": None, "rpi4": {"cores": ["mgba"], "images": ["rpi4"]}}
        document = {
            "schema_version": 1, "version": 1,
            "generator": "retrobios generate_pack.py",
            "generated": "2026-08-10T00:00:00Z", "files": [],
            "summary": {"total_files": 0, "verified": 0, "untracked": 0, "errors": 0},
            "errors": [],
        }
        generate_pack.annotate_pack_systems(
            document, generate_pack.pack_systems(install_list, targets))
        self.assertIn("install_list", document)
        self.assertIn("targets", document)
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            dist = Path(directory)
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(document))
            self.assertEqual(validate_schemas._validate_pack_manifests(dist), [])

            broken = {**document, "targets": {"rpi4": [1]},
                      "install_list": {**install_list, "files": "none"}}
            with zipfile.ZipFile(dist / "Pack.zip", "w") as archive:
                archive.writestr("manifest.json", json.dumps(broken))
            errors = validate_schemas._validate_pack_manifests(dist)
            self.assertTrue(any(":targets:" in message for message in errors), errors)
            self.assertTrue(any(":install_list:" in message for message in errors), errors)

    def test_null_core_list_keeps_the_other_targets(self):
        """A target without a core inventory must not void the manifest.

        generate_target_manifests emits null for a target that publishes no
        core list. Rejecting the document would silently disable --target for
        every target on that platform.
        """
        normalized = install._validate_targets({"windows": None, "switch": ["a5200"]})
        self.assertIsNone(normalized["windows"]["cores"])
        self.assertEqual(normalized["switch"]["cores"], ["a5200"])

    def test_legacy_target_lists_are_normalized(self):
        self.assertEqual(
            install._validate_targets({"rpi4": ["core-a", "core-b"]}),
            {"rpi4": {"cores": ["core-a", "core-b"]}},
        )


class TargetManifestRegressions(unittest.TestCase):
    def test_yaml_scalar_core_is_rejected_instead_of_leaking_to_json(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "output"
            source.mkdir()
            (source / "platform.yml").write_text(
                "targets:\n  device:\n    cores: [81, valid-core]\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-empty strings"):
                generate_target_manifests(str(source), str(output))


class CheckoutCompletenessRegressions(unittest.TestCase):
    """Coverage is resolved against the disk, so the checkout must be whole.

    Files over 50 MB and the data directory caches are gitignored. A job that
    regenerates the README or the site without restoring them counts those
    files as missing and publishes a coverage the collection does not have.
    """

    def _steps(self, workflow: str, job: str) -> list[dict]:
        data = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
        return data["jobs"][job]["steps"]

    def _index(self, steps: list[dict], needle: str) -> int:
        for position, step in enumerate(steps):
            if needle in step.get("name", "") or needle in str(step.get("run", "")):
                return position
        self.fail(f"no step matching {needle!r}")

    def test_site_deploy_completes_the_checkout_before_generating(self):
        steps = self._steps("deploy-site.yml", "build")
        generate = self._index(steps, "Generate site")
        self.assertLess(self._index(steps, "restore_large_files.py"), generate)
        self.assertLess(self._index(steps, "refresh_data_dirs.py"), generate)

    def test_restore_matches_assets_by_content_not_by_name(self):
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
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
            cwd = os.getcwd()
            os.chdir(root)
            try:
                restored, unsatisfied = restore(
                    str(cache), "database.json", ".gitignore"
                )
                self.assertEqual((restored, unsatisfied), (1, []))
                self.assertEqual((root / "bios/Sony/big.pup").read_bytes(), payload)
                # A path already in the checkout is never overwritten.
                restored, unsatisfied = restore(
                    str(cache), "database.json", ".gitignore"
                )
                self.assertEqual((restored, unsatisfied), (0, []))
            finally:
                os.chdir(cwd)

    def test_restore_without_its_registry_fails(self):
        """A mistyped --gitignore read as an empty registry: nothing to
        restore, nothing unsatisfied, exit 0 with every asset absent."""
        import subprocess

        from scripts.restore_large_files import gitignored_paths

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            missing = str(Path(directory) / "absent")
            with self.assertRaises(FileNotFoundError):
                gitignored_paths(missing)
            proc = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "restore_large_files.py"),
                 "--gitignore", missing, "--cache", directory],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("lists the release assets", proc.stderr)

    def test_restore_refuses_a_copy_replaced_after_the_index(self):
        """The cache is hashed first and copied later: another run that
        replaced the cached name in between put its bytes at a path the
        database pins to the old ones."""
        from scripts import restore_large_files

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
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
            real_index = restore_large_files.index_cache

            def index_then_replace(cache_dir: str) -> dict[str, str]:
                index = real_index(cache_dir)
                (cache / "asset.bin").write_bytes(b"re-uploaded bytes")
                return index

            cwd = os.getcwd()
            os.chdir(root)
            try:
                with mock.patch.object(restore_large_files, "index_cache", index_then_replace):
                    restored, unsatisfied = restore_large_files.restore(
                        str(cache), "database.json", ".gitignore"
                    )
                self.assertEqual((restored, unsatisfied), (0, ["bios/Sony/big.pup"]))
                self.assertFalse((root / "bios/Sony/big.pup").exists())
                self.assertEqual(os.listdir(root / "bios/Sony"), [])
            finally:
                os.chdir(cwd)

    def test_restore_leaves_tracked_paths_alone(self):
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
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
            cwd = os.getcwd()
            os.chdir(root)
            try:
                restored, unsatisfied = restore(
                    str(cache), "database.json", ".gitignore"
                )
                self.assertEqual((restored, unsatisfied), (0, []))
                self.assertFalse((root / "bios/tracked.bin").exists())
            finally:
                os.chdir(cwd)

    def test_restore_without_a_cache_names_what_is_missing(self):
        """A job that skipped `mkdir .cache/large` exited 0 with every
        gitignored file absent: the early return ran before the check."""
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            (root / ".gitignore").write_text("bios/big.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {"a" * 40: {"path": "bios/big.bin"}}}),
                encoding="utf-8",
            )
            cwd = os.getcwd()
            os.chdir(root)
            try:
                self.assertEqual(
                    restore("no-cache", "database.json", ".gitignore"),
                    (0, ["bios/big.bin"]),
                )
            finally:
                os.chdir(cwd)


def _git_paths(*args: str, stdin: list[str] | None = None) -> set[str] | None:
    """The NUL-separated paths a git command prints, or None outside a
    checkout. check-ignore exits 1 when it matches nothing, an answer."""
    try:
        result = subprocess.run(
            ["git", *args],
            input="".join(f"{p}\0" for p in stdin or []),
            capture_output=True, text=True, cwd=ROOT, check=False,
        )
    except FileNotFoundError:
        return None
    answered = (0, 1) if args[0] == "check-ignore" else (0,)
    if result.returncode not in answered:
        return None
    return {p for p in result.stdout.split("\0") if p}


class ManifestVersionIsThePlatformsOwn(unittest.TestCase):
    """Every install manifest named its list "1.0", and an inheriting YAML
    took its parent's version: Lakka was published as RetroArch v1.22.2.
    The installer compares the list's version with the one a machine runs,
    so each manifest states the version its own platform YAML records."""

    def setUp(self):
        from scripts.common import _platform_config_cache
        _platform_config_cache.clear()

    def test_committed_manifests_state_their_platform_version(self):
        from scripts.common import load_platform_config
        manifests = sorted((ROOT / "install").glob("*.json"))
        self.assertTrue(manifests)
        for path in manifests:
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                config = load_platform_config(data["platform"], str(ROOT / "platforms"))
                self.assertTrue(config.get("version"))
                self.assertEqual(data["version"], str(config["version"]))

    def test_no_child_shows_its_parents_version(self):
        from scripts.common import load_platform_config
        platforms = ROOT / "platforms"
        children = {}
        for path in sorted(platforms.glob("*.yml")):
            raw = yaml.safe_load(path.read_text()) or {}
            if isinstance(raw, dict) and raw.get("inherits"):
                children[path.stem] = raw
        self.assertIn("lakka", children)
        for name, raw in children.items():
            with self.subTest(platform=name):
                parent = yaml.safe_load(
                    (platforms / f"{raw['inherits']}.yml").read_text())
                version = load_platform_config(name, str(platforms)).get("version")
                self.assertEqual(version, raw.get("version"))
                self.assertNotEqual(version, parent.get("version"))

    def test_an_unversioned_child_has_no_version(self):
        from scripts.common import load_platform_config
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            Path(tmp, "parent.yml").write_text("platform: P\nversion: '2.0'\nsystems: {}\n")
            Path(tmp, "child.yml").write_text("inherits: parent\nplatform: C\n")
            self.assertNotIn("version", load_platform_config("child", tmp))

    def test_lakka_names_the_release_its_cores_are_read_at(self):
        platforms = ROOT / "platforms"
        lakka = yaml.safe_load((platforms / "lakka.yml").read_text())
        targets = yaml.safe_load((platforms / "targets" / "lakka.yml").read_text())
        tag = re.search(r"/blob/([^/]+)/", targets["source"]).group(1)
        self.assertEqual(lakka["version"], tag)


class EveryManifestEntryIsFetchable(unittest.TestCase):
    """An install manifest may not list a file the installer cannot get.

    install.py fetches a file either from its repo_path or from a release
    asset. An entry carrying neither is a line in the download list that can
    only ever fail. It happened when resolution landed on a file the database
    does not index, so the hash was computed but the repo lookup came back
    empty and the entry shipped anyway.
    """

    def test_committed_manifests_all_have_a_source(self):
        manifests = sorted((ROOT / "install").glob("*.json"))
        self.assertTrue(manifests, "no install manifests to check")
        for path in manifests:
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                orphans = [
                    entry["dest"]
                    for entry in data.get("files", []) + data.get("case_variants", [])
                    if not entry.get("repo_path") and not entry.get("release_asset")
                ]
                self.assertEqual(
                    orphans, [], f"{path.name} lists unfetchable files: {orphans[:3]}"
                )

    def test_an_unresolvable_file_is_recorded_as_omitted(self):
        """The reason must be one install.py knows how to report."""
        for path in sorted((ROOT / "install").glob("*.json")):
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                for entry in data.get("omitted_files", []):
                    self.assertIn(entry.get("reason"), install.OMISSION_REASONS)

    def test_the_installer_accepts_every_published_manifest(self):
        """A reason the schema allowed and the installer did not made the
        installer refuse the whole RomM manifest: no RomM install ran."""
        for path in sorted((ROOT / "install").glob("*.json")):
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text())
                install._validate_manifest(data, data["platform"])

    def test_every_standalone_layout_goes_with_its_list(self):
        """install/standalone/<platform>.json, which only --standalone
        reads: the installer accepts it against its own list, each item
        written whole has a source, and a list naming builds has its file."""
        listed = {path.stem: json.loads(path.read_text())
                  for path in sorted((ROOT / "install").glob("*.json"))}
        layouts = sorted((ROOT / "install" / "standalone").glob("*.json"))
        self.assertEqual({path.stem for path in layouts},
                         {plat for plat, data in listed.items()
                          if data.get("standalone_builds")})
        for path in layouts:
            with self.subTest(layout=path.name):
                data = json.loads(path.read_text())
                kept = install._check_standalone_layouts(data, listed[path.stem], path.stem)
                orphans = [item["dest"] for items in kept.values() for item in items
                           if isinstance(item, dict)
                           and not item.get("repo_path") and not item.get("release_asset")]
                self.assertEqual(orphans, [])

    def test_schema_and_installer_name_the_same_reasons(self):
        schema = json.loads(
            (ROOT / "schemas" / "install-manifest.schema.json").read_text()
        )
        reasons = schema["properties"]["omitted_files"]["items"]["properties"][
            "reason"
        ]["enum"]
        self.assertEqual(set(reasons), set(install.OMISSION_REASONS))

    def _manifests(self) -> list[Path]:
        paths = sorted((ROOT / "install").glob("*.json"))
        paths += sorted((ROOT / "install" / "targets").glob("*.json"))
        self.assertTrue(paths, "no install manifests to check")
        return paths

    def test_repo_paths_name_the_file_the_database_holds(self):
        """A manifest written before a file moved sends the installer to 404.

        database.json is regenerated whenever a file is refiled, but the manifests
        are a separate artefact and were left behind once (the two DS
        firmware dumps of the 7 September refile). The installer fetches
        repo_path from raw.githubusercontent.com, so a stale one is a
        download that can never succeed.
        """
        database = ROOT / "database.json"
        if not database.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(database.read_text(encoding="utf-8"))["files"]
        for path in self._manifests():
            with self.subTest(manifest=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                stale = [
                    (entry["dest"], entry["repo_path"], files.get(entry["sha1"], {}).get("path"))
                    for entry in data.get("files", []) + data.get("case_variants", [])
                    if entry.get("repo_path")
                    and files.get(entry.get("sha1", ""), {}).get("path") != entry["repo_path"]
                ]
                self.assertEqual(stale, [], f"{path.name} names moved files: {stale[:3]}")

    def test_release_entries_are_exactly_the_files_git_does_not_hold(self):
        """The installer has two sources, and the manifest must pick the right one.

        A committed file is served by the repository, a gitignored one by
        the large-files release. Marking a committed file as a release asset
        sends the installer to an asset nobody uploaded (sdlpal/5.avi, 83 MB
        in git, was announced as release asset `5.avi`). Marking a gitignored
        file as a repo file sends it to a raw URL that has no content. A
        file neither committed nor ignored is a commit nobody made, and is
        named as such rather than as a release asset.
        """
        tracked = _git_paths("ls-files", "-z", "--", "bios")
        if tracked is None:
            self.skipTest("not a git checkout")
        manifests: dict[str, list[dict]] = {}
        for path in self._manifests():
            data = json.loads(path.read_text(encoding="utf-8"))
            manifests[path.name] = [
                entry
                for entry in data.get("files", []) + data.get("case_variants", [])
                if entry.get("repo_path")
            ]
        outside = sorted(
            {e["repo_path"] for group in manifests.values() for e in group} - tracked
        )
        ignored = _git_paths("check-ignore", "-z", "--no-index", "--stdin", stdin=outside)
        if ignored is None:
            self.skipTest("not a git checkout")
        for name, group in manifests.items():
            with self.subTest(manifest=name):
                wrong = []
                for entry in group:
                    repo_path = entry["repo_path"]
                    state = (
                        "committed" if repo_path in tracked
                        else "gitignored" if repo_path in ignored
                        else "untracked, never committed"
                    )
                    if state == "untracked, never committed" or (
                        bool(entry.get("release_asset")) != (state == "gitignored")
                    ):
                        wrong.append((entry["dest"], repo_path, state))
                self.assertEqual(wrong, [], f"{name} picks the wrong source: {wrong[:3]}")

    def test_no_collected_file_is_left_uncommitted(self):
        """157 files of the 17 September campaign sat in bios/ untracked:
        the database indexed them, the manifests gave them a repo_path and
        the installer got a 404. A file under bios/ is either committed or
        listed in .gitignore as a release asset, nothing in between."""
        untracked = _git_paths("ls-files", "-z", "--others", "--exclude-standard", "--", "bios")
        if untracked is None:
            self.skipTest("not a git checkout")
        self.assertEqual(sorted(untracked)[:20], [], f"{len(untracked)} untracked files under bios/")

    def test_every_database_path_is_committed_or_a_release_asset(self):
        """A git mv under bios/ committed without regenerating anything left
        database.json and the manifests agreeing on the old path: the tests
        above compare them with each other, so all passed, and the installer
        got a 404 (issue 78, with the database stale too)."""
        database = ROOT / "database.json"
        if not database.is_file():
            self.skipTest("database.json not generated")
        files = json.loads(database.read_text(encoding="utf-8"))["files"]
        paths = {
            path
            for entry in files.values()
            for path in [entry.get("path"), *(entry.get("paths") or [])]
            if path
        }
        tracked = _git_paths("ls-files", "-z")
        if tracked is None:
            self.skipTest("not a git checkout")
        outside = sorted(paths - tracked)
        ignored = _git_paths("check-ignore", "-z", "--no-index", "--stdin", stdin=outside)
        if ignored is None:
            self.skipTest("not a git checkout")
        stale = [path for path in outside if path not in ignored]
        self.assertEqual(
            stale[:20], [],
            f"{len(stale)} database paths git neither holds nor ignores: "
            "python scripts/generate_db.py --force --bios-dir bios --output database.json, "
            "then the manifests",
        )


class ReleaseAssetCriterion(unittest.TestCase):
    """What decides whether the installer fetches from the release is git, not size.

    Files over 50 MB are supposed to be gitignored and uploaded to the
    large-files release, but four committed files break that rule and one of
    them reached a manifest as a release asset that does not exist. The
    truthful question is whether the repository serves the bytes, and the
    ledger of what it does not serve is .gitignore.
    """

    def _repo(self, directory: str, ignored: str) -> str:
        Path(directory, ".gitignore").write_text(ignored + "\n", encoding="utf-8")
        return directory

    def test_a_large_committed_file_is_served_by_the_repository(self):
        from scripts import generate_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = self._repo(directory, "bios/elsewhere.bin")
            big = Path(root, "bios", "big.avi")
            big.parent.mkdir()
            with big.open("wb") as handle:
                handle.truncate(60_000_000)
            generate_pack._registered.cache_clear()
            try:
                self.assertFalse(generate_pack._is_release_asset(str(big), root))
            finally:
                generate_pack._registered.cache_clear()

    def test_the_manifest_names_the_asset_as_github_serves_it(self):
        # GitHub publishes a space as a dot. The site linked the dotted
        # name while the manifest gave install.py the spaced one, a 404.
        from scripts import generate_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = self._repo(directory, "bios/MAME/MAME 0.174 Arcade XML.dat")
            target = Path(root, "bios", "MAME", "MAME 0.174 Arcade XML.dat")
            target.parent.mkdir(parents=True)
            target.write_bytes(b"x")
            generate_pack._registered.cache_clear()
            try:
                self.assertEqual(
                    generate_pack._release_asset_name(str(target), root),
                    "MAME.0.174.Arcade.XML.dat",
                )
            finally:
                generate_pack._registered.cache_clear()

    def test_a_gitignored_file_is_served_by_the_release_whatever_its_size(self):
        from scripts import generate_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = self._repo(directory, "bios/small.zip")
            small = Path(root, "bios", "small.zip")
            small.parent.mkdir()
            small.write_bytes(b"PK")
            generate_pack._registered.cache_clear()
            try:
                self.assertTrue(generate_pack._is_release_asset(str(small), root))
            finally:
                generate_pack._registered.cache_clear()


class ReleaseAssetsMatchTheCollection(unittest.TestCase):
    """The bytes the release serves must be the bytes the manifests describe.

    install.py checks Content-Length against the manifest size before it
    downloads, and the manifest size is that of the local copy. Both FBNeo
    sample archives were rebuilt locally after their upload and never
    re-uploaded: same members, different container, every install of them
    failed. The comparison is offline here on a fixture, while the script runs it
    against the live release.
    """

    def test_missing_and_resized_assets_are_reported_and_nothing_else(self):
        from scripts import check_release_assets

        expected = {
            "bios/Other/fbneo/fbneo/samples/twotiger.zip": 154985212,
            "bios/Arcade/MAME/MAME 0.174 Arcade XML.dat": 53677408,
            "bios/Other/sdlpal/sdlpal/5.avi": 82833972,
        }
        assets = {
            "twotiger.zip": 154888877,
            "MAME.0.174.Arcade.XML.dat": 53677408,
            "unrelated.zip": 1,
        }
        findings = check_release_assets.compare(expected, assets)
        self.assertEqual(
            findings,
            [
                ("missing", "bios/Other/sdlpal/sdlpal/5.avi", 82833972, None),
                ("size", "bios/Other/fbneo/fbneo/samples/twotiger.zip", 154985212, 154888877),
            ],
        )

    def test_expected_assets_are_the_gitignored_database_entries(self):
        from scripts import check_release_assets

        db = {
            "files": {
                "a" * 40: {"path": "bios/Other/x/big.zip", "size": 10},
                "b" * 40: {"path": "bios/Other/x/small.bin", "size": 2},
            }
        }
        gitignore = "# large\nbios/Other/x/big.zip\ntmp/\n"
        self.assertEqual(
            check_release_assets.expected_assets(db, gitignore),
            {"bios/Other/x/big.zip": 10},
        )

    def test_release_notes_are_rendered_from_the_collection(self):
        """The release page is written by hand and drifts, so it is rendered instead.

        Three assets had no row, three rows carried the SHA1 of an asset
        that had since been replaced, and the footer counted 41 files for 44.
        Hand-written descriptions survive by name. A new row takes its
        description from the profile that declares the file, and an asset the
        collection does not index is listed apart, with its size only.
        """
        from scripts import check_release_assets

        db = {"files": {
            "a" * 40: {"path": "bios/Nintendo/Wii/nand.bin", "size": 553649152},
            "b" * 40: {"path": "bios/Other/fbneo/fbneo/samples/twotiger.zip", "size": 154985212},
            "c" * 40: {"path": "bios/Other/x/small.bin", "size": 2},
        }}
        gitignore = "bios/Nintendo/Wii/nand.bin\nbios/Other/fbneo/fbneo/samples/twotiger.zip\n"
        assets = {"nand.bin": 553649152, "twotiger.zip": 154985212,
                  "sdlpal-data.zip": 140773720, "whoopee.zip": 222665810}
        previous = (
            "## Arcade\n\n| File | Description | Size | SHA1 |\n|---|---|---|---|\n"
            "| [twotiger.zip](u) | Two Tigers samples | 148 MB | `" + "0" * 40 + "` |\n"
            "| [whoopee.zip](u) | Toaplan Whoopee samples | 212 MB | `" + "9" * 40 + "` |\n"
        )
        descriptions = {"nand.bin": "BootMii NAND backup"}
        bundles = {"sdlpal-data.zip": "SDLPAL Chinese Paladin game data (.mkf archives)"}
        body = check_release_assets.render_notes(
            db, gitignore, assets, previous, descriptions, bundles, {"sdlpal-data.zip": "d" * 40}
        )
        self.assertIn("| [twotiger.zip](https://github.com/Abdess/retrobios/releases/download/large-files/twotiger.zip) | Two Tigers samples | 148 MB | `" + "b" * 40 + "` |", body)
        self.assertIn("| [nand.bin](https://github.com/Abdess/retrobios/releases/download/large-files/nand.bin) | BootMii NAND backup | 528 MB | `" + "a" * 40 + "` |", body)
        self.assertIn("| [sdlpal-data.zip](https://github.com/Abdess/retrobios/releases/download/large-files/sdlpal-data.zip) | SDLPAL Chinese Paladin game data (.mkf archives) | 134 MB | `" + "d" * 40 + "` |", body)
        self.assertIn("## Not indexed", body)
        self.assertIn("| [whoopee.zip](https://github.com/Abdess/retrobios/releases/download/large-files/whoopee.zip) | Toaplan Whoopee samples | 212 MB |", body)
        self.assertNotIn("9" * 40, body)
        self.assertNotIn("small.bin", body)
        self.assertIn("4 files, 1.0 GB total", body)
        self.assertEqual(body.index("## Console firmware"), min(
            body.index(h) for h in ("## Console firmware", "## Arcade", "## Not indexed")
        ))

    def test_stale_notes_are_a_finding(self):
        from scripts import check_release_assets

        findings = check_release_assets.compare({}, {}, notes_current=False)
        self.assertEqual(findings, [("notes", "release description", 0, None)])

    def test_pipeline_runs_the_check_online_and_marks_it_skipped_offline(self):
        """Run with each step recorded instead of executed: reading the
        source for two strings stayed green with the guard inverted."""
        import contextlib
        import io
        from unittest import mock

        from scripts import pipeline

        def steps(*flags: str) -> list[str]:
            ran: list[str] = []

            def record(cmd, label):
                ran.append(label)
                return True, ""

            argv = ["pipeline.py", "--skip-packs", "--skip-docs", *flags]
            with mock.patch.object(pipeline, "run", record), \
                    mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit) as done:
                pipeline.main()
            self.assertEqual(done.exception.code, 0)
            return ran, out.getvalue()

        online, _ = steps()
        self.assertIn("2b2 check release assets", online)
        offline, printed = steps("--offline")
        self.assertNotIn("2b2 check release assets", offline)
        self.assertIn("check_release_assets.................... SKIPPED", printed)


class OneRefreshPerOnlineRun(unittest.TestCase):
    """An online run refreshed the data trees at step 2, again in the pack
    build and again in the manifest build: a moving tree (fbneo-cheats on
    master) could change between the two, and the pack and the manifest
    described different revisions."""

    def test_the_builds_reuse_step_twos_trees(self):
        import contextlib
        import io
        from unittest import mock

        from scripts import pipeline

        commands: dict[str, list[str]] = {}

        def record(cmd, label):
            commands[label] = cmd
            return True, ""

        # A scratch output directory: step 4 purges the ZIPs of the one it
        # is given, and this run must never touch dist/.
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as out, \
                mock.patch.object(pipeline, "run", record), \
                mock.patch.object(
                    sys, "argv", ["pipeline.py", "--skip-docs", "--output-dir", out]
                ), \
                contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit):
            pipeline.main()
        self.assertIn("2 refresh data directories", commands)
        for label in ("4 generate packs", "4b generate install manifests"):
            with self.subTest(step=label):
                self.assertIn("--no-refresh-data", commands[label])
                self.assertNotIn("--offline", commands[label])


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
            capture_output=True, text=True, cwd=ROOT,
        ).stdout
        return out.rsplit(":", 1)[-1].strip()

    def test_gitattributes_exists(self):
        self.assertTrue(
            (ROOT / ".gitattributes").is_file(),
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
        from common import write_if_changed

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
                cwd=ROOT, capture_output=True, text=True, timeout=600, check=False,
            )
            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertIn("PyYAML required", proc.stderr)
            self.assertFalse(output.exists())

    def test_no_script_swallows_an_import_error(self):
        offenders = []
        for path in sorted((ROOT / "scripts").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Name)
                    and node.type.id in ("ImportError", "ModuleNotFoundError")
                    and all(isinstance(stmt, ast.Pass) for stmt in node.body)
                ):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [])


class TestsCleanUpTheirScratch(unittest.TestCase):
    """Sixteen classes called mkdtemp() and kept the directory: each suite
    run left about 400 of them on the RAM-backed /tmp."""

    def test_every_class_that_makes_a_directory_removes_it(self):
        offenders = []
        for path in sorted((ROOT / "tests").glob("test_*.py")):
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


class PipelineReportsWhatItDid(unittest.TestCase):
    """A step that did not run must not be summarised as OK.

    --offline skips the network steps and --with-export gates three more.
    Reporting them as OK claims work nobody did, and a run whose export
    never happened read exactly like one where it had.
    """

    def test_a_skipped_step_is_not_reported_as_done(self):
        import pipeline

        self.assertTrue(bool(pipeline.SKIPPED), "a skip must not fail the run")
        self.assertEqual(repr(pipeline.SKIPPED), "SKIPPED")
        self.assertIsNot(pipeline.SKIPPED, True)

    def test_every_skip_branch_uses_the_sentinel(self):
        source = (ROOT / "scripts" / "pipeline.py").read_text()
        stale = re.findall(r'results\["(\w+)"\] = True', source)
        self.assertEqual(stale, [], f"steps still claiming OK when skipped: {stale}")

class DeclaredDependenciesMatchTheDocumentedWorkflows(unittest.TestCase):
    """What the workflows install has to be what the project declares.

    mkdocs-material and pymdown-extensions were hard requirements of the site
    build in CI and in the release guide while pyproject declared neither, so
    a contributor following either had to read the workflow to find out.
    """

    @staticmethod
    def _pyproject() -> dict:
        import tomllib

        with (ROOT / "pyproject.toml").open("rb") as handle:
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
            body = (ROOT / ".github" / "workflows" / workflow).read_text(
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
    PackRecord, and 990 such contradictions went through CI green. mypy now
    runs in CI against mypy-baseline.txt, the errors the code carried when the
    check started."""

    BASELINE = ROOT / "mypy-baseline.txt"
    ENTRY = re.compile(r"(?P<path>[^:]+\.py):0: error: .+  \[[a-z-]+\]")

    def test_ci_holds_the_code_to_the_baseline(self):
        body = (ROOT / ".github" / "workflows" / "validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("mypy-baseline filter", body)
        self.assertNotIn("--allow-unsynced", body)

    def test_every_baseline_entry_names_a_file_that_exists(self):
        stale = []
        for line in self.BASELINE.read_text(encoding="utf-8").splitlines():
            match = self.ENTRY.fullmatch(line)
            self.assertIsNotNone(match, f"unreadable baseline entry: {line}")
            if not (ROOT / match["path"]).is_file():
                stale.append(match["path"])
        self.assertEqual(stale, [], "baseline entries for files that are gone")

    def test_the_code_reports_no_error_outside_the_baseline(self):
        for module in ("mypy", "mypy_baseline"):
            try:
                __import__(module)
            except ImportError:
                self.skipTest(f"{module} is not installed (pip install -e '.[dev]')")
        report = subprocess.run(
            [sys.executable, "-m", "mypy"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        result = subprocess.run(
            [sys.executable, "-m", "mypy_baseline", "filter", "--no-colors"],
            cwd=ROOT, input=report.stdout, capture_output=True, text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


class TheProjectInstallsWithPip(unittest.TestCase):
    """pyproject declared a dev extra that pip could not install: without a
    [build-system] and an explicit module list, setuptools' flat-layout
    discovery found scripts/ and tests/ and refused to build."""

    def test_setuptools_discovers_nothing_to_package(self):
        import importlib.util  # noqa: PLC0415

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
        done = subprocess.run([sys.executable, "-c", program], cwd=ROOT,
                              capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        self.assertEqual(done.stdout.strip(), "[] []")
        import tomllib  # noqa: PLC0415

        with (ROOT / "pyproject.toml").open("rb") as handle:
            build = tomllib.load(handle)["build-system"]
        self.assertEqual(build["build-backend"], "setuptools.build_meta")


class ACheckThatCannotAnswerDoesNotPass(unittest.TestCase):
    """Exiting zero says the question was answered and the answer was yes.

    Four scripts said that without answering: a refresh that reached no
    remote, a freshness check whose upstream was unreachable, a restore whose
    cache could not supply a declared path, and a pack verification asked
    about one platform whose pack was not there.
    """

    def test_naming_a_platform_with_no_pack_is_not_a_pass(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            named = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform",
                 "retroarch", "--verify-packs", "--output-dir", directory],
                capture_output=True, text=True, cwd=str(ROOT), timeout=300,
            )
            self.assertNotEqual(
                named.returncode, 0,
                "a named platform with no pack reported success:\n"
                + named.stdout + named.stderr,
            )
            # --all is a sweep: a platform nobody built is out of scope and
            # skipped, but a sweep that found no pack at all checked nothing.
            swept = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--all",
                 "--verify-packs", "--output-dir", directory],
                capture_output=True, text=True, cwd=str(ROOT), timeout=300,
            )
            self.assertIn("SKIP (no pack in", swept.stdout)
            self.assertNotEqual(swept.returncode, 0, swept.stdout + swept.stderr)

    def test_an_unsatisfiable_declared_path_is_reported(self):
        from scripts.restore_large_files import restore

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            (root / ".gitignore").write_text("bios/absent.bin\n", encoding="utf-8")
            (root / "database.json").write_text(
                json.dumps({"files": {"a" * 40: {"path": "bios/absent.bin"}}}),
                encoding="utf-8",
            )
            cwd = os.getcwd()
            os.chdir(root)
            try:
                restored, unsatisfied = restore(
                    str(cache), "database.json", ".gitignore"
                )
            finally:
                os.chdir(cwd)
            self.assertEqual(restored, 0)
            self.assertEqual(unsatisfied, ["bios/absent.bin"])

    def test_an_unreachable_buildbot_is_not_a_fresh_verdict(self):
        """Every HEAD unanswered printed "16 unknown" and exited 0, so the
        online pipeline printed check_buildbot OK."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import check_buildbot_system as cbs  # noqa: PLC0415

        registry = str(ROOT / "platforms" / "_data_dirs.yml")
        tracked = cbs.load_tracked_entries(registry)
        self.assertTrue(tracked)
        cases = {
            "index unreachable": mock.patch.object(
                cbs, "fetch_index", side_effect=OSError("down")),
            "every HEAD unanswered": mock.patch.object(
                cbs, "fetch_index", return_value=set(tracked)),
        }
        for label, index in cases.items():
            with self.subTest(label), index, \
                    mock.patch.object(cbs, "get_remote_etag", return_value=None), \
                    mock.patch.object(sys, "argv", ["check_buildbot_system.py",
                                                    "--registry", registry]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(SystemExit) as stop:
                cbs.main()
            self.assertEqual(stop.exception.code, 1)

    def test_a_missing_profile_directory_says_so(self):
        from scripts import common as _common

        with self.assertRaisesRegex(_common.InputMissing, "no emulator profile directory"):
            _common.load_emulator_profiles(str(ROOT / "no-such-emulator-dir"))


class TestEntryPointsRunEveryClass(unittest.TestCase):
    """`unittest.main()` has to sit after the last test class.

    In this file it sat in the middle, so running it directly discovered only
    the classes defined above it: eight cases never ran that way, while
    `python -m unittest discover` ran all of them. The two roads have to agree.
    """

    def test_no_module_calls_main_before_its_last_class(self):
        for path in sorted((ROOT / "tests").glob("test_*.py")):
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
    made `import scripts.common` fail on the first sibling import it reached.
    """

    def _run(self, *args: str):
        import subprocess

        return subprocess.run(
            [sys.executable, *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=300,
        )

    def test_imported_as_a_package(self):
        result = self._run(
            "-c", "import scripts.common, scripts.verify, scripts.generate_pack"
        )
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_module(self):
        result = self._run("-m", "scripts.scraper.libretro_scraper", "--help")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])

    def test_run_as_a_script(self):
        result = self._run("scripts/list_platforms.py")
        self.assertEqual(result.returncode, 0, result.stderr[-400:])


class ContributorsSurviveAFailedRequest(unittest.TestCase):
    """The one part of the README that comes from the network.

    A refused or rate-limited request left the list empty, which deleted the
    section from a published README. It happened during a pipeline run and
    the result was committed, after which the freshness check regenerated the
    section and failed on the difference. Losing the list is a worse answer
    than publishing a stale one.
    """

    def _block(self, text: str):
        import tempfile

        sys.path.insert(0, str(ROOT / "scripts"))
        from generate_readme import _existing_contributor_block

        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
            handle.write(text)
            name = handle.name
        try:
            return _existing_contributor_block(name)
        finally:
            os.unlink(name)

    def test_a_published_list_is_read_back(self):
        text = (
            "# Title\n\n## Contributors\n\n"
            '<a href="https://github.com/a"><img src="x" alt="a"></a>\n'
            '<a href="https://github.com/b"><img src="y" alt="b"></a>\n\n'
            "## Community tools\n\nsomething else\n"
        )
        block = self._block(text)
        self.assertEqual(block[0], "## Contributors")
        self.assertIn('alt="a"', "\n".join(block))
        self.assertIn('alt="b"', "\n".join(block))
        self.assertNotIn("Community tools", "\n".join(block))
        self.assertNotIn("something else", "\n".join(block))

    def test_a_readme_without_the_section_yields_nothing(self):
        self.assertEqual(self._block("# Title\n\n## Other\n\ntext\n"), [])

    def test_an_unreadable_file_yields_nothing(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from generate_readme import _existing_contributor_block

        self.assertEqual(_existing_contributor_block("/nonexistent/README.md"), [])

    def test_the_committed_readme_still_carries_its_contributors(self):
        """Regenerating offline must never be the reason this disappears."""
        text = (ROOT / "README.md").read_text()
        # Missing is the failure this guards, never a reason to skip.
        self.assertIn("## Contributors", text)
        self.assertGreater(
            text.count('<a href="https://github.com/'), 0,
            "the section is present but empty",
        )


class APackNameFitsAFileName(unittest.TestCase):
    """--system snes joined 23 emulator names and died on ENAMETOOLONG
    before writing anything, while verify --system snes reported."""

    def test_a_long_selection_is_bounded_and_told_apart(self):
        from scripts.generate_pack import MAX_PACK_NAME_BYTES, _bounded_pack_name

        names = [f"Emulator_Number_{i}" for i in range(23)]
        long_name = _bounded_pack_name(names, names, "_BIOS_Pack.zip")
        self.assertLessEqual(len(long_name.encode()), MAX_PACK_NAME_BYTES)
        self.assertTrue(long_name.startswith("Emulator_Number_0_and_22_more_"))
        other = _bounded_pack_name(names, names[:-1] + ["x"], "_BIOS_Pack.zip")
        self.assertNotEqual(long_name, other)
        self.assertEqual(_bounded_pack_name(["A", "B"], ["a", "b"], ".zip"), "A_B.zip")

    def test_a_long_system_list_is_bounded(self):
        """Thirty systems joined made a 261-byte platform pack name."""
        from scripts.generate_pack import MAX_SYSTEM_TAG_BYTES, _system_tag

        systems = [f"vendor-console-number-{i}" for i in range(30)]
        tag = _system_tag(systems)
        self.assertLessEqual(len(tag.encode()), MAX_SYSTEM_TAG_BYTES + 1)
        self.assertNotEqual(tag, _system_tag(systems[:-1] + ["other-console"]))
        self.assertEqual(_system_tag(["sony-playstation"]), "_Playstation")

    def test_two_systems_never_name_one_system(self):
        """sega-dreamcast,arcade and sega-dreamcast-arcade both wrote
        RetroArch_..._Dreamcast_Arcade.zip, and the second replaced the first."""
        from scripts.generate_pack import _system_tag

        pairs = [
            (["sega-dreamcast", "arcade"], ["sega-dreamcast-arcade"]),
            (["mega-cd", "sega-32x"], ["mega-cd-32x"]),
            (["x86", "nintendo-64"], ["x86-64"]),
        ]
        for two, one in pairs:
            with self.subTest(two=two):
                self.assertNotEqual(_system_tag(two), _system_tag(one))

    def test_two_hash_lists_get_two_names(self):
        """--from-md5 named its pack after the context only: a second list
        overwrote the first pack in the same directory."""
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertIn('_Custom_{selection}', source)

    def test_the_system_pack_names_itself(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertIn("pack_name=final_name", source)


class AGroupPackIsWrittenUnderItsOwnName(unittest.TestCase):
    """The RetroArch + Lakka pack was written as RetroArch_..._BIOS_Pack.zip
    and renamed: a `--platform retroarch` pack already in the directory was
    overwritten then carried away, and os.rename refuses an existing target
    on Windows."""

    def test_no_pack_is_renamed_after_its_build(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn("os.rename(", source)
        self.assertIn("pack_name=group_name", source)


class ARegionDroppedExtraBlocksNothing(unittest.TestCase):
    """The builder skips a region-dropped core extra before placing it,
    but the report placed it anyway, so on a case-folding platform it hid the
    next core's FOO.ROM that the pack does carry."""

    def test_the_report_skips_what_the_region_pass_drops(self):
        from unittest import mock

        from scripts import packextras

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            other = Path(directory) / "FOO.ROM"
            other.write_bytes(b"other bytes")
            first = Path(directory) / "foo.rom"
            first.write_bytes(b"first bytes")
            copies = {"foo.rom": str(first), "FOO.ROM": str(other)}
            extras = [
                {"name": "foo.rom", "destination": "foo.rom", "source_emulator": "a"},
                {"name": "FOO.ROM", "destination": "FOO.ROM", "source_emulator": "b"},
            ]
            config = {"case_insensitive_fs": True, "base_destination": ""}

            def report(region_drops):
                with mock.patch.object(packextras, "_collect_emulator_extras",
                                       return_value=extras), \
                        mock.patch.object(packextras, "resolve_local_file",
                                          side_effect=lambda fe, *a, **k: (
                                              copies[fe["name"]], "name_exact")):
                    return packextras.hidden_extras(
                        config, "emulators", {"files": {}}, {}, {}, None, region_drops
                    )

            self.assertTrue(report(None))
            self.assertEqual(report({"foo.rom"}), {})


class AnotherEmulatorsTreeProvesNothing(unittest.TestCase):
    """lrps2 names no hash for pcsx2/resources/GameIndex.yaml, and the only
    full-tail copy was ARMSX2's, which counted as path proof and replaced
    the GameIndex RetroArch pins on desktop targets, where ARMSX2 does not
    exist. Upstream PCSX2 took ARMSX2's patches.zip by name the same way."""

    def _db(self, root, files):
        import hashlib

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {},
                                       "by_path_suffix": {}}}
        for relative, payload in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            sha1 = hashlib.sha1(payload).hexdigest()
            db["files"][sha1] = {"path": relative, "name": path.name, "sha1": sha1,
                                 "size": len(payload)}
            db["indexes"]["by_name"].setdefault(path.name, []).append(sha1)
            parts = relative.split("/")
            for start in range(1, len(parts) - 1):
                db["indexes"]["by_path_suffix"].setdefault(
                    "/".join(parts[start:]), []).append(sha1)
        return db

    def test_neither_the_full_tail_nor_the_name_lands_in_a_foreign_tree(self):
        from scripts.common import resolve_local_file

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            # The collection's layout, read relative to its root.
            previous = os.getcwd()
            os.chdir(root)
            self.addCleanup(os.chdir, previous)
            db = self._db(root, {
                "bios/Other/armsx2/pcsx2/resources/GameIndex.yaml": b"fork",
                "bios/Other/armsx2/pcsx2/resources/patches.zip": b"fork patches",
                "bios/Sony/PlayStation 2/patches.zip": b"upstream patches",
            })
            index, status = resolve_local_file(
                {"name": "GameIndex.yaml", "path": "pcsx2/resources/GameIndex.yaml",
                 "source_profile": "lrps2"},
                db, dest_hint="pcsx2/resources/GameIndex.yaml",
            )
            # Held only in the fork's tree, the file answers by name and
            # proves nothing about this entry.
            self.assertEqual(status, "name_exact")
            patches, _status = resolve_local_file(
                {"name": "patches.zip", "path": "resources/patches.zip",
                 "source_profile": "pcsx2"},
                db, dest_hint="resources/patches.zip",
            )
            self.assertTrue(patches.endswith("PlayStation 2/patches.zip"))

    def test_no_desktop_retroarch_pack_serves_armsx2s_tree(self):
        from scripts import slots
        from scripts.common import (
            load_data_dir_registry,
            load_database,
            load_emulator_profiles,
            load_platform_config,
            load_target_config,
        )

        if not (ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = load_database(str(ROOT / "database.json"))
        config = load_platform_config("retroarch", str(ROOT / "platforms"))
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        cores = set(load_target_config("retroarch", "x86_64", str(ROOT / "platforms")))
        overrides = slots.pack_overrides(
            config, profiles, db, None, load_data_dir_registry(str(ROOT / "platforms")),
            target_cores=cores,
        )
        self.assertFalse([d for d, p in overrides.items() if "/armsx2/" in p])


class APinnedCoreFileTakesTheSlotFirst(unittest.TestCase):
    """hypseus-singe asks for gamecontrollerdb.txt by name and took the BIOS
    root of Batocera, RetroBat and RetroPie with C-Dogs' 26 KB table, where
    Solarus pins its own by sha1."""

    def test_the_content_naming_claim_is_placed_first(self):
        from unittest import mock

        from scripts import packextras

        undeclared = [
            {"profile": "hypseus", "emulator": "hypseus", "name": "db.txt",
             "path": "db.txt", "in_repo": True, "systems": ["a"]},
            {"profile": "solarus", "emulator": "solarus", "name": "db.txt",
             "path": "db.txt", "in_repo": True, "systems": ["b"], "sha1": "a" * 40},
        ]
        config = {"systems": {}, "base_destination": "bios"}
        with mock.patch("verify.find_undeclared_files", return_value=undeclared), \
                mock.patch.object(packextras, "resolve_platform_cores",
                                  return_value=set()) as cores:
            extras = packextras._collect_emulator_extras(
                config, "emulators", {"files": {}, "indexes": {}}, set(), "bios", {}
            )
        self.assertEqual([e["source_profile"] for e in extras][:1], ["solarus"])
        # The stub is what ran: patched with create=True on a name the module
        # imported inside the function, it was never read and the real
        # resolve_platform_cores walked the repository's profiles.
        cores.assert_called_once()


class ANameWithItsDirectoryIsTheDestination(unittest.TestCase):
    """gam4980 declares gam4980/E.BIN with no path: resolved by its basename,
    verify --emulator and the emulator pack took the A4980's OS while the
    platform pack served the GAM4980's."""

    def test_the_directory_in_the_name_picks_the_copy(self):
        import hashlib

        from scripts.common import resolve_local_file

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            previous = os.getcwd()
            os.chdir(root)
            self.addCleanup(os.chdir, previous)
            files, by_name, by_suffix = {}, {}, {}
            for relative, payload in (("bios/BBK/A4980/A4980/E.BIN", b"a4980"),
                                      ("bios/BBK/GAM4980/gam4980/E.BIN", b"gam4980")):
                Path(relative).parent.mkdir(parents=True, exist_ok=True)
                Path(relative).write_bytes(payload)
                sha1 = hashlib.sha1(payload).hexdigest()
                files[sha1] = {"path": relative, "name": "E.BIN", "sha1": sha1}
                by_name.setdefault("E.BIN", []).append(sha1)
                parent = relative.split("/")[-2]
                by_suffix.setdefault(f"{parent}/E.BIN", []).append(sha1)
            db = {"files": files, "indexes": {"by_name": by_name, "by_md5": {},
                                              "by_crc32": {}, "by_path_suffix": by_suffix}}
            path, status = resolve_local_file(
                {"name": "gam4980/E.BIN", "source_profile": "gam4980"}, db
            )
            self.assertEqual((path, status), ("bios/BBK/GAM4980/gam4980/E.BIN", "path_exact"))


class AnUnreadableDatabaseStopsTheScan(unittest.TestCase):
    """A database.json left with merge markers read as an absent one: every
    release-asset entry silently left the rewritten database, then the
    manifests."""

    def test_a_corrupt_database_is_not_an_empty_one(self):
        from unittest import mock

        from scripts import generate_db

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = Path(directory) / "database.json"
            path.write_text("<<<<<<< HEAD\n{}\n")
            with mock.patch.object(generate_db, "_load_gitignored_large_files",
                                   return_value={"bios/big.bin"}):
                with self.assertRaises(SystemExit):
                    generate_db._preserve_large_file_entries({}, str(path))
                self.assertEqual(
                    generate_db._preserve_large_file_entries(
                        {}, str(Path(directory) / "absent.json")
                    ),
                    0,
                )


class TheZipIndexCacheKnowsItsInputs(unittest.TestCase):
    """build_zip_contents_index cached on (path, mtime) alone: a smaller
    max_entry_size, or a database giving the same archive another sha1,
    got the first call's index back."""

    def test_the_bound_and_the_sha1_are_part_of_the_key(self):
        from scripts import ziptools

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = Path(directory) / "a.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("big.bin", b"x" * 4096)
            ziptools._zip_contents_cache = None
            db = {"files": {"a" * 40: {"path": str(path)}}}
            self.assertEqual(len(ziptools.build_zip_contents_index(db)), 1)
            self.assertEqual(ziptools.build_zip_contents_index(db, max_entry_size=10), {})
            other = {"files": {"b" * 40: {"path": str(path)}}}
            self.assertEqual(
                set(ziptools.build_zip_contents_index(other).values()), {"b" * 40}
            )
            ziptools._zip_contents_cache = None


class GeneratedModelsAreWrittenWhole(unittest.TestCase):
    """The truth model and the cumulative MAME clone map were written by
    truncate-then-write, and a corrupt clone map also read as empty and was
    then overwritten, losing what earlier runs recorded."""

    def test_both_writers_replace_their_file_atomically(self):
        for module in ("generate_truth.py", "dedup.py"):
            source = (ROOT / "scripts" / module).read_text(encoding="utf-8")
            with self.subTest(module=module):
                self.assertIn("write_text_atomic(", source)
                self.assertNotIn('open(out_path, "w")', source)
                self.assertNotIn('open(clone_path, "w")', source)

    def test_an_unreadable_clone_map_stops_the_run(self):
        from scripts import dedup

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            root = Path(directory)
            bios = root / "bios"
            # A device clone: two archive names, the same ROMs, in MAME's tree.
            (bios / "Arcade" / "MAME").mkdir(parents=True)
            for name in ("set.zip", "setclone.zip"):
                with zipfile.ZipFile(bios / "Arcade" / "MAME" / name, "w") as archive:
                    archive.writestr("rom.bin", b"rom")
            data = (bios / "Arcade" / "MAME" / "set.zip").read_bytes()
            (bios / "Arcade" / "MAME" / "setclone.zip").write_bytes(data)
            (root / "_mame_clones.json").write_text("<<<<<<< HEAD")
            with self.assertRaises(SystemExit):
                dedup.deduplicate(str(bios), dry_run=False)
            # Stopped before removing anything.
            self.assertTrue((bios / "Arcade" / "MAME" / "setclone.zip").exists())


class APackNoteBesideItsSlotIsANote(unittest.TestCase):
    """The builder writes INSTRUCTIONS_<name>.txt beside the slot it
    explains, but verify_pack recognised notes at the ZIP root only and failed
    a pack holding games/keen6/INSTRUCTIONS_egagraph.ck6.txt."""

    def test_a_nested_note_is_not_hashed_against_the_collection(self):
        from scripts.packverify import verify_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = Path(directory) / "Pack.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("games/keen6/INSTRUCTIONS_egagraph.ck6.txt", "File needed")
                archive.writestr("bios/RENAMED_x.bin.txt", "renamed")
            result = verify_pack(str(path), {"files": {}, "indexes": {}})
        self.assertTrue(result[0], result)

    def test_verify_reads_the_rule_where_it_is_defined(self):
        source = (ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        self.assertNotIn("from generate_pack import _preferred_entries", source)


class NoHandlerSwallowsEverything(unittest.TestCase):
    """The project forbids `except Exception: pass`, but the edit hook missed
    the two-line form and nothing in CI checked it."""

    def test_no_catch_all_handler_only_passes(self):
        import ast

        offenders = []
        for path in [*sorted((ROOT / "scripts").rglob("*.py")), ROOT / "install.py"]:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                broad = node.type is None or (
                    isinstance(node.type, ast.Name)
                    and node.type.id in ("Exception", "BaseException")
                )
                if broad and all(isinstance(stmt, ast.Pass) for stmt in node.body):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [])


class AnArchiveShipsWholeUnderARegion(unittest.TestCase):
    """verify --emulator dropped kronos' regional stvbios.zip members before
    rebuilding the archive, so its archive held 4 of 14 members and its
    required changed, while the emulator pack ships the archive whole."""

    def test_verify_filters_loose_files_only(self):
        source = (ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        self.assertIn(
            'if fe.get("archive")\n                or _resolve_destination(fe, standalone) not in region_drops',
            source,
        )


class APathConflictKeepsTheMainVerdict(unittest.TestCase):
    """The builder's file/directory conflict branch judged a declaration by
    the raw resolver status: a zipped_file archive whose member is right was
    counted excluded while verify counted it OK."""

    def test_the_branch_reads_baseline_verdict(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        branch = source[source.index("Content ships under the conflicting shape"):]
        branch = branch[: branch.index("storage = file_entry.get")]
        self.assertIn("baseline_verdict(", branch)
        self.assertNotIn('conflict_status == "hash_mismatch"', branch)


class TheDatabaseCacheIsWrittenWhole(unittest.TestCase):
    """A crash while serializing left a truncated db_cache.json behind, and
    the next run rehashed the whole collection from scratch."""

    def test_a_failed_save_keeps_the_previous_cache(self):
        import json
        from unittest import mock

        from scripts import generate_db

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            path = os.path.join(directory, "cache", "db_cache.json")
            generate_db.save_cache(path, {"a": 1})
            with mock.patch.object(json, "dumps", side_effect=TypeError("miscomputed")):
                with self.assertRaises(TypeError):
                    generate_db.save_cache(path, {"a": 2})
            self.assertEqual(generate_db.load_cache(path), {"a": 1})
            self.assertEqual(os.listdir(os.path.dirname(path)), ["db_cache.json"])


class KidVidTapesStayWithTheContent(unittest.TestCase):
    """Stella opens its KidVid tapes by bare name (stella2014, from the
    working directory) or from its base directory (stella2023, the content
    folder, and stella, a folder under the save directory): never the system
    directory. Without load_from every Linux pack put about 68 MB of WAVs at
    the BIOS root, in two cases. The save directory is a place a pack
    reaches: stella's tapes go there, never to the BIOS tree."""

    def test_no_pack_places_them_in_the_system_directory(self):
        from scripts.common import load_emulator_profiles
        from scripts.validation import (
            outside_gap_scope,
            read_from_save_dir,
            read_from_system_dir,
        )

        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        for name in ("stella", "stella2014", "stella2023"):
            tapes = [f for f in profiles[name]["files"]
                     if f["name"].lower().endswith(".wav")]
            with self.subTest(profile=name):
                self.assertEqual(len(tapes), 7)
                self.assertFalse(any(read_from_system_dir(f, False) for f in tapes))
                for f in tapes:
                    self.assertTrue(
                        outside_gap_scope(f, False) or read_from_save_dir(f, False)
                    )


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
        for path in sorted(ROOT.glob("scripts/**/*.py")) + [ROOT / "install.py"]:
            again = self._redeclared(path)
            if again:
                offenders[path.name] = again
        self.assertEqual(offenders, {})


class OnlyTheSchemaValidatorNeedsJsonschema(unittest.TestCase):
    """Build scripts and install.py run on stdlib plus pyyaml, and jsonschema is
    tooling for validate_schemas and CI. An import anywhere else turns a
    contributor's pipeline run into an ImportError."""

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
            str(path.relative_to(ROOT))
            for path in sorted(ROOT.glob("scripts/**/*.py")) + [ROOT / "install.py"]
            if path.name != "validate_schemas.py"
            and self._imports_jsonschema(path.read_text())
        ]
        self.assertEqual(offenders, [])

    def test_a_nested_import_is_seen(self):
        self.assertTrue(
            self._imports_jsonschema("def f():\n    from jsonschema import validate\n")
        )


class HashMergeBackupsAreNotSources(unittest.TestCase):
    """The hash merge copies a profile to <name>.old.yml before rewriting it.

    Every loader skipped the copy except validate_schemas, which then failed
    on a stale MAME profile nobody would ever ship.
    """

    def test_the_validator_skips_a_backup(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            from validate_schemas import _validate_yaml_directory
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            (Path(directory) / "mame.old.yml").write_text("emulator: [\n")
            self.assertEqual(
                _validate_yaml_directory(Path(directory), "emulator.schema.json"), []
            )

    def test_the_backup_suffix_is_written_once(self):
        offenders = [
            str(path.relative_to(ROOT))
            for path in sorted(ROOT.glob("scripts/**/*.py"))
            if path.name != "common.py" and '".old.yml"' in path.read_text()
        ]
        self.assertEqual(offenders, [])



class AnUnreadableArchiveIsSaidOutLoud(unittest.TestCase):
    """resolve_local_file skipped a ZIP it could not open without a word: a
    truncated archive read as a missing dump (not_found) or a wrong one."""

    def test_the_resolver_names_the_archive(self):
        import common  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            broken = Path(tmp) / "neogeo.zip"
            broken.write_bytes(b"PK\x03\x04 truncated")
            sha1 = hashlib.sha1(broken.read_bytes()).hexdigest()
            db = {"files": {sha1: {"path": str(broken), "name": "neogeo.zip", "sha1": sha1,
                                   "md5": "0" * 32, "size": broken.stat().st_size}},
                  "indexes": {"by_name": {"neogeo.zip": [sha1]}, "by_md5": {},
                              "by_crc32": {}, "by_path_suffix": {}}}
            entry = {"name": "neogeo.zip", "md5": "1" * 32, "zipped_file": "sp-s2.sp1"}
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                common.resolve_local_file(entry, db)
        self.assertIn(f"unreadable archive {broken}", stderr.getvalue())


class GeneralUserGSReachesEveryCoreThatNamesIt(unittest.TestCase):
    """The SoundFont was held as dosbox_pure's DOSBOX.SF2 alone: dosbox-staging
    and dosbox-x, which name it GeneralUser-GS.sf2 and GeneralUser_GS.sf2,
    shipped no General MIDI bank."""

    def test_each_name_resolves_to_the_one_file(self):
        import common  # noqa: PLC0415

        if not (ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = json.loads((ROOT / "database.json").read_text())
        profiles = common.load_emulator_profiles(str(ROOT / "emulators"))
        held = "bios/Other/GeneralUser GS/GeneralUser-GS.sf2"
        for emulator, name in (("dosbox_pure", "DOSBOX.SF2"),
                               ("dosbox-staging", "GeneralUser-GS.sf2"),
                               ("dosbox-x", "GeneralUser_GS.sf2")):
            with self.subTest(emulator=emulator):
                entry = next(f for f in profiles[emulator]["files"] if f["name"] == name)
                path, _status = common.resolve_local_file(
                    {**entry, "source_profile": emulator}, db, dest_hint=entry.get("path", ""))
                self.assertEqual(path, held)


class APlatformPinDoesNotReplaceTheCoresRevision(unittest.TestCase):
    """RetroArch pins ScummVM's kyra.dat and FBNeo's hiscore.dat at older
    revisions. Collected as variants with profiles that claimed no content,
    the platform's md5 became the only proof and the pack shipped the old
    files to cores built against newer ones."""

    def test_the_profile_revision_serves_the_core(self):
        import common  # noqa: PLC0415

        if not (ROOT / "database.json").exists():
            self.skipTest("database.json is not generated")
        db = json.loads((ROOT / "database.json").read_text())
        profiles = common.load_emulator_profiles(str(ROOT / "emulators"))
        for emulator, name, pinned in (("scummvm", "kyra.dat", "21a57f79886e46f410cfb50186ed8d77"),
                                       ("fbneo", "hiscore.dat", "37fc4e050b53a1ef2c2e7f3042553025")):
            with self.subTest(emulator=emulator):
                entry = next(f for f in profiles[emulator]["files"] if f["name"] == name)
                self.assertTrue(entry.get("sha1"), "the profile claims its revision")
                self.assertIn(pinned, db["indexes"]["by_md5"], "the platform's pin is held")
                path, status = common.resolve_local_file(
                    {**entry, "source_profile": emulator}, db, dest_hint=entry["path"])
                self.assertEqual(status, "sha1_exact")
                self.assertEqual(db["files"][entry["sha1"]]["path"], path)


class PipelineStepsSpeakAsTheyGo(unittest.TestCase):
    """run() captured a step and printed it at the end, stderr after stdout:
    a twenty-minute pack build was silent and a warning lost its place."""

    def test_output_keeps_its_order_and_is_returned(self):
        script = ("import sys; print('one', flush=True); "
                  "print('two', file=sys.stderr, flush=True); print('three')")
        echoed = io.StringIO()
        with contextlib.redirect_stdout(echoed):
            ok, output = pipeline.run([sys.executable, "-c", script], "probe")
        self.assertTrue(ok)
        self.assertEqual(output, "one\ntwo\nthree\n")
        text = echoed.getvalue()
        self.assertLess(text.index("one"), text.index("two"))
        self.assertLess(text.index("two"), text.index("three"))
        self.assertLess(text.index("three"), text.index("--- probe: OK"))


class ADataDirectoryIsWalkedOnce(unittest.TestCase):
    """Each unresolved name walked every data-directory cache again: the
    resolution cost names x tree on every pack build."""

    def test_two_lookups_share_one_walk_and_keep_its_order(self):
        import common  # noqa: PLC0415

        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            cache = Path(tmp) / "cache"
            (cache / "a").mkdir(parents=True)
            (cache / "b").mkdir()
            (cache / "a" / "Font.bin").write_bytes(b"1")
            (cache / "b" / "font.bin").write_bytes(b"2")
            (cache / "b" / "other.bin").write_bytes(b"3")
            registry = {"x": {"local_cache": str(cache)}}
            common.forget_data_dir_index()
            walks = []
            real_walk = os.walk

            def counting_walk(top, *a, **k):
                walks.append(top)
                return real_walk(top, *a, **k)

            with mock.patch.object(common.os, "walk", counting_walk):
                first, _ = common._resolve_in_data_dirs(["font.bin"], registry,
                                                        lambda _p: "name_exact")
                second, _ = common._resolve_in_data_dirs(["other.bin"], registry,
                                                         lambda _p: "name_exact")
            common.forget_data_dir_index()
        self.assertEqual(len(walks), 1)
        expected = sorted(str(p) for p in (cache / "a" / "Font.bin", cache / "b" / "font.bin"))
        self.assertIn(first[0], expected)
        self.assertEqual(second[0], str(cache / "b" / "other.bin"))


class ADuplicateYamlKeyIsRefused(unittest.TestCase):
    """PyYAML kept the last of two equal keys: the registry carried two
    target_source keys for Recalbox and nothing noticed."""

    def test_the_loader_names_the_repeated_key(self):
        from safeparse import yaml_load  # noqa: PLC0415

        with self.assertRaises(yaml.constructor.ConstructorError) as caught:
            yaml_load("platform: x\ntarget_source: a\ntarget_source: b\n")
        self.assertIn("duplicate key 'target_source'", str(caught.exception))
        self.assertEqual(yaml_load("a: &x {b: 1}\nc: *x\n"), {"a": {"b": 1}, "c": {"b": 1}})


class AnAcceptedVersionIsNoCoreDiscrepancy(unittest.TestCase):
    """eduke32 lists the retail and demo NWINTER.GRP under one name: the extra
    carries the first, and a held demo copy is a version the code takes."""

    PROFILE = {"files": [
        {"name": "NWINTER.GRP", "size": 9, "crc32": "00000000",
         "validation": ["size", "crc32"]},
        {"name": "NWINTER.GRP", "size": 4, "crc32": "",
         "validation": ["size", "crc32"]},
    ]}

    def _extra(self) -> dict:
        # The shape find_undeclared_files gives a core extra: source_path
        # defaults to the name when the profile declares no path.
        return {"name": "NWINTER.GRP", "source_name": "NWINTER.GRP",
                "source_path": "NWINTER.GRP", "source_profile": "eduke32"}

    def test_a_sibling_version_matches(self):
        from scripts.generate_pack import _matches_an_alternative

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            held = Path(tmp) / "NWINTER.GRP"
            held.write_bytes(b"demo")
            profile = json.loads(json.dumps(self.PROFILE))
            profile["files"][1]["crc32"] = f"{zlib.crc32(b'demo'):08x}"
            self.assertTrue(_matches_an_alternative(
                self._extra(), str(held), {"eduke32": profile}))

    def test_a_copy_no_entry_declares_still_disagrees(self):
        from scripts.generate_pack import _matches_an_alternative

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            held = Path(tmp) / "NWINTER.GRP"
            held.write_bytes(b"other")
            profile = json.loads(json.dumps(self.PROFILE))
            profile["files"][1]["crc32"] = f"{zlib.crc32(b'demo'):08x}"
            self.assertFalse(_matches_an_alternative(
                self._extra(), str(held), {"eduke32": profile}))

    def test_the_pack_consults_the_alternatives(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text()
        self.assertRegex(source, r'status == "hash_mismatch" and not _matches_an_alternative\(')


class ADataDirectoryCopyPassesTheNameChecks(unittest.TestCase):
    """The name steps over bios/ refuse a candidate outside the size or the
    Adler-32 the entry's code checks, but a cache copy found by the same name
    was returned without either check."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))
        cache = self.tmp / "cache"
        cache.mkdir()
        (cache / "wiitdb-pt.txt").write_bytes(b"12345")
        self.registry = {"dolphin-sys": {"local_cache": str(cache)}}
        self.db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {},
                                            "by_path_suffix": {}, "by_crc32": {}}}

    def resolve(self, **fields):
        entry = {"name": "wiitdb-pt.txt", **fields}
        return resolve_local_file(entry, self.db, data_dir_registry=self.registry)

    def test_a_size_the_code_accepts_resolves(self):
        self.assertEqual(self.resolve(size=5, validation=["size"])[1], "data_dir")

    def test_another_size_is_a_contradiction(self):
        self.assertEqual(self.resolve(size=1, validation=["size"])[1], "hash_mismatch")

    def test_another_adler32_is_a_contradiction(self):
        status = self.resolve(validation=["adler32"], known_hash_adler32="0xdeadbeef")[1]
        self.assertEqual(status, "hash_mismatch")


class AMameCloneNameIsANameStep(unittest.TestCase):
    """The clone fallback relaunched resolution on the bare canonical name:
    an unsourceable entry and a size the code checks were both served the
    parent set."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))
        bios = self.tmp / "bios" / "Arcade"
        bios.mkdir(parents=True)
        parent = bios / "parent.zip"
        parent.write_bytes(b"PARENTSET")
        (self.tmp / "_mame_clones.json").write_text(
            json.dumps({"parent.zip": {"clones": ["clone.zip"]}})
        )
        sha1 = hashlib.sha1(parent.read_bytes()).hexdigest()
        self.db = {
            "bios_dir": str(self.tmp / "bios"),
            "files": {sha1: {"path": str(parent), "name": "parent.zip",
                             "sha1": sha1, "size": 9}},
            "indexes": {"by_name": {"parent.zip": [sha1]}, "by_md5": {},
                        "by_path_suffix": {}, "by_crc32": {}},
        }

    def resolve(self, **fields):
        return resolve_local_file({"name": "clone.zip", **fields}, self.db)

    def test_a_clone_resolves_to_its_parent(self):
        self.assertEqual(self.resolve()[1], "mame_clone")

    def test_an_unsourceable_entry_is_not_served_the_parent(self):
        self.assertEqual(self.resolve(unsourceable="not held"), (None, "not_found"))

    def test_a_size_the_parent_contradicts_is_not_served(self):
        self.assertEqual(
            self.resolve(size=5, validation=["size"]), (None, "not_found")
        )


class ProseCitationsUseTheTrackedForm(unittest.TestCase):
    """profile_sync tracks `path:line` citations only. `libretro.c
    I_FindFile, line 1742` escaped it, and sixteen such citations in six
    profiles stayed behind when their pins moved, four already pointing at
    other code."""

    UNTRACKED = re.compile(
        r"[\w./+-]+\.(?:c|cc|cpp|cxx|h|hh|hpp|inc|cs|py|rs|go|java|kt|js|ts"
        r"|m|mm|s|asm|lua|sh)\b[^\n:]{0,80}?\blines? \d+"
    )

    def test_the_pattern_reads_the_old_forms(self):
        for text in ("libretro.c I_FindFile, line 1742",
                     "memory.c LoadBios() line 1353",
                     "libretro_core_options.h lines 52-64"):
            self.assertRegex(text, self.UNTRACKED)
        self.assertNotRegex("I_FindFile, libretro/libretro.c:4176-4252", self.UNTRACKED)

    def test_no_profile_writes_a_line_number_profile_sync_cannot_see(self):
        found = [
            f"{path.name}:{number}: {match.group(0)}"
            for path in sorted((ROOT / "emulators").glob("*.yml"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            for match in self.UNTRACKED.finditer(line)
        ]
        self.assertEqual(found, [])


class ACitationInsideASourceRefIsTracked(unittest.TestCase):
    """split_source_ref reads each chunk's located head and drops the rest.
    zesarux cited src/cpu.h:545 inside an annotation, four lines off at its
    pin, and pce-emu joined two citations with ` + `: neither was anchored."""

    def citations(self, ref: str) -> list[str]:
        from scripts.profile_sync import collect_citations

        document = {"files": [{"name": "x.rom", "source_ref": ref}]}
        return [(c.kind, c.ref) for c in collect_citations(document)]

    def test_an_annotation_citation_is_read_as_prose(self):
        found = self.citations(
            "src/cpu.c:3381-3383, src/utils.c:4100 "
            "(MACHINE_IS_SPECTRUM_128_P2 covers Pentagon, src/cpu.h:549)"
        )
        self.assertIn(("prose", "src/cpu.h:549"), found)
        self.assertNotIn(("prose", "src/cpu.c:3381-3383"), found)

    def test_a_joined_citation_is_read_as_prose(self):
        found = self.citations(
            "src/pce_fast/pce.cpp:477-483 + src/pce_fast/huc.cpp:284-304"
        )
        self.assertIn(("prose", "src/pce_fast/huc.cpp:284-304"), found)
        self.assertEqual([c for c in found if c[0] == "prose"],
                         [("prose", "src/pce_fast/huc.cpp:284-304")])

    def test_offsets_match_the_scalar(self):
        from scripts.profile_sync import ref_prose_text

        ref = "a.c:1-2, 5 (see b.c:7)"
        masked = ref_prose_text(ref)
        self.assertEqual(len(masked), len(ref))
        self.assertEqual(masked.index("b.c:7"), ref.index("b.c:7"))
        self.assertNotIn("a.c", masked)


class TriageSurvivesAForgeRefusal(unittest.TestCase):
    """git.eden-emu.dev answers 403 to commit lookups: `--all --triage`
    died on the traceback after half an hour and printed no ranking."""

    def test_the_ranking_is_printed_with_the_profile_marked(self):
        from types import SimpleNamespace

        from scripts import profile_sync

        reports = [
            profile_sync.ProfileReport(name="eden", pin="a" * 40, head="b" * 40),
            profile_sync.ProfileReport(name="vice", pin="c" * 40, head="d" * 40),
        ]
        selected = {
            "eden": {"source": "https://git.eden-emu.dev/eden-emu/eden"},
            "vice": {"source": "https://github.com/libretro/vice-libretro"},
        }

        def check_version(profile, *_args):
            if "eden" in profile["source"]:
                raise profile_sync.upstream.UpstreamError("HTTP 403")
            return None

        args = SimpleNamespace(cache_dir="", offline=True)
        out = io.StringIO()
        with mock.patch.object(profile_sync, "check_version", check_version), \
                mock.patch.object(profile_sync, "select_repo", lambda p: object()), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            profile_sync._print_triage(args, selected, reports)
        # A header row and a closing count frame the ranking.
        lines = out.getvalue().splitlines()[1:-1]
        self.assertEqual(len(lines), 2)
        self.assertTrue(any("eden" in l and "unreachable" in l for l in lines))


class VerifyStrictAppliesInEveryMode(unittest.TestCase):
    """--strict was read only by the platform branch: `--emulator x --strict`
    printed MISSING (required) and exited 0, and the listings accepted it."""

    @classmethod
    def setUpClass(cls):
        if not (ROOT / "database.json").exists():
            raise unittest.SkipTest("database.json is not built")
        cls.dir = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        (cls.dir / "fakeemu.yml").write_text(
            "emulator: FakeEmu\ntype: libretro\nsystems: [zz-console]\nfiles:\n"
            "  - name: does_not_exist_strict.bin\n    required: true\n"
            "    md5: 0123456789abcdef0123456789abcdef\n    validation: [md5]\n"
        )

    @classmethod
    def tearDownClass(cls):
        __import__("shutil").rmtree(cls.dir, True)

    def run_verify(self, *flags: str) -> int:
        return subprocess.run(
            [sys.executable, "scripts/verify.py", *flags], cwd=ROOT,
            capture_output=True, text=True,
        ).returncode

    def test_emulator_and_system_modes_fail_on_a_missing_required_file(self):
        for mode in (["--emulator", "fakeemu"], ["--system", "zz-console"]):
            with self.subTest(mode=mode[0]):
                flags = [*mode, "--emulators-dir", str(self.dir)]
                self.assertEqual(self.run_verify(*flags), 0)
                self.assertEqual(self.run_verify(*flags, "--strict"), 1)

    def test_a_listing_refuses_strict(self):
        self.assertEqual(self.run_verify("--list-emulators", "--strict"), 2)


class OpenMsxRomsSitInItsSystemroms(unittest.TestCase):
    """openMSX entries had no path and landed at the BIOS root, where no
    frontend points FilePool. The profile writes share/systemroms below
    openMSX's user folder, the pool's first place (src/file/FilePool.cc,
    FileOperations.cc), and RetroBat, which sets OPENMSX_HOME to
    bios/openmsx and declares its ROMs under openMSX/share/systemroms, gets
    them there."""

    def test_every_entry_is_under_share_systemroms(self):
        from scripts.common import (  # noqa: PLC0415
            load_emulator_profiles,
            load_platform_config,
            platform_layouts,
            standalone_set,
        )

        profile = load_emulator_profiles(str(ROOT / "emulators"))["openmsx"]
        retrobat = yaml.safe_load((ROOT / "platforms" / "retrobat.yml").read_text())
        declared_dirs = {
            fe["destination"].rsplit("/", 1)[0].lower()
            for system in retrobat["systems"].values()
            for fe in system.get("files", [])
            if "systemroms" in fe.get("destination", "")
        }
        self.assertEqual(declared_dirs, {"openmsx/share/systemroms"})
        config = load_platform_config("retrobat", str(ROOT / "platforms"))
        ((view, _standalone),) = platform_layouts("openmsx", profile, standalone_set(config))
        placed = {f["name"]: f for f in view["files"]}
        for entry in profile["files"]:
            with self.subTest(name=entry["name"]):
                self.assertEqual(entry.get("path", "").lower(),
                                 f"share/systemroms/{entry['name']}".lower())
                self.assertEqual(placed[entry["name"]].get("standalone_path", "").lower(),
                                 f"openmsx/share/systemroms/{entry['name']}".lower())


class ASameNamedMemberIsNotTheFile(unittest.TestCase):
    """The gap report counted touchhle's LiberationMono-Regular.ttf as held
    because idtech4a++'s extras.zip has a member of that name, another font,
    while verify --emulator said missing."""

    def test_a_declared_hash_decides_a_member_or_data_hit(self):
        from scripts import cross_reference as xr

        tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        (tmp / "data").mkdir()
        (tmp / "data" / "font.ttf").write_bytes(b"DATA FONT")
        (tmp / "bios").mkdir()
        with zipfile.ZipFile(tmp / "bios" / "extras.zip", "w") as zf:
            zf.writestr("files/other.ttf", b"MEMBER FONT")
        names = xr._build_supplemental_index(str(tmp / "data"), str(tmp / "bios"))
        locations = xr._supplemental_locations(str(tmp / "data"), str(tmp / "bios"))
        with mock.patch.object(xr, "_supplemental_locations", lambda: locations):
            for fname, data in (("font.ttf", b"DATA FONT"), ("other.ttf", b"MEMBER FONT")):
                with self.subTest(name=fname):
                    held = {"name": fname, "sha1": hashlib.sha1(data).hexdigest()}
                    other = {"name": fname, "sha1": "0" * 40}
                    self.assertTrue(xr._data_hit(fname, None, held, names))
                    self.assertFalse(xr._data_hit(fname, None, other, names))
                    self.assertTrue(xr._data_hit(fname, None, {"name": fname}, names))


class AnEmptyTargetIsNotEveryCore(unittest.TestCase):
    """A board scraped with `cores: []` and `add_cores: [gpsp]`: the pack
    served gpsp's files only, the published list said null (every core)."""

    def test_the_published_list_is_the_builder_reading(self):
        from scripts.common import load_target_config
        from scripts.generate_pack import generate_target_manifests

        tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        targets = tmp / "platforms" / "targets"
        targets.mkdir(parents=True)
        (targets / "demo.yml").write_text(
            "platform: demo\ntargets:\n"
            "  board:\n    architecture: aarch64\n    cores: []\n"
            "  full:\n    architecture: x86_64\n    cores: null\n"
        )
        (targets / "_overrides.yml").write_text(
            "demo:\n  targets:\n    board:\n      add_cores: [gpsp]\n"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            generate_target_manifests(str(targets), str(tmp / "out"))
        published = json.loads((tmp / "out" / "demo.json").read_text())
        builder = load_target_config("demo", "board", str(tmp / "platforms"))
        self.assertEqual(published["board"], sorted(builder))
        self.assertEqual(published["board"], ["gpsp"])
        self.assertIsNone(published["full"])


class ADataDirectoryIsHeldWhileRead(unittest.TestCase):
    """A pack resolved names against data/bluemsx, then a concurrent refresh
    swapped the tree: the index named files that were gone and the copy
    died on FileNotFoundError, or shipped bytes nobody had verified."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_ROOT))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, True))

    def test_the_index_follows_a_swapped_tree(self):
        from scripts import common

        cache = self.tmp / "cache"
        cache.mkdir()
        (cache / "old.rom").write_bytes(b"old")
        self.assertIn("old.rom", common._data_dir_basenames(str(cache)))
        cache.rename(self.tmp / "gone")
        cache.mkdir()
        (cache / "new.rom").write_bytes(b"new")
        index = common._data_dir_basenames(str(cache))
        self.assertIn("new.rom", index)
        self.assertNotIn("old.rom", index)

    def test_a_holder_makes_the_refresh_lock_wait(self):
        import fcntl

        from scripts import refresh_data_dirs

        cache = self.tmp / "bluemsx"
        cache.mkdir()
        lock = cache.with_name(f".{cache.name}.lock")

        def exclusive_free() -> bool:
            with open(lock, "a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return False
                fcntl.flock(handle, fcntl.LOCK_UN)
                return True

        with contextlib.ExitStack() as held:
            refresh_data_dirs.hold_data_dirs(held, {"bluemsx": {"local_cache": str(cache)}})
            self.assertFalse(exclusive_free())
        self.assertTrue(exclusive_free())

    def test_a_cache_not_yet_on_disk_is_held_too(self):
        """Skipped while absent, a tree a refresh installed mid-run was
        missing for verify and present for the packs of the same run."""
        import fcntl

        from scripts import refresh_data_dirs

        cache = self.tmp / "absent"
        lock = cache.with_name(f".{cache.name}.lock")
        with contextlib.ExitStack() as held:
            refresh_data_dirs.hold_data_dirs(held, {"absent": {"local_cache": str(cache)}})
            self.assertFalse(cache.exists())
            with open(lock, "a") as handle, self.assertRaises(BlockingIOError):
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_both_entry_points_hold_the_trees(self):
        pack = (ROOT / "scripts" / "generate_pack.py").read_text()
        verify_src = (ROOT / "scripts" / "verify.py").read_text()
        self.assertIn("hold_data_dirs(held,", verify_src)
        refresh = pack.index("results = refresh_all(")
        self.assertIn("hold_data_dirs(held, data_registry)", pack[refresh:])

    def test_verify_packs_alone_holds_the_trees(self):
        # --verify-packs returned before the hold and resolved core files
        # against data/ while a refresh could swap a tree.
        pack = (ROOT / "scripts" / "generate_pack.py").read_text()
        branch = pack.index("if args.verify_packs and not args.all_variants:")
        run = pack.index("_run_verify_packs(args)", branch)
        self.assertIn("hold_data_dirs(held,", pack[branch:run])


class EachRootReadsItsOwnRegistry(unittest.TestCase):
    """The release-asset registry was cached once per process whatever root
    was asked: a second tree got the first tree's .gitignore."""

    def test_two_roots_in_one_process(self):
        from scripts import generate_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as a, \
                tempfile.TemporaryDirectory(dir=TMP_ROOT) as b:
            Path(a, ".gitignore").write_text("bios/one.bin\n")
            Path(b, ".gitignore").write_text("bios/two.bin\n")
            self.assertTrue(generate_pack._is_release_asset(str(Path(a, "bios/one.bin")), a))
            self.assertFalse(generate_pack._is_release_asset(str(Path(b, "bios/one.bin")), b))
            self.assertTrue(generate_pack._is_release_asset(str(Path(b, "bios/two.bin")), b))

    def test_one_parser_reads_the_registry(self):
        for module in ("generate_pack.py", "generate_db.py"):
            source = (ROOT / "scripts" / module).read_text()
            with self.subTest(module=module):
                self.assertIn("load_registered_paths", source)
                self.assertNotIn('startswith("bios/")\n    }', source)



class TheSiteCountsSlotsNotVersions(unittest.TestCase):
    """raze lists every GRP its code accepts under one name: the site said
    59 files, 46 missing, where verify --emulator said 23 slots, 12 missing."""

    def test_one_held_version_fills_the_slot(self):
        from scripts.generate_site import _emulator_file_summary, _emulator_held_line

        files = [
            {"name": "DUKE3D.GRP", "crc32": "1"},
            {"name": "DUKE3D.GRP", "crc32": "2"},
            {"name": "BLOOD.RFF", "crc32": "3"},
        ]
        line = _emulator_file_summary(files)[0]
        self.assertIn("**2 files** (3 accepted versions)", line)
        held = _emulator_held_line(files, lambda f: f.get("crc32") == "2")[0]
        self.assertIn("1 in repo and 1 missing", held)



class EveryReadmeNamesItsFolder(unittest.TestCase):
    """The Lakka pack's README reused RetroArch's guide and never named
    /storage/system, the folder the registry and the installer use."""

    def test_the_registry_folder_is_in_the_guide(self):
        from scripts.packreadme import _build_readme

        registry = yaml.safe_load((ROOT / "platforms" / "_registry.yml").read_text())
        for name, entry in registry["platforms"].items():
            folder = (entry.get("extract_to") or "").rstrip("/")
            if not folder:
                continue
            with self.subTest(platform=name):
                text = _build_readme(name, name, "", 1, 1,
                                     detect=[{"os": "linux", "bios_path": folder}])
                self.assertIn(folder, text)
        lakka = _build_readme("lakka", "Lakka", "", 1, 1)
        self.assertNotIn("retroarch/system", lakka)



class NoSourceWarnsWhenCompiled(unittest.TestCase):
    """A docstring naming C:\\RetroArch-Win64 with one backslash compiled to
    an invalid escape: a SyntaxWarning on every run of the installer."""

    def test_every_script_compiles_clean(self):
        import warnings

        sources = [ROOT / "install.py", *sorted((ROOT / "scripts").rglob("*.py"))]
        for path in sources:
            with self.subTest(path=path.name), warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                warnings.simplefilter("error", DeprecationWarning)
                compile(path.read_text(encoding="utf-8"), str(path), "exec")


class TheInstallerNamesWhatItSkipped(unittest.TestCase):
    def test_count_agrees_and_required_files_are_named(self):
        one = install._omission_lines(1, [{"name": "diabdat.mpq", "required": True}])
        self.assertTrue(one[0].startswith("1 file was not installed"))
        self.assertTrue(any("diabdat.mpq" in line for line in one[1:]))
        many = install._omission_lines(
            12,
            [{"name": f"f{i:02}", "required": True, "system": f"s{i:02}",
              "cores": ["core"]} for i in range(12)],
        )
        self.assertTrue(many[0].startswith("12 files were not installed"))
        self.assertIn("    s00 (core): f00", many)
        self.assertTrue(any("and 4 more systems" in line for line in many))



class EveryToolRefusesAFlagItWouldDrop(unittest.TestCase):
    """The mode x flag matrix existed for generate_pack only: verify took
    --strict in --emulator mode and ignored it, pipeline took --source with
    --skip-packs and built nothing. Each pair here must exit non-zero
    before doing any work."""

    REFUSED = {
        "scripts/verify.py": [
            ["--list-emulators", "--strict"],
            ["--list-emulators", "--verbose"],
            ["--list-emulators", "--json"],
            ["--list-systems", "--region", "us"],
            ["--emulator", "handy", "--target", "switch"],
            ["--platform", "retroarch", "--standalone"],
        ],
        "scripts/pipeline.py": [
            ["--offline", "--skip-packs", "--source", "truth"],
            ["--offline", "--skip-packs", "--all-variants"],
            ["--offline", "--skip-packs", "--full-narrowings"],
            ["--offline", "--all-variants", "--source", "platform"],
            ["--offline", "--all-variants", "--source", "full"],
            ["--offline", "--skip-packs", "--source", "full"],
            ["--offline", "--source", "truth", "--full-narrowings"],
            ["--offline", "--source", "platform", "--full-narrowings"],
        ],
        # The expert narrowings: what the pack builder refuses beside its
        # option of the same name, and a flag with no mode to apply it.
        "install.py": [
            ["--json"],
            ["--standalone"],
            ["--emulator", "duckstation", "--standalone", "--region", "us"],
            ["--emulator", "duckstation", "--standalone", "--one-per-slot"],
            ["--one-per-slot", "--system", "sony-playstation"],
            ["--one-per-slot", "--emulator", "duckstation"],
            ["--one-per-slot", "--for-games"],
            ["--one-per-slot", "--declared-only"],
            ["--one-per-slot", "--list-systems"],
            ["--source", "truth", "--system", "sony-playstation"],
            ["--source", "truth", "--target", "switch"],
            ["--source", "truth", "--one-per-slot"],
            ["--source", "truth", "--tui"],
            ["--source", "platform"],
            ["--find", "0" * 40, "--system", "sony-playstation"],
            ["--find", "0" * 40, "--one-per-slot"],
            ["--find", "0" * 40, "--check"],
            ["--find", "0" * 40, "--list-systems"],
            ["--find", "0" * 40, "--json", "--events"],
            ["--find", "0" * 40, "--json", "--pack", "tmp/"],
            ["--find", "0" * 40, "--json", "--add-app"],
            ["--find", "0" * 40, "--json", "--standalone-copies"],
            ["--find", "0" * 40, "--json", "--romm-firmware", "{platform}/bios"],
            ["--find", "0" * 40, "--json", "--from", "tmp"],
            ["--find", "0" * 40, "--pack", "tmp/"],
            ["--find", "not-a-hash"],
            ["--find", "0" * 12],
        ],
    }

    def test_each_pair_is_refused(self):
        for script, cases in self.REFUSED.items():
            for argv in cases:
                with self.subTest(script=script, argv=argv):
                    proc = subprocess.run(
                        [sys.executable, script, *argv], cwd=ROOT,
                        capture_output=True, text=True, timeout=120,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)



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
            capture_output=True, text=True, cwd=ROOT, check=False,
        ).stdout.splitlines()
        self.assertTrue(listed)
        self.assertEqual([line for line in listed if "-t ." not in line], [])



class TheWantedPageCountsRomsetMembers(unittest.TestCase):
    """The site called build_report without archive_members: the public
    Wanted page asked for dumps the collection holds inside romsets."""

    def test_members_are_read_unless_given(self):
        from scripts import provenance_report

        calls = []

        def members(db):
            calls.append(db)
            return {}

        with mock.patch.object(provenance_report, "archive_members", members):
            provenance_report.build_report({"files": {}}, {})
            provenance_report.build_report({"files": {}}, {}, {})
        self.assertEqual(len(calls), 1)



class AutoFetchAsksVerifyWhatIsMissing(unittest.TestCase):
    """auto_fetch judged presence by sha1 or md5 in the database: Batocera's
    pc6001.zip, checked inside the zip and held, was a target, and no core
    file was ever one. 721 announced where verify saw none critical."""

    def test_the_targets_are_verify_verdicts(self):
        from scripts import auto_fetch
        import verify as verify_mod

        config = {"verification_mode": "md5", "systems": {"s": {"files": [
            {"name": "ok.bin", "md5": "1" * 32},
            {"name": "gone.bin", "md5": "2" * 32},
            {"name": "bad.bin", "md5": "3" * 32},
        ]}}}
        result = {
            "details": [
                {"system": "s", "name": "ok.bin", "status": verify_mod.Status.OK},
                {"system": "s", "name": "gone.bin", "status": verify_mod.Status.MISSING},
                {"system": "s", "name": "bad.bin", "status": verify_mod.Status.UNTESTED},
            ],
            "undeclared_files": [
                {"name": "diabdat.mpq", "in_repo": False, "required": True,
                 "system": "diablo", "emulator": "DevilutionX"},
                {"name": "held.bin", "in_repo": True, "required": True},
                {"name": "extra.bin", "in_repo": False, "required": False},
                # zesarux installs 128s.rom with the emulator: not a target,
                # and a copy placed in bios/ fails pipeline step 4d.
                {"name": "128s.rom", "in_repo": False, "required": True,
                 "bundled": True, "emulator": "ZEsarUX"},
            ],
        }
        with mock.patch.object(verify_mod, "verify_platform", lambda c, d: result):
            names = [m["name"] for m in auto_fetch.find_missing(config, {})]
        self.assertEqual(names, ["gone.bin", "bad.bin", "diabdat.mpq"])



class MessagesSeparateWithAColon(unittest.TestCase):
    """Em-dashes were replaced by " -" in messages: "bios/BLOOD.RFF -raze
    says size mismatch" reads as a flag glued to a file name."""

    PATTERN = re.compile(r"\} -[{a-z]")

    def test_no_message_uses_a_dash_separator(self):
        found = []
        for path in [ROOT / "install.py", *sorted((ROOT / "scripts").rglob("*.py"))]:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if self.PATTERN.search(line):
                    found.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(found, [])



class AReaderThatLeavesEarlyIsNoCrash(unittest.TestCase):
    """`verify.py --list-emulators | head -1` ended on a BrokenPipeError
    traceback, and so did every listing and report."""

    def test_a_closed_pipe_ends_quietly(self):
        proc = subprocess.Popen(
            [sys.executable, "scripts/verify.py", "--list-emulators"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # The listing fits a 64 KiB pipe: a child that wrote it all before
        # the close below never met the broken pipe and exited 0. A 4 KiB
        # pipe keeps it writing when the reader leaves.
        try:
            import fcntl  # noqa: PLC0415

            fcntl.fcntl(proc.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
        except (ImportError, AttributeError, OSError):
            pass
        proc.stdout.readline()
        proc.stdout.close()
        _, err = proc.communicate(timeout=120)
        self.assertNotIn(b"Traceback", err)
        self.assertEqual(proc.returncode, 141)

    def test_every_entry_point_goes_through_run_cli(self):
        plain = re.compile(r'if __name__ == "__main__":\n    (main\(\)|sys\.exit\(main\(\)\))')
        found = [p.name for p in sorted((ROOT / "scripts").glob("*.py"))
                 if plain.search(p.read_text())]
        self.assertEqual(found, [])



class TheToolsPageSaysWhatDedupDoes(unittest.TestCase):
    """tools.md said duplicates move to .variants/ (they are deleted) and
    named 2 of the 11 directories dedup leaves alone."""

    def test_every_protected_tree_is_named(self):
        from scripts import dedup

        line = next(
            l for l in (ROOT / "wiki" / "tools.md").read_text().splitlines()
            if l.startswith("| `dedup.py`")
        )
        self.assertNotIn(".variants", line)
        for name in dedup.NODEDUP_DIRS:
            self.assertIn(name, line)



class ThePipelineTableNamesEveryStep(unittest.TestCase):
    """tools.md listed the steps without 1c, 2b2, 3a and 3b."""

    def test_every_labelled_step_is_documented(self):
        labels = set(re.findall(
            r'"(\d[a-z]?\d?)(?:/8)? [a-z]', (ROOT / "scripts" / "pipeline.py").read_text()
        ))
        doc = (ROOT / "wiki" / "tools.md").read_text()
        documented = set(re.findall(r"^\| (\d[a-z]?\d?)(?:/8)? \|", doc, re.MULTILINE))
        self.assertEqual(labels - documented, set())



class TheIssueFormListsEveryPlatform(unittest.TestCase):
    """The missing-BIOS form offered 7 of the 12 registered platforms."""

    def test_every_registered_platform_is_an_option(self):
        from scripts.common import list_registered_platforms, load_platform_config

        form = yaml.safe_load(
            (ROOT / ".github" / "ISSUE_TEMPLATE" / "missing-bios.yml").read_text()
        )
        options = next(
            item["attributes"]["options"] for item in form["body"]
            if item.get("id") == "platform"
        )
        for name in list_registered_platforms(str(ROOT / "platforms")):
            display = load_platform_config(name, str(ROOT / "platforms"))["platform"]
            self.assertIn(display, options)



class TheTestJobHasTheDataTrees(unittest.TestCase):
    """Packs built without data directories exit non-zero, but the CI test job
    had none, and two pack parity tests failed there only."""

    def test_the_trees_are_fetched_before_the_suite(self):
        steps = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "validate.yml").read_text()
        )["jobs"]["run-tests"]["steps"]
        runs = [step.get("run", "") for step in steps]
        fetch = next(i for i, run in enumerate(runs) if "refresh_data_dirs.py" in run)
        suite = next(i for i, run in enumerate(runs) if "unittest discover" in run)
        self.assertLess(fetch, suite)



class VerifyPacksSaysWhatItExcluded(unittest.TestCase):
    """--verify-packs read the result tuple by position, dropped the unsafe
    exclusions (352/353 shown as OK with no reason) and printed 5 errors."""

    def test_the_result_is_unpacked_whole_and_every_error_printed(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text()
        body = source[source.index("def _run_verify_packs"):]
        body = body[:body.index("\ndef ")]
        self.assertIn("bl_excluded, bl_absent) = result", body)
        self.assertIn("_baseline_shortfall(bl_excluded, bl_absent)", body)
        shortfall = source[source.index("def _baseline_shortfall"):]
        self.assertIn("unsafe excluded", shortfall[:shortfall.index("\ndef ")])
        self.assertNotIn("errors[:5]", body)
        self.assertNotRegex(body, r"result\[\d\]")



class TheGapReportKeepsItsShape(unittest.TestCase):
    """Multi-line notes fell to column 0 and read as emulator headings, a
    profile without systems printed `Abuse ()`, `*` had no legend, and
    --platform totals said "across all emulators"."""

    def test_layout(self):
        from scripts.cross_reference import print_report

        report = {"abuse": {
            "emulator": "Abuse", "systems": [], "gaps": 1, "total_files": 1,
            "platform_covered": 0, "gap_missing": 1,
            "gap_details": [{"name": "a.spe", "required": True, "source": "missing",
                             "note": "first line\nsecond line"}],
        }}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_report(report, "the emulators batocera runs")
        text = out.getvalue()
        self.assertIn("* marks a file the emulator requires", text)
        self.assertIn("\nAbuse\n", text)
        self.assertIn("a.spe [MISSING]: first line second line", text)
        self.assertIn("across the emulators batocera runs", text)



class AFileToSourceIsAFileNotAName(unittest.TestCase):
    """The gaps page keyed acquisition targets by name: Fallout 2's
    master.dat disappeared behind Fallout 1's."""

    def test_rows_are_keyed_by_name_and_hash(self):
        source = (ROOT / "scripts" / "generate_site.py").read_text()
        self.assertIn('key = (g["name"], g.get("identity") or f"emulator:{emu_name}")', source)
        from scripts.cross_reference import _first_hash

        self.assertEqual(_first_hash({"md5": ["AB", "cd"]}), "md5:ab")
        self.assertEqual(_first_hash({"crc32": "1", "sha1": "F" * 40}), "sha1:" + "f" * 40)
        self.assertEqual(_first_hash({}), "")



class GeneratedArtifactsMeetTheirSchemas(unittest.TestCase):
    """A manifest field added without its schema passed every local test
    and failed the site deploy, which is the first run of the full check."""

    @unittest.skipUnless(HAS_JSONSCHEMA, "needs jsonschema")
    def test_the_full_schema_check_passes(self):
        proc = subprocess.run(
            [sys.executable, "scripts/validate_schemas.py"], cwd=ROOT,
            capture_output=True, text=True, timeout=600,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)



class AFileCardSaysAllItKnows(unittest.TestCase):
    """Emulator pages cut a set at 10 members without their hashes, never
    showed standalone_path, and gave no file an anchor to link to."""

    def test_members_standalone_path_and_anchor(self):
        from scripts.generate_site import _render_emulator_file

        entry = {
            "name": "neogeo.zip", "path": "neogeo.zip", "category": "bios_zip",
            "standalone_path": "Firmware/neogeo.zip",
            "contents": [{"name": f"m{i}.bin", "size": 1024, "crc32": f"{i:08x}"}
                         for i in range(12)],
        }
        text = "\n".join(_render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: True, "file-neogeo-zip",
        ))
        # The card is a heading with this id, linked by the heading's own
        # permalink.
        self.assertIn('<h3 id="file-neogeo-zip" class="rb-file-title"', text)
        self.assertIn("Standalone path: `Firmware/neogeo.zip`", text)
        self.assertIn("`m11.bin`", text)
        self.assertIn("CRC32 `0000000b`", text)
        self.assertNotIn("more", text)



class EmulatorPagesStateTheirDataForMachines(unittest.TestCase):
    """Every emulator page's JSON-LD differed only by name and url."""

    def test_source_pin_date_and_files(self):
        from scripts.generate_site import emulator_structured_data

        data = emulator_structured_data({
            "emulator": "DuckStation", "source": "https://github.com/stenzek/duckstation",
            "source_commit": "4122fed9", "core_version": "v0.1-12070",
            "profiled_date": "2026-03-23",
            "files": [{"name": "scph5501.bin", "md5": "490F666E", "sha1": ["a" * 40]},
                      {"name": "free.bin"}],
        })
        self.assertEqual(data["about"]["codeRepository"], "https://github.com/stenzek/duckstation")
        # The release the profile describes, never the pin.
        self.assertEqual(data["about"]["version"], "v0.1-12070")
        self.assertNotIn("description", data["about"])
        self.assertEqual(data["dateModified"], "2026-03-23")
        self.assertEqual(data["hasPart"][0]["identifier"], ["sha1:" + "a" * 40, "md5:490f666e"])
        self.assertNotIn("identifier", data["hasPart"][1])

    def test_every_repository_with_its_own_release(self):
        """xemu's libretro build lives in another repository. Each source
        repository states the release of its build, a version holding a
        commit id states none, and a port's upstream is another code base."""
        from scripts.generate_site import emulator_structured_data

        data = emulator_structured_data({
            "emulator": "MesenCE",
            "source": {"standalone": "https://github.com/nesdev-org/MesenCE",
                       "libretro": "https://github.com/libretro/MesenCE"},
            "source_commit": {"standalone": "f9b14039", "libretro": "d9804db7"},
            "core_version": {"standalone": "2.2.1", "libretro": "2.0.0"},
            "upstream": "https://github.com/SourMesen/Mesen2", "upstream_commit": "aa11",
        })
        self.assertEqual(
            [(a["codeRepository"].rsplit("/", 1)[1], a.get("version")) for a in data["about"]],
            [("MesenCE", "2.2.1"), ("MesenCE", "2.0.0"), ("Mesen2", None)])
        xemu = emulator_structured_data({
            "emulator": "xemu",
            "source": {"standalone": "https://github.com/xemu-project/xemu",
                       "libretro": "https://github.com/LibretroAdmin/xemu-libretro"},
            "core_version": {"standalone": "0.8.139-2-g25e1ee2fd5",
                             "libretro": "libretro-experimental"},
        })
        self.assertEqual([a.get("version") for a in xemu["about"]], [None, None])



class AManifestHashesAFileOnce(unittest.TestCase):
    """Every manifest entry rehashed its file with five algorithms: 70 476
    calls for 15 011 files, 163 s of a 218 s step."""

    def test_verified_hashes_are_reused(self):
        from scripts import generate_pack

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            path = Path(tmp, "a.bin")
            path.write_bytes(b"abc")
            sha1 = hashlib.sha1(b"abc").hexdigest()
            db = {"files": {sha1: {"path": str(path)}}}
            calls = []
            real = generate_pack.compute_hashes

            def counting(file_path, algorithms=None):
                calls.append(algorithms)
                return real(file_path, algorithms)

            with mock.patch.object(generate_pack, "compute_hashes", counting):
                first = generate_pack._stable_hashes(str(path), db)
                second = generate_pack._stable_hashes(str(path), db)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], frozenset({"sha1", "sha256"}))



class AZipMemberIsHashedOnce(unittest.TestCase):
    """check_inside_zip decompressed a member for every md5 candidate and
    every step: 4 788 times for 355 members in verify --all."""

    def test_repeated_questions_read_the_archive_once(self):
        from scripts import ziptools

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            archive = Path(tmp, "set.zip")
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("ROM.bin", b"abc")
            good = hashlib.md5(b"abc").hexdigest()
            opened = []
            real = ziptools.zipfile.ZipFile

            def counting(*args, **kwargs):
                opened.append(args[0])
                return real(*args, **kwargs)

            with mock.patch.object(ziptools.zipfile, "ZipFile", counting):
                answers = [ziptools.check_inside_zip(str(archive), "rom.bin", md5)
                           for md5 in (good, "0" * 32, good)]
        self.assertEqual(answers, ["ok", "untested", "ok"])
        self.assertEqual(len(opened), 1)



class CompanionsComeFromADirectoryIndex(unittest.TestCase):
    """_companions walked the whole database per scanned image."""

    def test_same_answer_one_walk(self):
        from scripts import packextras

        files_db = {
            "a": {"path": "bios/Sony/PS2/ps2.bin", "name": "ps2.bin"},
            "b": {"path": "bios/Sony/PS2/ps2.bin.rom1", "name": "ps2.bin.rom1"},
            "c": {"path": "bios/Sony/PS2/ps2.nvm", "name": "ps2.nvm"},
            "d": {"path": "bios/Other/ps2.nvm", "name": "ps2.nvm"},
        }
        found = packextras._companions("bios/Sony/PS2/ps2.bin", "ps2.bin", {"rom1", "nvm"}, files_db)
        self.assertEqual([sha1 for sha1, _ in found], ["b", "c"])
        index = packextras._files_by_directory(files_db)
        self.assertIs(packextras._files_by_directory(files_db), index)



class TargetListsReadThePinnedRelease(unittest.TestCase):
    """Each target scraper asked upstream for its latest tag: a Recalbox
    10.2 board list could filter 10.1.1 systems, and Batocera's target file
    did not even record the tag it read."""

    def test_the_revision_comes_from_the_platform_yaml(self):
        from scripts.scraper.targets import BaseTargetScraper

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            for name, source, tag in (
                ("a", "https://raw.githubusercontent.com/o/r/batocera-43.1/x/y", "batocera-43.1"),
                ("b", "https://gitlab.com/recalbox/recalbox/-/raw/10.1.1/a/b.xml", "10.1.1"),
                ("c", "https://github.com/o/r/blob/v2/f.cs", "v2"),
            ):
                Path(tmp, f"{name}.yml").write_text(f"source: {source}\n")
                self.assertEqual(BaseTargetScraper.pinned_revision(name, tmp), tag)
            Path(tmp, "d.yml").write_text("source: https://example.test/x\n")
            with self.assertRaises(RuntimeError):
                BaseTargetScraper.pinned_revision("d", tmp)

    def test_no_target_scraper_asks_for_the_latest_tag(self):
        for name in ("batocera", "rocknix", "recalbox"):
            source = (ROOT / "scripts" / "scraper" / "targets" / f"{name}_targets_scraper.py").read_text()
            with self.subTest(scraper=name):
                # The Batocera scraper reads the pin of the platform it is
                # instantiated for (KNULLI subclasses it).
                self.assertTrue(
                    "self.pinned_revision(PLATFORM_NAME)" in source
                    or "self.pinned_revision(self.PLATFORM)" in source
                )
                self.assertNotIn("fetch_stable_tag()", source)
                self.assertNotIn("fetch_github_latest_version(", source)



class SignaturesCarryTheirTypes(unittest.TestCase):
    """Type hints on every signature is a written rule; 177 had none, the
    shared API among them (artifact locks, the data-dir resolver, the region
    priority list of _select_variants)."""

    # Lowered as modules are annotated, never raised.
    CEILING = 0
    COMPLETE = ("artifacts.py", "common.py", "validation.py", "generate_pack.py")

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
        paths = [ROOT / "install.py", *sorted((ROOT / "scripts").rglob("*.py"))]
        missing = [m for path in paths for m in self._missing(path)]
        self.assertLessEqual(len(missing), self.CEILING, missing[:20])
        for name in self.COMPLETE:
            with self.subTest(module=name):
                self.assertEqual(self._missing(ROOT / "scripts" / name), [])



class ATreeNobodyHoldsIsMissingNotAnAsset(unittest.TestCase):
    """julius's caesar3/ directory, unexpanded, went to the asset store,
    which answered with .cache/large/ itself: the emulator pack died on
    IsADirectoryError where verify said MISSING."""

    def test_directory_entries_never_reach_the_asset_store(self):
        from scripts import largefiles, packresolve

        db = {"files": {}, "indexes": {"by_name": {}, "by_md5": {}, "by_crc32": {},
                                      "by_path_suffix": {}}}
        for entry in ({"name": "caesar3/", "type": "directory"}, {"name": "caesar3/"}):
            with self.subTest(entry=entry):
                self.assertEqual(
                    packresolve.resolve_file(entry, db, "bios", {}, offline=True),
                    (None, "not_found"),
                )
        self.assertIsNone(largefiles.fetch_large_file("caesar3/", offline=True))
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            Path(tmp, "sub").mkdir()
            self.assertIsNone(largefiles._fetch_asset("sub", tmp, "", "", offline=True))



class EmuDeckRunsItsEmulatorsStandalone(unittest.TestCase):
    """EmuDeck declared no standalone_cores: Dolphin, Cemu, xemu, ARMSX2 and
    Supermodel, installed as apps by EmuScripts, got the libretro layout and
    lost their standalone-only files."""

    def test_every_emuscripts_emulator_is_standalone(self):
        from scripts.common import load_platform_config, runs_standalone, load_emulator_profiles

        config = load_platform_config("emudeck", str(ROOT / "platforms"))
        self.assertEqual(
            sorted(config["standalone_cores"]),
            sorted(c for c in config["cores"] if c != "retroarch"),
        )
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        standalone = set(config["standalone_cores"])
        for name in ("dolphin", "cemu", "armsx2", "supermodel"):
            with self.subTest(emulator=name):
                self.assertTrue(runs_standalone(name, profiles[name], standalone))

    def test_retroarch_brings_its_libretro_cores(self):
        """The scraper dropped RetroArch's own script: np2kai, neocd and
        every core EmuDeck installs through RetroArch got no file that
        checkBIOS.sh does not name."""
        from scripts.common import (
            load_emulator_profiles, load_platform_config, resolve_platform_cores,
        )

        config = load_platform_config("emudeck", str(ROOT / "platforms"))
        self.assertIn("retroarch", config["cores"])
        cores = resolve_platform_cores(config, load_emulator_profiles(str(ROOT / "emulators")))
        for name in ("np2kai", "neocd", "dolphin"):
            with self.subTest(core=name):
                self.assertIn(name, cores)



class DocumentedHashLookupsFindTheirFile(unittest.TestCase):
    """The --from-md5 example was a test fixture hash: copied from the docs,
    it answered NOT FOUND, which then exited 0."""

    def test_every_documented_lookup_is_in_the_database(self):
        db = json.loads((ROOT / "database.json").read_text(encoding="utf-8"))
        by_md5 = db["indexes"]["by_md5"]
        found = 0
        for page in sorted((ROOT / "wiki").glob("*.md")):
            text = page.read_text(encoding="utf-8")
            for md5 in re.findall(r"--from-md5 ([0-9a-f]{32})\b", text):
                found += 1
                with self.subTest(page=page.name, md5=md5):
                    self.assertIn(md5, by_md5)
        self.assertGreater(found, 0)



class ToolReferenceListsEveryModule(unittest.TestCase):
    """The exporter table described retropie_exporter as a System.dat writer
    and left out bizhawk, misterfpga and rocknix, and the target table missed
    recalbox and rocknix. A contributor reads these tables as the map."""

    def _rows(self, heading: str) -> set[str]:
        text = (ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        section = text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        return set(re.findall(r"^\| `(\w+)` \|", section, re.M))

    def test_every_exporter_has_a_row(self):
        modules = {p.stem for p in (ROOT / "scripts" / "exporter").glob("*_exporter.py")}
        self.assertEqual(self._rows("Exporters"), modules - {"base_exporter"})

    def test_every_target_scraper_has_a_row(self):
        modules = {
            p.stem for p in (ROOT / "scripts" / "scraper" / "targets").glob("*_targets_scraper.py")
        }
        self.assertEqual(self._rows("Target scrapers"), modules)



class ToolReferenceCountsMatchTheirArtifacts(unittest.TestCase):
    """tools.md said 67 derivable entries for 79 and 1,113 identified
    archives for 1,181: counts written by hand drift from the tools."""

    def setUp(self):
        self.text = (ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")

    def test_recipe_store_counts(self):
        store = json.loads((ROOT / "recipes" / "mame.json").read_text(encoding="utf-8"))
        versions = {dat for entry in store["entries"] for dat in entry.get("dats") or [entry["dat"]]}
        listed = sum(len(entry.get("dats") or [entry["dat"]]) for entry in store["entries"])
        match = re.search(
            r"(\d+) MAME versions produce ([\d,]+) entries but only ([\d,]+)\s+distinct",
            self.text,
        )
        self.assertIsNotNone(match)
        stated = [int(group.replace(",", "")) for group in match.groups()]
        self.assertEqual(stated, [len(versions), listed, len(store["entries"])])

    def test_no_derivable_count(self):
        """The count now lives in derivable.json alone, which step 1b rewrites."""
        self.assertNotRegex(self.text, r"\d+ entries on the current snapshots")



class WikiProseHasNoTornSentence(unittest.TestCase):
    """tools.md read "replaces each destination atomically. The shell and /
    Both one-liners verify...": half of an old sentence left in front of
    its rewrite, on the page that explains the installer's trust boundary."""

    STARTERS = {"Both", "The", "This", "It", "A", "An", "Each", "Every", "When",
                "If", "They", "These", "That", "There"}

    def test_no_line_ends_on_a_function_word_before_a_new_sentence(self):
        for page in sorted((ROOT / "wiki").glob("*.md")):
            lines = page.read_text(encoding="utf-8").splitlines()
            in_code = False
            for number, (line, following) in enumerate(zip(lines, lines[1:]), 1):
                if line.startswith("```"):
                    in_code = not in_code
                if in_code:
                    continue
                if (re.search(r"\b(and|or|the|a|an|of|to)$", line.rstrip())
                        and following.split(" ")[0] in self.STARTERS):
                    self.fail(f"{page.name}:{number} ends mid-sentence: {line.strip()!r}")



class EveryOptionIsDocumented(unittest.TestCase):
    """profile_sync's --system, --stale-before and --ref, auto_fetch
    --create-issues, download.py --info and forty more were in no page: a
    maintainer ran --all and spent the API quota that --system would have
    saved. --help lists a flag, but only a page says when to reach for it."""

    def test_every_long_option_of_a_tracked_script_is_in_the_docs(self):
        tracked = subprocess.run(
            ["git", "ls-files", "scripts"], capture_output=True, text=True,
            cwd=str(ROOT), check=True,
        ).stdout.split()
        docs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [*sorted((ROOT / "wiki").glob("*.md")),
                         ROOT / "README.md", ROOT / "CONTRIBUTING.md"]
        )
        option = re.compile(r'add_argument\(\s*(?:"-\w",\s*)?"(--[\w-]+)"')
        undocumented = sorted(
            f"{name}: {flag}"
            for name in tracked if name.endswith(".py")
            for flag in set(option.findall((ROOT / name).read_text(encoding="utf-8")))
            if not re.search(re.escape(flag) + r"(?![\w-])", docs)
        )
        self.assertEqual(undocumented, [])



class OfflineHelpSaysWhatItCuts(unittest.TestCase):
    """--offline read "Skip data directory freshness check" while it also
    stops release assets from downloading: on a fresh clone the gitignored
    files were missing from the pack and nothing had announced it."""

    def test_both_helps_name_the_release_assets(self):
        for script in ("generate_pack.py", "pipeline.py"):
            with self.subTest(script=script):
                out = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--help"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True,
                ).stdout
                block = out.split("--offline", 2)[-1].split("\n  --", 1)[0]
                self.assertIn("release", " ".join(block.split()))



class PipelineDocstringNamesThePrintedSteps(unittest.TestCase):
    """The docstring numbered 1 to 9 while the run prints 1/8 to 8/8, and
    had no 2a, 2b, 3a, 3b or 6: a reader of a failed `6/8 pack integrity`
    found nothing under 6."""

    def test_the_two_lists_hold_the_same_steps(self):
        import ast

        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        doc = ast.get_docstring(ast.parse(source))
        listed = set(re.findall(r"^  (\d[a-z0-9]*)\s{2,}", doc, re.M))
        sys.path.insert(0, str(ROOT / "scripts"))
        import pipeline

        printed = {pipeline.step_number(key) for key in pipeline.STEP_LABELS}
        self.assertEqual(listed, printed)



class VerifyAllSummaryNamesWhatIsWrong(unittest.TestCase):
    """The closing line counted platform severities only: a required core
    file missing on ROCKNIX was absent from it, and the one warning did not
    say which platform carried it."""

    def test_counts_carry_platforms_and_core_misses(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify

        clean = {"severity_counts": {}, "undeclared_files": []}
        warned = {"severity_counts": {verify.Severity.WARNING: 1}, "undeclared_files": []}
        core_miss = {
            "severity_counts": {},
            "undeclared_files": [{
                "name": "n64.psh", "required": True, "in_repo": False,
                "category": "bios", "in_pack": True,
            }],
        }
        summary = verify._overall_summary(
            [(clean, ["RetroArch"]), (warned, ["RetroDECK"]), (core_miss, ["ROCKNIX"])]
        )
        self.assertIn("1 warning (RetroDECK 1)", summary)
        self.assertIn("n64.psh (ROCKNIX)", summary)
        self.assertIn("0 critical,", summary)

    def test_a_file_missing_on_several_platforms_is_counted_once(self):
        """sfiii2a.zip missing on 15 platforms read '24 core file(s)' for 10
        distinct files, the name printed 15 times on one line."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify

        def missing(*names: str) -> dict:
            return {"severity_counts": {}, "undeclared_files": [
                {"name": name, "required": True, "in_repo": False,
                 "category": "bios", "in_pack": True} for name in names
            ]}

        summary = verify._overall_summary([
            (missing("sfiii2a.zip"), ["Batocera"]),
            (missing("sfiii2a.zip", "ROM"), ["RetroPie"]),
            (missing("sfiii2a.zip"), ["RomM"]),
            (missing(), ["MinUI"]),
        ])
        self.assertIn(
            "2 core file(s) a core cannot run without are missing: "
            "sfiii2a.zip (every platform but MinUI); ROM (RetroPie)",
            summary,
        )
        self.assertEqual(summary.count("sfiii2a.zip"), 1)



class OneOutputFormPerRun(unittest.TestCase):
    """`diff_truth.py --json --format markdown` printed JSON with rc 0, the
    markdown asked for dropped without a word."""

    def test_json_and_markdown_are_refused_together(self):
        for script, argv in (
            ("diff_truth.py", ["--platform", "romm", "--json", "--format", "markdown"]),
            ("diff_truth.py", ["--platform", "romm", "--json", "--markdown"]),
            ("validate_pr.py", ["--json", "--markdown", "bios/Sony/PlayStation/scph5501.bin"]),
        ):
            with self.subTest(script=script, argv=argv):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", *argv], capture_output=True,
                    text=True, cwd=str(ROOT), timeout=120, check=False,
                )
                self.assertEqual(proc.returncode, 2, proc.stdout[-300:])
                self.assertIn("not allowed with", proc.stderr)



class BundledFilesAreNotToSource(unittest.TestCase):
    """DaedalusX64's n64.psh, the shader library its renderer installs
    beside the binary, was reported as a required core file missing and
    listed among the files to source, with 19 more like it."""

    def test_verify_does_not_count_it_missing(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify

        entry = {"name": "n64.psh", "required": True, "in_repo": False,
                 "category": "bios", "in_pack": True, "bundled": True}
        self.assertEqual(verify._core_required_missing([entry]), [])
        summary = verify._overall_summary(
            [({"severity_counts": {}, "undeclared_files": [entry]}, ["ROCKNIX"])]
        )
        self.assertNotIn("n64.psh", summary)

    def test_the_site_gives_it_its_own_status(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import generate_site

        rows = generate_site._gap_export_rows({}, {"daedalusx64": {
            "emulator": "DaedalusX64", "systems": ["nintendo-64"],
            "gap_details": [{"name": "n64.psh", "source": "missing", "required": True,
                             "in_repo": False, "bundled": True}],
        }})
        self.assertEqual([row["status"] for row in rows], ["bundled"])

    def test_a_held_bundled_file_is_not_packed(self):
        """A file installed with the emulator is already on the user's
        machine, so the pack leaves it out even when the collection holds it."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify

        entry = {"name": "n64.psh", "required": True, "in_repo": True,
                 "emulator": "daedalusx64", "category": "bios", "bundled": True}
        with mock.patch("packextras.unplaceable_extras", return_value={}):
            verify._mark_unplaced({}, [entry], {})
        self.assertFalse(entry["in_pack"])
        self.assertIn("installed with its emulator", entry["omitted"])

    def test_a_build_scope_keeps_it_for_the_other_build(self):
        """PPSSPP's standalone release ships assets/, its libretro core does
        not: bundled for one build, the entry still reaches a core's pack."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from validation import deliverable

        entries = [{"ref": "ppsspp-assets", "mode": "libretro"},
                   {"name": "a.bin", "bundled": True, "mode": "standalone"},
                   {"name": "b.bin", "bundled": True}]
        self.assertEqual([e.get("ref") or e["name"] for e in deliverable(entries, False)],
                         ["ppsspp-assets"])
        self.assertEqual(deliverable(entries, True), [])

    def test_a_platform_package_can_differ_both_ways(self):
        """Batocera's hcl package installs the binary alone, its blueMSX core
        package copies the machines beside the core."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from validation import installed_with_emulator

        hcl = {"name": "data.pak", "bundled": True, "not_bundled_on": ["batocera"]}
        machines = {"name": "Machines/MSX/config.ini", "installed_on": ["batocera", "retropie"]}
        self.assertTrue(installed_with_emulator(hcl, "retrobat"))
        self.assertFalse(installed_with_emulator(hcl, "batocera"))
        self.assertTrue(installed_with_emulator(machines, "retropie"))
        self.assertFalse(installed_with_emulator(machines, "retroarch"))
        self.assertTrue(installed_with_emulator(hcl))

    def test_every_platform_named_is_registered(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from common import list_registered_platforms, load_emulator_profiles

        known = set(list_registered_platforms(str(ROOT / "platforms")))
        unknown = sorted({
            (name, platform)
            for name, profile in load_emulator_profiles(str(ROOT / "emulators")).items()
            for entry in (profile.get("files") or []) + (profile.get("data_directories") or [])
            if isinstance(entry, dict)
            for field in ("installed_on", "not_bundled_on")
            for platform in entry.get(field) or []
            if platform not in known
        })
        self.assertEqual(unknown, [])

    def test_a_tree_the_platform_installs_leaves_its_pack(self):
        """retroarch.yml names dolphin-sys and ppsspp-assets and Lakka
        inherits them, while Lakka's core packages install both trees."""
        import tempfile

        import yaml as _yaml

        sys.path.insert(0, str(ROOT / "scripts"))
        import common

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            Path(tmp, "dolphin.yml").write_text(_yaml.safe_dump({
                "emulator": "Dolphin", "type": "libretro", "files": [],
                "data_directories": [{"ref": "dolphin-sys", "installed_on": ["lakka"]}]}))
            self.assertEqual(common.installed_data_refs("lakka", tmp), frozenset({"dolphin-sys"}))
            self.assertEqual(common.installed_data_refs("retroarch", tmp), frozenset())
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertIn("if ref_key in installed_data_refs(platform_name):", source)

    def test_the_pack_builder_skips_it(self):
        source = (ROOT / "scripts" / "packextras.py").read_text(encoding="utf-8")
        self.assertIn('if u.get("bundled"):', source)



class AdlerValuesReadLikeTheDownloads(unittest.TestCase):
    """The Dolphin card read Adler32: `['0x66f334fe', '0xe789b5a5']`, a list
    repr no download spells, and never said the values are taken over the
    byte-swapped ROM, so the raw ea3734fe in files.csv matched neither."""

    def test_values_and_the_swap_are_stated(self):
        from scripts.generate_site import _render_emulator_file

        entry = {"name": "dsp_rom.bin", "path": "dsp_rom.bin",
                 "known_hash_adler32": ["0x66f334fe", "0xE789B5A5"],
                 "adler32_byteswap": True}
        text = "\n".join(_render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: True, "file-dsp",
        ))
        self.assertIn("`66f334fe`, `e789b5a5`", text)
        self.assertIn("byte-swapped", text)
        self.assertNotIn("['", text)



class GapsPageCountsOneWay(unittest.TestCase):
    """The stats block said 1 untested (by destination) while Problem Files
    listed 4 untested entries, three of them at paths another declaration
    of the same platform already holds."""

    def test_settled_declarations_are_listed_apart(self):
        from scripts.generate_site import _render_problem_files

        problems = [{"platform": "RetroDECK", "name": "dsifirmware.bin", "status": "untested",
                     "required": True, "reason": "x", "discrepancy": ""}]
        settled = [{"platform": "RetroDECK", "name": "cdibios.zip", "status": "untested",
                    "held_by": "arcade"}]
        text = "\n".join(_render_problem_files(problems, settled))
        self.assertIn("0 missing, 1 untested", text)
        self.assertIn("Other revisions of a held destination", text)
        self.assertIn("`cdibios.zip`", text)

    def test_missing_says_the_destination_count_of_the_opening_sentence(self):
        # The page opened on "48 are missing" (by destination) above a
        # heading that said "10 files": one row per name.
        from scripts.generate_site import _render_problem_files

        problems = [{"platform": "AmberELEC", "name": "hardwareconfig.xml",
                     "status": "missing", "required": True, "reason": "",
                     "discrepancy": "", "category": "unread"}] * 3
        text = "\n".join(_render_problem_files(problems, missing_total=3))
        self.assertIn("3 missing under 1 name,", text)
        self.assertIn('rb-badge-danger">1 name</span>', text)
        self.assertNotIn("1 missing", text)

    def test_a_missing_row_links_each_entry_and_names_its_folder(self):
        """The row said `N88_KNJ1.ROM | unread | yes | AmberELEC` in plain text:
        neither where the list puts it nor which cores were examined."""
        from scripts.generate_site import _render_problem_files

        problems = [{"platform": "AmberELEC", "platform_key": "amberelec", "name": "N88_KNJ1.ROM",
                     "status": "missing", "required": True, "reason": "", "discrepancy": "",
                     "category": "unread", "system": "nec-pc-88",
                     "destination": "bios/quasi88/N88_KNJ1.ROM"}]
        text = "\n".join(_render_problem_files(problems))
        self.assertIn("| [AmberELEC](platforms/amberelec.md#nec-pc-88) "
                      "`bios/quasi88/N88_KNJ1.ROM` |", text)

    def test_the_destination_is_the_list_entrys(self):
        from scripts.generate_site import _declared_destination
        sys.path.insert(0, str(ROOT / "scripts"))
        from common import load_platform_config

        config = load_platform_config("amberelec", str(ROOT / "platforms"))
        detail = {"name": "N88_KNJ1.ROM", "system": "nec-pc-88"}
        self.assertEqual(_declared_destination(config, detail), "bios/quasi88/N88_KNJ1.ROM")

    def test_verify_marks_the_settled_entry(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify

        result = {"name": "cdibios.zip", "status": verify.Status.UNTESTED}
        self.assertTrue(verify._twin_unmet(result, "arcade"))
        self.assertEqual(result["settled_by"], "arcade")



class UnsourceableCardSaysWhy(unittest.TestCase):
    """DraStic's nds_firmware_modified.bin carried an 'unsourceable' badge
    and nothing else. The reason was only on the gaps page."""

    def test_reason_and_link(self):
        from scripts.generate_site import _render_emulator_file

        entry = {"name": "nds_firmware_modified.bin", "path": "x.bin",
                 "unsourceable": "written by the firmware editor, so no dump of it exists"}
        text = "\n".join(_render_emulator_file(
            entry, {"files": [entry]}, None, [entry], lambda f: False, "file-x",
        ))
        self.assertIn("Not collected yet: written by the firmware editor", text)
        self.assertIn("../gaps.md#not-collected-yet", text)
        self.assertNotIn("collectable", text)

    def test_the_gaps_page_names_where_a_wanted_file_is_listed(self):
        """The section read "Acknowledged gaps ... (verified from source
        code)" while No-Intro lists XM7's KANJI2.ROM and MAME's fm7740sx.zip
        carries it: the flag only keeps a homonym out, the file is wanted."""
        from scripts.generate_site import generate_gap_analysis

        unsourced = {"name": "KANJI2.ROM", "reason": "no dump distributed", "source_ref": ""}
        report = {"xm7": {"emulator": "XM7", "gaps": 0, "gap_missing": 0, "gap_bios": 0,
                          "unsourceable": [unsourced], "gap_details": []}}
        catalogued = {"no-intro": {"missing": [{
            "name": "KANJI2.rom",
            "romsets": [{"source": "mame", "archive": "fm7740sx.zip"}],
            "needed_by": [{"emulator": "xm7", "name": "KANJI2.ROM", "required": True}],
        }]}}
        page = generate_gap_analysis(
            {"xm7": {"emulator": "XM7", "files": []}}, {}, {"files": {}, "indexes": {}},
            gap_report=report, catalogued=catalogued)
        self.assertIn("## Not collected yet", page)
        self.assertIn('<span id="acknowledged-gaps"></span>', page)
        self.assertIn("| No-Intro `KANJI2.rom`, mame `fm7740sx.zip` |", page)
        self.assertNotIn("Acknowledged", page)
        self.assertNotIn("verified from source code", page)



class CollectionCardsSayWhereToGetTheFile(unittest.TestCase):
    """A system page card gave the hashes, readers and provenance of
    scph5501.bin and no path or link to the bytes."""

    def test_raw_and_release_asset_urls(self):
        import scripts.generate_site as site

        site._RELEASE_ASSET_NAMES = None
        self.addCleanup(setattr, site, "_RELEASE_ASSET_NAMES", None)
        self.assertEqual(
            site._fetch_url("bios/Sony/PlayStation/scph5501.bin"),
            "https://raw.githubusercontent.com/Abdess/retrobios/main/bios/Sony/PlayStation/scph5501.bin",
        )
        self.assertTrue(site._fetch_url("bios/Arcade/MAME/MAME 0.174 Arcade XML.dat").endswith(
            "/releases/download/large-files/MAME.0.174.Arcade.XML.dat"
        ))



class CollectionCardsCarryFullHashes(unittest.TestCase):
    """A pasted md5 or crc32 found nothing: cards showed 12 characters of
    SHA1 and MD5 (the rest in a title the search does not index) and no
    CRC32 or SHA256."""

    def test_every_hash_in_full(self):
        from scripts.generate_site import FileConsumers, _system_file_card

        entry = {"name": "DUKE.RTS", "path": "bios/x/DUKE.RTS", "size": 10,
                 "sha1": "a" * 40, "md5": "9d29f9673bbdb56068acf7645c13749c",
                 "crc32": "504086c1", "sha256": "b" * 64}
        text = "\n".join(_system_file_card(entry, FileConsumers({}, {})))
        for value in (entry["sha1"], entry["md5"], entry["crc32"], entry["sha256"]):
            self.assertIn(f'<dd class="rb-hash">{value}</dd>', text)


class AHeldRevisionLinksItsBuildFile(unittest.TestCase):
    """advanced_drastic's page printed the KNULLI build file that holds its
    revision as plain text, while pin_build carries the repository, the tag
    and the path a pinned link needs. 36 profiles carry one."""

    def test_the_build_file_row(self):
        from scripts.generate_site import _build_rows

        rows = _build_rows({"pin_frozen": "KNULLI builds this revision.", "pin_build": [{
            "platform": "knulli", "repo": "https://github.com/knulli-cfw/knulli-linux",
            "revision": "20260511", "path": "package/emulators/advanced_drastic/advanced_drastic.mk",
            "variable": "ADVANCED_DRASTIC_VERSION", "value": "eaf41ab9"}]})
        # A tag can move: named, never linked.
        self.assertIn(
            "| Build file | KNULLI `package/emulators/advanced_drastic/advanced_drastic.mk` "
            "at `20260511` sets `ADVANCED_DRASTIC_VERSION` |", rows)

    def test_a_build_read_at_a_recorded_commit_links(self):
        from scripts.generate_site import _build_rows

        pin = "46128cd252cdecae852a4d0bafa2aaf9d03ab563"
        rows = _build_rows({"pin_build": [{
            "platform": "retropie", "repo": "https://github.com/RetroPie/RetroPie-Setup",
            "revision": pin, "path": "scriptmodules/emulators/advmame-1.4.sh",
            "variable": "rp_module_repo", "value": "x"}]})
        self.assertIn(
            f"[RetroPie `scriptmodules/emulators/advmame-1.4.sh`](https://github.com/RetroPie/"
            f"RetroPie-Setup/blob/{pin}/scriptmodules/emulators/advmame-1.4.sh)", rows[0])

    def test_the_record_holds_the_build_files(self):
        import sitesources  # noqa: PLC0415

        files = sitesources.build_files({"pin_build": [
            {"repo": "https://github.com/o/r", "revision": "a" * 40, "path": "p.mk"},
            {"repo": "https://github.com/o/r", "revision": "v1", "path": "q.mk"}]})
        self.assertEqual([(f[1], f[2]) for f in files], [("a" * 40, "p.mk")])


class AVariantCardSaysWhatToSaveItAs(unittest.TestCase):
    """The Download button of a .variants/ card saved advision.zip.1c086064,
    the storage name, and nothing said RetroBat looks for advision.zip."""

    def test_the_name_to_save_it_under(self):
        from scripts.generate_site import FileConsumers, _system_file_card

        entry = {"name": "advision.zip", "size": 10, "sha1": "a" * 40,
                 "path": "bios/Entex/Adventure Vision/.variants/advision.zip.1c086064"}
        text = "\n".join(_system_file_card(entry, FileConsumers({}, {})))
        self.assertIn("Save as", text)
        self.assertIn("advision.zip.1c086064", text)
        plain = "\n".join(_system_file_card(
            {**entry, "path": "bios/Entex/Adventure Vision/advision.zip"}, FileConsumers({}, {})))
        self.assertNotIn("Save as", plain)



class NullReadsAsNone(unittest.TestCase):
    """`upstream: ~` printed `| Upstream | None |` and `bios_filename: null`
    printed `bios_filename: None`: a stated "there is none" read as a gap."""

    def test_page_and_values(self):
        from scripts.generate_site import _plain_value, generate_emulator_page

        self.assertEqual(_plain_value(None), "none")
        page = generate_emulator_page(
            "own", {"emulator": "Own", "type": "standalone", "source": "https://x/own",
                    "upstream": None, "core_version": None, "files": []},
            {"files": {}, "indexes": {}},
        )
        self.assertNotIn("None", page)
        self.assertIn("none: the source is the project itself", page)

    def test_the_rendered_site_has_no_python_none(self):
        from tests import sitepages

        pattern = re.compile(r"\| None \||: None$|: None \|", re.M)
        found = [sitepages.name(p) for p in sitepages.pages()
                 if pattern.search(p.read_text(encoding="utf-8"))]
        self.assertEqual(found, [])



class EmulatorCardsLinkTheCopyAndTheSection(unittest.TestCase):
    """Dolphin's IPL.bin (GC/USA) read "in repo" without naming the copy,
    did not link its collection card, and its platform links landed on the
    page top instead of the GameCube section."""

    def test_copy_and_sections(self):
        from types import SimpleNamespace

        from scripts.generate_site import _render_emulator_file

        sha1 = "ef9194ab4804aa0aa8540d846caf291b28331165"
        consumers = SimpleNamespace(
            sha1_of=lambda entry, dest="", owner="": sha1,
            path_of=lambda value: "bios/Nintendo/GameCube/GC/USA/IPL.bin",
            platforms={sha1: {"batocera"}},
            platform_systems={sha1: {"batocera": {"nintendo-gamecube"}}},
        )
        entry = {"name": "IPL.bin", "path": "GC/USA/IPL.bin"}
        text = "\n".join(_render_emulator_file(
            entry, {"files": [entry]}, consumers, [entry], lambda f: True, "file-ipl", "dolphin",
        ))
        self.assertIn("../systems/nintendo.md#sha1-ef9194ab4804", text)
        self.assertIn("../platforms/batocera.md#nintendo-gamecube", text)



class VersionAnchorsFollowContent(unittest.TestCase):
    """raze's nine DUKE3D.GRP were anchored -1 to -9 by declaration rank: a
    version declared before another moved every later link to another
    edition."""

    @staticmethod
    def _anchors(files):
        from scripts.generate_site import generate_emulator_page

        page = generate_emulator_page(
            "raze", {"emulator": "Raze", "type": "standalone", "files": files},
            {"files": {}, "indexes": {}},
        )
        return re.findall(r'<h3 id="(file-[^"]+)" class="rb-file-title"', page)

    def test_inserting_a_version_keeps_the_others(self):
        a = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "bbc9ce44"}
        b = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "aa4f6a40"}
        c = {"name": "DUKE3D.GRP", "path": "DUKE3D.GRP", "crc32": "982afe4a"}
        before = self._anchors([a, b])
        after = self._anchors([c, a, b])
        self.assertTrue(set(before) <= set(after))

    def test_same_size_versions_are_told_by_description(self):
        v1 = {"name": "AUDIO.ABS", "path": "AUDIO.ABS", "size": 6904, "description": "v1.12"}
        v2 = {"name": "AUDIO.ABS", "path": "AUDIO.ABS", "size": 6904, "description": "v1.13"}
        self.assertEqual(self._anchors([v1, v2]),
                         ["file-audio-abs-6904b-v1-12", "file-audio-abs-6904b-v1-13"])



class SitemapDatesComeFromThePage(unittest.TestCase):
    """All 664 sitemap URLs carried the build date: eduke32, re-read on
    2026-10-04, was announced as changed on the day of every build."""

    def test_the_page_date_or_none_reaches_the_sitemap(self):
        import tempfile

        from scripts import generate_site

        saved = dict(generate_site.PAGE_DATA)
        self.addCleanup(lambda: (generate_site.PAGE_DATA.clear(),
                                 generate_site.PAGE_DATA.update(saved)))
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            docs = Path(tmp)
            (docs / "emulators").mkdir()
            (docs / "emulators" / "dated.md").write_text("# Dated\n\nA page with its own date.\n")
            (docs / "emulators" / "undated.md").write_text("# Undated\n\nA page with no date.\n")
            generate_site.PAGE_DATA["emulators/dated.md"] = {"dateModified": "2026-10-04"}
            lastmod = generate_site.decorate_markdown_pages(docs)
        self.assertEqual(lastmod, {"/retrobios/emulators/dated/": "2026-10-04"})
        # The sitemap reads that map, and leaves every other page undated.
        config = (ROOT / "website" / "astro.config.mjs").read_text(encoding="utf-8")
        self.assertIn("lastmod.json", config)
        self.assertIn("serialize(item)", config)


class SiteCodeSpansHoldTheirValue(unittest.TestCase):
    """Values from profiles, platform files and file names went into code
    spans as they were: a backtick in one closed the span and what followed
    was read as markup."""

    def test_a_backtick_cannot_close_the_span(self):
        from scripts.siterender import _code

        span = _code("a`<img src=x onerror=alert(1)>`")
        self.assertEqual(span.count("`"), 2)
        self.assertTrue(span.startswith("`") and span.endswith("`"))



class TheDatasetDescribesItsDownloads(unittest.TestCase):
    """data.md was a Dataset named "Data & API" with no distribution,
    licence, date or creator: nothing a dataset harvester could index."""

    def test_distribution_licence_and_date(self):
        from scripts.generate_site import dataset_structured_data

        exports = [{"title": "Content database", "url": "api/v1/database.json",
                    "media_type": "application/json", "bytes": 10, "sha256": "ab" * 32}]
        data = dataset_structured_data(exports, {"generated_at": "2026-10-18T07:00:00Z"})
        self.assertEqual(data["dateModified"], "2026-10-18")
        self.assertIn("MIT", data["license"])
        (download,) = data["distribution"]
        self.assertEqual(download["@type"], "DataDownload")
        self.assertTrue(download["contentUrl"].endswith("/api/v1/database.json"))
        self.assertEqual(download["sha256"], "ab" * 32)
        self.assertNotEqual(data["name"], "Data & API")



class SystemPagesDescribeTheirFiles(unittest.TestCase):
    """systems/* published a generic TechArticle: no file, hash or
    provenance for the pages that carry a card per file."""

    def test_parts_carry_hashes_anchor_and_provenance(self):
        from scripts.generate_site import system_structured_data

        entry = {"name": "scph5501.bin", "sha1": "0555c6fae8906f3f09baf5988f00e55f88e9f30b",
                 "md5": "490f666e1afb15b7362b406ed1cea246", "crc32": "8d8cb7e4", "size": 524288,
                 "provenance": {"redump": {"dat": "Sony - PlayStation - BIOS Images",
                                           "name": "ps-30a.bin"}}}
        (part,) = system_structured_data("sony", {"PlayStation": [entry]})["hasPart"]
        self.assertTrue(part["url"].endswith("systems/sony/#sha1-0555c6fae890"))
        self.assertIn("md5:490f666e1afb15b7362b406ed1cea246", part["identifier"])
        self.assertIn("redump: Sony - PlayStation - BIOS Images (ps-30a.bin)", part["citation"])

    def test_a_huge_page_lists_its_verified_files_and_points_at_the_table(self):
        from scripts.generate_site import SYSTEM_PARTS_IN_FULL, system_structured_data

        plain = [{"name": f"f{i}", "sha1": f"{i:040x}"} for i in range(SYSTEM_PARTS_IN_FULL)]
        cited = {"name": "v", "sha1": "f" * 40,
                 "provenance": {"tosec": {"dat": "d", "name": "n"}}}
        data = system_structured_data("engines", {"x": [*plain, cited]})
        self.assertEqual([p["name"] for p in data["hasPart"]], ["v"])
        self.assertTrue(data["isBasedOn"].endswith("downloads/files.csv"))



class TheCollectionShipsADat(unittest.TestCase):
    """The exports had JSON, CSV and SQLite and no DAT, the one format
    clrmamepro and RomVault read: auditing a BIOS tree meant writing a
    converter from files.csv."""

    def test_round_trip_through_the_logiqx_parser(self):
        sys.path.insert(0, str(ROOT / "scripts" / "scraper"))
        from logiqx_parser import parse_logiqx
        from scripts.generate_site import collection_dat

        db = {"files": {
            "a" * 40: {"path": "bios/Sony/PlayStation/scph5501.bin", "size": 4,
                       "crc32": "8D8CB7E4", "md5": "1" * 32, "sha1": "a" * 40},
            "b" * 40: {"path": "bios/Nintendo/GameCube/GC/USA/IPL.bin", "size": 8,
                       "crc32": "00000001", "md5": "2" * 32, "sha1": "b" * 40},
        }}
        dat = parse_logiqx(collection_dat(db, "2026-10-18T07:00:00Z"))
        self.assertEqual(dat.version, "20261018")
        roms = {(r.game, r.name): r for r in dat.roms}
        # The set name is the subfolder a copy of bios/ holds: named
        # "Sony - PlayStation", clrmamepro looked beside Sony/ for it.
        self.assertIn(("Sony\\PlayStation", "scph5501.bin"), roms)
        self.assertIn(("Nintendo\\GameCube", "GC\\USA\\IPL.bin"), roms)
        self.assertEqual(roms[("Sony\\PlayStation", "scph5501.bin")].crc32, "8d8cb7e4")

    def test_each_setup_has_a_dat_of_its_installed_folder(self):
        """A Batocera user auditing share/bios against the collection DAT met
        thousands of sets laid out by manufacturer, and nothing of the folder
        Batocera reads."""
        sys.path.insert(0, str(ROOT / "scripts" / "scraper"))
        from logiqx_parser import parse_logiqx
        from scripts.generate_site import _platform_data_links, platform_dat

        db = {"files": {"a" * 40: {"size": 4, "crc32": "8D8CB7E4", "md5": "1" * 32,
                                   "sha1": "a" * 40}}}
        manifest = {
            "platform": "batocera", "display_name": "Batocera", "base_destination": "bios",
            "files": [{"dest": "dc/naomi2.zip", "sha1": "a" * 40, "size": 4},
                      {"dest": "saves/x.bin", "sha1": "a" * 40, "size": 4, "root": "save"}],
            "data_directories": [{"dest": "dolphin-emu/Sys",
                                  "files": {"GC/font.bin": {"sha1": "c" * 40, "size": 2}}}],
        }
        dat = parse_logiqx(platform_dat(manifest, db, {"c" * 40: {"md5": "3" * 32}},
                                        "2026-11-05T00:00:00Z"))
        roms = {(r.game, r.name): r for r in dat.roms}
        self.assertEqual(set(roms), {("bios", "dc\\naomi2.zip"),
                                     ("bios", "dolphin-emu\\Sys\\GC\\font.bin")})
        self.assertEqual(roms[("bios", "dc\\naomi2.zip")].md5, "1" * 32)
        self.assertEqual(roms[("bios", "dolphin-emu\\Sys\\GC\\font.bin")].md5, "3" * 32)
        self.assertIn("[DAT](../downloads/dat/batocera.dat)", _platform_data_links("batocera"))



class ZippedFileMd5IsParsedOnce(unittest.TestCase):
    """verify lowercased a comma md5 list, the builder and packverify did
    not: an uppercase Recalbox-style md5 on a zipped_file entry was OK for
    verify and a mismatch for the pack and the manifest."""

    def test_an_uppercase_member_md5_is_accepted_everywhere(self):
        import hashlib
        import zipfile as zf_mod

        from scripts.validation import inner_rom_check
        from scripts.verify import verify_entry_md5

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            archive = Path(directory, "x.zip")
            with zf_mod.ZipFile(archive, "w") as zf:
                zf.writestr("rom.bin", b"rom")
            member = hashlib.md5(b"rom").hexdigest().upper()
            for md5 in (member, f"{member},{'0' * 32}"):
                with self.subTest(md5=md5):
                    entry = {"name": "x.zip", "zipped_file": "rom.bin", "md5": md5}
                    self.assertEqual(inner_rom_check(entry, str(archive)), "ok")
                    self.assertEqual(
                        verify_entry_md5(entry, str(archive))["status"], "ok"
                    )

    def test_the_three_sites_share_the_parser(self):
        for module in ("validation.py", "packverify.py", "verify.py"):
            source = (ROOT / "scripts" / module).read_text()
            self.assertIn("parse_md5_list(", source, module)



class AHashListIsReadOneWay(unittest.TestCase):
    """mesence declares four sha256 for BS-X.bin as one comma-joined string.
    The resolver split it and shipped the file, but the gap report and
    profile_sync looked the whole string up and called it missing."""

    def test_every_reader_splits_the_list(self):
        from scripts.cross_reference import _declared_content
        from scripts.hashing import parse_hash_list
        from scripts.profile_sync import entry_hashes

        a, b = "a" * 64, "B" * 64
        entry = {"name": "BS-X.bin", "sha256": f"{a}, {b}", "crc32": "0xDEADBEEF"}
        self.assertEqual(parse_hash_list(entry["sha256"]), [a, b.lower()])
        self.assertEqual(_declared_content(entry)["sha256"], {a, b.lower()})
        self.assertEqual(_declared_content(entry)["crc32"], {"deadbeef"})
        self.assertEqual(set(entry_hashes(entry)), {a, b.lower(), "deadbeef"})



class RommRunsTheCoresItsPlayerNames(unittest.TestCase):
    """RomM's player merges a nightly core map into the stable one when netplay
    is on. Inheriting EmulatorJS's list left azahar, bsnes and
    genesis_plus_gx_wide out of the RomM pack, though RomM launches them."""

    SOURCE = """
const _EJS_CORES_MAP: Record<string, string[]> = {
  "3do": ["opera"],
  arcade: [
    "mame2003_plus",
    "fbneo",
  ],
} as const;

const _EJS_NIGHTLY_CORES_MAP: Record<string, string[]> = {
  "3ds": ["azahar"],
  snes: ["snes9x", "bsnes"],
};
"""

    def test_both_maps_are_read(self):
        from scripts.scraper.romm_scraper import parse_player_cores

        self.assertEqual(
            parse_player_cores(self.SOURCE),
            ["azahar", "bsnes", "fbneo", "mame2003_plus", "opera", "snes9x"],
        )

    def test_a_missing_map_raises(self):
        from scripts.scraper.romm_scraper import parse_player_cores

        source = self.SOURCE.replace("_EJS_NIGHTLY_CORES_MAP", "_RENAMED")
        with self.assertRaises(RuntimeError):
            parse_player_cores(source)

    def test_the_platform_file_carries_the_nightly_cores(self):
        from common import load_platform_config

        cores = set(load_platform_config("romm", str(ROOT / "platforms"))["cores"])
        self.assertTrue({"azahar", "bsnes", "genesis_plus_gx_wide"} <= cores)


class RommNeoGeoFoldersGetTheirBios(unittest.TestCase):
    """RomM runs fbneo for neogeoaes and neogeomvs as for arcade and reads
    firmware per platform folder, but the fixture gives neogeo.zip to arcade
    alone, so a Neo Geo game in its own folder started without it."""

    def test_the_mirror_is_per_file(self):
        from scripts.scraper.romm_scraper import FIRMWARE_MIRRORS, SLUG_MAP

        arcade = FIRMWARE_MIRRORS["arcade"]
        self.assertEqual(arcade["neogeoaes"], ("neogeo.zip",))
        self.assertEqual(arcade["neogeomvs"], ("neogeo.zip",))
        self.assertIn("neogeoaes", SLUG_MAP)

    def test_a_file_files_under_its_own_system_only(self):
        # Adding the Neo Geo slugs sent MAME 2003's ZN-1 BIOS and data files
        # into neogeoaes/, and FBNeo's CPS3 sets already sat in colecovision/:
        # a system the platform lacks has no folder, and a mirror-only
        # folder attracts no system-less file.
        from scripts.packextras import _slug_for

        config_systems = {"arcade", "snk-neogeo-aes", "nintendo-ds"}
        sys_to_slug = {"arcade": "arcade", "snk-neogeo-aes": "neogeoaes",
                       "nintendo-ds": "nds"}
        profiles = {"mame2003": {"systems": ["snk-neogeo-aes", "zn1-acclaim"]},
                    "melonds": {"systems": ["nintendo-ds", "nintendo-dsi"]}}
        args = (profiles, config_systems, {}, sys_to_slug, {"arcade", "nintendo-ds"})
        self.assertEqual(_slug_for({"profile": "mame2003", "system": "zn1-acclaim"}, *args), "")
        self.assertEqual(_slug_for({"profile": "mame2003"}, *args), "")
        self.assertEqual(_slug_for({"profile": "melonds", "system": "nintendo-dsi"}, *args), "")
        self.assertEqual(_slug_for({"profile": "melonds"}, *args), "nds")

    def test_the_platform_file_carries_it(self):
        text = (ROOT / "platforms" / "romm.yml").read_text(encoding="utf-8")
        self.assertIn("destination: neogeoaes/neogeo.zip", text)
        self.assertIn("destination: neogeomvs/neogeo.zip", text)
        self.assertNotIn("neogeoaes/pgm.zip", text)



class AProfilePathIsTheEmulatorsNotOurs(unittest.TestCase):
    """No guard stopped a profile `path:` naming .variants/, our storage:
    the pack would write the file where no emulator reads."""

    def test_a_variants_path_is_refused(self):
        from unittest import mock

        try:
            from scripts import validate_schemas
        except ImportError as exc:
            self.skipTest(f"validate_schemas needs jsonschema: {exc}")

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            emulators = Path(directory) / "emulators"
            emulators.mkdir()
            (emulators / "x.yml").write_text(
                "emulator: X\nfiles:\n  - name: scph1001.bin\n"
                "    path: .variants/scph1001.bin.abc12345\n"
            )
            with mock.patch.object(validate_schemas, "ROOT", Path(directory)):
                errors = validate_schemas._repository_layout_in_profiles()
        self.assertEqual(len(errors), 1)
        self.assertIn(".variants/", errors[0])



class DocumentedExamplesHoldTogether(unittest.TestCase):
    """The verification block downloaded RetroArch_BIOS_Pack.zip*, a name
    no release ever published (packs are versioned and split), and the
    first-install example ended on "72 files installed" after announcing a
    download of 12,893."""

    def test_the_verification_pattern_matches_published_pack_names(self):
        import fnmatch
        import re

        page = (ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        patterns = re.findall(r"--pattern '([^']*Pack[^']*)'", page)
        self.assertTrue(patterns)
        for name in ("RetroArch_Lakka_v1.22.2_BIOS_Pack.part1of2.zip",
                     "RetroArch_v1.22.2_BIOS_Pack.zip"):
            with self.subTest(name=name):
                self.assertTrue(any(fnmatch.fnmatch(name, p) for p in patterns))

    def test_the_first_install_example_counts_one_number(self):
        import re

        # The annotated run moved from First install to the installer page.
        page = (ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        downloading = re.search(r"Downloading (\d+) files", page).group(1)
        done = re.search(r"Done\. (\d+) files installed", page).group(1)
        # The data trees come after the download, counted in the index.
        index = page[page.index("Fetching file index for batocera"):]
        trees = re.search(r"^    .* and (\d+) data files", index, re.M)
        self.assertEqual(int(done), int(downloading) + (int(trees.group(1)) if trees else 0))



class TheReadmeCountsSystemsAsListSystemsDoes(unittest.TestCase):
    """The README counted every raw spelling (nes and nintendo-nes as two)
    and announced 550 systems while the tool it points to listed 513."""

    def test_one_count(self):
        import io
        import re
        from contextlib import redirect_stdout

        from scripts.common import list_system_ids

        out = io.StringIO()
        with redirect_stdout(out):
            list_system_ids(str(ROOT / "emulators"))
        listed = len(out.getvalue().splitlines())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        announced = int(re.search(r"\*\*(\d+) systems\*\*", readme).group(1))
        self.assertEqual(announced, listed)



class ATargetIsNamedWhenItRemovesTheCore(unittest.TestCase):
    """--platform batocera --target rpi4 --emulator dolphin said "dolphin is
    not run by batocera", which runs it on every x86 board."""

    def test_the_message_names_the_target(self):
        result = subprocess.run(
            [sys.executable, "scripts/cross_reference.py", "--platform", "batocera",
             "--target", "bcm2711", "--emulator", "dolphin"],
            cwd=ROOT, capture_output=True, text=True, timeout=600,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("bcm2711 target", result.stderr)
        self.assertNotIn("is not run by", result.stderr)



class ANamedPackThatIsAbsentFails(unittest.TestCase):
    """--verify-packs --platform retroarch on an empty directory printed
    "SKIP" and exited 1: a skip label on a failure, and no next step."""

    def test_the_line_says_fail_and_how_to_build(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            result = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--platform", "retroarch",
                 "--verify-packs", "--output-dir", directory],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("retroarch: FAIL (no pack in", result.stdout)
        self.assertIn("generate_pack.py --platform retroarch", result.stdout)

    def test_all_with_no_pack_is_a_failure(self):
        """--all on a mistyped or purged directory skipped every platform
        and exited 0, a passed integrity check that checked nothing."""
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            result = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", "--all",
                 "--verify-packs", "--output-dir", directory],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("no pack to verify", result.stderr)



class AnAliasSelectsItsProfile(unittest.TestCase):
    """`--emulator mednafen_psx` refused with "use --emulator beetle_psx",
    a step the tool could take itself: the name a user reads in RetroArch
    now selects the profile it is an alias of, and says so on stderr. An
    alias without alias_of is found through the profile whose cores: names
    it."""

    def test_the_alias_selects_its_profile(self):
        import contextlib as _contextlib
        import io as _io

        from scripts.common import ProfileSelectionError, select_emulator_profiles

        profiles = {
            "flycast": {"type": "libretro", "cores": ["flycast", "flycast_gles2"]},
            "flycast_gles2": {"type": "alias", "alias_of": "flycast"},
            "orphan": {"type": "alias"},
            "core": {"type": "libretro", "cores": ["orphan"]},
            "lost": {"type": "alias"},
        }
        for name, expected in (("flycast_gles2", "flycast"), ("orphan", "core")):
            err = _io.StringIO()
            with self.subTest(name=name), _contextlib.redirect_stderr(err):
                selected = select_emulator_profiles([name], profiles)
            self.assertEqual([key for key, _ in selected], [expected])
            self.assertIn(f"{name} is {expected}", err.getvalue())
        with _contextlib.redirect_stderr(_io.StringIO()):
            both = select_emulator_profiles(["flycast", "flycast_gles2"], profiles)
        self.assertEqual([key for key, _ in both], ["flycast"])
        with self.assertRaises(ProfileSelectionError):
            select_emulator_profiles(["lost"], profiles)

    def test_verify_runs_the_alias(self):
        result = subprocess.run(
            [sys.executable, "scripts/verify.py", "--emulator", "mednafen_psx"],
            cwd=ROOT, capture_output=True, text=True, timeout=300, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("beetle_psx", result.stdout)
        self.assertIn("mednafen_psx is beetle_psx", result.stderr)



class AFailedVerificationIsAnError(unittest.TestCase):
    """--all ended on "WARNING: some packs have verification errors" and
    exit 1: a warning that fails the run, naming no pack."""

    def test_the_last_line_names_the_packs(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text()
        self.assertNotIn("WARNING: some packs have verification errors", source)
        self.assertIn('print(f"ERROR: packs failed verification: {\', \'.join(failing)}", file=sys.stderr)', source)



class TheGroundTruthFooterSaysWhatItCounts(unittest.TestCase):
    """"417 platform-only (no emulator profile)" where 369 of 526 files had
    a profile, 20% here for 21% on the site, and "0/81 (0%)" for MiSTer,
    which declares no core by design."""

    def _footer(self, coverage):
        import io as _io
        from contextlib import redirect_stdout

        from scripts.verify import Severity, print_platform_result

        out = _io.StringIO()
        counts = {Severity.OK: 1, Severity.INFO: 0, Severity.WARNING: 0, Severity.CRITICAL: 0}
        result = {"platform": "X", "verification_mode": "existence", "total_files": 1,
                  "severity_counts": counts, "status_counts": {"ok": 1},
                  "undeclared_files": [], "exclusion_notes": [], "details": [],
                  "ground_truth_coverage": coverage}
        with redirect_stdout(out):
            print_platform_result(result, ["X"])
        return out.getvalue()

    def test_counts_and_rounding(self):
        text = self._footer({"with_validation": 109, "with_profile": 369,
                             "platform_only": 417, "total": 526, "applicable": True})
        self.assertIn("(21%)", text)
        self.assertIn("157 platform-only", text)

    def test_not_applicable(self):
        text = self._footer({"with_validation": 0, "with_profile": 0,
                             "platform_only": 81, "total": 81, "applicable": False})
        self.assertIn("not applicable", text)
        self.assertNotIn("0/81", text)


class ThePipelineSummaryTimesEachStep(unittest.TestCase):
    """The summary gave OK per step and one total: the slow step of a
    twenty-minute run could only be found by reading the log."""

    def test_each_outcome_carries_its_time(self):
        from unittest import mock

        clock = iter([10.0, 12.5, 12.5, 20.0])
        with mock.patch.object(pipeline.time, "monotonic", lambda: next(clock)):
            results = pipeline.StepResults(pipeline.time.monotonic())
            results["generate_db"] = True
            results["refresh_data"] = pipeline.SKIPPED
            results["verify"] = True
        self.assertEqual(results.seconds, {"generate_db": 2.5, "refresh_data": 0.0, "verify": 7.5})
        self.assertEqual(dict(results), {"generate_db": True, "refresh_data": pipeline.SKIPPED,
                                         "verify": True})


class StrictFailsOnMissingOnly(unittest.TestCase):
    """The docstring promised exit 1 on a required file missing or rejected,
    but a rejected file is UNTESTED, a warning, and --strict never saw it."""

    def test_the_contract(self):
        from scripts import verify as verify_mod
        from scripts.verify import Severity

        verify_mod._exit_if_strict(True, [{"severity_counts": {Severity.WARNING: 2}}])
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            verify_mod._exit_if_strict(True, [{"severity_counts": {Severity.CRITICAL: 1}}])
        self.assertNotIn("or rejected", verify_mod._exit_if_strict.__doc__)


class TheRepairCommandWritesTheFileNamed(unittest.TestCase):
    """--db nosuch.json said to rebuild with --output database.json: the
    command wrote another file and the next run failed the same way."""

    def test_the_command_names_the_path(self):
        from scripts.common import DatabaseUnreadable, load_database

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            target = str(Path(directory) / "nosuch.json")
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(target)
            self.assertIn(f"--output {target}", str(caught.exception))
            Path(target).write_text("{")
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(target)
            self.assertIn(f"--output {target}", str(caught.exception))

    def test_a_typo_beside_the_database_names_the_database(self):
        """--db databse.json beside database.json was told to rescan the whole
        collection into a second file named after the typo."""
        from scripts.common import DatabaseUnreadable, load_database

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as directory:
            (Path(directory) / "database.json").write_text("{}")
            typo = Path(directory) / "databse.json"
            with self.assertRaises(DatabaseUnreadable) as caught:
                load_database(str(typo))
        message = str(caught.exception)
        self.assertIn(f"Close match: {typo.with_name('database.json')}", message)
        self.assertNotIn("generate_db.py", message)


class VerifyPacksRefusesWhatItCannotDo(unittest.TestCase):
    """The --verify-packs refusals lived in the --all-variants checks, which
    return without that flag: --split and --one-per-slot went through, and
    a run with neither --platform nor --all failed after taking the lock."""

    def test_usage_errors_exit_2_before_any_lock(self):
        cases = (
            ["--verify-packs"],
            ["--verify-packs", "--platform", "retroarch", "--split"],
            ["--verify-packs", "--platform", "retroarch", "--one-per-slot"],
        )
        for extra in cases:
            with self.subTest(args=extra), tempfile.TemporaryDirectory(dir=TMP_ROOT) as out:
                result = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", *extra, "--output-dir", out],
                    cwd=ROOT, capture_output=True, text=True, timeout=300,
                )
                self.assertEqual(result.returncode, 2, result.stderr[-300:])
                self.assertIn("--verify-packs", result.stderr)
                self.assertFalse((Path(out) / ".lock").exists())


class AHashScanningCoreContradictsNoPlatform(unittest.TestCase):
    """ares finds its firmware by sha256 in a folder and opens no file by
    name, so its entries' names are labels. Labels reused from other dumps
    (MSX2.ROM, bios_CD_U.bin) put ares's revision on a path where RetroBat
    pins another: slots called RetroBat's declaration wrong, and the pack
    dropped ares's own dump behind the platform's."""

    def test_no_conflict_names_ares(self):
        import json

        from scripts import slots
        from scripts.common import list_registered_platforms, load_emulator_profiles

        root = ROOT
        if not (root / "database.json").exists():
            self.skipTest("database.json is not built")
        profiles = load_emulator_profiles(str(root / "emulators"))
        db = json.loads((root / "database.json").read_text(encoding="utf-8"))
        claimed = [
            (platform, conflict.destination)
            for platform in list_registered_platforms(str(root / "platforms"))
            for conflict in slots.scan_platform(platform, profiles, db, str(root / "platforms"))
            if any(claim.emulator == "ares" for claim in conflict.profile_claims)
        ]
        self.assertEqual(claimed, [])


class FsUaeKickstartIsFoundByContent(unittest.TestCase):
    """FS-UAE scans its Kickstarts directory and names a ROM by checksum
    (src/fs-uae/config.c:121-140, main.c:431-470), and with no ROM loads the
    AROS replacement (memory.cpp:2374-2379). kick13.rom and its required
    flag came from the RetroPie launcher, which the platform layer records."""

    def test_the_kickstart_is_an_optional_label(self):
        from scripts.validation import opens_by_name

        profile = yaml.safe_load((ROOT / "emulators" / "fs-uae.yml").read_text(encoding="utf-8"))
        entry = next(f for f in profile["files"] if f.get("sha1") == "891e9a547772fe0c6c19b610baf8bc4ea7fcb785")
        self.assertFalse(opens_by_name(entry, profile, standalone=True))
        self.assertFalse(entry.get("required"))
        self.assertNotIn("RetroPie launcher", entry.get("note", ""))


class NoProfileHashFromASecondarySource(unittest.TestCase):
    """ecwolf.yml pinned ecwolf.pk3 to an md5 its note said came from the
    .info. The code checks none, and no file shipped at the pin carries it:
    a source without a hash gives the profile none."""

    PATTERN = re.compile(
        r"(md5|sha1|crc32|hash)[^.]{0,40}\bfrom (the )?(\.info|core-?info|docs?|documentation)",
        re.IGNORECASE,
    )

    def test_no_hashed_entry_names_a_secondary_source(self):
        found = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in profile.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                if any(entry.get(k) for k in ("md5", "sha1", "crc32", "sha256")) and (
                    self.PATTERN.search(str(entry.get("note", "")))
                ):
                    found.append(f"{path.name}: {entry.get('name')}")
        self.assertEqual(found, [])


class XeniosFollowsItsReleaseBranch(unittest.TestCase):
    """The xenios pin 87b176a0 sat on `preview`, which diverged from the
    default `xenios` branch, and without source_branch profile_sync read the
    pin as orphaned. Since November 2026 the releases (2.2 to 2.3.1) come from
    `xenios` and `preview` stopped in June: the pin is release 2.3.1 on the
    default branch, so the profile names no other branch."""

    def test_the_profile_follows_the_branch_its_pin_is_on(self):
        profile = yaml.safe_load((ROOT / "emulators" / "xenios.yml").read_text(encoding="utf-8"))
        self.assertIn(profile.get("source_branch"), (None, "xenios"))
        self.assertEqual(profile["source_commit"][:7], "cf7c7ee")


class PcemUpstreamPinIsTheLastSync(unittest.TestCase):
    """The pcem bump set upstream_commit to dev's HEAD 25b54e3f, and dev was
    rewritten: the pin left every branch (compare: diverged 109/114). The
    port shares no history with upstream and took mainline patches by hand
    until 2016-04-13, whose last upstream commit is 10739b96. Held there, a
    bump cannot move it to a HEAD the port never contained."""

    def test_the_upstream_pin_is_held_at_the_last_sync(self):
        profile = yaml.safe_load((ROOT / "emulators" / "pcem.yml").read_text(encoding="utf-8"))
        self.assertEqual(profile["upstream_commit"], "10739b9618e388a5bf8c21e752f12b3952fa83e1")
        self.assertTrue(profile.get("upstream_frozen"))


class AHashScanLabelNamesNoOtherDump(unittest.TestCase):
    """A core that finds its firmware by content names no file, so each
    entry name is a label. ares labelled its Famicom Disk System revision
    (RP2C33-01, crc32 1c7ae5d5) disksys.rom, the name six NES cores read for
    the RP2C33A-01A dump: on ROCKNIX the manifest put ares's revision at
    disksys.rom for all of them. A label that another profile gives a
    different dump is refused, the two dumps compared through the
    collection's hash indexes."""

    # Names the core's own code gives the image, not labels.
    CODE_NAMED = {
        ("bizhawk", "MSX.rom"):
            "FirmwareDatabase.cs:362 names the image MSX.rom",
        ("swanstation", "ps1_rom.bin"):
            "the whole PS3 image is the file the PS3 itself names ps1_rom.bin, "
            "beetle_psx reads its first 512 KB under the same name",
        ("duckstation-legacy", "ps1_rom.bin"):
            "the same whole PS3 image, whose first 512 KB src/core/bios.cpp:89 hashes",
        ("openmsx", "COLECO.ROM"):
            "share/machines/ColecoVision_SGM.xml:56 names it, tried beside the machine XML",
        ("openmsx", "fmpac.rom"):
            "share/machines/Boosted_MSX2_EN.xml:83 names it, tried beside the machine XML",
        ("openmsx-libretro", "rs232.rom"):
            "share/extensions/rs232.xml:18-22 names it, tried beside the extension XML",
    }

    @staticmethod
    def _identity(entry: dict, db: dict) -> tuple[set, set]:
        raw: set = set()
        sha1s: set = set()
        indexes = db["indexes"]
        for field, index in (("sha1", None), ("md5", "by_md5"),
                             ("crc32", "by_crc32"), ("sha256", "by_sha256")):
            value = entry.get(field)
            values = value if isinstance(value, list) else [value] if value else []
            for item in values:
                for digest in str(item).lower().split(","):
                    digest = digest.strip()
                    if not digest:
                        continue
                    raw.add((field, digest))
                    sha1 = digest if index is None else indexes[index].get(digest)
                    if sha1 in db["files"]:
                        sha1s.add(sha1)
        return raw, sha1s

    def test_labels_are_not_other_dumps_names(self):
        import json

        from scripts.common import load_emulator_profiles

        if not (ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        db = json.loads((ROOT / "database.json").read_text(encoding="utf-8"))
        profiles = load_emulator_profiles(str(ROOT / "emulators"))
        by_name: dict[str, list[tuple[str, dict]]] = {}
        for emulator, profile in profiles.items():
            for entry in profile.get("files") or []:
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        by_name.setdefault(str(name).casefold(), []).append((emulator, entry))
        clashes = []
        for emulator, profile in profiles.items():
            if profile.get("found_by") != "content":
                continue
            for entry in profile.get("files") or []:
                raw, sha1s = self._identity(entry, db)
                if not sha1s:
                    continue
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if (emulator, name) in self.CODE_NAMED:
                        continue
                    for other, other_entry in by_name.get(str(name).casefold(), []):
                        if other == emulator:
                            continue
                        other_raw, other_sha1s = self._identity(other_entry, db)
                        if other_sha1s and not raw & other_raw and not sha1s & other_sha1s:
                            clashes.append(f"{emulator} {name} is {other}'s name for another dump")
        self.assertEqual(sorted(set(clashes)), [])


class ANoteOutsideTheSystemDirCarriesLoadFrom(unittest.TestCase):
    """mame2000 opens hiscore.dat, history.dat and mameinfo.dat from the
    directory of the loaded content (src/libretro/fileio.c:1002-1014), and
    mame2014 and mame2015 open hiscore.dat from the working directory
    (src/emu/hiscore.c:330-337). Their notes said so, but no load_from did:
    the entries claimed system/hiscore.dat and the RetroArch pack shipped a
    file neither core opens there. A libretro entry whose note places the
    read outside the system directory declares where."""

    ELSEWHERE = re.compile(
        r"\b(?:opened|read|loaded)\b[^.]*?\bfrom (?:the )?(?:working directory|"
        r"ROM directory|content directory|directory of the loaded content)"
        r"|IMAMEBASEPATH",
        re.IGNORECASE,
    )

    def test_prose_and_load_from_agree(self):
        offenders = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if profile.get("type") != "libretro":
                continue
            for entry in profile.get("files") or []:
                if entry.get("path") or entry.get("load_from") or entry.get("mode") == "standalone":
                    continue
                if self.ELSEWHERE.search(str(entry.get("note") or "")):
                    offenders.append(f"{path.name}: {entry.get('name')}")
        self.assertEqual(offenders, [])


class ReportsHoldTheDataTrees(unittest.TestCase):
    """Run on their own, the README, site and slot reports resolved against
    data/ without the shared hold, so a concurrent refresh could swap a tree
    while they read it and the published counts came from half of it."""

    def test_each_entry_point_holds_them(self):
        import ast

        for script in ("generate_readme.py", "generate_site.py", "slots.py",
                       "export_native.py", "cross_reference.py"):
            tree = ast.parse((ROOT / "scripts" / script).read_text(encoding="utf-8"))
            main = next(
                node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "main"
            )
            with self.subTest(script=script):
                self.assertTrue(any(
                    isinstance(call, ast.Call)
                    and getattr(call.func, "id", None) == "hold_data_dirs"
                    for call in ast.walk(main)
                ))


class TheTreeKeepsStandaloneEntries(unittest.TestCase):
    """With no platform named, the gap report laid every dual profile out as
    libretro only: eka2l1, dolphin and xenia-edge lost 133 files that
    Batocera and RetroBat run standalone and no platform declares."""

    def test_a_standalone_only_entry_is_reported(self):
        if not (ROOT / "database.json").exists():
            self.skipTest("database.json is not built")
        out = subprocess.run(
            [sys.executable, "scripts/cross_reference.py", "--emulator", "eka2l1"],
            cwd=ROOT, capture_output=True, text=True, timeout=600, check=True,
        ).stdout
        undeclared = re.search(r"(\d+) undeclared", out)
        self.assertIsNotNone(undeclared, out[-500:])
        self.assertGreater(int(undeclared.group(1)), 0)


class TheCliSetsBundledFilesApart(unittest.TestCase):
    """cross_reference counted daedalusx64's n64.psh and touchHLE's runtime
    libraries as missing, to be sourced, though the project leaves them out
    by design and verify and the gaps page already say so."""

    def test_a_bundled_gap_is_not_missing(self):
        from scripts.cross_reference import print_report

        gap = {"name": "n64.psh", "required": True, "bundled": True, "note": "",
               "source": "missing"}
        report = {"emu": {
            "emulator": "Emu", "systems": [], "total_files": 1, "platform_covered": 0,
            "gaps": 1, "gap_missing": 1, "gap_details": [gap],
        }}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_report(report)
        text = out.getvalue()
        self.assertIn("0 missing (need to be sourced)", text)
        self.assertIn("1 bundled with their emulator", text)
        self.assertIn("n64.psh [BUNDLED]", text)


class ThePackCheckAppliesTheFrontendRule(unittest.TestCase):
    """The integrity step compared a member's md5 alone. Under RomM's rule
    (size, then any of md5, sha1 and crc32) the builder ships a revision
    matched on its sha1, and the check then refused a correct pack."""

    def test_romm_accepts_on_size_and_sha1(self):
        import hashlib
        import zipfile

        from scripts.packverify import _check_member_hash

        payload = b"revision B"
        entry = {
            "md5": "0" * 32,
            "sha1": hashlib.sha1(payload).hexdigest(),
            "size": len(payload),
        }
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            pack = Path(tmp) / "p.zip"
            with zipfile.ZipFile(pack, "w") as zf:
                zf.writestr("bios/x.bin", payload)
            with zipfile.ZipFile(pack) as zf:
                self.assertIsNone(
                    _check_member_hash(zf, "bios/x.bin", entry, "md5", "size_and_any_hash")
                )
                self.assertIsNotNone(_check_member_hash(zf, "bios/x.bin", entry, "md5"))


class ABrokenRegistryIsNotAnEmptyOne(unittest.TestCase):
    """A registered platform whose YAML was renamed was skipped without a
    word, and a missing registry read as no platforms: verify --all --strict
    and every --all build passed having checked nothing."""

    def test_both_raise(self):
        from scripts.common import list_registered_platforms

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            with self.assertRaises(FileNotFoundError):
                list_registered_platforms(tmp)
            Path(tmp, "_registry.yml").write_text(
                "platforms:\n  rocknix:\n    config: rocknix.yml\n", encoding="utf-8"
            )
            with self.assertRaises(FileNotFoundError) as caught:
                list_registered_platforms(tmp)
            self.assertIn("rocknix", str(caught.exception))


class AnUnansweredSearchIsNotANotFound(unittest.TestCase):
    """auto_fetch caught every network error and reported the file as
    needing a community contribution: offline, each file became an issue
    asking the public for something the tool never looked for."""

    def _fetch(self, error):
        from unittest import mock

        from scripts import auto_fetch

        def refuse(*_args, **_kwargs):
            raise error

        entry = {"name": "nowhere.bin", "system": "test-system", "sha1": "0" * 40}
        db = {"files": {}, "indexes": {"by_md5": {}, "by_name": {}}}
        with mock.patch("urllib.request.urlopen", refuse), \
                mock.patch.object(auto_fetch, "step2_scan_branches", lambda e: None), \
                contextlib.redirect_stdout(io.StringIO()):
            return auto_fetch.fetch_missing([entry], db, "bios")

    def test_offline_is_not_searched(self):
        import urllib.error

        result = self._fetch(urllib.error.URLError("offline"))
        self.assertEqual(result["still_missing"], [])
        self.assertEqual(result["stats"]["errors"], 1)

    def test_a_404_everywhere_is_not_found(self):
        import urllib.error

        result = self._fetch(urllib.error.HTTPError("u", 404, "missing", {}, None))
        self.assertEqual(len(result["still_missing"]), 1)
        self.assertEqual(result["stats"]["errors"], 0)


class AutoFetchProvesEveryHashItIsGiven(unittest.TestCase):
    """auto_fetch checked a download by sha1 or md5 only: RetroDECK's
    dsifirmware.bin, pinned by sha256 alone, was announced as searched and
    could never be accepted."""

    DATA = b"firmware bytes"

    def test_a_sha256_proves_a_download(self):
        import hashlib

        from scripts import auto_fetch

        sha256 = {"sha256": hashlib.sha256(self.DATA).hexdigest()}
        self.assertTrue(auto_fetch.verify_content(self.DATA, sha256))
        self.assertFalse(auto_fetch.verify_content(b"other", sha256))

    def test_every_declared_cryptographic_hash_must_match(self):
        import hashlib

        from scripts import auto_fetch

        both = {"sha256": hashlib.sha256(self.DATA).hexdigest(), "md5": "0" * 32}
        self.assertFalse(auto_fetch.verify_content(self.DATA, both))
        both["md5"] = hashlib.md5(self.DATA).hexdigest()
        self.assertTrue(auto_fetch.verify_content(self.DATA, both))

    def test_crc32_and_size_never_accept_a_download(self):
        """A crc32 can be forged: bytes a source crafts to it would land in
        bios/."""
        import urllib.request
        import zlib
        from unittest import mock

        from scripts import auto_fetch

        crc = {"name": "forged.bin", "system": "test-system",
               "crc32": f"{zlib.crc32(self.DATA):08X}", "size": len(self.DATA)}
        self.assertFalse(auto_fetch.verify_content(self.DATA, crc))
        self.assertFalse(auto_fetch.verifiable(crc))

        served = io.BytesIO(self.DATA)
        with tempfile.TemporaryDirectory() as bios, \
                mock.patch.object(urllib.request, "urlopen", lambda *a, **k: served), \
                mock.patch.object(auto_fetch, "step2_scan_branches",
                                  lambda e: self.DATA), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            result = auto_fetch.fetch_missing([crc], {"files": {}}, bios)
            self.assertEqual(list(Path(bios).rglob("*")), [])
        self.assertEqual(result["stats"]["found"], 0)
        self.assertEqual(result["stats"]["unverifiable"], 1)
        self.assertIn("declares no cryptographic hash", out.getvalue())

    def test_a_held_sha256_is_found_in_the_database(self):
        from scripts import auto_fetch

        db = {"files": {"s": {"path": "bios/x/dsi.bin", "size": 3}},
              "indexes": {"by_sha256": {"f" * 64: "s"}}}
        self.assertEqual(
            auto_fetch.step1_crossref_db({"sha256": "F" * 64}, db), "bios/x/dsi.bin"
        )

    def test_an_entry_without_a_hash_is_not_searched(self):
        from unittest import mock

        from scripts import auto_fetch

        entry = {"name": "DICROM.ROM", "system": "fujitsu-fm7"}
        out = io.StringIO()
        with mock.patch.object(auto_fetch, "step2_scan_branches") as branches, \
                contextlib.redirect_stdout(out):
            result = auto_fetch.fetch_missing([entry], {"files": {}}, "bios", dry_run=True)
        branches.assert_not_called()
        self.assertEqual(result["stats"]["unverifiable"], 1)
        self.assertNotIn("Would search", out.getvalue())
        self.assertIn("Not searched", out.getvalue())


class AForcedRehashIsCheckedAgainstTheLastOne(unittest.TestCase):
    """This host has computed a wrong SHA-1 under load. The pipeline's forced
    rebuild threw the previous digests away and wrote whatever it read."""

    def test_a_reading_the_cache_and_a_second_reading_contradict_is_outvoted(self):
        from unittest import mock

        from scripts import generate_db

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        readings = iter([{"sha1": "b" * 40}, {"sha1": "a" * 40}])
        with mock.patch.object(generate_db, "compute_hashes", lambda *a, **k: next(readings)), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            settled = generate_db._settled_hashes(Path("x.bin"), cached, 1.0, 4)
        self.assertEqual(settled["sha1"], "a" * 40)
        self.assertIn("WARNING", err.getvalue())

    def test_two_agreeing_readings_against_an_unmoved_file_stop_the_run(self):
        """The host has returned the same wrong SHA-1 twice in a row
        (DSi_Nand_USA.bin as 62b100f2, 2026-10-22). Taking two agreeing
        readings as a rewrite put the wrong value in the cache, where every
        later run read it back. An unmoved file is never rewritten silently."""
        from unittest import mock

        from scripts import generate_db

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        with mock.patch.object(generate_db, "compute_hashes", lambda *a, **k: {"sha1": "b" * 40}), \
                self.assertRaisesRegex(RuntimeError, "touch"):
            generate_db._settled_hashes(Path("x.bin"), cached, 1.0, 4)

    def test_a_changed_file_takes_its_new_digest(self):
        from unittest import mock

        from scripts import generate_db

        cached = {"sha1": "a" * 40, "mtime": 1.0, "size": 4}
        with mock.patch.object(generate_db, "compute_hashes", lambda *a, **k: {"sha1": "c" * 40}):
            self.assertEqual(
                generate_db._settled_hashes(Path("x.bin"), cached, 2.0, 4)["sha1"], "c" * 40
            )


class AnUnknownTargetIsRefusedUnderAll(unittest.TestCase):
    """--all --target swtich skipped every platform with targets and checked
    BizHawk and MiSTer unfiltered: a green run about no Switch at all."""

    def test_a_typo_is_refused_and_targetless_platforms_are_left_out(self):
        from scripts.common import build_target_cores_cache, list_registered_platforms

        platforms = list_registered_platforms(str(ROOT / "platforms"))
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                build_target_cores_cache(platforms, "swtich", str(ROOT / "platforms"), is_all=True)
            _cache, kept = build_target_cores_cache(
                platforms, "switch", str(ROOT / "platforms"), is_all=True
            )
        self.assertNotIn("bizhawk", kept)
        self.assertIn("retroarch", kept)


class DocsDescribeTheRegistriesTheyName(unittest.TestCase):
    """The contributing guide said files over 50 MB are release assets and that
    RPG Maker and ScummVM were the trees kept out of dedup. `.gitignore`
    decides the first, four committed files exceed 50 MB, and NODEDUP_DIRS
    holds eleven trees."""

    SIZE_RULE = re.compile(r"(over|larger than|>)\s*50\s*MB[^\n]*(release|asset)", re.I)

    def _texts(self):
        paths = sorted((ROOT / "wiki").glob("*.md"))
        paths += [ROOT / "scripts" / "generate_readme.py", ROOT / "CONTRIBUTING.md"]
        return [(p, p.read_text(encoding="utf-8")) for p in paths]

    def test_no_page_says_size_decides_a_release_asset(self):
        offenders = [str(p.relative_to(ROOT)) for p, text in self._texts()
                     if self.SIZE_RULE.search(text)]
        self.assertEqual(offenders, [])

    def test_the_dedup_list_is_named_whole_or_by_its_constant(self):
        from dedup import NODEDUP_DIRS
        tools = (ROOT / "wiki" / "tools.md").read_text(encoding="utf-8")
        line = next(l for l in tools.splitlines() if "NODEDUP_DIRS" in l)
        # Compared as list items: `mame` was missing while the substring
        # test found it in `_mame_clones.json` on the same line.
        listed = line.split("`NODEDUP_DIRS`", 1)[1].split(":", 1)[1].rstrip(" |")
        self.assertEqual(
            sorted(item.strip() for item in listed.split(",")),
            sorted(NODEDUP_DIRS),
        )
        readme_gen = (ROOT / "scripts" / "generate_readme.py").read_text(encoding="utf-8")
        self.assertIn("NODEDUP_DIRS", readme_gen)


class AScraperThatCannotStartSaysWhy(unittest.TestCase):
    """Scrapers resolve their tag or branch head in the constructor, and
    scraper_cli built the scraper outside its try: a refused API call ended
    in a traceback instead of a message saying to set GITHUB_TOKEN."""

    def _run(self, scraper_class, token: str | None):
        import contextlib
        import io
        from unittest import mock

        from scraper.base_scraper import scraper_cli

        env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
        if token:
            env["GITHUB_TOKEN"] = token
        err = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, "argv", ["x", "--dry-run"]), \
                contextlib.redirect_stderr(err), \
                self.assertRaises(SystemExit) as stop:
            scraper_cli(scraper_class)
        return stop.exception.code, err.getvalue()

    def test_a_failing_constructor_exits_with_a_hint(self):
        class Refused:
            def __init__(self):
                raise RuntimeError("cannot read the head of a/b@main: HTTP 403")

        code, err = self._run(Refused, None)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", err)
        self.assertIn("GITHUB_TOKEN", err)

    def test_with_a_token_the_hint_points_elsewhere(self):
        class Offline:
            def fetch_requirements(self):
                raise ConnectionError("no route to host")

        code, err = self._run(Offline, "t")
        self.assertEqual(code, 1)
        self.assertNotIn("GITHUB_TOKEN", err)


class AStepThatCannotFailTheRunIsNotShownFailed(unittest.TestCase):
    """check_buildbot leaves all_ok alone, and the summary printed it FAILED
    right above "Pipeline COMPLETE". The total also missed the duration
    column by fourteen characters."""

    def test_every_step_outside_all_ok_is_declared_non_blocking(self):
        import pipeline

        lines = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8").splitlines()
        loose = set()
        for number, line in enumerate(lines):
            found = re.search(r'results\["(\w+)"\] = ok$', line.strip())
            if not found:
                continue
            after = " ".join(lines[number + 1:number + 4])
            if "all_ok" not in after and "sys.exit" not in after:
                loose.add(found.group(1))
        self.assertEqual(loose, set(pipeline.NON_BLOCKING))

    def test_the_total_sits_under_the_durations(self):
        step = f"  {'x':.<40} {'OK':<7}{1.0:>8.1f}s"
        total = f"  {'total':.<40} {'':<7}{12.5:>8.1f}s"
        self.assertEqual(len(step), len(total))
        self.assertIn("{'':<7}{total_elapsed:>8.1f}s",
                      (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8"))


class AHashConflictIsReportedOnce(unittest.TestCase):
    """check_freshness opened on six copies of one truth.py warning, one per
    platform whose model met the same two GameIndex.yaml declarations."""

    def test_the_same_pair_prints_once(self):
        import contextlib
        import io

        import truth

        truth._CONFLICTS_SHOWN.clear()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for _platform in range(6):
                existing = {"name": "x.yaml", "sha1": "a" * 40}
                truth._merge_hashes(existing, {"name": "x.yaml", "sha1": "b" * 40}, "core")
        self.assertEqual(err.getvalue().count("WARNING"), 1)


class ThePipelineRunsTheSchemaCheckCIRuns(unittest.TestCase):
    """The pipeline the repository asks for after every change never ran
    validate_schemas.py, which PR validation does: a profile with an
    unquoted numeric core name passed it and failed CI on push."""

    def test_the_ci_command_is_a_pipeline_step(self):
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        command = re.search(r"python (scripts/validate_schemas\.py[^\n]*)", workflow).group(1)
        script, *flags = command.split()
        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn(f'"{script}"', source)
        for flag in flags:
            self.assertIn(f'"{flag}"', source)

    def test_the_site_is_rendered_as_the_deploy_renders_it(self):
        """The pipeline generated pages without rendering them: 20 pages with
        duplicate ids passed it and failed the deploy."""
        workflow = (ROOT / ".github" / "workflows" / "deploy-site.yml").read_text(encoding="utf-8")
        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn("npm run build --prefix website", workflow)
        self.assertIn('["npm", "run", "build", "--prefix", "website"]', source)
        self.assertIn("scripts/validate_site.py", workflow)
        self.assertIn('"scripts/validate_site.py"', source)


class TheReleaseBuildsEveryServedPackInOneRun(unittest.TestCase):
    """The release ran the pipeline, then built and checked RetroPie by hand:
    the consistency check between verify and the pack never covered it."""

    def test_the_pipeline_step_covers_every_platform(self):
        page = (ROOT / "wiki" / "release-process.md").read_text(encoding="utf-8")
        self.assertIn("python scripts/pipeline.py\n", page)
        self.assertNotIn("generate_pack.py --platform retropie", page)


class WhatOnlyAnInstallProvidesIsListed(unittest.TestCase):
    """A file installed with its emulator is already on the user's machine.
    A copy nothing else asks for is dead weight in the collection."""

    def test_only_the_bundled_only_copy_is_listed(self):
        import tempfile

        import bundled_only

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp, \
                mock.patch.object(bundled_only, "list_registered_platforms", return_value=[]):
            def entry(sha1, name):
                path = Path(tmp, name)
                path.write_bytes(name.encode())
                return {"path": str(path), "name": name, "sha1": sha1,
                        "md5": sha1[:32], "size": path.stat().st_size}

            db = {"bios_dir": tmp,
                  "files": {"a" * 40: entry("a" * 40, "icon.png"),
                            "b" * 40: entry("b" * 40, "bios.rom")},
                  "indexes": {"by_name": {"icon.png": ["a" * 40], "bios.rom": ["b" * 40]},
                              "by_md5": {}, "by_crc32": {}, "by_sha256": {},
                              "by_path_suffix": {}}}
            profiles = {
                "app": {"files": [{"name": "icon.png", "sha1": "a" * 40, "bundled": True},
                                  {"name": "bios.rom", "sha1": "b" * 40, "bundled": True}]},
                "core": {"files": [{"name": "bios.rom", "sha1": "b" * 40}]},
            }
            rows = bundled_only.bundled_only(db, profiles, tmp, Path(tmp))
            self.assertEqual([row["path"] for row in rows], [str(Path(tmp, "icon.png"))])
            # A platform whose package leaves the file out brings it from the
            # collection: the copy stays.
            profiles["app"]["files"][0]["not_bundled_on"] = ["someplatform"]
            self.assertEqual(bundled_only.bundled_only(db, profiles, tmp, Path(tmp)), [])

    def test_every_copy_of_the_listed_bytes_is_listed(self):
        """The database keeps one path per content: splitwolf's sprite
        folders hold one file several times and took five passes to empty."""
        import hashlib
        import tempfile

        import bundled_only

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            for name in ("dir1/a.bmp", "dir2/a.bmp", "dir2/b.bmp"):
                Path(tmp, name).parent.mkdir(exist_ok=True)
                Path(tmp, name).write_bytes(b"same" if "a.bmp" in name else b"diff")
            sha1 = hashlib.sha1(b"same").hexdigest()
            row = {"sha1": sha1, "path": Path(tmp, "dir1/a.bmp").as_posix(), "size": 4,
                   "emulators": ["splitwolf"]}
            copies = bundled_only.other_copies([row], Path(tmp))
            self.assertEqual([c["path"] for c in copies], [Path(tmp, "dir2/a.bmp").as_posix()])

    def test_the_collection_holds_no_copy_only_an_install_provides(self):
        """The pull request checks run this suite, not the pipeline: without
        this, a copy only a bundled entry reaches merges green."""
        import bundled_only
        from common import load_database, load_emulator_profiles

        rows = bundled_only.bundled_only(
            load_database(str(ROOT / "database.json")),
            load_emulator_profiles(str(ROOT / "emulators")),
            str(ROOT / "platforms"), ROOT / "install",
        )
        self.assertEqual([f"{r['path']} ({', '.join(r['emulators'])})" for r in rows], [],
                         "remove the copy: the emulator's own install provides it")


class TheApiSchemaHoldsTheFieldsItPromises(unittest.TestCase):
    """The data page promises fields are only added within v1, and the
    published schema left items unconstrained: renaming url in
    file-locations.json passed validation and broke consumers silently."""

    def test_a_renamed_field_is_refused(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is tooling only")
        schema = json.loads((ROOT / "schemas" / "site-api-envelope.schema.json").read_text())
        envelope = {"schema_version": 1, "generated_at": "2026-10-20T00:00:00Z",
                    "kind": "file-locations", "count": 1,
                    "items": [{"sha1": "a" * 40, "url": "https://x/y"}]}
        jsonschema.validate(envelope, schema)
        envelope["items"] = [{"sha1": "a" * 40, "href": "https://x/y"}]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(envelope, schema)


class AFileTheLauncherNeverOpens(unittest.TestCase):
    """RetroBat hands standalone BlastEm absolute paths to its own BIOS
    names, so the defaults the emulator would read (cdbios.bin) were listed
    as required and missing on RetroBat although nothing there opens them."""

    def test_unread_on_drops_the_entry_for_that_platform_only(self):
        from validation import deliverable, unread_on

        entry = {"name": "cdbios.bin", "unread_on": ["retrobat"]}
        self.assertTrue(unread_on(entry, "retrobat"))
        self.assertFalse(unread_on(entry, "batocera"))
        self.assertFalse(unread_on(entry, ""))
        self.assertEqual(deliverable([entry], True, "retrobat"), [])
        self.assertEqual(deliverable([entry], True, "batocera"), [entry])

    def test_the_gap_report_reads_it(self):
        source = (ROOT / "scripts" / "verify.py").read_text(encoding="utf-8")
        self.assertIn('unread_on(f, config.get("_key", ""))', source)


class RequiredOnlyReachesDataDirectories(unittest.TestCase):
    """--required-only filtered files and packed every data tree anyway: the
    Required RetroArch pack still carried the 90 FreeIntv overlays, which the
    core reads only with its multi-screen option and replaces by a drawn
    keypad when absent (FreeIntv src/libretro.c:294-296, 350-369)."""

    def _members(self, required_only: bool) -> list[str]:
        from scripts import generate_pack as gp

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            for key in ("needed", "optional"):
                Path(tmp, key).mkdir()
                Path(tmp, key, f"{key}.bin").write_bytes(b"x")
            registry = {
                key: {"local_cache": str(Path(tmp, key))}
                for key in ("needed", "optional")
            }
            systems = {
                "sys": {
                    "data_directories": [
                        {"ref": "needed", "destination": "a"},
                        {"ref": "optional", "destination": "b", "required": False},
                    ]
                }
            }
            return [
                dest
                for _src, dest in gp._data_directory_members(
                    systems, registry, "retroarch", "", False, set(), set(), set(),
                    required_only=required_only,
                )
            ]

    def test_an_optional_tree_leaves_the_required_pack(self):
        self.assertEqual(self._members(False), ["a/needed.bin", "b/optional.bin"])
        self.assertEqual(self._members(True), ["a/needed.bin"])

    def test_every_tree_walk_reads_the_flag(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        # The pack's walk and the manifest's, which records the flag for
        # install.py --required-only.
        self.assertEqual(source.count('if required_only and dd.get("required") is False:'), 1)
        self.assertIn('needed = dd.get("required") is not False\n        if required_only and not needed:',
                      source)
        self.assertIn("seen_parents, required_only=required_only,", source)
        self.assertIn("data_refs, required_only=required_only,", source)

    def test_the_overlays_are_declared_optional(self):
        retroarch = yaml.safe_load((ROOT / "platforms" / "retroarch.yml").read_text())
        trees = retroarch["systems"]["mattel-intellivision"]["data_directories"]
        self.assertEqual(trees, [
            {"ref": "freeintv-overlays", "destination": "freeintv_overlays",
             "required": False},
        ])

    def test_an_alias_reads_the_trees_of_its_core(self):
        """An alias is the same binary under another name. FreeIntv declared
        no overlay tree while its alias freeintv_ts_overlay did, so the
        emulator pack of the core itself left the overlays out."""
        profiles = {
            path.stem: yaml.safe_load(path.read_text(encoding="utf-8"))
            for path in (ROOT / "emulators").glob("*.yml")
        }

        def trees(profile: dict) -> dict:
            return {
                dd["ref"]: dd.get("required", True)
                for dd in profile.get("data_directories") or []
            }

        for name, profile in profiles.items():
            target = profile.get("alias_of")
            if not target or target not in profiles:
                continue
            with self.subTest(alias=name, core=target):
                self.assertEqual(trees(profile), trees(profiles[target]))


class InstallerJsonKindsNeverOverwriteEachOther(unittest.TestCase):
    """Install manifests and target core lists are both <platform>.json.
    --manifest-targets aimed at install/ replaced install/retroarch.json, the
    file every installer downloads, with a target table, exit 0."""

    def _run(self, *flags: str, held: str) -> tuple:
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            target = Path(tmp, "retroarch.json")
            before = (ROOT / held).read_text(encoding="utf-8")
            target.write_text(before, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "scripts/generate_pack.py", *flags,
                 "--offline", "--output-dir", tmp],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
            )
            return proc, before, target.read_text(encoding="utf-8")

    def test_target_lists_refuse_a_manifest_directory(self):
        proc, before, after = self._run(
            "--manifest-targets", held="install/retroarch.json"
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("holds install manifests", proc.stderr)
        self.assertIn("--output-dir", proc.stderr)
        self.assertEqual(after, before)

    def test_manifests_refuse_a_target_list_directory(self):
        proc, before, after = self._run(
            "--manifest", "--platform", "retroarch",
            held="install/targets/retroarch.json",
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("holds per-target core lists", proc.stderr)
        self.assertEqual(after, before)


class PlatformSystemTypoGetsTheClosestNames(unittest.TestCase):
    """--platform retroarch --system sony-playstaton listed the first ten
    systems of the alphabet, 3do to coleco-colecovision."""

    def test_the_hint_names_the_close_systems(self):
        from scripts import generate_pack as gp

        out = io.StringIO()
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp, \
                contextlib.redirect_stdout(out):
            result = gp.generate_pack(
                "retroarch", str(ROOT / "platforms"), {"files": {}, "indexes": {}},
                str(ROOT / "bios"), tmp, emulators_dir=str(ROOT / "emulators"),
                system_filter=["sony-playstaton"], offline=True,
            )
        self.assertIsNone(result)
        printed = out.getvalue()
        self.assertIn("Close matches: sony-playstation", printed)
        self.assertIn("--platform retroarch --list-systems", printed)
        self.assertNotIn("3do", printed)


class HashInputNamesWhatItAccepts(unittest.TestCase):
    """A 12-digit value was looked up as an MD5 and reported NOT FOUND, a
    SHA-256 vanished from the input, and the run said only "No valid hashes
    found in input"."""

    def test_digests_are_read_by_length(self):
        from scripts.packresolve import parse_hash_input

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(parse_hash_input(f"0x1A2B3C4D,{sha256}"), [
            ("crc32", "1a2b3c4d"), ("sha256", sha256),
        ])
        self.assertEqual(parse_hash_input("a" * 29), [("md5", "a" * 29)])

    def test_anything_else_is_refused_with_the_formats(self):
        from scripts.packresolve import parse_hash_file, parse_hash_input

        for raw in ("1234567890ab", "zz", "490f666e1afb15b7362b406ed1cea246,zz"):
            with self.subTest(raw=raw), self.assertRaises(ValueError) as ctx:
                parse_hash_input(raw)
            self.assertIn("SHA-256 (64)", str(ctx.exception))
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            listing = Path(tmp, "hashes.txt")
            listing.write_text("# list\n490f666e1afb15b7362b406ed1cea246  a.bin\nb.bin\n")
            with self.assertRaises(ValueError) as ctx:
                parse_hash_file(str(listing))
        self.assertIn("line 3 (b.bin)", str(ctx.exception))

    def test_a_sha256_finds_its_file(self):
        from scripts.packresolve import sha1_for_hash

        db = json.loads((ROOT / "database.json").read_text(encoding="utf-8"))
        sha1, entry = next(
            (k, e) for k, e in db["files"].items() if e.get("sha256")
        )
        self.assertEqual(sha1_for_hash("sha256", entry["sha256"], db), sha1)
        self.assertEqual(sha1_for_hash("md5", entry["md5"][:29], db), sha1)


class ErrorsGoToStderr(unittest.TestCase):
    """The lock refusal and "no pack for" went to stdout: a run redirected to
    a log showed nothing on the terminal and exited 1."""

    @staticmethod
    def _leading_text(node: ast.expr) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr) and node.values:
            return ErrorsGoToStderr._leading_text(node.values[0])
        return ""

    def test_no_error_line_is_printed_to_stdout(self):
        for script in ("generate_pack.py", "pipeline.py"):
            tree = ast.parse((ROOT / "scripts" / script).read_text(encoding="utf-8"))
            seen = 0
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print"
                        and node.args):
                    continue
                text = self._leading_text(node.args[0])
                # Detail lines under a pack's own verdict stay with it.
                if not text.lstrip().startswith("ERROR") or text.startswith("    "):
                    continue
                seen += 1
                with self.subTest(script=script, line=node.lineno):
                    self.assertIn("file", [k.arg for k in node.keywords])
            self.assertGreater(seen, 0, script)


class PipelineOutputDirIsTheOneItWrites(unittest.TestCase):
    """Started from scripts/, the pipeline locked and purged scripts/dist/
    while every step, run from the repository root, wrote to dist/."""

    def test_the_default_is_the_root_dist_wherever_the_run_starts(self):
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(ROOT / "scripts")
        self.assertEqual(pipeline._output_dir(None), str(ROOT / "dist"))
        self.assertEqual(pipeline._output_dir("out"), str(ROOT / "scripts" / "out"))

    def test_main_resolves_it_before_the_lock(self):
        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        body = source[source.index("def main("):]
        self.assertLess(
            body.index("args.output_dir = _output_dir(args.output_dir)"),
            body.index("hold_artifact_lock(args.output_dir)"),
        )


class ToolsRunFromAnyDirectory(unittest.TestCase):
    """From scripts/, verify.py and generate_pack.py ended on a
    FileNotFoundError traceback about platforms/_registry.yml."""

    def _run(self, cwd: Path, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *argv], cwd=cwd, capture_output=True, text=True,
            timeout=600,
        )

    def test_listing_works_from_scripts(self):
        for script in ("verify.py", "generate_pack.py"):
            with self.subTest(script=script):
                proc = self._run(
                    ROOT / "scripts", str(ROOT / "scripts" / script),
                    "--platform", "RetroArch", "--list-systems",
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn("sony-playstation", proc.stdout)

    def test_a_typed_path_is_read_from_where_it_was_typed(self):
        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            proc = self._run(
                Path(tmp), str(ROOT / "scripts" / "generate_pack.py"),
                "--manifest-targets", "--output-dir", "lists",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(Path(tmp, "lists", "retroarch.json").is_file())


class SkipPacksHelpSaysWhatRuns(unittest.TestCase):
    """--help said "Only regenerate DB and verify" while the run went on to
    rewrite derivable.json, README.md and docs/."""

    def test_the_help_names_the_steps_that_still_run(self):
        proc = subprocess.run(
            [sys.executable, "scripts/pipeline.py", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=60, check=True,
        )
        text = " ".join(proc.stdout.split())
        self.assertNotIn("Only regenerate DB and verify", text)
        self.assertIn("step 4e still rewrites install/games/, and steps 7 to 8b rewrite README.md "
                      "and the site unless --skip-docs is given", text)
        self.assertNotIn("docs/", text)

    def test_every_step_it_names_is_one_it_skips(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import pipeline

        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        keys = re.findall(r'skip_notice\("(\w+)", "--skip-packs"\)', source)
        skipped = {pipeline.step_number(key) for key in keys}
        self.assertEqual(skipped, {"4", "4b", "4c", "6"})


class AmigaCdDriversLiveInTheExtendedRom(unittest.TestCase):
    """WinUAE starts without the CD32 or CDTV extended ROM, but cd.device,
    cdtv.device, cdfs.library and cdstrap are resident modules of those ROMs
    and the Kickstarts carry none. Its AROS replacement stands in only for a
    missing Kickstart (memory.cpp:3055-3063), so the CDTV ROM has no
    fallback to downgrade its absence."""

    def test_both_extended_roms_are_required_without_fallback(self):
        profile = yaml.safe_load(
            (ROOT / "emulators" / "winuae.yml").read_text(encoding="utf-8")
        )
        entries = {f["name"]: f for f in profile["files"]}
        for name in ("amiga-ext-310-cd32.rom", "amiga-ext-130-cdtv.rom"):
            with self.subTest(name=name):
                self.assertIs(entries[name]["required"], True)
                self.assertNotIn("hle_fallback", entries[name])


class BizHawkListsEveryDsiNandSlot(unittest.TestCase):
    """FirmwareDatabase.cs:405-410 declares six DSi NAND slots, each a
    placeholder hash and 251658240 + 64 bytes, and DecideNAND
    (MelonDS.cs:684-706) stops a DSi load when none is set. The profile
    listed DSi_Firmware.bin, a placeholder slot of the same kind, and left
    the NANDs out."""

    def test_the_six_regional_nands_are_declared(self):
        profile = yaml.safe_load(
            (ROOT / "emulators" / "bizhawk.yml").read_text(encoding="utf-8")
        )
        entries = {f["name"]: f for f in profile["files"]}
        for region_code in ("JPN", "EUR", "USA", "AUS", "CHN", "KOR"):
            with self.subTest(region=region_code):
                entry = entries[f"DSi_Nand_{region_code}.bin"]
                self.assertEqual(entry["size"], 251658240 + 64)
                self.assertIs(entry["required"], False)
                self.assertNotIn("sha1", entry)


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
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.split()
        self.assertIn("install.py", tracked)
        self.assertIn("scripts/scraper/mame_parser.py", tracked)
        found = []
        for name in sorted(set(tracked)):
            lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
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


class ExternalDownloadsFollowTheRunPolicy(unittest.TestCase):
    """download_external lived outside packresolve and fetched under
    --offline, into the system /tmp, holding the whole body in memory."""

    ENTRY = {"name": "ext.bin", "source_url": "https://example.invalid/ext.bin",
             "sha1": hashlib.sha1(b"payload").hexdigest()}

    def _response(self, body: bytes):
        stream = io.BytesIO(body)
        response = mock.MagicMock()
        response.__enter__.return_value = stream
        response.__exit__.return_value = False
        return response

    def test_offline_never_reaches_the_network(self):
        import packresolve

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(packresolve.urllib.request, "urlopen") as urlopen, \
                contextlib.redirect_stdout(io.StringIO()):
            ok = packresolve.download_external(self.ENTRY, f"{tmp}/x", offline=True)
        self.assertFalse(ok)
        urlopen.assert_not_called()

    def test_the_run_switch_is_inherited(self):
        import packresolve

        saved = packresolve._OFFLINE
        packresolve.set_offline(True)
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                    mock.patch.object(packresolve.urllib.request, "urlopen") as urlopen, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(packresolve.download_external(self.ENTRY, f"{tmp}/x"))
            urlopen.assert_not_called()
        finally:
            packresolve.set_offline(saved)

    def test_a_verified_body_lands_and_a_wrong_one_is_removed(self):
        import packresolve

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "x"
            with mock.patch.object(packresolve.urllib.request, "urlopen",
                                   return_value=self._response(b"payload")):
                self.assertTrue(packresolve.download_external(self.ENTRY, str(target), offline=False))
            self.assertEqual(target.read_bytes(), b"payload")
            target.unlink()
            with mock.patch.object(packresolve.urllib.request, "urlopen",
                                   return_value=self._response(b"other")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(packresolve.download_external(self.ENTRY, str(target), offline=False))
            self.assertFalse(target.exists())

    def test_scratch_files_stay_in_the_repository(self):
        source = (ROOT / "scripts" / "generate_pack.py").read_text(encoding="utf-8")
        self.assertNotIn("def download_external", source)
        self.assertNotIn("urlopen", source)
        for call in re.findall(r"NamedTemporaryFile\(([^)]*)\)", source):
            self.assertIn("dir=", call)


class ATargetTypoIsAnErrorInEveryTool(unittest.TestCase):
    """cross_reference.py ended a mistyped --target in a traceback, and the
    hint sent cross_reference and slots users to a flag they do not have."""

    def test_each_tool_names_the_closest_target(self):
        for script in ("cross_reference.py", "slots.py", "verify.py"):
            with self.subTest(script=script):
                proc = subprocess.run(
                    [sys.executable, f"scripts/{script}", "--platform", "retroarch",
                     "--target", "swich"],
                    cwd=ROOT, capture_output=True, text=True, timeout=300,
                )
                output = proc.stdout + proc.stderr
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn("Traceback", output)
                self.assertIn("Close matches: switch.", output)
                self.assertIn("verify.py --platform retroarch --list-targets", output)


class AnUnknownSystemIsRefusedBeforeAnyWork(unittest.TestCase):
    """generate_pack checked --system inside the build: a typo took the
    output lock and refreshed every data directory, then ended on a WARNING."""

    def test_refused_before_the_lock_and_the_refresh(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as tmp:
            out = Path(tmp) / "never"
            with mock.patch.dict(os.environ, {"RETROBIOS_OFFLINE": ""}):
                proc = subprocess.run(
                    [sys.executable, "scripts/generate_pack.py", "--platform", "batocera",
                     "--system", "playstaton-nothing", "--output-dir", str(out)],
                    cwd=ROOT, capture_output=True, text=True, timeout=120,
                )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn(
                "error: --system playstaton-nothing: unknown system playstaton-nothing",
                proc.stderr,
            )
            self.assertFalse(out.exists())

    def test_a_known_system_passes_the_early_check(self):
        import argparse

        import generate_pack

        parser = argparse.ArgumentParser()
        args = argparse.Namespace(
            system="sony-playstation", platform="retroarch", all=False,
            platforms_dir=str(ROOT / "platforms"), manifest=False,
        )
        generate_pack._resolve_systems(args, parser)
        self.assertEqual(args.system_ids, ["sony-playstation"])


class NoArchiveRepeatsAMemberName(unittest.TestCase):
    """s8k_cpu.zip held three member names twice (MAME reuses them across
    two ROM_SYSTEM_BIOS of one device). Every pack build printed raw zipfile
    warnings and Info-ZIP stops on an interactive replace? at extraction."""

    def test_member_names_are_unique(self):
        archives = sorted((ROOT / "bios").rglob("*.zip"))
        if not archives:
            self.skipTest("no archive under bios/")
        repeated = []
        for path in archives:
            try:
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
            except (zipfile.BadZipFile, OSError):
                continue
            if len(names) != len(set(names)):
                repeated.append(str(path.relative_to(ROOT)))
        self.assertEqual(repeated, [])


class PipelineChildrenSkipNodeCompileCache(unittest.TestCase):
    """The site build's compile cache filled the 4 GB /tmp tmpfs to 3.4 GB:
    every child the pipeline starts carries NODE_DISABLE_COMPILE_CACHE."""

    def test_the_run_helper_sets_it(self):
        source = (ROOT / "scripts" / "pipeline.py").read_text(encoding="utf-8")
        self.assertIn('"NODE_DISABLE_COMPILE_CACHE": "1"', source)


class HiganSuperGameBoyFolderIsFree(unittest.TestCase):
    """higan reads program.rom in the option's folder, SGB.sfc/, then Super
    GameBoy.sfc/. bsnes, Mesen-S and ares read SGB1.sfc and SGB2.sfc as files
    in the same system directory, and SuperSnes9x sgb.sfc, so a pack that only
    had the first two folders never gave the higan cores a Super Game Boy."""

    def test_each_higan_core_has_a_folder_no_core_reads_as_a_file(self):
        import yaml

        file_names: set[str] = set()
        for path in (ROOT / "emulators").glob("*.yml"):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in document.get("files") or []:
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        file_names.add(str(name).casefold())
                if entry.get("path"):
                    file_names.add(str(entry["path"]).casefold())
        for profile in ("higan_sfc", "higan_sfc_balanced"):
            document = yaml.safe_load(
                (ROOT / "emulators" / f"{profile}.yml").read_text(encoding="utf-8")
            )
            folders = {
                str(entry["path"]).split("/", 1)[0]
                for entry in document["files"]
                if str(entry.get("path") or "").endswith("/program.rom")
                and entry.get("system") == "nintendo-sgb"
            }
            with self.subTest(profile=profile):
                self.assertTrue(
                    [f for f in folders if f.casefold() not in file_names], folders
                )


class ProfileNotesDescribeTheCoreAlone(unittest.TestCase):
    """mednafen_pce_fast, sdlpop and x64sdl described the core by what
    another profile of this directory does ("unlike beetle_pce", "unlike the
    other engines in this directory"), which means nothing once the profile
    is read on its own, and 21 lines shouted NOT, ALL or MUST."""

    SHOUT = re.compile(r"\b(NOT|NEVER|ONLY|MUST|ALL|DIFFERENT)\b(?! FOUND)")

    def test_no_profile_shouts_or_compares_with_another_profile(self):
        names = {path.stem.casefold() for path in (ROOT / "emulators").glob("*.yml")}
        names |= {name.replace("_", "-") for name in names}
        found = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if self.SHOUT.search(line):
                    found.append(f"{path.stem}:{number}")
                for match in re.finditer(r"\bunlike (?:the )?([\w+-]+)", line, re.I):
                    if match.group(1).casefold() in names:
                        found.append(f"{path.stem}:{number}")
        self.assertEqual(found, [])


class Ps2BiosImagesAreFoundByContent(unittest.TestCase):
    """PCSX2 and its forks scan the BIOS folder and keep the first 4 to 8 MB
    image with a romdir (pcsx2/ps2/BiosTools.cpp:258-282 at f0523f8a). With
    no found_by the label ps2-0230a-20080220.bin read as a name the core
    opens, and the RetroDECK export added it as a required file."""

    def test_every_ps2_image_scan_is_marked(self):
        """ARMSX2's arcade scan takes 2 to 8 MB COH-H images by their EXTINFO
        serial (BiosTools.cpp:366-419 at 7f914418): r27v1602f.8g read as a
        name armsx2 opens on six platforms."""
        import yaml

        from validation import opens_by_name

        named = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            # Whatever the profile's own flags: TeknoParrot documents its
            # pcsx2x6 component, whose scan is the same (BiosTools.cpp:268-291
            # at 583f0e90), and carries no agnostic flag.
            for entry in profile.get("files") or []:
                if (
                    entry.get("min_size") in (2097152, 4194304)
                    and entry.get("max_size") == 8388608
                    and opens_by_name(entry, profile)
                ):
                    named.append(f"{path.stem}: {entry['name']}")
        self.assertEqual(named, [])


class SynthRomsAreFoundByContent(unittest.TestCase):
    """dosbox-staging's libmt32emu scan identifies each file of the ROM
    folder with identifyROMFile (src/midi/mt32_lasynth_model.cpp:68-91 at
    fa1856c0), and the Sound Canvas plugin hashes its model folder
    (Nuked-SC55-CLAP, RomLoader::Hashing). The truth read the labels as
    names dosbox-staging opens, and MT32_CONTROL.ROM did not count."""

    def test_every_synth_rom_is_marked(self):
        import yaml

        from validation import opens_by_name

        profile = yaml.safe_load(
            (ROOT / "emulators" / "dosbox-staging.yml").read_text(encoding="utf-8")
        )
        named = [
            entry["name"]
            for entry in profile["files"]
            if str(entry.get("path", "")).startswith(("mt32-roms/", "soundcanvas-roms/"))
            and opens_by_name(entry, profile)
        ]
        self.assertEqual(named, [])


class Dev9FilesAreReadFromTheWorkingDirectory(unittest.TestCase):
    """DEV9 opens eeprom.dat and flash.dat by bare name (PCSX2
    pcsx2/DEV9/DEV9.cpp:144, AetherSX2 DEV9/flash.cpp:89): the working
    directory, never the BIOS folder. Eight profiles left load_from unset,
    so the file was packed into the BIOS folder, where nothing reads it."""

    def test_every_dev9_file_names_the_working_directory(self):
        import yaml

        unset = []
        for path in sorted((ROOT / "emulators").glob("*.yml")):
            profile = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for entry in profile.get("files") or []:
                if entry.get("name") in ("eeprom.dat", "flash.dat") and "DEV9" in str(
                    entry.get("source_ref")
                ) and entry.get("load_from") != "working_directory":
                    unset.append(f"{path.stem}: {entry['name']}")
        self.assertEqual(unset, [])


class OpenMsxSystemRomsAreFoundBySha1(unittest.TestCase):
    """openMSX reaches a ROM in share/systemroms through the file pool by
    SHA1 alone, a filename being looked up only beside the machine's XML
    (src/memory/Rom.cc:121-170). Read as names the core opens, the labels
    were added to the KNULLI and Batocera exports."""

    def test_no_systemrom_label_reads_as_a_name(self):
        import yaml

        from validation import opens_by_name

        profile = yaml.safe_load((ROOT / "emulators" / "openmsx.yml").read_text())
        named = [
            entry["name"] for entry in profile["files"]
            if "share/systemroms/" in str(entry.get("path"))
            and opens_by_name(entry, profile)
        ]
        self.assertEqual(named, [])


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
        sources = sorted((ROOT / "scripts").rglob("*.py")) + [ROOT / "install.py"]
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
                            f"{path.relative_to(ROOT)}:{ret.lineno} "
                            f"{len(value.elts)} returned, {len(declared)} declared"
                        )
        self.assertEqual(mismatched, [])


class PrboomPlusCitesFullPaths(unittest.TestCase):
    """prboom-plus cited gl_hires.c, e6y.c, d_client.c and g_game.c bare:
    none resolves against the repository, so the page showed them as plain
    code with no link, and "behind GL_DOOM and PRBOOM_DEBUG" was read as a
    seventeenth citation. Each name has one path in the tree at the pin."""

    def test_every_cited_file_has_its_directory(self):
        import yaml

        from scripts.sourceref import source_ref_values, split_source_ref

        profile = yaml.safe_load((ROOT / "emulators" / "prboom-plus.yml").read_text(encoding="utf-8"))
        refs: list[str] = []

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "source_ref":
                        refs.extend(r for _, r in source_ref_values(value))
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(profile)
        parts = [p for ref in refs for p in split_source_ref(ref)]
        self.assertGreater(len(parts), 40)
        for part in parts:
            with self.subTest(path=part.path):
                self.assertIsNotNone(part.start)
                self.assertTrue(part.path.startswith("prboom2/"), part.path)


class AutoFetchIssueBodyReadsAsWritten(unittest.TestCase):
    """The --create-issues body was a template: Title Case headings, "The
    following...", an exclamation mark, numbered orders to the reader, a
    spaced dash, and hashes cut to 12 characters a contributor cannot
    match a file against."""

    ENTRY = {"name": "scph5501.bin", "system": "sony-playstation",
             "sha1": "b056ee5a4d65937e1a3a17e1e78f3258ea49c38e",
             "md5": "490f666e1afb15b7362b406ed1cea246"}

    def test_full_hashes_and_no_template_phrasing(self):
        from scripts import auto_fetch

        body = auto_fetch.generate_issue_body([self.ENTRY], "RetroArch")
        self.assertIn(f"`{self.ENTRY['sha1']}`", body)
        self.assertIn(f"`{self.ENTRY['md5']}`", body)
        self.assertNotIn("...", body)
        self.assertNotIn("!", body)
        self.assertNotRegex(body, r"(?i)the following|please| - |\bfork\b")
        self.assertNotRegex(body, r"(?m)^\d+\. ")
        for heading in re.findall(r"(?m)^#+ (.*)$", body):
            later = [w for w in heading.split()[1:] if w != "RetroArch"]
            self.assertEqual(later, [w.lower() for w in later], heading)

    def test_the_docstring_says_nothing_is_posted(self):
        from scripts import auto_fetch

        self.assertNotIn("Create GitHub Issue", auto_fetch.__doc__)
        self.assertIn("posts nothing", auto_fetch.__doc__)



class EveryReaderOfACoreFileIsNamed(unittest.TestCase):
    """A requirement two cores read is reported once, the first profile
    hosting the others' claims. Whatever drops the host must not drop the
    claims with it."""

    def test_a_host_its_emulator_installs_leaves_the_others_in_the_pack(self):
        from verify import _split_bundled_claims

        dsperate = {"profile": "dsperate", "name": "usrcheat.dat", "in_repo": True}
        drastic = {"profile": "drastic", "name": "usrcheat.dat", "bundled": True,
                   "in_repo": True, "other_claims": [dsperate]}
        out = _split_bundled_claims([drastic])
        self.assertEqual([(u["profile"], u.get("other_claims")) for u in out],
                         [("drastic", None), ("dsperate", None)])
        alone = {"profile": "drastic", "bundled": True, "other_claims": [
            {"profile": "drastic-legacy", "bundled": True}]}
        self.assertEqual(_split_bundled_claims([alone]), [alone])

    def test_a_held_file_out_of_reach_names_every_core_reading_it(self):
        """harm1.wad is a release asset: a checkout without it omits the file,
        and the omission named gzdoom alone where lzdoom reads it too."""
        from generate_pack import _claim_cores

        extra = {"source_profile": "gzdoom", "other_claims": [
            {"source_profile": "uzdoom"}, {"source_profile": "lzdoom"}]}
        self.assertEqual(_claim_cores(extra), ["gzdoom", "lzdoom", "uzdoom"])

    def test_a_missing_file_names_every_core_reading_it(self):
        from generate_pack import _record_absent

        omitted: dict[str, dict] = {}

        def record(full_dest, entry, system, reason, cores):
            omitted[full_dest] = {"dest": full_dest, "reason": reason, "cores": cores}

        absent = [
            {"name": "NAPALM.GRP", "destination": "NAPALM.GRP", "source_profile": profile,
             "source_system": system}
            for profile, system in (("raze", "nam"), ("eduke32", "napalm"))
        ]
        platform = {"dest": "SHARED.BIN", "reason": "not_found", "cores": None}
        omitted["SHARED.BIN"] = platform
        absent.append({"name": "SHARED.BIN", "destination": "SHARED.BIN",
                       "source_profile": "raze"})
        _record_absent(absent, {}, "", set(), False, set(), omitted, record)
        self.assertEqual(omitted["NAPALM.GRP"]["cores"], ["eduke32", "raze"])
        # A platform's own omission stays the platform's.
        self.assertIsNone(omitted["SHARED.BIN"]["cores"])


if __name__ == "__main__":
    unittest.main()
