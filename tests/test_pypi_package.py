"""The `retrobios` package on PyPI is install.py and the command that runs it.

`uvx retrobios`, `pipx run retrobios` and `pip install retrobios` reach the
installer the one-line command runs: the same bytes, so the same id, the
same file lists, cache and exit codes. scripts/build_pypi.py stages the
project and builds it with `uv build` and the flit_core backend, and these
tests read what it wrote and run it.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import configparser
import email.parser
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_pypi  # noqa: E402

MODULE_FILES = {"retrobios/__init__.py", "retrobios/__main__.py", "retrobios/install.py"}


class Built(unittest.TestCase):
    """One build per class, in a scratch folder."""

    _scratch: tempfile.TemporaryDirectory
    scratch: Path
    wheel: Path
    sdist: Path
    version: str

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("uv") is None:
            if os.environ.get("CI"):
                raise AssertionError("CI installs uv")
            raise unittest.SkipTest("uv is not installed")
        cls._scratch = tempfile.TemporaryDirectory(prefix="pypi-")
        cls.scratch = Path(cls._scratch.name)
        cls.wheel, cls.sdist = build_pypi.build(cls.scratch / "dist")
        cls.version = cls.wheel.name.split("-")[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls._scratch.cleanup()


class TheArchivesHoldTheInstallerAndNothingElse(Built):

    def test_wheel_members(self):
        info = f"retrobios-{self.version}.dist-info"
        with zipfile.ZipFile(self.wheel) as archive:
            names = set(archive.namelist())
            self.assertEqual(names, MODULE_FILES | {
                f"{info}/{name}" for name in
                ("METADATA", "WHEEL", "entry_points.txt", "RECORD", "licenses/LICENSE")})
            self.assertEqual(archive.read("retrobios/install.py"),
                             (REPO_ROOT / "install.py").read_bytes())
            entry_points = archive.read(f"{info}/entry_points.txt").decode()
            meta = email.parser.Parser().parsestr(archive.read(f"{info}/METADATA").decode())
        scripts = configparser.ConfigParser()
        scripts.read_string(entry_points)
        self.assertEqual(dict(scripts["console_scripts"]), {"retrobios": "retrobios:main"})
        self.assertEqual(meta["Name"], "retrobios")
        self.assertEqual(meta["Version"], self.version)
        self.assertEqual(meta["Requires-Python"], ">=3.8")
        self.assertIsNone(meta["Requires-Dist"])
        # The backend ends the body with one more newline than the file.
        self.assertEqual(meta.get_payload().rstrip("\n"),
                         (REPO_ROOT / "packaging/pypi/README.md").read_text(
                             encoding="utf-8").rstrip("\n"))

    def test_metadata(self):
        info = f"retrobios-{self.version}.dist-info"
        with zipfile.ZipFile(self.wheel) as archive:
            meta = email.parser.Parser().parsestr(archive.read(f"{info}/METADATA").decode())
        self.assertEqual(meta["Metadata-Version"], "2.4")
        self.assertEqual(meta["License-Expression"], "MIT")
        classifiers = meta.get_all("Classifier")
        # PEP 639: the license is the expression, never a classifier as well.
        self.assertEqual([name for name in classifiers if name.startswith("License ::")], [])
        self.assertEqual(
            [name for name in classifiers if name.startswith("Programming Language :: Python :: 3.")],
            [f"Programming Language :: Python :: 3.{minor}" for minor in range(8, 15)])
        for name in ("Programming Language :: Python :: 3 :: Only",
                     "Development Status :: 5 - Production/Stable",
                     "Intended Audience :: End Users/Desktop", "Environment :: Console",
                     "Operating System :: OS Independent", "Topic :: System :: Emulators"):
            self.assertIn(name, classifiers)
        self.assertTrue(meta["Keywords"])
        self.assertEqual(sorted(url.split(",")[0] for url in meta.get_all("Project-URL")),
                         ["Documentation", "Homepage", "Issues", "Releases", "Source"])

    def test_sdist_members(self):
        top = f"retrobios-{self.version}"
        with tarfile.open(self.sdist) as archive:
            names = {member.name for member in archive.getmembers()}
            installer = archive.extractfile(f"{top}/retrobios/install.py").read()
        self.assertEqual(names, {f"{top}/{name}" for name in (
            *MODULE_FILES, "PKG-INFO", "pyproject.toml", "README.md", "LICENSE")})
        self.assertEqual(installer, (REPO_ROOT / "install.py").read_bytes())

    def test_no_collection_file(self):
        with zipfile.ZipFile(self.wheel) as archive:
            names = archive.namelist()
        with tarfile.open(self.sdist) as archive:
            names += [name.split("/", 1)[1] for name in archive.getnames()]
        for top in ("bios/", "data/", "install/", "platforms/", "emulators/"):
            self.assertEqual([name for name in names if name.startswith(top)], [], top)

    def test_build_is_reproducible(self):
        # SOURCE_DATE_EPOCH is install.py's commit time, so the clock moving
        # between the two builds changes no byte.
        again = build_pypi.build(self.scratch / "again")
        self.assertEqual([path.read_bytes() for path in again],
                         [self.wheel.read_bytes(), self.sdist.read_bytes()])


class TheVersionIsInstallPyCommitDate(unittest.TestCase):
    """The release date put November code under an October version: the
    version now follows the commits of install.py itself."""

    def test_one_change_that_day(self):
        # 2026-11-09 12:00 UTC, then a change the day before.
        self.assertEqual(build_pypi.package_version([1794225600, 1794139200]), "2026.11.9")

    def test_the_rank_in_the_day(self):
        self.assertEqual(build_pypi.package_version([1794229200, 1794225600, 1794222000]),
                         "2026.11.9.3")

    def test_no_commit_refused(self):
        with self.assertRaises(ValueError):
            build_pypi.package_version([])


class AnUnpinnedInstallerIsRefused(unittest.TestCase):
    """The package runs the installer the one-line command runs, or none."""

    def test_pin_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="pypi-pin-") as name:
            root = Path(name)
            (root / "install.py").write_bytes(b"print('another')\n")
            shutil.copyfile(REPO_ROOT / "install.sh", root / "install.sh")
            original = build_pypi.ROOT
            build_pypi.ROOT = root
            try:
                with self.assertRaises(ValueError):
                    build_pypi.installer_bytes()
            finally:
                build_pypi.ROOT = original


def _python38() -> str | None:
    found = shutil.which("python3.8")
    if found is None and os.environ.get("CI"):
        raise AssertionError("CI installs Python 3.8")
    return found


class TheInstalledCommandIsTheInstaller(Built):
    """Installed in a fresh venv, `retrobios` answers as `python install.py`."""

    def _installed(self, python: str, name: str) -> Path:
        env = self.scratch / name
        made = subprocess.run([python, "-m", "venv", str(env)], capture_output=True, text=True,
                              check=False)
        self.assertEqual(made.returncode, 0, made.stderr[-2000:])
        bindir = env / ("Scripts" if os.name == "nt" else "bin")
        done = subprocess.run(
            [str(bindir / "python"), "-m", "pip", "install", "--no-index", "--no-deps",
             "--disable-pip-version-check", str(self.wheel)],
            capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        return bindir / "retrobios"

    def _same_answers(self, python: str, name: str) -> None:
        command = self._installed(python, name)
        # `retrobios` and `python -m retrobios` both run install.py, whose
        # examples then name the package command.
        launchers = ([str(command)], [str(command.with_name("python")), "-m", "retrobios"])
        as_package = {**os.environ, "RETROBIOS_BOOTSTRAP": "pypi"}
        for launcher in launchers:
            for args in (["--help"], ["--version"], ["--no-such-option"]):
                with self.subTest(python=name, launcher=launcher[-1], args=args):
                    packaged = subprocess.run([*launcher, *args], capture_output=True,
                                              text=True, check=False, cwd=self.scratch)
                    script = subprocess.run([python, str(REPO_ROOT / "install.py"), *args],
                                            capture_output=True, text=True, check=False,
                                            cwd=self.scratch, env=as_package)
                    self.assertEqual(
                        (packaged.returncode, packaged.stdout, packaged.stderr),
                        (script.returncode, script.stdout, script.stderr))

    def test_this_python(self):
        self._same_answers(sys.executable, "venv-current")

    def test_a_hint_gives_back_the_package_command(self):
        """Nothing detected, the example said `python3 install.py`."""
        command = self._installed(sys.executable, "venv-hint")
        home = self.scratch / "empty-home"
        home.mkdir()
        env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home),
               "RETROBIOS_INSTALL_OFFLINE": "1"}
        env.pop("RETROBIOS_BOOTSTRAP", None)
        run = subprocess.run([str(command), "--yes"], capture_output=True, text=True,
                             check=False, cwd=self.scratch, env=env)
        out = run.stdout + run.stderr
        self.assertIn("retrobios --platform retroarch --dest", out)
        self.assertNotIn("install.py --platform", out)

    def test_python_38(self):
        python = _python38()
        if python is None:
            self.skipTest("python3.8 is not on PATH")
        self._same_answers(python, "venv-38")


if __name__ == "__main__":
    unittest.main()
