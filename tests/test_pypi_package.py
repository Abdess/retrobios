"""The `retrobios` package on PyPI is install.py and the command that runs it.

`uvx retrobios`, `pipx run retrobios` and `pip install retrobios` reach the
installer the one-line command runs: the same bytes, so the same id, the
same file lists, cache and exit codes. scripts/build_pypi.py writes the
wheel and the sdist, and these tests read what it wrote and run it.
"""

from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import email.parser
import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import venv
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_pypi  # noqa: E402

MODULE_FILES = {"retrobios/__init__.py", "retrobios/install.py"}


class Built(unittest.TestCase):
    """One build per class, in a scratch folder."""

    _scratch: tempfile.TemporaryDirectory
    scratch: Path
    wheel: Path
    sdist: Path
    version: str

    @classmethod
    def setUpClass(cls) -> None:
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
        self.assertEqual(entry_points, "[console_scripts]\nretrobios = retrobios:main\n")
        self.assertEqual(meta["Name"], "retrobios")
        self.assertEqual(meta["Version"], self.version)
        self.assertEqual(meta["Requires-Python"], ">=3.8")
        self.assertIsNone(meta["Requires-Dist"])
        self.assertEqual(meta.get_payload(),
                         (REPO_ROOT / "packaging/pypi/README.md").read_text(encoding="utf-8"))

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
        for args in (["--help"], ["--version"], ["--no-such-option"]):
            with self.subTest(python=name, args=args):
                packaged = subprocess.run([str(command), *args], capture_output=True,
                                          text=True, check=False, cwd=self.scratch)
                script = subprocess.run([python, str(REPO_ROOT / "install.py"), *args],
                                        capture_output=True, text=True, check=False,
                                        cwd=self.scratch)
                self.assertEqual(
                    (packaged.returncode, packaged.stdout, packaged.stderr),
                    (script.returncode, script.stdout, script.stderr))

    def test_this_python(self):
        self._same_answers(sys.executable, "venv-current")

    def test_python_38(self):
        python = _python38()
        if python is None:
            self.skipTest("python3.8 is not on PATH")
        self._same_answers(python, "venv-38")


def _setuptools_builds_the_sdist() -> bool:
    """setuptools 77 reads the license expression the sdist declares."""
    if importlib.util.find_spec("setuptools") is None:
        return False
    import setuptools  # noqa: PLC0415

    return int(setuptools.__version__.split(".")[0]) >= 77


class TheSdistBuildsTheSameWheel(Built):
    """pip and uv build the sdist with setuptools: the files must be those the
    wheel written here holds."""

    def test_setuptools_wheel(self):
        if not _setuptools_builds_the_sdist():
            if os.environ.get("CI"):
                self.fail("CI installs setuptools 77 or newer")
            self.skipTest("setuptools 77 or newer is not installed")
        out = self.scratch / "from-sdist"
        work = self.scratch / "unpacked"
        with tarfile.open(self.sdist) as archive:
            archive.extractall(work, filter="data")
        done = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
             "--no-index", "--disable-pip-version-check", "-w", str(out),
             str(work / f"retrobios-{self.version}")],
            capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr[-2000:])
        (built,) = out.glob("*.whl")
        info = f"retrobios-{self.version}.dist-info"
        with zipfile.ZipFile(built) as theirs, zipfile.ZipFile(self.wheel) as ours:
            self.assertEqual(set(theirs.namelist()) - {f"{info}/top_level.txt"},
                             set(ours.namelist()))
            for name in (*MODULE_FILES, f"{info}/entry_points.txt"):
                self.assertEqual(theirs.read(name), ours.read(name), name)
            fields = ("Name", "Version", "Summary", "License-Expression", "Requires-Python")
            theirs_meta, ours_meta = (
                email.parser.Parser().parsestr(archive.read(f"{info}/METADATA").decode())
                for archive in (theirs, ours))
            for field in fields:
                self.assertEqual(theirs_meta[field], ours_meta[field], field)


if __name__ == "__main__":
    unittest.main()
