"""The `retrobios` package PyPI serves: install.py as a command."""

from __future__ import annotations

import datetime
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.paths import REPO_ROOT
from installer_build.pins import pinned_sha256


PACKAGE_DIR = REPO_ROOT / "packaging" / "pypi"
DEFAULT_OUTPUT = REPO_ROOT / "tmp" / "pypi-dist"
MODULE = "retrobios"

# The launcher. runpy runs install.py as __main__, so its own __main__ block
# keeps the exit codes it gives a reader that left (141) and Ctrl+C (130).
LAUNCHER = '''"""The RetroBIOS installer, install.py, run as the retrobios command."""

import os
import runpy
from pathlib import Path

__version__ = "{version}"


def main() -> None:
    # The hints give back the command that ran this, not python3 install.py.
    os.environ["RETROBIOS_BOOTSTRAP"] = "pypi"
    runpy.run_path(str(Path(__file__).with_name("install.py")), run_name="__main__")
'''


def package_version(stamps: list[int]) -> str:
    """The version of install.py from its commit times, newest first (UTC)."""
    if not stamps:
        raise ValueError("install.py has no commit to date the package by")
    day = datetime.datetime.fromtimestamp(stamps[0], datetime.timezone.utc).date()
    rank = sum(1 for stamp in stamps
               if datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).date() == day)
    base = f"{day.year}.{day.month}.{day.day}"
    return base if rank == 1 else f"{base}.{rank}"


def install_py_commits() -> list[int]:
    """Commit times of install.py, newest first, from git."""
    out = subprocess.run(["git", "log", "--format=%ct", "--", "install.py"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [int(line) for line in out.split()]


def installer_bytes() -> bytes:
    """install.py, refused unless it is the one install.sh pins: the package
    then runs the installer the one-line command runs, under the same id."""
    data = (REPO_ROOT / "install.py").read_bytes()
    if pinned_sha256("install.sh", REPO_ROOT) != hashlib.sha256(data).hexdigest():
        raise ValueError("install.py is not the installer install.sh pins: recompute the pin")
    return data


def stage(folder: Path, version: str) -> None:
    """The project as the backend reads it."""
    module = folder / MODULE
    module.mkdir(parents=True)
    for name in ("pyproject.toml", "README.md"):
        shutil.copyfile(PACKAGE_DIR / name, folder / name)
    shutil.copyfile(REPO_ROOT / "LICENSE", folder / "LICENSE")
    shutil.copyfile(PACKAGE_DIR / MODULE / "__main__.py", module / "__main__.py")
    (module / "__init__.py").write_text(LAUNCHER.format(version=version), encoding="utf-8")
    (module / "install.py").write_bytes(installer_bytes())


def build(output_dir: Path) -> tuple[Path, Path]:
    """The wheel and the sdist in output_dir, replacing earlier builds there."""
    stamps = install_py_commits()
    version = package_version(stamps)
    output_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.whl", "*.tar.gz"):
        for old in output_dir.glob(f"{MODULE}-{pattern}"):
            old.unlink()
    scratch = REPO_ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pypi-stage-", dir=scratch) as name:
        folder = Path(name) / "retrobios"
        stage(folder, version)
        # Without a flag, uv builds the sdist, then the wheel from that sdist:
        # what a user building from the sdist gets is what is published.
        subprocess.run(
            ["uv", "build", "--quiet", "--out-dir", str(output_dir.resolve()), str(folder)],
            check=True, env={**os.environ, "SOURCE_DATE_EPOCH": str(stamps[0])})
    wheel = output_dir / f"{MODULE}-{version}-py3-none-any.whl"
    sdist = output_dir / f"{MODULE}-{version}.tar.gz"
    for path in (wheel, sdist):
        if not path.is_file():
            raise RuntimeError(f"uv build wrote no {path.name}")
    return wheel, sdist
