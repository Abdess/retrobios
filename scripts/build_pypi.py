#!/usr/bin/env python3
"""Build the `retrobios` package PyPI serves: install.py as a command.

The wheel and the sdist hold install.py, byte for byte the copy the
bootstraps pin, a two-line launcher that runs it as a script, the metadata,
README.md and LICENSE. Nothing of the collection. The metadata comes from
packaging/pypi/pyproject.toml.

The version is the UTC date of the last commit that changed install.py,
with the zeros PEP 440 drops left out: 2026-11-09 gives 2026.11.9. When
install.py changed several times that day, the newest gets .N, its rank in
the day: the third change gives 2026.11.9.3. The same install.py always
gives the same version, so PyPI refuses a republish of unchanged code.

Both archives are written here with the standard library rather than by a
build backend: the bytes then depend on the inputs alone, on any machine and
with no network. The sdist still names setuptools as its backend, for pip
and uv to build it.

Usage:
    python scripts/build_pypi.py
    python scripts/build_pypi.py --output-dir tmp/pypi-dist
"""

from __future__ import annotations

import argparse
import base64
import calendar
import datetime
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

from sitebootstrap import PIN, SH_NAME

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = ROOT / "packaging" / "pypi"
DEFAULT_OUTPUT = ROOT / "tmp" / "pypi-dist"
MODULE = "retrobios"

# The launcher. runpy runs install.py as __main__, so its own __main__ block
# keeps the exit codes it gives a reader that left (141) and Ctrl+C (130).
LAUNCHER = '''"""The RetroBIOS installer, install.py, run as the retrobios command."""

import runpy
from pathlib import Path

__version__ = "{version}"


def main() -> None:
    runpy.run_path(str(Path(__file__).with_name("install.py")), run_name="__main__")
'''

# The [project] keys the metadata below writes. Another key in pyproject.toml
# would reach a build from the sdist and not the wheel written here.
PROJECT_KEYS = frozenset({
    "name", "dynamic", "description", "readme", "requires-python", "license",
    "license-files", "dependencies", "classifiers", "urls", "scripts",
})


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
    out = subprocess.run(["git", "log", "--format=%ct", "--", "install.py"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [int(line) for line in out.split()]


def load_project() -> dict:
    import tomllib  # noqa: PLC0415  # 3.11, only where a package is built

    with (PACKAGE_DIR / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    unknown = set(project) - PROJECT_KEYS
    if unknown:
        raise ValueError(f"build_pypi.py writes no metadata for {sorted(unknown)}")
    if project["dependencies"] or project["dynamic"] != ["version"]:
        raise ValueError("the package has no dependencies and only its version is dynamic")
    return project


def metadata(project: dict, version: str, readme: str) -> str:
    """Core metadata 2.4, as the wheel's METADATA and the sdist's PKG-INFO."""
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {project['name']}",
        f"Version: {version}",
        f"Summary: {project['description']}",
        *(f"Project-URL: {label}, {url}" for label, url in project["urls"].items()),
        f"License-Expression: {project['license']}",
        *(f"License-File: {name}" for name in project["license-files"]),
        *(f"Classifier: {name}" for name in project["classifiers"]),
        f"Requires-Python: {project['requires-python']}",
        "Description-Content-Type: text/markdown",
    ]
    return "\n".join(lines) + "\n\n" + readme


def installer_bytes() -> bytes:
    """install.py, refused unless it is the one install.sh pins: the package
    then runs the installer the one-line command runs, under the same id."""
    data = (ROOT / "install.py").read_bytes()
    pins = PIN[SH_NAME].findall((ROOT / "install.sh").read_text(encoding="utf-8"))
    if pins != [hashlib.sha256(data).hexdigest()]:
        raise ValueError("install.py is not the installer install.sh pins: recompute the pin")
    return data


def package_files(version: str) -> tuple[dict, dict[str, bytes]]:
    """The project table, and the files both archives ship, by path."""
    project = load_project()
    readme = (PACKAGE_DIR / project["readme"]).read_text(encoding="utf-8")
    files = {
        f"{MODULE}/__init__.py": LAUNCHER.format(version=version).encode(),
        f"{MODULE}/install.py": installer_bytes(),
        "METADATA": metadata(project, version, readme).encode("utf-8"),
        "README.md": readme.encode("utf-8"),
        "pyproject.toml": (PACKAGE_DIR / "pyproject.toml").read_bytes(),
    }
    for name in project["license-files"]:
        files[name] = (ROOT / name).read_bytes()
    return project, files


def _record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}"


def write_wheel(path: Path, project: dict, files: dict[str, bytes], version: str,
                stamp: tuple[int, int, int]) -> None:
    info = f"{project['name']}-{version}.dist-info"
    scripts = "".join(f"{name} = {target}\n" for name, target in project["scripts"].items())
    members = {
        f"{MODULE}/__init__.py": files[f"{MODULE}/__init__.py"],
        f"{MODULE}/install.py": files[f"{MODULE}/install.py"],
        f"{info}/METADATA": files["METADATA"],
        f"{info}/WHEEL": (b"Wheel-Version: 1.0\nGenerator: retrobios build_pypi.py\n"
                          b"Root-Is-Purelib: true\nTag: py3-none-any\n"),
        f"{info}/entry_points.txt": f"[console_scripts]\n{scripts}".encode(),
        **{f"{info}/licenses/{name}": files[name] for name in project["license-files"]},
    }
    record = "".join(_record_line(name, data) + "\n" for name, data in members.items())
    members[f"{info}/RECORD"] = (record + f"{info}/RECORD,,\n").encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            entry = zipfile.ZipInfo(name, date_time=(*stamp, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, data)


def write_sdist(path: Path, project: dict, files: dict[str, bytes], version: str,
                stamp: tuple[int, int, int]) -> None:
    top = f"{project['name']}-{version}"
    members = {
        "PKG-INFO": files["METADATA"],
        "pyproject.toml": files["pyproject.toml"],
        "README.md": files["README.md"],
        **{name: files[name] for name in project["license-files"]},
        f"{MODULE}/__init__.py": files[f"{MODULE}/__init__.py"],
        f"{MODULE}/install.py": files[f"{MODULE}/install.py"],
    }
    mtime = calendar.timegm((*stamp, 0, 0, 0))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members.items():
            entry = tarfile.TarInfo(f"{top}/{name}")
            entry.size, entry.mtime, entry.mode = len(data), mtime, 0o644
            archive.addfile(entry, io.BytesIO(data))
    with path.open("wb") as handle, gzip.GzipFile(fileobj=handle, mode="wb", filename="",
                                                   mtime=mtime) as packed:
        packed.write(raw.getvalue())


def build(output_dir: Path) -> tuple[Path, Path]:
    """The wheel and the sdist in output_dir, replacing earlier builds there."""
    version = package_version(install_py_commits())
    year, month, day = (int(part) for part in version.split(".")[:3])
    stamp = (year, month, day)
    project, files = package_files(version)
    output_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.whl", "*.tar.gz"):
        for old in output_dir.glob(f"{project['name']}-{pattern}"):
            old.unlink()
    wheel = output_dir / f"{project['name']}-{version}-py3-none-any.whl"
    sdist = output_dir / f"{project['name']}-{version}.tar.gz"
    write_wheel(wheel, project, files, version, stamp)
    write_sdist(sdist, project, files, version, stamp)
    return wheel, sdist


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help="where the wheel and the sdist go (default: tmp/pypi-dist)")
    args = parser.parse_args()
    for path in build(args.output_dir):
        print(path)
    return 0


if __name__ == "__main__":
    from common import run_cli

    run_cli(main)
