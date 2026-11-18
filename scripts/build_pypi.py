#!/usr/bin/env python3
"""Build the `retrobios` package PyPI serves: install.py as a command.

The wheel and the sdist hold install.py, byte for byte the copy the
bootstraps pin, a launcher that runs it as a script (`retrobios` and
`python -m retrobios`), the metadata, README.md and LICENSE. Nothing of the
collection. packaging/pypi/ holds the project file, the README and
`__main__.py`; this script stages them with install.py and LICENSE into a
build folder, writes `__init__.py` with the version, and runs `uv build`
there with the flit_core backend pinned in the project file.

The version is the UTC date of the last commit that changed install.py,
with the zeros PEP 440 drops left out: 2026-11-09 gives 2026.11.9. When
install.py changed several times that day, the newest gets .N, its rank in
the day: the third change gives 2026.11.9.3. The same install.py always
gives the same version, so PyPI refuses a republish of unchanged code.
SOURCE_DATE_EPOCH is that commit's time, so two builds of one commit give
the same bytes.

Usage:
    python scripts/build_pypi.py
    python scripts/build_pypi.py --output-dir tmp/pypi-dist
"""

from __future__ import annotations

import argparse
from pathlib import Path

from installer_build.pypi import DEFAULT_OUTPUT, build


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help="where the wheel and the sdist go (default: tmp/pypi-dist)")
    args = parser.parse_args()
    for path in build(args.output_dir):
        print(path)
    return 0


if __name__ == "__main__":
    from core.cli import run_cli

    run_cli(main)
