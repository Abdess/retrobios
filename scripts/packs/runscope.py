"""The platforms a run keeps, its notices printed and a refusal ending it."""

from __future__ import annotations

import sys
from typing import TextIO

from resolve.cores import RunScope


def settle_scope(scope: RunScope, notices_to: TextIO) -> list[str]:
    """Print the scope's notices on `notices_to` and return the platforms it
    keeps. A refused scope prints its reason on stderr and exits 1."""
    for line in scope.notices:
        print(line, file=notices_to)
    if scope.refusal is not None:
        print(f"ERROR: {scope.refusal}", file=sys.stderr)
        sys.exit(1)
    return scope.kept
