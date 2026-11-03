"""No test downloads a release asset unless it says so.

The CI job sets RETROBIOS_OFFLINE, but a local run of the documented command
did not, and e2e fixtures queried the large-files release and wrote its
answers into the shared .cache/large. A test that serves its own assets
clears the variable for itself.

Scratch files go under the repository's tmp/, which git does not track: a
fresh clone has none, and a module run alone raised FileNotFoundError on a
temporary directory instead of naming the missing parent.
"""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("RETROBIOS_OFFLINE", "1")
# A test never waits on, nor blocks, the measurements running on the host.
os.environ.setdefault(
    "RETROBIOS_PROBE_LOCK",
    str(Path(__file__).resolve().parent.parent / "tmp" / "tests" / "probe.lock"),
)

(Path(__file__).resolve().parent.parent / "tmp" / "tests").mkdir(
    parents=True, exist_ok=True
)
# The installer's cache (the games index, what reading a card found) is the
# suite's own: a run never reads nor fills the one of the person running it.
os.environ.setdefault(
    "RETROBIOS_CACHE",
    str(Path(__file__).resolve().parent.parent / "tmp" / "tests" / "cache"),
)
