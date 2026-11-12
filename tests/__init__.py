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
import tempfile
from pathlib import Path

os.environ.setdefault("RETROBIOS_OFFLINE", "1")
# The installer reads the XDG base directories as RetroArch and the
# emulators do. The CI runner sets XDG_CONFIG_HOME to its own home, so tests
# that fake HOME found the runner's folders instead of theirs. A test that
# exercises one of them sets it for itself.
for _name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
    os.environ.pop(_name, None)
# A test never waits on, nor blocks, the measurements running on the host.
# scripts/run_tests.py runs each module in a process of its own, beside
# others: each one gets its own scratch folder, so two never share the
# installer cache, the probe lock or a fixed name below it.
_SCRATCH = Path(os.environ.get("RETROBIOS_TEST_SCRATCH")
                or Path(__file__).resolve().parent.parent / "tmp" / "tests")
_SCRATCH.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("RETROBIOS_PROBE_LOCK", str(_SCRATCH / "probe.lock"))
# A TemporaryDirectory() without dir= landed in /tmp, a 4 GB tmpfs here: once
# another run filled it, modules unrelated to any change failed with ENOSPC.
# The default is the repository's tmp/, for this process and its children.
os.environ["TMPDIR"] = str(_SCRATCH)
tempfile.tempdir = str(_SCRATCH)
# A scratch directory is not part of this checkout: git run inside one must
# not walk up to the repository, as it could not from /tmp.
os.environ["GIT_CEILING_DIRECTORIES"] = str(_SCRATCH)
# The installer's cache (the games index, what reading a card found) is the
# suite's own: a run never reads nor fills the one of the person running it.
os.environ.setdefault("RETROBIOS_CACHE", str(_SCRATCH / "cache"))
