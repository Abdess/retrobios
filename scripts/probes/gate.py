"""The gate a campaign commit passes: tests, schemas, verify and pack of the changed profiles."""

from __future__ import annotations

import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from unattended import worktree
from probes.host import Host


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------

def gate(root: Path, emulators: Sequence[str], host: Host | None = None) -> int:
    """The measurement tests, the schemas, and verify plus an emulator pack
    for each profile the campaign changed."""
    host = host or Host()
    python = sys.executable
    steps = [
        [python, "-m", "unittest", "tests.test_measurements", "tests.test_campaign"],
        [python, "scripts/validate_schemas.py", "--source-only"],
    ]
    for emulator in sorted(set(emulators)):
        steps.append([python, "scripts/verify.py", "--emulator", emulator])
        steps.append([python, "scripts/generate_pack.py", "--emulator", emulator, "--offline",
                      "--output-dir", "tmp/campaign/packs"])
    for argv in steps:
        proc = host.run(argv, cwd=root, check=False)
        if proc.returncode != 0:
            print(f"gate: {' '.join(argv)} exited {proc.returncode}", file=sys.stderr)
            return 1
    shutil.rmtree(root / "tmp" / "campaign" / "packs", ignore_errors=True)
    return 0


def changed_profiles(root: Path) -> list[str]:
    return [Path(p).stem for p in worktree.changed_files(root)
            if p.startswith("emulators/") and p.endswith(".yml")]
