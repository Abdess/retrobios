"""Each step's command, run from the repository root with its output echoed as it comes."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from core.paths import REPO_ROOT
from orchestrate.labels import step_title


def pack_output_dir(typed: str | None) -> str:
    """The pack directory as an absolute path.

    Every step runs from the repository root, while the lock and the purge
    of stale packs ran here, against the caller's directory: started from
    scripts/, the run locked and purged scripts/dist/ and wrote its packs to
    dist/. A directory the caller typed is read from where they typed it.
    """
    if typed is None:
        return str(REPO_ROOT / "dist")
    return str(Path(typed).resolve())


def run(cmd: list[str], label: str) -> tuple[bool, str]:
    """Run a command, echoing its output as it comes. Returns (success, output).

    The output used to be captured and printed when the step ended, stderr
    after stdout: a twenty-minute pack build showed nothing, and a warning
    landed far from the line it was about. One stream, read line by line.
    """
    title = step_title(label)
    print(f"\n--- {title} ---", flush=True)
    start = time.monotonic()
    lines: list[str] = []
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        # Node's compile cache lands in /tmp, a 4 GB tmpfs here: the site
        # build filled it to 3.4 GB across a day of pipeline runs.
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONUNBUFFERED": "1", "NODE_DISABLE_COMPILE_CACHE": "1"},
    ) as proc:
        for line in proc.stdout or ():
            lines.append(line)
            print(line, end="", flush=True)
        returncode = proc.wait()
    elapsed = time.monotonic() - start

    ok = returncode == 0
    print(f"--- {title}: {'OK' if ok else 'FAILED'} ({elapsed:.1f}s) ---")
    return ok, "".join(lines)
