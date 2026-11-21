"""The check_freshness.py --json report a refresh starts from, run or read from a file."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.paths import REPO_ROOT
from freshness.stalejob import AUTO_AREAS, MANUAL_AREAS

CHECK_FRESHNESS = REPO_ROOT / "scripts" / "check_freshness.py"


def run_check_freshness(areas: tuple[str, ...], extra: list[str]) -> list[dict]:
    """Run check_freshness.py --json and return its findings."""
    cmd = [sys.executable, str(CHECK_FRESHNESS), "--json"]
    if areas and set(areas) != set(AUTO_AREAS + MANUAL_AREAS):
        cmd += ["--only", ",".join(areas)]
    cmd += extra
    try:
        proc = subprocess.run(
            cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False, timeout=1800
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"check_freshness.py did not finish in {exc.timeout:.0f} s: run "
            f"`{' '.join(cmd[1:])} > report.json` alone, then pass --findings report.json"
        ) from exc
    # Exit 1 is the STALE rows, and also a crash: only a JSON list on stdout
    # tells them apart, and the crash's own message is on stderr.
    try:
        findings = json.loads(proc.stdout) if proc.returncode in (0, 1) else None
    except json.JSONDecodeError:
        findings = None
    if not isinstance(findings, list):
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        raise RuntimeError(
            f"check_freshness.py failed (exit {proc.returncode}):\n"
            + "\n".join(tail or ["(no output)"])
        )
    return findings


def load_findings(path: Path, areas: tuple[str, ...]) -> list[dict]:
    """A saved check_freshness.py --json report, kept to the asked areas."""
    try:
        findings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read findings from {path}: {exc}") from exc
    if not isinstance(findings, list):
        raise RuntimeError(f"{path} is not a check_freshness.py --json report")
    return [f for f in findings if f.get("area") in areas]
