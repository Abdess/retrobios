"""The circuit breaker: the CI runs of pushed automation commits, read through
gh, decide whether a job may commit and push.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence

from unattended.jobs import token_env
from unattended.worktree import TARGET


REPO_SLUG = "Abdess/retrobios"


CI_RED = frozenset({"failure", "timed_out", "startup_failure"})
CI_GREEN = frozenset({"success", "skipped", "neutral"})


# Circuit breaker


def gh_json(args: list[str]) -> object:
    """Parsed output of a gh command, or None when gh cannot answer."""
    try:
        proc = subprocess.run(
            ["gh", *args], capture_output=True, text=True, timeout=120, check=False,
            env=token_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


RUN_FIELDS = "workflowName,status,conclusion,headSha,createdAt"


def ci_verdict(runs: Sequence[dict]) -> str:
    """failure as soon as one run is red, success once all ended green."""
    if any(r.get("conclusion") in CI_RED for r in runs):
        return "failure"
    if not runs or any(r.get("status") != "completed" for r in runs):
        return "pending"
    if all(r.get("conclusion") in CI_GREEN for r in runs):
        return "success"
    return "pending"


def refresh_breaker(state: dict, gh: Callable[[list[str]], object], now: str) -> None:
    """Read CI for the last automation push, open or close the breaker."""
    push = state.setdefault("push", {})
    breaker = state.setdefault("breaker", {"open": False})
    sha = push.get("sha")
    if sha and push.get("ci") not in ("success", "failure"):
        runs = gh(["run", "list", "-R", REPO_SLUG, "--commit", sha, "--json", RUN_FIELDS])
        if isinstance(runs, list):
            verdict = ci_verdict(runs)
            push["ci"] = verdict
            if verdict == "failure":
                red = [r for r in runs if r.get("conclusion") in CI_RED]
                state["breaker"] = breaker = {
                    "open": True,
                    "sha": sha,
                    "opened_at": now,
                    "failed_run_at": max(str(r.get("createdAt") or "") for r in runs),
                    "reason": ", ".join(sorted({str(r.get("workflowName")) for r in red})),
                }
                state.setdefault("alerts", {})["ci"] = {
                    "since": now, "detail": f"red CI on {sha[:12]}: {breaker['reason']}",
                }
    if not breaker.get("open"):
        return
    runs = gh([
        "run", "list", "-R", REPO_SLUG, "--branch", TARGET, "--limit", "40",
        "--json", RUN_FIELDS,
    ])
    if not isinstance(runs, list):
        return
    after = [
        r for r in runs
        if str(r.get("createdAt") or "") > breaker.get("failed_run_at", "")
        and r.get("headSha") != breaker.get("sha")
    ]
    if not after:
        return
    newest = max(after, key=lambda r: str(r.get("createdAt") or ""))["headSha"]
    if ci_verdict([r for r in after if r.get("headSha") == newest]) == "success":
        state["breaker"] = {"open": False, "closed_at": now, "closed_by": newest}
        state.get("alerts", {}).pop("ci", None)


def may_push(state: dict) -> str:
    """Empty when a push may go out, else the reason it may not."""
    if state.get("breaker", {}).get("open"):
        return "circuit breaker open"
    push = state.get("push") or {}
    if push.get("sha") and push.get("ci") != "success":
        return f"CI of {push['sha'][:12]} has not ended green"
    return ""
