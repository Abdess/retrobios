"""What fails a verify run under --strict, and the line that says why."""

from __future__ import annotations

import sys

from packs.verdicts import Severity, Status


def platform_strict_failure(results: list[dict]) -> str | None:
    """The failure of platform results counting a critical file: a required
    file missing where the frontend reads hashes, or None.

    A file present whose hash the frontend does not confirm is UNTESTED, a
    warning (Batocera's BiosStatus calls it so): reported, not failed.
    """
    critical = sum(r["severity_counts"].get(Severity.CRITICAL, 0) for r in results)
    if not critical:
        return None
    return (f"ERROR: {critical} required file(s) missing where the frontend "
            "checks hashes")


def emulator_strict_failure(result: dict) -> str | None:
    """The failure of an emulator lacking a file it cannot run without, or None.

    The emulator, not a frontend, is the judge here: a required file with no
    HLE fallback that the collection does not hold stops the core.
    """
    missing = sorted({
        d["name"] for d in result["details"]
        if d["status"] == Status.MISSING and d.get("required", True)
        and not d.get("hle_fallback")
    })
    if not missing:
        return None
    return f"ERROR: {len(missing)} required file(s) missing: {', '.join(missing)}"


def exit_if_strict(strict: bool, results: list[dict]) -> None:
    """Exit 1 under --strict when a platform result counts a critical file."""
    failure = platform_strict_failure(results)
    if strict and failure:
        print(failure, file=sys.stderr)
        sys.exit(1)


def exit_if_strict_emulator(strict: bool, result: dict) -> None:
    """Exit 1 under --strict when an emulator lacks a file it cannot run without."""
    failure = emulator_strict_failure(result)
    if strict and failure:
        print(failure, file=sys.stderr)
        sys.exit(1)
