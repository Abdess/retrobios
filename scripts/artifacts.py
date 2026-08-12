"""Writing generated files, and not writing them.

A generated artefact carries a timestamp but must not be rewritten
when only the clock moved: the CI freshness guard is a git diff, and
it is only meaningful if the comparison ignores the hour."""

from __future__ import annotations

import contextlib
import os
import re


_TIMESTAMP_PATTERNS = [
    re.compile(r'"generated_at":\s*"[^"]*"'),  # database.json
    re.compile(r'"imported_at":\s*"[^"]*"'),  # provenance snapshots
    re.compile(r"\*Auto-generated on [^*]*\*"),  # README.md
    re.compile(r"\*Generated on [^*]*\*"),  # docs site pages
    # The decorated pages carry the same stamp again as a rendered element,
    # and missing it rewrote every page on every run for the clock alone.
    re.compile(r'<div class="rb-timestamp">[^<]*</div>'),
]

def write_if_changed(path: str, content: str, normalize=None) -> bool:
    """Write content to path only if the non-timestamp content differs.

    Compares new and existing content after stripping timestamp lines.
    Returns True if the file was written, False if skipped (unchanged).

    A caller that writes a file in two passes -a body, then the same body
    wrapped in front matter -passes ``normalize`` to reduce both sides to the
    part it owns. Without it the second pass always sees a difference, the
    file is rewritten, and the fresh timestamp defeats the comparison.
    """
    if os.path.exists(path):
        with open(path) as f:
            existing = f.read()
        before, after = (
            (normalize(existing), normalize(content))
            if normalize
            else (existing, content)
        )
        if _strip_timestamps(before) == _strip_timestamps(after):
            return False
    with open(path, "w") as f:
        f.write(content)
    return True

def _strip_timestamps(text: str) -> str:
    """Remove known timestamp patterns for content comparison."""
    result = text
    for pattern in _TIMESTAMP_PATTERNS:
        result = pattern.sub("", result)
    return result

class ArtifactLockBusy(RuntimeError):
    """Raised when another process already holds the artifact directory."""

@contextlib.contextmanager
def artifact_lock(directory: str, exclusive: bool = True):
    """Serialize access to a shared artifact directory across processes.

    Two pipeline runs building the same dist/ leave readers looking at
    half-written ZIPs, which surfaces as BadZipFile far from its cause.
    Writers take the lock exclusively, readers share it. On platforms
    without flock the lock is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    os.makedirs(directory, exist_ok=True)
    lock_path = os.path.join(directory, ".lock")
    mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    with open(lock_path, "w") as handle:
        try:
            fcntl.flock(handle, mode | fcntl.LOCK_NB)
        except OSError as exc:
            raise ArtifactLockBusy(
                f"{directory} is in use by another run "
                f"(lock: {lock_path}). Wait for it to finish."
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
