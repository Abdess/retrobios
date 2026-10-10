"""Writing generated files, and not writing them.

A generated artefact carries a timestamp but must not be rewritten
when only the clock moved: the CI freshness guard is a git diff, and
it is only meaningful if the comparison ignores the hour."""

from __future__ import annotations

import contextlib
import os
import tempfile
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
    write_text_atomic(path, content)
    return True


def write_text_atomic(path: str, content: str) -> None:
    """Write a whole file or nothing.

    Truncate-then-write leaves a half-written artifact behind an interrupt:
    a partial database.json, manifest or README.md is committed-looking and
    silently wrong. The scratch file sits beside the target so the rename
    stays on one filesystem, which is what makes it atomic.
    """
    directory = os.path.dirname(os.path.abspath(path))
    handle, scratch = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(scratch, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(scratch)
        raise


def write_bytes_atomic(path: str, content: bytes) -> None:
    """Write a whole binary file or nothing, as write_text_atomic does."""
    directory = os.path.dirname(os.path.abspath(path))
    handle, scratch = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "wb") as f:
            f.write(content)
        os.replace(scratch, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(scratch)
        raise


@contextlib.contextmanager
def file_lock(lock_path: str | os.PathLike, shared: bool = False):
    """Hold a lock on lock_path, waiting for it if taken.

    Several sessions refresh the same caches: without it, two swaps of one
    tree interleave, or two read-modify-writes of one index lose an entry.
    On platforms without flock the lock is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)), exist_ok=True)
    with open(lock_path, "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def copy_file_atomic(source: str, path: str) -> None:
    """Copy a file into place whole or not at all, metadata included."""
    import shutil

    directory = os.path.dirname(os.path.abspath(path))
    handle, scratch = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    os.close(handle)
    try:
        shutil.copy2(source, scratch)
        os.replace(scratch, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(scratch)
        raise

def _strip_timestamps(text: str) -> str:
    """Remove known timestamp patterns for content comparison."""
    result = text
    for pattern in _TIMESTAMP_PATTERNS:
        result = pattern.sub("", result)
    return result

class ArtifactLockBusy(RuntimeError):
    """Raised when another process already holds the artifact directory."""

# A run that holds an artifact directory for its whole duration names it
# here for the steps it spawns: they would otherwise be refused by it.
HELD_LOCK_ENV = "RETROBIOS_HELD_ARTIFACT_DIR"


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
    if os.environ.get(HELD_LOCK_ENV) == os.path.realpath(directory):
        yield
        return
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


@contextlib.contextmanager
def hold_artifact_lock(directory: str):
    """Hold a directory exclusively across several child steps.

    A lock taken step by step frees the directory between them: another
    run can purge the packs one step built before the next step checks
    them. The children this process spawns inherit the hold.
    """
    with artifact_lock(directory):
        previous = os.environ.get(HELD_LOCK_ENV)
        os.environ[HELD_LOCK_ENV] = os.path.realpath(directory)
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop(HELD_LOCK_ENV, None)
            else:
                os.environ[HELD_LOCK_ENV] = previous

def _build_timestamp(db: dict | None = None) -> str:
    """Timestamp for generated artifacts.

    Reads the database snapshot the artifact was built from, so rebuilding
    the same data twice yields the same value. Falls back to the clock only
    when no database is at hand.
    """
    stamp = (db or {}).get("generated_at")
    if isinstance(stamp, str) and stamp:
        return stamp
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
