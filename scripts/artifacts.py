"""Writing generated files, and not writing them.

A generated artefact carries a timestamp but must not be rewritten
when only the clock moved: the CI freshness guard is a git diff, and
it is only meaningful if the comparison ignores the hour."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import BinaryIO
import contextlib
import json
import os
import tempfile
import threading
import re


_TIMESTAMP_PATTERNS = [
    re.compile(r'"generated_at":\s*"[^"]*"'),  # database.json
    re.compile(r'"imported_at":\s*"[^"]*"'),  # provenance snapshots
    re.compile(r'"fetched":\s*"[^"]*"'),  # games/catalogs/
    re.compile(r"\*Auto-generated on [^*]*\*"),  # README.md
    re.compile(r"\*Generated on [^*]*\*"),  # docs site pages
    # The decorated pages carry the same stamp again as a rendered element,
    # and missing it rewrote every page on every run for the clock alone.
    re.compile(r'<div class="rb-timestamp">[^<]*</div>'),
    re.compile(r'<time datetime="[^"]*">Data as of [^<]*</time>'),
]

def json_text(value: object) -> str:
    """Stable scalar representation for CSV and SQLite exports."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, bool)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def write_if_changed(
    path: str, content: str, normalize: Callable[[str], str] | None = None
) -> bool:
    """Write content to path only if the non-timestamp content differs.

    Compares new and existing content after stripping timestamp lines.
    Returns True if the file was written, False if skipped (unchanged).

    A caller that writes a file in two passes (a body, then the same body
    wrapped in front matter) passes ``normalize`` to reduce both sides to the
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


_UMASK_LOCK = threading.Lock()


def process_umask() -> int:
    """The process umask, read without letting a second thread see it at 0.

    Reading the umask sets it, so it is put back at once. Two threads doing
    that unguarded interleave as A sets 0 and reads 022, B sets 0 and reads 0,
    A restores 022, B restores 0: the process keeps umask 0 and every file it
    creates afterwards is world-writable.
    """
    with _UMASK_LOCK:
        umask = os.umask(0)
        os.umask(umask)
    return umask


def plain_file_mode() -> int:
    """The mode open() gives a new file: 0o666 less the process umask."""
    return 0o666 & ~process_umask()


def set_plain_mode(path: str | os.PathLike) -> None:
    """Give a scratch file the mode a plain open() would have.

    mkstemp creates its file 0600 so no other user reads it while it is
    written. Renamed into place, that mode stayed: database.json, the
    manifests, the packs and the recipe snapshots came out unreadable to
    every other account on the machine and to a web server serving them.
    """
    os.chmod(path, plain_file_mode())


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
        set_plain_mode(scratch)
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
        set_plain_mode(scratch)
        os.replace(scratch, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(scratch)
        raise


@contextlib.contextmanager
def file_lock(lock_path: str | os.PathLike, shared: bool = False) -> Iterator[None]:
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


def copy_stream_atomic(stream: BinaryIO, path: str) -> None:
    """Stream a download into place whole or not at all.

    A fixed scratch name let two runs interleave their bytes in one file of
    the right size, which the rename then promoted."""
    import shutil

    directory = os.path.dirname(os.path.abspath(path))
    handle, scratch = tempfile.mkstemp(
        dir=directory, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "wb") as f:
            shutil.copyfileobj(stream, f)
        set_plain_mode(scratch)
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


class ArtifactDirectoryMissing(FileNotFoundError):
    """A reader named a directory that does not exist."""

# A run that holds artifact directories for its whole duration names them
# here, os.pathsep apart, for the steps it spawns: they would otherwise be
# refused by it. A pipeline holds the repository root and its --output-dir.
HELD_LOCK_ENV = "RETROBIOS_HELD_ARTIFACT_DIR"
# Where the repository root's lock is taken instead, set by tests/__init__.
REPOSITORY_LOCK_ENV = "RETROBIOS_REPOSITORY_LOCK_DIR"


def _held_directories() -> list[str]:
    return [d for d in os.environ.get(HELD_LOCK_ENV, "").split(os.pathsep) if d]


@contextlib.contextmanager
def artifact_lock(directory: str, exclusive: bool = True) -> Iterator[None]:
    """Serialize access to a shared artifact directory across processes.

    Two pipeline runs building the same dist/ leave readers looking at
    half-written ZIPs, which surfaces as BadZipFile far from its cause.
    Writers take the lock exclusively, readers share it. On platforms
    without flock the lock is a no-op.
    """
    # A reader creating the directory it was pointed at left a typo behind
    # as a directory holding a .lock, and the next run with the same typo
    # no longer said the path did not exist.
    if not exclusive and not os.path.isdir(directory):
        raise ArtifactDirectoryMissing(
            f"{directory}: no such directory, pass the --output-dir the packs "
            "were written to (default dist/)"
        )
    try:
        import fcntl
    except ImportError:
        yield
        return

    os.makedirs(directory, exist_ok=True)
    if os.path.realpath(directory) in _held_directories():
        yield
        return
    lock_dir = directory
    # The test suite runs its modules side by side, each a process with its
    # own scratch folder (scripts/run_tests.py): the repository's hold is
    # taken there, so a module that runs the pipeline or a generator is not
    # refused because another module holds it. Nothing else sets it.
    moved = os.environ.get(REPOSITORY_LOCK_ENV)
    real = os.path.realpath(directory)
    if moved and os.path.isfile(os.path.join(real, "scripts", "artifacts.py")):
        # Keyed by the root's path: a scratch checkout and the process it
        # spawns name the same root, and find the same lock.
        lock_dir = os.path.join(moved, real.strip(os.sep).replace(os.sep, "__"))
        os.makedirs(lock_dir, exist_ok=True)
    lock_path = os.path.join(lock_dir, ".lock")
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
def hold_artifact_lock(directory: str) -> Iterator[None]:
    """Hold a directory exclusively across several child steps.

    A lock taken step by step frees the directory between them: another
    run can purge the packs one step built before the next step checks
    them. The children this process spawns inherit the hold.
    """
    with artifact_lock(directory), publish_hold(directory):
        yield


@contextlib.contextmanager
def publish_hold(directory: str) -> Iterator[None]:
    """Name a directory this process holds to the steps it spawns."""
    previous = os.environ.get(HELD_LOCK_ENV)
    os.environ[HELD_LOCK_ENV] = os.pathsep.join(
        [*_held_directories(), os.path.realpath(directory)]
    )
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(HELD_LOCK_ENV, None)
        else:
            os.environ[HELD_LOCK_ENV] = previous


# What a pipeline run writes at fixed paths, whatever its --output-dir.
REPOSITORY_OUTPUTS = ("database.json", "install/", "README.md", "CONTRIBUTING.md", "website/")


@contextlib.contextmanager
def hold_repository_outputs(root: str = ".") -> Iterator[None]:
    """Hold the outputs a pipeline writes at fixed paths, for the whole run.

    The output-directory lock let a run on tmp/packtest start beside a run
    on dist/: both rewrote database.json, and the second to reach the
    manifest step found install/ held after minutes of work, or, when the
    steps did not overlap, rewrote the committed manifests from its own
    state. The lock file is the repository root's .lock. A pipeline passes
    it to its steps with publish_hold.
    """
    stack = contextlib.ExitStack()
    try:
        stack.enter_context(artifact_lock(root))
    except ArtifactLockBusy as exc:
        raise ArtifactLockBusy(
            f"another run is writing {', '.join(REPOSITORY_OUTPUTS)} "
            f"(lock: {os.path.join(root, '.lock')}). Wait for it to finish."
        ) from exc
    with stack:
        yield


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def repository_output_lock(path: str) -> contextlib.AbstractContextManager[None]:
    """The repository hold, when *path* is one of its fixed outputs.

    Only a pipeline took it: generate_db.py run beside a pipeline replaced
    database.json between its verify and its packs, and a manifest run on
    install/ made the pipeline's own manifest step fail after minutes of
    work. A path elsewhere (a scratch --output) takes nothing.
    """
    target = os.path.realpath(path)
    for output in REPOSITORY_OUTPUTS:
        fixed = os.path.join(_REPO_ROOT, output.rstrip("/"))
        if target == fixed or target.startswith(fixed + os.sep):
            return hold_repository_outputs(_REPO_ROOT)
    return contextlib.nullcontext()


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
