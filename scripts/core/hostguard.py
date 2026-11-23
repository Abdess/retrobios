"""Host-wide guards every heavy job shares: the automation lock, free disk space and the misread rule."""

from __future__ import annotations

import contextlib
import os
import shutil
from collections.abc import Iterator
from pathlib import Path


DEFAULT_LOCK = Path.home() / ".local" / "state" / "retrobios" / "auto.lock"
LOCK_ENV = "RETROBIOS_AUTO_LOCK"
LOCK_HELD_ENV = "RETROBIOS_AUTO_LOCK_HELD"
# A segfault as a shell reports it. Python reports the signal as -11.
SHELL_SEGFAULT = 139
HOST_MISREAD_MARKERS = ("SystemError", "unknown opcode")


class LockBusy(RuntimeError):
    """Another job holds the host-wide lock."""


@contextlib.contextmanager
def global_lock(path: Path) -> Iterator[None]:
    """Hold the host-wide automation lock, or raise LockBusy at once."""
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise LockBusy(f"{path} is held by another job") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def lock_busy(path: Path) -> bool:
    try:
        with global_lock(path):
            return False
    except LockBusy:
        return True


def free_gb(path: Path) -> float:
    return shutil.disk_usage(path).free / 1024 ** 3


def host_misread(returncode: int, text: str) -> bool:
    """A failure this host's CPU produces under load, worth one retry: a signal
    kill, a segfault a shell reported, or an error sound hardware never raises.
    """
    if returncode < 0 or returncode == SHELL_SEGFAULT:
        return True
    return returncode != 0 and any(marker in text for marker in HOST_MISREAD_MARKERS)
