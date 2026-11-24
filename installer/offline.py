"""The offline mode and the local sources a run reads in place of the network."""
from __future__ import annotations

import os
import weakref
from pathlib import Path
from typing import TYPE_CHECKING

from installer.host_fs import read_local_json
from installer.invocation import DEFAULT_JOBS, OFFLINE_VARIABLE, offline_requested
from installer.platforms import AVAILABLE_PLATFORMS
from installer.remote import MAX_MANIFEST_BYTES

if TYPE_CHECKING:
    from installer.from_folders import FolderIndex
    from installer.pack_source import PackSource


class LocalSources:
    """Where this run reads instead of the network: a file list, a pack, the
    folders it copies BIOS files from."""

    def __init__(self) -> None:
        self.manifest: Path | None = None
        self.pack: PackSource | None = None
        # The folders named with --from, read once for every platform.
        self.folders: list[FolderIndex] = []
        # The reads at once of the files in place (--jobs).
        self.jobs: int = DEFAULT_JOBS
        # Every folder index of the run still in use, closed at its end.
        self.indexes: weakref.WeakSet[FolderIndex] = weakref.WeakSet()
        self._serves: tuple = (None, None, frozenset())

    def serves(self) -> frozenset:
        """The platforms the file list or pack given to this run is for,
        empty when none is given. The setup list offers those alone: after
        o, Batocera was listed for a RetroArch list, and refused once its
        folder was asked."""
        if self._serves[:2] != (self.manifest, self.pack):
            named = (local_manifest_platform(self.manifest) if self.manifest is not None
                     else None)
            found = ({named} if named else set()) if self.manifest is not None \
                else set(self.pack.platforms()) if self.pack is not None else set()
            self._serves = (self.manifest, self.pack, frozenset(found))
        return self._serves[2]

    @property
    def offline(self) -> bool:
        """No network request in this run: a pack is read, or --offline."""
        return self.pack is not None or offline_requested()

    def reset(self) -> None:
        if self.pack is not None:
            self.pack.close()
        self.close_indexes()
        self.manifest = None
        self.pack = None
        self.folders = []
        self.jobs = DEFAULT_JOBS

    def close_indexes(self) -> None:
        for index in list(self.indexes):
            index.close()
        self.indexes = weakref.WeakSet()


LOCAL = LocalSources()


class _Offline(OSError):
    """A network request in a run told to make none."""


OFFLINE_WORDS = "this run makes no network request"
# The value --offline gives the variable: the words then name the option,
# and the variable itself where it was set.
OFFLINE_FLAG_VALUE = "--offline"


def offline_named() -> str:
    """What made this run offline, as the words name it."""
    value = os.environ.get(OFFLINE_VARIABLE, "")
    return (f"{OFFLINE_VARIABLE}={value}" if value not in ("", "0", OFFLINE_FLAG_VALUE)
            else "--offline")


def offline_undo() -> str:
    """How a run gets the network back: without the option, or with the
    variable unset. "without --offline" told a user who never typed it to
    remove it."""
    return ("without --offline" if offline_named() == "--offline"
            else f"with {OFFLINE_VARIABLE} unset")


def offline_words() -> str:
    """This run makes no network request, and what said so."""
    return f"{OFFLINE_WORDS} ({offline_named()})"


def _network_allowed(what: str) -> None:
    if LOCAL.pack is not None:
        raise _Offline(f"{what}: this run reads a pack and makes no network request")
    if offline_requested():
        raise _Offline(f"{what}: {offline_words()}")


def local_manifest_platform(path: Path) -> str | None:
    """The platform a saved file list names, None when it names none."""
    try:
        data = read_local_json(path, MAX_MANIFEST_BYTES)
    except (OSError, ValueError):
        return None
    plat = data.get("platform") if isinstance(data, dict) else None
    return plat if plat in AVAILABLE_PLATFORMS else None


def _offline_only() -> bool:
    """--offline without a pack: what is not on this machine cannot come."""
    return offline_requested() and LOCAL.pack is None
