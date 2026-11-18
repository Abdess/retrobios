"""Members of a ZIP read as streams, one opener per member."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable
from pathlib import Path

from core.hashing import stream_hashes
from core.torrentzip import Source as Readable


class _Member(io.RawIOBase):
    """One member of a ZIP, open for reading, closing the archive with it."""

    def __init__(self, archive: Path, name: str) -> None:
        super().__init__()
        self._zip = zipfile.ZipFile(archive)
        self._stream = self._zip.open(name)

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        if not self.closed:
            self._stream.close()
            self._zip.close()
        super().close()


def _opener(source: Path, member: str | None) -> Callable[[], Readable]:
    if member is None:
        return lambda: source.open("rb")
    return lambda: _Member(source, member)


def _member_sha1(path: Path, name: str) -> str:
    with _Member(path, name) as stream:
        return stream_hashes(stream, frozenset({"sha1"}))["sha1"]
