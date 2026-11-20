"""Streaming reader for MAME -listxml documents and Logiqx DATs.

The 0.289 listxml is 311 MB, so a document is read through a sliding window
and never held whole. romset_dat_importer, mame_devices and
arcade_parent_importer read elements, attributes and ROM members here.
"""

from __future__ import annotations

import html
import re
import zipfile
from collections.abc import Callable, Collection, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import IO, NamedTuple

LISTXML_CHUNK = 8 * 1024 * 1024
# Longer than any start tag the documents write, shorter than any element.
_TAG_TAIL = 4096

_ATTR = re.compile(rb'([\w:-]+)="([^"]*)"')
_ROM = re.compile(rb"<rom\b([^>]*)>")

Opener = Callable[[], AbstractContextManager[IO[bytes]]]


class Element(NamedTuple):
    tag: str
    attrs: dict[str, str]
    body: bytes


def attrs(raw: bytes) -> dict[str, str]:
    """Attributes of a start tag, entities decoded (``f&amp;m.basic.bin``)."""
    return {
        key.decode(): html.unescape(value.decode())
        for key, value in _ATTR.findall(raw)
    }


def iter_elements(
    stream: IO[bytes], tags: Collection[str] = ("machine",), head: bytes = b"",
) -> Iterator[Element]:
    """Every element named in *tags*, in document order.

    Attributes come in any order (mame2003 writes ``<game runnable="no"
    name="neogeo">``). The window keeps the element still open from its start
    tag and grows until that element closes, whatever its size. *head* is
    what the caller already read from *stream*.
    """
    element = re.compile(rb"<(" + b"|".join(t.encode() for t in tags) + rb")\b([^>]*)>")
    buffer = head
    while True:
        chunk = stream.read(LISTXML_CHUNK)
        buffer += chunk
        position = 0
        # Where the next read has to resume: the start of an element still
        # open, else a tail long enough to hold a start tag cut in two.
        keep_from = max(0, len(buffer) - _TAG_TAIL)
        while match := element.search(buffer, position):
            closing = b"</" + match.group(1) + b">"
            end = buffer.find(closing, match.end())
            if end == -1:
                keep_from = match.start()
                break
            yield Element(
                match.group(1).decode(), attrs(match.group(2)), buffer[match.end() : end]
            )
            position = end + len(closing)
            keep_from = max(position, len(buffer) - _TAG_TAIL)
        if not chunk:
            return
        buffer = buffer[keep_from:]


def rom_members(
    body: bytes, dedupe: bool = False, extra: Collection[str] = (),
) -> list[dict]:
    """Dumped ROMs of one element: name, size, crc32, sha1.

    A ROM without a crc is undumped and left out. *dedupe* keeps the first
    ROM of each name, as the loader does. *extra* names attributes copied
    when the ROM writes them.
    """
    members: list[dict] = []
    seen: set[str] = set()
    for match in _ROM.finditer(body):
        found = attrs(match.group(1))
        name, crc = found.get("name", ""), found.get("crc", "").lower()
        if not name or not crc or (dedupe and name in seen):
            continue
        seen.add(name)
        try:
            size = int(found.get("size", "0") or 0)
        except ValueError:
            size = 0
        member = {"name": name, "size": size, "crc32": crc, "sha1": found.get("sha1", "").lower()}
        member.update((key, found[key]) for key in extra if key in found)
        members.append(member)
    return members


def xml_members(archive: zipfile.ZipFile) -> list[str]:
    return [n for n in archive.namelist() if n.lower().endswith(".xml")]


@contextmanager
def open_listxml(path: Path) -> Iterator[IO[bytes]]:
    """Byte stream over a -listxml document, plain or as MAME's release zip."""
    if path.suffix.lower() != ".zip":
        with path.open("rb") as stream:
            yield stream
        return
    with zipfile.ZipFile(path) as archive:
        names = xml_members(archive)
        if len(names) != 1:
            raise ValueError(f"{path}: expected one .xml member, found {len(names)}")
        with archive.open(names[0]) as stream:
            yield stream
