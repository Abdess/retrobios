"""ROM bytes the collection holds, addressed by crc32, and the TorrentZip builds of recipes over them."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

from core.paths import REPO_ROOT
from core.torrentzip import build_torrentzip
from core.ziptools import is_archive_path, zip_members
from romrecipes.collection import collection_root, on_disk
from romrecipes.romsets import Recipe


class AtomPool:
    """ROM bytes in the collection, addressed by CRC32.

    Members are located once and read on demand: arcade sample sets reach
    hundreds of megabytes and a whole-pool preload buys nothing.
    """

    def __init__(
        self, bios_dir: Path, digest_cache: Path | None = None, db: dict | None = None
    ) -> None:
        # crc32 -> (archive, member), or (file, None) for a loose ROM.
        self._index: dict[str, tuple[Path, str | None]] = {}
        # Where every database path is read, by identification as by the pool.
        self.root = collection_root(bios_dir)
        # (md5, size) of each build, kept across runs: TorrentZip bytes are a
        # function of the members alone, so a recipe hashed once is known
        # until the writer changes. Rebuilding the 1 221 archives took 70 s
        # of every pipeline run, 63 s of it in zlib.
        self._digest_cache = digest_cache
        self._digests: dict[str, list] = _read_digests(digest_cache)
        self._digests_changed = False
        # A recipe is built once: identification and reconstruction ask for the
        # same archives, and every build re-reads and re-deflates its ROMs.
        self._built: dict[tuple[tuple[str, str], ...], bytes | None] = {}
        self.unreadable: list[str] = []
        # .variants/ copies (x.zip.1a2b3c4d) hold members no primary holds,
        # bbcm.zip.4cc3e25a's fa2b881f among them. Primaries answer first.
        archives = (p for p in bios_dir.rglob("*") if is_archive_path(p.name) and p.is_file())
        for archive in sorted(archives, key=lambda p: (".variants" in p.parts, p)):
            try:
                for member in zip_members(archive):
                    self._index.setdefault(member.crc32, (archive, member.name))
            except (OSError, zipfile.BadZipFile) as exc:
                self.unreadable.append(f"{archive}: {exc}")
        # Loose ROMs, by the crc32 the database already computed: nmk004.zip
        # needs nmk004.bin, which the collection holds only as a file.
        tree = bios_dir.resolve()
        for entry in ((db or {}).get("files") or {}).values():
            crc, path = str(entry.get("crc32") or "").lower(), entry.get("path", "")
            if not crc or not path or is_archive_path(path):
                continue
            loose = on_disk(self.root, path)
            if tree in loose.resolve().parents and loose.is_file():
                self._index.setdefault(crc, (loose, None))

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, crc32: str) -> bool:
        return crc32.lower() in self._index

    def read(self, crc32: str) -> bytes:
        archive, member = self._index[crc32.lower()]
        if member is None:
            return archive.read_bytes()
        with zipfile.ZipFile(archive) as handle:
            return handle.read(member)

    def digest(self, recipe: Recipe) -> tuple[str, int] | None:
        """(md5, size) of the recipe's TorrentZip build, None if incomplete."""
        if not all(crc in self for _name, crc in recipe):
            return None
        key = _recipe_key(recipe)
        known = self._digests.get(key)
        if known is None:
            blob = self.build(recipe)
            if blob is None:
                return None
            known = self._digests[key] = [hashlib.md5(blob).hexdigest(), len(blob)]
            self._digests_changed = True
        return known[0], known[1]

    def save_digests(self) -> None:
        """Write the digest cache back, when this run learned anything."""
        if self._digest_cache is None or not self._digests_changed:
            return
        from core.artifacts import write_text_atomic

        self._digest_cache.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomic(
            str(self._digest_cache), json.dumps(self._digests, sort_keys=True) + "\n"
        )

    def build(self, recipe: Recipe) -> bytes | None:
        """Return the TorrentZip bytes for *recipe*, or None if incomplete."""
        key = tuple(recipe)
        if key not in self._built:
            if all(crc in self for _name, crc in recipe):
                self._built[key] = build_torrentzip(
                    [(name, self.read(crc)) for name, crc in recipe]
                )
            else:
                self._built[key] = None
        return self._built[key]


DIGEST_CACHE = REPO_ROOT / ".cache" / "romset_digests.json"
# The writer's own source is part of every key: a change to how TorrentZip
# bytes are laid out invalidates every digest it produced.
_WRITER = hashlib.sha256(
    (REPO_ROOT / "scripts" / "core" / "torrentzip.py").read_bytes()
).hexdigest()[:16]


def _recipe_key(recipe: Recipe) -> str:
    members = json.dumps([[name, crc.lower()] for name, crc in recipe])
    return hashlib.sha256(f"{_WRITER}:{members}".encode()).hexdigest()


def _read_digests(path: Path | None) -> dict[str, list]:
    if path is None:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        print(f"  digest cache {path} unreadable, rebuilding: {exc}", file=sys.stderr)
        return {}
    return data if isinstance(data, dict) else {}
