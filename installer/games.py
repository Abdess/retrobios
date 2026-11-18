"""Games on the card: their folders, their regions and the BIOS they need."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import shlex
import sys
import time
import urllib.error
import zipfile
import zlib
from collections.abc import Callable, Collection, Iterable
from pathlib import Path
from typing import NamedTuple

from installer.app import card_app
from installer.cards import card_root_above
from installer.constants import BASE_URL, WORLD_REGION, _SHA256_RE
from installer.cores import entry_systems
from installer.detect_os import detect_os, detected_os
from installer.embedded import games_part, shown_path
from installer.events import EVENTS
from installer.line_ui import fold_line, region_title
from installer.narrowing import _region_comparable
from installer.network import _fetch_json, _read_capped
from installer.offline import LOCAL, _Offline, offline_words
from installer.probe import _is_dir
from installer.record import system_title
from installer.terminal import EVENT_PROGRESS_INTERVAL, Terminal, detail
from installer.text import _plural, agree

# --- Games on the card -------------------------------------------------------
#
# --for-games keeps what the games of a card need, read from install/games/
# (scripts/generate_games_index.py): per system the files its default core
# reads (a fallback set), one region where the game's own bytes prove it,
# and for an arcade set the BIOS sets its romof chain reaches. Any doubt
# keeps the wider set: the game must run.

GAMES_URL = f"{BASE_URL}/install/games/{{path}}"
GAMES_FORMAT = 1
MAX_GAMES_INDEX_BYTES = 4 * 1024 * 1024
MAX_GAMES_DOC_BYTES = 32 * 1024 * 1024
CACHE_VARIABLE = "RETROBIOS_CACHE"
# A card is read up to this many files, and this deep below each rom folder
# (EmuDeck keeps some games in roms/<system>/roms).
MAX_GAME_FILES = 200_000
GAME_FOLDER_DEPTH = 3
# A cartridge dump is hashed whole, never a file larger than this: a disc
# image is read at its header only.
MAX_HASHED_GAME = 256 * 1024 * 1024
GAMES_SCAN_FILE = "games-scan-1.json"
MAX_GAMES_SCAN_BYTES = 64 * 1024 * 1024
_GAMES_DOC_NAME = re.compile(r"^(setups|fallback|systems|arcade)/[A-Za-z0-9_.+-]+\.json$")
# Where a setup lists no extension (MinUI and its forks list every file),
# what is never a game.
_NOT_GAME_SUFFIXES = frozenset({
    ".txt", ".xml", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".mp4", ".pdf",
    ".nfo", ".db", ".srm", ".sav", ".state", ".cfg", ".ini", ".html", ".url",
    ".lnk", ".disabled",
})
ARCADE_SUFFIXES = (".zip", ".7z")
# Files whose bytes are not the game's at an offset: an archive, a CHD.
_PACKED_SUFFIXES = frozenset({".zip", ".7z", ".rar", ".gz", ".chd", ".cso", ".rvz", ".wia",
                              ".gcz", ".wbfs", ".pbp"})
# Why a game got every BIOS of its system: said with its name.
GAMES_REASONS = {
    "not_recognised": "not recognised",
    "not_read": "format not read",
    "region_unknown": "region not proven",
    "unknown_set": "set unknown to the core",
    "no_parent": "BIOS set not in the list",
}


class GamesUnavailable(Exception):
    """install/games/ could not be read: the run keeps the wider set."""

    def __init__(self, reason: str, words: str) -> None:
        super().__init__(words)
        self.reason = reason
        self.words = words


def cache_folder() -> Path | None:
    """Where this machine keeps what a later run reuses: RETROBIOS_CACHE,
    else the system's cache folder. None where none is known."""
    named = os.environ.get(CACHE_VARIABLE, "")
    if named:
        return Path(named)
    try:
        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA")
            return Path(base) / "retrobios" if base else None
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Caches" / "retrobios"
        xdg = os.environ.get("XDG_CACHE_HOME")
        return (Path(xdg) if xdg else Path.home() / ".cache") / "retrobios"
    except RuntimeError:
        # No home folder to name.
        return None


def _cache_write(path: Path, data: bytes) -> None:
    """Kept for the next run, or not at all: a cache that cannot be written
    costs a second read, never the run."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        scratch = path.with_name(f"{path.name}.{os.getpid()}.part")
        scratch.write_bytes(data)
        os.replace(scratch, path)
    except OSError as exc:
        if os.environ.get("RETROBIOS_DEBUG"):
            print(f"  Not cached: {path} ({exc.strerror or exc})", file=sys.stderr)


class GamesData:
    """install/games/ for this run: index.json, then each document it lists,
    checked against the sha256 the index gives. Read from the games folder
    beside --manifest, the cache, or the network, in that order."""

    def __init__(self) -> None:
        self.index: dict | None = None
        self.docs: dict[str, dict] = {}

    def reset(self) -> None:
        self.index = None
        self.docs = {}

    @staticmethod
    def beside() -> Path | None:
        return LOCAL.manifest.parent / "games" if LOCAL.manifest is not None else None

    @staticmethod
    def cached(name: str) -> Path | None:
        root = cache_folder()
        return root / "games" / name if root is not None else None

    def load_index(self, network: bool = True, attempts: int = 2) -> dict:
        if self.index is not None:
            return self.index
        raw = None
        beside = self.beside()
        if beside is not None:
            raw = _read_capped(beside / "index.json", MAX_GAMES_INDEX_BYTES)
        cached = self.cached("index.json")
        reason = "offline"
        failure = ""
        if raw is None and network:
            try:
                raw = _fetch_json(GAMES_URL.format(path="index.json"), MAX_GAMES_INDEX_BYTES,
                                  "games index", attempts=attempts, raw=True)
            except _Offline:
                reason = "offline"
            except (urllib.error.URLError, OSError, ValueError,
                    http.client.HTTPException) as exc:
                reason = "network"
                failure = str(exc)
            else:
                if cached is not None:
                    _cache_write(cached, raw)
        if raw is None and cached is not None:
            raw = _read_capped(cached, MAX_GAMES_INDEX_BYTES)
        if raw is None:
            raise GamesUnavailable(reason, (
                f"the games index is not on this machine and {offline_words()}"
                if reason == "offline"
                else f"the games index could not be downloaded ({failure})"))
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GamesUnavailable("invalid", f"the games index is not valid ({exc})") from exc
        if (not isinstance(data, dict) or data.get("format_version") != GAMES_FORMAT
                or not all(isinstance(data.get(kind), dict)
                           for kind in ("setups", "fallback", "systems", "arcade"))):
            raise GamesUnavailable("invalid", "the games index is of another format")
        self.index = data
        return data

    @staticmethod
    def _doc_held(beside: Path | None, cached: Path | None, name: str, digest: str,
                  limit: int) -> bytes | None:
        """A listed document beside --manifest or in the cache, of its sha256."""
        for source in (beside / name if beside is not None else None, cached):
            if source is None:
                continue
            found = _read_capped(source, limit)
            if found is not None and hashlib.sha256(found).hexdigest() == digest:
                return found
        return None

    @staticmethod
    def _doc_fetched(kind: str, name: str, digest: str, limit: int, attempts: int,
                     cached: Path | None) -> bytes | None:
        """A listed document downloaded and cached, None when offline."""
        try:
            fetched = _fetch_json(GAMES_URL.format(path=name), limit, f"games {kind}",
                                  attempts=attempts, raw=True)
        except _Offline:
            return None
        except (urllib.error.URLError, OSError, ValueError,
                http.client.HTTPException) as exc:
            raise GamesUnavailable(
                "network", f"install/games/{name} could not be downloaded ({exc})") from exc
        if hashlib.sha256(fetched).hexdigest() != digest:
            raise GamesUnavailable("invalid", f"install/games/{name} is not the one "
                                   "the games index lists")
        if cached is not None:
            _cache_write(cached, fetched)
        return fetched

    def doc(self, kind: str, key: str, network: bool = True,
            attempts: int = 2) -> dict | None:
        """One listed document, None when the index lists none of that name."""
        entry = self.load_index(network, attempts).get(kind, {}).get(key)
        if not isinstance(entry, dict):
            return None
        name = str(entry.get("file", ""))
        digest = str(entry.get("sha256", ""))
        if not _GAMES_DOC_NAME.match(name) or not _SHA256_RE.match(digest):
            raise GamesUnavailable("invalid", f"the games index names {name!r}")
        if name in self.docs:
            return self.docs[name]
        limit = min(int(entry.get("size") or 0), MAX_GAMES_DOC_BYTES)
        beside = self.beside()
        cached = self.cached(f"{digest}.json")
        raw = self._doc_held(beside, cached, name, digest, limit)
        if raw is None and network:
            raw = self._doc_fetched(kind, name, digest, limit, attempts, cached)
        if raw is None:
            raise GamesUnavailable("offline", f"install/games/{name} is not on this machine "
                                   f"and {offline_words()}")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GamesUnavailable("invalid", f"install/games/{name} is not valid") from exc
        if not isinstance(data, dict):
            raise GamesUnavailable("invalid", f"install/games/{name} is not valid")
        self.docs[name] = data
        return data


GAMES = GamesData()


# --- Where the games are -----------------------------------------------------


def _setup_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def games_setups(index: dict, plat: str, bios_path: Path, os_type: str = "") -> list[str]:
    """The setups whose rom folders this BIOS folder's games may sit in,
    best first: the system detection named (muOS, ArkOS), else the
    platform's own."""
    setups = index.get("setups") or {}
    named = detected_os(plat, bios_path)
    if not named:
        above = card_root_above(bios_path)
        named = above[0] if above else ""
    if not named:
        # --platform names the list, not the card: the full screen passes
        # --platform=retroarch for a muOS card, detection never runs in that
        # run, and the card's ROMS/ was never read. The card's own files
        # name its system, as card_app reads them for the app.
        card = card_app(bios_path)
        named = card.system if card else ""
    if not named:
        # --dest on a handheld's games part from a computer (ArkOS's
        # EASYROMS/bios): detection never ran there, and the card's own rom
        # folders sit beside the BIOS folder.
        part = games_part(bios_path.parent)
        named = part.name if part else ""
    key = _setup_key(named) if named else ""
    found = [name for name in sorted(setups) if key and (name == key or name.startswith(key + "-"))]
    if not found and plat in setups:
        found = [plat]
        windows = f"{plat}-windows"
        if (os_type or detect_os()) == "windows" and windows in setups:
            found.insert(0, windows)
    return found


def _list_dir(path: Path) -> list[os.DirEntry]:
    try:
        with os.scandir(path) as listing:
            return list(listing)
    except OSError:
        return []


def _entry_is_dir(entry: os.DirEntry) -> bool:
    try:
        return entry.is_dir()
    except OSError:
        return False


def _root_tail(setup: dict) -> str:
    """The last name of the setup's rom folder path: Roms, roms, ROMS, games."""
    text = str((setup.get("roms_root") or {}).get("path") or "")
    return re.split(r"[\\/]", text.rstrip("\\/"))[-1] if text else ""


def games_root(setup: dict, bios_path: Path) -> Path | None:
    """The setup's rom folder for this BIOS folder: where the setup puts it
    from the BIOS folder, else a folder of its name at most three levels up
    (a card mounted on a computer keeps its own layout)."""
    relative = (setup.get("roms_root") or {}).get("from_bios")
    if isinstance(relative, str) and relative:
        candidate = Path(os.path.normpath(str(bios_path / relative)))
        if _is_dir(candidate):
            return candidate
    tail = _root_tail(setup).casefold()
    if not tail or tail.startswith("<") or tail == "none":
        return None
    for holder in [bios_path, *list(bios_path.absolute().parents)[:3]]:
        for entry in _list_dir(holder):
            if entry.name.casefold() == tail and _entry_is_dir(entry):
                return Path(entry.path)
    return None


def _may_hold_games(bios_path: Path) -> bool:
    """Whether a rom folder could sit near this BIOS folder, said without the
    network: a folder named roms in it or up to two levels above it, a path
    that runs through one (roms, games), or a handheld's games part, whose
    console folders sit beside bios (ArkOS's EASYROMS plugged into a
    computer was never offered its games)."""
    holders = [bios_path, *list(bios_path.absolute().parents)[:2]]
    if any(part.casefold() in ("roms", "games") for part in bios_path.absolute().parts[-3:]):
        return True
    if games_part(bios_path.parent) is not None:
        return True
    return any(entry.name.casefold() == "roms" and _entry_is_dir(entry)
               for holder in holders for entry in _list_dir(holder))


class GameFolder(NamedTuple):
    """A folder of games and the row that says what reads it."""

    path: Path
    row: dict


def game_folders(setup: dict | None, index: dict, root: Path,
                 named: bool) -> list[GameFolder]:
    """Each folder below root that a setup row reads. named is a folder the
    user gave: one the setup does not list is then read by the name every
    setup gives it, and the folder itself when it is one system's."""
    rows = list((setup or {}).get("folders") or [])
    exact = (setup or {}).get("case_sensitive") is True
    skipped = {str(item.get("name", "")).casefold()
               for key in ("skip", "media") for item in (setup or {}).get(key) or []
               if isinstance(item, dict) and item.get("name")}
    by_name: dict[str, list[dict]] = {}
    for row in rows:
        if not (row.get("systems") or row.get("profile")):
            # A folder of the OS that no system and no core reads: apps, media.
            continue
        for name in [row.get("folder"), *(row.get("aliases") or [])]:
            if isinstance(name, str) and name:
                by_name.setdefault(name if exact else name.casefold(), []).append(row)
    names = index.get("folders") or {}

    def rows_for(name: str) -> list[dict]:
        matched = by_name.get(name if exact else name.casefold())
        if matched:
            return matched
        systems = names.get(name.casefold()) if named or not rows else None
        return [{"folder": name, "systems": list(systems)}] if systems else []

    found = []
    for entry in sorted(_list_dir(root), key=lambda item: item.name):
        if entry.name.startswith(".") or entry.name.casefold() in skipped:
            continue
        if not _entry_is_dir(entry):
            continue
        found += [GameFolder(Path(entry.path), row) for row in rows_for(entry.name)]
    if named and not found:
        found = [GameFolder(root, row) for row in rows_for(root.name)]
    return found


# --- The games in a folder ---------------------------------------------------


def _suffix(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _listed_names(path: Path) -> list[str]:
    """The files a .cue, .m3u or .gdi names, as written."""
    data = _read_capped(path, 1024 * 1024)
    if data is None:
        return []
    text = data.decode("utf-8", errors="replace")
    kind = _suffix(path.name)
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind == ".cue":
            match = re.match(r'(?i)^FILE\s+(?:"([^"]+)"|(\S+))', line)
            if match:
                names.append(match.group(1) or match.group(2))
        elif kind == ".gdi":
            parts = shlex.split(line, posix=True) if '"' in line else line.split()
            if len(parts) >= 5:
                names.append(parts[4])
        else:
            names.append(line)
    return names


def folder_games(folder: GameFolder, setup: dict | None,
                 budget: int) -> tuple[list[Path], int]:
    """The games of one folder, and how many other files it holds. A file
    a .cue, .m3u or .gdi names is part of that game, not a game."""
    row = folder.row
    extensions = {str(ext).lower() for ext in row.get("extensions") or []}
    whole_names = {str(name).casefold() for name in row.get("files") or []}
    if not extensions and not whole_names and row.get("arcade"):
        extensions = set(ARCADE_SUFFIXES)
    skipped = {str(item.get("name", "")).casefold()
               for key in ("skip", "media") for item in (setup or {}).get(key) or []
               if isinstance(item, dict) and item.get("name")}
    games: list[Path] = []
    others = 0
    pending = [(folder.path, 0)]
    while pending and len(games) < budget:
        where, depth = pending.pop()
        for entry in sorted(_list_dir(where), key=lambda item: item.name):
            name = entry.name
            lowered = name.casefold()
            if name.startswith(".") or lowered == "map.txt" or lowered.endswith(".disabled"):
                continue
            if _entry_is_dir(entry):
                if depth + 1 < GAME_FOLDER_DEPTH and lowered not in skipped:
                    pending.append((Path(entry.path), depth + 1))
                continue
            if extensions or whole_names:
                is_game = lowered in whole_names or any(lowered.endswith(ext)
                                                        for ext in extensions)
            else:
                is_game = _suffix(name) not in _NOT_GAME_SUFFIXES
            if is_game:
                games.append(Path(entry.path))
            else:
                others += 1
    named: set[str] = set()
    for game in games:
        if _suffix(game.name) in (".cue", ".m3u", ".gdi"):
            for listed in _listed_names(game):
                target = Path(os.path.normpath(str(game.parent / listed)))
                if target != game:
                    named.add(os.path.normcase(str(target)))
    kept = [game for game in games if os.path.normcase(str(game)) not in named]
    return kept, others


# --- Reading a game ----------------------------------------------------------


class _ScanCache:
    """What hashing a game found, kept between runs by path, size and time:
    a second run over the same card reads nothing that has not changed."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.entries: dict[str, list] = {}
        self.seen: dict[str, list] = {}
        self.changed = False
        data = _read_capped(path, MAX_GAMES_SCAN_BYTES) if path is not None else None
        if data is not None:
            try:
                loaded = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                loaded = {}
            if isinstance(loaded, dict):
                self.entries = {k: v for k, v in loaded.items()
                                if isinstance(v, list) and len(v) == 4}

    @staticmethod
    def stamp(path: Path) -> tuple[int, int] | None:
        try:
            info = path.stat()
        except OSError:
            return None
        return info.st_size, info.st_mtime_ns

    def get(self, path: Path, stamp: tuple[int, int]) -> list | None:
        key = str(path)
        found = self.entries.get(key)
        if found is not None and found[0] == stamp[0] and found[1] == stamp[1]:
            self.seen[key] = found
            return found
        return None

    def put(self, path: Path, stamp: tuple[int, int], crc: str | None,
            members: list | None) -> None:
        value = [stamp[0], stamp[1], crc, members]
        self.seen[str(path)] = value
        self.changed = True

    def save(self) -> None:
        if self.path is None or not self.changed:
            return
        # The entries of other cards stay: one cache serves every card.
        merged = {**self.entries, **self.seen}
        _cache_write(self.path, json.dumps(merged, separators=(",", ":")).encode("utf-8"))


def _crc32_file(path: Path) -> str | None:
    crc = 0
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                crc = zlib.crc32(block, crc)
    except OSError:
        return None
    return f"{crc & 0xFFFFFFFF:08x}"


def _zip_members(path: Path) -> list | None:
    """Each member's crc32 and size, from the central directory alone."""
    try:
        with zipfile.ZipFile(path) as archive:
            return [[f"{info.CRC:08x}", info.file_size] for info in archive.infolist()
                    if not info.is_dir()]
    except (OSError, zipfile.BadZipFile, ValueError):
        return None


class DiscImage:
    """The bytes a header reader names in a disc image: a sector of a CD
    image (2048-byte, or 2352-byte raw with its mode), or an offset of a
    GameCube disc. None where the format is one this file does not read
    (CHD, RVZ, PBP and the other compressed forms)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data_path: Path | None = None
        self.sector_size = 2048
        self.user_offset = 0
        self.disc_offset = 0
        suffix = _suffix(path.name)
        if suffix == ".m3u":
            listed = _listed_names(path)
            if listed:
                first = Path(os.path.normpath(str(path.parent / listed[0])))
                inner = DiscImage(first) if _suffix(first.name) != ".m3u" else None
                if inner is not None:
                    self.__dict__.update(inner.__dict__)
            return
        if suffix == ".cue":
            self._cue(path)
        elif suffix in (".iso", ".gcm"):
            self.data_path = path
        elif suffix == ".ciso":
            self.data_path, self.disc_offset = path, 0x8000
        elif suffix in (".bin", ".img"):
            self.data_path = path
            self._raw_mode()

    def _cue(self, path: Path) -> None:
        data = _read_capped(path, 1024 * 1024)
        text = (data or b"").decode("utf-8", errors="replace")
        current = None
        for line in text.splitlines():
            words = line.strip()
            match = re.match(r'(?i)^FILE\s+(?:"([^"]+)"|(\S+))', words)
            if match:
                current = Path(os.path.normpath(str(path.parent / (match.group(1)
                                                                    or match.group(2)))))
                continue
            track = re.match(r"(?i)^TRACK\s+\d+\s+(\S+)", words)
            if track and current is not None:
                mode = track.group(1).upper()
                if mode == "AUDIO":
                    continue
                self.data_path = current
                if mode.endswith("/2352"):
                    self.sector_size = 2352
                    self.user_offset = 16 if mode.startswith("MODE1") else 24
                return

    def _raw_mode(self) -> None:
        head = self.read_raw(0, 16)
        if head is not None and head[:12] == b"\x00" + b"\xff" * 10 + b"\x00":
            self.sector_size = 2352
            self.user_offset = 16 if head[15] == 1 else 24

    def read_raw(self, offset: int, length: int) -> bytes | None:
        if self.data_path is None or offset < 0:
            return None
        try:
            with open(self.data_path, "rb") as handle:
                handle.seek(offset)
                data = handle.read(length)
        except OSError:
            return None
        return data if len(data) == length else None

    def read_sector(self, sector: int, offset: int, length: int) -> bytes | None:
        """User data of one sector of a CD image, from offset."""
        if offset + length > 2048:
            return None
        return self.read_raw(sector * self.sector_size + self.user_offset + offset, length)

    def read_disc(self, offset: int, length: int) -> bytes | None:
        """Bytes of a GameCube or Wii disc, in an ISO or the first block of a CISO."""
        return self.read_raw(self.disc_offset + offset, length)

    def iso_file(self, name: str, limit: int = 64 * 1024) -> bytes | None:
        """A file of the ISO 9660 root directory, found by name."""
        volume = self.read_sector(16, 0, 2048)
        if volume is None or volume[1:6] != b"CD001":
            return None
        record = volume[156:190]
        extent = int.from_bytes(record[2:6], "little")
        size = int.from_bytes(record[10:14], "little")
        wanted = name.upper().encode("ascii")
        for sector in range(extent, extent + min((size + 2047) // 2048, 16)):
            block = self.read_sector(sector, 0, 2048)
            if block is None:
                return None
            position = 0
            while position < 2048 and block[position]:
                length = block[position]
                found = block[position + 33:position + 33 + block[position + 32]]
                if found.split(b";")[0].upper() == wanted:
                    start = int.from_bytes(block[position + 2:position + 6], "little")
                    count = min(int.from_bytes(block[position + 10:position + 14], "little"),
                                limit)
                    parts = []
                    for index in range((count + 2047) // 2048):
                        part = self.read_sector(start + index, 0, 2048)
                        if part is None:
                            return None
                        parts.append(part)
                    return b"".join(parts)[:count]
                position += length
        return None


def _boot_name(image: DiscImage, location: dict) -> str | None:
    """The executable SYSTEM.CNF boots (BOOT, BOOT2), as the reader takes it."""
    data = image.iso_file(str(location.get("iso_file") or ""))
    if data is None:
        return None
    key = str(location.get("key") or "BOOT")
    for line in data.decode("ascii", errors="replace").splitlines():
        match = re.match(rf"^\s*{re.escape(key)}\s*=\s*(\S+)", line)
        if not match:
            continue
        value = match.group(1)
        required = location.get("requires")
        if required and not value.lower().startswith(str(required).lower()):
            return None
        value = re.split(r"[\\/:]", value)[-1]
        return value.split(";")[0]
    return None


_INT_FORMS = {"u8": (1, "big"), "u16le": (2, "little"), "u16be": (2, "big"),
              "u32le": (4, "little"), "u32be": (4, "big")}


def _located(image: DiscImage | None, game: Path, location: dict) -> bytes | str | None:
    """The bytes a reader's location names, or the text for an iso_file."""
    length = int(location.get("length") or 0)
    if "iso_file" in location:
        return _boot_name(image, location) if image is not None else None
    if location.get("container") == "gamecube-disc":
        return image.read_disc(int(location.get("disc_offset", 0)), length) \
            if image is not None else None
    if "sector" in location:
        return image.read_sector(int(location["sector"]), int(location.get("offset", 0)),
                                 length) if image is not None else None
    if location.get("copier_header") or location.get("relative_offsets") \
            or set(location) - {"offset", "length", "encoding", "candidates"}:
        # A copier header, a pointer, a partition: forms this file leaves to
        # the core, so the reading proves nothing.
        return None
    offsets = location.get("candidates") or [location.get("offset", 0)]
    reads = set()
    for offset in offsets:
        try:
            with open(game, "rb") as handle:
                handle.seek(int(offset))
                data = handle.read(length)
        except OSError:
            return None
        if len(data) != length:
            return None
        reads.add(data)
    # Several places that disagree say nothing the reader could rely on.
    return reads.pop() if len(reads) == 1 else None


def _magic_holds(image: DiscImage | None, magic: dict | None) -> bool:
    if not magic:
        return True
    if image is None:
        return False
    if "u32be" in magic:
        data = image.read_disc(int(magic.get("disc_offset", 0)), 4)
        return data is not None and int.from_bytes(data, "big") == int(magic["u32be"])
    wanted = str(magic.get("bytes", "")).encode("latin-1")
    data = image.read_sector(int(magic.get("sector", 0)), int(magic.get("offset", 0)),
                             len(wanted))
    return data == wanted


def _decoded(reader: dict, value: bytes | str) -> frozenset | str | None:
    """Regions a reader's value stands for, "unknown" for a value the code
    reads as none, the serial for a serial reader, None when undecided."""
    decode = reader.get("decode") or {}
    kind = decode.get("kind")
    encoding = (reader.get("location") or {}).get("encoding", "ascii")
    if isinstance(value, bytes):
        if encoding in _INT_FORMS:
            size, order = _INT_FORMS[encoding]
            number: object = int.from_bytes(value[:size],
                                            "little" if order == "little" else "big")
            text = ""
        else:
            number = None
            text = value.decode("latin-1")
    else:
        number, text = None, value
    if kind == "serial":
        serial = text.strip().rstrip("\x00").strip()
        return serial or None
    values = [item for item in decode.get("values") or [] if item.get("regions")]
    found: set[str] = set()
    if kind == "integer" and number is not None:
        found = {region for item in values if item.get("value") == number
                 for region in item["regions"]}
    elif kind == "letters":
        found = {region for item in values if str(item.get("value")) in text
                 for region in item["regions"]}
    elif kind == "exact-prefix":
        match = next((item for item in values if text.startswith(str(item.get("value")))), None)
        found = set(match["regions"]) if match else set()
    elif kind == "prefix-nocase":
        match = next((item for item in values
                      if text.lower().startswith(str(item.get("value")).lower())), None)
        found = set(match["regions"]) if match else set()
    elif kind == "char-at":
        guard = decode.get("guard")
        index = int(decode.get("index", 0))
        if (guard and not re.match(str(guard), text)) or len(text) <= index:
            return "unknown"
        match = next((item for item in values if text[index] == str(item.get("value"))), None)
        found = set(match["regions"]) if match else set()
    else:
        return None
    if found:
        return frozenset(found)
    otherwise = decode.get("otherwise")
    if isinstance(otherwise, list) and otherwise:
        return frozenset(str(region) for region in otherwise)
    return "unknown"


def _serial_key(serial: str) -> str:
    """A serial as the disc and the DAT both spell it once only letters and
    digits are kept: SLPS_022.51 and SLPS 02251 are one."""
    return re.sub(r"[^0-9A-Z]", "", serial.upper())


class GameFacts:
    """What one game file says: its identity and region from the catalogs,
    each header reader's reading, the BIOS sets of an arcade set."""

    def __init__(self, path: Path, shown: str, folder: GameFolder) -> None:
        self.path = path
        self.shown = shown
        self.folder = folder
        # The system whose catalog and readers read it.
        self.system = ""
        self.kind = "game"
        self.recognised = False
        self.title = ""
        self.dat_regions: frozenset | None = None
        self.readings: dict[str, object] = {}
        self.read = True
        self.parents: tuple[str, ...] = ()
        self.devices: tuple[str, ...] = ()
        self.reason = ""


class SystemData:
    """The parts of a systems/<system>.json document a scan reads, indexed."""

    def __init__(self, doc: dict | None) -> None:
        doc = doc or {}
        identify = doc.get("identify") or {}
        self.regions = [frozenset(str(r) for r in group)
                        for group in identify.get("regions") or []]
        sources = identify.get("sources") or []
        # Redump catalogs index a disc's first data track: hashing it would
        # read the whole disc, so a disc is known by its serial.
        self.discs = any(source.get("source") == "redump" for source in sources)
        self.games: dict[tuple[str, int], tuple[int, str]] = {}
        self.sizes: set[int] = set()
        if not self.discs:
            for row in identify.get("games") or []:
                if isinstance(row, list) and len(row) == 4:
                    self.games[(str(row[0]), int(row[1]))] = (int(row[2]), str(row[3]))
                    self.sizes.add(int(row[1]))
        self.serials: dict[str, frozenset] = {}
        for serial, indices in (identify.get("serials") or {}).items():
            key = _serial_key(serial)
            joined = frozenset(region for i in indices if 0 <= i < len(self.regions)
                               for region in self.regions[i])
            self.serials[key] = self.serials.get(key, frozenset()) | joined
        headers = doc.get("headers") or {}
        self.readers: dict[str, dict] = headers.get("readers") or {}
        self.cores: dict[str, dict] = headers.get("cores") or {}
        self.rules: dict[str, dict] = doc.get("region_rules") or {}
        self.extras: list[dict] = doc.get("extras") or []

    def region_of(self, index: int) -> frozenset | None:
        if 0 <= index < len(self.regions) and self.regions[index]:
            return self.regions[index]
        return None


def identity_readers(system: SystemData) -> set[str]:
    """The readers that give a serial, which the catalog turns into a game."""
    return {name for name, reader in system.readers.items()
            if isinstance(reader, dict)
            and ((reader.get("decode") or {}).get("kind") == "serial"
                 or "iso_file" in (reader.get("location") or {}))}


def _read_game_catalog(facts: GameFacts, suffix: str, stamp: tuple[int, int],
                       system: SystemData, cache: _ScanCache) -> None:
    """The catalog's game for the file's crc32 and size, or a ZIP's members."""
    path = facts.path
    if suffix in (".7z", ".rar", ".chd"):
        facts.read = False
        return
    cached = cache.get(path, stamp)
    crc = members = None
    if cached is not None:
        crc, members = cached[2], cached[3]
    elif suffix == ".zip":
        members = _zip_members(path)
        cache.put(path, stamp, crc, members)
    elif stamp[0] in system.sizes and stamp[0] <= MAX_HASHED_GAME:
        crc = _crc32_file(path)
        cache.put(path, stamp, crc, members)
    candidates = [(crc, stamp[0])] if crc else []
    candidates += [(str(m[0]), int(m[1])) for m in members or []
                   if isinstance(m, list) and len(m) == 2]
    for key in candidates:
        found = system.games.get(key)
        if found is not None:
            facts.recognised = True
            facts.dat_regions = system.region_of(found[0])
            facts.title = found[1]
            break


def _read_game_headers(facts: GameFacts, system: SystemData, wanted: set[str],
                       packed: bool) -> None:
    """The serial and the header readings of the readers wanted."""
    path = facts.path
    image = DiscImage(path) if system.discs else None
    if system.discs and (image is None or image.data_path is None):
        # A CHD, an RVZ, a PBP: read by the core, not by this file.
        facts.read = False
        image = None
    for name in sorted(wanted):
        reader = system.readers.get(name)
        if not isinstance(reader, dict):
            continue
        location = reader.get("location") or {}
        if image is None and (packed or "sector" in location or "iso_file" in location
                              or location.get("container")):
            # Bytes at an offset of a ZIP are not the game's.
            facts.readings[name] = None
            continue
        magic = reader.get("magic")
        if magic and not _magic_holds(image, magic):
            facts.readings[name] = None
            continue
        raw = _located(image, path, location)
        if raw is None:
            facts.readings[name] = None
            continue
        decoded = _decoded(reader, raw)
        is_serial = (reader.get("decode") or {}).get("kind") == "serial"
        facts.readings[name] = None if is_serial else decoded
        serial = raw if isinstance(raw, str) else decoded if is_serial else None
        found = system.serials.get(_serial_key(serial)) if isinstance(serial, str) else None
        if found is not None:
            facts.recognised = True
            facts.title = facts.title or str(serial)
            facts.dat_regions = found or facts.dat_regions


def read_game(facts: GameFacts, system_id: str, system: SystemData, readers: set[str],
              cache: _ScanCache) -> None:
    """Fill facts from the file: its crc32 and size (a cartridge, a ZIP's
    members), its serial and the header readings the cores use (a disc)."""
    path = facts.path
    facts.system = system_id
    suffix = _suffix(path.name)
    stamp = cache.stamp(path)
    if stamp is None:
        facts.read = False
        return
    packed = suffix in _PACKED_SUFFIXES
    if system.games:
        _read_game_catalog(facts, suffix, stamp, system, cache)
    wanted = readers | identity_readers(system)
    if not wanted:
        return
    _read_game_headers(facts, system, wanted, packed)


def core_regions(facts: GameFacts, system_id: str, system: SystemData,
                 profile: str) -> frozenset | None:
    """The regions a game is proven to need under one core: the catalog's
    tag of the content matched, the region the core's own readers compute
    from its bytes, or both when they agree. None for no proof or for two
    proofs that disagree."""
    if facts.system != system_id:
        return None
    core = system.cores.get(profile) or {}
    header: frozenset | None = None
    order = [name for name in core.get("order") or [] if isinstance(name, str)]
    all_read = bool(order)
    for name in order:
        value = facts.readings.get(name)
        if value is None:
            all_read = False
            continue
        if isinstance(value, frozenset):
            header = value
            break
    otherwise = core.get("otherwise")
    if header is None and all_read and isinstance(otherwise, list) and otherwise:
        header = frozenset(str(region) for region in otherwise)
    proofs = [proof for proof in (facts.dat_regions, header) if proof]
    if not proofs:
        return None
    if len(proofs) == 2 and not any(_region_comparable(a, b)
                                    for a in proofs[0] for b in proofs[1]):
        return None
    return frozenset().union(*proofs)


# Cases of games/regions.yml a proven region does not settle whatever the
# game: device state (an option, a per-game setting) or the code itself.
_ALWAYS_WIDE = ("always", "option", "user-state")


def region_rule_keeps_all(rule: dict | None, games: list[GameFacts]) -> bool:
    """Whether the core keeps every region whatever its games prove: no rule
    read at its pin, or one of the cases games/regions.yml names (a region
    option, an override BIOS, a fallback across regions, a disc database)."""
    if not isinstance(rule, dict):
        return True
    for case in rule.get("keep_all_regions") or []:
        if not isinstance(case, dict):
            return True
        name, condition = case.get("case"), case.get("condition")
        if condition in _ALWAYS_WIDE:
            return True
        if name == "first-disc-region":
            if any(_suffix(game.path.name) == ".m3u" for game in games):
                return True
        elif name not in ("multi-area-disc", "gamecube-unknown-region", "saturn-kr-ipl"):
            return True
    return False


def needed_regions(rule: dict, proofs: list[frozenset | None]) -> frozenset | None:
    """The regions the games of one core prove, routed as the core routes
    them, None when one game proves none."""
    if not proofs or any(proof is None for proof in proofs):
        return None
    routes = rule.get("routes") or {}
    needed = frozenset(str(routes.get(region, region))
                       for proof in proofs for region in proof or ())
    wide = {str(case.get("case")) for case in rule.get("keep_all_regions") or []
            if isinstance(case, dict)}
    if "saturn-kr-ipl" in wide and needed & {"asia-ntsc", "south-korea"}:
        return None
    return needed


def keep_regions(dests: list[str], entries: dict[str, dict], needed: frozenset,
                 region_free: set[str]) -> list[str]:
    """The files of a set the proven regions keep: every file with no region
    tag, a world or region-free file, and those whose tag a needed region
    matches. A needed region no file matches keeps the whole set."""

    def regions(dest: str) -> list[str]:
        entry = entries.get(dest) or {}
        if Path(dest).name.casefold() in region_free:
            return []
        tags = [str(r) for r in entry.get("regions") or []]
        return [] if WORLD_REGION in tags else tags

    tagged = {dest: regions(dest) for dest in dests if regions(dest)}
    for region in needed:
        if not any(_region_comparable(region, tag) for tags in tagged.values() for tag in tags):
            return list(dests)
    return [dest for dest in dests
            if dest not in tagged
            or any(_region_comparable(region, tag) for region in needed for tag in tagged[dest])]


class GamesPlan:
    """What the games of a card need, and what was read to say so."""

    def __init__(self, root: Path, card: bool) -> None:
        self.root = root
        self.card = card
        self.games: list[GameFacts] = []
        self.not_games = 0
        self.support = 0
        # Per system: folder names, game count, recognised, regions kept
        # (empty for every region), and the cores whose sets were read.
        self.systems: dict[str, dict] = {}
        self.keep: set[str] = set()
        self.required: set[str] = set()
        self.unknown_core: list[str] = []
        self.truncated = False
        # The cores the games run on (a folder's default and its boards'),
        # and the systems of a folder no setup names a core for.
        self.profiles: set[str] = set()
        self.any_core: set[str] = set()

    @property
    def fallback(self) -> list[GameFacts]:
        return [game for game in self.games if game.reason]

    def where(self) -> str:
        return "on this card" if self.card else "in this folder"

    def wanted(self, required_only: bool) -> set[str]:
        return self.required if required_only else self.keep

    def apply(self, files: list[dict], omitted: list[dict],
              required_only: bool) -> tuple[list[dict], list[dict]]:
        """The files and omissions of the list the games need."""
        wanted = self.wanted(required_only)
        folded = {dest.casefold() for dest in wanted}
        kept = [entry for entry in files if entry.get("dest") in wanted
                or (entry.get("case_variant") and str(entry.get("dest")).casefold() in folded)]
        systems = {system for entry in kept for system in entry_systems(entry)}
        kept_omitted = [entry for entry in omitted
                        if (entry.get("dest") in wanted
                            or bool(set(entry_systems(entry)) & systems))
                        and (entry.get("required") or not required_only)]
        return kept, kept_omitted

    def event_systems(self) -> list[dict]:
        return [{"system": system, "folder": ", ".join(info["folders"]),
                 "games": info["games"], "recognised": info["recognised"],
                 "regions": sorted(info["regions"] or ())}
                for system, info in sorted(self.systems.items())]

    def event_fallback(self) -> list[dict]:
        return [{"system": game_system(game), "folder": game.folder.path.name,
                 "name": game.shown, "reason": game.reason} for game in self.fallback]


def game_system(game: GameFacts) -> str:
    systems = game.folder.row.get("systems") or []
    return str(systems[0]) if systems else ""


def _folder_profiles(row: dict) -> list[str | None]:
    """The cores a folder's games may run on: its default, and each board's
    (a card moves between boards, and is often read on a computer)."""
    found: list[str | None] = [row.get("profile")]
    for spec in (row.get("board_defaults") or {}).values():
        if isinstance(spec, dict) and spec.get("profile") not in found:
            found.append(spec.get("profile"))
    return found


def _folder_set_keys(row: dict, fallback: dict) -> list[str]:
    """The fallback sets of a folder: its own and its boards', else, for a
    folder no setup names a core for, every set of its systems."""
    keys = list(row.get("fallback") or [])
    for spec in (row.get("board_defaults") or {}).values():
        if isinstance(spec, dict):
            keys += [key for key in spec.get("fallback") or [] if key not in keys]
    if keys or "fallback" in row:
        return keys
    systems = set(row.get("systems") or [])
    return sorted(key for key in fallback.get("sets") or {}
                  if key.split("|", 1)[0] in systems)


def _set_rows(fallback: dict, key: str) -> tuple[list[str], set[str]]:
    """A fallback set's destinations and those the declaring layer marks optional."""
    table = fallback.get("files") or []
    chosen = (fallback.get("sets") or {}).get(key) or {}

    def dest(index: object) -> str | None:
        if isinstance(index, int) and 0 <= index < len(table):
            return str(table[index][0])
        return None

    files = [d for d in (dest(i) for i in chosen.get("files") or []) if d]
    optional = {d for d in (dest(i) for i in chosen.get("optional") or []) if d}
    return files, optional


def _named_dests(names: Iterable[str], pool: Iterable[str]) -> list[str]:
    wanted = {name.casefold() for name in names}
    return [dest for dest in pool if Path(dest).name.casefold() in wanted]


def plan_games(plat: str, bios_path: Path, manifest: dict, folder: Path | None = None,
               term: Terminal | None = None, data: GamesData | None = None,
               os_type: str = "", network: bool = True) -> GamesPlan | None:
    """What the games of the card (or of folder) need, from install/games/.

    None when the card has no rom folder this setup reads and no folder was
    named. Raises GamesUnavailable when the index cannot be read, or does
    not describe this list (a destination it names is not in the list).
    """
    data = data or GAMES
    index = data.load_index(network)
    fallback = data.doc("fallback", plat, network)
    if fallback is None:
        raise GamesUnavailable("no_sets", f"install/games/ holds no BIOS sets for {plat}")
    setup, root = _games_setup_root(data, index, plat, bios_path, folder, os_type, network)
    if root is None:
        return None
    folders = game_folders(setup, index, root, folder is not None)
    plan = GamesPlan(root, folder is None)
    entries = {str(entry.get("dest")): entry for entry in manifest.get("files") or []}
    listed = set(entries)
    found = _found_games(plan, folders, setup)
    docs = _GamesDocs(data, network)
    cache_root = cache_folder()
    cache = _ScanCache(cache_root / GAMES_SCAN_FILE if cache_root is not None else None)
    progress = _GamesProgress(sum(len(games) for _folder, games in found), term)
    read = [(game_folder, _read_folder_games(plan, game_folder, games, docs, cache, progress))
            for game_folder, games in found]
    progress.end()
    cache.save()
    _plan_read_folders(plan, read, fallback, entries, docs)
    missing = sorted((plan.keep | plan.required) - listed)
    if missing:
        raise GamesUnavailable("stale", "the games index does not describe this file list "
                                        f"({missing[0]} is not in it)")
    return plan


def _games_setup_root(data: GamesData, index: dict, plat: str, bios_path: Path,
                      folder: Path | None, os_type: str,
                      network: bool) -> tuple[dict | None, Path | None]:
    """The rom folder setup the card follows, and the root of its games."""
    setup = None
    root = folder
    for key in games_setups(index, plat, bios_path, os_type):
        candidate = data.doc("setups", key, network)
        if candidate is None:
            continue
        setup = setup or candidate
        if folder is None:
            found_root = games_root(candidate, bios_path)
            if found_root is not None:
                setup, root = candidate, found_root
                break
    return setup, root


def _found_games(plan: GamesPlan, folders: list[GameFolder],
                 setup: dict | None) -> list[tuple[GameFolder, list[Path]]]:
    """The games of each folder, up to MAX_GAME_FILES in all."""
    budget = MAX_GAME_FILES
    found: list[tuple[GameFolder, list[Path]]] = []
    for game_folder in folders:
        games, others = folder_games(game_folder, setup, budget)
        budget -= len(games)
        plan.not_games += others
        found.append((game_folder, games))
        if budget <= 0:
            plan.truncated = True
            break
    return found


def _arcade_lookup(doc: dict) -> dict:
    """An arcade document as the lookups of _read_arcade read it."""
    parents: dict[str, list[str]] = {}
    for root_set, members in (doc.get("bios") or {}).items():
        for member in members:
            parents.setdefault(member, []).append(root_set)
    devices: dict[str, list[str]] = {}
    for device, members in (doc.get("devices") or {}).items():
        for member in members:
            devices.setdefault(member, []).append(device)
    known = set(parents) | set(devices) | set(doc.get("no_bios") or [])
    # FBNeo keys a console game by its driver (msx_1942): the
    # MSX, NES and Arcade lists each hold a 1942.
    consoles: dict[str, list[str]] = {}
    for key in known:
        driver, cut, stem = key.partition("_")
        if cut and stem:
            consoles.setdefault(stem, []).append(driver)
    return {
        "parents": parents, "devices": devices, "consoles": consoles,
        "plain": set(doc.get("no_bios") or []),
        "support": (set(doc.get("bios_sets") or []) | set(doc.get("bios") or {})
                    | set(doc.get("devices") or {})),
    }


class _GamesDocs:
    """The system and arcade documents of install/games/, each read once."""

    def __init__(self, data: GamesData, network: bool) -> None:
        self.data = data
        self.network = network
        self.systems: dict[str, SystemData] = {}
        self.arcades: dict[str, dict] = {}

    def system(self, system: str) -> SystemData:
        if system not in self.systems:
            self.systems[system] = SystemData(self.data.doc("systems", system, self.network))
        return self.systems[system]

    def arcade(self, name: str) -> dict | None:
        if name not in self.arcades:
            doc = self.data.doc("arcade", name, self.network)
            self.arcades[name] = {} if doc is None else _arcade_lookup(doc)
        return self.arcades[name] or None


class _GamesProgress:
    """The games read so far, as events and on the live line."""

    def __init__(self, total: int, term: Terminal | None) -> None:
        self.total = total
        self.done = 0
        self.evented = 0.0
        self.drawn = 0.0
        live = term is not None and term.live and not term.quiet
        self.stream = term.stream if live and term is not None else None

    def step(self, final: bool = False) -> None:
        now = time.monotonic()
        if EVENTS.on and (final or now - self.evented >= EVENT_PROGRESS_INTERVAL):
            self.evented = now
            EVENTS.emit("games_reading", files_done=self.done, files_total=self.total)
        if self.stream is not None and (final or now - self.drawn >= 0.1):
            self.drawn = now
            print(f"\r  read {self.done}/{self.total} games", end="", file=self.stream,
                  flush=True)

    def end(self) -> None:
        if self.total:
            self.step(final=True)
            if self.stream is not None:
                print("\r\033[K", end="", file=self.stream, flush=True)


def _folder_readers(row_systems: list[str], profiles: list[str | None],
                    docs: _GamesDocs) -> set[str]:
    """The cores of a folder's profiles that read its first system."""
    readers: set[str] = set()
    if row_systems:
        cores = docs.system(row_systems[0]).cores
        for profile in profiles:
            readers |= {name for name in (cores.get(profile or "") or {}).get("order") or []
                        if isinstance(name, str)}
    return readers


def _count_game(plan: GamesPlan, game_folder: GameFolder, row_systems: list[str],
                facts: GameFacts) -> None:
    """Count a game under each system of its folder."""
    for system in row_systems:
        info = plan.systems.setdefault(system, {"folders": [], "games": 0,
                                                "recognised": 0, "regions": None})
        if game_folder.path.name not in info["folders"]:
            info["folders"].append(game_folder.path.name)
        info["games"] += 1
        info["recognised"] += int(facts.recognised)


def _read_folder_games(plan: GamesPlan, game_folder: GameFolder, games: list[Path],
                       docs: _GamesDocs, cache: _ScanCache,
                       progress: _GamesProgress) -> list[GameFacts]:
    """Read the games of one folder: the ones that are not support sets."""
    row = game_folder.row
    row_systems = [str(s) for s in row.get("systems") or []]
    arcade = row.get("arcade") if isinstance(row.get("arcade"), str) else None
    profiles = _folder_profiles(row)
    if row_systems and not row.get("profile") and "fallback" not in row:
        plan.unknown_core += [s for s in row_systems if s not in plan.unknown_core]
    readers = _folder_readers(row_systems, profiles, docs)
    group: list[GameFacts] = []
    for path in games:
        shown = os.path.relpath(path, plan.root).replace(os.sep, "/")
        facts = GameFacts(path, shown, game_folder)
        progress.done += 1
        if row.get("arcade"):
            _read_arcade(facts, docs.arcade(arcade) if arcade else None,
                         _console_hints(game_folder))
        elif row_systems:
            read_game(facts, row_systems[0], docs.system(row_systems[0]), readers, cache)
        progress.step()
        if facts.kind == "support":
            plan.support += 1
            continue
        plan.games.append(facts)
        group.append(facts)
        _count_game(plan, game_folder, row_systems, facts)
    return group


def _plan_read_folders(plan: GamesPlan, read: list[tuple[GameFolder, list[GameFacts]]],
                       fallback: dict, entries: dict[str, dict], docs: _GamesDocs) -> None:
    """Add to the plan what the games read in each folder need."""
    for game_folder, group in read:
        if group:
            for profile in _folder_profiles(game_folder.row):
                if profile:
                    plan.profiles.add(str(profile))
                else:
                    plan.any_core.update(str(s) for s in game_folder.row.get("systems") or [])
            arcade = game_folder.row.get("arcade")
            sets = (docs.arcade(arcade) or {}).get("support", set()) \
                if isinstance(arcade, str) else set()
            _plan_game_folder(plan, game_folder, group, fallback, entries, docs.system, sets)


# Systems whose folder an arcade core reads as arcade sets, by their bare
# set name. Any other system's sets are console games, keyed by driver.
_ARCADE_SYSTEMS = frozenset({"arcade", "neogeo", "snk-neogeo", "sega-naomi", "sega-naomi2",
                             "sammy-atomiswave", "sega-stv", "cps1", "cps2", "cps3"})


def _console_hints(folder: GameFolder) -> tuple[str, ...] | None:
    """None for an arcade folder, else the words of its systems and its
    name, which tell one console's driver prefix from another's."""
    systems = [str(s) for s in folder.row.get("systems") or []]
    if not systems or any(s in _ARCADE_SYSTEMS or s.startswith("arcade") for s in systems):
        return None
    words = {word for system in systems for word in system.split("-")}
    words.add(folder.path.name.lower())
    return tuple(sorted(words))


def _read_arcade(facts: GameFacts, index: dict | None,
                 console: tuple[str, ...] | None = None) -> None:
    """An arcade set: a BIOS or device set (not a game), a game and the BIOS
    sets its romof chain reaches, or a name the core's DAT does not hold. In
    a console's folder (console, the words of its systems) a set is looked
    for under the core's driver name for it (msx_1942): the bare name is an
    arcade set's."""
    if _suffix(facts.path.name) not in ARCADE_SUFFIXES:
        facts.kind = "support"
        return
    name = os.path.splitext(facts.path.name)[0].lower()
    if index is None:
        facts.reason = "not_recognised"
        return
    if name in index["support"]:
        facts.kind = "support"
        return
    keys = [name]
    if console is not None:
        drivers = index.get("consoles", {}).get(name, [])
        hinted = [d for d in drivers if d in console]
        # A prefix no word of the folder names: every console's driver of
        # that name, so that the right one is among them.
        keys = [f"{d}_{name}" for d in sorted(hinted or drivers)] or [name]
    parents = {p for key in keys for p in index["parents"].get(key, ())}
    devices = {d for key in keys for d in index["devices"].get(key, ())}
    facts.parents, facts.devices = tuple(sorted(parents)), tuple(sorted(devices))
    if parents or devices or any(key in index["plain"] for key in keys):
        facts.recognised = True
        facts.title = keys[0] if len(keys) == 1 else name
    else:
        facts.reason = "unknown_set"


def _read_by_profiles(entries: dict[str, dict], dest: str, profiles: list[str]) -> bool:
    """Whether one of a folder's profiles reads dest, every core when the
    entry names none."""
    cores = (entries.get(dest) or {}).get("cores")
    return cores is None or any(name in cores for name in profiles)


def _plan_arcade_folder(plan: GamesPlan, games: list[GameFacts], entries: dict[str, dict],
                        profiles: list[str], sets: dict[str, tuple[list[str], set[str]]],
                        arcade_sets: Collection[str]) -> None:
    """Add to the plan the BIOS and device sets an arcade folder's games need."""
    # A BIOS set is looked for in the whole list, as the platform's own
    # declaration (neogeo.zip) and as the core's (fbneo/neogeo.zip).
    usable = [dest for dest in entries if _read_by_profiles(entries, dest, profiles)]
    whole = False
    for game in games:
        if game.reason:
            whole = True
            continue
        names = set(game.parents + game.devices)
        needed = _named_dests([f"{name}.zip" for name in names], usable)
        held = {Path(dest).name.casefold() for dest in needed}
        if any(f"{name}.zip".casefold() not in held for name in names):
            game.reason = "no_parent"
            whole = True
            continue
        plan.keep.update(needed)
        plan.required.update(needed)
    if whole:
        # Every set of the folder, and every BIOS set the core reads.
        own = _named_dests([f"{name}.zip" for name in arcade_sets],
                           [dest for dest in usable
                            if (entries.get(dest) or {}).get("cores") is not None])
        plan.keep.update(own)
        plan.required.update(own)
        for files, optional in sets.values():
            plan.keep.update(files)
            plan.required.update(dest for dest in files if dest not in optional)


def _region_kept(files: list[str], games: list[GameFacts], entries: dict[str, dict],
                 system: str, info: SystemData,
                 profile: str) -> tuple[list[str], bool, frozenset | None]:
    """The files of a set the games' regions keep, whether every region is
    kept, and the regions it was narrowed to (None when not narrowed)."""
    rule = info.rules.get(profile)
    region_free = {str(name).casefold() for name in (rule or {}).get("region_free") or []}
    tagged = any((entries.get(dest) or {}).get("regions") for dest in files)
    if not tagged:
        return list(files), False, None
    if region_rule_keeps_all(rule, games):
        return list(files), True, None
    proofs = [core_regions(game, system, info, profile) for game in games]
    needed = needed_regions(rule or {}, proofs)
    if needed is None:
        for game, proof in zip(games, proofs):
            if proof is None and not game.reason:
                game.reason = ("not_read" if not game.read
                               else "not_recognised" if not game.recognised
                               else "region_unknown")
        return list(files), True, None
    kept = keep_regions(files, entries, needed, region_free)
    if len(kept) < len(files):
        return kept, False, needed
    return kept, True, None


def _plan_set_extras(plan: GamesPlan, info: SystemData, profile: str, games: list[GameFacts],
                     files: list[str], kept: list[str], entries: dict[str, dict],
                     profiles: list[str]) -> None:
    """Add to the plan the games/extras.yml files of a set that fire."""
    for extra in info.extras:
        if extra.get("profile") != profile or not _extra_fires(extra, games):
            continue
        if extra.get("region_files"):
            named = [dest for dest in kept if (entries.get(dest) or {}).get("regions")]
        else:
            names = extra.get("files") or []
            named = _named_dests(names, files) or _named_dests(
                names, [dest for dest in entries if _read_by_profiles(entries, dest, profiles)])
        plan.keep.update(named)
        if extra.get("required") or extra.get("filename_override"):
            plan.required.update(named)


def _plan_game_folder(plan: GamesPlan, game_folder: GameFolder, games: list[GameFacts],
                      fallback: dict, entries: dict[str, dict],
                      system_data: Callable[[str], SystemData],
                      arcade_sets: Collection[str] = ()) -> None:
    """Add to the plan what one folder's games need. arcade_sets are the
    BIOS and device sets of the folder's arcade index."""
    row = game_folder.row
    profiles = [name for name in _folder_profiles(row) if name]

    if not row.get("systems"):
        # A port's own folder, read by one core and named by no system: what
        # that core loads.
        named = [dest for dest, entry in entries.items()
                 if any(name in (entry.get("cores") or []) for name in profiles)]
        plan.keep.update(named)
        plan.required.update(named)
        return
    keys = _folder_set_keys(row, fallback)
    sets: dict[str, tuple[list[str], set[str]]] = {key: _set_rows(fallback, key) for key in keys}
    if row.get("arcade"):
        _plan_arcade_folder(plan, games, entries, profiles, sets, arcade_sets)
        return
    narrowed: dict[str, set[str]] = {}
    wide: set[str] = set()
    for key, (files, optional) in sets.items():
        system, _, profile = key.partition("|")
        info = system_data(system)
        kept, every, narrowed_to = _region_kept(files, games, entries, system, info, profile)
        if every:
            wide.add(system)
        elif narrowed_to is not None:
            narrowed.setdefault(system, set()).update(narrowed_to)
        plan.keep.update(kept)
        plan.required.update(dest for dest in kept if dest not in optional)
        _plan_set_extras(plan, info, profile, games, files, kept, entries, profiles)
    for system, regions in narrowed.items():
        state = plan.systems.get(system)
        # Said only where no core of the folder keeps the other regions.
        if state is not None and system not in wide:
            state["regions"] = sorted(set(state["regions"] or ()) | regions)


def _extra_fires(extra: dict, games: list[GameFacts]) -> bool:
    """Whether a games/extras.yml entry applies to these games. A trigger on
    header bytes this file does not read applies: the file stays."""
    trigger = extra.get("trigger") or {}
    if trigger.get("every_game") or trigger.get("header"):
        return True
    extensions = {str(ext).lower() for ext in trigger.get("extensions") or []}
    return any(_suffix(game.path.name) in extensions for game in games)


def games_lines(plan: GamesPlan, manifest: dict | None, every: bool = False) -> list[str]:
    """The games read, in words: the head of the plan and of --check."""
    count = len(plan.games)
    if not count:
        lines = [f"No game found {plan.where()} ({shown_path(plan.root)})."]
        if plan.not_games:
            lines.append(f"  {_plural(plan.not_games, 'other file')} in its game folders: "
                         "none has an extension its system reads.")
        return lines
    recognised = sum(1 for game in plan.games if game.recognised)
    lines = [f"Games {plan.where()}: {count} in {_plural(len(plan.systems), 'system')}, "
             f"{recognised} recognised by their content ({shown_path(plan.root)})."]
    narrowed = [f"{system_title(system, manifest)} {', '.join(map(region_title, info['regions']))}"
                for system, info in sorted(plan.systems.items()) if info["regions"]]
    if narrowed:
        lines.append(f"  One region where the games prove it: {'; '.join(narrowed)}.")
    if plan.unknown_core:
        titles = ", ".join(system_title(system, manifest) for system in plan.unknown_core)
        lines.append(f"  No default core is known for {titles}: the files of each of its "
                     "cores are kept.")
    lines += fallback_lines(plan, every)
    if plan.truncated:
        lines.append(f"  Read up to {MAX_GAME_FILES} files: the others are left out of the count.")
    return lines


def fallback_lines(plan: GamesPlan, every: bool = False) -> list[str]:
    """The games that got every BIOS of their system, named."""
    fallback = plan.fallback
    if not fallback:
        return []
    shown = fallback if every else fallback[:3]
    names = ", ".join(f"{game.shown} ({GAMES_REASONS.get(game.reason, game.reason)})"
                      for game in shown)
    more = "" if len(shown) == len(fallback) else f" and {len(fallback) - len(shown)} more"
    their = "its" if len(fallback) == 1 else "their"
    return [f"  {agree(len(fallback), 'game gets', 'games get')} every BIOS of {their} "
            f"system: {names}{more}."]


def emit_games(plat: str, plan: GamesPlan, required_only: bool) -> None:
    EVENTS.emit("games", platform=plat, folder=str(plan.root), games=len(plan.games),
                recognised=sum(1 for game in plan.games if game.recognised),
                found=plan.event_systems(), fallback=plan.event_fallback(),
                not_games=plan.not_games, required_only=required_only)


def games_probe(plat: str, bios_path: Path, network: bool = True,
                data: GamesData | None = None, os_type: str = "",
                attempts: int = 2) -> int | None:
    """How many folders of the card hold a game, read by name alone (no
    file opened), None when it cannot be said: no rom folder near the BIOS
    folder, or install/games/ out of reach. What makes "For the games on this
    card" the first choice."""
    if not _may_hold_games(bios_path):
        return None
    data = data or GAMES
    try:
        index = data.load_index(network, attempts)
        for key in games_setups(index, plat, bios_path, os_type):
            setup = data.doc("setups", key, network, attempts)
            root = games_root(setup, bios_path) if setup is not None else None
            if root is None:
                continue
            held = 0
            for game_folder in game_folders(setup, index, root, False):
                games, _others = folder_games(game_folder, setup, 1)
                held += bool(games)
            return held
    except GamesUnavailable:
        return None
    return None


def read_games(args: argparse.Namespace, plat: str, bios_path: Path, manifest: dict,
               term: Terminal | None, os_type: str) -> GamesPlan | None:
    """The games of the card read for this run, their lines said. None when
    there are none to read, or what they need cannot be known: the run then
    keeps every file, and says so where --for-games asked."""
    asked = args.for_games is not None
    folder = args.for_games if isinstance(args.for_games, Path) else None
    if folder is not None:
        folder = Path(os.path.expanduser(str(folder))).absolute()
        if not _is_dir(folder):
            message = f"the games folder {folder} does not exist or cannot be opened"
            EVENTS.emit("games_unavailable", platform=plat, reason="no_folder", message=message)
            print(f"Error: {message}.", file=sys.stderr)
            sys.exit(1)
    # Not asked for, a run given its list as a file looks for the games index
    # beside it and in the cache only: one fetched now could describe another
    # list.
    network = asked or LOCAL.manifest is None
    if folder is None and not asked and not games_probe(plat, bios_path, network,
                                                       os_type=os_type):
        return None
    where = "on the card" if folder is None else f"in {folder}"
    detail(f"\nReading the games {where}...")
    try:
        plan = plan_games(plat, bios_path, manifest, folder, term, os_type=os_type,
                          network=network)
    except GamesUnavailable as exc:
        if asked:
            EVENTS.emit("games_unavailable", platform=plat, reason=exc.reason,
                        message=exc.words)
            print(fold_line(f"  What the games need is not known: {exc.words}. Every file "
                            "of the list is kept."))
        return None
    if plan is None:
        if asked:
            message = (f"no games folder was found beside {shown_path(bios_path)}: name it "
                       "with --for-games FOLDER")
            EVENTS.emit("games_unavailable", platform=plat, reason="no_folder", message=message)
            print(fold_line(f"  {message[0].upper()}{message[1:]}. Every file of the list "
                            "is kept."))
        return None
    emit_games(plat, plan, bool(args.required_only))
    for line in games_lines(plan, manifest, bool(args.verbose)):
        detail(fold_line(line if line.startswith("  ") else f"  {line}"))
    return plan


_PART_MARKER = re.compile(r"^(?P<stem>.+_BIOS_Pack)\.part(?P<index>\d+)of(?P<count>\d+)\.txt$")
MAX_MARKER_BYTES = 64 * 1024
