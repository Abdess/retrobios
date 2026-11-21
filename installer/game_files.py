"""The games of a card read from disk: their folders, what each file is, and the scan cache."""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import zipfile
import zlib
from pathlib import Path
from typing import NamedTuple

from installer.cards import games_part
from installer.host_fs import _is_dir, write_atomically
from installer.network import _read_capped

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
        write_atomically(path, data)
    except OSError as exc:
        if os.environ.get("RETROBIOS_DEBUG"):
            print(f"  Not cached: {path} ({exc.strerror or exc})", file=sys.stderr)


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
