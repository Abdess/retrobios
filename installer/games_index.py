"""The games index under install/games/: where it lives, its bounds, the setups it covers."""
from __future__ import annotations

import hashlib
import http.client
import json
import re
import urllib.error
from pathlib import Path

from installer.cards import games_part
from installer.destination import card_root_above
from installer.detect_os import detect_os, detected_os
from installer.game_files import _cache_write, cache_folder
from installer.handheld_app import card_app
from installer.manifest import _SHA256_RE
from installer.network import _fetch_json, _read_capped
from installer.offline import LOCAL, _Offline, offline_words
from installer.remote import active_remote


# --- Games on the card -------------------------------------------------------
#
# --for-games keeps what the games of a card need, read from install/games/
# (scripts/generate_games_index.py): per system the files its default core
# reads (a fallback set), one region where the game's own bytes prove it,
# and for an arcade set the BIOS sets its romof chain reaches. Any doubt
# keeps the wider set: the game must run.

GAMES_FORMAT = 1


def games_url(path: str) -> str:
    """Where install/games/<path> is read from in this run."""
    return f"{active_remote().base}/install/games/{path}"


MAX_GAMES_INDEX_BYTES = 4 * 1024 * 1024
MAX_GAMES_DOC_BYTES = 32 * 1024 * 1024


_GAMES_DOC_NAME = re.compile(r"^(setups|fallback|systems|arcade)/[A-Za-z0-9_.+-]+\.json$")


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
                raw = _fetch_json(games_url("index.json"), MAX_GAMES_INDEX_BYTES,
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
            fetched = _fetch_json(games_url(name), limit, f"games {kind}",
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
