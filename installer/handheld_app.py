"""The installer copied onto a handheld's card as a launcher of its own."""
from __future__ import annotations

import argparse
import functools
import hashlib
import http.client
import io
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from installer.cards import card_system
from installer.console import _answer_yes
from installer.events import EVENTS
from installer.host_fs import NOT_WRITABLE, _write_refused
from installer.local_check import _sha256_file
from installer.network import _fetch_json, _read_limited, _retry_after_failure, network_words
from installer.offline import LOCAL, _Offline, _network_allowed
from installer.outcome import _transfer_failure
from installer.paths import _destination_path, _safe_relative_path
from installer.remote import BASE_URL, MAX_RETRIES, RAW_FILE_URL
from installer.safe_replace import KEPT, _write_verified
from installer.text import _plural

# The RetroBIOS app on a handheld's card. A card prepared on a computer can
# also carry the launcher of ports/ for its system, so the player checks and
# updates the BIOS files from the console later. The files come from the
# same ref as the file lists, listed with their hashes in
# install/launchers/index.json, which scripts/generate_launcher_index.py
# writes from the members of the launcher archives.
LAUNCHERS_URL = f"{BASE_URL}/install/launchers/index.json"
MAX_LAUNCHERS_BYTES = 256 * 1024
MAX_APP_FILE_SIZE = 8 * 1024 * 1024
MAX_APP_FILES = 64
APP_SCHEMA = 1


class AppPlace(NamedTuple):
    """Where a system's launcher goes on its card, and what the player does next.

    key names its entry in the launcher list, folder is below the card's
    root, executable says whether the menu runs the launcher script itself.
    """

    key: str
    folder: str
    executable: bool
    then: str


APP_PLACES: dict[str, AppPlace] = {
    # The Archive Manager lists the .muxapp files of ARCHIVE at the root of
    # SD1, SD2 and a USB drive, and installs one into Applications
    # (MustardOS/frontend 9c0fb5da, module/muxarchive.c:16,157-164,196-218,
    # MUOS_ARCH_PATH "ARCHIVE" in common/base/options.h:180). The archive
    # carries the modes of its members.
    "muOS": AppPlace("muos", "ARCHIVE", False,
                     "Then open the Archive Manager on the console, install RetroBIOS, "
                     "and start it from Applications."),
    # The card's root is the SHARE partition, /userdata on the console.
    # Ports runs a .sh with /bin/bash (knulli-cfw distribution ab3a6809,
    # configgen/generators/sh/shGenerator.py:19-35), and evmapy reads the
    # .keys file beside it: no mode is needed on the card.
    "KNULLI": AppPlace("knulli", "roms/ports", False,
                       "Then update the game list on the console, and start RetroBIOS "
                       "from Ports."),
    # The card's root is the STORAGE partition, /storage on the console. Tools
    # runs each file of /storage/.config/modules in foot or weston-terminal,
    # which starts it as a program: the build installs them 0755 (ROCKNIX
    # distribution 8b70f693, projects/ROCKNIX/packages/virtual/emulators/
    # package.mk:118-122 and 1701-1707).
    "ROCKNIX": AppPlace("rocknix", ".config/modules", True,
                        "Then start RetroBIOS from Tools on the console."),
}

# Card systems with no Python 3 to run the installer: Onion ships Python 2.7
# alone (OnionUI/Onion 07505ea5, static/build/.tmp_update/bin/parasyte/),
# MinUI (dbf89435), NextUI (5291344b) and Allium (ee0dda97) none, and
# MyMinUI is built from MinUI.
NO_PYTHON_CARDS = frozenset(("Onion", "Allium", "MinUI", "NextUI", "MyMinUI"))


def no_python_words(system: str) -> str:
    """Said where the card's system cannot run the installer. "This console"
    read as the computer the person was at."""
    return (f"{system} cannot run RetroBIOS: to update these files later, run it again "
            "on this computer.")


APP_OFFER = "Put RetroBIOS on this card (update from the console later)"
APP_OFFER_SHORT = "Put RetroBIOS on this card"


class CardApp(NamedTuple):
    """A card a BIOS folder is on, and whether the RetroBIOS app can go there."""

    root: Path
    system: str
    place: AppPlace | None
    why: str


def card_app(bios_dir: Path) -> CardApp | None:
    """The card bios_dir is the BIOS folder of, None for a folder on no card
    the installer recognises. why says, when place is None, why the app
    cannot go on it."""
    folder = Path(os.path.abspath(bios_dir))
    for root in [folder, *list(folder.parents)[:3]]:
        found = card_system(root)
        if found is None or Path(os.path.abspath(found[1])) != folder:
            continue
        system = found[2]
        place = APP_PLACES.get(system)
        if place is not None:
            return CardApp(root, system, place, "")
        why = (f"{system} has no Python to run RetroBIOS" if system in NO_PYTHON_CARDS
               else f"there is no RetroBIOS app for {system} yet")
        return CardApp(root, system, None, why)
    return None


def _app_entry(value: object, field: str, source: bool = True) -> dict:
    """One file of the launcher list, checked as a manifest entry is."""
    if not isinstance(value, dict):
        raise ValueError("an entry is not an object")
    _safe_relative_path(value.get(field), field)
    size = value.get("size")
    if type(size) is not int or not 0 < size <= MAX_APP_FILE_SIZE:
        raise ValueError(f"{value.get(field)}: invalid size")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"{value.get(field)}: invalid sha256")
    if not isinstance(value.get("executable", False), bool):
        raise ValueError(f"{value.get(field)}: invalid executable")
    if source:
        repo, content = value.get("repo_path"), value.get("content")
        if (repo is None) == (content is None):
            raise ValueError(f"{value.get(field)}: needs repo_path or content")
        if repo is not None:
            _safe_relative_path(repo, "repo_path")
        elif not isinstance(content, str):
            raise ValueError(f"{value.get(field)}: invalid content")
    return value


def app_targets(data: object, place: AppPlace) -> list[dict]:
    """The files the launcher list puts on a card for place, each under its
    folder: an archive carries its members, the others their source.

    The list comes from the same base as the file lists, and is held to
    the folder its system reads: no entry writes elsewhere on the card.
    """
    if not isinstance(data, dict) or data.get("schema") != APP_SCHEMA:
        raise ValueError(f"not a launcher list of schema {APP_SCHEMA}")
    launchers = data.get("launchers")
    launcher = launchers.get(place.key) if isinstance(launchers, dict) else None
    if not isinstance(launcher, dict):
        raise ValueError(f"it holds no launcher for {place.key}")
    if "archive" in launcher:
        target = dict(_app_entry(launcher["archive"], "dest", source=False))
        members = launcher.get("members")
        if not isinstance(members, list) or not 0 < len(members) <= MAX_APP_FILES:
            raise ValueError("invalid members")
        target["members"] = [_app_entry(member, "name") for member in members]
        if len({member["name"] for member in target["members"]}) != len(members):
            raise ValueError("two members share a name")
        targets = [target]
    else:
        files = launcher.get("files")
        if not isinstance(files, list) or not 0 < len(files) <= MAX_APP_FILES:
            raise ValueError("invalid files")
        targets = [_app_entry(entry, "dest") for entry in files]
    prefix = PurePosixPath(place.folder).parts
    for target in targets:
        parts = PurePosixPath(target["dest"]).parts
        if len(parts) <= len(prefix) or parts[:len(prefix)] != prefix:
            raise ValueError(f"{target['dest']} is outside {place.folder}")
    if len({target["dest"].casefold() for target in targets}) != len(targets):
        raise ValueError("two files share a destination")
    return targets


def app_archive(members: list[tuple[dict, bytes]]) -> bytes:
    """A launcher archive from its members: stored, sorted, dated 1980-01-01,
    only the executable bit kept, so the same members give the same bytes
    on any machine and the list can record their hash."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for entry, data in sorted(members, key=lambda member: member[0]["name"]):
            info = zipfile.ZipInfo(entry["name"], date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            mode = 0o755 if entry.get("executable") else 0o644
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def _app_download(url: str, size: int) -> bytes:
    """The bytes at url, tried MAX_RETRIES times, refused past size."""
    _network_allowed("the RetroBIOS app")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return _read_limited(resp, size, url)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            delay = _retry_after_failure(exc, attempt, MAX_RETRIES)
            if delay is None:
                raise
        time.sleep(delay)
    raise AssertionError("unreachable")


def _app_bytes(entry: dict, name: str) -> bytes:
    """An entry's bytes, from the list itself or the repository, once they
    have the size and the SHA-256 the list records."""
    content = entry.get("content")
    if content is not None:
        data = content.encode("utf-8")
    else:
        url = RAW_FILE_URL.format(path=urllib.parse.quote(entry["repo_path"], safe="/"))
        data = _app_download(url, entry["size"])
    if len(data) != entry["size"]:
        raise ValueError(f"{name} holds {len(data)} bytes, the list records {entry['size']}")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"{name}: SHA-256 mismatch")
    return data


def _target_bytes(target: dict) -> bytes:
    """What goes at a target's place: its file, or its archive built from
    its members and checked against the hash the list records for it."""
    members = target.get("members")
    if members is None:
        return _app_bytes(target, target["dest"])
    data = app_archive([(member, _app_bytes(member, member["name"])) for member in members])
    if len(data) != target["size"] or hashlib.sha256(data).hexdigest() != target["sha256"]:
        raise ValueError(f"{target['dest']} built from its members is not the one the "
                         "list records")
    return data


def _app_in_place(path: Path, target: dict) -> bool:
    try:
        return (path.is_file() and path.stat().st_size == target["size"]
                and _sha256_file(path) == target["sha256"])
    except OSError:
        return False


def _app_failure(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"the server answered HTTP {exc.code}"
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, _Offline) or _transfer_failure(exc):
        return network_words(exc)[1]
    return getattr(exc, "strerror", None) or str(exc)


def put_app(card: CardApp) -> dict:
    """Put the launcher of card's system on it: the fields of the app event.

    Every file is fetched and verified before the first one is written, and
    written as a BIOS file is, the one in place kept aside when it differs.
    A file already in place with the recorded hash is left alone, so a
    second run writes nothing.
    """
    fields: dict = {"system": card.system, "folder": str(card.root), "ok": False,
                    "reason": card.why, "dests": [], "written": [], "kept": []}
    if card.place is None:
        return fields
    try:
        data = _fetch_json(LAUNCHERS_URL, MAX_LAUNCHERS_BYTES, "list of the app's files")
        targets = app_targets(data, card.place)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        fields["reason"] = f"its list of files could not be read: {_app_failure(exc)}"
        return fields
    fields["dests"] = [target["dest"] for target in targets]
    places = [(target, _destination_path(card.root, target["dest"])) for target in targets]
    needed = [(target, path) for target, path in places if not _app_in_place(path, target)]
    try:
        payloads = [_target_bytes(target) for target, _path in needed]
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        fields["reason"] = f"it could not be downloaded: {_app_failure(exc)}"
        return fields
    before = {item["folder"]: (item["files"], item["bytes"]) for item in KEPT.summary()}
    for (target, path), payload in zip(needed, payloads):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fields["reason"] = NOT_WRITABLE if _write_refused(exc) else _app_failure(exc)
            break
        _dest, ok, why = _write_verified(
            target, card.root, path, functools.partial(io.BytesIO, payload), None,
            "the RetroBIOS app")
        if not ok:
            fields["reason"] = f"{target['dest']}: {why}"
            break
        fields["written"].append(target["dest"])
    else:
        fields["ok"], fields["reason"] = True, ""
    for item in KEPT.summary():
        files, size = before.get(item["folder"], (0, 0))
        if item["files"] > files:
            fields["kept"].append({"folder": item["folder"], "files": item["files"] - files,
                                   "bytes": item["bytes"] - size})
    return fields


def app_lines(card: CardApp, fields: dict) -> list[str]:
    """What putting the app on the card did, in words."""
    if not fields["ok"]:
        return [f"RetroBIOS could not be put on the {card.system} card: {fields['reason']}."]
    if fields["written"]:
        lines = [f"RetroBIOS is on the {card.system} card: "
                 f"{_plural(len(fields['written']), 'file')} written in {card.root}."]
    else:
        lines = [f"RetroBIOS is already on the {card.system} card: nothing to write."]
    lines += [f"The files it replaced are kept in {kept['folder']}" for kept in fields["kept"]]
    if card.place is not None:
        lines.append(card.place.then)
    return lines


def app_refusal(args: argparse.Namespace, platforms: list[tuple[str, Path]]) -> list[CardApp]:
    """The cards --add-app puts the app on, one per folder. A folder that is
    on no card the app can go on is refused with the reason, code 2, before
    anything is written."""
    cards: list[CardApp] = []
    if not args.add_app:
        return cards
    for _plat, path in platforms:
        card = card_app(path)
        if card is None:
            why = (f"{path} is not on a card this installer recognises (a muOS, "
                   "KNULLI or ROCKNIX card)")
        else:
            why = card.why
        if card is None or why:
            EVENTS.emit("app", system=card.system if card else "",
                        folder=str(card.root if card else path), ok=False, reason=why,
                        dests=[], written=[], kept=[])
            print(f"Error: --add-app puts the RetroBIOS app on a handheld's SD card, and "
                  f"{why}.", file=sys.stderr)
            if card is not None and card.system in NO_PYTHON_CARDS:
                print(f"  {no_python_words(card.system)}", file=sys.stderr)
            else:
                print("  Name the card's root or its BIOS folder with --dest.",
                      file=sys.stderr)
            sys.exit(2)
        if card not in cards:
            cards.append(card)
    _APP_PENDING[:] = cards
    return cards


# The cards --add-app named, until the install finishes and the app is put.
_APP_PENDING: list[CardApp] = []


def app_not_added() -> None:
    """--add-app in a run that stopped before the app: said, never silent."""
    cards, _APP_PENDING[:] = list(_APP_PENDING), []
    for card in cards:
        EVENTS.emit("app", system=card.system, folder=str(card.root), ok=False,
                    reason="the install did not finish", dests=[], written=[], kept=[])
        print(f"  RetroBIOS was not put on the {card.system} card: the install did "
              "not finish.", file=sys.stderr)


def finish_app(
    args: argparse.Namespace, platforms: list[tuple[str, Path]], cards: list[CardApp],
    interactive: bool,
) -> None:
    """After an install that finished: the app on the cards --add-app named,
    or on those the person says yes for at a terminal."""
    _APP_PENDING[:] = []
    chosen = list(cards)
    if not args.add_app:
        for card in dict.fromkeys(filter(None, (card_app(path) for _plat, path in platforms))):
            if card.place is None:
                if card.system in NO_PYTHON_CARDS:
                    print(f"\n{no_python_words(card.system)}")
                continue
            if not interactive or args.yes or LOCAL.offline:
                continue
            if _answer_yes(f"\nPut RetroBIOS on this {card.system} card, to check and "
                           "update its BIOS files from the console later? [y/N] "):
                chosen.append(card)
    failed = False
    for card in chosen:
        print(f"\nPutting RetroBIOS on the {card.system} card...")
        fields = put_app(card)
        EVENTS.emit("app", **fields)
        stream = sys.stdout if fields["ok"] else sys.stderr
        for line in app_lines(card, fields):
            print(f"  {line}", file=stream)
        failed = failed or not fields["ok"]
    if failed:
        sys.exit(1)
