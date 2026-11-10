"""The collection as the site files it: every folder holding each file.

The database keeps one path per content. The folders a copy is also filed
in, the system sections and the game-engine sections are read here, by the
page generator and by the tools that draw or fetch per-system images. The
bios folder comes from siteinputs, never the working directory.
"""

from __future__ import annotations

import functools
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import siteinputs  # noqa: E402
from common import GAME_DATA_TOPS, load_emulator_profiles  # noqa: E402


def _copy_places(db: dict) -> dict[str, set[tuple[str, str, str]]]:
    """sha1 -> every (manufacturer, console, file name) holding a copy.

    The database keeps one path per content, deduplication having left one
    copy. by_path_suffix still records the other folders a copy is filed in,
    under the name that folder gives it.
    """
    files = db.get("files", {})
    bios_dir = siteinputs.bios_dir(db)
    places: dict[str, set[tuple[str, str, str]]] = {}
    for sha1, entry in files.items():
        parts = str(entry.get("path", "")).split("/")
        if len(parts) >= 3 and parts[0] == "bios":
            places.setdefault(sha1, set()).add((parts[1], parts[2], parts[-1]))
    for tail, sha1s in db.get("indexes", {}).get("by_path_suffix", {}).items():
        parts = tail.split("/")
        if len(parts) < 3 or parts[1].startswith(".") or len(sha1s) != 1:
            continue
        if sha1s[0] in files and (bios_dir / tail).is_file():
            places.setdefault(sha1s[0], set()).add((parts[0], parts[1], parts[-1]))
    return places


def _slug(manufacturer: str) -> str:
    return manufacturer.lower().replace(" ", "-")


def collection_paths(db: dict) -> dict[str, set[str]]:
    """Every path under bios/ that holds each file, by sha1.

    The database keeps one path per content. The others are the full tails
    by_path_suffix records that name a file on disk: RPG Maker, engine
    trees and the copies filed under several consoles keep 2,502 of them.
    """
    files = db.get("files", {})
    bios_dir = siteinputs.bios_dir(db)
    paths: dict[str, set[str]] = {}
    for sha1, entry in files.items():
        path = str(entry.get("path", ""))
        if path.startswith("bios/") and path.count("/") >= 2:
            paths.setdefault(sha1, set()).add(path)
    for tail, sha1s in db.get("indexes", {}).get("by_path_suffix", {}).items():
        if tail.count("/") < 2 or len(sha1s) != 1 or sha1s[0] not in files:
            continue
        if (bios_dir / tail).is_file():
            paths.setdefault(sha1s[0], set()).add(f"bios/{tail}")
    return paths


def _group_by_manufacturer(db: dict) -> dict[str, dict[str, list]]:
    """Group files by manufacturer -> console -> files.

    The database keeps one path per content, and a copy filed elsewhere was
    on no page of its own: the Channel F BIOS sat under Arcade > FBNeo only,
    and Fairchild had no system page. Every folder holding a copy lists it,
    read from the full paths by_path_suffix records. The game engines'
    files are grouped by engine (_engine_sections).
    """
    files = db.get("files", {})
    manufacturers: dict[str, dict[str, list]] = {}
    for sha1, where in _copy_places(db).items():
        for manufacturer, console in sorted({(m, c) for m, c, _ in where}):
            manufacturers.setdefault(manufacturer, {}).setdefault(console, []).append(files[sha1])
    return _engine_sections(manufacturers)


def _engine_sections(manufacturers: dict[str, dict[str, list]]) -> dict[str, dict[str, list]]:
    """A game engine's files in one section headed with the engine's name.

    The Systems index listed ".variants", "scummvm.zip" and "wildmidi.cfg"
    as games, and ScummVM's files sat on three pages. A folder of variants
    joins the section of its primary, a file kept at a top's root joins
    the section of the one engine that reads it (else of the engine the
    top is named after), the folder under Other named after a game-engine
    top joins that top, and a folder named by a profile key is headed with
    the engine's name (SECTION_LABELS), its address unchanged.
    """
    from siterender import _PROGRAM_TOPS, SECTION_LABELS, record_card_move  # noqa: PLC0415

    profiles = {key: profile for key, profile in _profiles_on_disk().items()
                if profile.get("type") != "alias" and profile.get("role") != "test"}
    readers: dict[str, set[str]] = {}
    for key, profile in profiles.items():
        for entry in profile.get("files") or []:
            if isinstance(entry, dict):
                for name in [entry.get("name"), *(entry.get("aliases") or [])]:
                    if name:
                        readers.setdefault(str(name).rsplit("/", 1)[-1], set()).add(key)

    def engine(key: str) -> str:
        return str(profiles[key].get("emulator") or key)

    def profile_of(name: str) -> str | None:
        return next((k for k in sorted(profiles)
                     if name.casefold() in (k.casefold(), engine(k).casefold())), None)

    out: dict[str, dict[str, list]] = {}
    for mfr, consoles in manufacturers.items():
        if mfr not in GAME_DATA_TOPS:
            out[mfr] = dict(consoles)
            continue
        own = profile_of(mfr)
        regrouped: dict[str, list] = {}
        for console, files in sorted(consoles.items(), key=lambda item: item[0].startswith(".")):
            for f in files:
                parts = str(f.get("path", "")).split("/")
                target = console
                if console.startswith(".") or (len(parts) == 3 and console == parts[-1]):
                    # A variant answers its primary's name: scummvm.zip.a93f1c4b.
                    base = parts[-1].rsplit(".", 1)[0] if console.startswith(".") else parts[-1]
                    keys = sorted(readers.get(base, ()))
                    reader = keys[0] if len(keys) == 1 else own
                    found = next((c for c, held in regrouped.items()
                                  if any(h.get("name") == base for h in held)), None)
                    target = found or (next((c for c in consoles if c == reader), None)
                                       or (engine(reader) if reader else base))
                if target != console:
                    record_card_move(mfr, console, str(f.get("sha1", "")), mfr, target)
                regrouped.setdefault(target, []).append(f)
        out[mfr] = regrouped
    # The folder under Other an engine top is named after: ScummVM's
    # engine data under Other/ScummVM, its themes under ScummVM/.
    others = out.get("Other", {})
    for folder in sorted(others):
        top = next((t for t in out if t in GAME_DATA_TOPS and t.casefold() == folder.casefold()),
                   None)
        if top is None or top in _PROGRAM_TOPS:
            continue
        sections = out[top]
        target = next((c for c in sections if c.casefold() == folder.casefold()), folder)
        held = {str(f.get("sha1", "")) for f in sections.get(target, [])}
        for f in others[folder]:
            record_card_move("Other", folder, str(f.get("sha1", "")), top, target)
        sections[target] = [*sections.get(target, []),
                            *(f for f in others.pop(folder) if str(f.get("sha1", "")) not in held)]
    for mfr in GAME_DATA_TOPS:
        for console in out.get(mfr, {}):
            named = console if console in profiles else None
            if named and engine(named) != console:
                SECTION_LABELS[(mfr, console)] = engine(named)
    return {mfr: consoles for mfr, consoles in out.items() if consoles}


def _profiles_on_disk() -> dict[str, dict]:
    return _profiles_in(str(siteinputs.current().emulators), skip_aliases=False)


@functools.lru_cache(maxsize=None)
def _profiles_in(emulators_dir: str, skip_aliases: bool) -> dict[str, dict]:
    return load_emulator_profiles(emulators_dir, skip_aliases=skip_aliases)
