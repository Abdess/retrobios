"""The files the collection lacks, as the wanted page reads them.

A visitor drops files on wanted/, each is hashed in the browser and
compared with this list, and the page lists every entry under the drop
box. The list is the gaps page's: a file a platform lists that its own
check finds missing or under another hash, a file an emulator loads that
no platform lists and the collection does not hold, and a file not
collected yet. A declaration that names no hash is kept and marked: it
is recognised by its name only, and the review of the upload decides.

Each entry keeps the hashes its declaration writes, read as the resolver
reads them (comma lists split, a crc32 counted only where no stronger hash
is declared), and the folder validate_pr.placement() gives those hashes:
the review of the pull request asks for that same folder.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Iterable
from pathlib import Path

import archive_build
from common import unique_emulator_profiles
from cross_reference import _first_hash
from hashing import cut_md5_owner, parse_hash_list
from validate_pr import LARGE_FILE_ISSUE_URL, Placement, placement

ALGORITHMS = ("sha1", "sha256", "md5", "crc32")
# GitHub's upload page takes 25 MB per file. A larger file goes in by a
# push or, past 100 MB, through the issue form (CONTRIBUTING.md).
BROWSER_UPLOAD_LIMIT = 25 * 1024 * 1024
# The upload page of a folder is this followed by the folder.
UPLOAD_ROOT = "https://github.com/Abdess/retrobios/upload/main/"
# Under the site's public folder, read by WantedFiles.astro.
DATA_FILE = "data/wanted.json"


def _sizes(entry: dict) -> list[int]:
    size = entry.get("size")
    values = size if isinstance(size, list) else [size]
    return sorted({int(v) for v in values if isinstance(v, int) and not isinstance(v, bool) and v > 0})


def declared_hashes(entry: dict) -> dict[str, list[str]]:
    """The hashes that identify an entry's own bytes, by algorithm.

    A zipped_file md5 is the md5 of a ROM inside the archive, not of the
    archive, so it says nothing about the file a visitor drops. A crc32
    counts only where no stronger hash is declared, as in
    resolve_local_file.
    """
    hashes = {algo: parse_hash_list(entry.get(algo)) for algo in ALGORITHMS}
    if entry.get("zipped_file"):
        hashes["md5"] = []
    hashes["md5"] = [v for v in hashes["md5"] if 0 < len(v) <= 32]
    hashes["sha1"] = [v for v in hashes["sha1"] if len(v) == 40]
    hashes["sha256"] = [v for v in hashes["sha256"] if len(v) == 64]
    hashes["crc32"] = [v.zfill(8) for v in hashes["crc32"] if len(v) <= 8]
    if hashes["sha1"] or hashes["sha256"] or hashes["md5"]:
        hashes["crc32"] = []
    return {algo: values for algo, values in hashes.items() if values}


def _alternatives(hashes: dict[str, list[str]]) -> list[dict[str, list[str]]]:
    """One declaration per file it accepts.

    A Recalbox entry lists every revision its check takes in one md5 field:
    each is a file of its own, with a folder of its own. Values of two
    algorithms cannot be paired, so such an entry stays whole.
    """
    listed = [algo for algo, values in hashes.items() if len(values) > 1]
    if len(hashes) == 1 and listed:
        algo = listed[0]
        return [{algo: [value]} for value in hashes[algo]]
    return [hashes]


class Held:
    """What the collection holds, by every hash a file or an archive
    member is known under."""

    def __init__(self, db: dict, ledger: Iterable[dict] = ()) -> None:
        files = db.get("files", {})
        indexes = db.get("indexes", {})
        self.sha1 = set(files)
        self.md5 = set(indexes.get("by_md5", {}))
        self.sha256 = set(indexes.get("by_sha256", {}))
        self.crc32: dict[str, set[int]] = {}
        for record in files.values():
            crc = str(record.get("crc32") or "").lower()
            if crc:
                self.crc32.setdefault(crc, set()).add(int(record.get("size") or 0))
        # A ROM held only inside one of the collection's archives.
        for archive in ledger:
            for member in archive.get("members") or []:
                if member.get("sha1"):
                    self.sha1.add(str(member["sha1"]).lower())
                crc = str(member.get("crc32") or "").lower()
                if crc:
                    self.crc32.setdefault(crc, set()).add(int(member.get("size") or 0))

    def holds(self, hashes: dict[str, list[str]], sizes: list[int]) -> bool:
        if any(v in self.sha1 for v in hashes.get("sha1", [])):
            return True
        if any(v in self.sha256 for v in hashes.get("sha256", [])):
            return True
        for value in hashes.get("md5", []):
            if value in self.md5 or (len(value) < 32 and cut_md5_owner(value, self.md5)):
                return True
        for value in hashes.get("crc32", []):
            held = self.crc32.get(value, set())
            if held and (not sizes or held & set(sizes)):
                return True
        return False


def gap_entries(profile: dict, name: str, identity: str, unsourceable: bool) -> list[dict]:
    """The profile entries behind one row of the gap report."""
    named = [f for f in profile.get("files") or []
             if isinstance(f, dict) and f.get("name") == name]
    if unsourceable:
        return [f for f in named if f.get("unsourceable")] or named
    if identity:
        return [f for f in named if _first_hash(f) == identity] or named
    return named


def _directory(entry: dict) -> str:
    """The directory a declaration names for its file: a platform's
    destination, a profile's path. Empty for a bare name."""
    where = str(entry.get("destination") or entry.get("path") or "")
    return where.rsplit("/", 1)[0] + "/" if "/" in where else ""


def _paired(files: list, details: list[dict]) -> Iterable[tuple[dict, dict]]:
    """Each verify detail of a system with the declaration it scores.

    verify scores the declarations of a system in order, one detail each,
    so the k-th detail of a name is the k-th declaration of that name:
    AmberELEC declares config.ini once per blueMSX machine, and a match by
    name alone gave each missing one every machine's folder.
    """
    by_name: dict[str, list[dict]] = {}
    for entry in files:
        if isinstance(entry, dict):
            by_name.setdefault(str(entry.get("name")), []).append(entry)
    seen: dict[str, int] = {}
    for detail in details:
        name = str(detail.get("name"))
        position = seen.get(name, 0)
        seen[name] = position + 1
        same = by_name.get(name, [])
        if position < len(same):
            yield detail, same[position]


def wanted_declarations(profiles: dict, coverages: dict, gap_report: dict) -> list[dict]:
    """Every declaration of a file the gaps page reports as lacking.

    Each is {name, system, required, reader: (kind, key, label), entry,
    reason, category, directory}: the reason a file not collected yet
    carries, empty otherwise, and game_data or bios as verify (a
    platform's entry) or the profile (an emulator's) gives it.
    """
    found: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        systems = coverage.get("config", {}).get("systems") or {}
        by_system: dict[str, list[dict]] = {}
        for detail in coverage.get("details", []):
            by_system.setdefault(detail.get("system", ""), []).append(detail)
        for system, details in sorted(by_system.items()):
            files = (systems.get(system) or {}).get("files") or []
            for detail, entry in _paired(files, details):
                if detail.get("settled_by") or detail.get("status") not in ("missing", "untested"):
                    continue
                found.append({
                    "name": str(entry["name"]), "system": system,
                    "required": bool(detail.get("required", True)),
                    "reader": ("platform", key, coverage["platform"]), "entry": entry,
                    "reason": "",
                    "category": detail.get("category") if detail.get("category") in RANK else BIOS,
                    "directory": _directory(entry),
                })
    unique = unique_emulator_profiles(profiles)
    for key, data in sorted(gap_report.items()):
        profile = unique.get(key)
        if profile is None:
            continue
        systems = [str(s) for s in data.get("systems") or profile.get("systems") or []]
        rows = [(gap, False) for gap in data.get("gap_details") or []
                if gap.get("source") == "missing" and not gap.get("bundled")]
        rows += [(row, True) for row in data.get("unsourceable") or []]
        for row, unsourceable in rows:
            for entry in gap_entries(profile, str(row.get("name", "")),
                                      str(row.get("identity") or ""), unsourceable):
                system = entry.get("system") or (systems[0] if len(systems) == 1 else "")
                found.append({
                    "name": str(entry["name"]), "system": str(system),
                    "required": bool(row.get("required", False)),
                    "reader": ("emulator", key, str(data.get("emulator", key))), "entry": entry,
                    "reason": str(row.get("reason") or "") if unsourceable else "",
                    "category": GAME_DATA if entry.get("category") == GAME_DATA else BIOS,
                    "directory": _directory(entry),
                })
    return found


def catalog_listings(report: dict | None, labels: dict[str, str]) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """(profile, file name casefolded) -> (catalog or romset, the name it
    lists the file under), from a provenance report built with the
    profiles' needs: the "Listed in" column of the gaps page."""
    out: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for source, data in sorted((report or {}).items()):
        label = labels.get(source, source)
        for entry in data.get("missing", []):
            where = [(label, str(entry.get("name", "")))]
            where += [(str(hit["source"]), str(hit["archive"])) for hit in entry.get("romsets", [])]
            for need in entry.get("needed_by", []):
                held = out.setdefault((need["emulator"], str(need["name"]).casefold()), [])
                held += [w for w in where if w not in held]
    return out


BIOS = "bios"
GAME_DATA = "game_data"
# verify's category for a platform entry no core the platform runs reads.
UNREAD = "unread"
# Firmware first, then what a platform lists and no core reads, then game
# data. The value is also the list's k field, absent for firmware.
RANK = {BIOS: 0, UNREAD: 1, GAME_DATA: 2}
# A name the code builds from the content (<serial>.txt, *.ini) is a
# pattern, not a file anyone can upload.
PATTERN = re.compile(r"[<>*?]")
# A file not collected yet stays wanted, however hard it is to find ("no
# public dump located", "retail data the collection does not hold"). It
# leaves the list only when its reason (the profile's `unsourceable:`)
# says no copy can be shared, read by the rules below.
NOT_SHAREABLE = re.compile("|".join([
    # Any file of the name serves: there is no one file to collect.
    r"\bno canonical\b",
    # The user writes, picks, records or places it (WHDLoad's key aside,
    # emucorev's config.txt: "plugin list the user writes").
    r"\bthe user\b|\buser[- ](?:supplied|authored|created|settings|overlay|placeholder)\b"
    r"|\bother users\b",
    # The emulator or the guest writes it: a save, a state, a generated key.
    r"\bwritten by (?:the (?:emulator|guest|firmware editor)|bam)\b|\bgenerated by the emulator\b"
    r"|\bwith the debug key\b|\bmachine state\b|\bcreat\w* (?:this directory )?empty\b",
    # It belongs to one person, one account or one copy (puae's WHDLoad.key).
    r"\bper[- ]user\b|\btied to the (?:account|tag)\b|\bnever distributed generically\b"
    r"|\bissued for one copy\b",
    # Nothing was ever released under the name.
    r"\bno (?:distributed form|released artefact|hardware dump equivalent)\b"
    r"|\bno file of this name is distributed\b",
]), re.I)


def shareable(reason: str) -> bool:
    """False when a reason says no copy of the file can be shared."""
    return not NOT_SHAREABLE.search(reason)


def _settle_cut(records: list[dict]) -> None:
    """A cut md5 names a dump only if exactly one md5 starts with it.

    Matched against the wanted md5s: with one match the cut is that md5.
    With several it names none, and an entry left with no hash is known by
    its name. With none the page compares by prefix.
    """
    full = {v for r in records for v in r["hashes"].get("md5", []) if len(v) == 32}
    for record in records:
        kept = []
        for value in record["hashes"].get("md5", []):
            if len(value) == 32:
                kept.append(value)
                continue
            starting = {md5 for md5 in full if md5.startswith(value)}
            if len(starting) == 1:
                kept.append(starting.pop())
            elif not starting:
                kept.append(value)
        if kept:
            record["hashes"]["md5"] = sorted(set(kept))
        else:
            record["hashes"].pop("md5", None)


class Placer:
    """validate_pr's placement for a declaration: its declared hashes,
    strongest first, and its name.

    The database stands in for the disk validate_pr reads: the site is
    built from a checkout whose release assets are not on disk.
    """

    def __init__(self, db: dict, platform_hashes: dict, profile_hashes: dict) -> None:
        self.db = db
        self.platform_hashes = platform_hashes
        self.profile_hashes = profile_hashes
        self.paths = {
            path for record in db.get("files", {}).values()
            for path in [record.get("path"), *(record.get("paths") or [])] if path
        }

    def place(self, hashes: dict[str, list[str]], name: str, systems: Iterable[str] = (),
              directory: str = "") -> Placement:
        """A declaration that writes no hash is known by its name alone,
        as the review knows a file whose hashes nothing declares, and its
        folder comes from its systems and its declared directory."""
        values = [value for algo in ("sha1", "md5", "sha256") for value in hashes.get(algo, [])
                  if len(value) == FULL_LENGTH[algo]]
        return placement(values, name, self.db, self.platform_hashes, self.profile_hashes,
                         declared=bool(hashes), exists=self.paths.__contains__,
                         systems=sorted(systems), directory=directory)

    def folder(self, entry: dict, system: str = "") -> str:
        """The folder an upload of a profile or platform entry goes to."""
        system = str(entry.get("system") or system)
        return self.place(declared_hashes(entry), str(entry.get("name", "")),
                          [system] if system else [], _directory(entry)).folder


FULL_LENGTH = {"sha1": 40, "md5": 32, "sha256": 64}


def upload_href(root: str, folder: str) -> str:
    """GitHub's upload page for a folder of the repository, bios/ when the
    placement names none."""
    return root + urllib.parse.quote((folder or "bios/").rstrip("/"))


def _order(record: dict) -> tuple:
    """Most useful first: required firmware, optional firmware, then the
    files no core reads, then game data, required first, and within each
    by how many setups and emulators read the file."""
    return (RANK[record["category"]], not record["required"], -len(record["readers"]),
            record["name"].casefold(), sorted(record["readers"]))


def reader_page(kind: str, key: str, entry: dict) -> str:
    """Where a reader's page is, below the site root: the page a row of
    the list links when no card anchor is given."""
    return f"{'emulators' if kind == 'emulator' else 'platforms'}/{key}/"


def build_wanted(
    profiles: dict,
    coverages: dict,
    gap_report: dict,
    db: dict,
    placer: Placer,
    system_name: Callable[[str], str],
    ledger: Iterable[dict] = (),
    link: Callable[[str, str, dict], str] = reader_page,
) -> dict:
    """The wanted list, compact, as public/data/wanted.json carries it.

    Readers, systems and folders are written once and named by position.
    An entry: n name, h hashes (absent when the declarations write none:
    the file is known by its name only), c a crc32 a declaration writes
    beside a stronger hash (shown, never matched), w readers, s systems,
    r required, z sizes, a the page holding its details (*link*: the card
    of the first emulator that reads it, else the page of the first setup
    that lists it), f folder, t the name it is uploaded under, v that name
    goes to the folder's .variants/ with the first 8 characters of its
    sha1. Entries come most useful first (_order). A file no one can share
    (the reason says so, NOT_SHAREABLE) is left out.
    """
    held = Held(db, ledger)
    records: dict[tuple, dict] = {}
    for declaration in wanted_declarations(profiles, coverages, gap_report):
        if PATTERN.search(declaration["name"]) or not shareable(declaration["reason"]):
            continue
        entry = declaration["entry"]
        sizes = _sizes(entry)
        for hashes in _alternatives(declared_hashes(entry)):
            if hashes and held.holds(hashes, sizes):
                continue
            key = ((declaration["name"], tuple(sorted((a, tuple(v)) for a, v in hashes.items())),
                    tuple(sizes)) if hashes
                   else (declaration["name"].casefold(), declaration["system"],
                         declaration["directory"]))
            record = records.setdefault(key, {
                "name": declaration["name"], "hashes": {a: list(v) for a, v in hashes.items()},
                "sizes": sizes, "systems": set(), "required": False, "readers": set(),
                "category": GAME_DATA, "directory": declaration["directory"],
                "crc": set(), "links": {},
            })
            if RANK[declaration["category"]] < RANK[record["category"]]:
                record["category"] = declaration["category"]
            if declaration["system"]:
                record["systems"].add(declaration["system"])
            record["required"] = record["required"] or declaration["required"]
            record["readers"].add(declaration["reader"])
            record["crc"] |= {v.zfill(8) for v in parse_hash_list(entry.get("crc32")) if len(v) <= 8}
            kind, reader_key, _label = declaration["reader"]
            record["links"].setdefault((kind != "emulator", reader_key), link(kind, reader_key, entry))
    _merge_named(records)
    ordered = sorted(records.values(), key=_order)
    _settle_cut(ordered)

    readers = sorted({reader for r in ordered for reader in r["readers"]},
                     key=lambda reader: (reader[0], reader[2].casefold(), reader[1]))
    reader_at = {reader: i for i, reader in enumerate(readers)}
    titles = sorted({system_name(s) for r in ordered for s in r["systems"]}, key=str.casefold)
    title_at = {title: i for i, title in enumerate(titles)}
    folders: list[str] = []
    folder_at: dict[str, int] = {}
    entries = []
    for record in ordered:
        spot = placer.place(record["hashes"], record["name"], record["systems"],
                            record["directory"])
        if spot.folder and spot.folder not in folder_at:
            folder_at[spot.folder] = len(folders)
            folders.append(spot.folder)
        item: dict = {"n": record["name"]}
        if record["hashes"]:
            item["h"] = {algo: record["hashes"][algo] for algo in ALGORITHMS if algo in record["hashes"]}
        if record["crc"] and "crc32" not in record["hashes"]:
            item["c"] = sorted(record["crc"])
        item["w"] = sorted(reader_at[reader] for reader in record["readers"])
        systems = sorted({title_at[system_name(s)] for s in record["systems"]})
        if systems:
            item["s"] = systems
        if record["required"]:
            item["r"] = 1
        if record["sizes"]:
            item["z"] = record["sizes"]
        item["a"] = record["links"][min(record["links"])]
        if spot.folder:
            item["f"] = folder_at[spot.folder]
        if spot.name:
            item["t"] = spot.name
            if spot.variant:
                item["v"] = 1
        entries.append(item)
    return {
        "upload": UPLOAD_ROOT,
        "issue": LARGE_FILE_ISSUE_URL,
        "limit": BROWSER_UPLOAD_LIMIT,
        "readers": [[kind[0], key, label] for kind, key, label in readers],
        "systems": titles,
        "folders": folders,
        "entries": entries,
    }


def _merge_named(records: dict[tuple, dict]) -> None:
    """A declaration that writes no hash takes any file of its name: when
    a declaration of the same name and system writes one, the file that
    meets it meets both, so its readers join that entry."""
    hashed: dict[tuple[str, str], list[dict]] = {}
    for record in records.values():
        if record["hashes"]:
            for system in record["systems"] or {""}:
                hashed.setdefault((record["name"].casefold(), system), []).append(record)
    for key in [k for k, record in records.items() if not record["hashes"]]:
        targets = hashed.get(key[:2], [])
        if len(targets) != 1:
            continue
        record = records.pop(key)
        target = targets[0]
        target["readers"] |= record["readers"]
        target["required"] = target["required"] or record["required"]
        target["crc"] |= record["crc"]
        for where, href in record["links"].items():
            target["links"].setdefault(where, href)
        if RANK[record["category"]] < RANK[target["category"]]:
            target["category"] = record["category"]


def load_ledger(path: Path) -> list[dict]:
    """The archive records of recipes/archives.json, empty when absent."""
    return list(archive_build.load_ledger(path).values())


def page(total: int, known: int) -> str:
    """The wanted page: the drop box, the steps from a file in hand to a
    file in the collection, then the table of every wanted file
    (WantedList.astro).

    Held to the Start here budgets (tests/test_site_copy.py): anyone with a
    file in hand reads it.
    """
    return "\n".join([
        "---",
        "terms: wanted list, donate, give a file, upload to github, help the collection, missing bios",
        "---",
        "",
        "# Wanted",
        "",
        "Have a file the collection lacks? Drop it below to see if it is wanted.",
        "Files are read on this device. Nothing leaves it before an upload to GitHub.",
        "",
        "<WantedFiles />",
        "",
        "Several files at once? Drop them all. Each gets its own answer and upload button.",
        "",
        "## Where a file comes from",
        "",
        "- A console or handheld at home: its BIOS, copied with a homebrew tool.",
        "- An old SD card, or the BIOS folder of an emulator used before.",
        "- A firmware update package from the maker.",
        "",
        "To check any other file, use [Find or check a file](files/index.md).",
        "",
        "## Send it",
        "",
        "1. Make a free GitHub account once: [sign up](https://github.com/signup).",
        "2. Drop the file at the top. If it is wanted, its button opens the right folder on GitHub.",
        "3. Rename the file if the page asks, then drop it there.",
        "4. GitHub makes a copy of the project and opens a pull request, a request to add the file.",
        "5. A check reads the file and comments on the request.",
        "",
        "The maintainer then merges it, and the file joins the downloads and the installer.",
        "",
        (f"A file over {BROWSER_UPLOAD_LIMIT // (1024 * 1024)} MB is too large for the upload page. "
         "Its button opens an issue form with the details filled in."),
        "",
        "## The wanted list",
        "",
        (f"{total:,} files, firmware first and game data last. A name opens its details. "
         f"{known:,} have a fingerprint (a hash), so a dropped copy is recognised."),
        "",
        "The others are known by name only: a dropped file of that name gets a button too.",
        "",
        "<WantedList />",
        "",
        "More ways to help are on [Contributing](contributing.md).",
        "",
    ])
