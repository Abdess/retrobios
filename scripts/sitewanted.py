"""The files the collection lacks, as the wanted page reads them.

A visitor drops files on wanted/, each is hashed in the browser and
compared with this list. The list is the gaps page's: a file a platform
lists that its own check finds missing or under another hash, a file an
emulator loads that no platform lists and the collection does not hold,
and a file not collected yet. A declaration that names no hash cannot be
recognised by its bytes and is left out.

Each entry keeps the hashes its declaration writes, read as the resolver
reads them (comma lists split, a crc32 counted only where no stronger hash
is declared), and the folder validate_pr.placement() gives those hashes:
the review of the pull request asks for that same folder.
"""

from __future__ import annotations

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


def wanted_declarations(profiles: dict, coverages: dict, gap_report: dict) -> list[dict]:
    """Every declaration of a file the gaps page reports as lacking.

    Each is {name, system, required, reader: (kind, key, label), entry}.
    """
    found: list[dict] = []
    for key, coverage in sorted(coverages.items()):
        systems = coverage.get("config", {}).get("systems") or {}
        for detail in coverage.get("details", []):
            if detail.get("settled_by") or detail.get("status") not in ("missing", "untested"):
                continue
            system = detail.get("system", "")
            for entry in (systems.get(system) or {}).get("files") or []:
                if isinstance(entry, dict) and entry.get("name") == detail.get("name"):
                    found.append({
                        "name": str(entry["name"]), "system": system,
                        "required": bool(detail.get("required", True)),
                        "reader": ("platform", key, coverage["platform"]), "entry": entry,
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
                })
    return found


def _settle_cut(records: list[dict]) -> None:
    """A cut md5 names a dump only if exactly one md5 starts with it.

    Matched against the wanted md5s: one of them, and the cut is that md5;
    several, and it names none; none, and the page compares by prefix.
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

    def place(self, hashes: dict[str, list[str]], name: str) -> Placement:
        values = [value for algo in ("sha1", "md5", "sha256") for value in hashes.get(algo, [])
                  if len(value) == FULL_LENGTH[algo]]
        return placement(values, name, self.db, self.platform_hashes, self.profile_hashes,
                         declared=True, exists=self.paths.__contains__)

    def folder(self, entry: dict) -> str:
        """The folder an upload of a profile or platform entry goes to."""
        return self.place(declared_hashes(entry), str(entry.get("name", ""))).folder


FULL_LENGTH = {"sha1": 40, "md5": 32, "sha256": 64}


def upload_href(root: str, folder: str) -> str:
    """GitHub's upload page for a folder of the repository, bios/ when the
    placement names none."""
    return root + urllib.parse.quote((folder or "bios/").rstrip("/"))


def build_wanted(
    profiles: dict,
    coverages: dict,
    gap_report: dict,
    db: dict,
    placer: Placer,
    system_name: Callable[[str], str],
    ledger: Iterable[dict] = (),
) -> dict:
    """The wanted list, compact, as public/data/wanted.json carries it.

    Readers, systems and folders are written once and named by position.
    An entry: n name, h hashes, w readers, s systems, r required, z sizes,
    f folder, t the name it is uploaded under, v that name goes to the
    folder's .variants/ with the first 8 characters of its sha1.
    """
    held = Held(db, ledger)
    records: dict[tuple, dict] = {}
    for declaration in wanted_declarations(profiles, coverages, gap_report):
        entry = declaration["entry"]
        sizes = _sizes(entry)
        for hashes in _alternatives(declared_hashes(entry)):
            if held.holds(hashes, sizes):
                continue
            key = (declaration["name"], tuple(sorted((a, tuple(v)) for a, v in hashes.items())),
                   tuple(sizes))
            record = records.setdefault(key, {
                "name": declaration["name"], "hashes": {a: list(v) for a, v in hashes.items()},
                "sizes": sizes, "systems": set(), "required": False, "readers": set(),
            })
            if declaration["system"]:
                record["systems"].add(declaration["system"])
            record["required"] = record["required"] or declaration["required"]
            record["readers"].add(declaration["reader"])
    ordered = sorted(records.values(), key=lambda r: (r["name"].casefold(), sorted(r["readers"])))
    _settle_cut(ordered)
    ordered = [r for r in ordered if r["hashes"]]

    readers = sorted({reader for r in ordered for reader in r["readers"]},
                     key=lambda reader: (reader[0], reader[2].casefold(), reader[1]))
    reader_at = {reader: i for i, reader in enumerate(readers)}
    folders: list[str] = []
    folder_at: dict[str, int] = {}
    titles: dict[str, str] = {}
    entries = []
    for record in ordered:
        spot = placer.place(record["hashes"], record["name"])
        if spot.folder and spot.folder not in folder_at:
            folder_at[spot.folder] = len(folders)
            folders.append(spot.folder)
        systems = sorted({titles.setdefault(s, system_name(s)) for s in record["systems"]})
        item: dict = {
            "n": record["name"],
            "h": {algo: record["hashes"][algo] for algo in ALGORITHMS if algo in record["hashes"]},
            "w": sorted(reader_at[reader] for reader in record["readers"]),
        }
        if systems:
            item["s"] = ", ".join(systems)
        if record["required"]:
            item["r"] = 1
        if record["sizes"]:
            item["z"] = record["sizes"]
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
        "folders": folders,
        "entries": entries,
    }


def load_ledger(path: Path) -> list[dict]:
    """The archive records of recipes/archives.json, empty when absent."""
    return list(archive_build.load_ledger(path).values())


def page(known: int) -> str:
    """The wanted page: the drop box, then what happens after an upload.

    Held to the Start here budgets (tests/test_site_copy.py): anyone with a
    file in hand reads it.
    """
    return "\n".join([
        "---",
        "terms: wanted list, donate, give a file, upload to github, help the collection",
        "---",
        "",
        "# Wanted",
        "",
        "Have a file the collection lacks? Drop it below. The page says if we want it.",
        "",
        "<WantedFiles />",
        "",
        "Your files are read on this device. Nothing is sent until you upload one to GitHub.",
        "",
        "## After the upload",
        "",
        "1. The button opens GitHub's upload page in the right folder. Sign in and drop the file there.",
        "2. GitHub puts it in your own copy of the project and opens a pull request.",
        "3. A check reads the file and says if it fits. Then we add it.",
        "",
        (f"The page knows {known:,} wanted files by their hash, a fingerprint of the contents. "
        "The rest are listed on [the gaps page](gaps.md)."),
        "",
        ("To look up any file, use [Find or check a file](files/index.md). "
        "More ways to help are on [Contributing](contributing.md)."),
        "",
    ])
