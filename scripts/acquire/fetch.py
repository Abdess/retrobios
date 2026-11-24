"""The searches for a missing file: the database, old branches, public repositories, Software Heritage, archive.org."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from acquire.placement import ACQUIRE_DIR, Placement, keep_acquired, place_file
from core import forgehttp
from core.hashing import parse_hash_list
from core.paths import EMULATORS_DIR, PLATFORMS_DIR, REPO_ROOT
from resolve.lookup import held_record_for
from resolve.reviewhashes import load_platform_hashes, load_profile_hashes

MAX_DOWNLOAD = 100 * 1024 * 1024  # 100MB per file

LEGACY_BRANCHES = ["libretro", "RetroArch", "RetroPie", "Recalbox", "batocera", "Other"]


def legacy_branch_files(branch: str) -> list[str] | None:
    """Every path origin/<branch> holds, None when the remote has no such branch."""
    ref = f"origin/{branch}"
    try:
        subprocess.run(["git", "rev-parse", "--verify", ref], capture_output=True, check=True,
                       cwd=REPO_ROOT)
    except subprocess.CalledProcessError:
        return None
    result = subprocess.run(["git", "ls-tree", "-r", "--name-only", ref], capture_output=True,
                            text=True, check=False, cwd=REPO_ROOT)
    return [path for path in result.stdout.split("\n") if path]


def legacy_branch_blob(branch: str, path: str) -> bytes | None:
    """The bytes origin/<branch> holds at a path, None when git cannot show them."""
    try:
        return subprocess.run(["git", "show", f"origin/{branch}:{path}"], capture_output=True,
                              check=True, cwd=REPO_ROOT).stdout
    except subprocess.CalledProcessError:
        return None

PUBLIC_REPOS = [
    # archtaurus/RetroPieBIOS - most complete verified collection
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/pcsx2/bios/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/ep128emu/roms/{name}",
    "https://raw.githubusercontent.com/archtaurus/RetroPieBIOS/master/BIOS/fuse/{name}",
    # prefetchnta/retroarch-bios - alternative verified collection
    "https://raw.githubusercontent.com/prefetchnta/retroarch-bios/main/system/{name}",
    "https://raw.githubusercontent.com/prefetchnta/retroarch-bios/main/system/pcsx2/bios/{name}",
    # BatoceraPLUS - Batocera-specific
    "https://raw.githubusercontent.com/BatoceraPLUS/Batocera.PLUS-bios/main/{name}",
]

# Software Heritage archives the source of every public forge, deleted
# repositories and rewritten histories included, and finds a file by its
# hash: a ROM once committed anywhere answers here even when no forge still
# serves it. Anonymous use allows 120 requests an hour.
SOFTWARE_HERITAGE = "https://archive.softwareheritage.org/api/1/content"

ARCHIVE_ORG_COLLECTIONS = [
    "RetroarchSystemFiles",
    "retroarch_bios",
    "retroarch-ultimate-bios-pack_20250824",
    "system_20240621",
    "full-pack-bios-batocera-39",
]


def find_missing(config: dict, db: dict) -> list[dict]:
    """Files the platform's own check or its cores' code would not find.

    Read from verify, the platform's native check: a hash or name lookup
    of our own called pc6001.zip and fmtowns.zip missing on Batocera, which
    checks them inside the zip and holds them, and saw none of the files
    the cores need that no platform lists.
    """
    from resolve.nativemode import reads_file_contents
    from packs.verdicts import Status
    from packs.coverage import verify_platform

    result = verify_platform(config, db)
    hashed = reads_file_contents(config.get("verification_mode", "existence"))
    wanted = {
        (d.get("system", ""), d.get("name", ""))
        for d in result["details"]
        if d["status"] == Status.MISSING or (hashed and d["status"] == Status.UNTESTED)
    }
    missing: list[dict] = []
    for sys_id, system in config.get("systems", {}).items():
        for file_entry in system.get("files", []):
            name = file_entry.get("name", "")
            if (sys_id, name) not in wanted:
                continue
            if file_entry.get("storage", "embedded") != "embedded":
                continue
            missing.append({
                "name": name,
                "system": sys_id,
                "sha1": file_entry.get("sha1"),
                "md5": file_entry.get("md5"),
                "sha256": file_entry.get("sha256"),
                "crc32": file_entry.get("crc32"),
                "size": file_entry.get("size"),
                "destination": file_entry.get("destination", name),
            })
    for u in result["undeclared_files"]:
        # A file installed with its emulator is not an acquisition target:
        # verify leaves it out of the missing count, and bundled_only.py
        # --strict refuses a copy that only bundled entries reach.
        if u.get("in_repo") or not u.get("required") or u.get("bundled"):
            continue
        missing.append({
            "name": u["name"],
            "system": u.get("system") or "",
            "sha1": u.get("sha1"),
            "md5": u.get("md5"),
            "sha256": u.get("sha256"),
            "crc32": u.get("crc32"),
            "size": u.get("size"),
            "destination": u.get("path") or u["name"],
            "emulator": u.get("emulator", ""),
        })
    return missing


CRYPTO_HASHES = (
    ("sha256", hashlib.sha256),
    ("sha1", hashlib.sha1),
    ("md5", hashlib.md5),
)


def verifiable(entry: dict) -> bool:
    """Whether a network download can be proved to be this file.

    Only a cryptographic hash proves it. A crc32 and a size can be met by
    crafted bytes, so they identify a file the database already holds
    (step 1) and never accept one a remote source serves.
    """
    return any(parse_hash_list(entry.get(field)) for field, _digest in CRYPTO_HASHES)


def verify_content(data: bytes, expected: dict) -> bool:
    """Whether downloaded bytes match every cryptographic hash declared.

    Each declared field must hold the bytes' digest among its accepted
    values. An entry declaring none is refused.
    """
    declared = [
        (accepted, digest)
        for field, digest in CRYPTO_HASHES
        for accepted in [parse_hash_list(expected.get(field))]
        if accepted
    ]
    return bool(declared) and all(
        digest(data).hexdigest() in accepted for accepted, digest in declared
    )


def step1_crossref_db(entry: dict, db: dict) -> str | None:
    """Where the collection holds the declared content, read as the resolver
    reads it: a held file a declared hash contradicts is still searched for."""
    sha1 = held_record_for(entry, db)
    return db["files"][sha1]["path"] if sha1 else None


def step2_scan_branches(entry: dict) -> bytes | None:
    """Search old git branches for the file by hash."""
    name = entry["name"]

    for branch in LEGACY_BRANCHES:
        for filepath in legacy_branch_files(branch) or ():
            if os.path.basename(filepath) == name:
                content = legacy_branch_blob(branch, filepath)
                if content is not None and verify_content(content, entry):
                    return content

    return None


def _get(url: str, unanswered: list[str], timeout: float = 30) -> bytes | None:
    """Body of a GET, None when there is none to check.

    A 404 and a body over MAX_DOWNLOAD are answers, the file is not there.
    Any other failure, once the retries of core.upstream are spent, leaves
    the question open and is added to *unanswered*: an offline run used to
    report every file as needing a community contribution.
    """
    try:
        return forgehttp.fetch_body(
            url, timeout=timeout, max_bytes=MAX_DOWNLOAD, user_agent="retrobios-fetch/1.0"
        )
    except forgehttp.UpstreamError as exc:
        unanswered.append(f"{url}: {exc}")
    except ValueError:
        pass
    return None


def _get_json(url: str, unanswered: list[str]) -> dict:
    """A JSON object from a GET, {} when there is none."""
    body = _get(url, unanswered)
    if body is None:
        return {}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        unanswered.append(f"{url}: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def step3_search_public_repos(entry: dict, unanswered: list[str]) -> bytes | None:
    """Search public GitHub BIOS repos."""
    name = entry["name"]
    destination = entry.get("destination", name)

    names = [name, destination] if "/" in destination else [name]
    for url_template in PUBLIC_REPOS:
        for candidate in names:
            data = _get(url_template.format(name=candidate), unanswered)
            if data is not None and verify_content(data, entry):
                return data
    return None


def step3b_software_heritage(entry: dict, unanswered: list[str]) -> bytes | None:
    """Ask Software Heritage for the file by each accepted sha1, then
    sha256: its archive answers by content, whatever the file was named."""
    for field_name in ("sha1", "sha256"):
        for value in sorted(parse_hash_list(entry.get(field_name))):
            data = _get(f"{SOFTWARE_HERITAGE}/{field_name}:{value}/raw/", unanswered,
                        timeout=60)
            if data is not None and verify_content(data, entry):
                return data
    return None


def archive_org_by_sha1(sha1: str, unanswered: list[str]) -> bytes | None:
    """The first archive.org file whose metadata names sha1, read and checked.

    The member is chosen by its recorded sha1, never by its name: an item
    may store the dump under any path (bios/SCPH1001.BIN for scph1001.bin).
    """
    search_url = ("https://archive.org/advancedsearch.php?q="
                  f"{urllib.parse.quote(f'sha1:{sha1}')}&fl[]=identifier&output=json&rows=5")
    docs = _get_json(search_url, unanswered).get("response", {}).get("docs", [])
    for doc in docs:
        identifier = doc.get("identifier")
        if not identifier:
            continue
        files = _get_json(
            f"https://archive.org/metadata/{identifier}/files", unanswered
        ).get("result", [])
        for item in files:
            if str(item.get("sha1", "")).lower() != sha1:
                continue
            url = (f"https://archive.org/download/{identifier}/"
                   f"{urllib.parse.quote(item['name'])}")
            data = _get(url, unanswered, timeout=60)
            if data is not None and hashlib.sha1(data).hexdigest() == sha1:
                return data
    return None


def step4_search_archive_org(entry: dict, unanswered: list[str]) -> bytes | None:
    """Search archive.org firmware collections by direct download, then
    every item by each accepted sha1."""
    name = entry["name"]

    for collection_id in ARCHIVE_ORG_COLLECTIONS:
        for path in [name, f"system/{name}", f"bios/{name}"]:
            data = _get(f"https://archive.org/download/{collection_id}/{path}", unanswered)
            if data is not None and verify_content(data, entry):
                return data

    for sha1 in sorted(parse_hash_list(entry.get("sha1"))):
        data = archive_org_by_sha1(sha1, unanswered)
        if data is not None and verify_content(data, entry):
            return data
    return None


@dataclass(frozen=True)
class SearchResult:
    """What one file's search found, where, and which sources did not answer."""

    data: bytes | None
    source: str | None
    unanswered: tuple[str, ...]


# The sources a platform's missing file is searched in, in order.
PLATFORM_SOURCES = ("branch", "public_repo", "software_heritage", "archive_org")
# The sources a bare sha1 is searched in, in order.
SHA1_SOURCES = ("software_heritage", "archive_org_sha1")


def _ask(source: str, entry: dict, unanswered: list[str]) -> bytes | None:
    """The verified bytes one source holds for an entry, None when it holds none."""
    if source == "branch":
        return step2_scan_branches(entry)
    if source == "public_repo":
        return step3_search_public_repos(entry, unanswered)
    if source == "software_heritage":
        return step3b_software_heritage(entry, unanswered)
    if source == "archive_org":
        return step4_search_archive_org(entry, unanswered)
    if source == "archive_org_sha1":
        return archive_org_by_sha1(entry["sha1"], unanswered)
    raise ValueError(f"unknown source {source}")


def search(entry: dict, sources: tuple[str, ...]) -> SearchResult:
    """Ask each source in turn and stop at the first that serves the file."""
    unanswered: list[str] = []
    for source in sources:
        data = _ask(source, entry, unanswered)
        if data:
            return SearchResult(data, source, tuple(unanswered))
    return SearchResult(None, None, tuple(unanswered))


@dataclass(frozen=True)
class FetchRecord:
    """The outcome of one missing file's search.

    outcome is held, unverifiable, dry_run, found, incomplete or not_found.
    """

    entry: dict
    outcome: str
    held_at: str | None = None
    source: str | None = None
    placed: Placement | None = None
    unanswered: tuple[str, ...] = ()


@dataclass
class FetchRun:
    """Searches the missing files of one platform and places what it finds."""

    db: dict
    bios_dir: str
    dry_run: bool = False
    platforms_dir: str = PLATFORMS_DIR
    emulators_dir: str = EMULATORS_DIR
    acquire_dir: Path = ACQUIRE_DIR
    _tables: list[dict] = field(default_factory=list)

    def _place(self, data: bytes, entry: dict) -> Placement:
        # Read once, and only when something was found to place.
        if not self._tables:
            self._tables.extend((load_platform_hashes(self.platforms_dir, self.db),
                                 load_profile_hashes(self.emulators_dir, self.db)))
        return place_file(data, entry, self.bios_dir, self.db, *self._tables,
                          acquire_dir=self.acquire_dir)

    def fetch(self, entry: dict) -> FetchRecord:
        """Look for one file, from the database out to archive.org."""
        existing = step1_crossref_db(entry, self.db)
        if existing:
            return FetchRecord(entry, "held", held_at=existing)
        if not verifiable(entry):
            # A file of that name could only ever be refused.
            return FetchRecord(entry, "unverifiable")
        if self.dry_run:
            return FetchRecord(entry, "dry_run")
        found = search(entry, PLATFORM_SOURCES)
        if found.data:
            return FetchRecord(entry, "found", source=found.source,
                               placed=self._place(found.data, entry),
                               unanswered=found.unanswered)
        # Not looked for everywhere: no issue asks the community for it.
        outcome = "incomplete" if found.unanswered else "not_found"
        return FetchRecord(entry, outcome, unanswered=found.unanswered)


# The count each outcome adds to, and the outcomes still open for contributions.
_COUNTED = {"held": "found", "found": "found", "unverifiable": "unverifiable",
            "dry_run": "not_found", "not_found": "not_found", "incomplete": "errors"}
_STILL_MISSING = ("unverifiable", "dry_run", "not_found")


def fetch_summary(records: list[FetchRecord]) -> dict:
    """The counts a run reports and the files still open for contributions."""
    stats = {"found": 0, "not_found": 0, "errors": 0, "unverifiable": 0}
    for record in records:
        stats[_COUNTED[record.outcome]] += 1
    still_missing = [r.entry for r in records if r.outcome in _STILL_MISSING]
    return {"stats": stats, "still_missing": still_missing}


def fetch_missing(
    missing: list[dict],
    db: dict,
    bios_dir: str,
    dry_run: bool = False,
    platforms_dir: str = PLATFORMS_DIR,
    emulators_dir: str = EMULATORS_DIR,
    acquire_dir: Path = ACQUIRE_DIR,
) -> dict:
    """Search every missing file: the counts, the files still open and the records."""
    run = FetchRun(db, bios_dir, dry_run, platforms_dir, emulators_dir, acquire_dir)
    records = [run.fetch(entry) for entry in missing]
    return {**fetch_summary(records), "records": records}


@dataclass(frozen=True)
class LookupRecord:
    """The outcome of one --sha1 lookup.

    outcome is malformed, held, dry_run, not_found or found.
    """

    raw: str
    sha1: str
    outcome: str
    held_at: str | None = None
    source: str | None = None
    size: int = 0
    path: Path | None = None
    unanswered: tuple[str, ...] = ()


def lookup_sha1(raw: str, db: dict, dry_run: bool = False,
                acquire_dir: Path = ACQUIRE_DIR) -> LookupRecord:
    """--sha1: one file looked for by its hash alone, without a platform.

    Found bytes are verified, then saved as <acquire_dir>/<sha1>, never into
    bios/: placing a file is a decision the collection makes.
    """
    sha1 = raw.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha1):
        return LookupRecord(raw, sha1, "malformed")
    entry = {"name": sha1, "sha1": sha1, "system": ""}
    held = step1_crossref_db(entry, db)
    if held:
        return LookupRecord(raw, sha1, "held", held_at=held)
    if dry_run:
        return LookupRecord(raw, sha1, "dry_run")
    found = search(entry, SHA1_SOURCES)
    if found.data is None:
        return LookupRecord(raw, sha1, "not_found", unanswered=found.unanswered)
    out = keep_acquired(found.data, sha1, acquire_dir)
    return LookupRecord(raw, sha1, "found", source=found.source, size=len(found.data),
                        path=out, unanswered=found.unanswered)


def lookup_sha1s(sha1s: list[str], db: dict, dry_run: bool = False,
                 acquire_dir: Path = ACQUIRE_DIR) -> list[LookupRecord]:
    """Each --sha1 looked up in turn."""
    return [lookup_sha1(raw, db, dry_run, acquire_dir) for raw in sha1s]


CONTRIBUTING_URL = "https://github.com/Abdess/retrobios/blob/main/CONTRIBUTING.md"


def generate_issue_body(missing: list[dict], platform: str) -> str:
    """An issue body for the files a platform still needs.

    The hashes are written in full: a contributor matches a file against
    them, and a 12-character prefix confirms nothing.
    """
    lines = [
        f"## Files {platform} still needs",
        "",
        "| File | System | SHA1 | MD5 |",
        "|------|--------|------|-----|",
    ]
    for entry in missing:
        sha1 = ", ".join(f"`{h}`" for h in sorted(parse_hash_list(entry.get("sha1")))) or "none declared"
        md5 = ", ".join(f"`{h}`" for h in sorted(parse_hash_list(entry.get("md5")))) or "none declared"
        lines.append(f"| `{entry['name']}` | {entry['system']} | {sha1} | {md5} |")
    lines += [
        "",
        "A file with one of these hashes can be added through the upload link in"
        f" [CONTRIBUTING.md]({CONTRIBUTING_URL}). CI checks it on arrival.",
    ]
    return "\n".join(lines)
