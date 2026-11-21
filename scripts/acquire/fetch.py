"""The searches for a missing file: the database, old branches, public repositories, Software Heritage, archive.org."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

from core import upstream
from core.hashing import parse_hash_list
from resolve.localfile import held_record_for

MAX_DOWNLOAD = 100 * 1024 * 1024  # 100MB per file

LEGACY_BRANCHES = ["libretro", "RetroArch", "RetroPie", "Recalbox", "batocera", "Other"]

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
        ref = f"origin/{branch}"
        try:
            subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            continue

        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", ref],
            capture_output=True,
            text=True,
            check=False,
        )

        for filepath in result.stdout.strip().split("\n"):
            if os.path.basename(filepath) == name:
                try:
                    blob = subprocess.run(
                        ["git", "show", f"{ref}:{filepath}"],
                        capture_output=True,
                        check=True,
                    )
                    if verify_content(blob.stdout, entry):
                        return blob.stdout
                except subprocess.CalledProcessError:
                    continue

    return None


# Sources that did not answer during the current file's search. A 404 is an
# answer, the file is not there. Anything else leaves the question open: an
# offline run used to report every file as needing a community contribution.
_UNANSWERED: list[str] = []


def _get(url: str, timeout: float = 30) -> bytes | None:
    """Body of a GET, None when there is none to check: a 404 and a body
    over MAX_DOWNLOAD are answers, any other failure is recorded in
    _UNANSWERED once the retries of core.upstream are spent."""
    try:
        return upstream.fetch_body(
            url, timeout=timeout, max_bytes=MAX_DOWNLOAD, user_agent="retrobios-fetch/1.0"
        )
    except upstream.UpstreamError as exc:
        _UNANSWERED.append(f"{url}: {exc}")
    except ValueError:
        pass
    return None


def _get_json(url: str) -> dict:
    """A JSON object from a GET, {} when there is none."""
    body = _get(url)
    if body is None:
        return {}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        _UNANSWERED.append(f"{url}: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def step3_search_public_repos(entry: dict) -> bytes | None:
    """Search public GitHub BIOS repos."""
    name = entry["name"]
    destination = entry.get("destination", name)

    names = [name, destination] if "/" in destination else [name]
    for url_template in PUBLIC_REPOS:
        for candidate in names:
            data = _get(url_template.format(name=candidate))
            if data is not None and verify_content(data, entry):
                return data
    return None


def step3b_software_heritage(entry: dict) -> bytes | None:
    """Ask Software Heritage for the file by each accepted sha1, then
    sha256: its archive answers by content, whatever the file was named."""
    for field in ("sha1", "sha256"):
        for value in sorted(parse_hash_list(entry.get(field))):
            data = _get(f"{SOFTWARE_HERITAGE}/{field}:{value}/raw/", timeout=60)
            if data is not None and verify_content(data, entry):
                return data
    return None


def step4_search_archive_org(entry: dict) -> bytes | None:
    """Search archive.org firmware collections by direct download."""
    name = entry["name"]

    for collection_id in ARCHIVE_ORG_COLLECTIONS:
        for path in [name, f"system/{name}", f"bios/{name}"]:
            data = _get(f"https://archive.org/download/{collection_id}/{path}")
            if data is not None and verify_content(data, entry):
                return data

    sha1s = sorted(parse_hash_list(entry.get("sha1")))
    if not sha1s:
        return None
    # Each accepted revision is a query of its own: archive.org matches one.
    sha1 = " OR ".join(f"sha1:{value}" for value in sha1s)

    search_url = (
        "https://archive.org/advancedsearch.php?q="
        f"{urllib.parse.quote(sha1)}&output=json&rows=1"
    )

    docs = _get_json(search_url).get("response", {}).get("docs", [])
    identifier = docs[0].get("identifier") if docs else None
    if identifier:
        data = _get(f"https://archive.org/download/{identifier}/{name}")
        if data is not None and verify_content(data, entry):
            return data
    return None


def place_file(data: bytes, entry: dict, bios_dir: str, db: dict) -> str:
    """Place a fetched BIOS file in the correct location."""
    name = os.path.basename(entry["name"])
    system = entry["system"]

    dest_dir = Path(bios_dir)

    # Every part of the slug, not any: matching "nintendo" alone filed the
    # N64's n64.psh under the first Nintendo folder walked, the SNES one.
    parts = [part for part in system.lower().split("-") if len(part) > 1]
    matches = sorted(
        (len(f"{manufacturer_dir.name}/{console_dir.name}"), str(console_dir), console_dir)
        for manufacturer_dir in dest_dir.iterdir() if manufacturer_dir.is_dir()
        for console_dir in manufacturer_dir.iterdir() if console_dir.is_dir()
        and all(
            part in f"{manufacturer_dir.name}/{console_dir.name}".lower()
            for part in parts
        )
    )
    folder = matches[0][2] if matches else dest_dir / "Unknown" / system
    dest = folder / name
    if dest.exists() and dest.read_bytes() != data:
        # Another revision under the same name: the collection keeps it
        # beside, never in place of, the file already there.
        dest = folder / ".variants" / f"{name}.{hashlib.sha1(data).hexdigest()[:8]}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return str(dest)


def fetch_missing(
    missing: list[dict],
    db: dict,
    bios_dir: str,
    dry_run: bool = False,
) -> dict:
    """Run the 5-step auto-fetch pipeline for missing files."""
    stats = {"found": 0, "not_found": 0, "errors": 0, "unverifiable": 0}
    still_missing = []

    for entry in missing:
        name = entry["name"]
        _UNANSWERED.clear()
        print(f"\n  Searching: {name} ({entry['system']})")

        existing = step1_crossref_db(entry, db)
        if existing:
            print(f"    [1] Found in database at: {existing}")
            stats["found"] += 1
            continue

        if not verifiable(entry):
            # Searched, a file of that name could only ever be refused.
            print("    [-] Cannot be verified from the network: declares no "
                  "cryptographic hash. Not searched, nothing written")
            still_missing.append(entry)
            stats["unverifiable"] += 1
            continue

        if dry_run:
            print("    [DRY RUN] Would search branches, repos, Software Heritage, archive.org")
            still_missing.append(entry)
            stats["not_found"] += 1
            continue

        data = step2_scan_branches(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [2] Found in branch, saved to: {path}")
            stats["found"] += 1
            continue

        data = step3_search_public_repos(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [3] Found in public repo, saved to: {path}")
            stats["found"] += 1
            continue

        data = step3b_software_heritage(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [3b] Found in Software Heritage, saved to: {path}")
            stats["found"] += 1
            continue

        data = step4_search_archive_org(entry)
        if data:
            path = place_file(data, entry, bios_dir, db)
            print(f"    [4] Found on archive.org, saved to: {path}")
            stats["found"] += 1
            continue

        if _UNANSWERED:
            # Not looked for everywhere: no issue asks the community for it.
            print(
                f"    [5] Search incomplete, {len(_UNANSWERED)} source(s) did not "
                f"answer (first: {_UNANSWERED[0]})"
            )
            stats["errors"] += 1
            continue
        print("    [5] Not found, open for contributions")
        still_missing.append(entry)
        stats["not_found"] += 1

    return {"stats": stats, "still_missing": still_missing}


ACQUIRE_DIR = Path("tmp") / "acquire"


def lookup_sha1s(sha1s: list[str], db: dict, dry_run: bool = False) -> int:
    """--sha1: each file looked for by its hash alone, without a platform.
    Found bytes are verified, then saved as tmp/acquire/<sha1>, never into
    bios/: placing a file is a decision the collection makes. 0 when every
    one was found, 1 otherwise."""
    missing = 0
    for raw in sha1s:
        sha1 = raw.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40}", sha1):
            print(f"  {raw}: not a sha1", file=sys.stderr)
            missing += 1
            continue
        entry = {"name": sha1, "sha1": sha1, "system": ""}
        _UNANSWERED.clear()
        held = step1_crossref_db(entry, db)
        if held:
            print(f"  {sha1}: already held at {held}")
            continue
        if dry_run:
            print(f"  {sha1}: would ask Software Heritage and archive.org")
            continue
        data = step3b_software_heritage(entry)
        where = "Software Heritage"
        if data is None:
            data, where = _archive_org_by_sha1(sha1), "archive.org"
        if data is None:
            note = f", {len(_UNANSWERED)} source(s) did not answer" if _UNANSWERED else ""
            print(f"  {sha1}: not found{note}")
            missing += 1
            continue
        ACQUIRE_DIR.mkdir(parents=True, exist_ok=True)
        out = ACQUIRE_DIR / sha1
        out.write_bytes(data)
        print(f"  {sha1}: found in {where}, {len(data)} bytes, saved to {out}")
    return 1 if missing else 0


def _archive_org_by_sha1(sha1: str) -> bytes | None:
    """The first archive.org file whose metadata names sha1, read and checked."""
    search = ("https://archive.org/advancedsearch.php?q="
              f"{urllib.parse.quote(f'sha1:{sha1}')}&fl[]=identifier&output=json&rows=5")
    docs = _get_json(search).get("response", {}).get("docs", [])
    for doc in docs:
        identifier = doc.get("identifier")
        files = _get_json(f"https://archive.org/metadata/{identifier}/files").get("result", [])
        for item in files:
            if str(item.get("sha1", "")).lower() != sha1:
                continue
            url = (f"https://archive.org/download/{identifier}/"
                   f"{urllib.parse.quote(item['name'])}")
            data = _get(url, timeout=60)
            if data is not None and hashlib.sha1(data).hexdigest() == sha1:
                return data
    return None


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
